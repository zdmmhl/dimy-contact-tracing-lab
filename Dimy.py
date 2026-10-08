#!/usr/bin/env python3
"""
DIMY frontend (Tasks 1-10).
Usage: python3 Dimy.py t k n p server_ip server_port [--node-id ID]
"""
import base64
from dataclasses import dataclass
from typing import Dict, List, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

import argparse
import hashlib
import json
import random
import secrets
import socket
import threading
import time
import uuid

PRIME = 257
EphID_BYTES = 32
UDP_PORT = 37020
BROADCAST_IP = "255.255.255.255"

BF_BYTES = 100 * 1024          # 100 KB
BF_BITS  = BF_BYTES * 8        # 819200 bits
BF_HASHES = 3
DBF_PERIOD_FACTOR = 6          # one DBF covers t*6 seconds
MAX_DBFS = 6                   # keep at most 6 sealed DBFs


# ── Bloom Filter ─────────────────────────────────────────────────────────────

class BloomFilter:
    def __init__(self) -> None:
        self._bits = bytearray(BF_BYTES)

    def _positions(self, data: bytes):
        for i in range(BF_HASHES):
            digest = hashlib.sha256(i.to_bytes(4, "big") + data).digest()
            yield int.from_bytes(digest[:4], "big") % BF_BITS

    def add(self, data: bytes) -> None:
        for pos in self._positions(data):
            self._bits[pos >> 3] |= 1 << (pos & 7)

    def __contains__(self, data: bytes) -> bool:
        return all((self._bits[pos >> 3] >> (pos & 7)) & 1
                   for pos in self._positions(data))

    def merge(self, other: "BloomFilter") -> None:
        for i in range(BF_BYTES):
            self._bits[i] |= other._bits[i]

    def to_bytes(self) -> bytes:
        return bytes(self._bits)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        bf = cls()
        bf._bits = bytearray(data[:BF_BYTES])
        return bf


# ── TCP helpers ──────────────────────────────────────────────────────────────

def _recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _send_msg(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)


def _recv_msg(sock: socket.socket) -> dict:
    length = int.from_bytes(_recv_all(sock, 4), "big")
    return json.loads(_recv_all(sock, length).decode())


# ── Shamir Secret Sharing ────────────────────────────────────────────────────

@dataclass
class EphIDBundle:
    created_at: float
    ephid_hash: str
    private_key: x25519.X25519PrivateKey
    public_key_bytes: bytes
    shares: List[Tuple[int, List[int]]]
    next_share_idx: int = 0


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mod_inverse(value: int, modulus: int) -> int:
    value %= modulus
    if value == 0:
        raise ValueError("No inverse for zero")
    return pow(value, modulus - 2, modulus)


def split_secret_shamir(secret: bytes, k: int, n: int) -> List[Tuple[int, List[int]]]:
    polys: List[List[int]] = []
    for b in secret:
        coeffs = [b] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
        polys.append(coeffs)
    shares: List[Tuple[int, List[int]]] = []
    for x in range(1, n + 1):
        y_vec = []
        for coeffs in polys:
            y, power = 0, 1
            for c in coeffs:
                y = (y + c * power) % PRIME
                power = (power * x) % PRIME
            y_vec.append(y)
        shares.append((x, y_vec))
    return shares


def reconstruct_secret_shamir(shares: List[Tuple[int, List[int]]]) -> bytes:
    byte_len = len(shares[0][1])
    out = bytearray()
    for byte_idx in range(byte_len):
        acc = 0
        for i, (x_i, y_i_vec) in enumerate(shares):
            y_i = y_i_vec[byte_idx] % PRIME
            num, den = 1, 1
            for j, (x_j, _) in enumerate(shares):
                if i == j:
                    continue
                num = (num * (-x_j % PRIME)) % PRIME
                den = (den * ((x_i - x_j) % PRIME)) % PRIME
            acc = (acc + y_i * num * mod_inverse(den, PRIME)) % PRIME
        if acc > 255:
            raise ValueError("Reconstruction failed")
        out.append(acc)
    return bytes(out)


# ── DIMY Node ────────────────────────────────────────────────────────────────

class DimyNode:
    def __init__(self, t: int, k: int, n: int, p: int,
                 node_id: str, server_ip: str, server_port: int) -> None:
        self.t = t
        self.k = k
        self.n = n
        self.drop_probability = p / 100.0
        self.node_id = node_id
        self.server_ip = server_ip
        self.server_port = server_port

        self.stop_event = threading.Event()
        self.state_lock = threading.Lock()

        # Tasks 1-5
        self.current_bundle: EphIDBundle | None = None
        self.recent_private_keys: Dict[str, Tuple[float, x25519.X25519PrivateKey]] = {}
        self.recv_state: Dict[Tuple[str, str], Dict] = {}
        self.encounters: Dict[Tuple[str, str], str] = {}

        self.recv_sock: socket.socket | None = None
        self.send_sock: socket.socket | None = None

        # Tasks 6-7: DBF management
        self.dbf_lock = threading.Lock()
        self.current_dbf = BloomFilter()
        self.current_dbf_start = time.time()
        self.sealed_dbfs: List[Tuple[float, BloomFilter]] = []

        # Task 9
        self.cbf_uploaded = False

    # ── timing helpers ────────────────────────────────────────────────────────

    def _dbf_period(self) -> float:
        return float(self.t * DBF_PERIOD_FACTOR)

    def _dt_seconds(self) -> float:
        # Dt = (t * 6 * 6) / 60 minutes = t * 36 seconds
        return float(self.t * DBF_PERIOD_FACTOR * MAX_DBFS)

    # ── UDP setup ─────────────────────────────────────────────────────────────

    def setup_udp(self) -> None:
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind(("", UDP_PORT))
        self.recv_sock.settimeout(1.0)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # ── start ─────────────────────────────────────────────────────────────────

    def start(self) -> None:
        self.setup_udp()
        self.new_ephid_bundle()

        for target in (self.generator_loop, self.sender_loop, self.receiver_loop,
                       self.dbf_rotation_loop, self.qbf_loop, self.user_input_loop):
            threading.Thread(target=target, daemon=True).start()

        print(f"Node {self.node_id} started. UDP={BROADCAST_IP}:{UDP_PORT} "
              f"Server={self.server_ip}:{self.server_port}")
        print("Type 'positive' + Enter to upload CBF as a diagnosed user.")
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_event.set()
            print("Stopping...")

    # ── Task 1: EphID generation ──────────────────────────────────────────────

    def new_ephid_bundle(self) -> None:
        private_key = x25519.X25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ephid_hash = sha256_hex(public_key_bytes)
        shares = split_secret_shamir(public_key_bytes, self.k, self.n)

        bundle = EphIDBundle(
            created_at=time.time(),
            ephid_hash=ephid_hash,
            private_key=private_key,
            public_key_bytes=public_key_bytes,
            shares=shares,
        )
        with self.state_lock:
            self.current_bundle = bundle
            self.recent_private_keys[ephid_hash] = (bundle.created_at, private_key)
            self._trim_old_keys()

        print(f"Generated EphID {ephid_hash[:12]}... and {self.n} shares.")

    def _trim_old_keys(self) -> None:
        now = time.time()
        ttl = max(self.t * 4, 120)
        to_delete = [h for h, (ts, _) in self.recent_private_keys.items() if now - ts > ttl]
        for h in to_delete:
            del self.recent_private_keys[h]

    def generator_loop(self) -> None:
        while not self.stop_event.wait(self.t):
            self.new_ephid_bundle()

    # ── Task 3 / 3a: broadcast & drop ────────────────────────────────────────

    def sender_loop(self) -> None:
        while not self.stop_event.is_set():
            with self.state_lock:
                bundle = self.current_bundle
                payload = None
                if bundle and bundle.next_share_idx < self.n:
                    x, y_vec = bundle.shares[bundle.next_share_idx]
                    bundle.next_share_idx += 1
                    payload = {
                        "msg_type": "DIMY_SHARE",
                        "sender_id": self.node_id,
                        "created_at": bundle.created_at,
                        "ephid_hash": bundle.ephid_hash,
                        "k": self.k,
                        "n": self.n,
                        "x": x,
                        "y": y_vec,
                        "share_idx": bundle.next_share_idx,
                    }

            if payload:
                self.broadcast(payload)
                print(f"Sent share {payload['share_idx']}/{self.n} for {payload['ephid_hash'][:12]}...")
            self.stop_event.wait(3.0)

    def broadcast(self, payload: Dict) -> None:
        if not self.send_sock:
            return
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_sock.sendto(data, (BROADCAST_IP, UDP_PORT))

    def receiver_loop(self) -> None:
        if not self.recv_sock:
            return
        while not self.stop_event.is_set():
            try:
                data, addr = self.recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            if msg.get("msg_type") != "DIMY_SHARE":
                continue
            if msg.get("sender_id") == self.node_id:
                continue
            if random.random() < self.drop_probability:
                print(f"Dropped a share from {msg.get('sender_id')}.")
                continue
            self.handle_share(msg, addr)

    # ── Task 4: reconstruct EphID ─────────────────────────────────────────────

    def handle_share(self, msg: Dict, addr: Tuple[str, int]) -> None:
        sender_id = str(msg.get("sender_id", ""))
        ephid_hash = str(msg.get("ephid_hash", ""))
        x = msg.get("x")
        y = msg.get("y")
        k = msg.get("k")

        if not sender_id or not ephid_hash:
            return
        if not isinstance(x, int) or not isinstance(y, list):
            return
        if not isinstance(k, int) or len(y) != EphID_BYTES:
            return

        key = (sender_id, ephid_hash)
        state = self.recv_state.setdefault(key, {"shares": {}, "k": k, "reconstructed": False})

        if x not in state["shares"]:
            state["shares"][x] = y
            print(f"Received share from {sender_id} ({addr[0]}), "
                  f"count={len(state['shares'])}/{state['k']} for {ephid_hash[:12]}...")

        if state["reconstructed"] or len(state["shares"]) < state["k"]:
            return

        selected = sorted(state["shares"].items(), key=lambda item: item[0])[:state["k"]]
        try:
            reconstructed = reconstruct_secret_shamir(selected)
        except Exception:
            return

        if sha256_hex(reconstructed) != ephid_hash:
            print(f"Reconstruction hash mismatch for {sender_id}.")
            return

        state["reconstructed"] = True
        print(f"Reconstructed EphID from {sender_id} and hash verified.")
        self.compute_encid(sender_id, ephid_hash, reconstructed)

    # ── Task 5: Diffie-Hellman → EncID ────────────────────────────────────────

    def compute_encid(self, sender_id: str, sender_ephid_hash: str,
                      peer_public_bytes: bytes) -> None:
        with self.state_lock:
            bundle = self.current_bundle
        if not bundle:
            return

        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = bundle.private_key.exchange(peer_pub)
        except Exception:
            return

        encid = sha256_hex(shared_secret)
        pair_key = tuple(sorted([bundle.ephid_hash, sender_ephid_hash]))
        is_new = pair_key not in self.encounters
        self.encounters[pair_key] = encid

        print(f"EncID with {sender_id}: {encid} "
              f"({'new' if is_new else 'existing'}, "
              f"local={bundle.ephid_hash[:8]}..., peer={sender_ephid_hash[:8]}...)")

        # Task 6: encode into DBF, then discard EncID
        self._add_encid_to_dbf(encid)

    # ── Task 6: encode EncID into DBF, delete EncID ───────────────────────────

    def _add_encid_to_dbf(self, encid: str) -> None:
        with self.dbf_lock:
            self.current_dbf.add(encid.encode())
        print(f"EncID encoded into DBF and deleted from memory.")

    # ── Task 7: DBF rotation ──────────────────────────────────────────────────

    def dbf_rotation_loop(self) -> None:
        while not self.stop_event.wait(self._dbf_period()):
            now = time.time()
            cutoff = now - self._dt_seconds()
            with self.dbf_lock:
                self.sealed_dbfs.append((self.current_dbf_start, self.current_dbf))
                self.current_dbf = BloomFilter()
                self.current_dbf_start = now
                self.sealed_dbfs = [
                    (ts, bf) for ts, bf in self.sealed_dbfs if ts >= cutoff
                ][-MAX_DBFS:]
            print(f"New DBF created. Sealed DBFs stored: {len(self.sealed_dbfs)}/{MAX_DBFS}.")

    # ── Task 8: QBF every Dt ──────────────────────────────────────────────────

    def qbf_loop(self) -> None:
        while not self.stop_event.wait(self._dt_seconds()):
            if self.cbf_uploaded:
                print("CBF already uploaded — QBF generation stopped.")
                break
            with self.dbf_lock:
                bfs = [bf for _, bf in self.sealed_dbfs] + [self.current_dbf]
            qbf = BloomFilter()
            for bf in bfs:
                qbf.merge(bf)
            print(f"QBF generated from {len(bfs)} filter(s). Querying server...")
            self._send_qbf(qbf)

    # ── Task 9: CBF upload ────────────────────────────────────────────────────

    def _build_combined_bf(self) -> BloomFilter:
        with self.dbf_lock:
            bfs = [bf for _, bf in self.sealed_dbfs] + [self.current_dbf]
        combined = BloomFilter()
        for bf in bfs:
            combined.merge(bf)
        return combined

    def upload_cbf(self) -> None:
        cbf = self._build_combined_bf()
        try:
            with socket.create_connection(
                (self.server_ip, self.server_port), timeout=10
            ) as sock:
                _send_msg(sock, {
                    "type": "CBF_UPLOAD",
                    "node_id": self.node_id,
                    "data": base64.b64encode(cbf.to_bytes()).decode(),
                })
                resp = _recv_msg(sock)
            print(f"CBF upload: {resp.get('status', resp)}")
            self.cbf_uploaded = True
        except Exception as e:
            print(f"CBF upload failed: {e}")

    # ── Task 10: send QBF, receive risk result ────────────────────────────────

    def _send_qbf(self, qbf: BloomFilter) -> None:
        try:
            with socket.create_connection(
                (self.server_ip, self.server_port), timeout=10
            ) as sock:
                _send_msg(sock, {
                    "type": "QBF_QUERY",
                    "node_id": self.node_id,
                    "data": base64.b64encode(qbf.to_bytes()).decode(),
                })
                resp = _recv_msg(sock)
            result = resp.get("result", "UNKNOWN")
            print(f"Risk analysis result from server: {result}")
            if result == "MATCHED":
                print("*** WARNING: Potential COVID-19 exposure detected! ***")
        except Exception as e:
            print(f"QBF query failed: {e}")

    # ── Task 9 trigger via stdin ──────────────────────────────────────────────

    def user_input_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                line = input()
            except EOFError:
                break
            if line.strip().lower() == "positive":
                print("Diagnosed positive — uploading CBF to server...")
                self.upload_cbf()


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY frontend (Tasks 1-10)")
    parser.add_argument("t", type=int, help="EphID refresh interval (s)")
    parser.add_argument("k", type=int, help="Shamir threshold")
    parser.add_argument("n", type=int, help="Number of Shamir shares")
    parser.add_argument("p", type=int, help="Drop probability %%")
    parser.add_argument("server_ip", type=str, help="Backend server IP")
    parser.add_argument("server_port", type=int, help="Backend server port")
    parser.add_argument("--node-id", default="", help="Node ID override")
    return parser.parse_args()


def validate_args(t: int, k: int, n: int, p: int) -> None:
    valid_t = {15, 18, 21, 24, 27, 30}
    valid_p = {30, 40, 50, 60, 70}
    if t not in valid_t:
        raise ValueError(f"Invalid t={t}, expected one of {sorted(valid_t)}")
    if p not in valid_p:
        raise ValueError(f"Invalid p={p}, expected one of {sorted(valid_p)}")
    if k < 3:
        raise ValueError("k must be >= 3")
    if n < 5:
        raise ValueError("n must be >= 5")
    if k >= n:
        raise ValueError("k must be < n")


def main() -> None:
    args = parse_args()
    validate_args(args.t, args.k, args.n, args.p)
    node_id = args.node_id if args.node_id else f"node-{uuid.uuid4().hex[:8]}"
    node = DimyNode(args.t, args.k, args.n, args.p,
                    node_id, args.server_ip, args.server_port)
    node.start()


if __name__ == "__main__":
    main()
