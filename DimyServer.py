#!/usr/bin/env python3
"""
DIMY Backend Server (DimyServer.py)

Required by Assignment Section 4.3:
  "Your backend server code should be named DimyServer.py."

Behaviour (Back-end Server section):
  - Listens on TCP port 55000.
  - Stores all CBFs received from diagnosed nodes (CBF_UPLOAD).
  - On QBF_QUERY: checks whether the QBF overlaps with any stored CBF.
    Returns MATCHED or NOT_MATCHED to the querying node.
  - If no CBF is stored yet, always returns NOT_MATCHED.

Usage: python3 DimyServer.py [--port 55000] [--host ""]
"""
import argparse
import base64
import json
import socket
import threading

BF_BYTES = 100 * 1024  # must match client


# ── TCP helpers (same framing as Dimy.py / Dimy_demo.py) ─────────────────────

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


# ── Server ────────────────────────────────────────────────────────────────────

class DimyServer:
    def __init__(self, host: str = "", port: int = 55000) -> None:
        self.host = host
        self.port = port
        self._lock = threading.Lock()
        self._cbfs: list[bytes] = []   # raw bytes of each stored CBF

    # QBF matches CBF if they share at least one set bit (potential overlap)
    def _is_matched(self, qbf_bytes: bytes) -> bool:
        with self._lock:
            for cbf_bytes in self._cbfs:
                for a, b in zip(qbf_bytes, cbf_bytes):
                    if a & b:
                        return True
        return False

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        try:
            msg = _recv_msg(conn)
        except Exception as exc:
            print(f"[ERROR] read from {addr}: {exc}")
            conn.close()
            return

        msg_type = msg.get("type", "")
        node_id  = msg.get("node_id", str(addr))

        try:
            if msg_type == "CBF_UPLOAD":
                raw = base64.b64decode(msg["data"])
                with self._lock:
                    self._cbfs.append(raw)
                    n_cbfs = len(self._cbfs)
                print(f"[TASK9 ] CBF_UPLOAD  | node={node_id} | "
                      f"total CBFs stored={n_cbfs}")
                _send_msg(conn, {"status": "CBF_ACCEPTED"})

            elif msg_type == "QBF_QUERY":
                raw    = base64.b64decode(msg["data"])
                result = "MATCHED" if self._is_matched(raw) else "NOT_MATCHED"
                with self._lock:
                    n_cbfs = len(self._cbfs)
                print(f"[TASK10] QBF_QUERY   | node={node_id} | "
                      f"CBFs on file={n_cbfs} | result={result}")
                _send_msg(conn, {"result": result})

            else:
                print(f"[WARN ] Unknown msg_type={msg_type!r} from {addr}")
                _send_msg(conn, {"error": "unknown message type"})

        except Exception as exc:
            print(f"[ERROR] handle {msg_type} from {addr}: {exc}")
        finally:
            conn.close()

    def start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(32)
            print(f"[SERVER] DimyServer listening on TCP "
                  f"{self.host or '0.0.0.0'}:{self.port}")
            print("[SERVER] Waiting for CBF_UPLOAD and QBF_QUERY messages...\n")
            while True:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    ).start()
                except KeyboardInterrupt:
                    print("\n[SERVER] Shutting down.")
                    break


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="DIMY Backend Server")
    parser.add_argument("--port", type=int, default=55000,
                        help="TCP port to listen on (default 55000)")
    parser.add_argument("--host", default="",
                        help="Bind address (default all interfaces)")
    args = parser.parse_args()
    DimyServer(args.host, args.port).start()


if __name__ == "__main__":
    main()
