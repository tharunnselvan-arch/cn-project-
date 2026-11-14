#!/usr/bin/env python3
"""Simple TCP client using Python socket."""
import argparse
import socket

def main():
    p = argparse.ArgumentParser()
    p.add_argument("server_ip", nargs="?", default="10.0.0.5")
    p.add_argument("port", nargs="?", type=int, default=5000)
    p.add_argument("message", nargs="?", default="Hello from NIDR client")
    p.add_argument("--timeout", type=float, default=2.0)
    args = p.parse_args()
    print(f"[CONNECTING] {args.server_ip}:{args.port}")
    try:
        with socket.create_connection((args.server_ip, args.port), timeout=args.timeout) as sock:
            print("[CONNECTED] Successfully connected to server")
            sock.sendall(args.message.encode())
            reply = sock.recv(4096)
            print("[SERVER RESPONSE]", reply.decode(errors="replace"))
    except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError) as exc:
        print(f"[CONNECTION FAILED] {type(exc).__name__}: {exc}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
