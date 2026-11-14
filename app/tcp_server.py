#!/usr/bin/env python3
"""Concurrent TCP echo/ACK server. Uses only Python socket + threading."""
import socket
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5000

def handle_client(conn, addr):
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[CONNECTED] {peer}", flush=True)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            message = data.decode("utf-8", errors="replace")
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Received from {peer}: {message}",
                  flush=True)
            conn.sendall(("ACK: Message received by NIDR server: " + message).encode())
    except (ConnectionResetError, OSError) as exc:
        print(f"[CLIENT ERROR] {peer}: {exc}", flush=True)
    finally:
        conn.close()
        print(f"[CLOSED] {peer}", flush=True)

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(100)
        print(f"[SERVER] Listening on {HOST}:{PORT}", flush=True)
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
