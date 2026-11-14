#!/usr/bin/env python3
"""Controlled port sweep and rapid TCP connection burst for the Mininet lab only."""
import argparse
import socket
import time

def scan(host, start_port, end_port, timeout):
    print(f"[SCAN] {host} ports {start_port}-{end_port}")
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                print(f"[OPEN] {port}" if result == 0 else f"[CLOSED] {port}")
        except OSError as exc:
            print(f"[ERROR] {port}: {exc}")

def burst(host, port, count, interval, timeout):
    successes = failures = 0
    print(f"[BURST] {count} TCP connections to {host}:{port}")
    for i in range(count):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                successes += 1
                print(f"[{i+1}/{count}] connected")
        except (OSError, TimeoutError) as exc:
            failures += 1
            print(f"[{i+1}/{count}] failed: {type(exc).__name__}")
        if interval:
            time.sleep(interval)
    print(f"[SUMMARY] successful={successes} failed={failures}")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--host", default="10.0.0.5")
    s.add_argument("--start-port", type=int, default=4995)
    s.add_argument("--end-port", type=int, default=5005)
    s.add_argument("--timeout", type=float, default=0.25)
    b = sub.add_parser("burst")
    b.add_argument("--host", default="10.0.0.5")
    b.add_argument("--port", type=int, default=5000)
    b.add_argument("--count", type=int, default=40)
    b.add_argument("--interval", type=float, default=0.02)
    b.add_argument("--timeout", type=float, default=1.0)
    a = p.parse_args()
    if a.mode == "scan":
        if a.start_port < 1 or a.end_port > 65535 or a.start_port > a.end_port:
            p.error("invalid port range")
        scan(a.host, a.start_port, a.end_port, a.timeout)
    else:
        if not 1 <= a.count <= 200 or not 0 <= a.interval <= 2:
            p.error("count must be 1..200 and interval 0..2 seconds")
        burst(a.host, a.port, a.count, a.interval, a.timeout)

if __name__ == "__main__":
    main()
