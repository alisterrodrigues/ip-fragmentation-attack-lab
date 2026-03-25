#!/usr/bin/env python3
"""
verify_attack.py

Verifies whether the overlapping fragment attack successfully bypassed
the firewall by attempting a direct TCP connection to the previously
blocked port.

A successful connection with data exchange confirms that the fragmentation
attack established a session the iptables state table now recognizes,
permitting follow-on traffic to the previously blocked port.

Usage:
  python3 verify_attack.py <target_ip> [target_port]

Exit codes:
  0 — connection succeeded (attack confirmed)
  1 — connection failed
"""

import socket
import sys
import time


def test_connection(host: str, port: int, message: str = "Test message") -> bool:
    """
    Attempt a TCP connection to the target and exchange data.
    Returns True on success, False on failure.
    """
    # Brief wait to allow fragment reassembly to complete at the target
    print("[*] Waiting for fragment reassembly to complete...")
    time.sleep(5)

    print(f"[*] Attempting connection to {host}:{port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        print(f"[+] Connected to {host}:{port} — firewall bypass confirmed.")

        s.sendall(message.encode())
        print(f"[>] Sent:     {message}")

        response = s.recv(1024)
        print(f"[<] Received: {response.decode('utf-8').strip()}")

        s.close()
        return True

    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("[!] Attack may not have succeeded — check fragment delivery and reassembly.")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> [target_port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 7777

    success = test_connection(target_ip, target_port)
    sys.exit(0 if success else 1)
