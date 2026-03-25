#!/usr/bin/env python3
"""
victim/server.py

A lightweight TCP server listening on port 7777.
Logs all incoming connections and echoes a confirmation to each sender.

This server represents a protected service that should be unreachable
through the router's iptables rules — until the fragmentation attack
successfully bypasses the firewall and establishes a connection.
"""

import socket
import threading


def handle_client(client_socket: socket.socket, addr: tuple) -> None:
    """Handle an incoming client connection in a dedicated thread."""
    print(f"[+] Connection from {addr}")
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"[>] Received: {data.decode('utf-8')}")
            client_socket.send(b"Message received\n")
    except Exception as e:
        print(f"[-] Error handling {addr}: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection from {addr} closed.")


def start_server(port: int) -> None:
    """Bind and listen on the specified port, spawning a thread per connection."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[*] Server listening on port {port}")
    try:
        while True:
            client, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client, addr))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    PORT = 7777
    start_server(PORT)
