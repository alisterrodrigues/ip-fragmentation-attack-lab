#!/bin/bash
# -----------------------------------------------------------------------------
# router/setup.sh
# Enables IP forwarding and applies iptables firewall rules.
# -----------------------------------------------------------------------------

echo 1 > /proc/sys/net/ipv4/ip_forward
bash /iptables-rules.sh

echo "[+] Router container ready."
echo "    Interfaces:"
ip addr show
echo "    Routes:"
ip route

tail -f /dev/null
