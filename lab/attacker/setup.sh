#!/bin/bash
# -----------------------------------------------------------------------------
# attacker/setup.sh
# Configures routing and disables NIC offloading on the attacker container.
# -----------------------------------------------------------------------------

ip route del default 2>/dev/null
ip route add 10.0.2.0/24 via 10.0.3.5
ethtool -K eth0 rx off tx off gso off gro off tso off sg off 2>/dev/null

echo "[+] Attacker container ready."
echo "    IP: $(hostname -I)"
echo "    Routes:"
ip route

tail -f /dev/null
