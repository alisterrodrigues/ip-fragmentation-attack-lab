#!/bin/bash
# -----------------------------------------------------------------------------
# victim/setup.sh
# Configures default routing and starts the TCP server on port 7777.
# -----------------------------------------------------------------------------

ip route del default 2>/dev/null
ip route add default via 10.0.2.5
ethtool -K eth0 rx off tx off gso off gro off tso off sg off 2>/dev/null

echo "[+] Victim container ready."
echo "    IP: $(hostname -I)"
echo "    Routes:"
ip route

python3 /server.py &

tail -f /dev/null
