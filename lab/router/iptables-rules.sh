#!/bin/bash
# -----------------------------------------------------------------------------
# router/iptables-rules.sh
#
# Configures the firewall rules that the attack is designed to bypass.
#
# Core rule: DROP TCP traffic to port 7777 on the victim (10.0.2.20).
# This simulates a standard stateless packet filter blocking a protected service.
#
# The length filter (40-100 bytes) targets standard TCP SYN packets, which fall
# in this range. The crafted attack fragments carry only partial TCP headers and
# fall outside this range — this is one of the structural gaps the attack exploits.
# -----------------------------------------------------------------------------

# Flush all existing rules
iptables -F
iptables -t nat -F

# Default policy: ACCEPT (selective DROP)
iptables -P FORWARD ACCEPT

# Core rule: drop TCP SYN packets to port 7777 on the victim
# Length filter targets complete SYN packets (40-100 bytes)
iptables -A FORWARD -p tcp --dport 7777 -d 10.0.2.20 -m length --length 40:100 -j DROP

# Allow established and related traffic
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[+] Firewall rules applied."
echo "    FORWARD chain:"
iptables -L FORWARD -v
