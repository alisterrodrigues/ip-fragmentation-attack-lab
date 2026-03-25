#!/bin/bash
# -----------------------------------------------------------------------------
# shared/monitor.sh
#
# Runs tcpdump on the router to capture all traffic to/from the victim's
# port 7777. Start this before launching the attack to observe fragmented
# packets in transit and the reassembled SYN that bypasses the firewall.
#
# Run from the host:
#   docker exec router bash /shared/monitor.sh
#
# tcpdump flags:
#   -n        Do not resolve IP addresses to hostnames
#   -i any    Capture on all interfaces (both attack_net and victim_net sides)
#   -s 0      Capture full packet contents without truncation
#   -X        Display hex + ASCII dump of each packet
# -----------------------------------------------------------------------------

TARGET_IP="10.0.2.20"
TARGET_PORT="7777"

echo "[*] Starting traffic monitor on router"
echo "    Capturing: host ${TARGET_IP} and tcp port ${TARGET_PORT}"
echo "    Press Ctrl+C to stop"
echo ""

tcpdump -n -i any -s 0 -X "host ${TARGET_IP} and tcp port ${TARGET_PORT}"
