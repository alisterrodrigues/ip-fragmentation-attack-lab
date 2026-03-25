# IP Fragmentation Attack Lab

<p align="center">
  <img src="https://img.shields.io/badge/Attack_Type-Overlapping_Fragment-critical?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Tool-Scapy-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Tool-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Tool-Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/Tool-iptables-EE0000?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
</p>

---

## What This Is

A fully reproducible network security lab demonstrating how **overlapping IP fragment attacks** can bypass stateless packet filtering — the kind of firewall rule that still protects a significant portion of real-world networks, particularly in legacy and small-enterprise environments.

The core insight: stateless firewalls inspect individual packets in isolation, not reassembled connections. By splitting a TCP header across multiple crafted IP fragments with overlapping offsets, the destination port field — the exact field the firewall rule keys on — is never present intact in any single fragment the firewall sees. The fragments pass. The victim reassembles them into a valid TCP SYN. The firewall never knew.

This lab builds the entire attack environment from scratch using Docker, executes the attack with a custom Scapy script, and captures every stage of traffic with tcpdump and Wireshark to prove the bypass end-to-end.

---

## The Attack in Plain Terms

A firewall is configured to block all TCP connections to port 7777 on the victim. Rather than sending a standard SYN packet — which the firewall drops — the attacker crafts three IP fragments sharing the same IP identification number:

- **Fragment 1** carries only the first 2 bytes of the TCP header (source port). The destination port is absent. The firewall sees no port 7777, applies no rule, and forwards the fragment.
- **Fragment 2** overlaps Fragment 1 at offset 1 and carries the remainder of the TCP header — but with the destination port rewritten to appear as port 80 (HTTP). Since this arrives as a continuation fragment, the firewall does not inspect it for port information.
- **Fragment 3** carries the payload and completes the fragment set.

At the victim, the Linux kernel reassembles all three fragments according to RFC 791. Because Linux favors earlier fragment data when overlaps conflict, the original bytes from Fragment 1 are preserved — and the destination port in the reassembled packet is 7777. The TCP SYN arrives. The victim responds with a SYN-ACK. The connection is established through a firewall that never registered the traffic as matching its DROP rule.

---

## Network Topology

```
+------------------------------------------------------------------+
|  Attack Network: 10.0.3.0/24        Victim Network: 10.0.2.0/24 |
|                                                                   |
|  +-------------+   10.0.3.5   10.0.2.5   +------------------+   |
|  |  Attacker   +-------->[Router/FW]-------->| Victim Server  |   |
|  |  10.0.3.20  |                           |  10.0.2.20     |   |
|  +-------------+                           |  TCP :7777     |   |
|                                            +------------------+   |
|                 Firewall Rule:                                    |
|                 DROP tcp --dport 7777 -d 10.0.2.20               |
+------------------------------------------------------------------+

Attack: [ Frag 1 ] --> [ Frag 2 (overlap) ] --> [ Frag 3 (payload) ]
```

| Container | IP | Role |
|---|---|---|
| Attacker | 10.0.3.20 | Crafts and sends fragmented packets via Scapy |
| Router/Firewall | 10.0.3.5 / 10.0.2.5 | iptables DROP rule on TCP:7777; routes between networks |
| Victim | 10.0.2.20 | Runs TCP server on port 7777 — should be unreachable |

---

## Vulnerabilities Demonstrated

**1. Stateless Fragment Inspection**
The iptables DROP rule fires only when a complete TCP header with a destination port field is present. Fragment 1 carries only 2 bytes of TCP header — no destination port — and passes the rule without triggering it. Subsequent fragments are forwarded as continuations without re-inspection.

**2. OS Fragment Reassembly Behavior**
Linux's IP reassembly implementation (RFC 791) favors earlier fragment data when overlapping fragments conflict. Fragment 2 overlaps Fragment 1 and carries a rewritten destination port (80), but because Fragment 1 arrived first, the original 2 bytes are preserved in the reassembled output. The final packet has destination port 7777 — exactly as the attacker intended.

**3. TCP Header Split Across Fragment Boundary**
By calculating fragment offsets so that the destination port field spans the boundary between Fragment 1 and Fragment 2, the port number is never present and unambiguous in any single fragment during transit. There is nothing for the stateless filter to match against.

---

## Repository Structure

```
ip-fragmentation-attack-lab/
├── README.md
├── report/
│   └── IP_Fragmentation_Attack_Analysis.md
└── lab/
    ├── docker-compose.yml
    ├── requirements.txt
    ├── attacker/
    │   ├── Dockerfile
    │   └── setup.sh
    ├── router/
    │   ├── Dockerfile
    │   ├── setup.sh
    │   └── iptables-rules.sh
    ├── victim/
    │   ├── Dockerfile
    │   ├── setup.sh
    │   └── server.py
    └── shared/
        ├── overlapping_fragmentation_attack.py
        ├── verify_attack.py
        └── monitor.sh
```

---

## Running the Lab

### Prerequisites

- Docker and Docker Compose installed
- Linux host (tested on Ubuntu 22.04 / SEED Ubuntu VM)
- `NET_ADMIN` and `NET_RAW` capabilities available

### Step 1 — Build and Start Containers

```bash
cd lab/
docker-compose build
docker-compose up -d
```

### Step 2 — Verify the Firewall is Blocking

```bash
docker exec router iptables -L FORWARD -v -n
docker exec attacker nc -zv 10.0.2.20 7777
```

Expected: `Connection timed out` — the DROP rule is active.

### Step 3 — Start Traffic Monitor (Separate Terminal)

```bash
docker exec router bash /shared/monitor.sh
```

### Step 4 — Execute the Attack

```bash
docker exec attacker python3 /shared/overlapping_fragmentation_attack.py 10.0.2.20 7777
```

Expected output:
```
[+] Confirmed: 10.0.2.20:7777 is blocked by firewall. Proceeding with attack.
[*] Starting overlapping fragment attack -> 10.0.2.20:7777
[*] Sending Fragment 1 — partial TCP header (no destination port)
[*] Sending Fragment 2 — overlapping TCP header (dst port rewritten to 80)
[*] Sending Fragment 3 — payload
[+] All fragments sent.
```

### Step 5 — Verify the Bypass

```bash
docker exec attacker python3 /shared/verify_attack.py 10.0.2.20 7777
```

Expected output:
```
[*] Waiting for fragment reassembly to complete...
[*] Attempting connection to 10.0.2.20:7777
[+] Connected to 10.0.2.20:7777 — firewall bypass confirmed.
[>] Sent:     Test message
[<] Received: Message received
```

The iptables DROP rule is still active. The connection succeeded anyway.

### Step 6 — Check Victim Logs

```bash
docker logs -f victim
```

---

## What the Traffic Looks Like

From the router's tcpdump capture during attack execution:

```
# Fragment 1 — partial TCP header, no destination port present
IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag XXXX:8@0+)

# Fragment 2 — overlapping at offset 8, carries rewritten port 80
IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag XXXX:16@8+)

# Fragment 3 — payload, last fragment
IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag XXXX:32@24)

# Reassembled SYN arrives at victim — destination port 7777
IP 10.0.3.20 > 10.0.2.20: Flags [S], seq 1000:1020, length 20

# Victim responds — bypass complete
IP 10.0.2.20.7777 > 10.0.3.20.XXXXX: Flags [S.], seq 2000, ack 1021
```

The SYN-ACK from port 7777 is proof. The firewall rule never fired.

---

## Defensive Mitigations

| Mitigation | How It Addresses This Attack |
|---|---|
| **Stateful fragment inspection** | Tracks all fragments of a flow before forwarding; reassembles and inspects the full TCP header |
| **Virtual Fragment Reassembly (VFR)** | Firewall reconstructs the packet in memory and applies rules to the complete reassembled header |
| **Fragment timeout tuning** | Drops incomplete fragment sets that linger, preventing cache poisoning variants |
| **Path MTU Discovery enforcement** | Reduces legitimate fragmentation, making crafted fragments more anomalous and detectable |
| **Defense-in-depth segmentation** | Limits blast radius if a perimeter control is bypassed — no single inspection point is the last line |
| **OS and kernel patching** | Modern kernels implement stricter fragment validation policies at the reassembly level |

The core lesson: **stateless packet filtering is not a firewall**. It is a traffic filter. These are different security guarantees. Any environment relying solely on iptables rules without stateful inspection is potentially vulnerable to this class of attack.

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| **Scapy** | Crafting raw IP fragments with precise offset control |
| **Docker / Docker Compose** | Isolated multi-container network lab environment |
| **iptables** | Stateless firewall simulation on the router container |
| **tcpdump** | Real-time packet capture during attack execution |
| **Wireshark / PCAP** | Post-capture analysis of reassembled packets |
| **Python 3** | Attack scripting and connection verification |
| **netcat** | Initial firewall verification |

---

## Full Technical Analysis

> **[→ Read the Full Technical Report](./report/IP_Fragmentation_Attack_Analysis.md)**

Covers the complete attack breakdown, fragment-by-fragment packet analysis, Wireshark evidence, vulnerability analysis, and defensive recommendations.

---

*Developed by Alister A. Rodrigues. All testing conducted in an isolated lab environment. This work is intended for defensive security research and education.*
