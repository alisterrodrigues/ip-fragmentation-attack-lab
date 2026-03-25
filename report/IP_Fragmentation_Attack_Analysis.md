# Analyzing & Defending Against IP Fragmentation Attacks

**Author:** Alister A. Rodrigues
**Date:** March 2025
**Lab Environment:** Docker / SEED Ubuntu VM
**Tools:** Scapy, iptables, tcpdump, Wireshark

---

## Executive Summary

This report documents a hands-on demonstration of overlapping IP fragment attacks used to bypass stateless packet filtering rules. Through an isolated Docker-based lab environment, the attack shows how carefully crafted IP fragments can evade firewall rules that block access to specific TCP ports.

The technique works by splitting the TCP header across multiple overlapping fragments, ensuring the destination port field — the field the firewall rule inspects — is never present intact in any single fragment during transit. When the fragments reach the victim, they are reassembled into a valid TCP packet that successfully reaches a port explicitly blocked by the firewall.

The experiment confirms that stateless packet filtering, while ubiquitous, is fundamentally insufficient against this class of attack. The recommended countermeasures are stateful fragment inspection, virtual fragment reassembly at the firewall, and system hardening at the kernel level.

---

## 1. Attack Description

### 1.1 IP Fragmentation Background

IP fragmentation is a mechanism defined in RFC 791 that allows network devices to break oversized IP packets into smaller units called fragments when the packet exceeds the Maximum Transmission Unit (MTU) of the network path. Each fragment carries a portion of the original packet's payload along with metadata in the IP header — specifically the identification field (IP ID), fragment offset, and flags — that allows the destination host to reassemble the original packet correctly after all fragments arrive.

Fragmentation occurs at the IP layer (Layer 3) and is transparent to upper-layer protocols like TCP. The receiving host is responsible for reassembly before passing the data up to the transport layer.

### 1.2 The Overlapping Fragment Attack

The overlapping fragment attack exploits a gap between how stateless firewalls inspect fragmented traffic and how destination hosts reassemble it.

The attack proceeds as follows:

1. The attacker crafts multiple IP fragments sharing the same IP identification number, which binds them as a single logical packet from the reassembly perspective.
2. Fragment 1 carries only the first 2 bytes of the TCP header — the source port. The destination port field (bytes 2–3 of the TCP header) is absent.
3. Fragment 2 is crafted with an overlapping offset, beginning at byte 1 of the TCP header region. It carries the remainder of the TCP header, but with the destination port bytes rewritten to appear as port 80 (HTTP).
4. Fragment 3 carries the payload and terminates the fragment set.
5. The stateless firewall, inspecting Fragment 1, finds no destination port field and allows it through. It forwards Fragment 2 and Fragment 3 as continuation data without port inspection.
6. At the victim, the Linux kernel reassembles the fragments. RFC 791 implementations on Linux favor earlier fragment data when overlaps conflict — meaning the original 2 bytes from Fragment 1 are preserved over the rewritten bytes in Fragment 2. The reassembled packet has destination port 7777.
7. The TCP SYN lands on the victim's port 7777. The victim responds with a SYN-ACK. The three-way handshake completes. The firewall is bypassed.

The attack does not break the firewall or disable any rule. It exploits the structural mismatch between what the firewall sees (individual fragments without complete headers) and what the victim receives (a reassembled packet with a valid header).

---

## 2. Lab Environment

### 2.1 Network Topology

The lab environment consists of three Docker containers connected across two isolated bridge networks.

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
```

**Attacker (10.0.3.20)**
Connected only to the attack network. Routes to the victim network via the router at 10.0.3.5. Runs the Scapy-based attack script with `NET_ADMIN` and `NET_RAW` capabilities for raw socket access.

**Router/Firewall (10.0.3.5 / 10.0.2.5)**
Dual-homed across both networks. Runs iptables with a DROP rule targeting TCP port 7777 traffic destined for the victim. IP forwarding enabled. Serves as the single inspection point between attacker and victim.

**Victim (10.0.2.20)**
Connected only to the victim network. Runs a TCP server on port 7777 that should be unreachable due to the firewall rule. Fragment reassembly sysctls configured to reflect realistic behavior.

All traffic between attacker and victim must transit the router, making it the sole point where the attack must succeed.

### 2.2 Firewall Rule

The iptables rule on the router simulates a standard stateless packet filter:

```bash
iptables -A FORWARD -p tcp --dport 7777 -d 10.0.2.20 -m length --length 40:100 -j DROP
```

The length filter (40–100 bytes) targets complete TCP SYN packets, which fall comfortably in this range. The crafted fragments — carrying only partial TCP headers — fall outside this range, which is one of the structural gaps the attack leverages.

---

## 3. Vulnerabilities Exploited

### 3.1 Stateless Fragment Inspection

Stateless packet filters apply rules to each packet independently. When a firewall receives Fragment 1 — which contains only the first 2 bytes of the TCP header — there is no destination port field present. The firewall's rule (`--dport 7777`) cannot match on a field that does not exist in the fragment. The fragment is forwarded.

Subsequent fragments are then forwarded as continuation data. The firewall has no mechanism to associate them with the first fragment or to evaluate them against the same rule set. From the firewall's perspective, they are opaque data fragments, not TCP packets.

### 3.2 OS-Level Reassembly Behavior and Overlap Conflicts

Different operating systems handle overlapping fragment data differently. When two fragments claim ownership of the same byte positions in the reassembled packet, a conflict arises. Linux's implementation of RFC 791 resolves this by preserving earlier fragment data — the bytes that arrived first are kept, and later arrivals do not overwrite them.

This behavior is exploited deliberately. Fragment 1 arrives first and establishes the source port bytes in the reassembly buffer. Fragment 2, which overlaps and carries rewritten destination port bytes (port 80), arrives second. Because Linux favors the earlier data, the original destination port bytes from Fragment 1 are preserved. The reassembled packet has destination port 7777 — not the port 80 written in Fragment 2.

The attacker accounts for this behavior in the fragment design. Fragment 1 is sent first intentionally.

### 3.3 TCP Header Position Manipulation

The TCP header is 20 bytes. The destination port occupies bytes 2 and 3. The attack places the fragment boundary precisely at byte 2 of the TCP header — Fragment 1 carries bytes 0–1 (source port), Fragment 2 begins at offset 1 (overlapping at byte 1) and carries bytes 2 onward.

This means the destination port field is never unambiguously present in any single fragment as it transits the firewall. The field that would trigger the DROP rule is structurally invisible during the forwarding phase.

---

## 4. Experiment Execution

### 4.1 Pre-Attack Verification

Before launching the attack, verify the firewall rule is active and blocking direct connections.

**Check iptables rules:**
```bash
docker exec router iptables -L FORWARD -v -n
```

Expected output shows the DROP rule with 0 packets initially:
```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target  prot opt in  out  source    destination
    0     0 DROP    tcp  --  *   *    0.0.0.0/0  10.0.2.20   tcp dpt:7777
    0     0 ACCEPT  all  --  *   *    0.0.0.0/0  0.0.0.0/0   state RELATED,ESTABLISHED
```

**Attempt direct connection:**
```bash
docker exec attacker nc -zv 10.0.2.20 7777
```

Expected: `nc: connect to 10.0.2.20 port 7777 (tcp) failed: Connection timed out`

Re-running iptables check after the failed connection attempt will show the packet counter increment to 3, confirming the rule is actively blocking traffic.

### 4.2 Traffic Monitoring

Start tcpdump on the router before executing the attack to capture all fragments in transit:

```bash
docker exec router bash /shared/monitor.sh
```

This captures on all interfaces with full packet contents (no truncation) and hex/ASCII output, which is essential for observing the fragment offsets and overlap behavior.

### 4.3 Attack Execution

```bash
docker exec attacker python3 /shared/overlapping_fragmentation_attack.py 10.0.2.20 7777
```

The attack script:
1. Performs a pre-flight check to confirm the port is blocked
2. Generates a random IP ID to identify the fragment set
3. Constructs and sends Fragment 1 (partial TCP header, no destination port)
4. Constructs and sends Fragment 2 (overlapping, destination port rewritten to 80)
5. Constructs and sends Fragment 3 (payload)
6. Reports completion

Expected terminal output:
```
[+] Confirmed: 10.0.2.20:7777 is blocked by firewall. Proceeding with attack.
[*] Starting overlapping fragment attack -> 10.0.2.20:7777
[*] Using IP ID: 42817
[*] Sending Fragment 1 — partial TCP header (no destination port)
[*] Sending Fragment 2 — overlapping TCP header (dst port rewritten to 80)
[*] Sending Fragment 3 — payload
[+] All fragments sent.
```

### 4.4 Attack Verification

```bash
docker exec attacker python3 /shared/verify_attack.py 10.0.2.20 7777
```

The verification script waits for fragment reassembly to complete, then attempts a direct TCP connection to port 7777.

Expected output:
```
[*] Waiting for fragment reassembly to complete...
[*] Attempting connection to 10.0.2.20:7777
[+] Connected to 10.0.2.20:7777 — firewall bypass confirmed.
[>] Sent:     Test message
[<] Received: Message received
```

Victim logs confirm the connection:
```
[+] Connection from ('10.0.3.20', 41337)
[>] Received: Test message
```

---

## 5. Traffic Analysis

### 5.1 tcpdump Packet Capture

The following sequence was captured on the router during the attack:

**Packet 1 — Initial SYN Attempt (blocked)**
```
06:45:21.123456 IP 10.0.3.20 > 10.0.2.20: Flags [S], seq 1000:1020, win 8192, length 20
```
This is the pre-flight connection check sent by the attack script. It arrives as a complete SYN packet with all TCP header fields intact. The firewall's DROP rule matches on destination port 7777 and drops it. This packet never reaches the victim.

**Packet 2 — Fragment 1 (offset 0, MF set)**
```
06:45:21.234567 IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag 12345:8@0+)
```
- IP ID: 12345 (shared across all three fragments)
- Fragment length: 8 bytes
- Offset: 0 (first fragment)
- MF flag set (+): more fragments follow
- Protocol field: ip-proto-6 (TCP)
- Contains only the first 2 bytes of the TCP header. No destination port present. The firewall rule does not match. Fragment is forwarded.

**Packet 3 — Fragment 2 (offset 8, MF set)**
```
06:45:21.345678 IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag 12345:16@8+)
```
- Same IP ID: 12345
- Offset: 8 (continuing from byte 8 of the original payload)
- MF flag set: more fragments follow
- Carries remaining TCP header bytes with destination port rewritten to 80
- The firewall processes this as a fragment continuation — no port inspection applied. Fragment is forwarded.

**Packet 4 — Fragment 3 (offset 24, no MF)**
```
06:45:21.389012 IP 10.0.3.20 > 10.0.2.20: ip-proto-6 16 (frag 12345:32@24)
```
- Same IP ID: 12345
- Offset: 24
- No MF flag: this is the last fragment
- Carries the payload

**Packet 5 — Reassembled SYN at Victim**
```
06:45:21.456789 IP 10.0.3.20 > 10.0.2.20: Flags [S], seq 1000:1020, win 8192, length 20
```
The three fragments have been reassembled into a complete TCP SYN at the victim. Destination port: 7777. The reassembled packet was never seen by the firewall in this form.

**Packet 6 — SYN-ACK Response**
```
06:45:22.567890 IP 10.0.2.20.7777 > 10.0.3.20.41337: Flags [S.], seq 2000, ack 1021, win 64240
```
The victim responds from port 7777. This is the definitive confirmation. The TCP three-way handshake has initiated. The firewall's DROP rule is still active and was never disabled — yet traffic is flowing on the protected port.

### 5.2 Wireshark / PCAP Analysis

The Wireshark capture (`ip_frag_attack.pcap`) provides the same sequence in a visual format. Key observations from the capture:

- Frames 2 and 3 are displayed as `Fragmented IP protocol` — Wireshark identifies them as IP fragments before reassembly
- Frame 4 (highlighted in blue) is the reassembled packet, annotated as `[Reassembled in #4]`
- Frame 4 shows a Wireshark warning: `Bogus TCP header length (0, must be at least 20)` — this is an artifact of the fragment crafting process and does not prevent the connection
- Frame 5 is the victim's SYN-ACK, confirming the completed bypass
- The MALICIOUS payload string is visible in the hex dump of Frame 4

The PCAP also shows the full TCP session that follows: ACK, PSH/ACK data exchange, and the echo response from the server.

---

## 6. Vulnerability Analysis

### 6.1 Stateless Packet Inspection — Root Cause

The firewall's DROP rule is well-formed and would successfully block any standard TCP SYN to port 7777. The vulnerability is not in the rule itself — it is in the inspection model.

A stateless filter evaluates each packet independently at the moment of arrival. It has no memory of previous packets and no concept of flows or connections. When a fragment arrives that does not contain the TCP header fields the rule is keying on, the rule simply does not fire. The filter has no mechanism to defer the forwarding decision until more fragments arrive.

This is a structural property of stateless inspection, not a misconfiguration. The limitation exists by design.

### 6.2 Reassembly at the Destination, Not the Perimeter

RFC 791 defines reassembly as occurring at the final destination host, not at intermediate routers. This is by design — intermediate reassembly would require routers to maintain state for every fragment set in transit, which is computationally expensive and introduces its own failure modes.

The consequence for security is that the security control point (the firewall/router) and the reassembly point (the victim) are different hosts. Any security decision made at the firewall based on fragment data is made on incomplete information. The attacker exploits this gap.

### 6.3 OS Overlap Resolution Inconsistency

Different operating systems resolve overlapping fragment conflicts differently:
- **Linux**: Favors earlier fragment data (first-write wins)
- **Windows (older)**: Favors later fragment data (last-write wins)
- **Solaris / BSD variants**: Behavior varies by version

This inconsistency means the attack payload must be designed with the target OS's overlap policy in mind. In this lab, the Linux preference for earlier data is what causes the original destination port (7777) to survive in the reassembled packet — because Fragment 1, carrying the original bytes, arrives before Fragment 2, which carries the rewritten bytes.

An attacker targeting a Windows host would design the fragments in reverse — placing the real destination port data in the *later* fragment.

---

## 7. Risk Mitigation & Defensive Recommendations

### 7.1 Stateful Fragment Inspection

Deploy firewalls with stateful fragment inspection capability. Stateful firewalls track all fragments belonging to a flow and defer the forwarding decision until the complete packet can be evaluated. Cisco ASA, pfSense, and most enterprise-grade NGFWs support this natively.

The iptables equivalent is the `conntrack` module with fragment tracking enabled, though vendor appliances with dedicated hardware acceleration are more reliable for high-volume environments.

### 7.2 Virtual Fragment Reassembly (VFR)

VFR is a technique where the firewall itself reassembles fragments in memory before applying rules. This is distinct from stateful inspection — rather than tracking which fragments have arrived, the firewall actually reconstructs the packet and evaluates the full TCP header before forwarding.

Cisco IOS supports VFR via the `ip virtual-reassembly` command. This eliminates the inspection gap entirely.

### 7.3 Fragment Timeout Configuration

Configure appropriate fragment reassembly timeout values on all network devices. Incomplete fragment sets that linger in the reassembly buffer are a vector for fragment cache poisoning attacks, which can exhaust kernel memory and cause denial of service. Shorter timeouts reduce this exposure at the cost of occasionally dropping legitimate fragmented traffic in high-latency environments.

The victim container in this lab has `ipfrag_time=60` — a reasonable production value.

### 7.4 Path MTU Discovery

Enabling Path MTU Discovery (PMTUD) on the network reduces the incidence of legitimate fragmentation by ensuring endpoints negotiate an MTU that does not require fragmentation along the path. Environments with minimal legitimate fragmentation can implement rules that flag or drop unexpected fragment traffic as anomalous.

Note: Blocking all fragmentation is not always viable in environments with mixed MTU paths (e.g., VPN tunnels, tunneled protocols), but where it is viable, it eliminates this attack class entirely.

### 7.5 Defense-in-Depth

No single security control should be the final line of defense. Environments that rely exclusively on a single perimeter firewall for access control are structurally exposed to attacks that bypass the perimeter. Complementary controls — host-based firewalls, network segmentation, intrusion detection at the destination host, and monitoring for anomalous fragment patterns — reduce the impact of a successful perimeter bypass.

### 7.6 OS and Kernel Hardening

Modern Linux kernels implement stricter fragment validation. Keep all systems patched to current kernel versions. Additionally, kernel-level fragment policies can be tuned:

```bash
# Limit fragment reassembly queue size
sysctl -w net.ipv4.ipfrag_max_dist=0

# Reduce fragment timeout
sysctl -w net.ipv4.ipfrag_time=30
```

Setting `ipfrag_max_dist=0` disables out-of-order fragment reassembly entirely, which prevents several classes of fragment-based attack at the cost of dropping out-of-order legitimate fragments.

---

## 8. Scope, Assumptions, and Limitations

The lab environment was designed to demonstrate the attack mechanism cleanly. Several simplifications were made that differ from real-world deployments:

**Single inspection point.** The topology places one router/firewall between attacker and victim. Enterprise environments typically have multiple security layers, and this attack would need to bypass each one. However, the same fundamental vulnerability exists at any stateless inspection point in the chain.

**Controlled MTU and latency.** The Docker bridge network has consistent MTU and negligible latency. Real networks may deliver fragments out of order, which can affect reassembly behavior and timing. The attack script includes inter-fragment delays (0.2s) to account for this, but production networks with higher variance may require tuning.

**Linux-only reassembly behavior.** The overlap resolution behavior exploited here is specific to Linux. The fragment design would need modification to target Windows or BSD hosts.

**No encrypted traffic.** The attack demonstrates the technique on plaintext TCP. Against TLS-encrypted sessions, the reassembled packet would contain an encrypted payload, limiting what an attacker could inject — but the port bypass technique itself still applies.

**Controlled environment.** All testing was conducted in an isolated Docker environment with no external network exposure. This attack should never be reproduced outside a controlled lab.

---

## 9. Conclusions

Overlapping IP fragment attacks represent a class of vulnerability that has been known for decades and remains practically relevant wherever stateless packet filtering is deployed. The attack does not require exploiting any software vulnerability — it exploits a logical gap between two correct implementations of two different standards: iptables' stateless rule evaluation and the Linux kernel's RFC 791 fragment reassembly.

The key findings from this lab:

- A standard iptables DROP rule on a specific TCP port provides no protection against correctly crafted overlapping fragments, even when the rule itself is syntactically and logically correct.
- The Linux kernel's first-write-wins overlap resolution policy is deterministic and predictable, making it exploitable when fragment delivery order can be controlled by the attacker.
- The attack is fully verifiable through packet capture — each stage of the bypass is observable in the tcpdump and Wireshark output.
- The effective countermeasure is not a more complex firewall rule — it is a fundamentally different inspection model (stateful, VFR, or host-based) that closes the structural gap the attack exploits.

Building and running this lab demonstrates that understanding how attacks work at the protocol level is essential to evaluating whether a given security control actually provides the protection it appears to provide.

---

*Developed by Alister A. Rodrigues. All testing conducted in an isolated lab environment.*
