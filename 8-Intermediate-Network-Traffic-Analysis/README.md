# 🛡️ INTERMEDIATE NETWORK TRAFFIC ANALYSIS

## SOC Analyst Cheatsheet - Module 8/15

---

## 0. Overview

> 📌 **Intermediate Network Traffic Analysis** - Advanced techniques for analyzing attacks across network layers (Link, IP, Transport, Application).

### Why This Module Matters

In today's complex network environments, mastering traffic analysis is essential:
- Overwhelming volume of traffic traversing networks
- Attacks spanning multiple layers
- Need to detect patterns and trends

### What We'll Cover

| Layer | Attack Types |
|-------|--------------|
| **Link Layer** | ARP attacks, MAC flooding |
| **IP Layer** | IP fragmentation, TTL manipulation |
| **Transport Layer** | TCP attacks, port scanning, DoS |
| **Application Layer** | DNS tunneling, HTTP attacks |

### Additional Skills

- Anomaly detection techniques
- Log analysis
- Indicators of Compromise (IOCs)
- Proactive threat identification
- Reactive incident response

> 🔴 **Note:** Download pcap_files.zip from Resources section for hands-on exercises.

### PCAP Files Included

```bash
wget -O file.zip 'https://academy.hackthebox.com/storage/resources/pcap_files.zip' && mkdir tempdir && unzip file.zip -d tempdir && mkdir -p pcaps && mv tempdir/Intermediate_Network_Traffic_Analysis/* pcaps/ && rm -r tempdir file.zip
```

**PCAP Files List:**

| File | Description |
|------|-------------|
| ARP_Poison.pcapng | ARP Poisoning |
| ARP_Scan.pcapng | ARP Scanning |
| ARP_Spoof.pcapng | ARP Spoofing |
| basic_fuzzing.pcapng | Fuzzing Attacks |
| CRLF_and_host_header_manipulation.pcapng | HTTP Header Injection |
| deauthandbadauth.cap | WiFi Deauth + Bad Auth |
| decoy_scanning_nmap.pcapng | Nmap Decoy Scan |
| dns_enum_detection.pcapng | DNS Enumeration Detection |
| dns_tunneling.pcapng | DNS Tunneling |
| funky_dns.pcap | DNS Anomalies |
| funky_icmp.pcap | ICMP Anomalies |
| icmp_frag.pcapng | ICMP Fragmentation |
| ICMP_rand_source.pcapng | ICMP Random Source |
| ICMP_rand_source_larg_data.pcapng | ICMP Large Data |
| ICMP_smurf.pcapng | Smurf Attack |
| icmp_tunneling.pcapng | ICMP Tunneling |
| ip_ttl.pcapng | IP TTL Manipulation |
| LAND-DoS.pcapng | LAND DoS Attack |
| nmap_ack_scan.pcapng | Nmap ACK Scan |
| nmap_fin_scan.pcapng | Nmap FIN Scan |
| nmap_frag_fw_bypass.pcapng | Nmap Fragmentation Bypass |
| nmap_null_scan.pcapng | Nmap NULL Scan |
| nmap_syn_scan.pcapng | Nmap SYN Scan |
| nmap_xmas_scan.pcapng | Nmap XMAS Scan |
| number_fuzzing.pcapng | Number Fuzzing |
| rogueap.cap | Rogue Access Point |
| RST_Attack.pcapng | TCP RST Attack |
| SSL_renegotiation_edited.pcapng | SSL Renegotiation |
| TCP-hijacking.pcap | TCP Hijacking |
| TCP_rand_source_attacks.pcapng | TCP Random Source |
| telnet_tunneling_23.pcapng | Telnet Tunneling |
| telnet_tunneling_9999.pcapng | Telnet Tunneling (9999) |
| telnet_tunneling_ipv6.pcapng | Telnet over IPv6 |
| udp_tunneling.pcapng | UDP Tunneling |
| XSS_Simple.pcapng | XSS Attack |

---

## Table of Contents

1. [Overview](#0-overview)
2. [Link Layer Attacks](#1-link-layer-attacks)
3. [Network Layer Attacks](#2-network-layer-attacks)
4. [Transport Layer Attacks](#3-transport-layer-attacks)
5. [Application Layer Attacks](#4-application-layer-attacks)
6. [Detection Techniques](#5-detection-techniques)
7. [Interview Questions](#6-interview-questions)
8. [Additional Resources](#7-additional-resources)

---

## 1. Link Layer Attacks

*Coming soon...*

---

## 2. Network Layer Attacks

*Coming soon...*

---

## 3. Transport Layer Attacks

*Coming soon...*

---

## 4. Application Layer Attacks

*Coming soon...*

---

## 5. Detection Techniques

*Coming soon...*

---

## 6. Interview Questions

### Q1: What is ARP spoofing and how do you detect it?

**Answer:** ARP spoofing is a link layer attack where an attacker sends falsified ARP messages to link their MAC address with a legitimate IP address. Detection involves monitoring for ARP packets with duplicate MAC addresses or inconsistent IP-MAC mappings.

---

### Q2: How do you detect a port scan?

**Answer:** Look for patterns like multiple SYN packets to different ports from single source, unusual flag combinations (NULL, FIN, XMAS scans), and high volume of connection attempts to different destinations.

---

### Q3: What is DNS tunneling?

**Answer:** DNS tunneling encodes data in DNS queries/responses to bypass firewalls. Look for unusual DNS query patterns, large DNS responses, and non-standard record types.

---

### Q4: What is the difference between TCP SYN scan and TCP ACK scan?

**Answer:** SYN scan (half-open) sends SYN, expects SYN-ACK if port open. ACK scan sends ACK, expects RST regardless of port state - used to map firewall rules.

---

### Q5: What is ICMP tunneling?

**Answer:** ICMP tunneling encapsulates data within ICMP echo request/reply packets. Look for ICMP packets with unusual payload sizes or patterns.

---

## 7. Additional Resources

### Tools

| Tool | Purpose |
|------|---------|
| **Wireshark** | Packet analysis |
| **tcpdump** | CLI capture |
| **Scapy** | Packet crafting |
| **nmap** | Network scanning |
| **Ettercap** | MITM attacks |

### References

- [Nmap Documentation](https://nmap.org/docs.html)
- [Wireshark Wiki](https://www.wireshark.org/docs/)
- [MITRE ATT&CK - Network Attacks](https://attack.mitre.org/techniques/T1040/)

---

*Module 8/15 - Intermediate Network Traffic Analysis*
*For learning and SOC career preparation*