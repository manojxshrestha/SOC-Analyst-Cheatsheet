# 🛡️ INTERMEDIATE NETWORK TRAFFIC ANALYSIS

## SOC Analyst Cheatsheet - Module 8/15

---

## 0. Overview

> 📌 **Intermediate Network Traffic Analysis** - Advanced techniques for detecting network threats across all layers.

### Module Description

Through network traffic analysis, this module sharpens skills in detecting:
- **Link Layer:** ARP anomalies, rogue access points
- **Network Layer:** IP spoofing, TCP handshake irregularities
- **Application Layer:** Web vulnerabilities, peculiar DNS activities

### What We'll Cover

| Layer | Topics |
|-------|--------|
| **Link Layer** | ARP spoofing, ARP scanning, DoS, Rogue AP, Evil-Twin |
| **Network Layer** | Fragmentation attacks, IP spoofing, TTL attacks |
| **Transport Layer** | TCP handshake abnormalities, RST attacks, hijacking |
| **Application Layer** | HTTP enumeration, XSS, SSL renegotiation, DNS anomalies |

> 🔴 **Note:** Download pcap_files.zip from Resources section for hands-on exercises.

### PCAP Files

```bash
# Extract PCAP files from local Resources
unzip Resources/pcap_files.zip -d pcaps/
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
| icmp_frag.pcapng | ICMP Fragmentation |
| ICMP_smurf.pcapng | Smurf Attack |
| icmp_tunneling.pcapng | ICMP Tunneling |
| ip_ttl.pcapng | IP TTL Manipulation |
| LAND-DoS.pcapng | LAND DoS Attack |
| nmap_*_scan.pcapng | Various Nmap Scans |
| rogueap.cap | Rogue Access Point |
| RST_Attack.pcapng | TCP RST Attack |
| TCP-hijacking.pcap | TCP Hijacking |
| telnet_tunneling_*.pcapng | Telnet Tunneling |
| XSS_Simple.pcapng | XSS Attack |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Link Layer Attacks](#2-link-layer-attacks)
   - [ARP Spoofing & Abnormality Detection](#2-link-layer-attacks)
   - [ARP Scanning & Denial-of-Service](#arp-scanning--denial-of-service)
   - [802.11 Denial-of-Service](#80211-denial-of-service)
   - [Rogue Access Point & Evil-Twin](#rogue-access-point--evil-twin)
3. [Detecting Network Abnormalities](#3-detecting-network-abnormalities)
   - [Fragmentation Attacks](#fragmentation-attacks)
   - [IP Spoofing](#ip-spoofing)
   - [IP TTL Attacks](#ip-ttl-attacks)
   - [TCP Handshake Abnormalities](#tcp-handshake-abnormalities)
   - [TCP Connection Resets & Hijacking](#tcp-connection-resets--hijacking)
   - [ICMP Tunneling](#icmp-tunneling)
4. [Application Layer Attacks](#4-application-layer-attacks)
   - [HTTP/HTTPS Enumeration](#httphttps-enumeration)
   - [Strange HTTP Headers](#strange-http-headers)
   - [XSS & Code Injection](#xss--code-injection)
   - [SSL Renegotiation](#ssl-renegotiation)
   - [Peculiar DNS Traffic](#peculiar-dns-traffic)
   - [Strange Telnet & UDP](#strange-telnet--udp)
5. [Skills Assessment](#5-skills-assessment)

---

## 1. Introduction

*Content from Module 8 Section 1 - see Overview above*

---

## 2. Link Layer Attacks

### ARP Spoofing & Abnormality Detection

> 📌 **ARP Spoofing** - Attack that maps attacker's MAC address to a legitimate IP address to intercept traffic.

#### How ARP Works

<img width="873" height="718" alt="image" src="https://github.com/user-attachments/assets/f67039fe-0b0a-4c73-8bab-23a5a0a02563" />

**ARP Process:**
1. Host A needs to send data to Host B
2. Checks ARP cache for IP-to-MAC mapping
3. If not found, broadcasts ARP request: "Who has IP x.x.x.x?"
4. Host B replies with ARP response: "IP x.x.x.x = MAC aa:aa:aa:aa:aa:aa"
5. Host A updates ARP cache
6. Cache can update when hosts change IP/MAC

#### ARP Poisoning & Spoofing

<img width="860" height="668" alt="image" src="https://github.com/user-attachments/assets/01decf2b-4241-4aeb-9f06-0c6d7b41e42a" />

**Attack Steps:**
1. Attacker sends forged ARP messages to victim and router
2. Tells victim: "Gateway IP = Attacker's MAC"
3. Tells router: "Victim IP = Attacker's MAC"
4. Victim's ARP cache gets corrupted
5. Attacker becomes MITM
6. Can perform DNS spoofing, SSL stripping

**Prevention:**
- Static ARP entries (high maintenance)
- Switch/Router port security

#### Detecting ARP Spoofing

**Install tcpdump:**
```bash
sudo apt install tcpdump -y
```

**Capture traffic:**
```bash
sudo tcpdump -i eth0 -w filename.pcapng
```

**Open PCAP in Wireshark:**
```bash
wireshark ARP_Spoof.pcapng
```

**Filter ARP traffic:**
```
arp.opcode
```

<img width="1141" height="467" alt="image" src="https://github.com/user-attachments/assets/2f704340-5f4e-4dfc-9e7a-5ddd18dc9f28" />

Wireshark ARP requests and replies.

**ARP Opcodes:**
| Opcode | Description |
|--------|-------------|
| 1 | ARP Request |
| 2 | ARP Reply |

#### Detecting Duplicate IP

<img width="1229" height="180" alt="image" src="https://github.com/user-attachments/assets/9e6f4dc8-ea53-4b5e-80fc-56f17fe8af2d" />

**Filter for duplicate detection:**
```
arp.duplicate-address-detected && arp.opcode == 2
```

<img width="1046" height="182" alt="image" src="https://github.com/user-attachments/assets/de4208c2-7bf6-498d-afd8-480837dc125f" />

Wireshark showing duplicate IP detection.

**Check ARP cache on Linux:**
```bash
arp -a | grep 50:eb:f6:ec:0e:7f
arp -a | grep 08:00:27:53:0c:ba
```

> 🔴 **Red Flag:** Same IP mapped to two different MAC addresses!

#### Identifying Original IP Addresses

**Filter by MAC address:**
```
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
```

<img width="1038" height="226" alt="image" src="https://github.com/user-attachments/assets/ba0b7223-cef5-41b8-9c63-fd6d0e64d5f1" />

**Analysis:**
- MAC 08:00:27:53:0c:ba was originally 192.168.10.5
- Changed to 192.168.10.4 - indicates ARP spoofing!

**Filter all traffic from suspicious MACs:**
```
eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba
```

<img width="1246" height="142" alt="image" src="https://github.com/user-attachments/assets/81d6d8a1-c3d4-4c10-83a4-4367d90afdad" />

TCP + ARP packets showing suspicious activity.

#### MITM Detection

> 🔴 If traffic is forwarded (MITM), you'll see:
- Identical/near-symmetrical packets: victim → attacker → router
- TCP connections dropping if attacker doesn't forward

---

### ARP Scanning & Denial-of-Service

> 📌 Attackers use ARP scanning for information gathering before DoS/MITM attacks.

#### ARP Scanning Signs

**Red Flags:**
- Broadcast ARP requests sent to sequential IP addresses (.1, .2, .3...)
- Broadcast ARP requests sent to non-existent hosts
- Unusual volume of ARP traffic from single host

#### Finding ARP Scanning

**Open PCAP:**
```bash
wireshark ARP_Scan.pcapng
```

**Filter ARP:**
```
arp.opcode
```

<img width="927" height="345" alt="image" src="https://github.com/user-attachments/assets/77d736c3-7290-4b89-b12e-c01b2b08c0bc" />

> 🔴 **Detection:** Single host sending ARP requests to sequential IP addresses = ARP scanning (like Nmap)

#### Identifying Denial-of-Service

**Related PCAP:** ARP_Poison.pcapng

**Attack Pattern:**
1. Attacker compiles list of live hosts via ARP scanning
2. Shifts to DoS by contaminating entire subnet
3. Manipulates as many ARP caches as possible

<img width="1206" height="463" alt="image" src="https://github.com/user-attachments/assets/dfc8c97f-507f-4f0f-858c-e623f3936df3" />

**Attack Indicators:**
- ARP traffic declaring new physical addresses for all live IPs
- Intent: Corrupt router's ARP cache
- Duplicate allocation of gateway IP to client devices

<img width="1042" height="256" alt="image" src="https://github.com/user-attachments/assets/574ea528-b510-4fb1-a30c-a10dcfa646b7" />

**Red Flags:**
- Duplicate IP 192.168.10.1 assigned to multiple MACs
- Attacker attempting to corrupt victim ARP caches
- Intent: Obstruct traffic in both directions

#### Responding To ARP Attacks

**Response Options:**

| Action | Description |
|--------|-------------|
| **Tracing & Identification** | Locate attacker's physical machine. May find it's already compromised. |
| **Containment** | Disconnect/isolate affected segment at switch/router level to stop DoS/MITM |

> 💡 **Note:** Link layer attacks often fly under the radar but detection is crucial for preventing data exfiltration from higher OSI layers.

---

### 802.11 Denial-of-Service

*Coming soon...*

---

### Rogue Access Point & Evil-Twin

*Coming soon...*

---

## 3. Detecting Network Abnormalities

### Fragmentation Attacks

*Coming soon...*

### IP Spoofing

*Coming soon...*

### IP TTL Attacks

*Coming soon...*

### TCP Handshake Abnormalities

*Coming soon...*

### TCP Connection Resets & Hijacking

*Coming soon...*

### ICMP Tunneling

*Coming soon...*

---

## 4. Application Layer Attacks

### HTTP/HTTPS Enumeration

*Coming soon...*

### Strange HTTP Headers

*Coming soon...*

### XSS & Code Injection

*Coming soon...*

### SSL Renegotiation

*Coming soon...*

### Peculiar DNS Traffic

*Coming soon...*

### Strange Telnet & UDP

*Coming soon...*

---

## 5. Skills Assessment

*Coming soon...*

---

*Module 8/15 - Intermediate Network Traffic Analysis*
*For learning and SOC career preparation*