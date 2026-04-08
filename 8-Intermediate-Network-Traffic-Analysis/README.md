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