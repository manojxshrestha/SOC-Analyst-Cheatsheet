# 🛡️ WORKING WITH IDS/IPS

## SOC Analyst Cheatsheet - Module 9/15

---

## 0. Overview

### Module Description

This module offers an in-depth exploration of Suricata, Snort, and Zeek, covering both rule development and intrusion detection. We'll guide you through signature-based and analytics-based rule development, and you'll learn to tackle encrypted traffic.

> 🔴 **Prerequisite Knowledge:** Basic Windows operation knowledge and common attack principles

### What We'll Cover

| Topic | Description |
|-------|-------------|
| **Suricata** | Fundamentals, rule development (signature-based & encrypted traffic) |
| **Snort** | Fundamentals, rule development |
| **Zeek** | Fundamentals, intrusion detection |
| **Malware Detection** | PowerShell Empire, Covenant, Sliver, Cerber, Dridex, Ursnif, Patchwork |
| **Technique Detection** | DNS exfiltration, TLS/HTTP exfiltration, PsExec lateral movement, beaconing |

### Prerequisites

- Penetration Testing Process
- Incident Handling Process
- Security Monitoring & SIEM Fundamentals
- Intro to Network Traffic Analysis
- Intermediate Network Traffic Analysis

---

## 1. Introduction To IDS/IPS

### What is IDS/IPS?

In network security monitoring (NSM) operations, the use of Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) is paramount. The purpose of these systems is not only to identify potential threats but also to mitigate their impact.

> 📌 **IDS (Intrusion Detection System)** - A device or application that monitors network or system activities for malicious activities or policy violations and produces reports primarily to a management station. It gives us a clear sense of what's happening within our network, ensuring we have visibility on any potentially harmful actions. An IDS doesn't prevent an intrusion but alerts us when one occurs.

> 📌 **IPS (Intrusion Prevention System)** - Sits directly behind the firewall and provides an additional layer of protection. It doesn't just passively monitor the network traffic, but actively prevents any detected potential threats. Such a system doesn't just alert us of intruders, but also actively stops them from entering.

### IDS vs IPS Comparison

| Feature | IDS | IPS |
|---------|-----|-----|
| **Operation Mode** | Passive monitoring | Active prevention |
| **Primary Action** | Alerts only | Drops packets, blocks traffic, resets connection |
| **Network Placement** | Behind firewall (passive tap) | Inline (directly behind firewall) |
| **Detection Methods** | Signature-based & Anomaly-based | Signature-based & Anomaly-based |
| **Impact on Traffic** | No impact (out-of-band) | Can impact performance (in-line) |
| **Purpose** | Detection & Alerting | Detection & Blocking |

### Detection Methods

#### Signature-Based Detection

> 📌 **Signature-Based Detection** - The IDS/IPS recognizes bad patterns, such as malware signatures and previously identified attack patterns.

- Limited to **known threats only**
- Requires continuous signature updates
- Low false positive rate
- Effective for known malware and attack vectors

#### Anomaly-Based Detection

> 📌 **Anomaly-Based Detection** - Establishes a baseline of normal behavior and sends an alert when it detects behavior deviating from this baseline.

- More proactive approach
- Can detect **zero-day attacks**
- Susceptible to **false positives**
- Requires baseline training period

> 🔴 **Best Practice:** Use both methods together to balance each other out!

### Network Placement

```mermaid
flowchart LR
    A[Internet] --> B[Firewall]
    B --> C[IPS<br/>(inline)]
    C --> D[Internal<br/>Network]
    D --> E[IDS<br/>(passive)]

    style A fill:#ffcccc,color:#000
    style B fill:#ffe5cc,color:#000
    style C fill:#ffcccc,color:#000
    style D fill:#cce5ff,color:#000
    style E fill:#e6ccff,color:#000
```

#### Placement Rationale

| Component | Placement | Reason |
|-----------|-----------|--------|
| **Firewall** | Network edge | First line of defense, filters traffic based on rules |
| **IPS** | Behind firewall, inline | Can see and stop traffic that passes firewall |
| **IDS** | Behind firewall, passive | Analyzes traffic that bypassed firewall, focused on subtle threats |
| **Internal Network** | End points | Resources being protected |

> 📌 **Placement Strategy:** Both IDS and IPS devices are generally positioned behind the firewall, closer to the resources they protect. As they both work by examining network traffic, it makes sense to place them where they can see as much of the relevant traffic as possible.

### Host-Based IDS/IPS

| System | Description |
|--------|-------------|
| **HIDS** | Host-based Intrusion Detection System - monitors individual host's inbound and outbound traffic |
| **HIPS** | Host-based Intrusion Prevention System - actively prevents suspicious activity on host |

> 📌 **Host-based systems** monitor the individual host's inbound and outbound traffic for any suspicious activity, providing granular protection at the endpoint level.

### Defense-in-Depth Strategy

> 📌 **Defense-in-Depth** - A security strategy where multiple layers of security measures are used to protect the network.

The placement of IDS/IPS systems is an integral part of this strategy. The exact architecture will depend on various factors, including:
- Nature of the network
- Sensitivity of the data
- Threat landscape
- Specific network requirements

### Keeping IDS/IPS Effective

To ensure these systems perform at their best:

> 🔴 **Essential Practices:**
- Consistently update with latest threat signatures
- Fine-tune anomaly detection algorithms
- Requires ongoing, diligent effort from security team
- Critical given continually evolving threat landscape

### SIEM Integration

> 📌 **SIEM (Security Information and Event Management)** - Systems that collect and aggregate logs from IDS and IPS along with other devices in the network.

**SIEM Benefits:**
- Correlates events from different sources
- Analyzes relationships between events
- Uses advanced analytics to detect complex, coordinated attacks
- Provides complete, unified view of network's security
- Enables quick response to threats

---

## 2. Suricata Fundamentals

> 📌 **Suricata** - A powerful open-source Network Intrusion Detection System (IDS), Intrusion Prevention System (IPS), and Network Security Monitoring (NSM) tool developed by the Open Information Security Foundation (OISF).

### What is Suricata?

Suricata is an open-source powerhouse that serves as a cornerstone of network security. Its objective is to dissect every iota of network traffic, seeking potential signs of malicious activities.

**Key Strengths:**
- Conducts sweeping evaluation of network condition
- Delves into details of individual application-layer transactions
- Operates using intricately designed rules
- Performs at high velocities on both off-the-shelf and specifically designed hardware

---

### Suricata Operation Modes

Suricata operates in four (4) distinct modes:

| Mode | Description | Action |
|------|-------------|--------|
| **IDS Mode** | Silent observer | Examines traffic, flags attacks, no intervention |
| **IPS Mode** | Proactive stance | All traffic passes through strict checks, blocks malicious traffic |
| **IDPS Mode** | Hybrid approach | Passive monitoring + ability to send RST packets for abnormal activities |
| **NSM Mode** | Dedicated logging | Logs all network information, no active/passive analysis |

#### IDS Mode (Intrusion Detection System)

> 📌 In IDS mode, Suricata acts as a silent observer. It meticulously examines traffic, flagging potential attacks but refraining from any form of intervention. This mode augments network visibility by providing an in-depth view of network activities and accelerating response times, albeit without offering direct protection.

#### IPS Mode (Intrusion Prevention System)

> 📌 In IPS mode, Suricata adopts a proactive stance. All network traffic must pass through Suricata's stringent checks and is only granted access to the internal network upon Suricata's approval.

> 🔴 **Important:** Deploying Suricata in IPS mode demands an intimate understanding of the network landscape to prevent inadvertently blocking legitimate traffic. Each rule activation necessitates rigorous testing and validation. While this mode enhances security, the inspection process may introduce latency.

#### IDPS Mode (Intrusion Detection Prevention System)

> 📌 IDPS mode brings together the best of both IDS and IPS. While Suricata continues to passively monitor traffic, it possesses the ability to actively transmit RST packets in response to abnormal activities. This mode strikes a balance between active protection and maintaining low latency.

#### NSM Mode (Network Security Monitoring)

> 📌 In NSM mode, Suricata transitions into a dedicated logging mechanism, eschewing active or passive traffic analysis or prevention capabilities. It meticulously logs every piece of network information it encounters, providing valuable data for retrospective security incident investigations.

---

### Suricata Inputs

Suricata can process traffic from two main input types:

| Input Type | Description | Use Case |
|------------|-------------|----------|
| **Offline Input** | Reads PCAP files in LibPCAP format | Post-mortem analysis, experimenting with rules |
| **Live Input** | Reads directly from network interfaces | Real-time monitoring |

#### Offline Input

```bash
suricata -r /home/htb-student/pcaps/suspicious.pcap
```

- Reads previously captured packets
- Not only advantageous for conducting post-mortem data examination but also instrumental when experimenting with various rule sets and configurations

#### Live Input Options

| Option | Description | Notes |
|--------|-------------|-------|
| **LibPCAP** | Reads packets directly from network interfaces | Performance limitations, no load-balancing |
| **NFQ** | Linux-specific inline IPS mode | Collaborates with IPTables, requires drop rules |
| **AF_PACKET** | Performance improvement over LibPCAP | Supports multi-threading, not compatible with older Linux |

##### Live Input - LibPCAP Mode

```bash
sudo suricata --pcap=ens160 -vv
```

##### Live Input - NFQ Mode (Inline)

```bash
# First, set up iptables
sudo iptables -I FORWARD -j NFQUEUE

# Then run Suricata in inline mode
sudo suricata -q 0
```

##### Live Input - AF_PACKET Mode

```bash
sudo suricata -i ens160
# or
sudo suricata --af-packet=ens160
```

> 📌 **Note:** The `-i` option helps Suricata choose the best input option. In the case of Linux, the best input option is AF_PACKET.

---

### Suricata Outputs

Suricata creates multiple outputs, including logs, alerts, and additional network-related data such as DNS requests and network flows.

#### Key Output Files

| Output File | Description | Format |
|-------------|-------------|--------|
| **eve.json** | Recommended output, JSON formatted | JSON |
| **fast.log** | Text-based alert log | Plain text |
| **stats.log** | Statistics log for debugging | Plain text |
| **suricata.log** | General Suricata logs | Plain text |

#### EVE JSON Output

> 📌 **EVE (Every Oddities and Various Events)** - A JSON formatted log that records a wide range of event types including alerts, HTTP, DNS, TLS metadata, drop, SMTP metadata, flow, netflow, and more.

**EVE JSON Event Types:**
- Alerts
- HTTP traffic
- DNS requests/responses
- TLS metadata
- Drop events
- SMTP metadata
- Flow/Netflow data
- And more...

**Example - Filter Alert Events:**
```bash
cat /var/log/suricata/eve.json | jq -c 'select(.event_type == "alert")'
```

**Example - Filter DNS Events:**
```bash
cat /var/log/suricata/eve.json | jq -c 'select(.event_type == "dns")' | head -1 | jq .
```

#### fast.log Output

```
07/06/2023-08:34:35.003163  [**] [1:1:0] Known bad DNS lookup, possible Dridex infection [**] [Classification: (null)] [Priority: 3] {UDP} 10.9.24.101:51833 -> 10.9.24.1:53
```

#### stats.log Output

```
------------------------------------------------------------------------------------
Date: 7/6/2023 -- 08:34:24 (uptime: 0d, 00h 00m 08s)
------------------------------------------------------------------------------------
Counter                                       | TM Name                   | Value
------------------------------------------------------------------------------------
capture.kernel_packets                        | Total                     | 4
decoder.pkts                                  | Total                     | 3
decoder.bytes                                 | Total                     | 212
decoder.ipv6                                  | Total                     | 1
decoder.ethernet                              | Total                     | 3
decoder.icmpv6                                | Total                     | 1
```

#### EVE JSON Key Fields

| Field | Description |
|-------|-------------|
| **timestamp** | Time of event |
| **flow_id** | Unique identifier for each network flow |
| **event_type** | Type of event (alert, dns, http, tls, etc.) |
| **src_ip/dst_ip** | Source and destination IP addresses |
| **src_port/dest_port** | Source and destination ports |
| **pcap_cnt** | Packet counter for tracing packet order |

> 📌 **flow_id** is a unique identifier assigned by Suricata to each network flow. This helps track and correlate various events related to the same network flow.

> 📌 **pcap_cnt** is a counter that Suricata increments for each packet it processes. This allows tracing a packet back to its original order in the PCAP file.

---

### Suricata Configuration

#### Rule Files Location

```bash
ls -lah /etc/suricata/rules/
```

**Common Rule Files:**
- `emerging-malware.rules` - Malware detection rules
- `emerging-exploit.rules` - Exploit detection rules
- `emerging-dos.rules` - Denial of Service rules
- `drop.rules` - Rules that drop traffic in IPS mode
- `botcc.rules` - Botnet command and control rules

#### Network Variables

Variables can be defined in `suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
```

> 📌 Each rule usually involves specific variables like `$HOME_NET` and `$EXTERNAL_NET`. The rule examines traffic from the IP addresses specified in `$HOME_NET` heading towards `$EXTERNAL_NET`.

---

### Configuring Custom Rules

To add a custom rules file:

```bash
sudo vim /etc/suricata/suricata.yaml

# Add /home/htb-student/local.rules to rule-files
```

#### Example Rule

```bash
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

---

### Suricata File Extraction

Suricata has a powerful file extraction feature that captures and stores files transferred over various protocols.

#### Enabling File Extraction

Edit `suricata.yaml`:

```yaml
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
  dir: /var/log/suricata/filestore
```

#### File Extraction Rule

```bash
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

#### Running File Extraction

```bash
suricata -r /home/htb-student/pcaps/vm-2.pcap
```

#### Inspecting Extracted Files

Files are stored with SHA256 hash as filename in directories named after first 2 characters:

```bash
cd filestore
find . -type f
xxd ./21/21742fc621f83041db2e47b0899f5aea6caa00a4b67dbff0aae823e6817c5433 | head
```

> 📌 **File Storage:** The file-store module uses SHA256 of the file contents as the filename. Files are placed in directories named 00 to ff (first 2 characters of SHA256).

---

### Live Rule Reloading

Suricata allows updating ruleset without interrupting traffic inspection.

#### Enabling Live Rule Reloading

In `suricata.yaml`:

```yaml
detect-engine:
  - reload: true
```

#### Reloading Rules

```bash
sudo kill -usr2 $(pidof suricata)
```

> 🔴 This signals Suricata to check for changes in the ruleset periodically and apply them without needing to restart the service.

---

### Updating Suricata Rulesets

#### Basic Update

```bash
sudo suricata-update
```

#### List Available Rule Sources

```bash
sudo suricata-update list-sources
```

**Available Sources:**
| Source | Vendor | License |
|--------|--------|---------|
| et/open | Proofpoint | MIT |
| et/pro | Proofpoint | Commercial |
| sslbl/ssl-fp-blacklist | Abuse.ch | Non-Commercial |
| sslbl/ja3-fingerprints | Abuse.ch | Non-Commercial |
| tgreen/hunting | tgreen | GPLv3 |
| malsilo/win-malware | malsilo | MIT |
| stamus/lateral | Stamus Networks | GPL-3.0-only |

#### Enable a Rule Source

```bash
sudo suricata-update enable-source et/open
sudo suricata-update
```

#### Restart Suricata

```bash
sudo systemctl restart suricata
```

---

### Validating Suricata Configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

**Expected Output:**
```
6/7/2023 -- 07:13:29 - <Info> - Running suricata under test mode
6/7/2023 -- 07:13:29 - <Notice> - This is Suricata version 6.0.13 RELEASE running in SYSTEM mode
6/7/2023 -- 07:13:29 - <Notice> - Configuration provided was successfully loaded. Exiting.
```

---

### Suricata Key Features

| Feature | Description |
|---------|-------------|
| **Deep packet inspection** | Packet capture logging |
| **Anomaly detection** | Network Security Monitoring |
| **Intrusion Detection/Prevention** | Hybrid mode available |
| **Lua scripting** | Custom rule development |
| **Geographic IP identification** | GeoIP support |
| **IPv4/IPv6 support** | Full protocol support |
| **IP reputation** | Reputation-based detection |
| **File extraction** | Extract files from traffic |
| **Advanced protocol inspection** | Application layer analysis |
| **Multitenancy** | Multiple tenant support |

> 📌 Suricata can also detect "non-standard/anomalous" traffic using Protocol Anomaly Detection strategies.

---

### Replaying Traffic for Testing

```bash
# Replay PCAP to network interface
sudo tcpreplay -i ens160 /home/htb-student/pcaps/suspicious.pcap
```

---

### Hands-on Commands Reference

| Command | Description |
|---------|-------------|
| `suricata -r <pcap>` | Run in offline mode with PCAP |
| `suricata -i <interface>` | Run in live mode (AF_PACKET) |
| `suricata --pcap=<interface>` | Run in live mode (LibPCAP) |
| `suricata -q <queue>` | Run in inline NFQ mode |
| `suricata -T` | Test configuration |
| `suricata-update` | Update ruleset |
| `suricata-update list-sources` | List available sources |
| `suricata-update enable-source <source>` | Enable a rule source |

---

## 3. Snort

*Coming soon...*

---

## 4. Zeek

*Coming soon...*

---

## 5. Skills Assessment

*Coming soon...*

---

*Module 9/15 - Working with IDS/IPS*
*For learning and SOC career preparation*
