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

## 2. Suricata

*Coming soon...*

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
