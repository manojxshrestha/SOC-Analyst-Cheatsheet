# 🛡️ WORKING WITH IDS/IPS

## SOC Analyst Cheatsheet - Module 9/15

---

## 0. Overview

> 📌 **Working with IDS/IPS** - Learn Suricata, Snort, and Zeek for intrusion detection and signature development.

### Module Description

This module offers an in-depth exploration of Suricata, Snort, and Zeek, covering both rule development and intrusion detection.

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

> 📌 **IDS (Intrusion Detection System)** - Monitors network/system for malicious activities, produces alerts to management station.

> 📌 **IPS (Intrusion Prevention System)** - Actively prevents detected threats, sits behind firewall for additional layer of protection.

### IDS vs IPS

| Feature | IDS | IPS |
|---------|-----|-----|
| **Operation** | Passive monitoring | Active prevention |
| **Action** | Alerts only | Drops packets, blocks traffic, resets connection |
| **Placement** | Behind firewall | Inline (directly behind firewall) |
| **Detection** | Signature-based & Anomaly-based | Signature-based & Anomaly-based |

### Detection Methods

#### Signature-Based Detection
- Recognizes bad patterns (malware signatures, attack patterns)
- Limited to **known threats only**

#### Anomaly-Based Detection
- Establishes baseline of normal behavior
- Alerts when behavior deviates from baseline
- More proactive but susceptible to **false positives**

> 💡 **Best Practice:** Use both methods to balance each other out!

### Network Placement

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌────────────┐
│ Internet│────▶│Firewall │────▶│  IPS   │────▶│  Internal │
│         │     │         │     │(inline)│     │  Network  │
└─────────┘     └─────────┘     └─────────┘     └────────────┘
                                            │
                                            ▼
                                      ┌─────────┐
                                      │   IDS   │
                                      │(passive)│
                                      └─────────┘
```

- **IDS:** Placed behind firewall, analyzes traffic that bypassed first line of defense
- **IPS:** Placed inline, needs authority to stop traffic

### Host-Based Systems

| System | Description |
|--------|-------------|
| **HIDS** | Host-based Intrusion Detection System |
| **HIPS** | Host-based Intrusion Prevention System |

Monitors individual host's inbound/outbound traffic for suspicious activity.

### Defense-in-Depth

IDS/IPS placement is integral to defense-in-depth strategy. Exact architecture depends on:
- Network nature
- Data sensitivity
- Threat landscape

### IDS/IPS Updates

To ensure optimal performance:
- Consistent updates with latest threat signatures
- Fine-tune anomaly detection algorithms
- Requires ongoing effort from security team

### SIEM Integration

**SIEM systems** collect and aggregate logs from IDS/IPS:
- Correlate events from different sources
- Advanced analytics to detect complex, coordinated attacks
- Provides unified view of network security

---

## Coming Soon

- Suricata Fundamentals & Rule Development
- Snort Fundamentals & Rule Development
- Zeek Fundamentals & Intrusion Detection
- Skills Assessment

---

*Module 9/15 - Working with IDS/IPS*
*For learning and SOC career preparation*