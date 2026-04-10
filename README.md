<h1 align="center">SOC Analyst Cheatsheet</h1>

<p align="center">
  <a href="https://img.shields.io/badge/SOC-Analyst-100%25-green"><img src="https://img.shields.io/badge/SOC-Analyst-100%25-green" alt="SOC Analyst"></a>
  <a href="https://img.shields.io/badge/HTB-Academy-blue"><img src="https://img.shields.io/badge/HTB-Academy-blue" alt="HTB Academy"></a>
</p>

> Comprehensive security operations cheatsheet for SOC analysts.
> Essential commands, queries, techniques, and notes based on HTB Academy SOC Analyst learning path.

---

## Quick Navigation

| # | Module | Folder |
|---|--------|--------|
| 01 | Incident Handling Process | [1-Incident-Handling-Process](./1-Incident-Handling-Process/) |
| 02 | Security Monitoring & SIEM Fundamentals | [2-Security-Monitoring-SIEM-Fundamentals](./2-Security-Monitoring-SIEM-Fundamentals/) |
| 03 | Windows Event Logs & Finding Evil | [3-Windows-Event-Logs-Finding-Evil](./3-Windows-Event-Logs-Finding-Evil/) |
| 04 | Threat Hunting with Elastic | [4-Introduction-to-Threat-Hunting-Hunting-With-Elastic](./4-Introduction-to-Threat-Hunting-Hunting-With-Elastic/) |
| 05 | Investigating with Splunk | [5-Understanding-Log-Sources-Investigating-with-Splunk](./5-Understanding-Log-Sources-Investigating-with-Splunk/) |
| 06 | Windows Attacks & Defense | [6-Windows-Attacks-Defense](./6-Windows-Attacks-Defense/) |
| 07 | Network Traffic Analysis | [7-Intro-to-Network-Traffic-Analysis](./7-Intro-to-Network-Traffic-Analysis/) |
| 08 | Intermediate Network Traffic Analysis | [8-Intermediate-Network-Traffic-Analysis](./8-Intermediate-Network-Traffic-Analysis/) |
| 09 | Working with IDS/IPS | [9-Working-with-IDS-IPS](./9-Working-with-IDS-IPS/) |
| 10 | Introduction to Malware Analysis | [10-Introduction-to-Malware-Analysis](./10-Introduction-to-Malware-Analysis/) |
| 11 | JavaScript Deobfuscation | [11-JavaScript-Deobfuscation](./11-JavaScript-Deobfuscation/) |
| 12 | YARA & Sigma for SOC Analysts | [12-YARA-Sigma-for-SOC-Analysts](./12-YARA-Sigma-for-SOC-Analysts/) |
| 13 | Digital Forensics | [13-Introduction-to-Digital-Forensics](./13-Introduction-to-Digital-Forensics/) |
| 14 | Detecting Windows Attacks with Splunk | [14-Detecting-Windows-Attacks-with-Splunk](./14-Detecting-Windows-Attacks-with-Splunk/) |
| 15 | Security Incident Reporting | [15-Security-Incident-Reporting](./15-Security-Incident-Reporting/) |

---

## Cheatsheet Modules

| # | Module | Key Topics |
|---|--------|------------|
| 01 | Incident Handling Process | NIST IR Lifecycle, Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain, Diamond Model, IR Playbooks |
| 02 | Security Monitoring & SIEM Fundamentals | Elastic Stack, KQL queries, SOC tiers, SIEM concepts, Use Case Development |
| 03 | Windows Event Logs & Finding Evil | Event IDs (4624, 4625, 4688), Sysmon, detecting malicious activity, endpoint forensics |
| 04 | Threat Hunting with Elastic | Hypothesis-based hunting, KQL queries, MITRE ATT&CK mapping, proactive detection |
| 05 | Investigating with Splunk | SPL queries, authentication monitoring, network logs, search optimization |
| 06 | Windows Attacks & Defense | Kerberoasting, AS-REP Roasting, GPP, DCSync, Golden Ticket, Kerberos Delegation, Print Spooler, ACLs, PKI |
| 07 | Network Traffic Analysis | Wireshark, tcpdump, BPF filters, TCP/IP, packet analysis, network fundamentals |
| 08 | Intermediate Network Traffic Analysis | DNS analysis, HTTP/HTTPS traffic, malware patterns, PCAP analysis |
| 09 | Working with IDS/IPS | Snort/Suricata rules, alert analysis, signature development |
| 10 | Introduction to Malware Analysis | Static analysis, strings, hashing, PE analysis, sandboxing, malware triage |
| 11 | JavaScript Deobfuscation | Deobfuscation techniques, analyzing obfuscated JavaScript, malicious scripts |
| 12 | YARA & Sigma for SOC Analysts | YARA rules, Sigma rules, sigmac, Chainsaw, Splunk queries, threat intelligence |
| 13 | Digital Forensics | FTK Imager, KAPE, Volatility, memory forensics, disk forensics, timeline analysis, MFT, Registry |
| 14 | Detecting Windows Attacks with Splunk | Splunk queries for Windows attacks, MITRE ATT&CK coverage, advanced detection |
| 15 | Security Incident Reporting | Report writing, stakeholder communication, real-world case studies, lessons learned |

---

## Skills Gained

### Tier 1 SOC Skills
- Alert triage and prioritization
- Basic log analysis
- Incident documentation
- Communication with stakeholders

### Tier 2 SOC Skills
- Advanced investigation
- Malware triage
- Network traffic analysis
- SIEM query development
- Active Directory attack detection
- Certificate Services abuse detection

### Tier 3 SOC / Threat Hunting
- Proactive threat hunting
- Malware analysis
- Digital forensics
- Detection engineering
- Playbook development

---

## Tools Covered

**SIEM & Logging:** Splunk, Elastic Security, Wazuh

**Network Analysis:** Wireshark, tcpdump, NetworkMiner, Snort/Suricata

**Endpoint Security:** Windows Event Logs, Sysmon, EDR

**Forensics & Malware:** FTK Imager, Autopsy, Volatility, YARA, KAPE, Velociraptor

**AD Attacks:** Mimikatz, BloodHound, Rubeus, Certify, Certipy, Impacket

**Case Management:** TheHive, Cortex

---

<p align="center">
  <strong>by <a href="https://github.com/manojxshrestha">manojxshrestha</a></strong><br>
  <sub>Based on HTB Academy SOC Analyst learning path. For learning and SOC career preparation.</sub>
</p>