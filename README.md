# 🚀 SOC Analyst Cheatsheet

A comprehensive, practical cheatsheet repository for SOC analysts based on the HTB Academy SOC Analyst learning path. This repository contains detailed guides, commands, queries, and workflows for real-world security operations.

---

## 📚 Module Overview

| # | Module | Description | Key Topics |
|---|--------|-------------|------------|
| **1** | [Incident Handling Process](./1-Incident-Handling-Process/) ✅ | NIST-based incident response lifecycle | Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain, NIST IR Lifecycle (Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned), IR Playbooks, Case Studies, Diamond Model, RACI Matrix |
| **2** | Security Monitoring & SIEM Fundamentals | SIEM concepts and log management | Log sources, normalization, correlation, detection principles, SIEM architecture |
| **3** | Windows Event Logs & Finding Evil | Windows security event analysis | Event IDs (4624, 4625, 4688, etc.), Sysmon, detecting malicious activity |
| **4** | Introduction to Threat Hunting & Hunting With Elastic | Proactive threat detection | Hypothesis-based hunting, Elastic/KQL queries, MITRE ATT&CK mapping |
| **5** | Understanding Log Sources & Investigating with Splunk | Splunk for SOC analysts | SPL queries, authentication monitoring, network logs, search optimization |
| **6** | Windows Attacks & Defense | Common Windows attack techniques | Lateral movement, privilege escalation, persistence mechanisms |
| **7** | Intro to Network Traffic Analysis | Network fundamentals | Wireshark basics, TCP/IP, packet analysis, protocol analysis |
| **8** | Intermediate Network Traffic Analysis | Advanced network analysis | DNS analysis, HTTP/HTTPS traffic, malware traffic patterns, PCAP analysis |
| **9** | Working with IDS/IPS | Intrusion detection systems | Snort/Suricata rules, alert analysis, signature development |
| **10** | Introduction to Malware Analysis | Malware triage basics | Static analysis, strings, hashing, PE analysis, sandboxing |
| **11** | JavaScript Deobfuscation | Malicious script analysis | Deobfuscation techniques, analyzing obfuscated JavaScript |
| **12** | YARA & Sigma for SOC Analysts | Detection rule writing | YARA rules, Sigma rules, threat intelligence integration |
| **13** | Introduction to Digital Forensics | Forensic acquisition and analysis | RAM/disk forensics, evidence collection, chain of custody |
| **14** | Detecting Windows Attacks with Splunk | Advanced Windows detection | Splunk queries for Windows attacks, MITRE ATT&CK coverage |
| **15** | Security Incident Reporting | Incident documentation | Report writing, stakeholder communication, lessons learned |

---

## 🎯 Skills You'll Gain

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

### Tier 3 SOC / Threat Hunting Skills
- Proactive threat hunting
- Malware analysis
- Digital forensics
- Detection engineering
- Playbook development

---

## 🛠️ Tools Covered

### SIEM & Logging
- **Splunk** - Enterprise SIEM, SPL queries
- **Elastic Security** - Kibana, KQL queries
- **Wazuh** - Open source SIEM

### Network Analysis
- **Wireshark** - Packet analysis
- **tcpdump** - Command-line packet capture
- **NetworkMiner** - PCAP artifact extraction
- **Snort/Suricata** - IDS/IPS

### Endpoint Security
- **Windows Event Logs** - Security, System, Application
- **Sysmon** - Advanced endpoint telemetry
- **EDR** - Endpoint Detection & Response

### Forensics & Malware
- **FTK Imager** - Forensic imaging
- **Autopsy** - Disk analysis
- **Volatility** - Memory forensics
- **YARA** - Malware detection rules

### Case Management
- **TheHive** - Incident case management
- **Cortex** - Threat intelligence enrichment

---

## 📋 Each Module Includes

- **Concept Summary** - Theory and fundamentals
- **Key Artifacts** - Logs, fields, data sources
- **Detection Use Cases** - Real attack scenarios
- **Investigation Workflow** - Step-by-step process
- **Commands & Queries** - Splunk, Elastic, Windows, Linux
- **IOCs** - Common indicators of compromise
- **Analyst Tips** - Real-world shortcuts and insights

---

## 🚀 How to Use

1. **Navigate** to the relevant module folder for your investigation
2. **Search** the markdown for specific Event IDs, queries, or techniques
3. **Use** the commands and queries directly in your SIEM or analysis tools
4. **Reference** the playbooks for step-by-step incident response workflows

---

## 📁 Repository Structure

```
SOC-Analyst-Cheatsheet/
├── README.md
├── 1-Incident-Handling-Process/      ✅ Complete
├── 2-Security-Monitoring-SIEM-Fundamentals/   Coming Soon
├── 3-Windows-Event-Logs-Finding-Evil/        Coming Soon
├── 4-Introduction-to-Threat-Hunting/          Coming Soon
├── 5-Understanding-Log-Sources-Splunk/      Coming Soon
├── 6-Windows-Attacks-Defense/                Coming Soon
├── 7-Intro-to-Network-Traffic-Analysis/      Coming Soon
├── 8-Intermediate-Network-Traffic-Analysis/   Coming Soon
├── 9-Working-with-IDS-IPS/                   Coming Soon
├── 10-Introduction-to-Malware-Analysis/       Coming Soon
├── 11-JavaScript-Deobfuscation/              Coming Soon
├── 12-YARA-Sigma-for-SOC-Analysts/           Coming Soon
├── 13-Introduction-to-Digital-Forensics/      Coming Soon
├── 14-Detecting-Windows-Attacks-Splunk/       Coming Soon
└── 15-Security-Incident-Reporting/           Coming Soon
```

---

## 📖 Learning Path

This repository follows the HTB Academy SOC Analyst career path. For best results:

1. **Start with Module 1** - Understand incident handling fundamentals
2. **Build SIEM skills** - Modules 2-5
3. **Learn endpoint analysis** - Modules 3, 6
4. **Master network analysis** - Modules 7-9
5. **Add malware & forensics** - Modules 10-13
6. **Complete with reporting** - Module 15

---

## 🔗 Additional Resources

- [MITRE ATT&CK](https://attack.mitre.org)
- [NIST SP 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [The DFIR Report](https://thedfirreport.com/)
- [SANS IR](https://www.sans.org/security-resources/incident-management/)

---

*Built with research + HTB Academy materials*
*For learning and SOC career preparation*