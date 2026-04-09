# 🎯 YARA & SIGMA FOR SOC ANALYSTS

## SOC Analyst Cheatsheet - Module 12/15

---

## 0. Overview

> 📌 **YARA & Sigma** - Essential detection rules for SOC analysts to hunt threats on disk, processes, memory, and SIEM.

### Module Description

This module covers:
- Creating YARA rules manually and automatically
- Applying YARA rules to hunt threats (disk, processes, memory, online databases)
- Building Sigma rules and translating them to SIEM queries
- Using sigmac utility
- Hunting threats in event logs and SIEM solutions

> 🔴 **Difficulty:** Easy | **Tier:** 2 | **Estimated Time:** 3 days | **Cubes:** 20

### Prerequisites

- Understanding Log Sources & Investigating with Splunk
- Windows Event Logs & Finding Evil
- Introduction to Malware Analysis

### What We'll Cover

| Topic | Description |
|-------|-------------|
| **YARA Rules** | Pattern matching for malware detection |
| **Sigma Rules** | Generic log-based detection rules |
| **YARA Hunting** | Scan directories, processes, memory |
| **Sigma Hunting** | SIEM queries, event log analysis |

---

## Table of Contents

1. [Introduction to YARA & Sigma](#1-introduction-to-yara--sigma)
2. [Leveraging YARA](#2-leveraging-yara)
3. [Leveraging Sigma](#3-leveraging-sigma)
4. [Skills Assessment](#4-skills-assessment)

---

## 1. Introduction to YARA & Sigma

> 📌 **YARA and Sigma** are essential tools for SOC analysts to enhance threat detection and incident response capabilities.

### Overview

YARA and Sigma provide SOC analysts with:
- Improved threat detection
- Efficient log analysis
- Malware detection and classification
- IOC identification
- Collaboration and standardization
- Integration with security tools

**Key Difference:**
- **YARA** - Excels in file and memory analysis, pattern matching
- **Sigma** - Particularly adept at log analysis and SIEM systems

Both use conditional logic to detect suspicious activities in logs or match patterns in files.

---

### Why SOC Analysts Need YARA and Sigma

#### Enhanced Threat Detection

YARA and Sigma rules allow SOC analysts to develop customized detection rules tailored to their unique environment.

**Resources:**
- [YARA-Rules](https://github.com/Yara-Rules/rules/tree/master/malware)
- [Open-Source YARA rules](https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [joesecurity sigma-rules](https://github.com/joesecurity/sigma-rules)
- [SIGMA detection rules](https://github.com/mdecrevoisier/SIGMA-detection-rules)

---

#### Efficient Log Analysis

Sigma rules are essential for log analysis in SOC settings:
- Filter and correlate log data from disparate sources
- Concentrate on events pertinent to security monitoring
- Minimize irrelevant data
- Prioritize investigative efforts

**Tool:** Chainsaw - Apply Sigma rules to event log files

---

#### Collaboration and Standardization

YARA and Sigma offer standardized formats:
- Foster collaboration among SOC analysts
- Tap into collective cybersecurity expertise
- Knowledge sharing and best practices
- Stay updated with threat intelligence

**DFIR Report Rules:**
- [YARA Rules](https://github.com/The-DFIR-Report/Yara-Rules)
- [Sigma Rules](https://github.com/The-DFIR-Report/Sigma-Rules)

---

#### Integration with Security Tools

YARA and Sigma integrate with:
- SIEM platforms
- Log analysis systems
- Incident response platforms

**Automation enables:**
- Event correlation
- Security event enrichment
- Deployment in SIEM/XDR systems

**Tool:** [Uncoder.io](https://uncoder.io) - Convert Sigma rules to SIEM queries

---

#### Malware Detection and Classification

YARA rules are particularly useful for:
- Pinpointing and classifying malware
- Creating specific patterns/signatures for known malware
- Prompt detection and mitigation
- Bolstering organization's security posture

---

#### Indicator of Compromise (IOC) Identification

Both YARA and Sigma help locate and identify:
- Distinct artifacts linked to security incidents
- Behavioral indicators
- Swift detection and counteraction
- Mitigating consequences of security incidents

---

## 2. Leveraging YARA

*Coming soon...*

---

## 3. Leveraging Sigma

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 12/15 - YARA & Sigma for SOC Analysts*
*For learning and SOC career preparation*
