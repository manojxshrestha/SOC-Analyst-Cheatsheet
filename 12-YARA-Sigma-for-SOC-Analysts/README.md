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

> 📌 **YARA** is a powerful pattern-matching tool used for identifying and classifying files based on specific patterns, characteristics, or content.

### What is YARA?

YARA is a powerful pattern-matching tool and rule format used for identifying and classifying files based on specific patterns, characteristics, or content. SOC analysts commonly use YARA rules to detect and classify malware samples, suspicious files, or indicators of compromise (IOCs).

YARA rules can include:
- Strings
- Regular expressions
- Boolean logic operators

> 📌 YARA can recognize both textual and binary patterns and can be applied to memory forensics.

![YARA Detection Process](https://github.com/user-attachments/assets/151f8915-28c5-4e2c-8449-ddce9742cfe8)

*Process of detecting malware: identify suspicious pattern, create YARA rule, scan for similar malware*

---

### Usages of YARA

| Usage | Description |
|-------|-------------|
| **Malware Detection** | Detect and identify malware based on signatures, behaviors, or file properties |
| **File Analysis** | Classify files by format, version, metadata, packers |
| **IOC Detection** | Search for specific IOCs like file names, registry keys, network artifacts |
| **Community Sharing** | Tap into community-contributed detection rules |
| **Custom Solutions** | Combine with static/dynamic analysis, sandboxing |
| **Custom Signatures** | Create organization-specific rules for EDR/antivirus |
| **Incident Response** | Search files/memory for patterns during investigations |
| **Threat Hunting** | Proactively search environments for potential threats |

---

### How Does YARA Work?

![YARA Workflow](https://github.com/user-attachments/assets/64cad401-5fdd-4abb-b919-d042f94f2c0e)

*YARA malware detection process: identify patterns → create rules → scan files → detect matches*

**Process Flow:**

1. **Set of Rules** - Define patterns, strings, byte sequences
2. **Set of Files** - Input files (executables, documents, memory images)
3. **YARA Scan Engine** - Core component using YARA modules
4. **Scanning and Matching** - Compare content against rules
5. **Detection** - Report matches with file path and offset

---

### YARA Rule Structure

**Basic Example:**
```yara
rule my_rule {
    meta:
        author = "Author Name"
        description = "example rule"
        hash = ""
    
    strings: 
        $string1 = "test"
        $string2 = "rule"
        $string3 = "htb"

    condition: 
        all of them
}
```

**WannaCry Example:**
```yara
rule Ransomware_WannaCry {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior" 
    
    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
    
    condition:
        all of them
}
```

---

### YARA Rule Components

#### 1. Rule Header

- **Rule name** - Descriptive identifier
- **Rule tags** - Optional categorization
- **Rule metadata** - Author, description, date

```yara
rule Ransomware_WannaCry {
    meta:
      ...
}
```

#### 2. Rule Meta

```yara
rule Ransomware_WannaCry {
    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/..."
}
```

#### 3. Rule Body (Strings)

```yara
strings:
    $wannacry_payload_str1 = "tasksche.exe" fullword ascii
    $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
```

#### 4. Rule Conditions

**Basic:**
```yara
condition:
    all of them
```

**With File Size:**
```yara
condition:
    filesize < 100KB and (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A)
```

> 📌 **uint16(0)** - Extracts first 2 bytes of file
> - `0x5A4D` = ASCII "MZ" (PE executable)
> - `0x4D5A` = ASCII "ZM" (reverse PE)

---

### Reserved Keywords

> 🔴 These keywords cannot be used as rule identifiers:

![YARA Keywords](https://github.com/user-attachments/assets/ff0c0137-be14-4222-9ee9-b6fdc3a399c0)

*Table of YARA reserved keywords*

**Note:** Rule identifiers are:
- Case sensitive
- First character cannot be a digit
- Cannot exceed 128 characters

---

### Advanced Features

YARA provides:
- **Modifiers** - `fullword`, `ascii`, `nocase`, `wide`, `xor`, `base64`
- **Logical Operators** - `and`, `or`, `not`
- **External Modules** - Enhanced detection capabilities
- **uint16/uint32** - Integer extraction at offset
- **Filesize** - Check file size conditions
- **Entry point** - Check PE entry point

---

### YARA Resources

| Resource | URL |
|----------|-----|
| YARA Documentation | [yara.readthedocs.io](https://yara.readthedocs.io/) |
| YARA-Rules Repository | [github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules) |
| Open Source YARA Rules | [github.com/mikesxrs/Open-Source-YARA-rules](https://github.com/mikesxrs/Open-Source-YARA-rules) |
| DFIR Report YARA Rules | [github.com/The-DFIR-Report/Yara-Rules](https://github.com/The-DFIR-Report/Yara-Rules) |

---

## 3. Leveraging Sigma

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 12/15 - YARA & Sigma for SOC Analysts*
*For learning and SOC career preparation*
