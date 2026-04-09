# 🔍 INTRODUCTION TO DIGITAL FORENSICS

## SOC Analyst Cheatsheet - Module 13/15

---

## 0. Overview

> 📌 **Digital Forensics** - Core forensic concepts and tools for investigating digital evidence in Windows environments.

### Module Description

Dive into Windows digital forensics with Hack The Box Academy's "Introduction to Digital Forensics" module. Gain mastery over core forensic concepts and tools such as FTK Imager, KAPE, Velociraptor, and Volatility.

### What We'll Cover

| Topic | Description |
|-------|-------------|
| **Foundational Forensics** | Core concepts, evidence acquisition processes |
| **Tool Mastery** | FTK Imager, KAPE, Velociraptor, Volatility, Autopsy |
| **Memory Forensics** | Volatile memory analysis, artifact extraction |
| **Disk Forensics** | Disk image analysis, file structure examination |
| **Rapid Triage** | Quick investigation techniques for time-sensitive incidents |
| **Timeline Analysis** | MFT, USN Journal, Windows event logs |
| **Key Artifacts** | MFT, USN Journal, Registry Hives, Prefetch, ShimCache, Amcache, BAM, SRUM |

### Prerequisites

- Incident Handling Process
- Windows Event Logs & Finding Evil
- Introduction to Malware Analysis
- YARA & Sigma for SOC Analysts

---

## Table of Contents

0. [Overview](#0-overview)
1. [Introduction to Digital Forensics](#1-introduction-to-digital-forensics)
2. [Evidence Acquisition Techniques & Tools](#2-evidence-acquisition-techniques--tools)
3. [Memory Forensics](#3-memory-forensics)
4. [Disk Forensics](#4-disk-forensics)
5. [Rapid Triage Examination & Analysis Tools](#5-rapid-triage-examination--analysis-tools)
6. [Practical Digital Forensics Scenario](#6-practical-digital-forensics-scenario)
7. [Interview Questions](#7-interview-questions)
8. [Additional Resources](#8-additional-resources)

---

## 1. Introduction to Digital Forensics {#1-introduction-to-digital-forensics}

> 📌 **Digital Forensics** - The collection, preservation, analysis, and presentation of digital evidence to investigate cyber incidents.

### Overview

It is essential to clarify that this module does not claim to be an all-encompassing or exhaustive program on Digital Forensics. This module provides a robust foundation for SOC analysts, enabling them to confidently tackle key Digital Forensics tasks. The primary focus of the module will be the analysis of malicious activity within Windows-based environments.

---

### What is Digital Forensics?

**Digital forensics**, often referred to as computer forensics or cyber forensics, is a specialized branch of cybersecurity that involves the collection, preservation, analysis, and presentation of digital evidence to investigate cyber incidents, criminal activities, and security breaches.

It applies forensic techniques to digital artifacts, including computers, servers, mobile devices, networks, and storage media, to uncover the truth behind cyber-related events.

**Goals of Digital Forensics:**
- Reconstruct timelines
- Identify malicious activities
- Assess the impact of incidents
- Provide evidence for legal or regulatory proceedings

> 📌 Digital forensics is an integral part of the incident response process, contributing crucial insights and support at various stages.

---

### Key Concepts

#### Electronic Evidence

Digital forensics deals with electronic evidence, which can include:
- Files
- Emails
- Logs
- Databases
- Network traffic
- And more

This evidence is collected from computers, mobile devices, servers, cloud services, and other digital sources.

#### Preservation of Evidence

> 🔴 **Critical:** Ensuring the integrity and authenticity of digital evidence is crucial.

Proper procedures are followed to:
- Preserve evidence
- Establish a chain of custody
- Prevent any unintentional alterations

#### Forensic Process

The digital forensics process typically involves several stages:

| Stage | Description |
|-------|-------------|
| **Identification** | Determining potential sources of evidence |
| **Collection** | Gathering data using forensically sound methods |
| **Examination** | Analyzing the collected data for relevant information |
| **Analysis** | Interpreting the data to draw conclusions about the incident |
| **Presentation** | Presenting findings in a clear and comprehensible manner |

#### Types of Cases

Digital forensics is applied in a variety of cases:
- Cybercrime investigations (hacking, fraud, data theft)
- Intellectual property theft
- Employee misconduct investigations
- Data breaches and incidents affecting organizations
- Litigation support in legal proceedings

---

### Basic Steps for Performing a Forensic Investigation

1. **Create a Forensic Image** - Make an exact copy of the evidence
2. **Document the System's State** - Record initial observations
3. **Identify and Preserve Evidence** - Locate and secure relevant data
4. **Analyze the Evidence** - Examine the collected data
5. **Timeline Analysis** - Establish chronological sequence of events
6. **Identify Indicators of Compromise (IOCs)** - Find malicious artifacts
7. **Report and Documentation** - Document findings

---

### Digital Forensics for SOC Analysts

When we talk about the Security Operations Center (SOC), we're discussing the frontline defense against cyber threats. But what happens when a breach occurs, or when an anomaly is detected? That's where digital forensics comes into play.

#### Key Benefits for SOC Analysts

| Benefit | Description |
|---------|-------------|
| **Post-Mortem Analysis** | Detailed analysis of security incidents by tracing attacker steps |
| **Rapid Identification** | Swift identification of compromise moment, affected systems, malware type |
| **Legal Support** | Provides legally admissible evidence for court proceedings |
| **Proactive Hunting** | Actively search environments for signs of compromise |
| **Enhanced IR** | Better tailored incident response strategies |
| **Continuous Learning** | Stay ahead of new attack techniques |

> 📌 **Key Takeaway:** Digital forensics isn't just a reactive measure; it's a proactive tool that amplifies the capabilities of SOC analysts, ensuring that organizations remain resilient in the face of ever-evolving cyber threats.

---

## 2. Windows Forensics Overview {#2-windows-forensics-overview}

> 📌 **Windows Forensics** - Key artifacts and forensic procedures in Windows environments.

### NTFS (New Technology File System)

NTFS (New Technology File System) is a proprietary file system developed by Microsoft as part of its Windows NT operating system family. It was introduced with the release of Windows NT 3.1 in 1993 and has since become the default and most widely used file system in modern Windows operating systems.

NTFS was designed to address several limitations of its predecessor, the FAT (File Allocation Table) file system. It introduced numerous features and enhancements that improved reliability, performance, security, and storage capabilities.

---

### Key Forensic Artifacts in NTFS

| Artifact | Description |
|----------|-------------|
| **File Metadata** | Creation time, modification time, access time, attribute information |
| **MFT Entries** | Master File Table stores metadata for all files and directories |
| **File Slack** | Unused portion of a cluster that may contain data from previous files |
| **File Signatures** | File headers useful for identifying file types even with changed extensions |
| **USN Journal** | Update Sequence Number log recording changes to files/directories |
| **LNK Files** | Windows shortcuts containing target file info, timestamps, metadata |
| **Prefetch Files** | Application startup metadata showing execution history |
| **Registry Hives** | Configuration and system information (not directly file system) |
| **Shellbags** | Registry entries storing folder view settings |
| **Thumbnail Cache** | Miniature previews of images/documents |
| **Recycle Bin** | Deleted files that can be recovered |
| **Alternate Data Streams (ADS)** | Additional data streams associated with files |
| **Volume Shadow Copies** | Snapshots of file system at different points in time |
| **Security Descriptors/ACLs** | Access control lists determining permissions |

---

### Windows Event Logs

Windows Event Logs are an intrinsic part of the Windows Operating System, storing logs from different components including the system itself, applications, ETW providers, services, and others.

> 📌 Windows event logging offers comprehensive logging capabilities for application errors, security events, and diagnostic information.

Adversarial tactics from initial compromise using malware or other exploits, to credential accessing, privilege elevation and lateral movement using Windows operating system's internal tools are often captured via Windows event logs.

**Default Log Path:** `C:\Windows\System32\winevt\logs`

> 📌 The analysis of Windows Event Logs has been addressed in the modules titled "Windows Event Logs & Finding Evil" and "YARA & Sigma for SOC Analysts".

---

### Execution Artifacts

Windows execution artifacts refer to traces and evidence left behind when programs and processes are executed. These artifacts provide valuable insights into application execution, crucial for digital forensics investigations.

#### Types of Execution Artifacts

| Artifact | Location | Data Stored |
|----------|----------|-------------|
| **Prefetch Files** | `C:\Windows\Prefetch` | File paths, execution counts, timestamps |
| **Shimcache** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Program execution details, file paths, timestamps |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Application details, file paths, sizes, digital signatures |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Executed program details, execution counts |
| **RunMRU Lists** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Recently executed programs and command lines |
| **Jump Lists** | `%AppData%\Microsoft\Windows\Recent` | Recently accessed files, folders, tasks |
| **Shortcut (LNK) Files** | Various (Desktop, Start Menu) | Target executable, file paths, timestamps |
| **Recent Items** | `%AppData%\Microsoft\Windows\Recent` | Recently accessed files |
| **Windows Event Logs** | `C:\Windows\System32\winevt\Logs` | Process creation, termination, events |

---

### Windows Persistence Artifacts

Windows persistence refers to techniques used by attackers to ensure unauthorized presence on a compromised system.

#### Registry Autorun Keys

| Registry Path | Description |
|---------------|-------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | User-level auto-start programs |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Run once then delete |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | System-level auto-start programs |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | System-level run once |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | WinLogon process keys |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell configuration |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` | User shell folders |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | Shell folder paths |

#### Scheduled Tasks (Schtasks)

- **Location:** `C:\Windows\System32\Tasks`
- **Format:** XML files containing task creator, timing/triggers, command paths

#### Services

- **Registry Location:** `HKLM\System\CurrentControlSet\Services`
- Malicious actors often tamper with or create rogue services for persistence

---

### Web Browser Forensics

Web browser forensics analyzes remnants left by web browsers to understand user actions and potentially harmful behaviors.

#### Key Browser Artifacts

| Artifact | Description |
|----------|-------------|
| **Browsing History** | Records of websites visited (URLs, titles, timestamps) |
| **Cookies** | Session details, preferences, authentication tokens |
| **Cache** | Cached copies of web pages/images |
| **Bookmarks/Favorites** | Saved links to frequently visited sites |
| **Download History** | Downloaded files with source URLs |
| **Autofill Data** | Auto-entered form data (names, addresses, passwords) |
| **Search History** | Search engine queries |
| **Typed URLs** | URLs entered directly in address bar |
| **Passwords** | Saved or autofilled passwords |
| **Extensions/Add-ons** | Browser extensions and configurations |

---

### SRUM (System Resource Usage Monitor)

> 📌 SRUM is a feature introduced in Windows 8+ that tracks resource utilization and application usage patterns.

- **Data Location:** `C:\Windows\System32\sru\sru.db` (SQLite format)
- **Purpose:** Records application execution, resource consumption over time intervals

#### Key Facets of SRUM Forensics

| Facet | Description |
|-------|-------------|
| **Application Profiling** | Executable names, file paths, timestamps |
| **Resource Consumption** | CPU time, network usage, memory consumption |
| **Timeline Reconstruction** | Chronological application/process execution |
| **User Context** | User identifiers for activity attribution |
| **Malware Detection** | Identify unusual/unauthorized applications |
| **Incident Response** | Rapid insights into recent activities |

---

*Module 13/15 - Introduction to Digital Forensics*
*For learning and SOC career preparation*