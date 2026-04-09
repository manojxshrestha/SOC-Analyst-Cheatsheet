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
2. [Windows Forensics Overview](#2-windows-forensics-overview)
3. [Evidence Acquisition Techniques & Tools](#3-evidence-acquisition-techniques--tools)
4. [Memory Forensics](#4-memory-forensics)
5. [Disk Forensics](#5-disk-forensics)
6. [Rapid Triage Examination & Analysis Tools](#6-rapid-triage-examination--analysis-tools)
7. [Practical Digital Forensics Scenario](#7-practical-digital-forensics-scenario)
8. [Interview Questions](#8-interview-questions)
9. [Additional Resources](#9-additional-resources)

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

## 3. Evidence Acquisition Techniques & Tools {#3-evidence-acquisition-techniques--tools}

> 📌 **Evidence Acquisition** - Critical phase involving collection of digital artifacts from various sources.

### Overview

Evidence acquisition is a critical phase in digital forensics, involving the collection of digital artifacts and data from various sources to preserve potential evidence for analysis. This process requires specialized tools and techniques to ensure integrity, authenticity, and admissibility.

**Three Main Categories:**
1. Forensic Imaging
2. Extracting Host-based Evidence & Rapid Triage
3. Extracting Network Evidence

---

### Forensic Imaging

Forensic imaging is a fundamental process that involves creating an exact, bit-by-bit copy of digital storage media. This process is crucial for preserving the original state of data and ensuring admissibility in legal proceedings.

#### Forensic Imaging Tools

| Tool | Description |
|------|-------------|
| **FTK Imager** | Developed by AccessData/Exterro. Creates perfect copies of computer disks, view contents without altering data |
| **AFF4 Imager** | Free, open-source. Compatible with numerous file systems. Can extract files by creation time |
| **DD** | Command-line utility on Unix-based systems |
| **DCFLDD** | Enhanced version of DD with forensics features (hashing) |
| **Virtualization Tools** | Evidence from virtual environments via halting/snapshot |

---

### Example 1: Forensic Imaging with FTK Imager

Steps to create a disk image:

1. **Select File → Create Disk Image**
2. **Choose Media Source:** Physical Drive or Logical Drive

![FTK Imager - Create Disk Image](https://github.com/user-attachments/assets/212e5f05-1169-4d52-9aa9-a7249db3eed9)

3. **Select Drive** (e.g., PHYSICALDRIVE0)

![FTK Imager - Select Source](https://github.com/user-attachments/assets/310d5155-2a53-4411-8a65-f534c15025a6)

4. **Specify Destination** for the image

![FTK Imager - Create Image](https://github.com/user-attachments/assets/374a4246-0f75-4e72-a823-32ca121acf54)

5. **Choose Image Type:** Raw, SMART, E01, or AFF

![FTK Imager - Select Image Type](https://github.com/user-attachments/assets/8cc98e9a-8a20-4508-b552-aec722c4546a)

6. **Input Evidence Details:** Case Number, Evidence Number, Unique Description

![FTK Imager - Evidence Item Information](https://github.com/user-attachments/assets/59d38824-2a25-4b7c-8c8d-59c19c0ebd32)

7. **Set Destination Folder and Filename** (adjust fragmentation/compression if needed)

![FTK Imager - Select Image Destination](https://github.com/user-attachments/assets/cfae5614-d310-4083-a627-ba94aec6cfe9)

8. **Click Start** to begin imaging

![FTK Imager - Creating Image Progress](https://github.com/user-attachments/assets/c9e2667f-9c61-4177-b4d6-ea8c9a204331)

9. **Verify Image** (if selected) - compares MD5/SHA1 hashes

![FTK Imager - Verification Progress](https://github.com/user-attachments/assets/a6a6899c-2517-4823-83a3-88955fb4eac6)

![FTK Imager - Verification Results](https://github.com/user-attachments/assets/fb4eeac8-e29f-427a-b8d1-c1a1f8b255a)

> 📌 FTK Imager provides verification that calculates and compares MD5/SHA1 hashes to ensure image integrity.

---

### Example 2: Mounting a Disk Image with Arsenal Image Mounter

1. Launch Arsenal Image Mounter with administrative rights
2. Click **Mount disk image** button
3. Navigate to and select the `.VMDK` file
4. Choose to mount as **read-only** or **read-write**

![Arsenal Image Mounter - Mount VM](https://github.com/user-attachments/assets/64e6c0eb-b559-4bd1-900e-ef5e468f181c)

> 🔴 **Critical:** Always mount disk images as **read-only** to preserve original evidence integrity.

Once mounted, the image appears as a drive (e.g., `D:\`) and can be browsed like a physical drive.

![File Explorer - Mounted Image](https://github.com/user-attachments/assets/1d372c39-cd32-4efd-9f09-dd29c93f8502)

---

### Extracting Host-based Evidence & Rapid Triage

#### Volatile vs Non-Volatile Data

**Volatile Data** - Information that disappears after logoffs or power shutdowns:
- Active system memory (RAM)
- Captured using tools like FTK Imager, WinPmem, DumpIt

**Non-Volatile Data** - Remains on hard drive through shutdowns:
- Registry
- Windows Event Logs
- Prefetch, Amcache
- Application-specific artifacts

#### Memory Acquisition Tools

| Tool | Description |
|------|-------------|
| **WinPmem** | Default open-source memory acquisition for Windows |
| **DumpIt** | Simplistic utility for Windows/Linux memory dumps |
| **MemDump** | Free command-line RAM capture utility |
| **Belkasoft RAM Capturer** | Captures RAM even with anti-debugging protection |
| **Magnet RAM Capture** | Free, simple way to capture volatile memory |
| **LiME (Linux Memory Extractor)** | Loadable Kernel Module for Linux memory acquisition |

##### Example: Acquiring Memory with WinPmem

```cmd
C:\Users\X\Downloads> winpmem_mini_x64_rc2.exe memdump.raw
```

![WinPmem Memory Dump](https://github.com/user-attachments/assets/d7f84e90-3b0b-4e23-b7db-2aa27abf68bd)

##### Example: Acquiring VM Memory

1. Open the running VM's options
2. **Suspend** the running VM
3. Locate the `.vmem` file inside the VM's directory

![VMware Suspend VM](https://github.com/user-attachments/assets/7120464e-e1e4-4fc5-bb41-4811aa18f7b1)

![VMEM File Location](https://github.com/user-attachments/assets/9a324682-6390-4c83-9e62-f1e30dabd1b0)

---

### Rapid Triage with KAPE

> 📌 **KAPE (Kroll Artifact Parser and Extractor)** - One of the best rapid artifact parsing and extraction solutions.

KAPE operates based on **Targets** and **Modules**:
- **Targets:** Specific artifacts to extract from an image/system (duplicated to output directory)
- **Modules:** Programs run on collected data for processing

![KAPE Flowchart](https://github.com/user-attachments/assets/d4f69059-427c-43c2-9a0c-b7b63d380761)

![KAPE Workflow](https://github.com/user-attachments/assets/77f1a536-da66-49b3-86bb-c494137dfcee)

#### KAPE Modes

| Mode | File | Description |
|------|------|-------------|
| **GUI** | `gkape.exe` | Visual interface |
| **CLI** | `kape.exe` | Command-line interface |

![KAPE Files](https://github.com/user-attachments/assets/17e69376-ee00-4691-a2b6-a3aeb2aceee6)

#### KAPE GUI Interface

![KAPE GUI](https://github.com/user-attachments/assets/c2d0cccc-1b8d-4763-a0ea-29608e1e4c7c)

#### Target Configurations

| Target | Description |
|--------|-------------|
| **!SANS_Triage** | Compound collection for DFIR investigation |
| **RegistryHivesSystem** | System-related registry hives |
| **KapeTriage** | Multiple targets combined for faster collection |

![KAPE Target Config](https://github.com/user-attachments/assets/a1a8dc7b-07dc-43b8-8dc3-8aa828bd961e)

Example compound target includes: Antivirus, EventLogs, EvidenceOfExecution, Amcache

![KAPE Registry Target](https://github.com/user-attachments/assets/bafe8941-4de3-4014-8c38-5319733f6ed4)

![KAPE Compound Target](https://github.com/user-attachments/assets/1278ce30-2d0d-4256-847c-55f497369c83)

#### KAPE Command Example

```powershell
KAPE.exe --tsource D: --tdest C:\investigation\image --target !SANS_Triage
```

**KAPE Output:**

```
KAPE version 1.3.0.2, Author: Eric Zimmerman, Contact: https://www.kroll.com/kape (kape@kroll.com)

KAPE directory: C:\htb\dfir_module\data\kape\KAPE
Command line:   --tsource D: --tdest C:\htb\dfir_module\data\investigation\image --target !SANS_Triage --gui

System info: Machine name: REDACTED, 64-bit: True, User: REDACTED OS: Windows10 (10.0.22621)

Using Target operations
Found 18 targets. Expanding targets to file list...
Target ApplicationEvents with Id 2da16dbf-ea47-448e-a00f-fc442c3109ba already processed. Skipping!
...
Found 639 files in 4.032 seconds. Beginning copy...
  Deferring D:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTDefenderApiLogger.etl due to UnauthorizedAccessException...
  Deferring D:\$MFT due to UnauthorizedAccessException...
  ...
Deferred file count: 17. Copying locked files...
  Copied deferred file D:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTDefenderApiLogger.etl to C:\htb\dfir_module\data\investigation\image\D\Windows\System32\LogFiles\WMI\RtBackup\EtwRTDefenderApiLogger.etl. Hashing source file...
  Copied deferred file D:\$MFT to C:\htb\dfir_module\data\investigation\image\D\$MFT. Hashing source file...
  ...
```

**Output:**
- Found 639 files copied in ~4 seconds
- Collects: $MFT, $LogFile, $UsnJrnl, $Secure, $Boot
- Windows event logs in System32 subfolders
- Users and Windows directories

![KAPE Execute](https://github.com/user-attachments/assets/b84dc1d8-718c-49d0-9703-abf4a31336f3)

#### KAPE Output

![KAPE Output Directory](https://github.com/user-attachments/assets/8bd01fbe-3899-42ce-afc4-dcf004d09737)

![KAPE Event Logs](https://github.com/user-attachments/assets/36952500-ed3d-4f3b-bbf8-0b34a3a4a454)

---

### Velociraptor for Remote Collection

**Velociraptor** - Potent tool for gathering host-based information using VQL queries.

#### Using Velociraptor for KAPE Artifacts

1. **Initiate a new Hunt**

![Velociraptor - New Hunt](https://github.com/user-attachments/assets/d6e9a25d-be42-4438-a13b-e9eb28076fa6)

2. **Select Windows.KapeFiles.Targets** artifact

![Velociraptor - Configure Hunt](https://github.com/user-attachments/assets/6b0f1a4f-0308-4959-8ef5-81069e9d8e13)

3. **Configure** collection (e.g., _SANS_Triage)

![Velociraptor - Select Artifact](https://github.com/user-attachments/assets/ecce0f3d-a65b-4a02-9943-fe430df523c2)

![Velociraptor - Artifact Parameters](https://github.com/user-attachments/assets/e24dd340-1379-4d83-91e1-f6e9a0fe1baa)

![Velociraptor - Configure Target](https://github.com/user-attachments/assets/01a308da-6fbc-42fa-a5c9-717ac2b8c01f)

4. **Launch** the hunt

![Velociraptor - Launch Hunt](https://github.com/user-attachments/assets/fc447edb-0ed1-410b-9499-5d7aeb3690c8)

5. **Download** results

![Velociraptor - Download Results](https://github.com/user-attachments/assets/69e91f41-92f0-423a-9112-4f89fc5bcc05)

#### Velociraptor Output

![Velociraptor - Output Directory](https://github.com/user-attachments/assets/52a4cdab-915c-41da-9c81-987629fb26c1)

![Velociraptor - Collected Files](https://github.com/user-attachments/assets/61d33a42-390c-4ccf-b09c-71276f00f845)

#### Remote Memory Dump with Velociraptor

1. Start new Hunt
2. Select **Windows.Memory.Acquisition** artifact

![Velociraptor - Memory Acquisition](https://github.com/user-attachments/assets/e7613e3d-1717-4191-a5ef-f4661c4d5d13)

3. Download resulting archive
4. Extract `PhysicalMemory.raw` containing the memory dump

![Velociraptor - Memory Hunt Results](https://github.com/user-attachments/assets/f76d4f8c-44d2-4a24-9d88-f7d6ab4d8207)

---

### Extracting Network Evidence

**Network Evidence Categories:**

| Category | Tools/Description |
|----------|-------------------|
| **Traffic Capture** | Wireshark, tcpdump - snapshot of network conversations |
| **IDS/IPS Data** | Detection and blocking of malicious activities |
| **Traffic Flow** | NetFlow, sFlow - high-level overview of traffic patterns |
| **Firewall Logs** | Application identification, user detection, threat blocking |

> 📌 Network evidence analysis covered in: Intro to Network Traffic Analysis, Intermediate Network Traffic Analysis, Working with IDS/IPS, Detecting Windows Attacks with Splunk.

---

*Module 13/15 - Introduction to Digital Forensics*
*For learning and SOC career preparation*