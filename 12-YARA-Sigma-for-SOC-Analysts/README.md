# 🎯 YARA & SIGMA FOR SOC ANALYSTS

## SOC Analyst Cheatsheet - Module 12/15

---

## 0. Overview {#0-overview}

> 📌 **YARA & Sigma** - Essential detection rules for SOC analysts to hunt threats on disk, processes, memory, and SIEM.

### Module Description

This module covers:
- Creating YARA rules manually and automatically
- Applying YARA rules to hunt threats (disk, processes, memory, online databases)
- Building Sigma rules and translating them to SIEM queries
- Using sigmac utility
- Hunting threats in event logs and SIEM solutions

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

0. [Overview](#0-overview)
1. [Introduction to YARA & Sigma](#1-introduction-to-yara--sigma)
2. [Leveraging YARA](#2-leveraging-yara)
3. [Developing YARA Rules](#3-developing-yara-rules)
4. [Hunting Evil with YARA (Windows Edition)](#4-hunting-evil-with-yara-windows-edition)
5. [Hunting Evil with YARA (Linux Edition)](#5-hunting-evil-with-yara-linux-edition)
6. [Hunting Evil with YARA (Web Edition)](#6-hunting-evil-with-yara-web-edition)
7. [Sigma and Sigma Rules](#7-sigma-and-sigma-rules)
8. [Developing Sigma Rules](#8-developing-sigma-rules)
9. [Hunting Evil with Sigma (Chainsaw Edition)](#9-hunting-evil-with-sigma-chainsaw-edition)
10. [Hunting Evil with Sigma (Splunk Edition)](#10-hunting-evil-with-sigma-splunk-edition)
11. [Interview Questions](#11-interview-questions)
12. [Additional Resources](#12-additional-resources)

---

## 1. Introduction to YARA & Sigma {#1-introduction-to-yara--sigma}

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

## 2. Leveraging YARA {#2-leveraging-yara}

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
> - 0x5A4D = ASCII "MZ" (PE executable)
> - 0x4D5A = ASCII "ZM" (reverse PE)

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
- **Modifiers** - fullword, ascii, nocase, wide, xor, base64
- **Logical Operators** - and, or, not
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

## 3. Developing YARA Rules {#3-developing-yara-rules}

> 📌 This section covers manual and automated YARA rule development.

### Manual YARA Rule Development

Let's use a sample `svchost.exe` in `/home/htb-student/Samples/YARASigma` to understand the process.

#### Step 1: String Analysis

```bash
strings svchost.exe
```

**Output:**
```
!This program cannot be run in DOS mode.
UPX0
UPX1
UPX2
3.96
UPX!
KERNEL32.DLL
msvcrt.dll
ExitProcess
GetProcAddress
...
```

> 📌 The file is packed using UPX (Ultimate Packer for eXecutables).

#### Step 2: Create YARA Rule

```yara
rule UPX_packed_executable {
    meta:
        description = "Detects UPX-packed executables"

    strings: 
        $string_1 = "UPX0"
        $string_2 = "UPX1"
        $string_3 = "UPX2"

    condition:
        all of them
}
```

**Rule Breakdown:**
- **Rule Name:** UPX_packed_executable
- **Meta Description:** Detects UPX-packed executables
- **Strings:** Defines strings to search (UPX0, UPX1, UPX2)
- **Condition:** All strings must be found

---

### Automated YARA Rule Development with yarGen

> 📌 **yarGen** automatically generates YARA rules based on strings found in malicious files while avoiding common goodware strings. It uses a database of goodware strings to filter out common benign strings.

#### Step 1: String Analysis on dharma_sample.exe

```bash
strings dharma_sample.exe
```

**Full Output:**
```
!This program cannot be run in DOS mode.
Rich
.text
`.rdata
@.data
9A s
---SNIP---
~?h@
~?hP
hz-A
u       jd
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>@@@?456789:;<=@@@@@@@
@@@@@@
 !"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
---SNIP---
GetProcAddress
LoadLibraryA
WaitForSingleObject
InitializeCriticalSectionAndSpinCount
LeaveCriticalSection
GetLastError
EnterCriticalSection
ReleaseMutex
CloseHandle
KERNEL32.dll
RSDS%~m
C:\crysis\Release\PDB\payload.pdb
---SNIP---
```

> 📌 **Key Finding:** The unique string `C:\crysis\Release\PDB\payload.pdb` is a path reference that reveals the malware was compiled in a developer's environment (crysis). This is an excellent IOC for YARA rule creation!

#### Setup yarGen

```bash
# Download latest release
# Install dependencies
pip install -r requirements.txt

# Update databases
python yarGen.py --update
```

#### Using yarGen

```bash
python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar
```

**Command Breakdown:**

- python3 yarGen.py: Execute the yarGen Python script
- -m /home/htb-student/temp: This option specifies the source directory where the sample files (e.g., malware or suspicious files) are located. The script will analyze these samples to generate YARA rules.
- -o htb_sample.yar: This option indicates the output file name for the generated YARA rules. In this case, the YARA rules will be saved to a file named htb_sample.yar.

**Output Example:**
```
[+] Using identifier 'temp'
[+] Using reference 'https://github.com/Neo23x0/yarGen'
[+] Using prefix 'temp'
[+] Processing PEStudio strings ...
[+] Reading goodware strings from database 'good-strings.db' ...
    (This could take some time and uses several Gigabytes of RAM depending on your db size)
[+] Loading ./dbs/good-imphashes-part3.db ...
[+] Total: 4029 / Added 4029 entries
[+] Loading ./dbs/good-strings-part9.db ...
[+] Total: 788 / Added 788 entries
[+] Loading ./dbs/good-strings-part8.db ...
[+] Total: 332082 / Added 331294 entries
[+] Loading ./dbs/good-imphashes-part4.db ...
[+] Total: 6426 / Added 2397 entries
[+] Loading ./dbs/good-strings-part2.db ...
[+] Total: 1703601 / Added 1371519 entries
[+] Loading ./dbs/good-exports-part2.db ...
[+] Total: 90960 / Added 90960 entries
[+] Loading ./dbs/good-strings-part4.db ...
[+] Total: 3860655 / Added 2157054 entries
[+] Loading ./dbs/good-exports-part4.db ...
[+] Total: 172718 / Added 81758 entries
[+] Loading ./dbs/good-exports-part7.db ...
[+] Total: 223584 / Added 50866 entries
[+] Loading ./dbs/good-strings-part6.db ...
[+] Total: 4571266 / Added 710611 entries
[+] Loading ./dbs/good-strings-part7.db ...
[+] Total: 5828908 / Added 1257642 entries
[+] Loading ./dbs/good-exports-part1.db ...
[+] Total: 293752 / Added 70168 entries
[+] Loading ./dbs/good-exports-part3.db ...
[+] Total: 326867 / Added 33115 entries
[+] Loading ./dbs/good-imphashes-part9.db ...
[+] Total: 6426 / Added 0 entries
[+] Loading ./dbs/good-exports-part9.db ...
[+] Total: 326867 / Added 0 entries
[+] Loading ./dbs/good-imphashes-part5.db ...
[+] Total: 13764 / Added 7338 entries
[+] Loading ./dbs/good-imphashes-part8.db ...
[+] Total: 13947 / Added 183 entries
[+] Loading ./dbs/good-imphashes-part6.db ...
[+] Total: 13976 / Added 29 entries
[+] Loading ./dbs/good-strings-part1.db ...
[+] Total: 6893854 / Added 1064946 entries
[+] Loading ./dbs/good-imphashes-part7.db ...
[+] Total: 17382 / Added 3406 entries
[+] Loading ./dbs/good-exports-part6.db ...
[+] Total: 328525 / Added 1658 entries
[+] Loading ./dbs/good-imphashes-part2.db ...
[+] Total: 18208 / Added 826 entries
[+] Loading ./dbs/good-exports-part8.db ...
[+] Total: 332359 / Added 3834 entries
[+] Loading ./dbs/good-strings-part3.db ...
[+] Total: 9152616 / Added 2258762 entries
[+] Loading ./dbs/good-strings-part5.db ...
[+] Total: 12284943 / Added 3132327 entries
[+] Loading ./dbs/good-imphashes-part1.db ...
[+] Total: 19764 / Added 1556 entries
[+] Loading ./dbs/good-exports-part5.db ...
[+] Total: 404321 / Added 71962 entries
[+] Processing malware files ...
[+] Processing /home/htb-student/temp/dharma_sample.exe ...
[+] Generating statistical data ...
[+] Generating Super Rules ... (a lot of magic)
[+] Generating Simple Rules ...
[-] Applying intelligent filters to string findings ...
[-] Filtering string set for /home/htb-student/temp/dharma_sample.exe ...
[=] Generated 1 SIMPLE rules.
[=] All rules written to htb_sample.yar
[+] yarGen run finished
```

> 📌 **yarGen Database Loading** - yarGen loads multiple goodware databases to filter out common benign strings:
> - good-strings-part*.db - Goodware string databases
> - good-imphashes-part*.db - Goodware import hash databases
> - good-exports-part*.db - Goodware export databases
> - Total entries loaded can exceed 12 million strings!

#### Generated Rule Example

```yara
rule dharma_sample {
   meta:
      description = "temp - file dharma_sample.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-24"
      hash1 = "bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071"
   strings:
      $x1 = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
      $s2 = "sssssbs" fullword ascii
      $s3 = "sssssbsss" fullword ascii
      $s4 = "RSDS%~m" fullword ascii
      $s5 = "{RDqP^\\" fullword ascii
      $s6 = "QtVN$0w" fullword ascii
      $s7 = "Ffsc<{" fullword ascii
      $s8 = "^N3Y.H_K" fullword ascii
      $s9 = "tb#w\\6" fullword ascii
      $s10 = "-j6EPUc" fullword ascii
      $s11 = "8QS#5@3" fullword ascii
      $s12 = "h1+LI;d8" fullword ascii
      $s13 = "H;B cl" fullword ascii
      $s14 = "Wy]z@p]E" fullword ascii
      $s15 = "ipgypA" fullword ascii
      $s16 = "+>^wI{H" fullword ascii
      $s17 = "mF@S/]" fullword ascii
      $s18 = "OA_<8X-|" fullword ascii
      $s19 = "s+aL%M" fullword ascii
      $s20 = "sXtY9P" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}
```

> 📌 **Key Points:**
> - $x1 is an exclusive string (likely unique to malware) - matched with 1 of ($x*)
> - $s2 to $s20 are supplementary strings - matched with 4 of them
> - The rule requires the file to be a valid PE (`uint16(0) == 0x5a4d`) and smaller than 300KB

#### Testing YARA Rule

```bash
yara htb_sample.yar /home/htb-student/Samples/YARASigma
```

**Output:**
```
dharma_sample /home/htb-student/Samples/YARASigma/dharma_sample.exe
dharma_sample /home/htb-student/Samples/YARASigma/pdf_reader.exe
dharma_sample /home/htb-student/Samples/YARASigma/microsoft.com
dharma_sample /home/htb-student/Samples/YARASigma/check_updates.exe
dharma_sample /home/htb-student/Samples/YARASigma/KB5027505.exe
```

---

### Advanced YARA Rule Examples

#### Example 1: APT17 (ZoxPNG RAT)

**Sample:** `legit.exe`

**String Analysis:**
```bash
strings legit.exe
```

**Key Strings Found:**
```
!This program cannot be run in DOS mode.
Rich
.text
`.rdata
@.data
---SNIP---
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
 deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly
 inflate 1.1.4 Copyright 1995-2002 Mark Adler
Sleep
LocalAlloc
CloseHandle
GetLastError
VirtualFree
VirtualAlloc
GetProcAddress
LoadLibraryA
GetCurrentProcessId
GlobalMemoryStatusEx
GetCurrentProcess
GetACP
GetVersionExA
GetComputerNameA
GetTickCount
GetSystemTime
LocalFree
CreateProcessA
CreatePipe
TerminateProcess
ReadFile
PeekNamedPipe
WriteFile
SetFilePointer
CreateFileA
GetFileSize
GetDiskFreeSpaceExA
GetDriveTypeA
GetLogicalDriveStringsA
CreateDirectoryA
FindClose
FindNextFileA
FindFirstFileA
MoveFileExA
OpenProcess
KERNEL32.dll
LookupAccountSidA
ADVAPI32.dll
SHFileOperationA
SHELL32.dll
strcpy
rand
sprintf
memcpy
strncpy
srand
_snprintf
atoi
strcat
strlen
printf
memset
strchr
memcmp
MSVCRT.dll
---SNIP---
InternetCrackUrlA
InternetCloseHandle
InternetReadFile
HttpQueryInfoA
HttpSendRequestA
InternetSetOptionA
HttpAddRequestHeadersA
HttpOpenRequestA
InternetConnectA
InternetOpenA
WININET.dll
ObtainUserAgentString
urlmon.dll
WTSFreeMemory
WTSEnumerateProcessesA
WTSAPI32.dll
GetModuleFileNameExA
PSAPI.DLL
calloc
free
http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM:&imgrefurl=http://%s&docid=1bi0Ti1ZVr4bEM&imgurl=http://%s/%04d-%02d/%04d%02d%02d%02d%02d%02d.png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58
http://0.0.0.0/1
http://0.0.0.0/2
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)
image/pjpeg
image/jpeg
image/x-xbitmap
image/gif
Content-Type: application/x-www-form-urlencoded
B64:[%s]
Step 11
Step 10
Step 9
Step 8
Step 7
Step 6
Content-Type: image/x-png
Step 5
Step 4
Connection: close
Accept-Encoding: gzip, deflate
Accept-Language: en-US
Pragma: no-cache
User-Agent:
Cookie: SESSIONID=%s
Step 3
HTTP/1.1
Step 2
POST
Step 1
Get URL Info Error
[IISEND=0x%08X][Recv:] 0x%08X %s
IISCMD Error:%d
hWritePipe2 Error:%d
kernel32.dll
QueryFullProcessImageName
Not Support This Function!
---SNIP---
```

**Calculate Imphash:**
```bash
python3 imphash_calc.py /home/htb-student/Samples/YARASigma/legit.exe
```
**Output:** `414bbd566b700ea021cfae3ad8f4d9b9`

**YARA Rule:**
```yara
import "pe"

rule APT17_Malware_Oct17_Gen {
   meta:
      description = "Detects APT17 malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
      hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
      hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
      $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii

      $s1 = "hWritePipe2 Error:%d" fullword ascii
      $s2 = "Not Support This Function!" fullword ascii
      $s3 = "Cookie: SESSIONID=%s" fullword ascii
      $s4 = "http://0.0.0.0/1" fullword ascii
      $s5 = "Content-Type: image/x-png" fullword ascii
      $s6 = "Accept-Language: en-US" fullword ascii
      $s7 = "IISCMD Error:%d" fullword ascii
      $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
         )
      )
}
```

**Rule Breakdown:**

📌 **Rule Imports:**
- **import "pe"**: By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files

📌 **Rule Meta:**
- **description**: Main purpose - detect APT17 malware
- **license**: Detection Rule License 1.1
- **author**: Florian Roth (Nextron Systems)
- **reference**: https://goo.gl/puVc9q
- **date**: 3rd October 2017
- **hash1, hash2, hash3**: Hash values of samples related to APT17

📌 **Rule Body:**
- **$x* strings (exclusive strings)**: Less likely to appear in benign files
- **$s* strings (supplementary strings)**: Additional strings that support detection

📌 **Rule Condition:**
- **uint16(0) == 0x5a4d**: Check for "MZ" magic bytes (Windows PE file)
- **filesize < 200KB**: Limit to small files
- **pe.imphash()**: Match import hash "414bbd566b700ea021cfae3ad8f4d9b9"
- **1 of ($x*)**: At least one exclusive string must match
- **6 of them**: At least 6 total strings must match

---

#### Example 2: Neuron (Turla)

**Sample:** `Microsoft.Exchange.Service.exe` (.NET malware)

**Analysis Approach:**
Since the report mentions that both the Neuron client and Neuron service are written using the .NET framework, we will perform .NET "reversing" instead of string analysis using the monodis tool.

**Disassemble .NET Assembly:**
```bash
monodis --output=code Microsoft.Exchange.Service.exe
```

**Key Output - Classes Identified:**
```
.assembly extern System.Configuration.Install
{
  .ver 4:0:0:0
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A ) // .?_....:
}
---SNIP---
  .class public auto ansi abstract sealed beforefieldinit StorageUtils
  } // end of class Utils.StorageUtils
---SNIP---
```

**Key Output - Functions Identified:**
```
           default void ExecCMD (string path, string key, unsigned int8[] cmd, class Utils.Config cfg, class [mscorlib]System.Threading.ManualResetEvent mre)  cil managed
       IL_0028:  ldsfld class [System.Core]System.Runtime.CompilerServices.CallSite`1<class [mscorlib]System.Func`5<class [System.Core]System.Runtime.CompilerServices.CallSite,class [mscorlib]System.Type,object,class Utils.Config,class Utils.CommandScript>> Utils.Storage/'<ExecCMD>o__SiteContainer0'::'<>p__Site1'
---SNIP---
       IL_0029:  ldftn void class Utils.Storage::KillOldThread()
          default void KillOldThread ()  cil managed
    } // end of method Storage::KillOldThread
---SNIP---

       IL_0201:  ldstr "EncryptScript"
       IL_04a4:  call unsigned int8[] class Utils.Crypt::EncryptScript(unsigned int8[], unsigned int8[])
---SNIP---
          default unsigned int8[] EncryptScript (unsigned int8[] pwd, unsigned int8[] data)  cil managed
    } // end of method Crypt::EncryptScript
```

> 📌 By analyzing the .NET assembly with monodis, we can identify class names (StorageUtils, WebServer, StorageFile, CommandScript) and function names (ExecCMD, EncryptScript, KillOldThread) that are unique to the Neuron malware.

**Better Reversing Solution - dnSpy:**

A better reversing solution would be to load the .NET assembly (Microsoft.Exchange.Service.exe) into a .NET debugger and assembly editor like dnSpy.

![dnSpy Decompiler](https://github.com/user-attachments/assets/43a8dceb-e813-47d8-9ed1-b13ec2109501)

*Visual Studio interface showing decompiled C# code with highlighted method 'ExecCMD' in 'neuro_service' class, displaying parameters for executing commands.*

**YARA Rule:**
```yara
rule neuron_functions_classes_and_vars {
 meta:
    description = "Rule for detection of Neuron based on .NET functions and class names"
    author = "NCSC UK"
    reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
    reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
    $class1 = "StorageUtils" ascii
    $class2 = "WebServer" ascii
    $class3 = "StorageFile" ascii
    $class4 = "StorageScript" ascii
    $class5 = "ServerConfig" ascii
    $class6 = "CommandScript" ascii
    $class7 = "MSExchangeService" ascii
    $class8 = "W3WPDIAG" ascii
    $func1 = "AddConfigAsString" ascii
    $func2 = "DelConfigAsString" ascii
    $func3 = "GetConfigAsString" ascii
    $func4 = "EncryptScript" ascii
    $func5 = "ExecCMD" ascii
    $func6 = "KillOldThread" ascii
    $func7 = "FindSPath" ascii
    $dotnetMagic = "BSJB" ascii
 condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of them
}
```

**Rule Breakdown:**

**Strings Section:**
- **$class1 to $class8**: Class names within .NET assembly (StorageUtils, WebServer, StorageFile, StorageScript, ServerConfig, CommandScript, MSExchangeService, W3WPDIAG)
- **$func1 to $func7**: Function names (AddConfigAsString, DelConfigAsString, GetConfigAsString, EncryptScript, ExecCMD, KillOldThread, FindSPath)
- **$dotnetMagic = "BSJB"**: CLI header signature - present in .NET binaries

**Condition Section:**
- **uint16(0) == 0x5A4D**: Check for "MZ" magic bytes (Windows PE)
- **uint16(uint32(0x3c)) == 0x4550**: Verify "PE" header at offset 0x3c
- **$dotnetMagic**: Check for .NET CLI header (BSJB)
- **6 of them**: At least 6 strings must match

---

#### Example 3: Stonedrill (Shamoon 2.0)

**Sample:** `sham2.exe`

**Check Entropy:**
```bash
python3 entropy_pe_section.py -f /home/htb-student/Samples/YARASigma/sham2.exe
```

**Output:**
```
    virtual address: 0x1000
    virtual size: 0x25f86
    raw size: 0x26000
    entropy: 6.4093453613451885
.rdata
    virtual address: 0x27000
    virtual size: 0x62d2
    raw size: 0x6400
    entropy: 4.913675128870228
.data
    virtual address: 0x2e000
    virtual size: 0xb744
    raw size: 0x9000
    entropy: 1.039771174750106
.rsrc
    virtual address: 0x3a000
    virtual size: 0xc888
    raw size: 0xca00
    entropy: 7.976847940518103
```

> 📌 **Key Finding:** The resource section (.rsrc) has high entropy (7.98). Maximum entropy is 8.0, so this indicates the resource is encrypted/compressed! This is a strong indicator of obfuscated malicious content.

**YARA Rule:**
```yara
import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
  meta:
    copyright = "Kaspersky Lab"
    description = "Generic detection for samples that enumerate files with encrypted resource called 101"
    reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/"
    hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
    hash = "c843046e54b755ec63ccb09d0a689674"
    version = "1.4"
  strings:
    $mz = "This program cannot be run in DOS mode."
    $a1 = "FindFirstFile" ascii wide nocase
    $a2 = "FindNextFile" ascii wide nocase
    $a3 = "FindResource" ascii wide nocase
    $a4 = "LoadResource" ascii wide nocase

  condition:
    uint16(0) == 0x5A4D and
    all of them and
    filesize < 700000 and
    pe.number_of_sections > 4 and
    pe.number_of_signatures == 0 and
    pe.number_of_resources > 1 and pe.number_of_resources < 15 and for any i in (0..pe.number_of_resources - 1):
    ( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and pe.resources[i].id == 101 and
      pe.resources[i].length > 20000 and
      pe.resources[i].language == 0 and
      not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
    )
}
```

**Rule Breakdown:**

📌 **Rule Imports:**
- **import "pe"**: By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files. This makes the rule more precise when it comes to detecting characteristics in Windows executables.
- **import "math"**: Imports the math module, providing mathematical functions like entropy calculations.

📌 **Rule Meta:**
- **copyright = "Kaspersky Lab"**: The rule was authored or copyrighted by Kaspersky Lab.
- **description**: The rule aims to detect samples that enumerate files with encrypted resource called "101".
- **reference**: Provides a URL for additional context about the rule: https://securelist.com/from-shamoon-to-stonedrill/77725/
- **hash**: Two hashes given as examples of known malicious files matching this rule
- **version = "1.4"**: The version number of the YARA rule

📌 **Strings Section:**
- **$mz**: The ASCII string "This program cannot be run in DOS mode." - typically appears in the DOS stub part of a PE file
- **$a1 = "FindFirstFile"**, **$a2 = "FindNextFile"**: Windows API functions used to enumerate files
- **$a3 = "FindResource"**, **$a4 = "LoadResource"**: Windows API functions related to handling resources - Stonedrill samples feature encrypted resources

📌 **Rule Condition:**
- **uint16(0) == 0x5A4D**: Checks if the first two bytes are "MZ" (Windows PE file)
- **all of them**: All strings $a1, $a2, $a3, $a4 must be present
- **filesize < 700000**: File must be less than 700KB
- **pe.number_of_sections > 4**: Must have more than 4 sections
- **pe.number_of_signatures == 0**: Must NOT be digitally signed
- **pe.number_of_resources > 1 and pe.number_of_resources < 15**: Must have 2-14 resources
- **for any i**: Loop through each resource checking:
  - math.entropy() > 7.8 (encrypted)
  - pe.resources[i].id == 101 (resource ID)
  - pe.resources[i].length > 20000 (large resource)
  - pe.resources[i].language == 0 (English)
  - not ($mz in ...) (DOS stub not in resource)

---

### YARA Rule Development Resources

| Resource | Description |
|----------|-------------|
| [YARA Documentation](https://yara.readthedocs.io/) | Official YARA documentation |
| [Kaspersky Blog](https://securelist.com/) | YARA rule development guides |
| [How to Write Simple but Sound Yara Rules - Part 1](https://medium.com/@cyb3rops/how-to-write-simple-but-sound-yara-rules-part-1-121d29322282) | Florian Roth's guide |
| [How to Write Simple but Sound Yara Rules - Part 2](https://medium.com/@cyb3rops/how-to-write-simple-but-sound-yara-rules-part-2-6c5c3771c5c1) | Part 2 |
| [How to Write Simple but Sound Yara Rules - Part 3](https://medium.com/@cyb3rops/how-to-write-simple-but-sound-yara-rules-part-3-1c0d0017eb30) | Part 3 |

> 📌 **yarGen Post-Processing Note:** yarGen's main purpose is to develop the best possible rules for manual post-processing. The combination of clever automatic preselection and a critical human analyst beats both fully manual and fully automatic generation processes. Always review and refine generated rules before deployment!

---

## 4. Hunting Evil with YARA (Windows Edition) {#4-hunting-evil-with-yara-windows-edition}

> 📌 This section covers using YARA on Windows systems for identifying threats on disk, in memory, and ETW data.

### Hunting for Malicious Executables on Disk with YARA

YARA is a potent weapon for detecting and hunting malicious executables on disk. With custom YARA rules, we can pinpoint suspicious files based on distinct patterns, traits, or behaviors.

We will use the sample `dharma_sample.exe` residing in the `C:\Samples\YARASigma` directory.

#### Examining Malware in Hex Editor

First, examine the malware sample inside a hex editor (HxD) to identify the string `C:\crysis\Release\PDB\payload.pdb`.

![HxD Hex Editor - Find Dialog](https://github.com/user-attachments/assets/d102119d-946e-429b-8b34-e69b02803d73)

*Hex editor showing 'dharma_sample.exe' with hex values and decoded text. A find dialog searches for 'C:\crysis\Release\PDB\payload.pdb'.*

![HxD Hex Editor - PDB Path Found](https://github.com/user-attachments/assets/491743fe-3d83-4a17-9bd5-81991fe5ad3e)

*Hex editor displaying 'dharma_sample.exe' with hex values and decoded text. Highlighted path: 'C:\crysis\Release\PDB\payload.pdb'. Data inspector shows binary and character values.*

If we scroll almost to the bottom, we will notice another seemingly unique string `sssssbsss`.

![HxD Hex Editor - Repeated s Characters](https://github.com/user-attachments/assets/2c414959-ca23-44c5-a6d4-2fcb844f92b0)

*Hex editor displaying 'dharma_sample.exe' with hex values and decoded text. Highlighted section shows repeated 's' characters. Data inspector shows binary and character values.*

#### Linux Alternative - hexdump

On a Linux machine, the hexdump utility could have been used to identify the aforementioned hex bytes as follows.

```bash
remnux@remnux:~$ hexdump dharma_sample.exe -C | grep crysis -n3
```

**Output:**
```
3140-0000c7e0  52 00 43 6c 6f 73 65 48  61 6e 64 6c 65 00 4b 45  |R.CloseHandle.KE|
3141-0000c7f0  52 4e 45 4c 33 32 2e 64  6c 6c 00 00 52 53 44 53  |RNEL32.dll..RSDS|
3142-0000c800  25 7e 6d 90 fc 96 43 42  8e c3 87 23 6b 61 a4 92  |%~m...CB...#ka..|
3143:0000c810  03 00 00 00 43 3a 5c 63  72 79 73 69 73 5c 52 65  |....C:\crysis\Re|
3144-0000c820  6c 65 61 73 65 5c 50 44  42 5c 70 61 79 6c 6f 61  |lease\PDB\payloa|
3145-0000c830  64 2e 70 64 62 00 00 00  00 00 00 00 00 00 00 00  |d.pdb...........|
3146-0000c840  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

```bash
remnux@remnux:~$ hexdump dharma_sample.exe -C | grep sssssbsss -n3
```

**Output:**
```
5738-00016be0  3d 00 00 00 26 00 00 00  73 73 73 64 00 00 00 00  |=...&...sssd....|
5739-00016bf0  26 61 6c 6c 3d 00 00 00  73 64 00 00 2d 00 61 00  |&all=...sd..-.a.|
5740-00016c00  00 00 00 00 73 00 73 00  62 00 73 00 73 00 00 00  |....s.s.b.s.s...|
5741:00016c10  73 73 73 73 73 62 73 73  73 00 00 00 73 73 73 73  |sssssbsss...ssss|
5742-00016c20  73 62 73 00 22 00 00 00  22 00 00 00 5c 00 00 00  |sbs."..."...\...|
5743-00016c30  5c 00 00 00 5c 00 00 00  5c 00 00 00 5c 00 00 00  |\...\...\...\...|
5744-00016c40  22 00 00 00 20 00 22 00  00 00 00 00 5c 00 00 00  |"... .".....\...|
```

Let's incorporate all identified hex bytes into a rule:

```yara
rule ransomware_dharma {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"

    strings:
        $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }

        condition: all of them
}
```

> 📌 **Key Points:**
> - $string_pdb uses hex notation { 43...62 } to match the UTF-8 encoded path string
> - $string_ssss uses hex bytes to match the ASCII repeated "s" pattern
> - condition: all of them requires both strings to be found for a match

#### Scanning Filesystem with YARA

Initiating the YARA executable with this rule:

```powershell
yara64.exe -s C:\Rules\yara\dharma_ransomware.yar C:\Samples\YARASigma\ -r 2>null
```

**Output:**
```
ransomware_dharma C:\Samples\YARASigma\\dharma_sample.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\check_updates.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\microsoft.com
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\KB5027505.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\pdf_reader.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
```

**Command Breakdown:**

- yara64.exe: The YARA64 executable for 64-bit systems
- -s C:\Rules\yara\dharma_ransomware.yar: Specifies the YARA rules file
- C:\Samples\YARASigma: Directory to scan
- -r: Recursive scanning (subdirectories included)
- 2>nul: Suppresses error messages

> 📌 **Detection Results:** pdf_reader.exe, microsoft.com, check_updates.exe, and KB5027505.exe are detected in addition to dharma_sample.exe.

---

### Hunting for Evil Within Running Processes with YARA

To detect malware in running processes, we'll use YARA scanner on active processes.

#### Meterpreter Shellcode Detection Rule

```yara
rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        5 of them
}
```

> 📌 **Key Points:**
> - $s1 uses wildcards (?) to match variable bytes
> - $s2 uses ?? for any byte at that position
> - Rule requires 5 of 7 strings to match

#### Running the Malware Sample

We use `htb_sample_shell.exe` which injects Metasploit's meterpreter shellcode into cmdkey.exe:

```powershell
.\htb_sample_shell.exe
```

**Output:**
```
<-- Hack the box sample for yara signatures -->

[+] Parent process with PID 7972 is created : C:\Samples\YARASigma\htb_sample_shell.exe
[+] Child process with PID 9084 is created : C:\Windows\System32\cmdkey.exe
[+] Shellcode is written at address 000002686B1C0000 in remote process C:\Windows\System32\cmdkey.exe
[+] Remote thread to execute the shellcode is started with thread ID 368

Press enter key to terminate...
```

> 📌 **Process Injection:** Parent: htb_sample_shell.exe (PID 7972), Victim: cmdkey.exe (PID 9084), Shellcode address: 000002686B1C0000

#### Scanning Running Processes

```powershell
Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\meterpreter_shellcode.yar" $_.id }
```

**Key Output:**
```
Scanning with Yara for meterpreter shellcode on PID 9084
meterpreter_reverse_tcp_shellcode 9084
...
Scanning with Yara for meterpreter shellcode on PID 7972
meterpreter_reverse_tcp_shellcode 7972
```

#### Scanning Specific PID

```powershell
yara64.exe C:\Rules\yara\meterpreter_shellcode.yar 9084 --print-strings
```

**Output:**
```
meterpreter_reverse_tcp_shellcode 9084
0x2686b1c0104:$s3: 4C 77 26 07
0xe3fea7fef8:$s4: ws2_
0x2686b1c00d9:$s4: ws2_
0x7ffbfdad4490:$s4: ws2_
...
0x2686b1c0115:$s5: 29 80 6B 00
0x2686b1c0135:$s6: EA 0F DF E0
0x2686b1c014a:$s7: 99 A5 74 61
```

![YARA Process Scanner](https://github.com/user-attachments/assets/c2c9989d-9766-4e98-bd6e-5a0665fe221e)

*PowerShell and Process Hacker showing shellcode analysis. Parent process cmdkey.exe PID 9084. YARA detects meterpreter reverse TCP shellcode.*

> 📌 **Detection:** Shellcode found in PID 9084 (cmdkey.exe) and PID 7972 (htb_sample_shell.exe)

---

### Hunting for Evil Within ETW Data with YARA

Event Tracing For Windows (ETW) is a high-speed tracing facility using buffering and logging in the kernel.

![ETW Process Flow](https://github.com/user-attachments/assets/7f957d8a-7342-4b25-b838-50aa936dd1fd)

*ETW process: Controller enables/disables ETW collection, Event Trace Session with Buffer Pool logs events, Provider generates events, Consumer logs/analyzes events.*

#### ETW Components:

| Component | Description |
|-----------|-------------|
| **Controllers** | Initiate/terminate trace sessions, enable/disable providers |
| **Providers** | Generate events and channel to ETW sessions |
| **Consumers** | Subscribe to events for processing |

#### Useful ETW Providers:

| Provider | Use Case |
|----------|----------|
| **Microsoft-Windows-Kernel-Process** | Process injection, hollowing detection |
| **Microsoft-Windows-Kernel-File** | Unauthorized file access, ransomware |
| **Microsoft-Windows-Kernel-Network** | C2 communication, data exfiltration |
| **Microsoft-Windows-SMBClient/SMBServer** | Lateral movement detection |
| **Microsoft-Windows-DotNETRuntime** | Malicious .NET assembly loading |
| **OpenSSH** | Brute force attack detection |
| **Microsoft-Windows-PowerShell** | Suspicious PowerShell activity |
| **Microsoft-Windows-Kernel-Registry** | Persistence mechanism detection |
| **Microsoft-Windows-DNS-Client** | DNS tunneling, C2 detection |
| **Microsoft-Antimalware-Protection** | Evasion technique detection |

#### SilkETW with YARA

SilkETW is an open-source tool for ETW data with YARA integration.

```powershell
.\SilkETW.exe -h
```

**Help Output:**
```
██████╗██╗██╗   ██╗  ██╗███████╗████████╗██╗    ██╗
██╔════╝██║██║   ██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║
██████╗██║██║   █████╔╝ █████╗     ██║   ██║ █╗ ██║
╚════██║██║██║   ██╔═██╗ ██╔══╝     ██║   ██║███╗██║
██████║██║█████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝
╚══════╝╚═╝╚════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝
                  [v0.8 - Ruben Boonen => @FuzzySec]

 >--~~--> Args? <--~~--<

-h  (--help)          This help menu
-t  (--type)         Kernel or User collector
-kk (--kernelkeyword) Valid keywords: Process, Thread, ImageLoad, VirtualAlloc, NetworkTCPIP, etc.
-uk (--userkeyword)  User keyword mask, eg 0x2038
-pn (--providername) Provider name or GUID
-l  (--level)        Logging level: Always, Critical, Error, Warning, Informational, Verbose
-ot (--outputtype)   Output: POST to "URL", "file", or "eventlog"
-p  (--path)         Output file path or URL
-f  (--filter)       Filter types: None, EventName, ProcessID, ProcessName, Opcode
-fv (--filtervalue)  Filter value
-y  (--yara)         Path to folder containing Yara rules
-yo (--yaraoptions)  Record "All" events or only "Matches"
```

**Usage Examples:**
```powershell
# VirtualAlloc Kernel collector to Elasticsearch
SilkETW.exe -t kernel -kk VirtualAlloc -ot url -p https://some.elk:9200/valloc/_doc/

# DNS User collector with YARA matching
SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -l Always -ot file -p C:\Some\Path\out.json -y C:\Some\Yara\Folder -yo matches
```

---

### Example 1: YARA on PowerShell ETW

```powershell
.\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps_logs.json -l verbose -y C:\Rules\yara -yo Matches
```

**Command Breakdown:**
- -t user: User-mode event tracing
- -pn Microsoft-Windows-PowerShell: Target PowerShell events
- -ot file: Save to file
- -p ./etw_ps_logs.json: Output JSON file
- -l verbose: Detailed logging
- -y C:\Rules\yara: Enable YARA scanning
- -yo Matches: Display only matches

**YARA Rule (etw_powershell_hello.yar):**
```yara
rule powershell_hello_world_yara {
    strings:
        $s0 = "Write-Host" ascii wide nocase
        $s1 = "Hello" ascii wide nocase
        $s2 = "from" ascii wide nocase
        $s3 = "PowerShell" ascii wide nocase
    condition:
        3 of ($s*)
}
```

**Trigger Detection:**
```powershell
Invoke-Command -ScriptBlock {Write-Host "Hello from PowerShell"}
```

**Result:**
```
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 28
     -> Yara match: powershell_hello_world_yara
     -> Yara match: powershell_hello_world_yara
```

---

### Example 2: YARA on DNS ETW

```powershell
.\SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -ot file -p ./etw_dns_logs.json -l verbose -y C:\Rules\yara -yo Matches
```

**YARA Rule (etw_dns_wannacry.yar):**
```yara
rule dns_wannacry_domain {
    strings:
        $s1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
    condition:
        $s1
}
```

**Trigger Detection:**
```powershell
ping iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
```

**Result:**
```
Reply from 104.17.244.81: bytes=32 time=14ms TTL=56
...
[?] Events captured: 60
     -> Yara match: dns_wannacry_domain
     -> Yara match: dns_wannacry_domain
```

> 📌 **Key Points:**
> - Detects hardcoded WannaCry kill switch domain in DNS queries
> - Real-time C2 domain detection capability
> - -yo Matches reduces noise by showing only detections

---

## 5. Hunting Evil with YARA (Linux Edition) {#5-hunting-evil-with-yara-linux-edition}

> 📌 This section covers using YARA for memory forensics on Linux systems when direct system access is not available.

### Memory Image Scanning with YARA

In real-world scenarios, Security Analysts often don't have direct access to potentially compromised systems. However, we can receive memory captures (memory dumps) from suspicious systems - like receiving a snapshot of everything happening at a particular moment.

YARA extends the capabilities of memory forensics, allowing us to traverse memory content and hunt for telltale signs or compromise indicators.

#### YARA Memory Scanning Process:

1. **Create YARA Rules**: Develop bespoke rules or use existing ones targeting memory-based malware traits
2. **Compile YARA Rules**: Use yarac tool to compile rules into binary format (.yrc extension) - optional but best practice
3. **Obtain Memory Image**: Capture using tools like DumpIt, MemDump, Belkasoft RAM Capturer, Magnet RAM Capture, FTK Imager, LiME
4. **Scan with YARA**: Use yara tool to scan memory images for matches

> 📌 **Why Compile Rules?**
> - Optimizes performance with large number of rules
> - Provides some level of protection (binary format harder to reverse)

### Example: WannaCry Memory Scan

We have a memory snapshot `compromised_system.raw` from a system infected with WannaCry ransomware. Let's scan it with the `wannacry_artifacts_memory.yar` YARA rule.

**Command:**
```bash
yara /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar /home/htb-student/MemoryDumps/compromised_system.raw --print-strings
```

**Output:**
```
Ransomware_WannaCry /home/htb-student/MemoryDumps/compromised_system.raw
0x4e140:$wannacry_payload_str1: tasksche.exe
0x1cb9b24:$wannacry_payload_str1: tasksche.exe
0xdb564d8:$wannacry_payload_str1: tasksche.exe
0x13bac36c:$wannacry_payload_str1: tasksche.exe
0x16a2ae44:$wannacry_payload_str1: tasksche.exe
0x16ce55d8:$wannacry_payload_str1: tasksche.exe
0x17bf1fe6:$wannacry_payload_str1: tasksche.exe
0x17cb8002:$wannacry_payload_str1: tasksche.exe
0x17cb80d0:$wannacry_payload_str1: tasksche.exe
0x17cb80f8:$wannacry_payload_str1: tasksche.exe
0x18a68f50:$wannacry_payload_str1: tasksche.exe
0x18a9b4b8:$wannacry_payload_str1: tasksche.exe
0x18dc15a8:$wannacry_payload_str1: tasksche.exe
0x18df37d0:$wannacry_payload_str1: tasksche.exe
0x19a4b522:$wannacry_payload_str1: tasksche.exe
0x1aac0600:$wannacry_payload_str1: tasksche.exe
0x1c07ed9a:$wannacry_payload_str1: tasksche.exe
0x1c59cd32:$wannacry_payload_str1: tasksche.exe
0x1d1593f0:$wannacry_payload_str1: tasksche.exe
0x1d1c6fe2:$wannacry_payload_str1: tasksche.exe
0x1d92632a:$wannacry_payload_str1: tasksche.exe
0x1dd65c34:$wannacry_payload_str1: tasksche.exe
0x1e607a1e:$wannacry_payload_str1: tasksche.exe
0x1e607dca:$wannacry_payload_str1: tasksche.exe
0x13bac3d7:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x197ba5e0:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x1a07cedf:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x1a2cb300:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x1b644cd8:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x1d15945b:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x1dd65c9f:$wannacry_payload_str2: www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
0x450b048:$wannacry_payload_str3: mssecsvc.exe
0x5a7f3d4:$wannacry_payload_str3: mssecsvc.exe
0xda1c350:$wannacry_payload_str3: mssecsvc.exe
0x12481048:$wannacry_payload_str3: mssecsvc.exe
0x17027910:$wannacry_payload_str3: mssecsvc.exe
0x17f0dc18:$wannacry_payload_str3: mssecsvc.exe
0x18c360cc:$wannacry_payload_str3: mssecsvc.exe
0x1a2a02f0:$wannacry_payload_str3: mssecsvc.exe
0x13945408:$wannacry_payload_str4: diskpart.exe
0x19a28480:$wannacry_payload_str4: diskpart.exe
```

> 📌 **Key Findings:**
> - **tasksche.exe**: WannaCry executable name (found at multiple memory addresses)
> - **www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com**: Kill switch domain
> - **mssecsvc.exe**: WannaCry service executable
> - **diskpart.exe**: Used for disk encryption

---

### YARA with Volatility Framework

Beyond standalone tools, integrating YARA with memory forensics frameworks like **Volatility** amplifies detection capabilities.

Volatility is a powerful open-source memory forensics tool used to analyze memory images from various operating systems. YARA can be integrated as a plugin called **yarascan** for applying YARA rules to memory analysis.

#### Single Pattern YARA Scanning

Specify a YARA rule pattern directly in the command-line using the -U option. This is useful for specific patterns without creating a separate rules file.

**WannaCry IOC**: `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`

**Command:**
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```

**Output:**
```
Volatility Foundation Volatility Framework 2.6.1
Rule: r1
Owner: Process svchost.exe Pid 1576
0x004313d7  77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69   www.iuqerfsodp9i
0x004313e7  66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69   fjaposdfjhgosuri
0x004313f7  6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f   jfaewrwergwea.co
0x00431407  6d 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00   m...............
Rule: r1
Owner: Process svchost.exe Pid 1576
0x0013dcd8  77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69   www.iuqerfsodp9i
...
```

> 📌 **Key Finding:** Domain found in process svchost.exe (PID 1576) - confirms infection

#### Multiple YARA Rule Scanning

When we have multiple YARA rules, use the -y option followed by the rule file path.

**YARA Rule File (wannacry_artifacts_memory.yar):**
```yara
rule Ransomware_WannaCry {

    meta:
        author = "Madhukar Raina"
        version = "1.1"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior"

    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
        $wannacry_payload_str4 = "diskpart.exe" fullword ascii
        $wannacry_payload_str5 = "lhdfrgui.exe" fullword ascii

    condition:
        3 of them
}
```

**Command:**
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```

**Output (key sections):**
```
Rule: Ransomware_WannaCry
Owner: Process svchost.exe Pid 1576
0x0043136c  74 61 73 6b 73 63 68 65 2e 65 78 65 00 00 00 00   tasksche.exe....
0x004313cc  00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 69   ....http://www.i
0x004313dc  75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f   uqerfsodp9ifjapo
0x004313ec  73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77   sdfjhgosurijfaew
0x004313fc  72 77 65 72 67 77 65 61 2e 63 6f 6d 00 00 00 00   rwergwea.com....
Rule: Ransomware_WannaCry
Owner: Process svchost.exe Pid 1576
0x004313d7  77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69   www.iuqerfsodp9i
...
Rule: Ransomware_WannaCry
Owner: Process svchost.exe Pid 1576
0x0040e048  6d 73 73 65 63 73 76 63 2e 65 78 65 00 00 00 00   mssecsvc.exe....
...
```

> 📌 **Summary:**
> - The yarascan plugin found WannaCry IOCs in process svchost.exe (PID 1576)
> - Multiple strings matched across memory addresses
> - **-U option**: Direct pattern search in command line
> - **-y option**: Specify path to YARA rules file

---

## 6. Hunting Evil with YARA (Web Edition) {#6-hunting-evil-with-yara-web-edition}

> 📌 This section covers using YARA to hunt malware in online datasets via Unpac.me platform.

### Unpac.Me - Online YARA Hunting

Unpac.Me is a tool tailored for malware unpacking. It grants the capability to run YARA rules over their amassed database of malware submissions. For SOC analysts with limited access to commercial malware datasets, Unpac.Me is a prime asset.

#### Example YARA Rule - Dharma Ransomware

Let's test this YARA rule:

```yara
rule ransomware_dharma {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior" 
    
    strings:
        $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }

    condition: all of them
}
```

#### How to Get Started:

1. **Register** for zero-cost access and log into the platform
2. **Navigate** to Yara Hunt and choose "New Hunt"

![UnpacMe Yara Hunt Menu](https://github.com/user-attachments/assets/ad499825-1dd4-4542-8894-badf47689841)

*UnpacMe interface showing 'Yara Hunt' menu with options for 'New Hunt' and 'History'.*

3. **Enter** the YARA rule into the designated rule space

![UnpacMe Yara Hunt Interface](https://github.com/user-attachments/assets/a1a14d55-0301-4a51-838f-89bbb44be3c9)

*UnpacMe Yara Hunt interface displaying a YARA rule for detecting Dharma ransomware.*

4. **Validate** and then **Scan**

![Scan Options](https://github.com/user-attachments/assets/ebb13b22-850b-49f2-aa3b-01068a04420e)

*Interface showing options for Scan Assist, Fast Scan, Store Offsets, File Size Limits, Validate, Scan, and Total Recall.*

5. **View Results** - Scan results are displayed in real-time

![Hunt Results](https://github.com/user-attachments/assets/114eba5f-79f0-4714-b144-5fa18cbbfc48)

*Hunt Results showing ransomware_dharma rule with 1 unpacked malware match. Status: complete.*

![Validation Results](https://github.com/user-attachments/assets/734843d5-5003-4290-b8ce-f211bfd1423b)

*Rule validation passed. Scan coverage: 100%. Observed lifespan: 3 years. First seen: 21/02/2020. Last seen: 13/06/2023. File type: EXE, size: 95 KB.*

> 📌 **Key Results:**
> - **1 match** found in the malware database
> - **Validation**: Passed
> - **Scan Coverage**: 100%
> - **Lifespan**: 3 years (2020-2023)
> - **File Type**: EXE, 95 KB

> 📌 **Why Use Unpac.Me?**
> - Access to large malware dataset without commercial licensing
> - Validate YARA rules against real-world samples
> - Identify malware variants and families
> - Enhances detection capabilities for SOC analysts

---

## 7. Sigma and Sigma Rules {#7-sigma-and-sigma-rules}

> 📌 **Sigma** is a generic signature format for describing detection rules for log analysis and SIEM systems. It allows SOC analysts to create portable rules that work across multiple platforms.

### Overview

Sigma is a standardized format for analysts to create and share detection rules. It helps convert IOCs into queries that can be easily integrated with SIEMs and EDRs.

Sigma rules are written in YAML format and can be used to detect suspicious activities in various log sources. This also helps in building efficient processes for **Detection as Code**.

![Sigma Rule Conversion](https://github.com/user-attachments/assets/ce4f8cd3-ce01-4505-8545-df1b5c6a5fc1)

*Diagram showing Sigma Rule conversion using Uncoder.io or Sigma Converter to integrate with SIEM and EDR tools like ArcSight and Splunk.*

---

### Usages of Sigma

| Usage | Description |
|-------|-------------|
| **Universal Log Analytics Tool** | Write detection rules once, convert to various SIEM formats |
| **Community-driven Rule Sharing** | Tap into community that regularly contributes detection rules |
| **Incident Response** | Quickly search and analyze logs for specific patterns |
| **Proactive Threat Hunting** | Use specific patterns to pinpoint anomalies |
| **Seamless Integration** | Convert rules for SOAR platforms and automation tools |
| **Customization** | Tailor rules to unique environment characteristics |
| **Gap Identification** | Perform gap analysis against broader community rules |

---

### How Does Sigma Work?

At its heart, Sigma is about expressing patterns found in log events in a structured manner. Instead of scattered proprietary formats, Sigma provides a unified open standard - the **lingua franca** for log-based threat detection.

#### Key Components:

1. **Sigma Rules (YAML)**: Describe patterns of log events that correlate with malicious activity
2. **sigmac**: Converter that transforms Sigma rules into SIEM queries (ElasticSearch, QRadar, Splunk, etc.)
3. **pySigma**: Newer translation tool (replacing sigmac)

> 📌 **Note:** pySigma is increasingly becoming the go-to option for rule translation, as sigmac is now considered obsolete.

---

### Sigma Rule Structure

Sigma rule files are written in YAML format with the following structure:

![Sigma Rule Structure](https://github.com/user-attachments/assets/36bf57a1-35ed-4b6f-bdf3-1ee993fe9a94)

*Structure showing fields: title, status, description, author, reference, logsource, detection, and condition. Required fields are highlighted.*

---

### Sigma Rule Example

```yaml
title: Potential LethalHTA Technique Execution 
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471 
status: test 
description: Detects potential LethalHTA technique where "mshta.exe" is spawned by an "svchost.exe" process
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
author: Markus Neis 
date: 2018/06/07 
tags: 
    - attack.defense_evasion 
    - attack.t1218.005 
logsource: 
    category: process_creation  
    product: windows
detection:
    selection: 
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mshta.exe'
    condition: selection
falsepositives: 
    - Unknown
level: high
```

![Sigma Rule Components](https://github.com/user-attachments/assets/48fa9215-8c50-4b01-b054-2615cbf7b200)

*Image showing Sigma Rule components: title, ID, status, description, references, author, date, tags, logsource, detection, falsepositives, level*

---

### Sigma Rule Breakdown

📌 **title**: Brief title (max 256 characters) describing what the rule detects

📌 **id**: Globally unique identifier (UUID v4 recommended)

📌 **status**: Rule status
- `stable`: Tested over long period, no false positives
- `test`: Tested on limited systems, no obvious false positives
- `experimental`: Not tested outside lab environments
- `deprecated`: To be replaced by another rule
- `unsupported`: Cannot be used in current state

📌 **description**: Short description of the detection (max 65,535 characters)

📌 **references**: Citations to original sources (blog posts, articles, tweets)

📌 **author**: Creator of the rule

📌 **date**: Creation date in YYYY/MM/DD format

📌 **logsource**: Describes the log data
- **category**: Product group (firewall, web, antivirus)
- **product**: Specific product (windows, apache)
- **service**: Subset of product logs (sshd, security)

📌 **detection**: Search identifiers + condition
- Search identifiers represent properties to search in log data
- Condition defines how fields relate to each other

![Detection Structure](https://github.com/user-attachments/assets/1900f2b3-fc0d-457c-9790-ab912aeaaa10)

*Detection attributes showing search-identifiers for cmd.exe and powershell.exe with parent images*

---

### Value Modifiers

| Modifier | Explanation | Example |
|----------|-------------|---------|
| **contains** | Adds wildcard (*) around value | CommandLine\|contains |
| **all** | Links list elements with AND | CommandLine\|contains\|all |
| **startswith** | Adds wildcard at end | ParentImage\|startswith |
| **endswith** | Adds wildcard at beginning | Image\|endswith |
| **re** | Regular expression | CommandLine\|re: '\String' |

---

### Search Identifiers

#### Lists
- Contains strings applied to full log message (OR logic)
- Contains maps (OR logic)

![Lists and Maps](https://github.com/user-attachments/assets/3ec9c36c-7e28-4712-a4b1-fd7732ca6329)

*Detection examples with lists and maps*

**Example - List of strings:**
```yaml
detection:
    keywords:
        - evilservice
        - svchost.exe -n evil
```

**Example - List of maps:**
```yaml
detection:
    selection:
        - Image|endswith: '\example.exe'
        - Description|contains: 'Test executable'
```

#### Maps
- Key/value pairs where key is log field and value is string/integer
- All elements joined with AND

**Example - Event Log Security with multiple Event IDs:**
```yaml
detection:
    selection:
        EventLog: Security
        EventID:
          - 517
          - 1102
    condition: selection
```

---

### Condition Operators

| Operator | Example |
|----------|---------|
| **Logical AND/OR** | keywords1 or keywords2 |
| **1/all of them** | all of them |
| **1/all of search-identifier-pattern** | all of selection* |
| **Negation with 'not'** | keywords and not filters |
| **Brackets** | selection1 and (keywords1 or keywords2) |

**Example:**
```yaml
condition: selection1 or selection2 or selection3
```

---

### Sigma Rule Development Best Practices

📌 **Resources:**
- [SigmaHQ Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [Sigma Rule Creation Guide](https://github.com/SigmaHQ/sigma/tree/master/rules)

> 📌 **Key Takeaway:** Sigma enables portable detection rules that work across multiple SIEM platforms. Write once, use everywhere!

---

## 8. Developing Sigma Rules {#8-developing-sigma-rules}

> 📌 This section covers manual Sigma rule development with real-world examples.

### Manually Developing a Sigma Rule

In this section, we'll cover manual Sigma rule development.

#### Example 1: LSASS Credential Dumping

Let's use a sample named `shell.exe` (a renamed version of mimikatz) to understand the process of crafting a Sigma rule.

**Running the malware:**
```bash
C:\Samples\YARASigma>shell.exe
```

**Output (mimikatz execution):**
```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
---SNIP---
Authentication Id : 0 ; 100080 (00000000:000186f0)
Session           : Interactive from 1
User Name         : htb-student
Domain            : DESKTOP-VJF8GH8
Logon Server      : DESKTOP-VJF8GH8
Logon Time        : 8/25/2023 2:17:20 PM
SID               : S-1-5-21-1412399592-1502967738-1150298762-1001
        msv :
         [00000003] Primary
         * Username : htb-student
         * Domain   : .
         * NTLM     : 3c0e5d303ec84884ad5c3b7876a06ea6
         * SHA1     : b2978f9abc2f356e45cb66ec39510b1ccca08a0e
        wdigest :
         * Username : htb-student
         * Domain   : DESKTOP-VJF8GH8
         * Password : HTB_@cademy_stdnt!
---SNIP---
```

> 📌 The process created by shell.exe (mimikatz) tries to access the process memory of lsass.exe. Sysmon captured this activity in Event ID 10.

#### Understanding the Key Fields

Sysmon Event ID 10 triggers when a process accesses another process. The event log contains two important fields:
- **TargetImage**: The process being accessed
- **GrantedAccess**: Permission flags

![Sysmon Event ID 10](https://github.com/user-attachments/assets/f2d1171f-2916-4c53-aeee-21bdd33fb76b)

*Sysmon event showing shell.exe accessing lsass.exe with granted access 0x1010.*

#### Why 0x1010 Matters

The hex flag `0x1010` combines:
- `PROCESS_VM_READ` (0x0010): Read access to virtual memory
- `PROCESS_QUERY_INFORMATION` (0x0400): Query information from process

> 📌 While 0x0410 is the most common for LSASS memory dumping, 0x1010 is also frequently observed during credential dumping attacks.

#### Sigma Rule (Basic Version)

```yaml
title: LSASS Access with rare GrantedAccess flag 
status: experimental
description: This rule will detect when a process tries to access LSASS memory with suspicious access flag 0x1010
date: 2023/07/08
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith: '0x1010'
    condition: selection
```

> 📌 This rule is saved as `proc_access_win_lsass_access.yml` in the target system.

---

### Sigma Rule Breakdown

📌 **title**: Concise overview of the rule's objective - detecting LSASS memory access with a particular access flag

📌 **status**: `experimental` - rule is in testing phase, may need fine-tuning

📌 **description**: Explains what the rule detects

📌 **date**: 2023/07/08 - rule creation/update date

📌 **tags**: 
- `attack.credential_access` - MITRE ATT&CK tactic
- `attack.t1003.001` - LSASS credential dumping technique

📌 **logsource**:
- `category: process_access` - targets Sysmon Event ID 10
- `product: windows` - Windows-specific rule

📌 **detection**:
- `selection`: TargetImage ends with `\lsass.exe` AND GrantedAccess ends with `0x1010`
- `condition`: selection must match

---

### Converting Sigma to SIEM Queries (sigmac)

The **sigmac** tool transforms Sigma rules into SIEM queries.

**Location:** `C:\Tools\sigma-0.21\tools`

#### Converting to PowerShell (Get-WinEvent)

```bash
python sigmac -t powershell 'C:\Rules\sigma\proc_access_win_lsass_access.yml'
```

**Output:**
```powershell
Get-WinEvent | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\lsass.exe" -and $_.message -match "GrantedAccess.*.*0x1010") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

#### Testing Against Event Log

```powershell
Get-WinEvent -Path C:\Events\YARASigma\lab_events.evtx | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\lsass.exe" -and $_.message -match "GrantedAccess.*.*0x1010") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

**Result:**
```
TimeCreated : 7/9/2023 7:44:14 AM
Id          : 10
RecordId    : 7810
ProcessId   : 3324
MachineName : RDSEMVM01
Message     : Process accessed:
              RuleName:
              UtcTime: 2023-07-09 14:44:14.260
              SourceProcessGUID: {e7bf76b7-c7ba-64aa-0000-0010e8e9a602}
              SourceProcessId: 1884
              SourceThreadId: 7872
              SourceImage: C:\htb\samples\shell.exe
              TargetProcessGUID: {e7bf76b7-d7ec-6496-0000-001027d60000}
              TargetProcessId: 668
              TargetImage: C:\Windows\system32\lsass.exe
              GrantedAccess: 0x1010
              ...
```

> 📌 **Success!** The Sysmon Event ID 10 is successfully identified!

---

### Avoiding False Positives

> 🔴 **Remember:** False positives are the enemy of effective security monitoring!

#### Best Practices:
1. **Cross-reference SourceImage** against known safe processes that interact with LSASS
2. **Flag suspicious paths**: `\Temp\`, `\Users\Public\`, `\PerfLogs\`, `\AppData\`, `\htb\`
3. **Monitor GrantedAccess suffixes**: 10, 30, 50, 70, 90, B0, D0, F0, 18, 38, 58, 78, 98, B8, D8, F8, 1A, 3A, 5A, 7A, 9A, BA, DA, FA, 0x14C2, FF

#### Robust Sigma Rule

```yaml
title: LSASS Access From Program in Potentially Suspicious Folder
id: fa34b441-961a-42fa-a100-ecc28c886725
status: experimental
description: Detects process access to LSASS memory with suspicious access flags and from a potentially suspicious folder
references:
    - https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    - https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
author: Florian Roth (Nextron Systems)
date: 2021/11/27
modified: 2023/05/05
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith:
            - '10'
            - '30'
            - '50'
            - '70'
            - '90'
            - 'B0'
            - 'D0'
            - 'F0'
            - '18'
            - '38'
            - '58'
            - '78'
            - '98'
            - 'B8'
            - 'D8'
            - 'F8'
            - '1A'
            - '3A'
            - '5A'
            - '7A'
            - '9A'
            - 'BA'
            - 'DA'
            - 'FA'
            - '0x14C2'
            - 'FF'
        SourceImage|contains:
            - '\Temp\'
            - '\Users\Public\'
            - '\PerfLogs\'
            - '\AppData\'
            - '\htb\'
    filter_optional_generic_appdata:
        SourceImage|startswith: 'C:\Users\'
        SourceImage|contains: '\AppData\Local\'
        SourceImage|endswith:
            - '\Microsoft VS Code\Code.exe'
            - '\software_reporter_tool.exe'
            - '\DropboxUpdate.exe'
            - '\MBAMInstallerService.exe'
            - '\WebexMTA.exe'
            - '\WebEx\WebexHost.exe'
            - '\JetBrains\Toolbox\bin\jetbrains-toolbox.exe'
        GrantedAccess: '0x410'
    filter_optional_dropbox_1:
        SourceImage|startswith: 'C:\Windows\Temp\'
        SourceImage|endswith: '.tmp\DropboxUpdate.exe'
        GrantedAccess:
            - '0x410'
            - '0x1410'
    filter_optional_nextron:
        SourceImage|startswith:
            - 'C:\Windows\Temp\asgard2-agent\'
            - 'C:\Windows\Temp\asgard2-agent-sc\'
        SourceImage|endswith:
            - '\thor64.exe'
            - '\thor.exe'
            - '\aurora-agent-64.exe'
            - '\aurora-agent.exe'
        GrantedAccess:
            - '0x1fffff'
            - '0x1010'
            - '0x101010'
    condition: selection and not 1 of filter_optional_*
fields:
    - User
    - SourceImage
    - GrantedAccess
falsepositives:
    - Updaters and installers are typical false positives. Apply custom filters depending on your environment
level: medium
```

> 📌 **Key Feature:** The condition `selection and not 1 of filter_optional_*` filters out false positives from known safe processes.

---

### Example 2: Multiple Failed Logins (Event 4776)

According to Microsoft, **Event 4776** generates when credential validation occurs using NTLM authentication.

> 📌 This event shows credential validation attempts (successful and failed) from Source Workstation.

#### Event Details:
- **Event ID**: 4776
- **Error Code**: 0xC0000064 (user does not exist)
- **TargetUserName**: Account being authenticated
- **Workstation**: Source of authentication attempt

![Event 4776 - Failure](https://github.com/user-attachments/assets/2e46af58-a1e0-4d42-a6d1-790258e323af)

*Event 4776 showing credential validation attempt with error code 0xC0000064 for account NOUSER on workstation FS01.*

![Event 4776 - Details](https://github.com/user-attachments/assets/de666af1-6068-4611-9235-072398c52cd3)

*Event 4776 showing detailed view of failed login attempt.*

#### Sigma Rule for Failed Logins

```yaml
title: Failed NTLM Logins with Different Accounts from Single Source System
id: 6309ffc4-8fa2-47cf-96b8-a2f72e58e538
related:
    - id: e98374a6-e2d9-4076-9b5c-11bdb2569995
      type: derived
status: unsupported
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth (Nextron Systems)
date: 2017/01/10
modified: 2023/02/24
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection2:
        EventID: 4776
        TargetUserName: '*'
        Workstation: '*'
    condition: selection2 | count(TargetUserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium
```

#### Rule Breakdown

📌 **logsource**:
- `product: windows` - Windows systems
- `service: security` - Security event logs

📌 **detection**:
- `selection2`: EventID 4776 with any TargetUserName and Workstation
- `condition`: Count TargetUserName by Workstation > 3 (more than 3 failed attempts)

---

### Sigma Rule Development Resources

| Resource | Description |
|----------|-------------|
| [SigmaHQ Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide) | Official rule development guide |
| [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) | Technical specification |
| [Tech-EN Sigma Articles](https://tech-en.netlify.app/articles/en510480/) | Multi-part tutorial series |

---

## 9. Hunting Evil with Sigma (Chainsaw Edition) {#9-hunting-evil-with-sigma-chainsaw-edition}

> 📌 **Chainsaw** - A fast tool to hunt security threats in Windows Event Logs using Sigma rules when no SIEM is available.

### Overview

In cybersecurity, time is of the essence. Rapid analysis allows us to not just identify but also respond to threats before they escalate.

When we're up against the clock, racing to find a needle in a haystack of Windows Event Logs without access to a SIEM, **Sigma rules combined with tools like Chainsaw and Zircolite** are our best allies.

Both tools allow us to use Sigma rules to scan not just one, but multiple EVTX files concurrently, offering a broader and more comprehensive scan in a very efficient manner.

---

### Scanning Windows Event Logs With Chainsaw

**Chainsaw** is a freely available tool designed to swiftly pinpoint security threats within Windows Event Logs. This tool enables efficient keyword-based event log searches and is equipped with integrated support for Sigma detection rules as well as custom Chainsaw rules. Therefore, it serves as a valuable asset for validating our Sigma rules by applying them to actual event logs.

> 📌 Chainsaw can be found inside the `C:\Tools\chainsaw` directory of this section's target.

Let's first run Chainsaw with `-h` flag to see the help menu:

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe -h
Rapidly work with Forensic Artefacts

Usage: chainsaw_x86_64-pc-windows-msvc.exe [OPTIONS] <COMMAND>

Commands:
  dump     Dump an artefact into a different format
  hunt     Hunt through artefacts using detection rules for threat detection
  lint     Lint provided rules to ensure that they load correctly
  search   Search through forensic artefacts for keywords
  analyse  Perform various analyses on artifacts
  help     Print this message or the help of the given subcommand(s)

Options:
      --no-banner                  Hide Chainsaw's banner
      --num-threads <NUM_THREADS>  Limit the thread number (default: num of CPUs)
  -h, --help                       Print help
  -V, --version                    Print version
```

#### Chainsaw Commands

| Command | Description |
|---------|-------------|
| `dump` | Dump an artefact into a different format |
| `hunt` | Hunt through artefacts using detection rules for threat detection |
| `lint` | Lint provided rules to ensure that they load correctly |
| `search` | Search through forensic artefacts for keywords |
| `analyse` | Perform various analyses on artifacts |

#### Chainsaw Examples

```bash
# Hunt with Sigma and Chainsaw Rules
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/

# Hunt with Sigma rules and output in JSON
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --json

# Search for the case-insensitive word 'mimikatz'
./chainsaw search mimikatz -i evtx_attack_samples/

# Search for Powershell Script Block Events (EventID 4104)
./chainsaw search -t 'Event.System.EventID: =4104' evtx_attack_samples/
```

> 🔴 **Important:** The mapping file (specified through the `--mapping` parameter) tells Chainsaw which fields in the event logs to use for rule matching. Configuration is paramount!

---

### Example 1: Hunting for Multiple Failed Logins From Single Source With Sigma

Let's put Chainsaw to work by applying our Sigma rule, `win_security_susp_failed_logons_single_source2.yml` (available at `C:\Rules\sigma`), to `lab_events_2.evtx` (available at `C:\Events\YARASigma\lab_events_2.evtx`) that contains multiple failed login attempts from the same source.

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_2.evtx -s C:\Rules\sigma\win_security_susp_failed_logons_single_source2.yml --mapping .\mappings\sigma-event-logs-all.yml

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: C:\Rules\sigma\win_security_susp_failed_logons_single_source2.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Events\YARASigma\lab_events_2.evtx (extensions: .evt, .evtx)
[+] Loaded 1 forensic artefacts (69.6 KB)
[+] Hunting: [========================================] 1/1 -
[+] Group: Sigma
┌─────────────────────┬───────────────────────────┬───────┬────────────────────────────────┬──────────┬───────────┬─────────────────┬────────────────────────────────┐
│      timestamp      │        detections         │ count │     Event.System.Provider      │ Event ID │ Record ID │    Computer     │           Event Data           │
├─────────────────────┼───────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────┼────────────────────────────────┤
│ 2021-05-20 12:49:52 │ + Failed NTLM Logins with │ 5     │ Microsoft-Windows-Security-Aud │ 4776     │ 1861986   │ fs01.offsec.lan │ PackageName: MICROSOFT_AUTHENT │
│                     │ Different Accounts from   │       │ iting                          │          │           │                 │ ICATION_PACKAGE_V1_0           │
│                     │ Single Source System      │       │                                │          │           │                 │ Status: '0xc0000064'           │
│                     │                           │       │                                │          │           │                 │ TargetUserName: NOUSER         │
│                     │                           │       │                                │          │           │                 │ Workstation: FS01              │
└─────────────────────┴───────────────────────────┴───────┴────────────────────────────────┴──────────┴───────────┴─────────────────┴────────────────────────────────┘

[+] 1 Detections found on 1 documents
```

> 📌 **Result:** Our Sigma rule was able to identify the multiple failed login attempts against NOUSER.

Using the `-s` parameter, we can specify a directory containing Sigma detection rules (or one Sigma detection rule) and Chainsaw will automatically load, convert and run these rules against the provided event logs. The mapping file (specified through the `--mapping` parameter) tells Chainsaw which fields in the event logs to use for rule matching.

---

### Example 2: Hunting for Abnormal PowerShell Command Line Size With Sigma (Based on Event ID 4688)

Firstly, let's set the stage by recognizing that PowerShell, being a highly flexible scripting language, is an attractive target for attackers. Its deep integration with Windows APIs and .NET Framework makes it an ideal candidate for a variety of post-exploitation activities.

To conceal their actions, attackers utilize complex encoding layers or misuse cmdlets for purposes they weren't designed for. This leads to **abnormally long PowerShell commands** that often incorporate Base64 encoding, string merging, and several variables containing fragmented parts of the command.

A Sigma rule that can detect abnormally long PowerShell command lines can be found inside the `C:\Rules\sigma` directory of this section's target, saved as `proc_creation_win_powershell_abnormal_commandline_size.yml`.

```yaml
title: Unusually Long PowerShell CommandLine
id: d0d28567-4b9a-45e2-8bbc-fb1b66a1f7f6
status: test
description: Detects unusually long PowerShell command lines with a length of 1000 characters or more
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova / HTB Academy, Dimitrios Bougioukas
date: 2020/10/06
modified: 2023/04/14
tags:
    - attack.execution
    - attack.t1059.001
    - detection.threat_hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    selection_powershell:
        CommandLine|contains:
            - 'powershell.exe'
            - 'pwsh.exe'
    selection_length:        
        CommandLine|re: '.{1000,}'
    condition: selection and selection_powershell and selection_length
falsepositives:
    - Unknown
level: low
```

#### Sigma Rule Breakdown

| Section | Description |
|---------|-------------|
| **logsource** | Category: process_creation, Product: windows |
| **selection** | EventID 4688, NewProcessName ends with powershell.exe, pwsh.exe, or cmd.exe |
| **selection_powershell** | CommandLine contains powershell.exe or pwsh.exe |
| **selection_length** | CommandLine with 1000+ characters using regex `.{1000,}` |
| **condition** | All three selections must match |

Let's put Chainsaw to work by applying the abovementioned Sigma rule, `proc_creation_win_powershell_abnormal_commandline_size.yml` (available at `C:\Rules\sigma`), to `lab_events_3.evtx` (available at `C:\Events\YARASigma\lab_events_3.evtx`) that contains 4688 events with abnormally long PowerShell commands.

![Event 4688 - Long PowerShell Command](https://github.com/user-attachments/assets/9971481e-f35e-4e60-8f90-b2f48dc1914e)

*Event 4688 in Windows security auditing showing process creation with long PowerShell command line.*

#### First Attempt (Default Mapping)

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml --mapping .\mappings\sigma-event-logs-all.yml

[+] Loading detection rules from: C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Events\YARASigma\lab_events_3.evtx (extensions: .evtx)
[+] Loaded 1 forensic artefacts (69.6 KB)
[+] Hunting: [========================================] 1/1 -
[+] 0 Detections found on 0 documents
```

> 🔴 **Issue:** Our Sigma rule didn't find anything! The NewProcessName field was missing from the sigma-event-logs-all.yml mapping file.

We introduced the NewProcessName field into a `sigma-event-logs-all-new.yml` mapping file inside the `C:\Tools\chainsaw\mappings` directory.

#### Second Attempt (Updated Mapping)

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml --mapping .\mappings\sigma-event-logs-all-new.yml

[+] Loading detection rules from: C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Events\YARASigma\lab_events_3.evtx (extensions: .evtx, .evt)
[+] Loaded 1 forensic artefacts (69.6 KB)
[+] Hunting: [========================================] 1/1 -
[+] Group: Sigma
┌─────────────────────┬─────────────────────────────┬───────┬────────────────────────────────┬──────────┬───────────┬─────────────────────┬──────────────────────────────────┐
│      timestamp      │         detections          │ count │     Event.System.Provider      │ Event ID │ Record ID │      Computer       │            Event Data            │
├─────────────────────┼─────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────────┼──────────────────────────────────┤
│ 2021-04-22 08:51:04 │ + Unusually Long PowerShell │ 1     │ Microsoft-Windows-Security-Aud │ 4688     │ 435121    │ fs03vuln.offsec.lan │ CommandLine: powershell.exe -n   │
│                     │ CommandLine                 │       │ iting                          │          │           │                     │ op -w hidden -noni -c "if([Int   │
│                     │                             │       │                                │          │           │                     │ Ptr]::Size -eq 4){$b='powershe   │
│                     │                             │       │                                │          │           │                     │ ll.exe'}else{$b=$env:windir+'\   │
│                     │                             │       │                                │          │           │                     │ syswow64\WindowsPowerShell\v1.   │
│                     │                             │       │                                │          │           │                     │ 0\powershell.exe'};$s=New-Obje   │
│                     │                             │       │                                │          │           │                     │ ct System.Diagnostics.ProcessS   │
│                     │                             │       │                                │          │           │                     │ tartInfo;$s.FileName=$b;$s.Arg   │
│                     │                             │       │                                │          │           │                     │ uments='-noni -nop -w hidden -   │
│                     │                             │       │                                │          │           │                     │ c &([scriptblock]::create((New   │
│                     │                             │       │                                │          │           │                     │ -Object System.IO.StreamReader   │
│                     │                             │       │                                │          │           │                     │ (New-Object System.IO.Compress   │
│                     │                             │       │                                │          │           │                     │ ion.GzipStream((New-Object Sys   │
│                     │                             │       │                                │          │           │                     │ tem.IO.MemoryStream(,[System.C   │
│                     │                             │       │                                │          │           │                     │ onvert]::FromBase64String(''H4   │
│                     │                             │       │                                │          │           │                     │ sIAPg2gWACA7VWbW+bSBD+nEj5D6iy   │
│                     │                             │       │                                │          │           │                     │ ...                              │
│                     │                             │       │                                │          │           │                     │ (use --full to show all content) │
│                     │                             │       │                                │          │           │                     │ NewProcessId: '0x7f0'            │
│                     │                             │       │                                │          │           │                     │ NewProcessName: C:\Windows\Sys   │
│                     │                             │       │                                │          │           │                     │ tem32\WindowsPowerShell\v1.0\p   │
│                     │                             │       │                                │          │           │                     │ owershell.exe                    │
├─────────────────────┼─────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────────┼──────────────────────────────────┤
│ 2021-04-22 08:51:04 │ + Unusually Long PowerShell │ 1     │ Microsoft-Windows-Security-Aud │ 4688     │ 435120    │ fs03vuln.offsec.lan │ CommandLine: C:\Windows\system   │
│                     │ CommandLine                 │       │ iting                          │          │           │                     │ 32\cmd.exe /b /c start /b /min   │
│                     │                             │       │                                │          │           │                     │  powershell.exe -nop -w hidden   │
├─────────────────────┼─────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────────┼──────────────────────────────────┤
│ 2021-04-22 08:51:05 │ + Unusually Long PowerShell │ 1     │ Microsoft-Windows-Security-Aud │ 4688     │ 435124    │ fs03vuln.offsec.lan │ CommandLine: '"C:\Windows\sysw   │
│                     │ CommandLine                 │       │ iting                          │          │           │                     │ ow64\WindowsPowerShell\v1.0\po   │
└─────────────────────┴─────────────────────────────┴───────┴────────────────────────────────┴──────────┴───────────┴─────────────────────┴──────────────────────────────────┘

[+] 3 Detections found on 3 documents
```

> 📌 **Success!** Our Sigma rule successfully uncovered all three abnormally long PowerShell commands that exist inside lab_events_3.evtx.

---

### 🔴 Key Takeaway

> 📌 **Configuration when it comes to using or translating Sigma rules is of paramount importance!**

The mapping file tells Chainsaw which event log fields to use for rule matching. Without the correct mapping, even a well-written Sigma rule will fail to detect threats.

---

## 10. Hunting Evil with Sigma (Splunk Edition) {#10-hunting-evil-with-sigma-splunk-edition}

> 📌 **Splunk** - Convert Sigma rules to SIEM-specific queries using sigmac tool.

### Overview

As discussed when introducing Sigma, Sigma rules revolutionize our approach to log analysis and threat detection. What we're dealing with here is a sort of **Rosetta Stone for SIEM systems**. Sigma is like a universal translator that brings in a level of abstraction to event logs, taking away the painful element of SIEM-specific query languages.

Let's validate this assertion by converting two Sigma rules into their corresponding SPL formats and examining the outcomes.

---

### Example 1: Hunting for MiniDump Function Abuse to Dump LSASS's Memory (comsvcs.dll via rundll32)

A Sigma rule named `proc_access_win_lsass_dump_comsvcs_dll.yml` can be found inside the `C:\Tools\chainsaw\sigma\rules\windows\process_access` directory of the previous section's target.

> 📌 This Sigma rule detects adversaries leveraging the MiniDump export function of comsvcs.dll via rundll32 to perform a memory dump from LSASS.

We can translate this rule into a Splunk search with sigmac (available at `C:\Tools\sigma-0.21\tools`) as follows:

```powershell
PS C:\Tools\sigma-0.21\tools> python sigmac -t splunk C:\Tools\chainsaw\sigma\rules\windows\process_access\proc_access_win_lsass_dump_comsvcs_dll.yml -c .\config\splunk-windows.yml
(TargetImage="*\\lsass.exe" SourceImage="C:\\Windows\\System32\\rundll32.exe" CallTrace="*comsvcs.dll*")
```

> 📌 **sigmac command breakdown:**
> - `-t splunk` - Output format for Splunk
> - `-c .\config\splunk-windows.yml` - Use Splunk Windows configuration

Let's now navigate to the target system. Then, let's navigate to `http://[Target IP]:8000`, open the "Search & Reporting" application, and submit the Splunk search sigmac provided us with.

![Splunk Search - LSASS Dump Detection](https://github.com/user-attachments/assets/376c3b09-23b2-4a46-8e07-539fc42cc82a)

*Splunk interface showing a search for events with target image lsass.exe and source image rundll32.exe. Event details include host, source, and call trace information.*

> 📌 **Result:** The Splunk search provided by sigmac was indeed able to detect MiniDump function abuse to dump LSASS's memory.

---

### Example 2: Hunting for Notepad Spawning Suspicious Child Process

A Sigma rule named `proc_creation_win_notepad_susp_child.yml` can be found inside the `C:\Rules\sigma` directory of the previous section's target.

> 📌 This Sigma rule detects notepad.exe spawning a suspicious child process.

We can translate this rule into a Splunk search with sigmac (available at `C:\Tools\sigma-0.21\tools`) as follows:

```powershell
PS C:\Tools\sigma-0.21\tools> python sigmac -t splunk C:\Rules\sigma\proc_creation_win_notepad_susp_child.yml -c .\config\splunk-windows.yml
(ParentImage="*\\notepad.exe" (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe" OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\taskkill.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\calc.exe"))
```

> 📌 **SPL Query Breakdown:**
> - `ParentImage="*\\notepad.exe"` - Parent process is notepad.exe
> - `(Image="*\\powershell.exe" OR ...)` - Any of these suspicious child processes

Let's navigate to the target system. Then, let's navigate to `http://[Target IP]:8000`, open the "Search & Reporting" application, and submit the Splunk search sigmac provided us with.

![Splunk Search - Notepad Suspicious Child](https://github.com/user-attachments/assets/128ae3e8-d432-46f9-8aa6-8c9c21cd6d1a)

*Splunk interface showing a search for events with target image winlogon.exe and various image filters. Event details include host, source, command line, and computer name.*

> 📌 **Result:** The Splunk search provided by sigmac was indeed able to detect notepad.exe spawning suspicious processes (such as PowerShell).

---

### 🔴 Important Note

> 📌 **Sigma Config Files:**
> Please note that more frequently than not you will have to tamper with Sigma's config files (available inside the `C:\Tools\sigma-0.21\tools\config` directory of the previous section's target) in order for the SIEM queries to be readily usable.

The configuration files define how Sigma maps its generic field names to SIEM-specific field names. Without proper configuration, the generated queries may not work correctly.

---

### Sigma to Splunk Conversion Summary

| Sigma Rule | Splunk Query |
|------------|--------------|
| LSASS Dump (comsvcs.dll) | `(TargetImage="*\\lsass.exe" SourceImage="C:\\Windows\\System32\\rundll32.exe" CallTrace="*comsvcs.dll*")` |
| Notepad Suspicious Child | `(ParentImage="*\\notepad.exe" (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR ...))` |

---

## 11. Interview Questions {#11-interview-questions}

### Q1: What is the difference between YARA and Sigma?

**Answer:** YARA excels in file and memory analysis, pattern matching on disk and in running processes. Sigma is particularly adept at log analysis and SIEM systems, providing a generic format that can be converted to various SIEM query languages.

---

### Q2: What are the main components of a YARA rule?

**Answer:** A YARA rule consists of:
- **Rule Identifier** - Unique name for the rule
- **Metadata** - Additional information (author, date, description)
- **Strings** - Patterns to search for
- **Condition** - Logic that determines a match

---

### Q3: Explain the condition logic in YARA rules.

**Answer:** Conditions use Boolean operators (and, or, not) and can include:
- String matching: `$string1 at 0`, `$string2 in (100..200)`
- Count: `#string > 5`
- File size: `filesize < 10MB`
- Regular expressions: `$regex1 matches /(pattern)/`

---

### Q4: What is sigmac and what does it do?

**Answer:** sigmac is a command-line tool that converts Sigma rules into SIEM-specific query formats (Splunk SPL, Elasticsearch DSL, Azure KQL, etc.). It uses configuration files to map Sigma's generic field names to SIEM-specific field names.

---

### Q5: How do you detect encoded PowerShell commands?

**Answer:** Look for:
- Long PowerShell command lines (1000+ characters)
- Base64 encoded strings in command arguments
- Common obfuscation patterns: `-enc`, `-encodedcommand`, `-e`
- Unusual encoding methods in Sigma rules like `CommandLine|re: '.{1000,}'`

---

### Q6: What is Chainsaw and when would you use it?

**Answer:** Chainsaw is a fast tool to hunt security threats in Windows Event Logs. It's used when you don't have access to a SIEM and need to scan multiple EVTX files concurrently using Sigma rules. It supports both Sigma and custom Chainsaw detection rules.

---

### Q7: How do you handle false positives in Sigma rules?

**Answer:**
1. Add filters to exclude known false positives
2. Use `filter_optional_*` naming convention in Sigma rules
3. Test rules against production logs before deployment
4. Adjust detection logic with additional conditions
5. Add `not` conditions for legitimate activities

---

### Q8: What is the Pyramid of Pain in the context of YARA/Sigma?

**Answer:** The Pyramid of Pain shows indicator difficulty:
- **Bottom (easy to change):** Hash values, IP addresses
- **Top (hard to change):** TTPs (Tools, Tactics, Procedures)

YARA and Sigma rules detect TTPs, which are more valuable than simple IOCs.

---

### Q9: Explain the logsource section in Sigma rules.

**Answer:** The logsource defines where the rule applies:
- `product` - Operating system (windows, linux, macos)
- `service` - Windows service (security, system, application)
- `category` - Event category (process_creation, network_connection)

This ensures rules only match relevant log sources.

---

### Q10: What are the key differences between YARA and Sigma rules?

| Aspect | YARA | Sigma |
|--------|------|-------|
| **Primary Use** | File/memory scanning | Log analysis |
| **Target** | Static files, processes | SIEM events |
| **Format** | Custom syntax | YAML |
| **Conversion** | Standalone | Converts to SIEM queries |

---

## 12. Additional Resources {#12-additional-resources}

### YARA Resources
- [YARA-Rules](https://github.com/Yara-Rules/rules/tree/master/malware)
- [Open-Source YARA rules](https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master)
- [YARA Documentation](https://yara.readthedocs.io/)
- [yarGen](https://github.com/Neo23x0/yarGen)

### Sigma Resources
- [SigmaHQ Rules](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)
- [joesecurity sigma-rules](https://github.com/joesecurity/sigma-rules)
- [SIGMA detection rules](https://github.com/mdecrevoisier/SIGMA-detection-rules)

### Tools
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
- [Zircolite](https://github.com/wagga40/Zircolite)
- [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools)

### Communities
- r/cybersecurity (Reddit)
- r/SOCanalysts (Reddit)
- Twitter/X security researchers
- SANS Digital Forensics
- FIRST (Forum of Incident Response)

### Further Learning
- [MITRE ATT&CK](https://attack.mitre.org)
- [Red Canary Blog](https://redcanary.com/blog/)
- [The DFIR Report](https://thedfirreport.com/)
- [Carbon Black Blog](https://www.carbonblack.com/blog/)

---

*Module 12/15 - YARA & Sigma for SOC Analysts*
*For learning and SOC career preparation*
