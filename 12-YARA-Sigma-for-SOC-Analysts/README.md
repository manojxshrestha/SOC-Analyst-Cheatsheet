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
2. [YARA and YARA Rules](#2-yara-and-yara-rules)
3. [Developing YARA Rules](#3-developing-yara-rules)
4. [Leveraging Sigma](#4-leveraging-sigma)
5. [Skills Assessment](#5-skills-assessment)

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

## 3. Developing YARA Rules

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

- `python3 yarGen.py`: Execute the yarGen Python script
- `-m /home/htb-student/temp`: This option specifies the source directory where the sample files (e.g., malware or suspicious files) are located. The script will analyze these samples to generate YARA rules.
- `-o htb_sample.yar`: This option indicates the output file name for the generated YARA rules. In this case, the YARA rules will be saved to a file named htb_sample.yar.

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
> - `good-strings-part*.db` - Goodware string databases
> - `good-imphashes-part*.db` - Goodware import hash databases
> - `good-exports-part*.db` - Goodware export databases
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
> - `$x1` is an exclusive string (likely unique to malware) - matched with `1 of ($x*)`
> - `$s2` to `$s20` are supplementary strings - matched with `4 of them`
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

**Rule Imports:**
- `import "pe"`: By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files. This makes the rule more precise when it comes to detecting characteristics in Windows executables.

**Rule Meta:**
- `description`: Tells us the main purpose of the rule, which is to detect APT17 malware.
- `license`: Points to the location and version of the license governing the use of this YARA rule.
- `author`: The rule was written by Florian Roth from Nextron Systems.
- `reference`: Provides a link that goes into more detail about the malware or context of this rule.
- `date`: The date the rule was either created or last updated, in this case, 3rd October 2017.
- `hash1, hash2, hash3`: Hash values, probably of samples related to APT17, which the author used as references or as foundational data to create the rule.

**Rule Body:**
- `$x*` strings (exclusive strings): These are strings that are less likely to appear in benign files
- `$s*` strings (supplementary strings): Additional strings that support detection

**Rule Condition:**
- `uint16(0) == 0x5a4d`: Checks if the first two bytes of the file are "MZ", which is the magic number for Windows executables. So, we're focusing on detecting Windows binaries.
- `filesize < 200KB`: Limits the rule to scan only small files, specifically those smaller than 200KB.
- `pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9"`: This checks the import hash (imphash) of the PE (Portable Executable) file. Imphashes are great for categorizing and clustering malware samples based on the libraries they import.
- `1 of ($x*)`: At least one of the $x strings (from the strings section) must be present in the file.
- `6 of them`: Requires that at least six of the strings (from both $x and $s categories) be found within the scanned file.

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
- `$class1` to `$class8`: These are eight ASCII strings corresponding to class names within the .NET assembly (StorageUtils, WebServer, StorageFile, StorageScript, ServerConfig, CommandScript, MSExchangeService, W3WPDIAG)
- `$func1` to `$func7`: These seven ASCII strings represent function names within the .NET assembly (AddConfigAsString, DelConfigAsString, GetConfigAsString, EncryptScript, ExecCMD, KillOldThread, FindSPath)
- `$dotnetMagic = "BSJB"`: This signature is present in the CLI (Common Language Infrastructure) header of .NET binaries. Its presence indicates the file is a .NET assembly. Specifically, it's in the Signature field of the CLI header, which follows the PE header and additional tables.

**Condition Section:**
- `uint16(0) == 0x5A4D`: This checks if the first two bytes at the start of the file are "MZ", a magic number indicating a Windows Portable Executable (PE) format.
- `uint16(uint32(0x3c)) == 0x4550`: A two-step check. First, it reads a 32-bit (4 bytes) value from offset 0x3c of the file. In PE files, this offset typically contains a pointer to the PE header. It then checks whether the two bytes at that pointer are "PE" (0x4550), indicating a valid PE header. This ensures the file is a legitimate PE format and not a corrupted or obfuscated one.
- `$dotnetMagic`: Verifies the presence of the BSJB string. This signature is present in the CLI (Common Language Infrastructure) header of .NET binaries.
- `6 of them`: This condition states that at least six of the previously defined strings (either classes or functions) must be found within the file. This ensures that even if a few signatures are absent or have been modified, the rule will still trigger if a substantial number remain.

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
    filesize < 700000 and
    pe.number_of_sections > 4 and
    pe.number_of_signatures == 0 and
    pe.number_of_resources > 1 and pe.number_of_resources < 15 and 
    for any i in (0..pe.number_of_resources - 1):
    ( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and 
      pe.resources[i].id == 101 and
      pe.resources[i].length > 20000 and
      pe.resources[i].language == 0 and
      not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
    )
}
```

**Rule Breakdown:**

**Rule Imports:**
- `import "pe"`: By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files. This makes the rule more precise when it comes to detecting characteristics in Windows executables.
- `import "math"`: Imports the math module, providing mathematical functions like entropy calculations.

**Rule Meta:**
- `copyright = "Kaspersky Lab"`: The rule was authored or copyrighted by Kaspersky Lab.
- `description = "Generic detection for samples that enumerate files with encrypted resource called 101"`: The rule aims to detect samples that list files and have an encrypted resource with identifier "101".
- `reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/"`: Provides a URL for additional context or information about the rule.
- `hash`: Two hashes are given, probably as examples of known malicious files that match this rule.
- `version = "1.4"`: The version number of the YARA rule.

**Strings Section:**
- `$mz = "This program cannot be run in DOS mode."`: The ASCII string that typically appears in the DOS stub part of a PE file.
- `$a1 = "FindFirstFile"`, `$a2 = "FindNextFile"`: Strings for Windows API functions used to enumerate files. The usage of FindFirstFileW and FindNextFileW API functions can be identified through string analysis.
- `$a3 = "FindResource"`, `$a4 = "LoadResource"`: As already mentioned Stonedrill samples feature encrypted resources. These strings can be found through string analysis and they are related to Windows API functions used for handling resources within the executable.

**Rule Condition:**
- `uint16(0) == 0x5A4D`: Checks if the first two bytes of the file are "MZ," indicating a Windows PE file.
- `all of them`: All the strings $a1, $a2, $a3, $a4 must be present in the file.
- `filesize < 700000`: The file size must be less than 700,000 bytes.
- `pe.number_of_sections > 4`: The PE file must have more than four sections.
- `pe.number_of_signatures == 0`: The file must not be digitally signed.
- `pe.number_of_resources > 1 and pe.number_of_resources < 15`: The file must contain more than one but fewer than 15 resources.
- `for any i in (0..pe.number_of_resources - 1): ((math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and pe.resources[i].id == 101 and pe.resources[i].length > 20000 and pe.resources[i].language == 0 and not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length)))`: Go through each resource in the file and check if the entropy of the resource data is more than 7.8 AND the resource identifier is 101 AND the resource length is greater than 20,000 bytes AND the language identifier of the resource is 0 AND the DOS stub string is not present in the resource. It's not required for all resources to match the condition; only one resource meeting all the criteria is sufficient for the overall YARA rule to be a match.

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

## 5. Leveraging Sigma

*Coming soon...*

---

## 4. Hunting Evil with YARA (Windows Edition)

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

On a Linux machine, the hexdump utility can be used to identify the hex bytes:

```bash
hexdump dharma_sample.exe -C | grep crysis -n3
```

**Output:**
```
3140-0000c7e0  52 00 43 6c 6f 73 65 48  61 6e 64 6c 65 00 4b 45  |R.CloseHandle.KE|
3141-0000c7f0  52 4e 45 4c 33 32 2e 64  6c 6c 00 00 52 53 44 53  |RNEL32.dll..RSDS|
3142-0000c800  25 7e 6d 90 fc 96 43 42  8e c3 87 23 6b 61 a4 92  |%~m...CB...#ka..|
3143:0000c810  03 00 00 00 43 3a 5c 63  72 79 73 69 73 5c 52 65  |....C:\crysis\Re|
3144-0000c820  6c 65 61 73 65 5c 50 44  42 5c 70 61 79 6c 6f 61  |lease\PDB\payloa|
3145-0000c830  64 2e 70 64 62 00 00 00  00 00 00 00 00 00 00 00  |d.pdb...........|
```

```bash
hexdump dharma_sample.exe -C | grep sssssbsss -n3
```

**Output:**
```
5738-00016be0  3d 00 00 00 26 00 00 00  73 73 73 64 00 00 00 00  |=...&...sssd....|
5739-00016bf0  26 61 6c 6c 3d 00 00 00  73 64 00 00 2d 00 61 00  |&all=...sd..-.a.|
5740-00016c00  00 00 00 00 73 00 73 00  62 00 73 00 73 00 00 00  |....s.s.b.s.s...|
5741:00016c10  73 73 73 73 73 62 73 73  73 00 00 00 73 73 73 73  |sssssbsss...ssss|
```

#### Creating YARA Rule with Hex Strings

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
> - `$string_pdb` uses hex notation `{ 43...62 }` to match the UTF-8 encoded path string
> - `$string_ssss` uses hex bytes to match the ASCII repeated "s" pattern
> - `condition: all of them` requires both strings to be found for a match

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

- `yara64.exe`: The YARA64 executable for 64-bit systems
- `-s C:\Rules\yara\dharma_ransomware.yar`: Specifies the YARA rules file
- `C:\Samples\YARASigma`: Directory to scan
- `-r`: Recursive scanning (subdirectories included)
- `2>nul`: Suppresses error messages

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
> - `$s1` uses wildcards (`?`) to match variable bytes
> - `$s2` uses `??` for any byte at that position
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
- `-t user`: User-mode event tracing
- `-pn Microsoft-Windows-PowerShell`: Target PowerShell events
- `-ot file`: Save to file
- `-p ./etw_ps_logs.json`: Output JSON file
- `-l verbose`: Detailed logging
- `-y C:\Rules\yara`: Enable YARA scanning
- `-yo Matches`: Display only matches

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
> - `-yo Matches` reduces noise by showing only detections

---

## 5. Skills Assessment

*Coming soon...*

---

*Module 12/15 - YARA & Sigma for SOC Analysts*
*For learning and SOC career preparation*
