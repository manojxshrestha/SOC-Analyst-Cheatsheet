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

> 📌 **yarGen** automatically generates YARA rules based on strings found in malicious files while avoiding common goodware strings.

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
- `-m /home/htb-student/temp` - Source directory with malware samples
- `-o htb_sample.yar` - Output file for generated rules

**Output Example:**
```
[+] Using identifier 'temp'
[+] Processing PEStudio strings ...
[+] Reading goodware strings from database 'good-strings.db' ...
[+] Processing malware files ...
[+] Generating Simple Rules ...
[=] Generated 1 SIMPLE rules.
[=] All rules written to htb_sample.yar
[+] yarGen run finished
```

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
      ...
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}
```

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
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
      $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus" ascii
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
- `import "pe"` - Import PE module for Windows executables
- `uint16(0) == 0x5a4d` - Check for MZ magic bytes (PE file)
- `filesize < 200KB` - Limit to small files
- `pe.imphash()` - Match import hash
- `1 of ($x*)` - At least one $x string must match
- `6 of them` - At least 6 total strings must match

---

#### Example 2: Neuron (Turla)

**Sample:** `Microsoft.Exchange.Service.exe` (.NET malware)

**Disassemble .NET Assembly:**
```bash
monodis --output=code Microsoft.Exchange.Service.exe
```

**Key Strings Identified:**
- Classes: `StorageUtils`, `WebServer`, `StorageFile`, `CommandScript`
- Functions: `ExecCMD`, `EncryptScript`, `KillOldThread`
- .NET Magic: `BSJB` (CLI header)

**YARA Rule:**
```yara
rule neuron_functions_classes_and_vars {
 meta:
    description = "Rule for detection of Neuron based on .NET functions and class names"
    author = "NCSC UK"
    reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
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
- `uint16(0) == 0x5A4D` - Check for MZ header
- `uint16(uint32(0x3c)) == 0x4550` - Verify PE header at offset 0x3c
- `$dotnetMagic` - Check for .NET CLI header (BSJB)
- `6 of them` - At least 6 strings must match

---

#### Example 3: Stonedrill (Shamoon 2.0)

**Sample:** `sham2.exe`

**Check Entropy:**
```bash
python3 entropy_pe_section.py -f /home/htb-student/Samples/YARASigma/sham2.exe
```

**Output:**
```
.rsrc: entropy: 7.976847940518103  (High - encrypted!)
```

**YARA Rule:**
```yara
import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
  meta:
    copyright = "Kaspersky Lab"
    description = "Generic detection for samples with encrypted resource 101"
    reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/"
    hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
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
- `import "pe"` - PE module for analyzing PE files
- `import "math"` - Math module for entropy calculation
- `pe.number_of_sections > 4` - Must have more than 4 sections
- `pe.number_of_signatures == 0` - Must NOT be signed
- `pe.number_of_resources` - Must have resources (1-15)
- `math.entropy() > 7.8` - Resource must have high entropy (encrypted)
- `pe.resources[i].id == 101` - Resource ID must be 101

---

### YARA Rule Development Resources

| Resource | Description |
|----------|-------------|
| [YARA Documentation](https://yara.readthedocs.io/) | Official YARA documentation |
| [Kaspersky Blog](https://securelist.com/) | YARA rule development guides |
| [How to Write Simple but Sound Yara Rules - Part 1](https://blog...) | Florian Roth's guide |
| [How to Write Simple but Sound Yara Rules - Part 2](https://blog...) | Part 2 |
| [How to Write Simple but Sound Yara Rules - Part 3](https://blog...) | Part 3 |

---

## 4. Leveraging Sigma

*Coming soon...*

---

## 4. Skills Assessment

*Coming soon...*

---

*Module 12/15 - YARA & Sigma for SOC Analysts*
*For learning and SOC career preparation*
