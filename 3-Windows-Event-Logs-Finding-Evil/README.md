# Windows Event Logs & Finding Evil
## SOC Analyst Cheatsheet - Module 3/15

---

## 0. Overview

This module covers **Windows Event Logs & Sysmon** - the primary data sources for detecting malicious activity on Windows endpoints. You'll learn how to analyze security logs, use Sysmon for enhanced detection, identify suspicious behavior, and find evil using Windows event log analysis.

### Key Takeaways

| Concept | Description |
|---------|-------------|
| **Windows Event Logs** | Records of system, security, and application events |
| **Security Event IDs** | Windows security log event identifiers |
| **Sysmon** | System Monitor - enhanced logging for security |
| **DLL Hijacking** | Loading malicious DLLs via legitimate processes |
| **Process Injection** | Injecting code into legitimate processes |
| **Credential Dumping** | Extracting credentials from LSASS |

### Prerequisites

- Basic understanding of Windows OS
- Familiarity with Windows administration
- Understanding of Windows Event Viewer

### Module Duration

- **Theory**: 3-4 hours
- **Hands-on Practice**: 4-5 hours
- **Total**: ~8-9 hours

---

## Table of Contents

0. [Overview](#0-overview)
1. [Windows Event Logging Basics](#1-windows-event-logging-basics)
2. [Analyzing Evil With Sysmon & Event Logs](#2-analyzing-evil-with-sysmon--event-logs)
3. [Event Tracing for Windows (ETW)](#3-event-tracing-for-windows-etw)
4. [Interview Questions](#4-interview-questions)
5. [Additional Resources](#5-additional-resources)

---

## 1. Windows Event Logging Basics

Windows Event Logs are an intrinsic part of the Windows Operating System, storing logs from different components of the system including the system itself, applications running on it, ETW providers, services, and others.

Windows event logging offers comprehensive logging capabilities for application errors, security events, and diagnostic information. As cybersecurity professionals, we leverage these logs extensively for analysis and intrusion detection.

The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose.

Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.

Accessing the Windows Event Viewer as an administrative user allows us to explore the various logs available.

<img width="1192" height="972" alt="image" src="https://github.com/user-attachments/assets/2a988d43-8bcb-484f-810a-0ad9c746d5ef" />

Windows search for 'Event Viewer' showing options: Open, Run as administrator, Open file location, Pin to Start, Pin to taskbar.

<img width="1000" height="246" alt="image" src="https://github.com/user-attachments/assets/ddb8775f-47a0-4916-b546-ffa3f84c7203" />

Windows Logs showing Application, Security, Setup, System, and Forwarded Events with event counts and sizes.

The default Windows event logs consist of Application, Security, Setup, System, and Forwarded Events. While the first four logs cover application errors, security events, system setup activities, and general system information, the "Forwarded Events" section is unique, showcasing event log data forwarded from other machines.

It should be noted, that the Windows Event Viewer has the ability to open and display previously saved .evtx files, which can be then found in the "Saved Logs" section.

<img width="1755" height="1587" alt="image" src="https://github.com/user-attachments/assets/7e864e6d-4201-4ff7-af63-00497c5c1773" />

Event Viewer displaying DLLHijack logs with details of Sysmon events, including registry value changes and process information.

### The Anatomy of an Event Log

When examining Application logs, we encounter two distinct levels of events: information and error.

<img width="342" height="92" alt="image" src="https://github.com/user-attachments/assets/bdb98596-ad2a-4d5e-9a90-bad8ed5eedd2" />

Icons for Information and Error with counts.

Information events provide general usage details about the application, such as its start or stop events. Conversely, error events highlight specific errors and often offer detailed insights into the encountered issues.

<img width="1000" height="665" alt="image" src="https://github.com/user-attachments/assets/21998c23-a8a2-498b-95db-fafb9d5327c1" />

Event Viewer error for SideBySide, Event ID 35, detailing activation context generation failure for Visual Studio with processor architecture mismatch.

Each entry in the Windows Event Log is an "Event" and contains the following primary components:

- **Log Name**: The name of the event log (e.g., Application, System, Security, etc.)
- **Source**: The software that logged the event
- **Event ID**: A unique identifier for the event
- **Task Category**: This often contains a value or name that can help us understand the purpose or use of the event
- **Level**: The severity of the event (Information, Warning, Error, Critical, and Verbose)
- **Keywords**: Keywords are flags that allow us to categorize events in ways beyond the other classification options. These are generally broad categories, such as "Audit Success" or "Audit Failure" in the Security log
- **User**: The user account that was logged on when the event occurred
- **OpCode**: This field can identify the specific operation that the event reports
- **Logged**: The date and time when the event was logged
- **Computer**: The name of the computer where the event occurred
- **XML Data**: All the above information is also included in an XML format along with additional event data

The Keywords field is particularly useful when filtering event logs for specific types of events. It can significantly enhance the precision of search queries by allowing us to specify events of interest, thus making log management more efficient and effective.

Taking a closer look at the event log above, we observe several crucial elements. The Event ID in the top left corner serves as a unique identifier, which can be further researched on Microsoft's website to gather additional information. The "SideBySide" label next to the event ID represents the event source. Below, we find the general error description, often containing rich details. By clicking on the details, we can further analyze the event's impact using XML or a well-formatted view.

<img width="1000" height="640" alt="image" src="https://github.com/user-attachments/assets/a97d664c-5f14-4dda-bcf9-01116623ebd2" />

Event Viewer details for SideBySide, Event ID 35, showing provider, version, level, and creation time.

Additionally, we can extract supplementary information from the event log, such as the process ID where the error occurred, enabling more precise analysis.

<img width="1000" height="472" alt="image" src="https://github.com/user-attachments/assets/fa7aba6d-b0f8-4c3f-93ef-b36e5e30e8e9" />

Event Viewer details showing SystemTime, EventRecordID 1773, ProcessID 636, ThreadID 0, on computer ARASHPARSA2BB9.

Switching our focus to security logs, let's consider event ID 4624, a commonly occurring event (detailed at https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624).

<img width="1000" height="644" alt="image" src="https://github.com/user-attachments/assets/76abc65d-cd7e-40ef-94b1-ac41501d0d85" />

Event Viewer log for Event 4624, Microsoft Windows security auditing, showing successful account logon with Security ID SYSTEM, Account Name ARASHPARSA2BB9$, and Logon Type 5.

According to Microsoft's documentation, this event signifies the creation of a logon session on the destination machine, originating from the accessed computer where the session was established. Within this log, we find crucial details, including the "Logon ID", which allows us to correlate this logon with other events sharing the same "Logon ID". Another important detail is the "Logon Type", indicating the type of logon. In this case, it specifies a Service logon type, suggesting that "SYSTEM" initiated a new service.

### Leveraging Custom XML Queries

To streamline our analysis, we can create custom XML queries to identify related events using the "Logon ID" as a starting point. By navigating to "Filter Current Log" -> "XML" -> "Edit Query Manually," we gain access to a custom XML query language that enables more granular log searches.

<img width="1000" height="670" alt="image" src="https://github.com/user-attachments/assets/e626b057-5dfe-4e04-9474-d4b097babf38" />

Event Viewer filter setup with XML query for Security log, filtering by SubjectLogonId 0x3E7.

In the example query, we focus on events containing the "SubjectLogonId" field with a value of "0x3E7". The selection of this value stems from the need to correlate events associated with a specific "Logon ID" and understand the relevant details within those events.

<img width="1000" height="685" alt="image" src="https://github.com/user-attachments/assets/1cd544c2-f410-4a81-9658-72348b937517" />

Event 4624 details: SubjectUserName ARASHPARSA2BB9$, SubjectDomainName WORKGROUP, TargetUserName SYSTEM, LogonType 5, LogonProcessName Advapi.

By constructing such queries, we can narrow down our focus to the account responsible for initiating the service and eliminate unnecessary details. This approach helps unveil a clearer picture of recent logon activities associated with the specified Logon ID.

### Useful Windows Event Logs

Find below an indicative (non-exhaustive) list of useful Windows event logs:

**Windows System Logs**
- **Event ID 1074** (System Shutdown/Restart): Indicates when and why the system was shut down or restarted
- **Event ID 6005** (The Event log service was started): Marks the time when the Event Log Service was started (system boot-up)
- **Event ID 6006** (The Event log service was stopped): Signifies when the Event Log Service was stopped
- **Event ID 6013** (Windows uptime): Shows the uptime of the system in seconds (helps detect unauthorized reboots)
- **Event ID 7040** (Service status change): Indicates a change in service startup type

**Windows Security Logs**
- **Event ID 1102** (The audit log was cleared): Often a sign of an attempt to remove evidence
- **Event ID 4624** (Successful Logon): Records successful logon events
- **Event ID 4625** (Failed Logon): Logs failed logon attempts - multiple could indicate brute-force
- **Event ID 4648** (Explicit credentials): Triggered when a user logs on with explicit credentials to run a program (lateral movement)
- **Event ID 4672** (Special Privileges Assigned): Logged whenever an account logs on with super user privileges
- **Event ID 4698** (Scheduled task created): Triggered when a scheduled task is created (persistence)
- **Event ID 7045** (Service installed): New services might suggest malware installation

---

## 2. Analyzing Evil With Sysmon & Event Logs

In our pursuit of robust cybersecurity, it is crucial to understand how to identify and analyze malicious events effectively. Building upon our previous exploration of benign events, we will now delve into the realm of malicious activities and discover techniques for detection.

### Sysmon Basics

When investigating malicious events, several event IDs serve as common indicators of compromise. For instance, Event ID 4624 provides insights into new logon events, enabling us to monitor and detect suspicious user access and logon patterns. Similarly, Event ID 4688 furnishes information about newly created processes, aiding the identification of unusual or malicious process launches. To enhance our event log coverage, we can extend the capabilities by incorporating Sysmon, which offers additional event logging capabilities.

System Monitor (Sysmon) is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. Sysmon provides detailed information about process creation, network connections, changes to file creation time, and more.

Sysmon's primary components include:
- A Windows service for monitoring system activity
- A device driver that assists in capturing the system activity data
- An event log to display captured activity data

Sysmon's unique capability lies in its ability to log information that typically doesn't appear in the Security Event logs, and this makes it a powerful tool for deep system monitoring and cybersecurity forensic analysis.

Sysmon categorizes different types of system activity using event IDs, where each ID corresponds to a specific type of event. For example, Event ID 1 corresponds to "Process Creation" events, and Event ID 3 refers to "Network Connection" events.

For more granular control over what events get logged, Sysmon uses an XML-based configuration file. The configuration file allows you to include or exclude certain types of events based on different attributes like process names, IP addresses, etc. Popular Sysmon configuration files:
- https://github.com/SwiftOnSecurity/sysmon-config (Comprehensive)
- https://github.com/olafhartong/sysmon-modular (Modular approach)

To get started, you can install Sysmon by downloading it from the official Microsoft documentation. Once downloaded, open an administrator command prompt and execute the following command to install Sysmon:

```
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

To utilize a custom Sysmon configuration, execute the following after installing Sysmon:

```
C:\Tools\Sysmon> sysmon.exe -c filename.xml
```

Note: It should be noted that Sysmon for Linux also exists.

### Detection Example 1: Detecting DLL Hijacking

In our specific use case, we aim to detect a DLL hijack. The Sysmon event log IDs relevant to DLL hijacks can be found in the Sysmon documentation. To detect a DLL hijack, we need to focus on Event Type 7, which corresponds to module load events.

To achieve this, we need to modify the sysmonconfig-export.xml Sysmon configuration file we downloaded from https://github.com/SwiftOnSecurity/sysmon-config.

By examining the modified configuration, we can observe that the "include" comment signifies events that should be included.

<img width="1926" height="222" alt="image" src="https://github.com/user-attachments/assets/b54fdbbb-d6fe-4db9-89d0-602e1fca858d" />

XML snippet showing RuleGroup with ImageLoad set to 'include' and a note about no rules meaning nothing will be logged.

In the case of detecting DLL hijacks, we change the "include" to "exclude" to ensure that nothing is excluded, allowing us to capture the necessary data.

<img width="1820" height="200" alt="image" src="https://github.com/user-attachments/assets/e80c9c0e-0c13-4c43-86b8-75741318234a" />

XML snippet with RuleGroup, ImageLoad set to 'exclude', and a note about using 'include' with no rules.

To utilize the updated Sysmon configuration, execute the following:

```
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
```

<img width="1450" height="436" alt="image" src="https://github.com/user-attachments/assets/f46ab0d6-43dc-4992-8aa2-4d0b0708b81b" />

Command prompt showing Sysmon v13.33 loading sysmonconfig-export.xml, configuration validated and updated.

With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon."

<img width="1000" height="468" alt="image" src="https://github.com/user-attachments/assets/a97c30a2-4dca-48b4-8469-cec3d17ceeec" />

Sysmon event log showing multiple Information entries for Event ID 7, Image loaded.

Let's now see how a Sysmon event ID 7 looks like.

<img width="2124" height="588" alt="image" src="https://github.com/user-attachments/assets/4d944b07-bb15-4f58-806b-e2bc253961cc" />

Sysmon log entry: Image loaded, ProcessID 8060, Image mmc.exe, ImageLoaded psapi.dll, Signed true, User DESKTOP-N33HELB\Waldo.

The event log contains the DLL's signing status (in this case, it is Microsoft-signed), the process or image responsible for loading the DLL, and the specific DLL that was loaded. In our example, we observe that "MMC.exe" loaded "psapi.dll", which is also Microsoft-signed. Both files are located in the System32 directory.

Now, let's proceed with building a detection mechanism. To gain more insights into DLL hijacks, conducting research is paramount. We can focus on a specific hijack involving the vulnerable executable **`calc.exe`** and a list of DLLs that can be hijacked.

<img width="1000" height="550" alt="image" src="https://github.com/user-attachments/assets/f3448679-5d7d-47be-8b57-2e46591b1615" />

Table showing **calc.exe** with associated DLLs: CRYPTBASE.DLL, **edputil.dll**, **MLANG.dll**, **PROPSYS.dll**, **Secur32.dll**, **SSPICLI.DLL**, **WININET.dll**, and their functions.

Let's attempt the hijack using **`calc.exe`** and **`WININET.dll`** as an example. To simplify the process, we can utilize Stephen Fewer's "hello world" reflective DLL.

> ⚠️ **ATTACK VECTOR**: By placing a malicious **`WININET.dll`** in the same folder as **`calc.exe`**, the Calculator will load our DLL instead of the legitimate System32 DLL!

By following the required steps, which involve renaming reflective_dll.x64.dll to **WININET.dll**, moving **calc.exe** from C:\Windows\System32 along with **WININET.dll** to a writable directory (such as the Desktop folder), and executing **calc.exe**, we achieve success. Instead of the Calculator application, a MessageBox is displayed.

<img width="1008" height="592" alt="image" src="https://github.com/user-attachments/assets/dd56f9ae-f50f-41e5-bbde-226bbbf9c54d" />

Command prompt running **calc.exe**, desktop showing **WININET.dll** and calc icons, with a popup message 'Hello from DllMain!' indicating Reflective DLL Injection.

Next, we analyze the impact of the hijack. First, we filter the event logs to focus on Event ID 7, which represents module load events.

<img width="1090" height="1106" alt="image" src="https://github.com/user-attachments/assets/f343e949-4de6-483e-a73e-671d916e4401" />

Filter Current Log window with options for event level, event logs set to Microsoft-Windows-Sysmon/Operational, and Event ID 7.

Subsequently, we search for instances of **calc.exe**, by clicking "Find...", to identify the DLL load associated with our hijack.

<img width="2136" height="836" alt="image" src="https://github.com/user-attachments/assets/7407070a-3eff-44d2-bf68-9d252351767a" />

Sysmon log entry: Image loaded, ProcessID 6212, Image **calc.exe**, ImageLoaded **WININET.dll**, **Signed false**, User DESKTOP-N33HELB\Waldo. Find dialog open for 'calc.exe'.

The output from Sysmon provides valuable insights. Now, we can observe several indicators of compromise (IOCs) to create effective detection rules.

Let's explore these IOCs:

> 🔴 **KEY IOCs for DLL Hijack Detection:**

| IOC | Description | Why It's Suspicious |
|-----|-------------|---------------------|
| **`calc.exe`** in writable directory | Should only be in System32 | Legitimate calc.exe never runs from Desktop/Downloads |
| **`WININET.dll`** loaded outside System32 | Should load from C:\Windows\System32 | Indicates hijacked DLL loading |
| **Unsigned DLL** | Signed=false | Malicious DLLs typically unsigned |

- **`calc.exe`** originally located in System32, should not be found in a writable directory. Therefore, a copy of **`calc.exe`** in a writable directory serves as an IOC.
- **`WININET.dll`** originally located in System32, should not be loaded outside of System32 by calc.exe. If instances of **`WININET.dll`** loading occur outside of System32 with **`calc.exe`** as the parent process, it indicates a DLL hijack.
- The original **`WININET.dll`** is Microsoft-signed, while our injected DLL remains **unsigned**.

> 📌 **DETECTION TIP**: These three powerful IOCs provide an effective means of detecting a DLL hijack involving **`calc.exe`**!

### Detection Example 2: Detecting Unmanaged PowerShell/C-Sharp Injection

Before delving into detection techniques, let's gain a brief understanding of C# and its runtime environment. C# is considered a "managed" language, meaning it requires a backend runtime to execute its code. The Common Language Runtime (CLR) serves as this runtime environment. Managed code does not directly run as assembly; instead, it is compiled into a bytecode format that the runtime processes and executes. Consequently, a managed process relies on the CLR to execute C# code.

As defenders, we can leverage this knowledge to detect unusual C# injections or executions within our environment.

By using Process Hacker, we can observe a range of processes within our environment. Sorting the processes by name, we can identify interesting color-coded distinctions. Notably, "powershell.exe", a managed process, is highlighted in green compared to other processes.

<img width="1000" height="899" alt="image" src="https://github.com/user-attachments/assets/da514956-d962-40e4-b9b4-e9eb6d47ac5b" />

Task Manager showing processes like Microsoft.Photos.exe, msedge.exe, powershell.exe, ProcessHacker.exe, with CPU and memory usage details.

Hovering over powershell.exe reveals the label "Process is managed (.NET)," confirming its managed status.

<img width="1000" height="386" alt="image" src="https://github.com/user-attachments/assets/9a726a4b-ac33-4202-ab64-d08d94be8ecb" />

Task Manager tooltip for powershell.exe, showing file path, version 10.0.19041.546, signed by Microsoft, console host conhost.exe (5092).

Examining the module loads for powershell.exe, by right-clicking on powershell.exe, clicking "Properties", and navigating to "Modules", we can find relevant information.

<img width="1000" height="63" alt="image" src="https://github.com/user-attachments/assets/eec3231e-e49f-4e3a-8623-567efffa13fe" />

Image showing clr.dll and drjit.dll with memory addresses, sizes, and descriptions for Microsoft .NET Runtime components.

The presence of "Microsoft .NET Runtime...", clr.dll, and clrjit.dll should attract our attention. These 2 DLLs are used when C# code is ran as part of the runtime to execute the bytecode. If we observe these DLLs loaded in processes that typically do not require them, it suggests a potential execute-assembly or unmanaged PowerShell injection attack.

To showcase unmanaged PowerShell injection, we can inject an unmanaged PowerShell-like DLL into a random process, such as spoolsv.exe:

```powershell
powershell -ep bypass
Import-Module .\Invoke-PSInject.ps1
Invoke-PSInject -ProcId [Process ID of spoolsv.exe] -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

<img width="904" height="390" alt="image" src="https://github.com/user-attachments/assets/0009baf8-89b7-41a6-a0d7-b4cd112fc7a8" />

Tooltip for spoolsv.exe showing file path, version 10.0.19041.1288, signed by Microsoft, and associated with Print Spooler service.

After the injection, we observe that "spoolsv.exe" transitions from an unmanaged to a managed state.

<img width="742" height="416" alt="image" src="https://github.com/user-attachments/assets/f1d6b57f-2c53-4613-b483-cc3f781b1e0f" />

Tooltip for spoolsv.exe showing file path, version 10.0.19041.1288, signed by Microsoft, associated with Print Spooler service, and managed by .NET.

Additionally, by referring to both the related "Modules" tab of Process Hacker and Sysmon Event ID 7, we can examine the DLL load information to validate the presence of the aforementioned DLLs.

<img width="1000" height="617" alt="image" src="https://github.com/user-attachments/assets/a8bc74db-25ed-46e3-9dde-78e6b18fe377" />

Sysmon Event 7: Image loaded, ProcessID 2792, Image spoolsv.exe, ImageLoaded clr.dll, Microsoft .NET Runtime, signed by Microsoft, User NT AUTHORITY\SYSTEM.

### Detection Example 3: Detecting Credential Dumping

Another critical aspect of cybersecurity is detecting credential dumping activities. One widely used tool for credential dumping is **Mimikatz**, offering various methods for extracting Windows credentials. One specific command, **`sekurlsa::logonpasswords`**, enables the dumping of password hashes or plaintext passwords by accessing the **LSASS** (Local Security Authority Subsystem Service). LSASS is responsible for managing user credentials and is a primary target for credential-dumping tools like Mimikatz.

> ⚠️ **WARNING**: Mimikatz is a powerful post-exploitation tool used by both red teams and real attackers. Understanding how it works is essential for blue team defenders.

The attack can be executed as follows:

```
C:\Tools\Mimikatz> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug          <-- Enables SeDebugPrivilege
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords   <-- Dumps credentials from LSASS

Authentication Id : 0 ; 1128191 (00000000:001136ff)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : DESKTOP-NU10MTO
Logon Server      : DESKTOP-NU10MTO
Logon Time        : 5/31/2023 4:14:41 PM
SID               : S-1-5-21-2712802632-2324259492-1677155984-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX        <-- NTLM HASH
         * SHA1     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX0812156b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        ssp :   KO
        credman :
```

> 🔴 **CRITICAL**: The output reveals **NTLM hashes**, **Kerberos tickets**, and **plaintext passwords** (if available). This is a major security breach!

As we can see, the output of the "sekurlsa::logonpasswords" command provides powerful insights into compromised credentials.

### How to Detect Mimikatz Activity

To detect this activity, we can rely on a different Sysmon event. Instead of focusing on DLL loads, we shift our attention to process access events. By checking **Sysmon Event ID 10** ("ProcessAccess"), we can identify any suspicious attempts to access LSASS.

> 📌 **KEY DETECTION**: Sysmon Event ID 10 is your best friend for detecting credential dumping!

<img width="1000" height="271" alt="image" src="https://github.com/user-attachments/assets/34ce1b68-e298-4a74-9654-db55143ba6c6" />

<img width="1000" height="397" alt="image" src="https://github.com/user-attachments/assets/ffac5cd8-2923-4d9a-ae18-22f91e4c14a3" />

### 🚨 Indicators of Compromise (IOCs)

For instance, if we observe a random file ("AgentEXE" in this case) from a random folder ("Downloads" in this case) attempting to access LSASS, it indicates unusual behavior.

| IOC | Description |
|-----|-------------|
| **SourceImage** | Process accessing LSASS (e.g., AgentEXE.exe from Downloads) |
| **TargetImage** | Should be lsass.exe |
| **SourceUser** vs **TargetUser** | Different users indicate privilege escalation |
| **SeDebugPrivilege** | Required for LSASS access - another detection opportunity |

Additionally, the SourceUser being different from the TargetUser (e.g., "waldo" as the SourceUser and "SYSTEM" as the TargetUser) further emphasizes the abnormality.

> 🔑 **PRIVILEGE CHECK**: As part of the mimikatz-based credential dumping process, the user must request **SeDebugPrivilege**. This can be another Indicator of Compromise (IOC)!

### ⚠️ Important Note

Please note that some legitimate processes may access LSASS, such as authentication-related processes or security tools like AV or EDR. You'll need to create allowlists for known good processes to reduce false positives.

### Detection Query Example

```powershell
# Sysmon Event ID 10 - Look for LSASS access
EventID=10 TargetImage="*lsass.exe"
```

Filter for:
- Source processes from unexpected locations
- Unusual SourceUser accessing SYSTEM processes
- Processes that don't normally need LSASS access

---

## 3. Interview Questions

### Q1: What is Sysmon and why is it important for security monitoring?

**Answer:** Sysmon (System Monitor) is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creation, network connections, changes to file creation time, and more that typically doesn't appear in Security Event logs.

---

### Q2: What is the difference between Windows Event ID 4688 and Sysmon Event ID 1?

**Answer:**

| Feature | Windows 4688 | Sysmon Event 1 |
|---------|-------------|----------------|
| Command Line | May be empty | Always captured |
| Parent Command Line | Not captured | Captured |
| Hash | Not captured | SHA256, MD5, IMPHASH |
| Configurable | Limited | Extensive |

---

### Q3: How do you detect DLL hijacking using Sysmon?

**Answer:**

1. Enable Sysmon Event ID 7 (Image Load)
2. Look for DLLs loaded from unexpected locations
3. Check for unsigned DLLs loading into legitimate processes
4. Monitor for processes loading DLLs from user-writable directories

**IOCs to watch:**
- calc.exe running from Desktop instead of System32
- WININET.dll loaded from user directory
- Unsigned DLLs loading into signed processes

---

### Q4: How can you detect unmanaged PowerShell injection?

**Answer:**

Monitor for:
- **clr.dll** loading in processes that shouldn't run .NET (like spoolsv.exe)
- **clrjit.dll** in unusual processes
- Any non-PowerShell processes becoming "managed" (.NET processes)

These DLLs indicate .NET runtime loading in processes that don't typically use it.

---

### Q5: What Sysmon event ID is used to detect credential dumping?

**Answer:** Sysmon Event ID 10 - ProcessAccess

This event logs when one process accesses another, particularly important for detecting attempts to access lsass.exe (where credentials are stored).

---

### Q6: What are the indicators of credential dumping via LSASS access?

**Answer:**
- Sysmon Event 10 showing access to lsass.exe
- Source process from unusual location (e.g., Downloads folder)
- SourceUser different from TargetUser (e.g., user accessing SYSTEM process)
- Request for SeDebugPrivilege

---

### Q7: What is the difference between managed and unmanaged code?

**Answer:**

- **Managed Code**: Requires .NET Runtime (CLR) to execute - compiled to bytecode (C#, VB.NET, F#)
- **Unmanaged Code**: Runs directly as native assembly (C, C++, Delphi)

**Detection**: Look for clr.dll and clrjit.dll loading in processes that shouldn't have .NET.

---

### Q8: How do you configure Sysmon?

**Answer:**

```cmd
# Install Sysmon
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

# Apply configuration
sysmon.exe -c config.xml
```

Configuration files are XML-based and can be obtained from:
- SwiftOnSecurity/sysmon-config (comprehensive)
- olafhartong/sysmon-modular (modular)

---

### Q9: What Windows Event ID shows when the security log is cleared?

**Answer:** Event ID 1102 - The audit log was cleared

This is a critical indicator - attackers often clear logs to hide their tracks.

---

### Q10: How do you detect lateral movement via RDP in event logs?

**Answer:**

Look for:
- Event 4624 with LogonType=10 (RemoteInteractive)
- Source Network Address from external IP
- Service accounts doing RDP (should never happen)

---

## 4. Additional Resources

### Tools

- [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Swift On Security Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [Event Log Explorer](https://eventlogxp.com/)

### References

- [Microsoft Security Event ID Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/audit/security-auditing)
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK - T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [DLL Hijacking Techniques](https://blog.checkpoint.com/)

### Communities

- r/dfir (Reddit)
- r/sysadmin (Reddit)
- SANS Digital Forensics

---

*Module 3/15 - Windows Event Logs & Finding Evil*
*Built with research + HTB Academy materials*









































HTB Academy Logo
Windows Event Logs & Finding Evil
Windows Event Logs & Finding Evil 100%

Section 3 / 6
Event Tracing for Windows (ETW)

> 📌 **WHY ETW MATTERS**: ETW provides **high-performance, real-time telemetry** that goes far beyond traditional Windows Event Logs. Essential for modern blue team operations!

In the realm of effective threat detection and incident response, we often find ourselves relying on the limited log data at our disposal. However, this approach falls short of fully harnessing the immense wealth of information that can be derived from the powerful resource known as Event Tracing for Windows (ETW).

### What is ETW?

According to Microsoft, Event Tracing For Windows (ETW) is a general-purpose, high-speed tracing facility provided by the operating system. Using a buffering and logging mechanism implemented in the kernel, ETW provides a tracing mechanism for events raised by both user-mode applications and kernel-mode device drivers.

ETW, functioning as a high-performance event tracing mechanism deeply embedded within the Windows operating system, presents an unparalleled opportunity to bolster our defense capabilities. Its architecture facilitates the dynamic generation, collection, and analysis of various events occurring within the system, resulting in the creation of intricate, real-time logs that encompass a wide spectrum of activities.

By effectively leveraging ETW, we can tap into an expansive array of telemetry sources that surpass the limitations imposed by traditional log data. ETW captures a diverse set of events:
- System calls
- Process creation and termination
- Network activity
- File and registry modifications
- And numerous other dimensions

> 🔴 **KEY BENEFIT**: ETW provides **1,000+ built-in providers** in Windows 10, giving visibility that traditional logs cannot match!

ETW's versatility and extensibility are further accentuated by its seamless integration with Event Providers. These specialized components generate specific types of events and can be seamlessly incorporated into applications, operating system components, or third-party software. Consequently, this integration ensures a broad coverage of potential event sources. Furthermore, ETW's extensibility enables the creation of custom providers tailored to address specific organizational requirements, thereby fostering a targeted and focused approach to logging and monitoring.

Notably, ETW's lightweight nature and minimal performance impact render it an optimal telemetry solution for real-time monitoring and continuous security assessment. 

> 📌 **KEY POINT**: By selectively enabling and configuring relevant event providers, we can finely adjust the scope of data collection to align with our specific security objectives!

### ETW Architecture & Components

The underlying architecture and the key components of Event Tracing for Windows (ETW) are illustrated in the following diagram from Microsoft.

<img width="477" height="480" alt="image" src="https://github.com/user-attachments/assets/914b468c-7850-4664-97d7-a352200780ca" />

Diagram of Event Tracing for Windows (ETW) showing data flow from Providers A, B, and C to Sessions in ETW, controlled by a Controller, with events logged to Trace Files and delivered to a Consumer.

| Component | Description |
|-----------|-------------|
| **Controllers** | Manages ETW operations - start/stop sessions, enable/disable providers (e.g., `logman.exe`) |
| **Providers** | Generate events and write them to ETW sessions (4 types: MOF, WPP, Manifest-based, TraceLogging) |
| **Consumers** | Subscribe to events and receive them for analysis |
| **Channels** | Logical containers for organizing events |
| **ETL Files** | Event Trace Log files for storage and offline analysis |

> ⚠️ **NOTE**: Some event providers generate a significant volume of events. They are typically **disabled by default** and only enabled when a tracing session specifically requests them.

    ETW supports event providers in both kernel mode and user mode.
    Some event providers generate a significant volume of events, which can potentially overwhelm the system resources if they are constantly active. As a result, to prevent unnecessary resource consumption, these providers are typically disabled by default and are only enabled when a tracing session specifically requests their activation.
    In addition to its inherent capabilities, ETW can be extended through custom event providers.
    Only ETW provider events that have a Channel property applied to them can be consumed by the event log

### Interacting With ETW

> 📌 **KEY COMMANDS**: **Logman** is a pre-installed utility for managing Event Tracing for Windows (ETW) and Event Tracing Sessions.

```cmd
# Query all active ETW sessions
C:\Tools> logman.exe query -ets
```

This shows all active ETW sessions including **Sysmon Event Tracing Sessions**.

        cmd-session
C:\Tools> logman.exe query -ets

```
Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
Circular Kernel Context Logger          Trace                         Running
Eventlog-Security                       Trace                         Running
EventLog-Microsoft-Windows-Sysmon-Operational Trace                         Running
SYSMON TRACE                            Trace                         Running
SysmonDnsEtwSession                     Trace                         Running
...
```

> 🔑 **IMPORTANT**: The **"-ets"** parameter is vital to the command. Without it, Logman will not identify the Event Tracing Session!

### Key Commands

```cmd
# Query specific session details
logman.exe query "EventLog-System" -ets

# List all available providers
logman.exe query providers

# Query specific provider (e.g., Winlogon)
logman.exe query providers Microsoft-Windows-Winlogon
```

### Important ETW Providers for Security

| Provider | Purpose |
|----------|---------|
| **Microsoft-Windows-Winlogon** | Logon/logoff events |
| **Microsoft-Windows-Sysmon** | Process, network, file events |
| **Microsoft-Antimalware-*** | Windows Defender events |
| **Microsoft-Windows-PowerShell** | PowerShell script execution |
| **Microsoft-Windows-Kernel-*** | Kernel-level events |
| **Local Security Authority (LSA)** | Authentication events |

> 💡 **TAKEAWAY**: ETW provides **1,000+ built-in providers** in Windows 10!

### Querying ETW Sessions

```cmd
# Query specific session details
logman.exe query "EventLog-System" -ets
```

This shows session info including providers:

```
Name:                 EventLog-System
Status:               Running
Buffer Size:          64
File Mode:            Real-time

Provider:
Name:                 Microsoft-Windows-FunctionDiscoveryHost
Provider Guid:        {538CBBAD-4877-4EB2-B26E-7CAEE8F0F8CB}
KeywordsAny:          0x8000000000000000 (System)
```

### Key Provider Types

| Type | Description |
|------|-------------|
| **MOF Providers** | Based on Managed Object Format schemas |
| **WPP Providers** | Windows Software Trace Preprocessor |
| **Manifest-based** | Modern XML manifest-based |
| **TraceLogging** | Simplified event generation API |

### ETW vs Traditional Logs

| Feature | Traditional Event Logs | ETW |
|---------|------------------------|-----|
| **Providers** | ~5 main logs | 1,000+ providers |
| **Performance** | Low overhead | Minimal impact |
| **Real-time** | Limited | Native real-time |
| **Customization** | Limited | Highly customizable |

> 🔑 **TAKEAWAY**: Use ETW for deep forensics, traditional logs for baseline monitoring!

        cmd-session
C:\Tools> logman.exe query providers

Provider                                 GUID
-------------------------------------------------------------------------------
ACPI Driver Trace Provider               {DAB01D4D-2D48-477D-B1C3-DAAD0CE6F06B}
Active Directory Domain Services: SAM    {8E598056-8993-11D2-819E-0000F875A064}
Active Directory: Kerberos Client        {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Active Directory: NetLogon               {F33959B4-DBEC-11D2-895B-00C04F79AB69}
ADODB.1                                  {04C8A86F-3369-12F8-4769-24E484A9E725}
ADOMD.1                                  {7EA56435-3F2F-3F63-A829-F0B35B5CAD41}
Application Popup                        {47BFA2B7-BD54-4FAC-B70B-29021084CA8F}
Application-Addon-Event-Provider         {A83FA99F-C356-4DED-9FD6-5A5EB8546D68}
ATA Port Driver Tracing Provider         {D08BD885-501E-489A-BAC6-B7D24BFE6BBF}
AuthFw NetShell Plugin                   {935F4AE6-845D-41C6-97FA-380DAD429B72}
BCP.1                                    {24722B88-DF97-4FF6-E395-DB533AC42A1E}
BFE Trace Provider                       {106B464A-8043-46B1-8CB8-E92A0CD7A560}
BITS Service Trace                       {4A8AAA94-CFC4-46A7-8E4E-17BC45608F0A}
Certificate Services Client CredentialRoaming Trace {EF4109DC-68FC-45AF-B329-CA2825437209}
Certificate Services Client Trace        {F01B7774-7ED7-401E-8088-B576793D7841}
Circular Kernel Session Provider         {54DEA73A-ED1F-42A4-AF71-3E63D056F174}
Classpnp Driver Tracing Provider         {FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}
Critical Section Trace Provider          {3AC66736-CC59-4CFF-8115-8DF50E39816B}
DBNETLIB.1                               {BD568F20-FCCD-B948-054E-DB3421115D61}
Deduplication Tracing Provider           {5EBB59D1-4739-4E45-872D-B8703956D84B}
Disk Class Driver Tracing Provider       {945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}
Downlevel IPsec API                      {94335EB3-79EA-44D5-8EA9-306F49B3A041}
Downlevel IPsec NetShell Plugin          {E4FF10D8-8A88-4FC6-82C8-8C23E9462FE5}
Downlevel IPsec Policy Store             {94335EB3-79EA-44D5-8EA9-306F49B3A070}
Downlevel IPsec Service                  {94335EB3-79EA-44D5-8EA9-306F49B3A040}
EA IME API                               {E2A24A32-00DC-4025-9689-C108C01991C5}
Error Instrument                         {CD7CF0D0-02CC-4872-9B65-0DBA0A90EFE8}
FD Core Trace                            {480217A9-F824-4BD4-BBE8-F371CAAF9A0D}
FD Publication Trace                     {649E3596-2620-4D58-A01F-17AEFE8185DB}
FD SSDP Trace                            {DB1D0418-105A-4C77-9A25-8F96A19716A4}
FD WNet Trace                            {8B20D3E4-581F-4A27-8109-DF01643A7A93}
FD WSDAPI Trace                          {7E2DBFC7-41E8-4987-BCA7-76CADFAD765F}
FDPHost Service Trace                    {F1C521CA-DA82-4D79-9EE4-D7A375723B68}
File Kernel Trace; Operation Set 1       {D75D8303-6C21-4BDE-9C98-ECC6320F9291}
File Kernel Trace; Operation Set 2       {058DD951-7604-414D-A5D6-A56D35367A46}
File Kernel Trace; Optional Data         {7DA1385C-F8F5-414D-B9D0-02FCA090F1EC}
File Kernel Trace; Volume To Log         {127D46AF-4AD3-489F-9165-F00BA64D5467}
FWPKCLNT Trace Provider                  {AD33FA19-F2D2-46D1-8F4C-E3C3087E45AD}
FWPUCLNT Trace Provider                  {5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}
Heap Trace Provider                      {222962AB-6180-4B88-A825-346B75F2A24A}
IKEEXT Trace Provider                    {106B464D-8043-46B1-8CB8-E92A0CD7A560}
IMAPI1 Shim                              {1FF10429-99AE-45BB-8A67-C9E945B9FB6C}
IMAPI2 Concatenate Stream                {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9D}
IMAPI2 Disc Master                       {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E91}
IMAPI2 Disc Recorder                     {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E93}
IMAPI2 Disc Recorder Enumerator          {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E92}
IMAPI2 dll                               {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E90}
IMAPI2 Interleave Stream                 {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9E}
IMAPI2 Media Eraser                      {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E97}
IMAPI2 MSF                               {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9F}
IMAPI2 Multisession Sequential           {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7EA0}
IMAPI2 Pseudo-Random Stream              {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9C}
IMAPI2 Raw CD Writer                     {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9A}
IMAPI2 Raw Image Writer                  {07E397EC-C240-4ED7-8A2A-B9FF0FE5D581}
IMAPI2 Standard Data Writer              {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E98}
IMAPI2 Track-at-Once CD Writer           {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E99}
IMAPI2 Utilities                         {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E94}
IMAPI2 Write Engine                      {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E96}
IMAPI2 Zero Stream                       {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9B}
IMAPI2FS Tracing                         {F8036571-42D9-480A-BABB-DE7833CB059C}
Intel-iaLPSS-GPIO                        {D386CC7A-620A-41C1-ABF5-55018C6C699A}
Intel-iaLPSS-I2C                         {D4AEAC44-AD44-456E-9C90-33F8CDCED6AF}
Intel-iaLPSS2-GPIO2                      {63848CFF-3EC7-4DDF-8072-5F95E8C8EB98}
Intel-iaLPSS2-I2C                        {C2F86198-03CA-4771-8D4C-CE6E15CBCA56}
IPMI Driver Trace                        {D5C6A3E9-FA9C-434E-9653-165B4FC869E4}
IPMI Provider Trace                      {651D672B-E11F-41B7-ADD3-C2F6A4023672}
KMDFv1 Trace Provider                    {544D4C9D-942C-46D5-BF50-DF5CD9524A50}
Layer2 Security HC Diagnostics Trace     {2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65}
Local Security Authority (LSA)           {CC85922F-DB41-11D2-9244-006008269001}
LsaSrv                                   {199FE037-2B82-40A9-82AC-E1D46C792B99}
Microsoft-Antimalware-AMFilter           {CFEB0608-330E-4410-B00D-56D8DA9986E6}
Microsoft-Antimalware-Engine             {0A002690-3839-4E3A-B3B6-96D8DF868D99}
Microsoft-Antimalware-Engine-Instrumentation {68621C25-DF8D-4A6B-AABC-19A22E296A7C}
Microsoft-Antimalware-NIS                {102AAB0A-9D9C-4887-A860-55DE33B96595}
Microsoft-Antimalware-Protection         {E4B70372-261F-4C54-8FA6-A5A7914D73DA}
Microsoft-Antimalware-RTP                {8E92DEEF-5E17-413B-B927-59B2F06A3CFC}
Microsoft-Antimalware-Scan-Interface     {2A576B87-09A7-520E-C21A-4942F0271D67}
Microsoft-Antimalware-Service            {751EF305-6C6E-4FED-B847-02EF79D26AEF}
Microsoft-Antimalware-ShieldProvider     {928F7D29-0577-5BE5-3BD3-B6BDAB9AB307}
Microsoft-Antimalware-UacScan            {D37E7910-79C8-57C4-DA77-52BB646364CD}
Microsoft-AppV-Client                    {E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}
Microsoft-AppV-Client-StreamingUX        {28CB46C7-4003-4E50-8BD9-442086762D12}
Microsoft-AppV-ServiceLog                {9CC69D1C-7917-4ACD-8066-6BF8B63E551B}
Microsoft-AppV-SharedPerformance         {FB4A19EE-EB5A-47A4-BC52-E71AAC6D0859}
Microsoft-Client-Licensing-Platform      {B6CC0D55-9ECC-49A8-B929-2B9022426F2A}
Microsoft-Gaming-Services                {BC1BDB57-71A2-581A-147B-E0B49474A2D4}
Microsoft-IE                             {9E3B3947-CA5D-4614-91A2-7B624E0E7244}
Microsoft-IE-JSDumpHeap                  {7F8E35CA-68E8-41B9-86FE-D6ADC5B327E7}
Microsoft-IEFRAME                        {5C8BB950-959E-4309-8908-67961A1205D5}
Microsoft-JScript                        {57277741-3638-4A4B-BDBA-0AC6E45DA56C}
Microsoft-OneCore-OnlineSetup            {41862974-DA3B-4F0B-97D5-BB29FBB9B71E}
Microsoft-PerfTrack-IEFRAME              {B2A40F1F-A05A-4DFD-886A-4C4F18C4334C}
Microsoft-PerfTrack-MSHTML               {FFDB9886-80F3-4540-AA8B-B85192217DDF}
Microsoft-User Experience Virtualization-Admin {61BC445E-7A8D-420E-AB36-9C7143881B98}
Microsoft-User Experience Virtualization-Agent Driver {DE29CF61-5EE6-43FF-9AAC-959C4E13CC6C}
Microsoft-User Experience Virtualization-App Agent {1ED6976A-4171-4764-B415-7EA08BC46C51}
Microsoft-User Experience Virtualization-IPC {21D79DB0-8E03-41CD-9589-F3EF7001A92A}
Microsoft-User Experience Virtualization-SQM Uploader {57003E21-269B-4BDC-8434-B3BF8D57D2D5}
Microsoft-Windows Networking VPN Plugin Platform {E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}
Microsoft-Windows-AAD                    {4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}
Microsoft-Windows-ACL-UI                 {EA4CC8B8-A150-47A3-AFB9-C8D194B19452}

> 🔴 **FACT**: Windows 10 includes **more than 1,000 built-in providers**! Third-party software also adds ETW providers.

> 📌 **TIP**: Filter providers using `findstr`:

```cmd
C:\Tools> logman.exe query providers | findstr "Winlogon"
```

Output:
```
Microsoft-Windows-Winlogon               {DBE9B383-7CF3-4331-91CC-A3CB16A3B538}
Windows Winlogon Trace                   {D451642C-63A6-11D7-9720-00B0D03E0347}
```

### Querying Provider Details

```cmd
C:\Tools> logman.exe query providers Microsoft-Windows-Winlogon
```

This shows keywords, levels, and PIDs:

| Keyword | Description |
|---------|-------------|
| 0x4000000000000000 | Microsoft-Windows-Winlogon/Operational |
| 0x8000000000000000 | Microsoft-Windows-Winlogon/Diagnostic |
| 0x2000000000000000 | System |

| Level | Description |
|-------|-------------|
| 0x02 | Error |
| 0x03 | Warning |
| 0x04 | Informational |


The command completed successfully.

The Microsoft-Windows-Winlogon/Diagnostic and Microsoft-Windows-Winlogon/Operational keywords reference the event logs generated from this provider.

GUI-based alternatives also exist. These are:

    Using the graphical interface of the Performance Monitor tool, we can visualize various running trace sessions. A detailed overview of a specific trace can be accessed simply by double-clicking on it. This reveals all pertinent data related to the trace, from the engaged providers and their activated features to the nature of the trace itself. Additionally, these sessions can be modified to suit our needs by incorporating or eliminating providers. Lastly, we can devise new sessions by opting for the "User Defined" category.

<img width="1473" height="1745" alt="image" src="https://github.com/user-attachments/assets/3eff7a78-b522-4092-a118-4de89edf4a0f" />

    
    Windows desktop showing Command Prompt with performance tracking context details and Performance Monitor app search result.

<img width="1599" height="1121" alt="image" src="https://github.com/user-attachments/assets/b102b1fb-5373-43c6-a32a-ab487683ccc8" />


    Performance Monitor window displaying a list of running Event Trace Sessions.

    
    ETW Provider metadata can also be viewed through the EtwExplorer project.

    <img width="1000" height="585" alt="image" src="https://github.com/user-attachments/assets/f9f73d23-52fe-409b-9057-46f59c8a852d" />

    ETW Explorer window showing search results for 'PowerShell' with two providers listed, including GUIDs.

> 🔧 **TOOL**: Use **ETW Explorer** or **PerfMon** to explore providers visually!

### Useful ETW Providers for Security

> 📌 **MUST-KNOW PROVIDERS** for SOC Analysts:

| Provider | Purpose |
|----------|---------|
| **Microsoft-Windows-Kernel-Process** | Process injection, hollowing detection |
| **Microsoft-Windows-Kernel-File** | File access, ransomware activity |
| **Microsoft-Windows-Kernel-Network** | Network C2, exfiltration detection |
| **Microsoft-Windows-Kernel-Registry** | Persistence via registry keys |
| **Microsoft-Windows-SMBClient/SMBServer** | Lateral movement detection |
| **Microsoft-Windows-DotNETRuntime** | .NET exploitation detection |
| **Microsoft-Windows-PowerShell** | PowerShell script execution |
| **Microsoft-Antimalware-Service** | AV detection/evasion monitoring |
| **Microsoft-Windows-DNS-Client** | DNS tunneling, C2 detection |
| **Microsoft-Windows-Security-Mitigations** | Security control bypass detection |

> 🔐 **RESTRICTED PROVIDERS**: Some providers like **Microsoft-Windows-Threat-Intelligence** require **Protected Process Light (PPL)** status - only available to privileged security tools!

In the context of Microsoft-Windows-Threat-Intelligence, the benefits of this privileged access are manifold. This provider can record highly granular data about potential threats, enabling security professionals to detect and analyze sophisticated attacks that may have eluded other defenses. Its telemetry can serve as vital evidence in forensic investigations, revealing details about the origin of a threat, the systems and data it interacted with, and the alterations it made. Moreover, by monitoring this provider in real-time, security teams can potentially identify ongoing threats and intervene to mitigate damage.

In the next section, we will utilize ETW to investigate attacks that may evade detection if we rely solely on Sysmon for monitoring and analysis, due to its inherent limitations in capturing certain events.
References

    https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf
    https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw

3 / 6 Sections
adblock modal image




