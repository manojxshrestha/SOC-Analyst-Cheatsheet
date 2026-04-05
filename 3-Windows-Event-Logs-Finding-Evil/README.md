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
4. [Tapping Into ETW](#4-tapping-into-etw)
5. [Get-WinEvent - Mass Log Analysis](#5-get-winevent---mass-log-analysis)
6. [Interview Questions](#6-interview-questions)
7. [Additional Resources](#7-additional-resources)

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
4. [Tapping Into ETW](#4-tapping-into-etw)
5. [Interview Questions](#5-interview-questions)
6. [Additional Resources](#6-additional-resources)

---

## 1. Windows Event Logging Basics

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

## 3. Event Tracing for Windows (ETW)

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

```cmd
C:\Tools> logman.exe query -ets
```

```
Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
Circular Kernel Context Logger          Trace                         Running
Eventlog-Security                       Trace                         Running
DiagLog                                 Trace                         Running
Diagtrack-Listener                      Trace                         Running
EventLog-Application                    Trace                         Running
EventLog-Microsoft-Windows-Sysmon-Operational Trace                         Running
EventLog-System                         Trace                         Running
LwtNetLog                               Trace                         Running
Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace Trace                         Running
NetCore                                 Trace                         Running
NtfsLog                                 Trace                         Running
RadioMgr                                Trace                         Running
UBPM                                    Trace                         Running
WdiContextLog                           Trace                         Running
WiFiSession                             Trace                         Running
SHS-06012023-115154-7-7f                Trace                         Running
UserNotPresentTraceSession              Trace                         Running
8696EAC4-1288-4288-A4EE-49EE431B0AD9    Trace                         Running
ScreenOnPowerStudyTraceSession          Trace                         Running
SYSMON TRACE                            Trace                         Running
MSDTC_TRACE_SESSION                     Trace                         Running
SysmonDnsEtwSession                     Trace                         Running
MpWppTracing-20230601-115025-00000003-ffffffff Trace                         Running
WindowsUpdate_trace_log                 Trace                         Running
Admin_PS_Provider                       Trace                         Running
Terminal-Services-LSM-ApplicationLag-3764 Trace                         Running
Microsoft.Windows.Remediation           Trace                         Running
SgrmEtwSession                          Trace                         Running
```

> 🔑 **IMPORTANT**: The **"-ets"** parameter is vital to the command. Without it, Logman will not identify the Event Tracing Session!

When we examine an Event Tracing Session directly, we uncover specific session details including the Name, Max Log Size, Log Location, and the subscribed providers.

### Querying Session Details

```cmd
C:\Tools> logman.exe query "EventLog-System" -ets
```

```
Name:                 EventLog-System
Status:               Running
Root Path:            %systemdrive%\PerfLogs\Admin
Segment:              Off
Schedules:            On
Segment Max Size:     100 MB

Name:                 EventLog-System\EventLog-System
Type:                 Trace
Append:               Off
Circular:             Off
Overwrite:            Off
Buffer Size:          64
Buffers Lost:         0
Buffers Written:      47
Buffer Flush Timer:   1
Clock Type:           System
File Mode:            Real-time

Provider:
Name:                 Microsoft-Windows-FunctionDiscoveryHost
Provider Guid:        {538CBBAD-4877-4EB2-B26E-7CAEE8F0F8CB}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-Subsys-SMSS
Provider Guid:        {43E63DA5-41D1-4FBF-ADED-1BBED98FDD1D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x4000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-Kernel-General
Provider Guid:        {A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-FilterManager
Provider Guid:        {F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0
```

> 📌 **KEY INFO**: For each provider, you can get:
> - **Provider GUID**: Exclusive identifier
> - **Level**: Filtering for warning, informational, critical events
> - **Keywords Any**: Filter based on event type

### Listing All Providers

> 🔴 **FACT**: Windows 10 includes **more than 1,000 built-in providers**!

```cmd
C:\Tools> logman.exe query providers
```

```
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
BFE Trace Provider                       {106B464A-8043-46B1-8CB8-E92A0CD7A560}
BITS Service Trace                       {4A8AAA94-CFC4-46A7-8E4E-17BC45608F0A}
Certificate Services Client Trace        {F01B7774-7ED7-401E-8088-B576793D7841}
Circular Kernel Session Provider         {54DEA73A-ED1F-42A4-AF71-3E63D056F174}
Critical Section Trace Provider          {3AC66736-CC59-4CFF-8115-8DF50E39816B}
Disk Class Driver Tracing Provider       {945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}
Layer2 Security HC Diagnostics Trace     {2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65}
Local Security Authority (LSA)           {CC85922F-DB41-11D2-9244-006008269001}
LsaSrv                                   {199FE037-2B82-40A9-82AC-E1D46C792B99}
Microsoft-Antimalware-AMFilter           {CFEB0608-330E-4410-B00D-56D8DA9986E6}
Microsoft-Antimalware-Engine             {0A002690-3839-4E3A-B3B6-96D8DF868D99}
Microsoft-Antimalware-Protection         {E4B70372-261F-4C54-8FA6-A5A7914D73DA}
Microsoft-Antimalware-RTP                {8E92DEEF-5E17-413B-B927-59B2F06A3CFC}
Microsoft-Antimalware-Service            {751EF305-6C6E-4FED-B847-02EF79D26AEF}
Microsoft-Antimalware-ShieldProvider     {928F7D29-0577-5BE5-3BD3-B6BDAB9AB307}
Microsoft-AppV-Client                    {E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}
Microsoft-IE                             {9E3B3947-CA5D-4614-91A2-7B624E0E7244}
Microsoft-IEFRAME                        {5C8BB950-959E-4309-8908-67961A1205D5}
Microsoft-JScript                        {57277741-3638-4A4B-BDBA-0AC6E45DA56C}
Microsoft-Windows-AAD                    {4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}
Microsoft-Windows-ACL-UI                 {EA4CC8B8-A150-47A3-AFB9-C8D194B19452}
...
```

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

```
Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-Winlogon               {DBE9B383-7CF3-4331-91CC-A3CB16A3B538}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x4000000000000000  Microsoft-Windows-Winlogon/Operational
0x8000000000000000  Microsoft-Windows-Winlogon/Diagnostic
0x2000000000000000  System               System

Value               Level                Description
-------------------------------------------------------------------------------
0x02                win:Error            Error
0x03                win:Warning          Warning
0x04                win:Informational    Information
```

> 📌 **NOTE**: The `Microsoft-Windows-Winlogon/Operational` keyword references the event logs generated from this provider.

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

> 📌 **NOTE**: The `Microsoft-Windows-Winlogon/Operational` keyword references the event logs generated from this provider.

### GUI Tools for ETW

> 🔧 **TOOL**: Use **ETW Explorer** or **PerfMon** to explore providers visually!

Using the graphical interface of the Performance Monitor tool, we can visualize various running trace sessions. A detailed overview of a specific trace can be accessed simply by double-clicking on it.

<img width="1473" height="1745" alt="image" src="https://github.com/user-attachments/assets/3eff7a78-b522-4092-a118-4de89edf4a0f" />

Windows desktop showing Command Prompt with performance tracking context details and Performance Monitor app search result.

<img width="1599" height="1121" alt="image" src="https://github.com/user-attachments/assets/b102b1fb-5373-43c6-a32a-ab487683ccc8" />

Performance Monitor window displaying a list of running Event Trace Sessions.

> 📌 **ALTERNATIVE**: ETW Provider metadata can also be viewed through the **EtwExplorer** project.

<img width="1000" height="585" alt="image" src="https://github.com/user-attachments/assets/f9f73d23-52fe-409b-9057-46f59c8a852d" />

ETW Explorer window showing search results for 'PowerShell' with two providers listed, including GUIDs.

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

**Why Microsoft-Windows-Threat-Intelligence matters:**
- Records highly granular data about potential threats
- Vital evidence in forensic investigations
- Reveals details about threat origin, systems affected, and alterations made
- Real-time monitoring can identify ongoing threats

> 💡 **NEXT STEP**: In the next section, we will utilize ETW to investigate attacks that may evade detection if we rely solely on Sysmon!

---


























---

## 4. Tapping Into ETW

> 📌 **WHY THIS MATTERS**: Sysmon can be bypassed! ETW provides deeper visibility that can't be spoofed easily.

In this section, we'll explore how ETW can detect attacks that evade Sysmon.

### Detection Example 1: Detecting Strange Parent-Child Relationships

> 🔴 **KEY CONCEPT**: Abnormal parent-child process relationships are strong indicators of malicious activity!

**Normal behavior**: Certain processes NEVER spawn others. For example:
- `calc.exe` should never spawn `cmd.exe`
- `spoolsv.exe` should only spawn `conhost.exe`, not `whoami.exe`

> 📌 **REFERENCE**: Check [Samir Bousseaden's mind map](https://twitter.com/sbousseaden) for common parent-child relationships!

By utilizing **Process Hacker**, we can explore parent-child relationships within Windows.

<img width="1000" height="936" alt="image" src="https://github.com/user-attachments/assets/163ae53d-45e0-46cc-b184-47a44585244d" />

Process Hacker window displaying a list of running processes with details like PID, CPU, and memory usage.

Analyzing these relationships in standard and custom environments enables us to identify deviations from normal patterns. For example, if we observe the "spoolsv.exe" process creating "whoami.exe" instead of its expected behavior of creating a "conhost", it raises suspicion.

<img width="622" height="86" alt="image" src="https://github.com/user-attachments/assets/71c36933-9c2b-42c0-9d09-38d37f4a87b4" />

Process list showing spoolsv.exe with PID 2792 and conhost.exe with PID 648.

### Parent PID Spoofing Attack

> ⚠️ **ATTACK TECHNIQUE**: Attackers use **Parent PID (PPID) Spoofing** to hide malicious processes!

To showcase a strange parent-child relationship, where "cmd.exe" appears to be created by "spoolsv.exe" with no accompanying arguments, we will utilize an attacking technique called **Parent PID Spoofing**.

```powershell
PS C:\Tools\psgetsystem> powershell -ep bypass
PS C:\Tools\psgetsystem> Import-Module .\psgetsys.ps1 
PS C:\Tools\psgetsystem> [MyProcess]::CreateProcessFromParent([Process ID of spoolsv.exe],"C:\Windows\System32\cmd.exe","")
```

<img width="2566" height="1574" alt="image" src="https://github.com/user-attachments/assets/42fac4a8-0e5c-4f7a-8ffe-7b3742014c91" />

Desktop showing Process Hacker with running processes, Event Viewer with Sysmon logs, and PowerShell executing a command.

> 🔴 **DETECTION BYPASS**: Due to the parent PID spoofing technique we employed, **Sysmon Event 1 incorrectly displays spoolsv.exe as the parent of cmd.exe**. However, it was actually powershell.exe that created cmd.exe!

### ETW Detection: Microsoft-Windows-Kernel-Process

> 📌 **SOLUTION**: Use ETW to get accurate parent process info!

```cmd
# Collect from Kernel-Process provider
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```

<img width="2581" height="1425" alt="image" src="https://github.com/user-attachments/assets/f402bd86-49fd-4167-a071-8cead33acae8" />

Desktop showing Process Hacker with running processes, PowerShell executing commands, and Command Prompt running SilkETW for event tracing.

The ETW data correctly shows **powershell.exe** as the real parent - not spoofed like Sysmon!

<img width="3835" height="1757" alt="image" src="https://github.com/user-attachments/assets/a44eed41-0a92-440d-9fbc-d74f88cf467c" />

Desktop showing Process Hacker with running processes, PowerShell executing commands, and Notepad displaying process details with a search for PID 2508.

> 🔑 **KEY TAKEAWAY**: ETW's kernel-level visibility cannot be easily spoofed by user-mode techniques like PPID spoofing!

---

### Detection Example 2: Detecting Malicious .NET Assembly Loading

> 📌 **CONCEPT**: "Bring Your Own Land" (BYOL) - attackers now use custom .NET assemblies instead of native tools!

**Why BYOL is effective:**
1. Every Windows system has .NET pre-installed
2. .NET assemblies can be loaded directly into memory (no disk artifacts)
3. Rich libraries for HTTP, crypto, IPC make attack tools powerful
4. Bypasses file-based detection

**Example**: Cobalt Strike's `execute-assembly` command executes .NET assemblies in memory!

### Detecting .NET Assembly Loading

> 🔴 **KEY IOCs**: Look for loading of **clr.dll** and **mscoree.dll** in unusual processes!

```powershell
# Execute Seatbelt (legitimate but used by attackers)
PS C:\Tools\GhostPack Compiled Binaries>.\Seatbelt.exe TokenPrivileges

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v1.2.1         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,


====== TokenPrivileges ======

Current Token's Privileges

                     SeIncreaseQuotaPrivilege:  DISABLED
                          SeSecurityPrivilege:  DISABLED
                     SeTakeOwnershipPrivilege:  DISABLED
                        SeLoadDriverPrivilege:  DISABLED
                     SeSystemProfilePrivilege:  DISABLED
                        SeSystemtimePrivilege:  DISABLED
              SeProfileSingleProcessPrivilege:  DISABLED
              SeIncreaseBasePriorityPrivilege:  DISABLED
                    SeCreatePagefilePrivilege:  DISABLED
                            SeBackupPrivilege:  DISABLED
                           SeRestorePrivilege:  DISABLED
                          SeShutdownPrivilege:  DISABLED
                             SeDebugPrivilege:  SE_PRIVILEGE_ENABLED
                 SeSystemEnvironmentPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                    SeRemoteShutdownPrivilege:  DISABLED
                            SeUndockPrivilege:  DISABLED
                      SeManageVolumePrivilege:  DISABLED
                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                      SeCreateGlobalPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
                          SeTimeZonePrivilege:  DISABLED
                SeCreateSymbolicLinkPrivilege:  DISABLED
    SeDelegateSessionUserImpersonatePrivilege:  DISABLED
```

This triggers Sysmon Event ID 7 (Image Load):

<img width="1064" height="813" alt="image" src="https://github.com/user-attachments/assets/319077d3-e2b9-4ece-a97d-5bb8857bcf92" />
<img width="1064" height="782" alt="image" src="https://github.com/user-attachments/assets/3b27a48c-6102-41e4-b3d1-d54fcaee5f28" />

> 📌 **LIMITATION**: Sysmon shows DLL loading but NOT the actual assembly content/behavior!

### ETW Detection: Microsoft-Windows-DotNETRuntime

> 🔑 **DEEPER VISIBILITY**: ETW can reveal what's actually happening inside the .NET assembly!

```cmd
# Collect .NET Runtime events (keywords: JitKeyword, InteropKeyword, LoaderKeyword, NGenKeyword)
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

<img width="3065" height="1729" alt="image" src="https://github.com/user-attachments/assets/b17264e2-014b-4f60-8bc5-7109a71c5ce6" />

> 📌 **KEYWORDS TO MONITOR** (used in SilkETW command `-uk 0x2038`):
| Keyword | What It Tells You | Why It Matters |
|---------|------------------|----------------|
| **JitKeyword** | What methods are being compiled on-the-fly | Reveals actual code execution |
| **InteropKeyword** | When .NET calls Windows APIs (native functions) | Detects system interactions |
| **LoaderKeyword** | Which assemblies are being loaded | Shows what .NET programs are running |
| **NGenKeyword** | Precompiled native images being used | Detects pre-built attack tools |

> 💡 **IN PLAIN ENGLISH**: These keywords let us see what a .NET program is actually DOING - not just that it exists!

The ETW data reveals:
- Assembly name being loaded
- Method names being executed
- Internal behavior that Sysmon cannot see

> 💡 **TAKEAWAY**: ETW provides **execution-level visibility** beyond just DLL loading!

### How to Use Each Keyword

You can combine keywords or use them individually:

```cmd
# Collect ALL .NET events (0x2038 = all four combined)
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json

# Just JitKeyword (0x8) - see what methods are running
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x8 -ot file -p C:\windows\temp\jit.json

# Just LoaderKeyword (0x20) - see what assemblies load
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x20 -ot file -p C:\windows\temp\loader.json

# Combine Jit + Interop (0x10 + 0x8 = 0x18)
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x18 -ot file -p C:\windows\temp\combined.json
```

| Keyword | Hex Value | Use When |
|---------|-----------|----------|
| JitKeyword | 0x8 | You want to see actual code execution |
| InteropKeyword | 0x10 | You want to see Windows API calls |
| LoaderKeyword | 0x20 | You want to see loaded assemblies |
| NGenKeyword | 0x2000 | You suspect precompiled tools |
| All combined | 0x2038 | Full visibility |

### Summary: Sysmon vs ETW

| Aspect | Sysmon | ETW |
|--------|--------|-----|
| **Parent Process** | Can be spoofed (PPID) | Accurate (kernel-level) |
| **.NET Assembly** | Shows DLL loading only | Shows assembly behavior |
| **Configuration** | XML-based config | Provider/keyword filtering |
| **Performance** | Moderate | Lightweight |
| **Visibility** | User-mode | Kernel-level |

---

## 5. Get-WinEvent - Mass Log Analysis

> 📌 **WHY IT MATTERS**: For large organizations generating millions of logs daily, Get-WinEvent is essential for querying Windows Event logs en masse efficiently.

The **Get-WinEvent** cmdlet is an indispensable tool in PowerShell for querying Windows Event logs. It provides the capability to retrieve different types of event logs, including classic Windows event logs (System, Application), and Event Tracing for Windows (ETW) logs.

### Listing Available Logs

```powershell
# List all available logs with properties
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize
```

This shows:
- **LogName**: Name of the log
- **RecordCount**: Number of events in the log
- **IsClassicLog**: Whether it's .evt (true) or .evtx (false) format
- **IsEnabled**: If the log is currently enabled
- **LogMode**: Circular, Retain, or AutoBackup
- **LogType**: Administrative, Analytical, Debug, or Operational

### Listing Event Providers

```powershell
# List all event providers
Get-WinEvent -ListProvider * | Format-Table -AutoSize
```

Providers are the sources of events within the logs.

### Retrieving Events from Specific Logs

```powershell
# Get last 50 events from System log
Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# Get events from WinRM operational log
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# Get oldest events first
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Reading .evtx Files

```powershell
# Read events from exported .evtx file
Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering with FilterHashtable

```powershell
# Filter by Event ID
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# Filter by date range
$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate = (Get-Date -Year 2023 -Month 6 -Day 3).Date
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# Filter from .evtx file
Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering with FilterXml

```powershell
# Filter for specific DLL loading (clr.dll or mscoree.dll)
$Query = @"
<QueryList>
    <Query Id="0">
        <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
        </Select>
    </Query>
</QueryList>
"@
Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
```

### Filtering with FilterXPath

```powershell
# Find Sysinternals tool installation (EULA acceptance)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# Find network connections to suspicious IP
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```

### Getting All Properties

```powershell
# Get all properties of an event
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *

# Filter by encoded commands (-enc)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List
```

> 💡 **TIP**: `Properties[21]` corresponds to the ParentCommandLine field in Sysmon Event ID 1.

---

## 7. Interview Questions

### Q1: What is the difference between Windows Event ID 4688 and Sysmon Event ID 1?

**Answer:**

| Feature | Windows 4688 | Sysmon Event 1 |
|---------|-------------|----------------|
| Command Line | May be empty | Always captured |
| Parent Command Line | Not captured | Captured |
| Hash | Not captured | SHA256, MD5, IMPHASH |
| Configurable | Limited | Extensive |

---

### Q2: How do you detect DLL hijacking using Sysmon?

**Answer:**

1. Enable Sysmon Event ID 7 (Image Load)
2. Look for DLLs loaded from unexpected locations
3. Check for unsigned DLLs loading into legitimate processes
4. Monitor for processes loading DLLs from user-writable directories

---

### Q3: How can you detect unmanaged PowerShell injection?

**Answer:**

Monitor for:
- **clr.dll** loading in processes that shouldn't run .NET
- **clrjit.dll** in unusual processes
- Any non-PowerShell processes becoming "managed" (.NET processes)

---

### Q4: What Sysmon event ID is used to detect credential dumping?

**Answer:** Sysmon Event ID 10 - ProcessAccess

This event logs when one process accesses another, particularly important for detecting attempts to access lsass.exe (where credentials are stored).

---

### Q5: What are the indicators of credential dumping via LSASS access?

**Answer:**
- Sysmon Event 10 showing access to lsass.exe
- Source process from unusual location (e.g., Downloads folder)
- SourceUser different from TargetUser

---

### Q6: What is the difference between managed and unmanaged code?

**Answer:**

- **Managed Code**: Requires .NET Runtime (CLR) to execute - compiled to bytecode (C#, VB.NET)
- **Unmanaged Code**: Runs directly as native assembly (C, C++)

---

### Q7: How do you configure Sysmon?

**Answer:**

```cmd
# Install Sysmon
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

# Apply configuration
sysmon.exe -c config.xml
```

---

### Q8: What Windows Event ID shows when the security log is cleared?

**Answer:** Event ID 1102 - The audit log was cleared

This is a critical indicator - attackers often clear logs to hide their tracks.

---

### Q9: How do you detect lateral movement via RDP in event logs?

**Answer:**

Look for:
- Event 4624 with LogonType=10 (RemoteInteractive)
- Source Network Address from external IP
- Service accounts doing RDP (should never happen)

---

### Q10: What is ETW and how does it differ from traditional Windows Event Logs?

**Answer:**

ETW (Event Tracing for Windows) is a high-performance, real-time tracing facility built into Windows. Unlike traditional event logs, ETW provides:
- 1,000+ built-in providers
- Kernel-level visibility
- Real-time event capture
- Highly customizable filtering

---

### Q11: What is the purpose of the "-ets" parameter in logman?

**Answer:**

The `-ets` parameter tells Logman to query Event Tracing Sessions directly. Without it, Logman will not identify the ETW sessions running on the system.

---

## 7. Additional Resources

### Tools

- [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Swift On Security Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [Event Log Explorer](https://eventlogxp.com/)
- [ETW Explorer](https://github.com/zscore/ETWExplorer)

### References

- [A Primer on Event Tracing for Windows (ETW)](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
- [A Beginner's Guide to ETW](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)
- [Microsoft Security Event ID Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/audit/security-auditing)
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK - T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [DLL Hijacking Techniques](https://blog.checkpoint.com/)

### Communities

- r/dfir (Reddit)
- r/sysadmin (Reddit)
- SANS Digital Forensics
- Blue Team Tools Discord

---

*Module 3/15 - Windows Event Logs & Finding Evil*
*Built with research + HTB Academy materials*












































HTB Academy Logo
Windows Event Logs & Finding Evil
Windows Event Logs & Finding Evil 100%

Section 5 / 6
Go to Questions
Get-WinEvent

Understanding the importance of mass analysis of Windows Event Logs and Sysmon logs is pivotal in the realm of cybersecurity, especially in Incident Response (IR) and threat hunting scenarios. These logs hold invaluable information about the state of your systems, user activities, potential threats, system changes, and troubleshooting information. However, these logs can also be voluminous and unwieldy. For large-scale organizations, it's not uncommon to generate millions of logs each day. Hence, to distill useful information from these logs, we require efficient tools and techniques to analyze these logs en masse.

One of these tools is the Get-WinEvent cmdlet in PowerShell.
Using Get-WinEvent

The Get-WinEvent cmdlet is an indispensable tool in PowerShell for querying Windows Event logs en masse. The cmdlet provides us with the capability to retrieve different types of event logs, including classic Windows event logs like System and Application logs, logs generated by Windows Event Log technology, and Event Tracing for Windows (ETW) logs.

To quickly identify the available logs, we can leverage the -ListLog parameter in conjunction with the Get-WinEvent cmdlet. By specifying * as the parameter value, we retrieve all logs without applying any filtering criteria. This allows us to obtain a comprehensive list of logs and their associated properties. By executing the following command, we can retrieve the list of logs and display essential properties such as LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, and LogType. The | character is a pipe operator. It is used to pass the output of one command (in this case, the Get-WinEvent command) to another command (in this case, the Select-Object command).

        powershell-session
PS C:\Users\Administrator> Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

LogName                                                                                RecordCount IsClassicLog IsEnabled  LogMode        LogType
-------                                                                                ----------- ------------ ---------  -------        -------
Windows PowerShell                                                                            2916         True      True Circular Administrative
System                                                                                        1786         True      True Circular Administrative
Security                                                                                      8968         True      True Circular Administrative
Key Management Service                                                                           0         True      True Circular Administrative
Internet Explorer                                                                                0         True      True Circular Administrative
HardwareEvents                                                                                   0         True      True Circular Administrative
Application                                                                                   2079         True      True Circular Administrative
Windows Networking Vpn Plugin Platform/OperationalVerbose                                                 False     False Circular    Operational
Windows Networking Vpn Plugin Platform/Operational                                                        False     False Circular    Operational
SMSApi                                                                                           0        False      True Circular    Operational
Setup                                                                                           16        False      True Circular    Operational
OpenSSH/Operational                                                                              0        False      True Circular    Operational
OpenSSH/Admin                                                                                    0        False      True Circular Administrative
Network Isolation Operational                                                                             False     False Circular    Operational
Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel                                          0        False      True Circular    Operational
Microsoft-Windows-WWAN-SVC-Events/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-WPD-MTPClassDriver/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-WPD-CompositeClassDriver/Operational                                           0        False      True Circular    Operational
Microsoft-Windows-WPD-ClassInstaller/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-Workplace Join/Admin                                                           0        False      True Circular Administrative
Microsoft-Windows-WorkFolders/WHC                                                                0        False      True Circular    Operational
Microsoft-Windows-WorkFolders/Operational                                                        0        False      True Circular    Operational
Microsoft-Windows-Wordpad/Admin                                                                           False     False Circular    Operational
Microsoft-Windows-WMPNSS-Service/Operational                                                     0        False      True Circular    Operational
Microsoft-Windows-WMI-Activity/Operational                                                     895        False      True Circular    Operational
Microsoft-Windows-wmbclass/Trace                                                                          False     False Circular    Operational
Microsoft-Windows-WLAN-AutoConfig/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Wired-AutoConfig/Operational                                                   0        False      True Circular    Operational
Microsoft-Windows-Winsock-WS2HELP/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Winsock-NameResolution/Operational                                                      False     False Circular    Operational
Microsoft-Windows-Winsock-AFD/Operational                                                                 False     False Circular    Operational
Microsoft-Windows-WinRM/Operational                                                            230        False      True Circular    Operational
Microsoft-Windows-WinNat/Oper                                                                             False     False Circular    Operational
Microsoft-Windows-Winlogon/Operational                                                         648        False      True Circular    Operational
Microsoft-Windows-WinINet-Config/ProxyConfigChanged                                              2        False      True Circular    Operational
--- SNIP ---

This command provides us with valuable information about each log, including the name of the log, the number of records present, whether the log is in the classic .evt format or the newer .evtx format, its enabled status, the log mode (Circular, Retain, or AutoBackup), and the log type (Administrative, Analytical, Debug, or Operational).

Additionally, we can explore the event log providers associated with each log using the -ListProvider parameter. Event log providers serve as the sources of events within the logs. Executing the following command allows us to retrieve the list of providers and their respective linked logs.

        powershell-session
PS C:\Users\Administrator> Get-WinEvent -ListProvider * | Format-Table -AutoSize

Name                                                                       LogLinks
----                                                                       --------
PowerShell                                                                 {Windows PowerShell}
Workstation                                                                {System}
WMIxWDM                                                                    {System}
WinNat                                                                     {System}
Windows Script Host                                                        {System}
Microsoft-Windows-IME-OEDCompiler                                          {Microsoft-Windows-IME-OEDCompiler/Analytic}
Microsoft-Windows-DeviceSetupManager                                       {Microsoft-Windows-DeviceSetupManager/Operat...
Microsoft-Windows-Search-ProfileNotify                                     {Application}
Microsoft-Windows-Eventlog                                                 {System, Security, Setup, Microsoft-Windows-...
Microsoft-Windows-Containers-BindFlt                                       {Microsoft-Windows-Containers-BindFlt/Operat...
Microsoft-Windows-NDF-HelperClassDiscovery                                 {Microsoft-Windows-NDF-HelperClassDiscovery/...
Microsoft-Windows-FirstUX-PerfInstrumentation                              {FirstUXPerf-Analytic}
--- SNIP ---

This command provides us with an overview of the available providers and their associations with specific logs. It enables us to identify providers of interest for filtering purposes.

Now, let's focus on retrieving specific event logs using the Get-WinEvent cmdlet. At its most basic, Get-WinEvent retrieves event logs from local or remote computers. The examples below demonstrate how to retrieve events from various logs.

    Retrieving events from the System log

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated            Id ProviderName                             LevelDisplayName Message
    -----------            -- ------------                             ---------------- -------
    6/2/2023 9:41:42 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5...
    6/2/2023 9:38:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperien...
    6/2/2023 9:38:32 AM 10016 Microsoft-Windows-DistributedCOM         Warning          The machine-default permission settings do not grant Local Activation permission for the COM Server applicat...
    6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3...
    6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\microsoft.windowscommunications...
    6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ContentDelive...
    6/2/2023 9:36:35 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bb...
    6/2/2023 9:36:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n...
    6/2/2023 9:36:30 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h...
    6/2/2023 9:36:29 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.StartMenuExpe...
    6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat was clear...
    6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\ntuser.dat was cleared updating 2366 keys and creating...
    6/2/2023 9:36:14 AM  7001 Microsoft-Windows-Winlogon               Information      User Logon Notification for Customer Experience Improvement Program 
    6/2/2023 9:33:04 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\AppCompat\Programs\Amcache.hve was cleared updating 920 keys and c...
    6/2/2023 9:31:54 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\Del...
    6/2/2023 9:30:23 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\System32\config\COMPONENTS was cleared updating 54860 keys and cre...
    6/2/2023 9:30:16 AM    15 Microsoft-Windows-Kernel-General         Information      Hive \SystemRoot\System32\config\DRIVERS was reorganized with a starting size of 3956736 bytes and an ending...
    6/2/2023 9:30:10 AM  1014 Microsoft-Windows-DNS-Client             Warning          Name resolution for the name settings-win.data.microsoft.com timed out after none of the configured DNS serv...
    6/2/2023 9:29:54 AM  7026 Service Control Manager                  Information      The following boot-start or system-start driver(s) did not load: ...
    6/2/2023 9:29:54 AM 10148 Microsoft-Windows-WinRM                  Information      The WinRM service is listening for WS-Management requests. ...
    6/2/2023 9:29:51 AM 51046 Microsoft-Windows-DHCPv6-Client          Information      DHCPv6 client service is started
    --- SNIP ---


    This example retrieves the first 50 events from the System log. It selects specific properties, including the event's creation time, ID, provider name, level display name, and message. This facilitates easier analysis and troubleshooting.
    Retrieving events from Microsoft-Windows-WinRM/Operational

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated            Id ProviderName            LevelDisplayName Message
    -----------            -- ------------            ---------------- -------
    6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
    6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
    6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
    6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
    6/2/2023 9:29:54 AM   209 Microsoft-Windows-WinRM Information      The Winrm service started successfully
    --- SNIP ---


    In this example, events are retrieved from the Microsoft-Windows-WinRM/Operational log. The command retrieves the first 30 events and selects relevant properties for display, including the event's creation time, ID, provider name, level display name, and message.
    To retrieve the oldest events, instead of manually sorting the results, we can utilize the -Oldest parameter with the Get-WinEvent cmdlet. This parameter allows us to retrieve the first events based on their chronological order. The following command demonstrates how to retrieve the oldest 30 events from the 'Microsoft-Windows-WinRM/Operational' log.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated           Id ProviderName            LevelDisplayName Message
    -----------            -- ------------            ---------------- -------
    8/3/2022 4:41:38 PM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
    8/3/2022 4:41:42 PM  254 Microsoft-Windows-WinRM Information      Activity Transfer
    8/3/2022 4:41:42 PM  161 Microsoft-Windows-WinRM Error            The client cannot connect to the destination specifie...
    8/3/2022 4:41:42 PM  142 Microsoft-Windows-WinRM Error            WSMan operation Enumeration failed, error code 215085...
    8/3/2022 9:51:03 AM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
    8/3/2022 9:51:07 AM  254 Microsoft-Windows-WinRM Information      Activity Transfer

    Retrieving events from .evtx Files
    If you have an exported .evtx file from another computer or you have backed up an existing log, you can utilize the Get-WinEvent cmdlet to read and query those logs. This capability is particularly useful for auditing purposes or when you need to analyze logs within scripts.
    To retrieve log entries from a .evtx file, you need to provide the log file's path using the -Path parameter. The example below demonstrates how to read events from the 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' file, which represents an exported Windows PowerShell log.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated           Id ProviderName             LevelDisplayName Message
    -----------           -- ------------             ---------------- -------
    5/12/2019 10:01:51 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
    5/12/2019 10:01:50 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
    5/12/2019 10:01:43 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...


    By specifying the path of the log file using the -Path parameter, we can retrieve events from that specific file. The command selects relevant properties and formats the output for easier analysis, displaying the event's creation time, ID, provider name, level display name, and message.
    Filtering events with FilterHashtable
    To filter Windows event logs, we can use the -FilterHashtable parameter, which enables us to define specific conditions for the logs we want to retrieve.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated           Id ProviderName             LevelDisplayName Message
    -----------           -- ------------             ---------------- -------
    6/2/2023 10:40:09 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 10:39:01 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 10:34:12 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 10:33:26 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 10:33:16 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 9:36:10 AM    3 Microsoft-Windows-Sysmon Information      Network connection detected:...
    5/29/2023 6:30:26 PM   1 Microsoft-Windows-Sysmon Information      Process Create:...
    5/29/2023 6:30:24 PM   3 Microsoft-Windows-Sysmon Information      Network connection detected:...


    The command above retrieves events with IDs 1 and 3 from the Microsoft-Windows-Sysmon/Operational event log, selects specific properties from those events, and displays them in a table format. Note: If we observe Sysmon event IDs 1 and 3 (related to "dangerous" or uncommon binaries) occurring within a short time frame, it could potentially indicate the presence of a process communicating with a Command and Control (C2) server.
    For exported events the equivalent command is the following.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

    TimeCreated           Id ProviderName             LevelDisplayName Message
    -----------           -- ------------             ---------------- -------
    6/15/2019 12:14:32 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/15/2019 12:13:44 AM  3 Microsoft-Windows-Sysmon Information      Network connection detected:...
    6/15/2019 12:13:42 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...


    Note: These logs are related to a process communicating with a Command and Control (C2) server right after it was created.
    If we want the get event logs based on a date range (5/28/23 - 6/2/2023), this can be done as follows.

            powershell-session
     PS C:\Users\Administrator> $startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
     PS C:\Users\Administrator> $endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
     PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
     
     TimeCreated           Id ProviderName             LevelDisplayName Message
    -----------           -- ------------             ---------------- -------
    6/2/2023 3:26:56 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:23:41 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:20:27 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    6/2/2023 3:20:26 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
    --- SNIP ---


    Note: The above will filter between the start date inclusive and the end date exclusive. That's why we specified June 3rd and not 2nd.
    Filtering events with FilterHashtable & XML
    Consider an intrusion detection scenario where a suspicious network connection to a particular IP (52.113.194.132) has been identified. With Sysmon installed, you can use Event ID 3 (Network Connection) logs to investigate the potential threat.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
    `ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    New-Object PSObject -Property @{
        SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
        DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
        ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
        ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
    }
    }  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}

    DestinationIP  ProcessId SourceIP       ProcessGuid
    -------------  --------- --------       -----------
    52.113.194.132 9196      10.129.205.123 {52ff3419-51ad-6475-1201-000000000e00}
    52.113.194.132 5996      10.129.203.180 {52ff3419-54f3-6474-3d03-000000000c00}


    This script will retrieve all Sysmon network connection events (ID 3), parse the XML data for each event to retrieve specific details (source IP, destination IP, Process GUID, and Process ID), and filter the results to include only events where the destination IP matches the suspected IP.
    Further, we can use the ProcessGuid to trace back the original process that made the connection, enabling us to understand the process tree and identify any malicious executables or scripts.
    You might wonder how we could have been aware of Event.EventData.Data. The Windows XML EventLog (EVTX) format can be found here.
    In the "Tapping Into ETW" section we were looking for anomalous clr.dll and mscoree.dll loading activity in processes that ordinarily wouldn't require them. The command below is leveraging Sysmon's Event ID 7 to detect the loading of abovementioned DLLs.

            powershell-session
    PS C:\Users\Administrator> $Query = @"
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
                </Select>
            </Query>
        </QueryList>
        "@
    PS C:\Users\Administrator> Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
    Image loaded:
    RuleName: -
    UtcTime: 2023-06-05 22:23:16.560
    ProcessGuid: {52ff3419-6054-647e-aa02-000000001000}
    ProcessId: 2936
    Image: C:\Tools\GhostPack Compiled Binaries\Seatbelt.exe
    ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
    FileVersion: 4.8.4515.0 built by: NET48REL1LAST_C
    Description: Microsoft .NET Runtime Common Language Runtime -   WorkStation
    Product: Microsoft® .NET Framework
    Company: Microsoft Corporation
    OriginalFileName: clr.dll
    Hashes: MD5=2B0E5597FF51A3A4D5BB2DDAB0214531,SHA256=8D09CE35C987EADCF01686BB559920951B0116985FE4FEB5A488A6A8F7C4BDB9,IMPHASH=259C196C67C4E02F941CAD54D9D9BB8A
    Signed: true
    Signature: Microsoft Corporation
    SignatureStatus: Valid
    User: DESKTOP-NU10MTO\Administrator

    Image loaded:
    RuleName: -
    UtcTime: 2023-06-05 22:23:16.544
    ProcessGuid: {52ff3419-6054-647e-aa02-000000001000}
    ProcessId: 2936
    Image: C:\Tools\GhostPack Compiled Binaries\Seatbelt.exe
    ImageLoaded: C:\Windows\System32\mscoree.dll
    FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
    Description: Microsoft .NET Runtime Execution Engine
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: mscoree.dll
    Hashes: MD5=D5971EF71DE1BDD46D537203ABFCC756,SHA256=8828DE042D008783BA5B31C82935A3ED38D5996927C3399B3E1FC6FE723FC84E,IMPHASH=65F23EFA1EB51A5DAAB399BFAA840074
    Signed: true
    Signature: Microsoft Windows
    SignatureStatus: Valid
    User: DESKTOP-NU10MTO\Administrator
    --- SNIP ---

    Filtering events with FilterXPath
    To use XPath queries with Get-WinEvent, we need to use the -FilterXPath parameter. This allows us to craft an XPath query to filter the event logs.
    For instance, if we want to get Process Creation (Sysmon Event ID 1) events in the Sysmon log to identify installation of any Sysinternals tool we can use the command below. Note: During the installation of a Sysinternals tool the user must accept the presented EULA. The acceptance action involves the registry key included in the command below.

            powershell-session
     PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
     
     TimeCreated           Id ProviderName             LevelDisplayName Message
    -----------           -- ------------             ---------------- -------
    5/29/2023 12:44:46 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
    5/29/2023 12:29:53 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...


    Note: Image and CommandLine can be identified by browsing the XML representation of any Sysmon event with ID 1 through, for example, Event Viewer. 
    
    <img width="1543" height="693" alt="image" src="https://github.com/user-attachments/assets/bb33af48-36d5-4f07-aa14-1faa8858b12d" />

    Sysmon Event 1 showing process creation details for SecurityHealthHost.exe, including process ID, file path, and command line.


    
    Lastly, suppose we want to investigate any network connections to a particular suspicious IP address (52.113.194.132) that Sysmon has logged. To do that we could use the following command.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"

    ProviderName: Microsoft-Windows-Sysmon

    TimeCreated                      Id LevelDisplayName Message
    -----------                      -- ---------------- -------
    5/29/2023 6:30:24 PM              3 Information      Network connection detected:...
    5/29/2023 12:32:05 AM             3 Information      Network connection detected:...

    Filtering events based on property values
    The -Property * parameter, when used with Select-Object, instructs the command to select all properties of the objects passed to it. In the context of the Get-WinEvent command, these properties will include all available information about the event. Let's see an example that will present us with all properties of Sysmon event ID 1 logs.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *


    Message            : Process Create:
                       RuleName: -
                       UtcTime: 2023-06-03 01:24:25.104
                       ProcessGuid: {52ff3419-9649-647a-1902-000000001000}
                       ProcessId: 1036
                       Image: C:\Windows\System32\taskhostw.exe
                       FileVersion: 10.0.19041.1806 (WinBuild.160101.0800)
                       Description: Host Process for Windows Tasks
                       Product: Microsoft® Windows® Operating System
                       Company: Microsoft Corporation
                       OriginalFileName: taskhostw.exe
                       CommandLine: taskhostw.exe -RegisterDevice -ProtectionStateChanged -FreeNetworkOnly
                       CurrentDirectory: C:\Windows\system32\
                       User: NT AUTHORITY\SYSTEM
                       LogonGuid: {52ff3419-85d0-647a-e703-000000000000}
                       LogonId: 0x3E7
                       TerminalSessionId: 0
                       IntegrityLevel: System
                       Hashes: MD5=C7B722B96F3969EACAE9FA205FAF7EF0,SHA256=76D3D02B265FA5768294549C938D3D9543CC9FEF6927
                       4728E0A72E3FCC335366,IMPHASH=3A0C6863CDE566AF997DB2DEFFF9D924
                       ParentProcessGuid: {00000000-0000-0000-0000-000000000000}
                       ParentProcessId: 1664
                       ParentImage: -
                       ParentCommandLine: -
                       ParentUser: -
    Id                   : 1
    Version              : 5
    Qualifiers           :
    Level                : 4
    Task                 : 1
    Opcode               : 0
    Keywords             : -9223372036854775808
    RecordId             : 32836
    ProviderName         : Microsoft-Windows-Sysmon
    ProviderId           : 5770385f-c22a-43e0-bf4c-06f5698ffbd9
    LogName              : Microsoft-Windows-Sysmon/Operational
    ProcessId            : 2900
    ThreadId             : 2436
    MachineName          : DESKTOP-NU10MTO
    UserId               : S-1-5-18
    TimeCreated          : 6/2/2023 6:24:25 PM
    ActivityId           :
    RelatedActivityId    :
    ContainerLog         : Microsoft-Windows-Sysmon/Operational
    MatchedQueryIds      : {}
    Bookmark             :      System.Diagnostics.Eventing.Reader.EventBookmark
    LevelDisplayName     : Information
    OpcodeDisplayName    : Info
    TaskDisplayName      : Process Create (rule: ProcessCreate)
    KeywordsDisplayNames : {}
    Properties           : {System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty...}


    Let's now see an example of a command that retrieves Process Create events from the Microsoft-Windows-Sysmon/Operational log, checks the parent command line of each event for the string -enc, and then displays all properties of any matching events as a list.

            powershell-session
    PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List

    TimeCreated  : 5/29/2023 12:44:58 AM
    ProviderName : Microsoft-Windows-Sysmon
    Id           : 1
    Message      : Process Create:
               RuleName: -
               UtcTime: 2023-05-29 07:44:58.467
               ProcessGuid: {52ff3419-57fa-6474-7005-000000000c00}
               ProcessId: 2660
               Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
               FileVersion: 4.8.4084.0 built by: NET48REL1
               Description: Visual C# Command Line Compiler
               Product: Microsoft® .NET Framework
               Company: Microsoft Corporation
               OriginalFileName: csc.exe
               CommandLine: "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
               @"C:\Users\ADMINI~1\AppData\Local\Temp\z5erlc11.cmdline"
               CurrentDirectory: C:\Users\Administrator\
               User: DESKTOP-NU10MTO\Administrator
               LogonGuid: {52ff3419-57f9-6474-8071-510000000000}
               LogonId: 0x517180
               TerminalSessionId: 0
               IntegrityLevel: High
               Hashes: MD5=F65B029562077B648A6A5F6A1AA76A66,SHA256=4A6D0864E19C0368A47217C129B075DDDF61A6A262388F9D2104
               5D82F3423ED7,IMPHASH=EE1E569AD02AA1F7AECA80AC0601D80D
               ParentProcessGuid: {52ff3419-57f9-6474-6e05-000000000c00}
               ParentProcessId: 5840
               ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile
               -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIA
               A+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQ
               BsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQ
               BzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbw
               ByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQ
               AgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeA
               BlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIA
               BbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQ
               BzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIA
               B7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbA
               BlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQ
               AKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKA
               AkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA==
               ParentUser: DESKTOP-NU10MTO\Administrator

    TimeCreated  : 5/29/2023 12:44:57 AM
    ProviderName : Microsoft-Windows-Sysmon
    Id           : 1
    Message      : Process Create:
               RuleName: -
               UtcTime: 2023-05-29 07:44:57.919
               ProcessGuid: {52ff3419-57f9-6474-6f05-000000000c00}
               ProcessId: 3060
               Image: C:\Windows\System32\chcp.com
               FileVersion: 10.0.19041.1806 (WinBuild.160101.0800)
               Description: Change CodePage Utility
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: CHCP.COM
               CommandLine: "C:\Windows\system32\chcp.com" 65001
               CurrentDirectory: C:\Users\Administrator\
               User: DESKTOP-NU10MTO\Administrator
               LogonGuid: {52ff3419-57f9-6474-8071-510000000000}
               LogonId: 0x517180
               TerminalSessionId: 0
               IntegrityLevel: High
               Hashes: MD5=33395C4732A49065EA72590B14B64F32,SHA256=025622772AFB1486F4F7000B70CC51A20A640474D6E4DBE95A70
               BEB3FD53AD40,IMPHASH=75FA51C548B19C4AD5051FAB7D57EB56
               ParentProcessGuid: {52ff3419-57f9-6474-6e05-000000000c00}
               ParentProcessId: 5840
               ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile
               -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIA
               A+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQ
               BsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQ
               BzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbw
               ByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQ
               AgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeA
               BlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIA
               BbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQ
               BzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIA
               B7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbA
               BlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQ
               AKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKA
               AkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA==
               ParentUser: DESKTOP-NU10MTO\Administrator
    --- SNIP ---

        | Where-Object {$_.Properties[21].Value -like "*-enc*"}: This portion of the command further filters the retrieved events. The '|' character (pipe operator) passes the output of the previous command (i.e., the filtered events) to the 'Where-Object' cmdlet. The 'Where-Object' cmdlet filters the output based on the script block that follows it.
            $_: In the script block, $_ refers to the current object in the pipeline, i.e., each individual event that was retrieved and passed from the previous command.
            .Properties[21].Value: The Properties property of a "Process Create" Sysmon event is an array containing various data about the event. The specific index 21 corresponds to the ParentCommandLine property of the event, which holds the exact command line used to start the process. 
            
          <img width="1242" height="907" alt="image" src="https://github.com/user-attachments/assets/5010ed3b-c2f9-4de6-914d-d8819a67906e" />
  
            Sysmon Event 1 showing process creation details for mmc.exe, including process ID, file path, and command line, with high integrity level.


            
            -like "*-enc*": This is a comparison operator that matches strings based on a wildcard string, where * represents any sequence of characters. In this case, it's looking for any command lines that contain -enc anywhere within them. The -enc string might be part of suspicious commands, for example, it's a common parameter in PowerShell commands to denote an encoded command which could be used to obfuscate malicious scripts.
            | Format-List: Finally, the output of the previous command (the events that meet the specified condition) is passed to the Format-List cmdlet. This cmdlet displays the properties of the input objects as a list, making it easier to read and analyze.







HTB Academy Logo
Windows Event Logs & Finding Evil
Windows Event Logs & Finding Evil 100%

Section 6 / 6
Go to Questions
Skills Assessment

To keep you sharp, your SOC manager has assigned you the task of analyzing older attack logs and providing answers to specific questions.

Navigate to the bottom of this section and click on Click here to spawn the target system!

RDP to [Target IP] using the provided credentials, examine the logs located in the C:\Logs\* directories, and answer the questions below.

        shellsession
manojxshrestha@htb[/htb]$ xfreerdp /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /v:[Target IP] /dynamic-resolution

Connect to HTB
Target(s)

Time left: 116 min(s)

    10.129.10.212 (ACADEMY-SFUND-WIN10) 

Enable step-by-step solutions
PRO

    Question 1

    +3
    By examining the logs located in the "C:\Logs\DLLHijack" directory, determine the process responsible for executing a DLL hijacking attack. Enter the process name as your answer. Answer format: _.exe

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"
    Question 2

    +2
    By examining the logs located in the "C:\Logs\PowershellExec" directory, determine the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"
    Question 3

    +3
    By examining the logs located in the "C:\Logs\PowershellExec" directory, determine the process that injected into the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"
    Question 4

    +2
    By examining the logs located in the "C:\Logs\Dump" directory, determine the process that performed an LSASS dump. Enter the process name as your answer. Answer format: _.exe

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"
    Question 5

    +1
    By examining the logs located in the "C:\Logs\Dump" directory, determine if an ill-intended login took place after the LSASS dump. Answer format: Yes or No

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"
    Question 6

    +2
    By examining the logs located in the "C:\Logs\StrangePPID" directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship. Enter the process name as your answer. Answer format: _.exe

    RDP to 10.129.10.212 (ACADEMY-SFUND-WIN10), with user "Administrator" and password "HTB_@cad3my_lab_W1n10_r00t!@0"

6 / 6 Sections
adblock modal image






