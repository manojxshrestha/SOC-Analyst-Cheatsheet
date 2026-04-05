# Windows Event Logs & Finding Evil
## SOC Analyst Cheatsheet - Module 3/15

---

Section 1 / 6

# Windows Event Logs

## Windows Event Logging Basics

Windows Event Logs are an intrinsic part of the Windows Operating System, storing logs from different components of the system including the system itself, applications running on it, ETW providers, services, and others.

Windows event logging offers comprehensive logging capabilities for application errors, security events, and diagnostic information. As cybersecurity professionals, we leverage these logs extensively for analysis and intrusion detection.

The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose.

Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.

Accessing the Windows Event Viewer as an administrative user allows us to explore the various logs available.

<img width="1192" height="972" alt="image" src="https://github.com/user-attachments/assets/2a988d43-8bcb-484f-810a-0ad9c746d5ef" />

Windows search for 'Event Viewer' showing options: Open, Run as administrator, Open file location, Pin to Start, Pin to taskbar.

<img width="1000" height="246" alt="image" src="https://github.com/user-attachments/assets/ddb8775f-47a0-4916-b546-ffa3f84c7203" />

Windows Logs showing Application, Security, Setup, System, and Forwarded Events with event counts and sizes.

The default Windows event logs consist of Application, Security, Setup, System, and Forwarded Events. While the first four logs cover application errors, security events, system setup activities, and general system information, the "Forwarded Events" section is unique, showcasing event log data forwarded from other machines. This central logging feature proves valuable for system administrators who desire a consolidated view. In our current analysis, we focus on event logs from a single machine.

It should be noted, that the Windows Event Viewer has the ability to open and display previously saved .evtx files, which can be then found in the "Saved Logs" section.

<img width="1755" height="1587" alt="image" src="https://github.com/user-attachments/assets/7e864e6d-4201-4ff7-af63-00497c5c1773" />

Event Viewer displaying DLLHijack logs with details of Sysmon events, including registry value changes and process information.

## The Anatomy of an Event Log

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

According to Microsoft's documentation, this event signifies the creation of a logon session on the destination machine, originating from the accessed computer where the session was established. Within this log, we find crucial details, including the "Logon ID", which allows us to correlate this logon with other events sharing the same "Logon ID". Another important detail is the "Logon Type", indicating the type of logon. In this case, it specifies a Service logon type, suggesting that "SYSTEM" initiated a new service. However, further investigation is required to determine the specific service involved, utilizing correlation techniques with additional data like the "Logon ID".

## Leveraging Custom XML Queries

To streamline our analysis, we can create custom XML queries to identify related events using the "Logon ID" as a starting point. By navigating to "Filter Current Log" -> "XML" -> "Edit Query Manually," we gain access to a custom XML query language that enables more granular log searches.

<img width="1000" height="670" alt="image" src="https://github.com/user-attachments/assets/e626b057-5dfe-4e04-9474-d4b097babf38" />

Event Viewer filter setup with XML query for Security log, filtering by SubjectLogonId 0x3E7.

In the example query, we focus on events containing the "SubjectLogonId" field with a value of "0x3E7". The selection of this value stems from the need to correlate events associated with a specific "Logon ID" and understand the relevant details within those events.

<img width="1000" height="685" alt="image" src="https://github.com/user-attachments/assets/1cd544c2-f410-4a81-9658-72348b937517" />

Event 4624 details: SubjectUserName ARASHPARSA2BB9$, SubjectDomainName WORKGROUP, TargetUserName SYSTEM, LogonType 5, LogonProcessName Advapi.

It is worth noting, that if assistance is required in crafting the query, automatic filters can be enabled, allowing exploration of their impact on the XML representation. For further guidance, Microsoft offers informative articles on advanced XML filtering in the Windows Event Viewer.

By constructing such queries, we can narrow down our focus to the account responsible for initiating the service and eliminate unnecessary details. This approach helps unveil a clearer picture of recent logon activities associated with the specified Logon ID. However, even with this refinement, the amount of data remains significant.

Delving into the log details progressively reveals a narrative. For instance, the analysis begins with Event ID 4907, which signifies an audit policy change.

<img width="1000" height="965" alt="image" src="https://github.com/user-attachments/assets/bb4fbe6d-d734-4a5b-8bc9-c559b0909b25" />

Event Viewer showing Event 4907, Microsoft Windows security auditing, with audit policy change details for account ARASHPARSA2BB9$, object path, and logon ID 0x3E7.

Within the event description, we find valuable insights, such as "This event generates when the SACL of an object (for example, a registry key or file) was changed."

In case unfamiliar with SACL, referring to the provided link (https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) sheds light on access control lists (ACLs). The "S" in SACL denotes a system access control list, which enables administrators to log access attempts to secure objects. Each Access Control Entry (ACE) within a SACL specifies the types of access attempts by a designated trustee that trigger record generation in the security event log. ACEs in a SACL can generate audit records upon failed, successful, or both types of access attempts.

Based on this information, it becomes apparent that the permissions of a file were altered to modify the logging or auditing of access attempts. Further exploration of the event details reveals additional intriguing aspects.

<img width="1000" height="738" alt="image" src="https://github.com/user-attachments/assets/3d6c9a33-39bd-43c3-a515-5b106bac67c9" />

Event 4907 details: SubjectUserName ARASHPARSA2BB9$, SubjectDomainName WORKGROUP, ObjectType File, ObjectName path, ProcessName SetupHost.exe.

For example, the process responsible for the change is identified as "SetupHost.exe", indicating a potential setup process (although it's worth noting that malware can sometimes masquerade under legitimate names). The object name impacted appears to be the "bootmanager", and we can examine the new and old security descriptors ("NewSd" and "OldSd") to identify the changes. Understanding the meaning of each field in the security descriptor can be accomplished through references such as the article ACE Strings and Understanding SDDL Syntax.

From the observed events, we can infer that a setup process occurred, involving the creation of a new file and the initial configuration of security permissions for auditing purposes. Subsequently, we encounter the logon event, followed by a "special logon" event.

<img width="346" height="94" alt="image" src="https://github.com/user-attachments/assets/e460ee35-b4fa-4ba6-82fd-3c19e906a68c" />

Event IDs 4624 Logon and 4672 Special Logon.

Analyzing the special logon event, we gain insights into token permissions granted to the user upon a successful logon.

<img width="1000" height="825" alt="image" src="https://github.com/user-attachments/assets/13437cf0-e416-4b59-b620-991a4f1ac939" />

Event 4672, Microsoft Windows security auditing, showing SYSTEM account with special privileges like SeAssignPrimaryTokenPrivilege and SeDebugPrivilege.

A comprehensive list of privileges can be found in the documentation on privilege constants. For instance, the "SeDebugPrivilege" privilege indicates that the user possesses the ability to tamper with memory that does not belong to them.

## Useful Windows Event Logs

Find below an indicative (non-exhaustive) list of useful Windows event logs:

**Windows System Logs**
- **Event ID 1074** (System Shutdown/Restart): This event log indicates when and why the system was shut down or restarted. By monitoring these events, you can determine if there are unexpected shutdowns or restarts, potentially revealing malicious activity such as malware infection or unauthorized user access.
- **Event ID 6005** (The Event log service was started): This event log marks the time when the Event Log Service was started. This is an important record, as it can signify a system boot-up, providing a starting point for investigating system performance or potential security incidents around that period. It can also be used to detect unauthorized system reboots.
- **Event ID 6006** (The Event log service was stopped): This event log signifies the moment when the Event Log Service was stopped. It is typically seen when the system is shutting down. Abnormal or unexpected occurrences of this event could point to intentional service disruption for covering illicit activities.
- **Event ID 6013** (Windows uptime): This event occurs once a day and shows the uptime of the system in seconds. A shorter than expected uptime could mean the system has been rebooted, which could signify a potential intrusion or unauthorized activities on the system.
- **Event ID 7040** (Service status change): This event indicates a change in service startup type, which could be from manual to automatic or vice versa. If a crucial service's startup type is changed, it could be a sign of system tampering.

**Windows Security Logs**
- **Event ID 1102** (The audit log was cleared): Clearing the audit log is often a sign of an attempt to remove evidence of an intrusion or malicious activity.
- **Event ID 1116** (Antivirus malware detection): This event is particularly important because it logs when Defender detects a malware. A surge in these events could indicate a targeted attack or widespread malware infection.
- **Event ID 1118** (Antivirus remediation activity has started): This event signifies that Defender has begun the process of removing or quarantining detected malware.
- **Event ID 1119** (Antivirus remediation activity has succeeded): This event signifies that the remediation process for detected malware has been successful.
- **Event ID 1120** (Antivirus remediation activity has failed): This event is the counterpart to 1119 and indicates that the remediation process has failed.
- **Event ID 4624** (Successful Logon): This event records successful logon events. This information is vital for establishing normal user behavior. Abnormal behavior, such as logon attempts at odd hours or from different locations, could signify a potential security threat.
- **Event ID 4625** (Failed Logon): This event logs failed logon attempts. Multiple failed logon attempts could signify a brute-force attack in progress.
- **Event ID 4648** (A logon was attempted using explicit credentials): This event is triggered when a user logs on with explicit credentials to run a program. Anomalies in these logon events could indicate lateral movement within a network.
- **Event ID 4656** (A handle to an object was requested): This event is triggered when a handle to an object (like a file, registry key, or process) is requested.
- **Event ID 4672** (Special Privileges Assigned to a New Logon): This event is logged whenever an account logs on with super user privileges. Tracking these events helps to ensure that super user privileges are not being abused or used maliciously.
- **Event ID 4698** (A scheduled task was created): This event is triggered when a scheduled task is created. Monitoring this event can help you detect persistence mechanisms.
- **Event ID 4700 & Event ID 4701** (A scheduled task was enabled/disabled): This records the enabling or disabling of a scheduled task.
- **Event ID 4702** (A scheduled task was updated): Similar to 4698, this event is triggered when a scheduled task is updated.
- **Event ID 4719** (System audit policy was changed): This event records changes to the audit policy on a computer.
- **Event ID 4738** (A user account was changed): This event records any changes made to user accounts, including changes to privileges, group memberships, and account settings.
- **Event ID 4771** (Kerberos pre-authentication failed): This event is similar to 4625 (failed logon) but specifically for Kerberos authentication.
- **Event ID 4776** (The domain controller attempted to validate the credentials for an account): This event helps track both successful and failed attempts at credential validation by the domain controller.
- **Event ID 5001** (Antivirus real-time protection configuration has changed): This event indicates that the real-time protection settings of Defender have been modified.
- **Event ID 5140** (A network share object was accessed): This event is logged whenever a network share is accessed.
- **Event ID 5142** (A network share object was added): This event signifies the creation of a new network share.
- **Event ID 5145** (A network share object was checked to see whether client can be granted desired access): This event indicates that someone attempted to access a network share.
- **Event ID 5157** (The Windows Filtering Platform has blocked a connection): This is logged when the Windows Filtering Platform blocks a connection attempt.
- **Event ID 7045** (A service was installed in the system): A sudden appearance of unknown services might suggest malware installation.

Remember, one of the key aspects of threat detection is having a good understanding of what is "normal" in our environment. Anomalies that might indicate a threat in one environment could be normal behavior in another. It's crucial to tune our monitoring and alerting systems to our environment to minimize false positives and make real threats easier to spot.

---

*Module 3/15 - Windows Event Logs & Finding Evil*
*Built with research + HTB Academy materials*











































HTB Academy Logo
Windows Event Logs & Finding Evil
Windows Event Logs & Finding Evil 100%

Section 2 / 6
Go to Questions
Analyzing Evil With Sysmon & Event Logs

In our pursuit of robust cybersecurity, it is crucial to understand how to identify and analyze malicious events effectively. Building upon our previous exploration of benign events, we will now delve into the realm of malicious activities and discover techniques for detection.
Sysmon Basics

When investigating malicious events, several event IDs serve as common indicators of compromise. For instance, Event ID 4624 provides insights into new logon events, enabling us to monitor and detect suspicious user access and logon patterns. Similarly, Event ID 4688 furnishes information about newly created processes, aiding the identification of unusual or malicious process launches. To enhance our event log coverage, we can extend the capabilities by incorporating Sysmon, which offers additional event logging capabilities.

System Monitor (Sysmon) is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. Sysmon provides detailed information about process creation, network connections, changes to file creation time, and more.

Sysmon's primary components include:

    A Windows service for monitoring system activity.
    A device driver that assists in capturing the system activity data.
    An event log to display captured activity data.

Sysmon's unique capability lies in its ability to log information that typically doesn't appear in the Security Event logs, and this makes it a powerful tool for deep system monitoring and cybersecurity forensic analysis.

Sysmon categorizes different types of system activity using event IDs, where each ID corresponds to a specific type of event. For example, Event ID 1 corresponds to "Process Creation" events, and Event ID 3 refers to "Network Connection" events. The full list of Sysmon event IDs can be found here.

For more granular control over what events get logged, Sysmon uses an XML-based configuration file. The configuration file allows you to include or exclude certain types of events based on different attributes like process names, IP addresses, etc. We can refer to popular examples of useful Sysmon configuration files:

    For a comprehensive configuration, we can visit: https://github.com/SwiftOnSecurity/sysmon-config. <-- We will use this one in this section!
    Another option is: https://github.com/olafhartong/sysmon-modular, which provides a modular approach.

To get started, you can install Sysmon by downloading it from the official Microsoft documentation (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). Once downloaded, open an administrator command prompt and execute the following command to install Sysmon.

        cmd-session
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

Command prompt showing Sysmon v13.33 installation and startup messages.

To utilize a custom Sysmon configuration, execute the following after installing Sysmon.

        shellsession
C:\Tools\Sysmon> sysmon.exe -c filename.xml

Note: It should be noted that Sysmon for Linux also exists.
Detection Example 1: Detecting DLL Hijacking

In our specific use case, we aim to detect a DLL hijack. The Sysmon event log IDs relevant to DLL hijacks can be found in the Sysmon documentation (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). To detect a DLL hijack, we need to focus on Event Type 7, which corresponds to module load events. To achieve this, we need to modify the sysmonconfig-export.xml Sysmon configuration file we downloaded from https://github.com/SwiftOnSecurity/sysmon-config.

By examining the modified configuration, we can observe that the "include" comment signifies events that should be included.

<img width="1926" height="222" alt="image" src="https://github.com/user-attachments/assets/b54fdbbb-d6fe-4db9-89d0-602e1fca858d" />

XML snippet showing RuleGroup with ImageLoad set to 'include' and a note about no rules meaning nothing will be logged.

In the case of detecting DLL hijacks, we change the "include" to "exclude" to ensure that nothing is excluded, allowing us to capture the necessary data.

<img width="1820" height="200" alt="image" src="https://github.com/user-attachments/assets/e80c9c0e-0c13-4c43-86b8-75741318234a" />

XML snippet with RuleGroup, ImageLoad set to 'exclude', and a note about using 'include' with no rules.

To utilize the updated Sysmon configuration, execute the following.

        cmd-session
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
<img width="1450" height="436" alt="image" src="https://github.com/user-attachments/assets/f46ab0d6-43dc-4992-8aa2-4d0b0708b81b" />

Command prompt showing Sysmon v13.33 loading sysmonconfig-export.xml, configuration validated and updated.

With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon." A quick check will reveal the presence of the targeted event ID.
<img width="1000" height="468" alt="image" src="https://github.com/user-attachments/assets/a97c30a2-4dca-48b4-8469-cec3d17ceeec" />

Sysmon event log showing multiple Information entries for Event ID 7, Image loaded.

Let's now see how a Sysmon event ID 7 looks like.
<img width="2124" height="588" alt="image" src="https://github.com/user-attachments/assets/4d944b07-bb15-4f58-806b-e2bc253961cc" />

Sysmon log entry: Image loaded, ProcessID 8060, Image mmc.exe, ImageLoaded psapi.dll, Signed true, User DESKTOP-N33HELB\Waldo.

The event log contains the DLL's signing status (in this case, it is Microsoft-signed), the process or image responsible for loading the DLL, and the specific DLL that was loaded. In our example, we observe that "MMC.exe" loaded "psapi.dll", which is also Microsoft-signed. Both files are located in the System32 directory.

Now, let's proceed with building a detection mechanism. To gain more insights into DLL hijacks, conducting research is paramount. We stumble upon an informative blog post that provides an exhaustive list of various DLL hijack techniques. For the purpose of our detection, we will focus on a specific hijack involving the vulnerable executable calc.exe and a list of DLLs that can be hijacked.

<img width="1000" height="550" alt="image" src="https://github.com/user-attachments/assets/f3448679-5d7d-47be-8b57-2e46591b1615" />

Table showing calc.exe with associated DLLs: CRYPTBASE.DLL, edputil.dll, MLANG.dll, PROPSYS.dll, Secur32.dll, SSPICLI.DLL, WININET.dll, and their functions.

Let's attempt the hijack using "calc.exe" and "WININET.dll" as an example. To simplify the process, we can utilize Stephen Fewer's "hello world" reflective DLL. It should be noted that DLL hijacking does not require reflective DLLs.

By following the required steps, which involve renaming reflective_dll.x64.dll to WININET.dll, moving calc.exe from C:\Windows\System32 along with WININET.dll to a writable directory (such as the Desktop folder), and executing calc.exe, we achieve success. Instead of the Calculator application, a MessageBox is displayed.

<img width="1008" height="592" alt="image" src="https://github.com/user-attachments/assets/dd56f9ae-f50f-41e5-bbde-226bbbf9c54d" />


Command prompt running calc.exe, desktop showing WININET.dll and calc icons, with a popup message 'Hello from DllMain!' indicating Reflective DLL Injection.

Next, we analyze the impact of the hijack. First, we filter the event logs to focus on Event ID 7, which represents module load events, by clicking "Filter Current Log...".

<img width="1090" height="1106" alt="image" src="https://github.com/user-attachments/assets/f343e949-4de6-483e-a73e-671d916e4401" />

Filter Current Log window with options for event level, event logs set to Microsoft-Windows-Sysmon/Operational, and Event ID 7.

Subsequently, we search for instances of "calc.exe", by clicking "Find...", to identify the DLL load associated with our hijack.

<img width="2136" height="836" alt="image" src="https://github.com/user-attachments/assets/7407070a-3eff-44d2-bf68-9d252351767a" />

Sysmon log entry: Image loaded, ProcessID 6212, Image calc.exe, ImageLoaded WININET.dll, Signed false, User DESKTOP-N33HELB\Waldo. Find dialog open for 'calc.exe'.

The output from Sysmon provides valuable insights. Now, we can observe several indicators of compromise (IOCs) to create effective detection rules. Before moving forward though, let's compare this to an authenticate load of "wininet.dll" by "calc.exe".

<img width="1000" height="466" alt="image" src="https://github.com/user-attachments/assets/02769150-34d2-4d77-84e4-d5a93a04fa99" />

Sysmon log entry: Image loaded, ProcessID 5464, Image calc.exe, ImageLoaded wininet.dll, Signed true, User DESKTOP-N33HELB\Waldo. Find dialog open for 'calc.exe'.

Let's explore these IOCs:

    "calc.exe", originally located in System32, should not be found in a writable directory. Therefore, a copy of "calc.exe" in a writable directory serves as an IOC, as it should always reside in System32 or potentially Syswow64.
    "WININET.dll", originally located in System32, should not be loaded outside of System32 by calc.exe. If instances of "WININET.dll" loading occur outside of System32 with "calc.exe" as the parent process, it indicates a DLL hijack within calc.exe. While caution is necessary when alerting on all instances of "WININET.dll" loading outside of System32 (as some applications may package specific DLL versions for stability), in the case of "calc.exe", we can confidently assert a hijack due to the DLL's unchanging name, which attackers cannot modify to evade detection.
    The original "WININET.dll" is Microsoft-signed, while our injected DLL remains unsigned.

These three powerful IOCs provide an effective means of detecting a DLL hijack involving calc.exe. It's important to note that while Sysmon and event logs offer valuable telemetry for hunting and creating alert rules, they are not the sole sources of information.
Detection Example 2: Detecting Unmanaged PowerShell/C-Sharp Injection

Before delving into detection techniques, let's gain a brief understanding of C# and its runtime environment. C# is considered a "managed" language, meaning it requires a backend runtime to execute its code. The Common Language Runtime (CLR) serves as this runtime environment. Managed code does not directly run as assembly; instead, it is compiled into a bytecode format that the runtime processes and executes. Consequently, a managed process relies on the CLR to execute C# code.

As defenders, we can leverage this knowledge to detect unusual C# injections or executions within our environment. To accomplish this, we can utilize a useful utility called Process Hacker.

<img width="1000" height="899" alt="image" src="https://github.com/user-attachments/assets/da514956-d962-40e4-b9b4-e9eb6d47ac5b" />

Task Manager showing processes like Microsoft.Photos.exe, msedge.exe, powershell.exe, ProcessHacker.exe, with CPU and memory usage details.

By using Process Hacker, we can observe a range of processes within our environment. Sorting the processes by name, we can identify interesting color-coded distinctions. Notably, "powershell.exe", a managed process, is highlighted in green compared to other processes. Hovering over powershell.exe reveals the label "Process is managed (.NET)," confirming its managed status.

<img width="1000" height="386" alt="image" src="https://github.com/user-attachments/assets/9a726a4b-ac33-4202-ab64-d08d94be8ecb" />

Task Manager tooltip for powershell.exe, showing file path, version 10.0.19041.546, signed by Microsoft, console host conhost.exe (5092).

Examining the module loads for powershell.exe, by right-clicking on powershell.exe, clicking "Properties", and navigating to "Modules", we can find relevant information.

<img width="1000" height="63" alt="image" src="https://github.com/user-attachments/assets/eec3231e-e49f-4e3a-8623-567efffa13fe" />

Image showing clr.dll and drjit.dll with memory addresses, sizes, and descriptions for Microsoft .NET Runtime components.

The presence of "Microsoft .NET Runtime...", clr.dll, and clrjit.dll should attract our attention. These 2 DLLs are used when C# code is ran as part of the runtime to execute the bytecode. If we observe these DLLs loaded in processes that typically do not require them, it suggests a potential execute-assembly or unmanaged PowerShell injection attack.

To showcase unmanaged PowerShell injection, we can inject an unmanaged PowerShell-like DLL into a random process, such as spoolsv.exe. We can do that by utilizing the PSInject project in the following manner.

        powershell-session
 powershell -ep bypass
 Import-Module .\Invoke-PSInject.ps1
 Invoke-PSInject -ProcId [Process ID of spoolsv.exe] -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"

<img width="904" height="390" alt="image" src="https://github.com/user-attachments/assets/0009baf8-89b7-41a6-a0d7-b4cd112fc7a8" />

Tooltip for spoolsv.exe showing file path, version 10.0.19041.1288, signed by Microsoft, and associated with Print Spooler service.

After the injection, we observe that "spoolsv.exe" transitions from an unmanaged to a managed state.

<img width="742" height="416" alt="image" src="https://github.com/user-attachments/assets/f1d6b57f-2c53-4613-b483-cc3f781b1e0f" />


Tooltip for spoolsv.exe showing file path, version 10.0.19041.1288, signed by Microsoft, associated with Print Spooler service, and managed by .NET.

Additionally, by referring to both the related "Modules" tab of Process Hacker and Sysmon Event ID 7, we can examine the DLL load information to validate the presence of the aforementioned DLLs.

<img width="1000" height="617" alt="image" src="https://github.com/user-attachments/assets/a8bc74db-25ed-46e3-9dde-78e6b18fe377" />
t.ps1
 Invoke-PSInject -ProcId [Process ID of spo

Properties window for spoolsv.exe showing modules like advapi32.dll, amsi.dll, APMon.dll, with base addresses, sizes, and descriptions.Sysmon Event 7: Image loaded, ProcessID 2792, Image spoolsv.exe, ImageLoaded clr.dll, Microsoft .NET Runtime, signed by Microsoft, User NT AUTHORITY\SYSTEM.


Detection Example 3: Detecting Credential Dumping

Another critical aspect of cybersecurity is detecting credential dumping activities. One widely used tool for credential dumping is Mimikatz, offering various methods for extracting Windows credentials. One specific command, "sekurlsa::logonpasswords", enables the dumping of password hashes or plaintext passwords by accessing the Local Security Authority Subsystem Service (LSASS). LSASS is responsible for managing user credentials and is a primary target for credential-dumping tools like Mimikatz.

The attack can be executed as follows.

        cmd-session
C:\Tools\Mimikatz> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

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
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
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

As we can see, the output of the "sekurlsa::logonpasswords" command provides powerful insights into compromised credentials.

To detect this activity, we can rely on a different Sysmon event. Instead of focusing on DLL loads, we shift our attention to process access events. By checking Sysmon event ID 10, which represents "ProcessAccess" events, we can identify any suspicious attempts to access LSASS.

<img width="1000" height="271" alt="image" src="https://github.com/user-attachments/assets/34ce1b68-e298-4a74-9654-db55143ba6c6" />

<img width="1000" height="397" alt="image" src="https://github.com/user-attachments/assets/ffac5cd8-2923-4d9a-ae18-22f91e4c14a3" />

Event ID 10: ProcessAccess details process access events for detecting hacking tools targeting processes like Lsass.exe for credential theft.Sysmon Event 10: Process accessed, SourceImage AgentEXE.exe, TargetImage lsass.exe, SourceUser DESKTOP-R4PEEIF\waldo, TargetUser NT AUTHORITY\SYSTEM.

For instance, if we observe a random file ("AgentEXE" in this case) from a random folder ("Downloads" in this case) attempting to access LSASS, it indicates unusual behavior. Additionally, the SourceUser being different from the TargetUser (e.g., "waldo" as the SourceUser and "SYSTEM" as the TargetUser) further emphasizes the abnormality. It's also worth noting that as part of the mimikatz-based credential dumping process, the user must request SeDebugPrivileges. As the name suggests, it's primarily used for debugging. This can be another Indicator of Compromise (IOC).

Please note that some legitimate processes may access LSASS, such as authentication-related processes or security tools like AV or EDR.
