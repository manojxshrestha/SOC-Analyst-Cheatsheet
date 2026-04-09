# Detecting Windows Attacks with Splunk

## SOC Analyst Cheatsheet - Module 14/15

---

## 0. Overview

> 📌 **Detecting Windows Attacks with Splunk** - Advanced Windows and Active Directory attack detection using Splunk.

### Module Description

This module focuses on pinpointing attacks on Windows and Active Directory using Splunk. Participants will learn to identify Windows-based threats leveraging Windows Event Logs and Zeek network logs.

### What We'll Cover

| Category | Detection Techniques |
|----------|---------------------|
| **User/Domain Reconnaissance** | Native tools, BloodHound/SharpHound |
| **Password Attacks** | Password spraying, LLMNR poisoning, Kerberos brute force |
| **Credential Attacks** | Kerberoasting, AS-REProasting, Pass-the-hash, Overpass-the-Hash |
| **Ticket Attacks** | Pass-the-Ticket, Golden Tickets, Silver Tickets |
| **Delegation Attacks** | Unconstrained, Constrained delegation |
| **AD Attacks** | DCSync, DCShadow, Zerologon |
| **Network Attacks** | RDP brute force, Beaconing malware, Nmap scanning |
| **Exfiltration** | HTTP(S), DNS, Ransomware |

### Prerequisites

- Windows Event Logs & Finding Evil
- Understanding Log Sources & Investigating with Splunk
- Working with IDS/IPS

---

## Table of Contents

1. [Leveraging Windows Event Logs](#1-leveraging-windows-event-logs)
   - [Detecting Common User/Domain Recon](#detecting-common-userdomain-recon)
   - [Detecting Password Spraying](#detecting-password-spraying)
   - [Detecting Responder-like Attacks](#detecting-responder-like-attacks)
   - [Detecting Kerberoasting/AS-REProasting](#detecting-kerberoastingas-reproasting)
   - [Detecting Pass-the-Hash](#detecting-pass-the-hash)
   - [Detecting Pass-the-Ticket](#detecting-pass-the-ticket)
   - [Detecting Overpass-the-Hash](#detecting-overpass-the-hash)
   - [Detecting Golden Tickets/Silver Tickets](#detecting-golden-ticketssilver-tickets)
   - [Detecting Unconstrained/Constrained Delegation](#detecting-unconstrainedconstrained-delegation)
   - [Detecting DCSync/DCShadow](#detecting-dcsyncdcshadow)
2. [Creating Custom Splunk Applications](#2-creating-custom-splunk-applications)
3. [Leveraging Zeek Logs](#3-leveraging-zeek-logs)
   - [Detecting RDP Brute Force Attacks](#detecting-rdp-brute-force-attacks)
   - [Detecting Beaconing Malware](#detecting-beaconing-malware)
   - [Detecting Nmap Port Scanning](#detecting-nmap-port-scanning)
   - [Detecting Kerberos Brute Force Attacks](#detecting-kerberos-brute-force-attacks)
   - [Detecting Kerberoasting](#detecting-kerberoasting)
   - [Detecting Golden Tickets](#detecting-golden-tickets)
   - [Detecting Cobalt Strike's PSExec](#detecting-cobalt-strikes-psexec)
   - [Detecting Zerologon](#detecting-zerologon)
   - [Detecting Exfiltration (HTTP)](#detecting-exfiltration-http)
   - [Detecting Exfiltration (DNS)](#detecting-exfiltration-dns)
   - [Detecting Ransomware](#detecting-ransomware)

---

## 1. Leveraging Windows Event Logs

### Detecting Common User/Domain Recon {#detecting-common-userdomain-recon}

> 📌 **Domain Reconnaissance** - A pivotal stage in the cyberattack lifecycle where adversaries gather information about the target environment.

#### Domain Reconnaissance Overview

Active Directory (AD) domain reconnaissance represents a pivotal stage in the cyberattack lifecycle. During this phase, adversaries endeavor to gather information about the target environment, seeking to comprehend its architecture, network topology, security measures, and potential vulnerabilities.

While conducting AD domain reconnaissance, attackers focus on identifying crucial components such as:
- Domain Controllers
- User accounts
- Groups
- Trust relationships
- Organizational units (OUs)
- Group policies
- Other vital objects

> 📌 By gaining insights into the AD environment, attackers can pinpoint high-value targets, escalate privileges, and move laterally within the network.

---

### User/Domain Reconnaissance Using Native Windows Executables

An example of AD domain reconnaissance is when an adversary executes the `net group` command to obtain a list of Domain Administrators.

![net group Domain Admins](https://github.com/user-attachments/assets/9cafb44e-cbec-47e8-9dc6-04c800022b2d)

*Command prompt output showing 'net group "Domain Admins" /domain' for domain 'lab.internal.local'*

#### Common Native Tools/Commands

| Command | Description |
|---------|-------------|
| `whoami /all` | Display user and group information |
| `wmic computersystem get domain` | Get domain information |
| `net user /domain` | List all domain users |
| `net group "Domain Admins" /domain` | List Domain Admins group members |
| `arp -a` | Display ARP cache |
| `nltest /domain_trusts` | List domain trust relationships |

> 📌 For detection, administrators can employ PowerShell to monitor for unusual scripts or cmdlets and process command-line monitoring.

---

### User/Domain Reconnaissance Using BloodHound/SharpHound

**BloodHound** is an open-source domain reconnaissance tool created to analyze and visualize the Active Directory (AD) environment. It is frequently employed by attackers to discern attack paths and potential security risks within an organization's AD infrastructure.

![BloodHound Graph](https://github.com/user-attachments/assets/3c766987-ade7-4c0c-ad8f-e47c526519f7)

*BloodHound network graph showing relationships between AD objects*

**SharpHound** is a C# data collector for BloodHound. An example of usage includes an adversary running SharpHound with all collection methods:

![SharpHound Execution](https://github.com/user-attachments/assets/72602bed-898e-420d-bc52-3c6552dc3327)

*SharpHound3.exe execution showing data collection for LAB.INTERNAL.LOCAL*

---

### BloodHound Detection Opportunities

Under the hood, the BloodHound collector executes numerous LDAP queries directed at the Domain Controller, aiming to amass information about the domain.

![LDAP Query Code](https://github.com/user-attachments/assets/45b412e5-4629-497f-9c43-61f2d6f97c81)

*Code snippet showing BloodHound LDAP queries*

#### Event 1644 - LDAP Performance Monitoring

By default, the Windows Event Log does not record LDAP queries. The best option Windows can suggest is employing **Event 1644** - the LDAP performance monitoring log.

![Event 1644 Details](https://github.com/user-attachments/assets/fb0fe35a-11c9-4b82-b15d-bd7b875ff24f)

*Event 1644 showing LDAP search operation details*

**Even with Event 1644 enabled, BloodHound may not generate many of the expected events.**

---

### Using SilkETW for LDAP Monitoring

A more reliable approach is to utilize the Windows ETW provider **Microsoft-Windows-LDAP-Client**. 

> 📌 **SilkETW & SilkService** are versatile C# wrappers for ETW, designed to simplify the intricacies of ETW, providing an accessible interface for research and introspection.

SilkService supports output to the Windows Event Log, which streamlines log digestion. Another useful feature is the ability to employ Yara rules for hunting suspicious LDAP queries.

![SilkETW Execution](https://github.com/user-attachments/assets/38405a0a-6d0d-4089-8faf-a167c5b811ac)

*SilkETW running with Yara rules to detect suspicious LDAP queries*

---

### Common LDAP Filters Used by Recon Tools

Microsoft's ATP team has compiled a list of LDAP filters frequently used by reconnaissance tools:

![LDAP Filters Table](https://github.com/user-attachments/assets/438c3710-4d26-4d6a-9ad9-66529f2a75b2)

*Table listing recon tools and their LDAP filters*

| Tool | LDAP Filter |
|------|-------------|
| Metasploit enum_ad_user_comments | (samAccountType=805306368) |
| Metasploit enum_ad_computers | (objectClass=computer) |
| Metasploit enum_ad_groups | (objectClass=group) |
| PowerView Get-NetComputer | (operatingsystem=*) |
| PowerView Get-NetUser | (samAccountType=805306368) |
| PowerView Get-DFSSHareV2 | (objectClass=*) |

> 📌 Armed with this list of LDAP filters, BloodHound activity can be detected more efficiently.

---

### Detecting User/Domain Recon With Splunk

> 📌 A specific timeframe is given when identifying each attack to concentrate on relevant events, avoiding overwhelming volume of unrelated events.

---

### Detecting Recon By Targeting Native Windows Executables

**Timeframe:** earliest=1690447949 latest=1690450687

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

![Native Commands Detection](https://github.com/user-attachments/assets/28b2890d-04a4-4883-b746-6421b5a6ad38)

*Splunk search results showing command execution logs*

#### Search Breakdown

1. **Filtering by Index and Source**: Select events from `main` index where source is `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

2. **EventID Filter**: Filter to only select events with Event ID 1 (Sysmon Process Creation)

3. **Time Range Filter**: Restrict to Unix timestamps 1690447949 to 1690450687

4. **Process Name Filter**: 
   - Include: arp.exe, chcp.com, ipconfig.exe, net.exe, net1.exe, nltest.exe, ping.exe, systeminfo.exe, whoami.exe
   - OR cmd.exe/powershell.exe with suspicious process strings

5. **Statistics**: Aggregate by parent_process, parent_process_id, dest, user

6. **Filtering by Process Count**: Only include where mvcount(process) > 3

---

### Detecting Recon By Targeting BloodHound

**Timeframe:** earliest=1690195896 latest=1690285475

```spl
index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

![BloodHound Detection](https://github.com/user-attachments/assets/9597aac3-0db8-4932-a660-e2226fa61a0f)

*Splunk search results showing SharpHound detection*

#### Search Breakdown

1. **Filtering by Index and Source**: Select events from `WinEventLog:SilkService-Log`

2. **Path Extraction**: Use `spath` to extract fields from Message field

3. **Field Renaming**: Rename XmlEventData.* fields to simple names

4. **Tabulating Results**: Display _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter

5. **Search Filter**: Filter for `(samAccountType=805306368)` - user account LDAP query

6. **Statistics**: Aggregate by ComputerName, ProcessName, ProcessId

7. **Filtering by Event Count**: Only include where count > 10

8. **Time Conversion**: Convert maxTime to human-readable format

> 📌 This search detects SharpHound activity by identifying excessive LDAP queries with user account filters.

---

### Detecting Password Spraying {#detecting-password-spraying}

#### Password Spraying Overview

Unlike traditional brute-force attacks, where an attacker tries numerous passwords for a single user account, **password spraying** distributes the attack across multiple accounts using a limited set of commonly used or easily guessable passwords.

> 📌 The primary goal is to evade account lockout policies typically instituted by organizations. These policies usually lock an account after a specified number of unsuccessful login attempts to thwart brute-force attacks on individual accounts.

**However, password spraying lowers the chance of triggering account lockouts**, as each user account receives only a few password attempts, making the attack less noticeable.

![Password Spraying Tool](https://github.com/user-attachments/assets/3fbaab8e-a7d6-4fba-8bfe-7b96753d3ddb)

*Spray 2.1 password spraying tool by Jacob Wilkin*

---

#### Password Spraying Detection Opportunities

Detecting password spraying through Windows logs involves the analysis and monitoring of specific event logs to identify patterns and anomalies indicative of such an attack.

> 📌 **Common Pattern**: Multiple failed logon attempts with Event ID 4625 - Failed Logon from different user accounts but originating from the same source IP address within a short time frame.

#### Event Logs for Password Spraying Detection

| Event ID | Description | Error Code | Meaning |
|----------|-------------|------------|---------|
| 4625 | Failed Logon | Various | Failed logon attempt |
| 4768 | Kerberos TGT Request | 0x6 | Kerberos Invalid Users |
| 4768 | Kerberos TGT Request | 0x12 | Kerberos Disabled Users |
| 4776 | NTLM Authentication | 0xC0000064 | NTLM Invalid Users |
| 4776 | NTLM Authentication | 0xC000006A | NTLM Wrong Password |
| 4648 | Explicit Credentials | - | Logon using explicit credentials |
| 4771 | Kerberos Pre-Auth | - | Kerberos Pre-Authentication Failed |

---

### Detecting Password Spraying With Splunk

**Timeframe:** earliest=1690280680 latest=1690289489

```spl
index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

![Password Spraying Detection](https://github.com/user-attachments/assets/6260ec5e-bdb7-4b75-b68f-386d616cd5f9)

*Splunk search results showing password spraying from KALI (10.10.0.201)*

#### Search Breakdown

1. **Filtering by Index, Source, and EventCode**: Select events from `WinEventLog:Security` where EventCode is **4625** (Failed Logon)

2. **Time Range Filter**: Restrict to Unix timestamps 1690280680 to 1690289489

3. **Time Binning**: Use `bin span=15m` to create 15-minute time buckets

4. **Statistics**: Aggregate by:
   - `src` - Source computer
   - `Source_Network_Address` - Source IP
   - `dest` - Destination computer
   - `EventCode` - Event type
   - `Failure_Reason` - Why logon failed
   
   Calculate:
   - `values(user) as Users` - All attempted usernames
   - `dc(user) as dc_user` - Distinct count of users (key indicator!)

> 📌 **Key Detection**: High dc_user (distinct user count) from single IP indicates password spraying!

---

### Detecting Responder-like Attacks {#detecting-responder-like-attacks}

#### LLMNR/NBT-NS/mDNS Poisoning Overview

**LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)** poisoning, also referred to as NBNS spoofing, are network-level attacks that exploit inefficiencies in these name resolution protocols.

Both LLMNR and NBT-NS are used to resolve hostnames to IP addresses on local networks when the fully qualified domain name (FQDN) resolution fails. However, their lack of built-in security mechanisms renders them susceptible to spoofing and poisoning attacks.

> 📌 Typically, attackers employ the **Responder** tool to execute LLMNR, NBT-NS, or mDNS poisoning.

#### Attack Steps

1. A victim device sends a name resolution query for a mistyped hostname (e.g., `fileshrae`)
2. DNS fails to resolve the mistyped hostname
3. The victim device sends a name resolution query for the mistyped hostname using LLMNR/NBT-NS
4. The attacker's host responds to the LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic, pretending to know the identity of the requested host

![LLMNR/NBT-NS Attack](https://github.com/user-attachments/assets/049c04a3-44b7-48d2-996a-993129a0d2a2)

*DNS resolution process showing LLMNR/NBT-NS/mDNS fallback*

> 📌 The result of a successful attack is the acquisition of the victim's **NetNTLM hash**, which can be either cracked or relayed in an attempt to gain access to systems where these credentials are valid.

---

#### Responder Detection Opportunities

Detecting LLMNR, NBT-NS, and mDNS poisoning can be challenging. However, organizations can mitigate the risk by implementing the following measures:

1. **Network Monitoring**: Deploy solutions to detect unusual LLMNR and NBT-NS traffic patterns, such as an elevated volume of name resolution requests from a single source

2. **Honeypot Approach**: Name resolution for non-existent hosts should fail. If an attacker is present and spoofing LLMNR/NBT-NS/mDNS responses, name resolution will succeed.

![LLMNR Detection Script](https://github.com/user-attachments/assets/3be4edbb-7609-421e-8efb-a82491eb7bc6)

*PowerShell script for detecting LLMNR/NBT-NS spoofing*

#### Creating LLMNR Detection Event Log

```powershell
PS C:\Users\Administrator> New-EventLog -LogName Application -Source LLMNRDetection
```

```powershell
PS C:\Users\Administrator> Write-EventLog -LogName Application -Source LLMNRDetection -EventId 19001 -Message $msg -EntryType Warning
```

---

### Detecting Responder-like Attacks With Splunk

#### Method 1: LLMNR Detection Event Log

**Timeframe:** earliest=1690290078 latest=1690291207

```spl
index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

![LLMNR Detection Splunk](https://github.com/user-attachments/assets/be22ffe9-6e77-40fb-85c8-682889a0b020)

*Splunk results showing LLMNR server IPs*

#### Method 2: Sysmon Event ID 22 (DNS Queries)

**Sysmon Event ID 22** can also be utilized to track DNS queries associated with non-existent/mistyped file shares.

**Timeframe:** earliest=1690290078 latest=1690291207

```spl
index=main earliest=1690290078 latest=1690291207 EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

![Sysmon DNS Queries](https://github.com/user-attachments/assets/7f121fe0-e171-4cba-b69c-a9cde96ba1cd)

*Log entry showing mistyped file share query "myfileshar3"*

> 📌 Look for QueryName patterns like "fileshar*" with QueryResults pointing to attacker IP

---

#### Method 3: Event 4648 (Explicit Credentials)

**Event 4648** can be used to detect explicit logons to rogue file shares which attackers might use to gather legitimate user credentials.

**Timeframe:** earliest=1690290814 latest=1690291207

```spl
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

![Event 4648 Detection](https://github.com/user-attachments/assets/1fd6888d-b203-4415-a5c4-f61591c23a29)

*Splunk results showing explicit credentials logon to target server*

> 📌 **Key Detection**: Event 4648 shows when a user explicitly provides credentials to access a resource - look for unusual Target_Server_Name values

---

*Module 14/15 - Detecting Windows Attacks with Splunk*
*For learning and SOC career preparation*

---

### Detecting Kerberoasting/AS-REProasting {#detecting-kerberoastingas-reproasting}

#### Kerberoasting Overview

**Kerberoasting** is a technique targeting service accounts in Active Directory environments to extract and crack their password hashes. The attack exploits the way Kerberos service tickets are encrypted and the use of weak or easily crackable passwords for service accounts.

> 📌 Once an attacker successfully cracks the password hashes, they can gain unauthorized access to the targeted service accounts and potentially move laterally within the network.

![Rubeus Kerberoasting](https://github.com/user-attachments/assets/f69bf157-ac46-4573-a5f8-9025e0d6a93c)

*Rubeus kerberoast module identifying service account "iis_svc"*

#### Kerberoasting Attack Steps

1. **Identify Target Service Accounts**: Attacker enumerates AD to identify service accounts with SPNs (Service Principal Names)

2. **Request TGS Tickets**: Attacker requests TGS tickets from KDC - these contain encrypted service account password hashes

3. **Offline Brute-Force**: Attacker uses Hashcat or John the Ripper to crack the encrypted password hashes

---

#### Benign Service Access Process & Related Events

When a user connects to MSSQL using a service account with SPN:

1. **TGT Request**: Client requests TGT from KDC
2. **TGT Issue**: KDC verifies identity and issues TGT
3. **Service Ticket Request**: Client requests TGS for MSSQL SPN
4. **Service Ticket Issue**: KDC issues TGS encrypted with service account's secret key
5. **Client Connection**: Client presents TGS to MSSQL server
6. **MSSQL Server Validates**: Server decrypts TGS and grants access

![Kerberos Process](https://github.com/user-attachments/assets/4e812dc3-03ac-42b5-856f-f8f679816cee)

*Kerberos authentication process diagram*

#### Kerberos Events Generated

| Event ID | Description |
|----------|-------------|
| 4768 | Kerberos TGT Request |
| 4769 | Kerberos Service Ticket Request |
| 4624 | Successful Logon |

![Kerberos Events](https://github.com/user-attachments/assets/0c496630-0f6e-47a1-b50a-e4527485b0e0)

*Log entries showing Kerberos authentication events*

---

#### Kerberoasting Detection Opportunities

**Detection Logic**: Find all TGS request events and logon events from same user, then identify instances where TGS request exists WITHOUT subsequent logon event.

> 📌 In benign service access, an additional Event 4648 (Explicit Credentials) is generated along with the logon event.

---

### Detecting Kerberoasting With Splunk

#### Benign TGS Requests

**Timeframe:** earliest=1690388417 latest=1690388630

```spl
index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) 
| dedup RecordNumber 
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
```

![Benign TGS](https://github.com/user-attachments/assets/9356d3e2-26b2-4059-bc5d-61b6cefc2139)

*Benign service access showing Event 4648 and 4769*

---

#### Detecting Kerberoasting - SPN Querying

**Timeframe:** earliest=1690448444 latest=1690454437

```spl
index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

![SPN Querying](https://github.com/user-attachments/assets/cc3a67e0-2a11-445f-aa32-722300bdd74c)

*Detecting SPN enumeration via LDAP queries*

---

#### Detecting Kerberoasting - TGS Requests

**Timeframe:** earliest=1690450374 latest=1690450483

```spl
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

![Kerberoast Detection](https://github.com/user-attachments/assets/72da0ea8-f978-4649-a50b-23cb2c68ab8d)

*Kerberoasting detection - TGS without logon*

#### Search Breakdown

1. **Filter Events**: EventCode=4648 OR (4769 AND service_name=iis_svc)
2. **Dedup**: Remove duplicate records
3. **Extract Username**: Use regex to get username from user field
4. **Time Binning**: Bin events into 2-minute intervals
5. **Filter**: Exclude machine accounts (username!=*$)
6. **Stats**: Group by time and username
7. **Filter**: Exclude events with 4648 (benign access)

> 📌 **Key Detection**: TGS requests (4769) WITHOUT corresponding logon (4648) indicates Kerberoasting!

---

#### Using Transactions for Detection

**Timeframe:** earliest=1690450374 latest=1690450483

```spl
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$ 
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769) 
| where closed_txn=0 AND EventCode = 4769
| table _time, EventCode, service_name, username
```

![Transaction Detection](https://github.com/user-attachments/assets/5d8391e9-a7ef-4c50-9d99-6553add319f7)

*Using transaction command to detect incomplete transactions*

---

### AS-REPRoasting

**ASREPRoasting** targets user accounts without pre-authentication enabled. In Kerberos, pre-authentication is a security feature requiring users to prove their identity before TGT is issued.

![AS-REP Roasting](https://github.com/user-attachments/assets/21e3126f-1e84-4348-a4f5-ac19a66888ad)

*Rubeus AS-REP roasting*

#### AS-REPRoasting Attack Steps

1. **Identify Target User Accounts**: Find accounts without pre-authentication
2. **Request AS-REQ Service Tickets**: Request TGT for each target user
3. **Offline Brute-Force**: Crack the encrypted TGTs

---

#### Kerberos Pre-Authentication

When pre-authentication is enabled, the AS-REQ contains an encrypted timestamp (pA-ENC-TIMESTAMP). The KDC decrypts this to issue a TGT.

![Pre-Auth Enabled](https://github.com/user-attachments/assets/a14a6aea-8c8e-41fe-894f-f9780352a9ce)

*Network capture showing pre-authentication enabled*

When pre-authentication is **disabled**, no timestamp validation occurs, allowing TGT requests without knowing the password.

![Pre-Auth Disabled](https://github.com/user-attachments/assets/053db5aa-0124-4c6c-b0bf-72a8f8a09054)

*Network capture showing pre-authentication disabled*

---

### Detecting AS-REPRoasting With Splunk

#### Detecting AS-REPRoasting - Accounts With Pre-Auth Disabled

**Timeframe:** earliest=1690392745 latest=1690393283

```spl
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

![Pre-Auth Disabled Query](https://github.com/user-attachments/assets/554b8980-fb12-4b14-878d-42bd91abe245)

*Detecting accounts with pre-auth disabled*

---

#### Detecting AS-REPRoasting - TGT Requests For Pre-Auth Disabled Accounts

**Timeframe:** earliest=1690392745 latest=1690393283

```spl
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

![AS-REP Detection](https://github.com/user-attachments/assets/35595945-ae0b-4eae-9454-9fcdf7d7372a)

*Detecting AS-REP roasting via Event 4768*

#### Search Breakdown

1. **Filter**: EventCode=4768 with Pre_Authentication_Type=0
2. **Extract IP**: Use regex to handle IPv4-mapped IPv6 addresses
3. **Table**: Display time, IP, user, PreAuthType, TicketOptions, EncryptionType

> 📌 **Key Detection**: Event 4768 with Pre_Authentication_Type=0 indicates AS-REPRoasting attempt!

---

### Detecting Pass-the-Hash {#detecting-pass-the-hash}

#### Pass-the-Hash Overview

**Pass-the-Hash (PtH)** is a technique used by attackers to authenticate to a networked system using the NTLM hash of a user's password instead of the plaintext password. This attack exploits how Windows stores password hashes in memory, enabling adversaries with administrative access to capture the hash and reuse it for lateral movement.

> 📌 Pass-the-Hash allows attackers to move laterally within the network without knowing the actual password.

![Mimikatz Password Hash](https://github.com/user-attachments/assets/9f6c3892-2398-4792-aba1-2df4307dd963)

*Mimikatz output showing NTLM hash extraction*

#### Pass-the-Hash Attack Steps

1. **Extract NTLM Hash**: Attacker uses tools like Mimikatz to extract the NTLM hash of a user currently logged onto the compromised system (requires local admin privileges)

![Mimikatz Pass-the-Hash](https://github.com/user-attachments/assets/2573a0aa-f0a8-4d38-a46b-f1844cbdaacc)

*Mimikatz performing pass-the-hash impersonation*

2. **Authenticate with Hash**: Using the NTLM hash, attacker authenticates as the targeted user on other systems without knowing the password

3. **Lateral Movement**: Attacker uses the authenticated session to move laterally within the network

![Lateral Movement](https://github.com/user-attachments/assets/6f566124-be34-4c8a-a7bc-5679517da6d1)

*Accessing remote system with stolen credentials*

---

#### Windows Access Tokens & Alternate Credentials

An **access token** is a data structure that defines the security context of a process or thread. It contains information about the user's identity and privileges. When a user logs on, the system generates an access token that is assigned to all processes executed on behalf of that user.

**Alternate Credentials** allow users to supply different login credentials for specific actions without altering the primary login session. The `runas` command is commonly used for this purpose.

![runas Example](https://github.com/user-attachments/assets/815e6d77-b04c-4602-ab31-c9e48cd36896)

*Using runas to execute commands as different user*

The `/netonly` flag indicates credentials are for remote access only. Even when `whoami` returns the original username, spawned processes can access remote resources with the alternate credentials.

![runas netonly](https://github.com/user-attachments/assets/940adcdd-4fca-4bcf-929a-87a901e1981a)

*Using runas /netonly for remote access*

Each access token references a **LogonSession** generated at user logon. This contains Username, Domain, and AuthenticationID (NTHash/LMHash). When accessing remote resources, the LogonSession credentials are used.

![LogonSession Diagram](https://github.com/user-attachments/assets/04f70388-a096-459b-a1cb-01ac7ad68981)

*Process access token and LogonSession flow*

---

#### Pass-the-Hash Detection Opportunities

From the Windows Event Log perspective, the following logs are generated:

| Scenario | Event ID | Logon Type |
|----------|----------|------------|
| runas without /netonly | 4624 | 2 (Interactive) |
| runas with /netonly | 4624 | 9 (NewCredentials) |

![Event 4624 LogonType 2](https://github.com/user-attachments/assets/2b5ac258-ace7-4680-9c04-c9ff1ebd4568)

*Security events showing interactive logon*

![Event 4624 LogonType 9](https://github.com/attachments/assets/09c3d91b-4ec6-4f8c-8dd6-a56264b4caeb)

*Security events showing NewCredentials logon*

> 📌 **Simple Detection**: Event ID 4624 with LogonType 9 (NewCredentials) - but may have false positives from legitimate runas usage

**Enhanced Detection**: The key difference between runas /netonly and Pass-the-Hash is that Mimikatz accesses LSASS process memory to modify LogonSession credential materials. Correlate:
- Event 4624 LogonType 9 with Sysmon Event Code 10 (Process Access) targeting lsass.exe

---

#### Detecting Pass-the-Hash With Splunk

##### Method 1: Basic Detection - LogonType 9

**Timeframe:** earliest=1690450708 latest=1690451116

```spl
index=main earliest=1690450708 latest=1690451116 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

![LogonType 9 Detection](https://github.com/user-attachments/assets/1c2a5b3c-83dc-4bd9-8b17-e17ae33e7ae8)

*Detecting NewCredentials logon events*

---

##### Method 2: Enhanced Detection - LSASS Access + LogonType 9

**Timeframe:** earliest=1690450689 latest=1690451116

```spl
index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

![Enhanced Detection](https://github.com/user-attachments/assets/6f071dc8-f9b8-431f-ba81-276015a1239e)

*Correlating LSASS access with NewCredentials logon*

**Search Breakdown:**

1. **Sysmon Filter**: EventCode=10 (Process Access) targeting lsass.exe, excluding Windows Defender
2. **Security Filter**: EventCode=4624 with LogonType=9 and Logon_Process=seclogo
3. **Sort**: Order by time and record number
4. **Transaction**: Group events within 1 minute, ending with logon event
5. **Stats**: Aggregate and display relevant fields

> 📌 **Key Detection**: Correlating lsass.exe process access (Sysmon 10) with LogonType 9 events identifies Pass-the-Hash attacks!

---

### Detecting Pass-the-Ticket {#detecting-pass-the-ticket}

#### Pass-the-Ticket Overview

**Pass-the-Ticket (PtT)** is a lateral movement technique that abuses Kerberos TGT (Ticket Granting Ticket) and TGS (Ticket Granting Service) tickets. Instead of using NTLM hashes, PtT leverages Kerberos tickets to authenticate to other systems without knowing the user's passwords.

> 📌 PtT allows attackers to move laterally across multiple systems using valid Kerberos tickets extracted from memory.

![Rubeus Ticket Monitoring](https://github.com/user-attachments/assets/2a520da7-1feb-4f2e-97e0-e840b429f543)

*Rubeus monitoring for new TGTs*

#### Pass-the-Ticket Attack Steps

1. **Gain Access**: Attacker gains administrative access to a system through initial compromise or privilege escalation

2. **Extract Tickets**: Attacker uses tools like Mimikatz or Rubeus to extract valid TGT or TGS tickets from the compromised system's memory

![Rubeus PTT](https://github.com/user-attachments/assets/8220cf02-54e6-46fd-9050-b64f5697408d)

*Rubeus passing a ticket*

3. **Import Ticket**: Attacker submits the extracted ticket for the current logon session

![klist Output](https://github.com/user-attachments/assets/a19f0044-b0d4-4bc4-b260-7b585385652c)

*Cached Kerberos ticket after pass-the-ticket*

4. **Access Resources**: Attacker can now authenticate to other systems without plaintext passwords

---

#### Kerberos Authentication Process

Kerberos is a network authentication protocol used in Windows Active Directory environments:

1. **Request TGT**: Client requests TGT from KDC (Key Distribution Center)
2. **Receive TGT**: KDC verifies identity and issues TGT encrypted with user's secret key
3. **Request TGS**: Client requests service ticket (TGS) for target service
4. **Receive TGS**: KDC issues TGS encrypted with service account's secret key
5. **Present TGS**: Client presents TGS to server for authentication

![Kerberos Process](https://github.com/user-attachments/assets/148a77b9-41b2-47a1-bbce-bd13d50ce655)

*Kerberos authentication process diagram*

---

#### Related Windows Security Events

| Event ID | Description |
|----------|-------------|
| 4648 | Explicit Credential Logon Attempt |
| 4624 | Successful Logon |
| 4672 | Special Logon (admin privileges) |
| 4768 | Kerberos TGT Request |
| 4769 | Kerberos Service Ticket Request |
| 4770 | Kerberos Service Ticket Renewed |

![Kerberos Events](https://github.com/user-attachments/assets/b1a4d776-0b87-4c8a-bfcd-7cabd71aeda2)

*Log entries showing Kerberos authentication events*

---

#### Pass-the-Ticket Detection Opportunities

Detecting PtT is challenging because attackers use valid Kerberos tickets. The key distinction is that during PtT, the Kerberos authentication process is partial:

- Attacker imports a TGT ticket into a logon session
- Requests a TGS ticket for a remote service
- From DC perspective, the imported TGT was never requested from attacker's system (no Event ID 4768)

![PtT Process](https://github.com/user-attachments/assets/b6041d04-25e6-47a0-aa1a-85290e48969f)

*Kerberos process with imported TGT*

**Detection Approaches:**

1. **Missing TGT Request**: Look for Event ID 4769 (TGS Request) or 4770 (Ticket Renewed) WITHOUT prior Event ID 4768 (TGT Request) from same system

2. **Host/Service ID Mismatches**: Look for mismatches between Service and Host IDs (Event 4769) and actual Source/Destination IPs (Event ID 3)

3. **Pre-Authentication Failures**: Review Event ID 4771 for mismatches between Pre-Authentication type and Failure Code (e.g., type 2 with failure 0x18)

> 📌 These detection opportunities should be enhanced with behavior-based detection - context is vital to reduce false positives.

---

#### Detecting Pass-the-Ticket With Splunk

**Timeframe:** earliest=1690451665 latest=1690451745

```spl
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

![PtT Detection](https://github.com/user-attachments/assets/888dfe3e-e666-421d-a4ff-d70b04e9166f)

*Detecting TGS requests without prior TGT*

**Search Breakdown:**

1. **Filter Events**: EventCode IN (4768, 4769, 4770), exclude machine accounts (user!=*$)
2. **Extract Username**: Regex to get username from user field
3. **Extract IP**: Handle IPv4-mapped IPv6 addresses
4. **Transaction**: Group by username and IP, start with TGT request (4768), max 10 hours
5. **Filter**: Only open transactions (no ending event)
6. **Table**: Display relevant fields

> 📌 **Key Detection**: Open transactions with TGS (4769) or ticket renewal (4770) but NO TGT request (4768) indicates Pass-the-Ticket!

---

### Detecting Overpass-the-Hash {#detecting-overpass-the-hash}

#### Overpass-the-Hash Overview

**Overpass-the-Hash** (also known as **Pass-the-Key**) allows attackers to obtain Kerberos TGTs using stolen password hashes. This technique enables authentication via Kerberos rather than NTLM, using either NTLM hashes or AES keys as the basis for requesting a TGT.

> 📌 Overpass-the-Hash is stealthier than Pass-the-Hash because it doesn't require elevated privileges on the host to request the TGT.

![Mimikatz Hash Extraction](https://github.com/user-attachments/assets/d7ceeb8a-448d-4e24-a40f-37ad39722c70)

*Mimikatz extracting NTLM hash*

#### Overpass-the-Hash Attack Steps

1. **Extract Hash**: Attacker uses Mimikatz to extract NTLM hash of logged-in user (requires local admin privileges)

2. **Request TGT**: Attacker uses Rubeus to craft raw AS-REQ request for specified user to request a TGT ticket

![Rubeus TGT Request](https://github.com/user-attachments/assets/2c5caa20-a34d-47ee-8971-b2e5875f063a)

*Rubeus requesting TGT using RC4 hash*

3. **Submit Ticket**: Attacker submits the requested ticket for the current logon session (same as Pass-the-Ticket)

---

#### Overpass-the-Hash Detection Opportunities

| Tool | Detection Method |
|------|-------------------|
| **Mimikatz** | Same artifacts as Pass-the-Hash (Event 4624 LogonType 9 + Sysmon Event 10) |
| **Rubeus** | Sends AS-REQ directly to DC, generates Event 4768 (TGT Request). May not trigger PtT detection unless TGT is used on another host |

**Rubeus Detection Strategy:**
- Communication with DC (TCP/UDP port 88) from unusual processes
- Rubeus directly sends AS-REQ to Domain Controller, generating Event ID 4768

> 📌 Overpass-the-Hash using Rubeus can be detected by monitoring network connections to port 88 from processes other than lsass.exe

---

#### Detecting Overpass-the-Hash With Splunk

**Timeframe:** earliest=1690443407 latest=1690443544

```spl
index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

![Overpass Detection](https://github.com/user-attachments/assets/8a6bbb8e-bf49-4c7c-baee-75a75db3b26c)

*Detecting network connections to port 88*

**Search Breakdown:**

1. **Filter**: Sysmon EventCode=3 (network connection) to dest_port=88, excluding lsass.exe
2. **EventStats**: Get process names by process_id
3. **Filter**: Only network events
4. **Stats**: Display time, computer, dest IP/port, image, process

> 📌 **Key Detection**: Network connections to Kerberos port (88) from processes other than lsass.exe indicates potential Overpass-the-Hash!

---

### Detecting Golden Tickets/Silver Tickets {#detecting-golden-ticketssilver-tickets}

#### Golden Ticket Overview

A **Golden Ticket** is a forged Ticket Granting Ticket (TGT) that grants unauthorized access to a Windows Active Directory domain as a domain administrator. Attackers create a TGT with arbitrary user credentials and domain admin privileges, gaining full control over the domain.

> 📌 Golden Tickets are stealthy and persistent - they have long validity periods and remain valid until expiration or revocation.

![KRBTGT Hash Extraction](https://github.com/user-attachments/assets/89fec40a-5a97-4e1c-8aca-1d25ff41ec2f)

*Extracting KRBTGT account hash via DCSync*

#### Golden Ticket Attack Steps

1. **Extract KRBTGT Hash**: Attacker extracts NTLM hash of KRBTGT account via DCSync attack, NTDS.dit, or LSASS dumps on DC

2. **Forge TGT**: Using the KRBTGT hash, attacker forges a TGT for an arbitrary user with domain admin privileges

![Golden Ticket Creation](https://github.com/user-attachments/assets/c71c2965-6a9f-4468-a9d3-0c06512ba803)

*Mimikatz creating Golden Ticket*

3. **Inject Ticket**: Attacker injects the forged TGT (same as Pass-the-Ticket)

---

#### Golden Ticket Detection Opportunities

Detecting Golden Tickets is challenging since TGTs can be forged offline without leaving Mimikatz execution traces.

| Detection Method | Description |
|-----------------|-------------|
| DCSync Attack | Monitor for replication requests to KRBTGT |
| NTDS.dit Access | Monitor file access on domain controllers |
| LSASS Memory Read | Sysmon Event ID 10 on DC |
| Pass-the-Ticket | Same detection applies - look for tickets without proper TGT requests |

> 📌 Golden Tickets are just another ticket - use Pass-the-Ticket detection logic (Event 4769 without prior 4768)

---

#### Detecting Golden Tickets With Splunk

**Timeframe:** earliest=1690451977 latest=1690452262

```spl
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

![Golden Ticket Detection](https://github.com/user-attachments/assets/bac6e91f-bf8d-4c7c-baee-75a75db3b26c)

*Detecting anomalous ticket usage*

---

#### Silver Ticket Overview

**Silver Tickets** are forged Ticket Granting Service (TGS) tickets for a specific service account (e.g., MSSQL, SharePoint). While more limited than Golden Tickets (only access to specific resource), they can still impersonate any user.

> 📌 Silver Tickets are forged offline using the password hash of the target service account.

![Silver Ticket Creation](https://github.com/user-attachments/assets/c403c055-5367-44e6-b0ab-911ce14a7dbd)

*Mimikatz creating Silver Ticket*

#### Silver Ticket Attack Steps

1. **Extract Service Hash**: Attacker extracts NTLM hash of target service account using Mimikatz or other credential dumping

2. **Forge TGS**: Using the service account hash, attacker creates a forged TGS ticket for the specified service

![Silver Ticket Usage](https://github.com/user-attachments/assets/28b58da2-e871-4ccf-961a-b1fd9aaa7df5)

*Injecting and using Silver Ticket*

3. **Access Resource**: Attacker accesses the specific service with forged ticket

---

#### Silver Ticket Detection Opportunities

Detecting forged TGS tickets is challenging - no simple indicators exist. Both Golden and Silver Tickets can use arbitrary (including non-existent) users.

| Event ID | Description |
|----------|-------------|
| 4720 | User account was created - identify newly created users |
| 4672 | Special Logon - detect anomalously assigned privileges |
| 4624 | Successful logon - correlate with new users |

> 📌 Compare newly created users (4720) with logged-in users to identify suspicious activity

---

#### Detecting Silver Tickets With Splunk

##### Method 1: User Correlation - New Users Logging In

First, create a list of newly created users:

```spl
index=main latest=1690448444 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

Then compare with logged-in users:

```spl
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h = 1690451977
| where firstTime > last24h
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

![User Correlation](https://github.com/user-attachments/assets/a63bc3dc-f847-4d84-b6f3-2a1ff30f4527)

*Detecting logins from users not in the new users list*

---

##### Method 2: Special Privileges Assigned To New Logon

```spl
index=main latest=1690545656 EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = 1690451977 
| where firstTime > last24h 
| table firstTime, ComputerName, Account_Name 
| convert ctime(firstTime)
```

![Special Privileges](https://github.com/user-attachments/assets/8e991c70-ec90-4900-87ec-32b1c7f8d527)

*Detecting special privileges assigned to recent logons*

**Search Breakdown:**

1. **User Correlation**: 
   - Create list of newly created users (Event 4720)
   - Compare with logged-in users (Event 4624)
   - Find users logging in who were never created

2. **Special Privileges**:
   - Find Event 4672 (Special Logon) for recent logons
   - Identify anomalously assigned privileges

> 📌 **Key Detection**: Users logging in without being created (Event 4720 → 4624) or receiving special privileges (4672) shortly after first logon may indicate Silver Ticket usage!

---

### Detecting Unconstrained/Constrained Delegation {#detecting-unconstrainedconstrained-delegation}

#### Unconstrained Delegation Overview

**Unconstrained Delegation** allows a service to authenticate to another resource on behalf of any user. This is necessary when a web server needs to access a database on behalf of a user, for example.

![Unconstrained Delegation Settings](https://github.com/user-attachments/assets/69e5fad9-8612-4532-bb31-fe4509f0414c)

*Unconstrained delegation enabled on IIS server*

#### Unconstrained Delegation Attack Steps

1. **Identify Target**: Attacker finds systems with Unconstrained Delegation enabled

![Discovery](https://github.com/user-attachments/assets/9303345a-36f9-4284-8d9f-e8638d2af45a)

*PowerShell discovering Unconstrained Delegation*

2. **Gain Access**: Attacker gains access to a system with Unconstrained Delegation enabled

3. **Extract TGT**: Attacker extracts TGT tickets from memory using Mimikatz/Rubeus

![TGT Extraction](https://github.com/user-attachments/assets/eea50ae1-9e86-49bc-b6dc-a2207849736f)

*Rubeus extracting TGT*

---

#### Kerberos Authentication With Unconstrained Delegation

When Unconstrained Delegation is enabled:
1. User requests TGS for remote service
2. DC embeds user's TGT into the service ticket
3. User presents TGS + their own TGT to the service
4. Service can use user's TGT to authenticate to other services on user's behalf

![Unconstrained Delegation Process](https://github.com/user-attachments/assets/27200b16-6c43-4819-8aa6-ef81702f44ab)

*Kerberos unconstrained delegation flow*

---

#### Unconstrained Delegation Detection Opportunities

| Detection Method | Description |
|-----------------|-------------|
| PowerShell Logging | Event ID 4104 - commands like TrustedForDelegation |
| LDAP Search | userAccountControl:1.2.840.113556.1.4.803:=524288 |
| Pass-the-Ticket | TGT extraction/reuse detection |

> 📌 Monitor PowerShell script block logging (4104) for LDAP queries searching for delegation settings

---

#### Detecting Unconstrained Delegation With Splunk

**Timeframe:** earliest=1690544538 latest=1690544540

```spl
index=main earliest=1690544538 latest=1690544540 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" 
| table _time, ComputerName, EventCode, Message
```

![Unconstrained Detection](https://github.com/user-attachments/assets/b3cfb9f6-2504-45b8-b9f5-04593173038c)

*Detecting PowerShell queries for Unconstrained Delegation*

---

#### Constrained Delegation Overview

**Constrained Delegation** allows services to delegate user credentials only to **specified resources**. Any accounts with SPNs set in `msDS-AllowedToDelegateTo` can impersonate users to those specific SPNs.

![Constrained Delegation Settings](https://github.com/user-attachments/assets/f3b8b4ff-06f6-4ede-8506-210468d8d448)

*Constrained delegation to specific services*

#### Constrained Delegation Attack Steps

1. **Identify Target**: Find systems with Constrained Delegation and allowed SPNs

![CD Discovery](https://github.com/user-attachments/assets/ce7583bd-4a4d-4921-8b90-3e068844c759)

*Discovering Constrained Delegation*

2. **Get TGT**: Extract TGT from memory or request with principal's hash

![TGT Request](https://github.com/user-attachments/assets/5c8263aa-e843-4bb8-b677-84b1929faad5)

*Rubeus requesting TGT*

3. **S4U Impersonation**: Use S4U technique to impersonate high-privileged account

![S4U Request](https://github.com/user-attachments/assets/02e7b2a6-5364-40de-b4b6-35bcbc0a97c8)

*S4U2proxy impersonating WELDON_EVANS*

4. **Access Service**: Inject ticket and access targeted service as impersonated user

![Service Access](https://github.com/user-attachments/assets/3dcd8ba6-fa53-4f86-afd5-a9130f8983ff)

*Accessing service as impersonated user*

---

#### S4U Extensions

**S4U2self**: Allows a service to obtain a TGS for itself on behalf of any user (even without Kerberos auth)

![S4U2self](https://github.com/user-attachments/assets/8b4c762e-913f-4d28-81c5-ba4ccbab70c1)

*S4U2self process*

**S4U2proxy**: Takes a forwardable ticket and requests TGS to any SPN in msDS-AllowedToDelegateTo

With S4U2self + S4U2proxy, attackers can impersonate any user to SPNs in msDS-AllowedToDelegateTo.

---

#### Constrained Delegation Detection Opportunities

| Detection Method | Description |
|-----------------|-------------|
| PowerShell Logging | Event 4104 - msDS-AllowedToDelegateTo queries |
| Network Connections | Unusual process to Kerberos port 88 |
| Pass-the-Ticket | TGT extraction/reuse detection |

---

#### Detecting Constrained Delegation With Splunk

##### Method 1: PowerShell Logs

**Timeframe:** earliest=1690544553 latest=1690562556

```spl
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*" 
| table _time, ComputerName, EventCode, Message
```

![Constrained PS Detection](https://github.com/user-attachments/assets/909e8cb8-7656-42c3-8cf3-a2426b42e59b)

*Detecting PowerShell queries for Constrained Delegation*

---

##### Method 2: Sysmon Network Logs

**Timeframe:** earliest=1690562367 latest=1690562556

```spl
index=main earliest=1690562367 latest=1690562556 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

![Constrained Network Detection](https://github.com/user-attachments/assets/13e8a17f-8359-4a4e-a92e-290cd6749656)

*Detecting Rubeus connections to Kerberos port*

**Search Breakdown:**

1. **EventStats**: Map process IDs to process names
2. **Filter**: Network events (EventCode=3) to port 88
3. **Table**: Display time, computer, destination, image, process

> 📌 **Key Detection**: Network connections to Kerberos port 88 from unusual processes (like Rubeus) indicate potential delegation attacks!

---

### Detecting DCSync/DCShadow {#detecting-dcsyncdcshadow}

#### DCSync Overview

**DCSync** is a technique to extract password hashes from Active Directory Domain Controllers by abusing the Replication Directory Changes permission. Domain Controllers have this permission to read all object attributes including password hashes.

> 📌 Members of Administrators, Domain Admins, Enterprise Admin groups, or computer accounts on DCs can execute DCSync.

![DCSync Attack](https://github.com/user-attachments/assets/90938e89-4e2d-40c5-a2dd-230741ad09d0)

*Mimikatz performing DCSync on KRBTGT*

#### DCSync Attack Steps

1. **Gain Access**: Attacker gains administrative access or escalates privileges to request replication data

2. **Request Replication**: Attacker uses Mimikatz's DRSGetNCChanges interface to mimic a legitimate DC

3. **Extract Hashes**: Attacker obtains password hashes (KRBTGT, Administrators, etc.)

4. **Use Hashes**: Attacker crafts Golden/Silver Tickets or performs Pass-the-Hash/Overpass-the-Hash

---

#### DCSync Detection Opportunities

DS-Replication-Get-Changes operations are recorded with **Event ID 4662**. This requires enabling Audit Policy:

```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → DS Access
```

![Event 4662 Configuration](https://github.com/user-attachments/assets/511b3390-e9c0-4c6f-9260-1e0740310350)

*Event 4662 audit configuration*

**Detection Key**: Look for property GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes)

> 📌 Event 4662 contains only GUIDs - need to look for "Replicating Directory Changes" in Message

---

#### Detecting DCSync With Splunk

**Timeframe:** earliest=1690544278 latest=1690544280

```spl
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

![DCSync Detection](https://github.com/user-attachments/assets/bd12f805-9236-4e38-8eb4-010e03bd97e2)

*Detecting DCSync replication events*

---

#### DCShadow Overview

**DCShadow** is an advanced technique to modify Active Directory objects without producing standard security logs. It uses the Directory Replicator permission to register a rogue DC and make unauthorized changes.

> 📌 DCShadow is stealthy because it doesn't produce typical security event logs.

![DCShadow Operation](https://github.com/user-attachments/assets/6c211b1c-e58e-4871-a7c3-7211f73595d5)

*Mimikatz DCShadow token operation*

#### DCShadow Attack Steps

1. **Gain Access**: Attacker gains administrative privileges (Domain Admin or local DC admin) or KRBTGT hash

2. **Register Rogue DC**: Attacker registers a rogue domain controller using Directory Replicator permission

3. **Modify AD Objects**: Attacker changes AD objects (e.g., add user to Domain Admins)

![DCShadow Push](https://github.com/user-attachments/assets/c0b3950a-478d-4abf-bad2-873820680283)

*DCShadow pushing changes*

4. **Replicate**: Rogue DC replicates changes to legitimate DCs

---

#### DCShadow Detection Opportunities

To emulate a DC, DCShadow must:
- Add a new nTDSDSA object
- Append global catalog ServicePrincipalName to computer object

**Event ID 4742** (Computer account was changed) logs SPN changes.

> 📌 Monitor Event 4742 for unusual ServicePrincipalName additions

---

#### Detecting DCShadow With Splunk

**Timeframe:** earliest=1690623888 latest=1690623890

```spl
index=main earliest=1690623888 latest=1690623890 EventCode=4742 
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)" 
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn 
| search gcspn=*
```

![DCShadow Detection](https://github.com/user-attachments/assets/911333ab-479c-4c87-b578-ec8bf76c92ee)

*Detecting DCShadow via Event 4742*

**Search Breakdown:**

1. **Filter**: EventCode=4742 (Computer account changed)
2. **Extract**: Use regex to find GC SPN patterns in Message
3. **Filter**: Only show results with gcspn (SPN present)
4. **Table**: Display relevant fields

> 📌 **Key Detection**: Event 4742 with ServicePrincipalName changes indicate potential DCShadow registration!

---

## 2. Creating Custom Splunk Applications {#2-creating-custom-splunk-applications}

### Overview

Custom Splunk applications allow SOC analysts to organize and automate detection searches, dashboards, and reports for specific threat scenarios.

---

### How To Create A Custom Splunk Application

#### Step 1: Access Splunk Web

Navigate to Splunk Web in your browser.

#### Step 2: Manage Apps

From the menu bar, select **Apps** → **Manage Apps**.

![Manage Apps](https://github.com/user-attachments/assets/35b28367-7e0b-4f28-8318-f98fc3293fc3)

*Splunk Apps menu*

#### Step 3: Create New App

Click **Create app** and fill in the details:

| Field | Value |
|-------|-------|
| Name | Academy hackthebox - Detection of Active Directory Attacks |
| Folder name | Detection_of_Active_Directory_Attacks |
| Version | 1.0.0 |
| Description | App description |
| Template | barebones |

![Create App](https://github.com/user-attachments/assets/3948088b-6e8c-4bc6-913e-aea8e489f9ff)

*App creation form*

#### Step 4: Save and Verify

Click **Save**. Your app will appear in the Apps menu.

![App Listed](https://github.com/user-attachments/assets/63dc950b-7c1a-4bd8-9f4f-8f9688071157)

*New app in Apps menu*

---

### App Directory Structure

Navigate to `$SPLUNK_HOME/etc/apps/<your app>`:

```
/bin          # Scripts
/default      # Configuration, views, dashboards, navigation
/local        # User-modified configurations
/metadata     # Permissions files
```

![Directory Structure](https://github.com/user-attachments/assets/d101a5f9-3211-49f4-b2e2-8ac2fa332b2d)

*App directory structure*

---

### Navigation Configuration

The navigation is defined in `default/data/ui/nav/default.xml`:

```xml
<nav search_view="search">
  <view name="search" default='true' />
  <view name="analytics_workspace" />
  <view name="datasets" />
  <view name="reports" />
  <view name="alerts" />
  <view name="dashboards" />
</nav>
```

- `search_view`: Default view for searches
- `default='true'`: Home page view

---

### Creating Dashboards

#### Step 1: Create New Dashboard

Go to **Dashboards** → **Create New Dashboard**

![Create Dashboard](https://github.com/user-attachments/assets/5ff34086-0a1f-4fe0-a030-9aaa578eee9d)

*Create dashboard form*

Enter:
- **Title**: Domain Reconnaissance
- **Description**: (optional)
- **Permissions**: (set as needed)
- **Type**: Classic Dashboards

#### Step 2: Configure Dashboard

Add inputs and panels:

1. **Add Time Input**: Select "Time" token, set default range
2. **Add Panel**: Choose "Statistics Table"
3. **Search String**: Enter Splunk search (use `$token$` for inputs)

![Add Panel](https://github.com/user-attachments/assets/9bf2a2df-4aa4-4271-bbc3-3e9fb5874d8a)

*Adding panel to dashboard*

#### Step 3: Save Dashboard

Dashboards are stored at:
```
<AppPath>/local/data/ui/views/<dashboard_name>.xml
```

To add to navigation, update `default.xml`:

```xml
<nav search_view="search">
  <view name="search" default='true' />
  <view name="domain_reconnaissance" />
</nav>
```

![Navigation XML](https://github.com/user-attachments/assets/5b26851f-2615-40a9-9977-7f59535f7b0d)

*Navigation XML configuration*

#### Step 4: Restart Splunk

Reboot your Splunk instance. The dashboard will appear in the navigation bar.

---

### Grouping Dashboards

To group multiple dashboards under one entry:

```xml
<collection label="Command and Control">
  <view name="c2_investigator" />
  <view name="c2_investigator_zeek" />
</collection>
```

---

### Importing Existing Applications

To update an existing app:
1. Download `Detection-of-Active-Directory-Attacks.tar.gz` from Resources
2. Go to **Apps** → **Manage Apps** → **Install app from file**
3. Browse and select the file
4. Check "Upgrade app" to overwrite
5. Click **Upload**

> 📌 Custom apps allow SOC teams to consolidate detection searches, automate monitoring, and create reusable dashboards for specific threat scenarios.

---

## 3. Leveraging Zeek Logs {#3-leveraging-zeek-logs}

### Detecting RDP Brute Force Attacks {#detecting-rdp-brute-force-attacks}

#### RDP Brute Force Overview

**Remote Desktop Protocol (RDP)** brute force is a favorite attack vector for attackers to gain initial network access. Attackers systematically guess passwords until finding the correct one.

> 📌 Many users have weak or default passwords that are easily guessed.

#### RDP Traffic Analysis

RDP traffic can be identified in network captures:

![RDP Traffic](https://github.com/user-attachments/assets/6f623544-b881-4a43-8b7b-127bdc77915d)

*Network capture showing RDP session*

---

#### Accessing Target System

Connect via RDP using:

```bash
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
```

**Related Resources:**

| Item | Value |
|------|-------|
| Directory | `/home/htb-student/module_files/rdp_bruteforce` |
| Splunk Index | `rdp_bruteforce` |
| Sourcetype | `bro:rdp:json` |

---

#### Detecting RDP Brute Force With Splunk & Zeek

**Search:**

```spl
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
```

![RDP Brute Force Detection](https://github.com/user-attachments/assets/c65915f8-29fb-4d1a-901a-aa3e8b9c59c7)

*Detecting RDP brute force via Zeek logs*

**Search Breakdown:**

1. **Filter**: Index and sourcetype for Zeek RDP logs
2. **Bin**: Group events into 5-minute intervals
3. **Stats**: Count attempts by time, source IP, destination IP
4. **Filter**: Show only entries with >30 attempts

> 📌 **Key Detection**: >30 RDP connection attempts in 5 minutes from same source IP indicates brute force attack!

---

### Detecting Beaconing Malware {#detecting-beaconing-malware}

#### Beaconing Overview

**Malware beaconing** is periodic communication from infected systems to Command & Control (C2) servers. Like a lighthouse, beacons are sent at regular intervals.

> 📌 Beacons are typically small data packets sent via HTTP/HTTPS, DNS, or ICMP.

**Beacon Patterns:**

| Pattern | Description |
|---------|-------------|
| Fixed | Exact intervals (e.g., every 60 seconds) |
| Jittered | Slight variation from fixed pattern |
| Complex | Scheduled based on malware objectives |

This section focuses on detecting **Cobalt Strike** beaconing (default configuration).

---

#### Accessing Target System

Connect via RDP:

```bash
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
```

**Related Resources:**

| Item | Value |
|------|-------|
| Directory | `/home/htb-student/module_files/cobaltstrike_beacon` |
| Splunk Index | `cobaltstrike_beacon` |
| Sourcetype | `bro:http:json` |

---

#### Detecting Beaconing With Splunk & Zeek

```spl
index="cobaltstrike_beacon" sourcetype="bro:http:json" 
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```

![Beacon Detection](https://github.com/user-attachments/assets/8c1eba17-dfbb-404e-8b8b-40a0d383a010)

*Detecting Cobalt Strike beaconing*

**Search Breakdown:**

1. **Sort**: Order events by time
2. **Streamstats**: Calculate previous event time per source/dest/port
3. **Eval**: Compute time difference between consecutive beacons
4. **Eventstats**: Calculate average interval and total count
5. **Eval**: Set upper/lower bounds (10% margin around average)
6. **Where**: Filter events within the interval bounds
7. **Stats**: Count matching events and extract average interval
8. **Eval**: Calculate percentage of events within bounds
9. **Where**: Show only >90% match rate AND >10 total events

> 📌 **Key Detection**: Regular intervals (>90% within 10% of avg, >10 events) indicate beaconing behavior!

---

### Detecting Nmap Port Scanning {#detecting-nmap-port-scanning}

#### Port Scanning Overview

**Nmap** is used to probe networked systems for open ports - the "gates" through which data passes.

> 📌 Open ports are like unlocked doors that attackers can use to gain access.

**How Nmap Works:**
- Initiates TCP handshake with each port
- Successful connection = port is open
- Zero payload - only connection attempts
- May grab service banners (version info)

---

#### Accessing Target System

```bash
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
```

**Related Resources:**

| Item | Value |
|------|-------|
| Directory | `/home/htb-student/module_files/cobaltstrike_beacon` |
| Splunk Index | `cobaltstrike_beacon` |
| Sourcetype | `bro:conn:json` |

---

#### Detecting Nmap Scanning With Splunk & Zeek

```spl
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8) 
| bin span=5m _time 
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip 
| where num_dest_port >= 3
```

![Nmap Detection](https://github.com/user-attachments/assets/9ec5df3b-4339-427f-a5e2-990bd211eb33)

*Detecting Nmap port scanning*

**Search Breakdown:**

1. **Filter**: Index, sourcetype, orig_bytes=0 (no data sent), private IP ranges
2. **Bin**: Group into 5-minute intervals
3. **Stats**: Count distinct destination ports (dc) per time/src/dest
4. **Filter**: Show only >=3 ports accessed

> 📌 **Key Detection**: >=3 distinct ports accessed in 5 minutes with zero bytes sent indicates port scanning!

---

### Detecting Kerberos Brute Force Attacks {#detecting-kerberos-brute-force-attacks}

#### Kerberos Brute Force Overview

Attackers perform **Kerberos user enumeration** by sending AS-REQ (Authentication Service Request) messages to the KDC (Key Distribution Center).

> 📌 By analyzing KDC responses, attackers determine which usernames are valid.

**KDC Responses:**

| Response | Indicates |
|----------|-----------|
| TGT or KRB5KDC_ERR_PREAUTH_REQUIRED | Valid user account |
| KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN | Invalid user account |

#### Kerberos Traffic Analysis

![Kerberos Brute Force](https://github.com/user-attachments/assets/94f49798-3256-4aa8-8ba1-2b826ad24364)

*Network capture showing Kerberos brute force*

---

#### Accessing Target System

```bash
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
```

**Related Resources:**

| Item | Value |
|------|-------|
| Directory | `/home/htb-student/module_files/kerberos_bruteforce` |
| Splunk Index | `kerberos_bruteforce` |
| Sourcetype | `bro:kerberos:json` |

---

#### Detecting Kerberos Brute Force With Splunk & Zeek

```spl
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```

![Kerberos BF Detection](https://github.com/user-attachments/assets/c67b5c44-f511-4667-82b8-a8d9f1d5856f)

*Detecting Kerberos brute force*

**Search Breakdown:**

1. **Filter**: Exclude preauth required errors, filter failed AS requests
2. **Bin**: Group into 5-minute intervals
3. **Stats**: Count total attempts, unique users, and error types
4. **Filter**: Show only >30 attempts

> 📌 **Key Detection**: >30 failed Kerberos AS requests in 5 minutes indicates brute force attack!

---

### Detecting Kerberoasting (Zeek) {#detecting-kerberoasting-1}

#### Kerberoasting via Network Analysis

While we covered Kerberoasting detection using Windows Event Logs earlier, we can also detect it via **network traffic analysis** using Zeek logs.

> 📌 Kerberoasting uses RC4 encryption for TGS tickets - this is a key detection opportunity.

#### Kerberoasting Traffic

![Kerberoasting Traffic](https://github.com/user-attachments/assets/6242d5d9-4e56-4242-912c-d75e935b6b4a)

*Network capture showing TGS-REQ/TGS-REP with RC4 encryption*

---

#### Accessing Target System

```bash
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:[Target IP] /dynamic-resolution
```

**Related Resources:**

| Item | Value |
|------|-------|
| Directory | `/home/htb-student/module_files/sharphound` |
| Splunk Index | `sharphound` |
| Sourcetype | `bro:kerberos:json` |

---

#### Detecting Kerberoasting With Splunk & Zeek

```spl
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac" 
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```

![Kerberoast Zeek Detection](https://github.com/user-attachments/assets/df3cda6f-6b9a-4390-b203-94cdcf3c1e46)

*Detecting Kerberoasting via Zeek logs*

**Search Breakdown:**

1. **Filter**: TGS requests with RC4-HMAC cipher
2. **Filter**: Forwardable and renewable tickets
3. **Table**: Display key fields

> 📌 **Key Detection**: TGS requests with RC4 cipher, forwardable/renewable flags indicate Kerberoasting activity!

---

*Module 14/15 - Detecting Windows Attacks with Splunk*
*For learning and SOC career preparation*