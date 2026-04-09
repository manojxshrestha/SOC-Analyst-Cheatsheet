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

*Module 14/15 - Detecting Windows Attacks with Splunk*
*For learning and SOC career preparation*