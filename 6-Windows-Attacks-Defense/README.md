# 🛡️ WINDOWS ATTACKS & DEFENSE

## SOC Analyst Cheatsheet - Module 6/15

---

## 0. Overview

This module covers **Active Directory attacks and defense** - common attack techniques targeting Windows environments, detection methods, and preventive measures.

> 📌 **Key Focus**: Kerberos authentication abuse, credential harvesting, privilege escalation, and AD misconfigurations

### Key Takeaways

| Concept | Description |
|---------|-------------|
| **Kerberoasting** | Obtaining TGS tickets and cracking offline |
| **AS-REP Roasting** | Obtaining hashes for accounts with no preauth |
| **GPP Passwords** | Decrypting cached credentials in SYSVOL |
| **DCSync** | Mimicking domain controller for credential replication |
| **Golden Ticket** | Forging Kerberos TGT with KRBTGT hash |

### Prerequisites

- Basic understanding of Active Directory
- Familiarity with Windows authentication (Kerberos, NTLM)
- Understanding of LDAP protocols
- Basic PowerShell knowledge

---

## Table of Contents

1. [Introduction and Terminology](#1-introduction-and-terminology)
2. [Overview and Lab Environment](#2-overview-and-lab-environment)
3. [Kerberoasting](#3-kerberoasting)
4. [AS-REP Roasting](#4-as-rep-roasting)
5. [GPP Passwords](#5-gpp-passwords)

---

## 1. Introduction and Terminology

### What is Active Directory?

> 📌 **Active Directory (AD)** is a directory service for Windows enterprise environments that provides centralized management of resources including users, computers, groups, and policies.

Active Directory is the most critical service in any enterprise. A compromise of an AD environment means unrestricted access to all its systems and data.

### AD Key Terms

| Term | Description |
|------|-------------|
| **Domain** | Group of objects sharing the same AD database |
| **Tree** | One or more domains grouped (e.g., test.local, staging.test.local) |
| **Forest** | Topmost level, composed of multiple trees |
| **OU** | Organizational Units - containers for users, computers, other OUs |
| **Domain Controller** | Server providing Authentication and Authorization |
| **NTDS.DIT** | The most critical file in AD environment |
| **KRBTGT** | Account storing secrets for TGT validation |

### What Regular Users Can Enumerate

A regular AD user account with no added privileges can enumerate:

- Domain Computers
- Domain Users
- Domain Group Information
- Default Domain Policy
- Domain Functional Levels
- Password Policy
- Group Policy Objects (GPOs)
- Kerberos Delegation
- Domain Trusts
- Access Control Lists (ACLs)

### Authentication in Windows Environments

| Type | Description |
|------|-------------|
| **Username/Password** | Stored as LM, NTLM, NetNTLMv1/NetNTLMv2 hashes |
| **Kerberos Tickets** | TGT (Ticket Granting Ticket) and TGS (Ticket Granting Service) |
| **LDAP Authentication** | Username/password or certificate-based |

### Kerberos Components

> 📌 **Key Distribution Center (KDC)** - Kerberos service on Domain Controller that creates tickets

- **TGT** - Proof the client submitted valid user info to KDC
- **TGS** - Created for each service the client wants to access
- **KRBTGT** - Account storing secrets for TGT validation

### Important Network Ports

| Port | Service |
|------|---------|
| 53 | DNS |
| 88 | Kerberos |
| 135 | WMI/RPC |
| 137-139, 445 | SMB |
| 389, 636 | LDAP |
| 3389 | RDP |
| 5985, 5986 | WinRM |

### AD Limitations and Attack Surface

> 🔴 **Complexity** - Nested group members can lead to unintended Domain Admin memberships

> 🔴 **Design** - SYSVOL access over SMB allows code execution with valid credentials

> 🔴 **Legacy** - NetBIOS and LLMNR broadcast credentials on the wire

---

## 2. Overview and Lab Environment

### Attacks Covered

| # | Attack | Description |
|---|--------|-------------|
| 1 | Kerberoasting | Crack service account passwords from TGS tickets |
| 2 | AS-REP Roasting | Crack passwords from accounts without preauthentication |
| 3 | GPP Passwords | Decrypt cached credentials in SYSVOL |
| 4 | GPO Permissions | Abuse misconfigured Group Policy |
| 5 | Credentials in Shares | Find credentials in network shares |
| 6 | Credentials in Object Properties | Hunt credentials in user attributes |
| 7 | DCSync | Replicate domain controller data |
| 8 | Golden Ticket | Forge Kerberos TGT |
| 9 | Kerberos Constrained Delegation | Abuse delegation settings |
| 10 | Print Spooler & NTLM Relaying | Relay authentication |
| 11 | Coercing Attacks | Force DC authentication |
| 12 | Object ACLs | Abuse Access Control Lists |
| 13 | PKI ESC1 | Certificate misconfigurations |
| 14 | PKI ESC8 | Coercing + Certificates |

### Lab Environment

| Machine | IP Address |
|---------|-----------|
| DC1 | 172.16.18.3 |
| DC2 | 172.16.18.4 |
| Server01 | 172.16.18.10 |
| PKI | 172.16.18.15 |
| WS001 | 172.16.18.25 |
| Kali Linux | 172.16.18.20 |

### Connecting to Lab

**Connect to WS001 via RDP:**

```bash
xfreerdp /u:eagle\\bob /p:Slavi123 /v:TARGET_IP /dynamic-resolution
```

> 📌 **Credentials**: User: `bob`, Password: `Slavi123`

<img width="1668" height="1304" alt="image" src="https://github.com/user-attachments/assets/0f257d2d-293d-4a37-861b-b1d4f2738aeb" />

File Explorer open on FreeRDP session to 10.129.204.151.

**Connect to Kali via SSH:**

```bash
ssh kali@TARGET_IP
```

> 📌 **Credentials**: `kali/kali`

<img width="1323" height="772" alt="image" src="https://github.com/user-attachments/assets/8af5cbcc-fcec-437d-9950-6596bf6b55a2" />

**File Transfer between machines:**

```bash
smbclient \\\\TARGET_IP\\Share -U eagle/administrator%Slavi123
```

> 📌 **Credentials**: `eagle/administrator:Slavi123`

<img width="739" height="218" alt="image" src="https://github.com/user-attachments/assets/030b6547-a4f3-4b43-b78c-00d80f7b2a1d" />

---

## 3. Kerberoasting

### Description

> 📌 **Kerberoasting** exploits Kerberos authentication by obtaining TGS tickets and cracking them offline to reveal service account passwords.

When a Kerberos TGS service ticket is requested, it gets encrypted with the service account's NTLM password hash. Success depends on password strength.

**Encryption Types:**

| Type | Cracking Speed | Notes |
|------|---------------|-------|
| AES | Slowest | Most secure |
| RC4 | Faster | Commonly used |
| DES | Fastest | Legacy, rarely used |

> 🔴 Attackers can force downgrade to RC4 for faster cracking.

### Attack Path

**Step 1: Obtain crackable tickets**

```powershell
.\Rubeus.exe kerberoast /outfile:spn.txt
```

<img width="2281" height="1381" alt="image" src="https://github.com/user-attachments/assets/930e6693-522f-4fe6-88fb-f58384b5c58a" />

Rubeus extracts tickets for all users with SPN registered.

**Step 2: Crack with hashcat**

```bash
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

> 📌 **Hashcat Mode**: 13100 = Kerberos 5 TGS-REP

<img width="874" height="225" alt="image" src="https://github.com/user-attachments/assets/769b49f6-bc89-47ce-880e-7b24623a6ebb" />

**Alternative: Crack with John**

```bash
john spn.txt --format=krb5tgs --wordlist=passwords.txt
```

### Prevention

| Mitigation | Description |
|-----------|-------------|
| **Strong Passwords** | Use 100+ random characters for service accounts |
| **GMSA** | Use Group Managed Service Accounts when possible |
| **Limit SPNs** | Only assign SPNs when absolutely necessary |
| **Regular Cleanup** | Remove SPNs for decommissioned services |

### Detection

> 📌 **Event ID 4769** - Kerberos ticket requested

| Detection Method | Description |
|-----------------|-------------|
| **Volume Alert** | Alert if >10 tickets requested within 1 minute |
| **RC4 Alert** | Alert on RC4 encryption type (not default) |
| **AES-Only** | Require AES encryption for all tickets |
| **Source IP** | Group by requesting machine/IP |

**Honeypot Approach:**

- Create fake service account with SPN
- Alert on ANY TGS request for that account
- Use old IIS/SQL service account names

---

## 4. AS-REP Roasting

### Description

> 📌 **AS-REP Roasting** targets accounts with "Do not require Kerberos preauthentication" enabled, allowing offline password cracking.

### Attack Path

**Step 1: Obtain crackable hashes**

```powershell
.\Rubeus.exe asreproast /outfile:asrep.txt
```

<img width="1655" height="915" alt="image" src="https://github.com/user-attachments/assets/118b89c8-d609-4a8f-8bc0-cf452f203a0e" />

**Step 2: Prepare hash for hashcat**

Add `23$` after `$krb5asrep$`:

```
$krb5asrep$23$anni@eagle.local:hash...
```

**Step 3: Crack with hashcat**

```bash
hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile=cracked.txt
```

> 📌 **Hashcat Mode**: 18200 = Kerberos 5 AS-REP

<img width="1443" height="1449" alt="image" src="https://github.com/user-attachments/assets/5c1c9cf4-3f4a-46fd-82b8-0e45af081d74" />

### Prevention

| Mitigation | Description |
|-----------|-------------|
| **Disable Preauth** | Only enable when absolutely necessary |
| **Strong Passwords** | Minimum 20 characters for affected accounts |
| **Regular Review** | Quarterly audit of accounts with this property |
| **Separate Policy** | Apply stricter password policy to affected accounts |

### Detection

> 📌 **Event ID 4768** - Kerberos authentication ticket generated

> 🔴 **Pre-Authentication Type = 0** indicates no preauth (malicious)

| Field | Detection Value |
|-------|-----------------|
| Pre-Authentication Type | 0 (no preauth) |
| Ticket Encryption Type | 0x17 (RC4) |

### Honeypot Approach

Create a fake user account with "Do not require Kerberos preauthentication" enabled. Any AS-REQ for this account is suspicious.

---

## 5. GPP Passwords

### Description

> 📌 **Group Policy Preferences (GPP)** introduced ability to store credentials in XML policy files stored in SYSVOL.

The encryption key was publicly released by Microsoft in 2014, making decryption trivial.

**Affected Systems**: Windows Server 2008 - Server 2012 R2

**GPP Locations:**

| GPP Type | XML File |
|----------|----------|
| Groups | Groups.xml |
| Users | Users.xml |
| Services | Services.xml |
| Scheduled Tasks | ScheduledTasks.xml |
| Preferences | *.xml |

### AES Encryption Key

```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

<img width="1514" height="634" alt="image" src="https://github.com/user-attachments/assets/40892b16-f722-4853-9c3a-49a53c088883" />

**XML Example:**

<img width="2025" height="287" alt="image" src="https://github.com/user-attachments/assets/2c97f1d1-9489-441e-8224-83569889d6e4" />

### Attack Path

```powershell
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

<img width="1766" height="422" alt="image" src="https://github.com/user-attachments/assets/c0cf8faa-7727-4637-8e0a-a7e4319291ff" />

### Prevention

| Mitigation | Description |
|-----------|-------------|
| **KB2962486** | Apply Microsoft patch from 2014 |
| **No New Credentials** | Don't store passwords in GPP |
| **Remove Old GPP** | Clean up legacy GPP XML files |
| **SYSVOL ACLs** | Restrict access to authenticated users |

> 🔴 Patch does NOT remove existing cached credentials - must be manually cleaned.

### Detection

**Method 1: File Access Monitoring**

> 📌 **Event ID 4663** - File accessed

Monitor access to SYSVOL\Policies\*\*.xml files.

<img width="1743" height="1138" alt="image" src="https://github.com/user-attachments/assets/bc67d20e-276e-41f1-844c-e8f8a2bce47d" />

**Method 2: Logon Event Correlation**

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4768 | TGT requested |

> 📌 Correlate logon attempts with GPP credential exposure.

<img width="1521" height="1078" alt="image" src="https://github.com/user-attachments/assets/e3d50f22-0c50-40cd-b0a2-d7a22dbccc25" />

### Honeypot Approach

Create decoy service account with old password. Alert on any login attempts.

**Failed Logon Events:**

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |
| 4771 | Failed pre-authentication |
| 4776 | Failed credential validation |

<img width="1515" height="1117" alt="image" src="https://github.com/user-attachments/assets/b5fc6ca1-48b4-449e-99de-21997d9cb8cd" />

Event 4625: Failed logon

<img width="1660" height="1125" alt="image" src="https://github.com/user-attachments/assets/6f019f62-6ccf-4821-ae59-a0867b6e2bff" />

Event 4771: Failed pre-authentication

<img width="1040" height="478" alt="image" src="https://github.com/user-attachments/assets/e40eaab5-b46a-4b97-aa84-2d3fad83e009" />

Event 4776: Failed credential validation

---

*Module 6/15 - SOC Analyst Cheatsheet*
*Built with research + HTB Academy materials*