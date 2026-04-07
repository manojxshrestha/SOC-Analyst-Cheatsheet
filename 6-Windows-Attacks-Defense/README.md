# 🛡️ WINDOWS ATTACKS & DEFENSE

## SOC Analyst Cheatsheet - Module 6/15

---

## 0. Overview

This module covers **Active Directory attacks and defense** - common attack techniques targeting Windows environments, their detection methods, and preventive measures.

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
- Basic powershell knowledge

### Module Duration

- **Theory**: 3-4 hours
- **Hands-on Practice**: 4-5 hours
- **Total**: ~8-9 hours

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

### What Regular Users Can Enumerate

A regular AD user account with no added privileges can enumerate:

- Domain Computers
- Domain Users
- Domain Group Information
- Default Domain Policy
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

| Attack | Description |
|--------|-------------|
| Kerberoasting | Crack service account passwords from TGS tickets |
| AS-REP Roasting | Crack passwords from accounts without preauthentication |
| GPP Passwords | Decrypt cached credentials in SYSVOL |
| GPO Permissions | Abuse misconfigured Group Policy |
| Credentials in Shares | Find credentials in network shares |
| Credentials in Object Properties | Hunt credentials in user attributes |
| DCSync | Replicate domain controller data |
| Golden Ticket | Forge Kerberos TGT |
| Kerberos Constrained Delegation | Abuse delegation settings |
| Print Spooler & NTLM Relaying | Relay authentication |
| Coercing Attacks | Force DC authentication |
| Object ACLs | Abuse Access Control Lists |
| PKI ESC1 | Certificate misconfigurations |

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

<img width="1668" height="1304" alt="image" src="https://github.com/user-attachments/assets/0f257d2d-293d-4a37-861b-b1d4f2738aeb" />

File Explorer open on FreeRDP session.

<img width="1027" height="836" alt="image" src="https://github.com/user-attachments/assets/2c0fc210-d038-46ac-9698-f00ccf662724" />

**Connect to Kali via SSH:**

```bash
ssh kali@TARGET_IP
```

<img width="1323" height="772" alt="image" src="https://github.com/user-attachments/assets/8af5cbcc-fcec-437d-9950-6596bf6b55a2" />

**File Transfer between machines:**

```bash
smbclient \\\\TARGET_IP\\Share -U eagle/administrator%Slavi123
```

<img width="973" height="805" alt="image" src="https://github.com/user-attachments/assets/7a23cf1e-c11f-4bab-8b30-615b2f58bb63" />

<img width="739" height="218" alt="image" src="https://github.com/user-attachments/assets/030b6547-a4f3-4b43-b78c-00d80f7b2a1d" />

---

## 3. Kerberoasting

### Description

> 📌 **Kerberoasting** exploits Kerberos authentication by obtaining TGS tickets and cracking them offline to reveal service account passwords.

When a Kerberos TGS service ticket is requested, it gets encrypted with the service account's NTLM password hash. Success depends on password strength.

**Encryption Types:**
- AES (slowest to crack)
- RC4 (faster to crack)
- DES (legacy, rarely used)

### Attack Path

**Obtain crackable tickets:**

```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt
```

<img width="2281" height="1381" alt="image" src="https://github.com/user-attachments/assets/930e6693-522f-4fe6-88fb-f58384b5c58a" />

**Crack with hashcat:**

```bash
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

<img width="874" height="225" alt="image" src="https://github.com/user-attachments/assets/769b49f6-bc89-47ce-880e-7b24623a6ebb" />

**View cracked password:**

```bash
cat cracked.txt
```

<img width="1066" height="310" alt="image" src="https://github.com/user-attachments/assets/56e0d1cc-65d1-4269-b802-45a036fe03e4" />

### Prevention

- Use **strong passwords** (100+ characters) for service accounts
- Use **Group Managed Service Accounts (GMSA)** when possible
- Limit accounts with SPNs
- Regularly clean up unused SPNs

### Detection

> 📌 **Event ID 4769** - Kerberos ticket requested

However, high volume makes detection challenging. Focus on:
- AES-only environments (alert on 4769)
- RC4 ticket generation
- Unusual volume of requests

<img width="1753" height="1142" alt="image" src="https://github.com/user-attachments/assets/bd2abf34-0d8e-4e98-b4f0-cd432ce83520" />

Security log showing two 'Audit Success' events for Kerberos Service Ticket with Event ID 4769.

<img width="1877" height="1263" alt="image" src="https://github.com/user-attachments/assets/0575205b-559b-4832-af69-5034ca7013d0" />

**Honeypot Approach:**
- Create fake service account with SPN
- Alert on any TGS request for that account

<img width="1764" height="1142" alt="image" src="https://github.com/user-attachments/assets/6c7e172c-998c-4f6f-845d-3fe95d76f0d0" />

---

## 4. AS-REP Roasting

### Description

> 📌 **AS-REP Roasting** targets accounts with "Do not require Kerberos preauthentication" enabled, allowing offline password cracking.

### Attack

**Obtain crackable hashes:**

```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt
```

<img width="1655" height="915" alt="image" src="https://github.com/user-attachments/assets/118b89c8-d609-4a8f-8bc0-cf452f203a0e" />

**Crack with hashcat:**

```bash
sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force
```

<img width="1443" height="1449" alt="image" src="https://github.com/user-attachments/assets/5c1c9cf4-3f4a-46fd-82b8-0e45af081d74" />

**View cracked password:**

```bash
sudo cat asrepcrack.txt
```

<img width="1746" height="159" alt="image" src="https://github.com/user-attachments/assets/87c26570-c186-4f28-81eb-306035443c90" />

### Prevention

- Only enable "Do not require Kerberos preauthentication" when absolutely necessary
- Use strong passwords (20+ characters minimum)
- Review accounts quarterly

### Detection

> 📌 **Event ID 4768** - Kerberos authentication ticket generated

Focus on:
- Pre-Authentication Type = 0
- RC4 encryption (0x17)
- Unusual source IPs

<img width="1799" height="872" alt="image" src="https://github.com/user-attachments/assets/0baa0b4c-ccee-4ac3-8a16-ba158fb5271e" />

### Honeypot

Configure a fake account with no preauthentication. Any login attempt is suspicious.

<img width="1261" height="1148" alt="image" src="https://github.com/user-attachments/assets/51d4d1a9-1a2c-4992-9cc3-2fceea860f33" />

---

## 5. GPP Passwords

### Description

> 📌 **Group Policy Preferences (GPP)** introduced ability to store credentials in XML policy files stored in SYSVOL.

The encryption key was publicly released by Microsoft, making decryption trivial.

<img width="1514" height="634" alt="image" src="https://github.com/user-attachments/assets/40892b16-f722-4853-9c3a-49a53c088883" />

**XML file example:**

<img width="2025" height="287" alt="image" src="https://github.com/user-attachments/assets/2c97f1d1-9489-441e-8224-83569889d6e4" />

### Attack

```powershell
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword
```

<img width="1766" height="422" alt="image" src="https://github.com/user-attachments/assets/c0cf8faa-7727-4637-8e0a-a7e4319291ff" />

### Prevention

- Microsoft released patch KB2962486 in 2014
- No new credentials should be stored in GPP
- Review and remove existing GPP credentials

### Detection Methods

**Method 1: File Access Monitoring**
- Audit access to XML files in SYSVOL
- Any unexpected access is suspicious

<img width="1743" height="1138" alt="image" src="https://github.com/user-attachments/assets/bc67d20e-276e-41f1-844c-e8f8a2bce47d" />

**Method 2: Logon Events**
- Monitor for logon attempts using exposed service accounts

<img width="1521" height="1078" alt="image" src="https://github.com/user-attachments/assets/e3d50f22-0c50-40cd-b0a2-d7a22dbccc25" />

Event 4624: Successful logon

<img width="1634" height="817" alt="image" src="https://github.com/user-attachments/assets/86367eb5-e9c0-4338-b9c7-19cf0e840751" />

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4768 | TGT requested |

### Honeypot Approach

Create a decoy service account with old password. Alert on any login attempts.

**Failed logon indicators:**

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