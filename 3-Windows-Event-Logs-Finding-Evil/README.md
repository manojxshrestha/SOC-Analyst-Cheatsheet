# Windows Event Logs & Finding Evil
## SOC Analyst Cheatsheet - Module 3/15

---

## 0. Overview

This module covers **Windows Event Logs** - the primary data source for detecting malicious activity on Windows endpoints. You'll learn how to analyze security logs, identify suspicious behavior, and find evil using Windows event log analysis.

### Key Takeaways

| Concept | Description |
|---------|-------------|
| **Windows Event Logs** | Records of system, security, and application events |
| **Security Event IDs** | Windows security log event identifiers |
| **Sysmon** | System Monitor - enhanced logging for security |

### Prerequisites

- Basic understanding of Windows OS
- Familiarity with Windows administration

### Module Duration

- **Theory**: 2-3 hours
- **Hands-on Practice**: 3-4 hours

---

## Table of Contents

0. [Overview](#0-overview)
1. [Windows Event Log Fundamentals](#1-windows-event-log-fundamentals)
2. [Security Event IDs Overview](#2-security-event-ids-overview)
3. [Interview Questions](#3-interview-questions)
4. [Additional Resources](#4-additional-resources)

---

## 1. Windows Event Log Fundamentals

### What Are Windows Event Logs?

Windows Event Logs are records of significant system, security, and application events stored in `.evtx` files.

### Key Log Locations

| Log Name | Location | Purpose |
|----------|----------|---------|
| **Security** | `%SystemRoot%\System32\Winevt\Logs\Security.evtx` | Security events, logons, audits |
| **System** | `%SystemRoot%\System32\Winevt\Logs\System.evtx` | Driver, service, system issues |
| **Application** | `%SystemRoot%\System32\Winevt\Logs\Application.evtx` | Application errors, crashes |
| **Setup** | `%SystemRoot%\System32\Winevt\Logs\Setup.evtx` | Installation and setup events |

### Event Log Structure

```
Event ID: 4624
Time: 2024-10-10 14:32:15
Computer: DC01.contoso.com
User: CONTOSO\jsmith
Source: Microsoft-Windows-Security-Auditing
Level: Information
```

### Log Types by Priority

| Priority | Log Type | Description |
|----------|----------|-------------|
| **Critical** | Security | Authentication, privilege use, audit |
| **High** | System | Service failures, driver issues |
| **Medium** | Application | Application errors |

### Important Channels

| Channel | Provider | Description |
|---------|----------|-------------|
| **Microsoft-Windows-Security-Auditing** | Security | Core security events |
| **Microsoft-Windows-PowerShell/Operational** | PowerShell | PowerShell script block logging |
| **Microsoft-Windows-Sysmon/Operational** | Sysmon | Process, network, file events |

---

## 2. Security Event IDs Overview

### Key Security Event IDs for SOC Analysts

| Event ID | Name | Category | Detection Value |
|----------|------|-----------|-----------------|
| **4624** | Successful Logon | Authentication | High |
| **4625** | Failed Logon | Authentication | High |
| **4634** | Logoff | Session | Medium |
| **4648** | Explicit Credential Logon | Authentication | High |
| **4672** | Special Privileges Assigned | Privilege Use | High |
| **4688** | Process Creation | Process Tracking | High |
| **4697** | Service Installed | Security | High |
| **4720** | User Account Created | Account Management | High |
| **4728** | Member Added to Security Group | Account Management | High |
| **4732** | Member Added to Local Group | Account Management | High |
| **1102** | Audit Log Cleared | Security | Critical |
| **7045** | New Service Installed | Security | High |

### Logon Types

| Logon Type | Value | Description | Security Concern |
|------------|-------|-------------|------------------|
| **Interactive** | 2 | Local keyboard logon | Low (normal) |
| **Network** | 3 | File share, RPC access | Low (normal) |
| **Service** | 5 | Service account logon | Medium |
| **RemoteInteractive** | 10 | RDP logon | High |
| **NetworkCleartext** | 8 | Pass-the-hash target | High |

---

## 3. Interview Questions

### Q1: What Windows Event ID indicates a successful logon?

**Answer:** Event ID 4624 - An account was successfully logged on.

**Key fields to analyze:**
- LogonType (2=interactive, 3=network, 10=RDP)
- Account Name and Domain
- Source Network Address (IP)
- Workstation Name

---

### Q2: What is the difference between Event ID 4624 and 4625?

**Answer:**
- **4624** = Successful logon - account logged on successfully
- **4625** = Failed logon - account failed to log on

Failed logons (4625) are critical for detecting brute force attacks. Look for multiple failures from the same source IP.

---

### Q3: What Event ID shows when an account is added to a security group?

**Answer:** Event ID 4728 - A member was added to a security-enabled global group.

**Related events:**
- 4729: Member removed from security-enabled global group
- 4732: Member added to security-enabled local group

---

### Q4: How do you detect a brute force attack in Windows logs?

**Answer:**

1. Look for multiple 4625 events (failed logon) from same Source Network Address
2. Threshold: >5 failed attempts in 10 minutes
3. Then look for 4624 (successful logon) after the failed attempts

---

### Q5: What is the difference between Sysmon Event 1 and Windows Event 4688?

**Answer:**

| Feature | Windows 4688 | Sysmon Event 1 |
|---------|-------------|----------------|
| Command Line | May be empty | Always captured |
| Parent Command Line | Not captured | Captured |
| Hash | Not captured | SHA256, MD5 |

Sysmon provides richer data - always use it if possible.

---

### Q6: How do you detect PowerShell encoded commands?

**Answer:**

**Event IDs to use:**
- 4104 (Script Block Logging) - shows decoded commands
- 4688 - shows command line including "-encodedcommand"

---

### Q7: What Event ID indicates the security log was cleared?

**Answer:** Event ID 1102 - The audit log was cleared.

**This is a critical indicator of attempted cover-up!**

---

### Q8: What log shows process access to lsass.exe?

**Answer:** Sysmon Event ID 10 - ProcessAccess.

This is critical for detecting credential dumping attacks (Mimikatz).

---

### Q9: How do you detect lateral movement via RDP?

**Answer:**

1. Look for Event 4624 with LogonType=10 (RemoteInteractive)
2. Filter for Source Network Address external IPs
3. Check for service accounts doing RDP (they shouldn't)

---

### Q10: What Event ID shows a new scheduled task was created?

**Answer:** Event ID 4698 - A scheduled task was created.

---

## 4. Additional Resources

### Tools

- [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Swift On Security Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Event Log Explorer](https://eventlogxp.com/)

### References

- [Microsoft Security Event ID Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/audit/security-auditing)
- [MITRE ATT&CK - T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

*Module 3/15 - Windows Event Logs & Finding Evil*
*Built with research + HTB Academy materials*