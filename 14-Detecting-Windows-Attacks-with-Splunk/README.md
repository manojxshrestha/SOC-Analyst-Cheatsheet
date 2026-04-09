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

*Module 14/15 - Detecting Windows Attacks with Splunk*
*For learning and SOC career preparation*