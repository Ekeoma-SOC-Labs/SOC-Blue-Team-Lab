03 — Domain Controller (DC01) Setup & Active Directory Configuration
Overview

This section documents the full setup of Windows Server 2019 Domain Controller (DC01) for the SOC Home Lab.
It includes:

Server preparation

Active Directory Domain Services (ADDS) installation

DNS configuration

Domain creation (EKE.local)

Organizational Unit (OU) structure

User & computer accounts

GPO hardening

Network configuration

The domain controller is the core of the SOC lab. It provides authentication, policy enforcement, and identity management—mirroring a real enterprise environment.

1. Configure VirtualBox Network Interfaces

DC01 uses two network adapters:

Adapter	Mode	Purpose
Adapter 1	NAT	Internet access (Windows updates, package downloads)
Adapter 2	Host-only	Internal SOC network (communication with Win10 + Splunk)
Expected IP addresses (example)

NAT → 10.x.x.x (DHCP)

Host-only → 192.168.56.10 (Static IP assigned manually)

Screenshot placeholder

Paste screenshot here:

![DC01 Network Adapters](screenshots/dc01/dc01-network-adapters.png)

2. Set Static IP Address for DC01

A Domain Controller must have a static IP.

Settings → Network & Internet → Change Adapter Options → Host-only Adapter Properties

Assign:

IPv4 Address: 192.168.56.10
Subnet Mask: 255.255.255.0
Default Gateway: (leave blank)
DNS Server: 127.0.0.1

Screenshot placeholder:
![DC01 Static IP](screenshots/dc01/dc01-static-ip.png)

3. Rename Server

Set hostname:

DC01

Screenshot:
![DC01 Rename](screenshots/dc01/dc01-rename.png)


Restart.

4. Install Active Directory Domain Services (ADDS)

Open Server Manager

Click Add Roles and Features

Select:

Active Directory Domain Services

DNS Server (automatically selected)

Confirm and install

Screenshot:
![Install ADDS](screenshots/dc01/dc01-adds-install.png)

5. Promote Server to Domain Controller

After installation:

Click Promote this server to a domain controller

Choose:

Add a new forest

Root domain name: EKE.local

Set DSRM password

Keep DNS options default

Complete installation and reboot

Screenshot:
![DC Promotion](screenshots/dc01/dc-promotion.png)

6. Verify Domain Services

After reboot, log in as:

EKE\Administrator


Run:

Get-Service adws,dns,ntds,kdc


Expected: all services Running

Screenshot:
![ADDS Running](screenshots/dc01/adds-running.png)

7. Create Organizational Units (OUs)

Open Active Directory Users and Computers
Create the following structure:

EKE.local
│
├── _Admins
├── _Users
├── _Computers
├── _Servers
└── _Groups

Screenshot:
![OU Structure](screenshots/dc01/ou-structure.png)

8. Create Domain Users

Inside _Users:

Create:

WIN10User

SOCAnalyst

ITSupport

Any test accounts you want to simulate

Screenshot:
![Create Users](screenshots/dc01/create-users.png)

9. Join WIN10-CL01 to the Domain

(Already done earlier — document it here)

Steps:

On Win10 → System Properties → Rename this PC

Domain: EKE.local

Enter domain admin:

Administrator / Reign+Revival1@

Screenshot:
![Join Domain](screenshots/win10/win10-join-domain.png)

10. Create GPO for Basic Security Hardening

Open Group Policy Management:

Create a new GPO:

GPO: Baseline-Security


Apply to:

EKE.local domain


Configure:

Password Policies:
Minimum length: 12  
Password history: 24  
Complexity: Enabled  
Max age: 60 days

Account Lockout:
5 failed attempts  
Lockout 15 minutes

UAC & Local Admin Restriction:
Deny local login for all except administrators

Screenshot:
![GPO Baseline](screenshots/dc01/gpo-baseline.png)

11. Create GPO for Win10 Sysmon Deployment (Optional)

Later used to automate Sysmon installation via GPO.

12. Verify Replication and DNS

Run:

ipconfig /all
nslookup dc01
nslookup eke.local


Expected:

DNS resolves to 192.168.56.10

AD domain resolves correctly

Screenshot:
![DNS Verified](screenshots/dc01/dns-verified.png)

13. Final Checks

Run dcdiag

Check event logs under Directory Services

Ensure Win10 appears in _Computers OU

Author

Ekeoma Eneogwe
Cybersecurity Analyst — SOC / Blue Team
Active Directory • Network Security • Detection Engineering
