02 — Windows 10 Endpoint Configuration & Security Hardening
Overview

This document covers configuration of the Windows 10 machine used as the monitored endpoint in the SOC home lab. It includes networking setup, domain joining, Sysmon installation, log forwarding, and endpoint hardening.

1. Configure VirtualBox Network Interfaces

Windows 10 uses two adapters:

Adapter	Mode	Purpose
Adapter 1	NAT	Internet access (updates, packages)
Adapter 2	Host-only	Internal SOC network (communication with DC01 & Splunk)

Expected IP addresses (example):

NAT → 10.x.x.x (assigned automatically)

Host-only → 192.168.56.102 (static or DHCP from VirtualBox)

Screenshot:
![Win10 Network Adapters](screenshots/win10/win10-network-adapters.png)

2. Rename Computer & Join Domain (EKE.local)
Steps:

Open System Properties → Rename this PC

Set computer name: WIN10-CL01

Join Domain → EKE.local

Enter domain admin credentials

Restart system

Screenshot:
![Join Domain](screenshots/win10/win10-join-domain.png)

3. Verify Domain Connectivity

Run:

whoami
ping dc01
ping 192.168.56.10


Expected output:

eke\win10user
Reply from 192.168.56.10...


Screenshot:
![Whoami Output](screenshots/win10/whoami-domain.png)

4. Create Local Admin User (Optional)
net user LocalAdmin Pass@123 /add
net localgroup administrators LocalAdmin /add


This is useful for maintenance.

5. Install Sysmon (Critical for Detection)

Download Sysmon

Download SwiftOnSecurity Sysmon config

Run:

sysmon64.exe -i sysmonconfig.xml


Screenshot:
![Sysmon Install](screenshots/win10/sysmon-installed.png)

6. Install Splunk Universal Forwarder

Download UF installer (Windows x64)

Run:

msiexec /i splunkforwarder.msi AGREETOLICENSE=Yes /quiet

Configure forwarder:

Edit:

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


Add:

[WinEventLog://Security]
disabled = 0

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0


Outputs:

[tcpout]
defaultGroup=splunk_group

[tcpout:splunk_group]
server=192.168.56.103:9997


Screenshot:
![UF Config](screenshots/win10/universal-forwarder-config.png)

7. Verify Logs Reach Splunk

On Win10:

splunk list forward-server


Expected:

Active forwards:
    192.168.56.103:9997


On Splunk Searches:

index=wineventlog host=WIN10-CL01


Screenshot:
![Splunk Log Ingestion](screenshots/win10/splunk-results.png)

Author

Ekeoma Eneogwe
Cybersecurity Analyst — SOC / Blue Team
Hands-on detection engineering & security monitoring projects.
