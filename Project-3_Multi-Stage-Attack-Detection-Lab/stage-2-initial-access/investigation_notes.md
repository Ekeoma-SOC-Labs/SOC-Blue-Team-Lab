## Step 2.1 – Investigation Notes

Current stage: Initial Access

Planned simulation:
Kali will host a harmless PowerShell script.
Windows 10 will download and execute it.
## Step 2.2 – Investigation Notes

Activity performed:
Creation of a PowerShell script on the attacker machine.

File:
benign_initial_access.ps1

Purpose:
Simulate a benign payload that will later be executed on the Windows victim.

Analyst observation:
This step represents attacker preparation before payload delivery.

At this point, no evidence exists on the victim machine yet.
### Step 2.2 — Investigation Notes

Activity:
Creation of a PowerShell payload on the Kali attacker machine.

Evidence:
Terminal output confirms the presence of:

benign_initial_access.ps1

Observation:
Nano created an automatic backup file (.save).

Analysis:
This represents attacker payload preparation prior to delivery.
## Troubleshooting T1 – VM Network Issue

Observation:
Windows 10 VM cannot access network.

Impact:
Victim cannot connect to attacker server.

Action:
Checking VirtualBox network configuration.
## Troubleshooting T1 – VM Network Issue

Observation:
Windows 10 VM cannot access network.

Impact:
Victim cannot connect to attacker server.

Action:
Checking VirtualBox network configuration.

Expected artifact:
`C:\Temp\initial_access_marker.txt`

Expected evidence:
- download activity
- network connection between Windows and Kali
- PowerShell execution
- filesystem artifact creation

Analyst note:
This is the planning step. No suspicious execution has occurred yet.
## Troubleshooting T3 — Windows Network Address

Command executed:
ipconfig

Purpose:
Verify Windows received an IP address on the Host-Only network.

Reason:
Without a valid IP address, the victim machine cannot reach the attacker server.
## Troubleshooting – Windows Network Connectivity

Issue:
Windows VM could not communicate with the Kali attacker machine.

Observation:
Initial ipconfig output showed incorrect host-only IP configuration.

Resolution:
The Windows Ethernet adapter was reset and DHCP renewed.

Result:
Windows received a valid host-only IP address.

Victim IP: 192.168.56.102
Subnet: 255.255.255.0

Impact:
The victim machine can now communicate with the attacker server on the isolated lab network.
## Attacker Network Identification

Command executed on Kali:

ip a

Observation:

Two network interfaces were identified.

eth0 – Host-Only network
IP address: 192.168.56.106

eth1 – NAT network
IP address: 10.0.3.15

The host-only network (192.168.56.0/24) is used for the attack simulation between Kali and the Windows victim.
## Step 2.6 – Payload Retrieval

Victim downloaded a PowerShell script from the attacker HTTP server.

Victim IP:
192.168.56.102

Attacker IP:
192.168.56.106

Port:
8080

Observation:
The script contents were retrieved successfully via HTTP.

Security relevance:
PowerShell script downloads are frequently used in malware delivery and post-exploitation staging.
## Step 2.7 – PowerShell Payload Execution

Victim IP:
192.168.56.102

Script executed:
benign_initial_access.ps1

Command used:

powershell -ExecutionPolicy Bypass -File benign_initial_access.ps1
## Step 2.7 – Execution Evidence

Victim IP:
192.168.56.102

Payload:
benign_initial_access.ps1

Command executed:

powershell -ExecutionPolicy Bypass -File benign_initial_access.ps1

Observed artifacts:

Directory created:
C:\Temp

File created:
C:\Temp\initial_access_marker.txt

The marker file confirms that the payload executed successfully on the victim system.

Security relevance:

PowerShell execution with ExecutionPolicy bypass is commonly used by attackers to execute scripts while bypassing system protections.
## Step 2.8 – HTTP Traffic Investigation

Wireshark analysis confirmed the HTTP request used to download the payload.

Observed request:

GET /benign_initial_access.ps1

Victim IP:
192.168.56.102

Attacker IP:
192.168.56.106

Destination port:
8080

Security relevance:

HTTP requests for script files from internal servers may indicate attacker staging activity or malicious payload delivery.
## Step 2.8 – Wireshark Network Investigation

Wireshark packet capture confirmed the HTTP communication used to deliver the PowerShell payload.

Observed packets:

TCP handshake between victim and attacker.

HTTP request:

GET /benign_initil_access.ps1.save

HTTP response:

200 OK

Victim IP:
192.168.56.102

Attacker IP:
192.168.56.106

Destination port:
8080

Security relevance:

The captured HTTP request confirms the transfer of the PowerShell payload from the attacker server to the victim system.

Observed system changes:

Directory created:
C:\Temp

File created:
C:\Temp\initial_access_marker.txt

Security relevance:
PowerShell execution with ExecutionPolicy bypass is a common technique used by attackers to run malicious scripts.
