## Step 2.1 – Stage 2 Scenario Definition

Stage 2 focuses on Initial Access.

The planned simulation is:

- Kali hosts a harmless PowerShell script
- Windows 10 downloads the script
- Windows 10 executes the script
- The script creates a benign artifact on the Windows system

Expected artifact:

`C:\Temp\initial_access_marker.txt`
## Step 2.2 – Payload Preparation

A PowerShell script was created on the Kali attacker machine.

Script name:
benign_initial_access.ps1

Purpose:
Simulate a payload that will later be delivered to the Windows victim.

Script behavior:
- create directory C:\Temp
- create file initial_access_marker.txt
- write marker message into the file

This artifact will help the SOC analyst reconstruct the attack during investigation.
### Step 2.2 — Payload Script Creation

A PowerShell script was created on the Kali attacker machine.

Commands executed:

mkdir -p ~/project3_stage2  
cd ~/project3_stage2  
nano benign_initial_access.ps1

The script will simulate a payload execution on the Windows victim by creating a benign artifact.

Verification command:

ls

Evidence confirms the script file exists in the attacker staging directory.
### Step 2.5 – Victim Accesses Attacker Server

The Windows victim system accessed the attacker server hosted on the Kali machine.

URL accessed:

http://192.168.56.106:8080

The page returned a directory listing showing the hosted payload.

Files observed:

- benign_initial_access.ps1
- benign_initil_access.ps1.save

This confirms that the victim successfully communicated with the attacker infrastructure.
## Step 2.5 – Victim Server Contact

Victim machine accessed the attacker HTTP server.

Victim IP:
192.168.56.102

Attacker IP:
192.168.56.106

Port:
8080

Observation:
The server responded with a directory listing containing the payload script.

Impact:
This confirms the attacker delivery infrastructure is reachable from the victim host.
Expected evidence sources:

- Windows endpoint activity
- Splunk logs
- Zeek logs
- Wireshark packet capture

### Why this matters

This step defines the expected attack path before execution begins. It helps the analyst understand what evidence should appear during the Initial Access stage.
