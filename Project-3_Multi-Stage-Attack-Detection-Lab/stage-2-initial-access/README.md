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

Expected evidence sources:

- Windows endpoint activity
- Splunk logs
- Zeek logs
- Wireshark packet capture

### Why this matters

This step defines the expected attack path before execution begins. It helps the analyst understand what evidence should appear during the Initial Access stage.
