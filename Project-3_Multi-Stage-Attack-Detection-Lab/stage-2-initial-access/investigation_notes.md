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


Expected artifact:
`C:\Temp\initial_access_marker.txt`

Expected evidence:
- download activity
- network connection between Windows and Kali
- PowerShell execution
- filesystem artifact creation

Analyst note:
This is the planning step. No suspicious execution has occurred yet.
