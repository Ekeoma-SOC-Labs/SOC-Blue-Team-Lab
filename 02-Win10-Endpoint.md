02 – Windows 10 Endpoint Configuration
Overview

This section documents the configuration of the Windows 10 endpoint used in the SOC Blue Team Lab.
The Windows 10 machine serves as the monitored host where security events such as authentication attempts, PowerShell activity, process execution, and attack simulation logs are generated and forwarded to the SIEM (Splunk).

This endpoint represents a typical workstation in an enterprise environment.

1. Install Required Windows Features
Enable .NET Framework 3.5

Many enterprise tools require .NET for execution.

Steps:

Open Control Panel → Programs and Features

Select Turn Windows features on or off

Check .NET Framework 3.5

Click OK and allow installation to complete

2. Rename the Computer

A meaningful hostname helps with identification inside Active Directory and SIEM dashboards.

Steps:

Open Settings → System → About

Click Rename this PC

Enter hostname:

WIN10-CL01


Reboot the machine

3. Join the Windows 10 Machine to the Domain

This allows centralized authentication, Group Policy enforcement, and log collection.

Steps:

Go to Settings → Accounts → Access work or school

Select Connect

Choose Join this device to a local Active Directory domain

Enter the domain name:

EKE.local


Authenticate using domain credentials:

Username: Administrator
Password: (Domain Admin Password)


Restart the machine and log in with domain credentials.

4. Verify Domain Connectivity

Run the following in Command Prompt:

whoami


Expected output:

eke\win10user


Check network:

ipconfig /all
ping DC01
ping 192.168.56.10

5. Configure Windows Firewall (Optional for Lab)

For testing and SIEM visibility, allow ICMP and remote management.

netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4 dir=in action=allow
netsh advfirewall firewall add rule name="Remote Management" dir=in action=allow program="C:\Windows\System32\mmc.exe"

6. Enable PowerShell Logging (Critical for SOC Detection Engineering)

PowerShell logs are essential for detecting malware, recon commands, and privilege abuse.

Enable via Local Group Policy:

Open gpedit.msc and navigate to:

Computer Configuration → Administrative Templates → Windows PowerShell


Enable:

Turn on PowerShell Script Block Logging

Turn on Module Logging

Turn on Transcription

Set transcription output directory:

C:\PSLogs

7. Enable Audit Policy (Windows Event Logs)

Open Local Security Policy:

Security Settings → Local Policies → Audit Policy


Enable:

Audit Logon Events → Success & Failure

Audit Account Logon → Success & Failure

Audit Object Access → Success & Failure

Audit Process Tracking → Success & Failure

Audit Account Management → Success & Failure

Audit Policy Change → Success & Failure

Audit Privilege Use → Success & Failure

These logs feed into Splunk for detection engineering.

8. Install Splunk Universal Forwarder

This allows logs from the endpoint to be sent to the SIEM.

Download:

Splunk Universal Forwarder (Windows 64-bit)

Install Using Command Line (Recommended):
msiexec.exe /i splunkforwarder.msi AGREETOLICENSE=Yes RECEIVING_INDEXER="192.168.56.20:9997" /quiet


Start the service:

NET START SplunkForwarder

9. Configure Universal Forwarder Inputs

Create/edit file:

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


Add:

[WinEventLog://Security]
disabled = 0

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0

[monitor://C:\PSLogs]
index = winevents
sourcetype = powershell:transcript


Restart UF:

splunk restart

10. Validate Log Flow in Splunk

On your Splunk server:

Search for Windows Security Events:
index=wineventlog host="WIN10-CL01"

Search for PowerShell activity:
index=winevents sourcetype="powershell:transcript"


If logs are present → endpoint monitoring is working.

Conclusion

The Windows 10 endpoint is now fully configured for:

Domain integration

PowerShell visibility

Event Log monitoring

Log forwarding to Splunk

SOC detections & threat simulations

This setup mirrors a real enterprise workstation feeding telemetry into a Security Operations Center.
