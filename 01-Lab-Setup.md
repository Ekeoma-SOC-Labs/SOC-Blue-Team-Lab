01 — SOC Blue Team Lab Setup Documentation
Overview

This document captures the setup process for a hands-on SOC (Security Operations Center) home lab environment used for endpoint monitoring, SIEM ingestion, detection engineering, and attack simulation.
The environment includes:

Windows 10 Endpoint

Windows Server 2019 (Domain Controller)

Ubuntu Linux (Splunk SIEM Server)

VirtualBox Hypervisor

Custom SOC engineering configurations

The goal is to build a realistic enterprise environment for SOC analysis, threat detection, incident response, and blue team skill development.

1. Lab Infrastructure Summary
Component	Purpose	Status
Windows 10 (Endpoint)	User workstation, PowerShell logs, Sysmon logs, malware execution	✔ Configured
Windows Server 2019 (DC01)	Active Directory, central authentication	✔ Configured
Ubuntu Splunk Server	SIEM for log ingestion, dashboards, detection rules	✔ Configured
VirtualBox	Hypervisor	✔ Installed
2. Network Design

The lab uses a dual-adapter approach:

Windows 10 Endpoint

Adapter 1: NAT (internet access)

Adapter 2: Host-Only (internal lab communication)

Promiscuous Mode: Allow All

Domain Controller (DC01)

Adapter 1: Host-Only

Adapter 2: NAT (optional updates)

Ubuntu-Splunk

Adapter 1: NAT

Adapter 2: Host-Only

Host-Only Network:
192.168.56.0/24

Observed Host-Only IPs
Machine	IP
Windows 10	192.168.56.102 / 103
DC01	192.168.56.10
Splunk	192.168.56.x

Ping Tests:

✔ Windows 10 → DC01 (Successful)

✔ Windows 10 → Splunk (Successful)

✔ DC01 → Win10 (Successful)

This confirms internal communication is working correctly.

3. Windows 10 Endpoint Configuration
✓ Created Local Administrator (Offline Method)

Password reset via sethc.exe method:

Activated local Administrator account

Set password: Reign+Revival1@

✓ Joined Domain
EKE \ WIN10User

✓ Verified IP Configuration

Internal network functioning

Correct gateway and IP assignments

✓ Objective

This endpoint will forward logs to Splunk for:

Sysmon event reporting

PowerShell monitoring

Security event log analysis

Process creation logs

Network connection logs

4. Domain Controller (DC01)
✓ AD Services Installed

Domain: EKE.LOCAL

Administrator account active

Proper IP addressing configured

✓ Tested Connectivity

Windows 10 successfully pings the DC.

5. Ubuntu Splunk Server
✓ Installed Splunk

Listening on port 8000

Accessible from Windows 10 and DC01 (once firewall rules are added)

✓ Next Steps

Configure Splunk inputs for Windows logs

Install Splunk Universal Forwarder on Windows 10

Build Detection Dashboards

Start SOC Project #1:
Investigating malicious PowerShell execution

6. What Has Been Achieved So Far

✔ Built a 3-machine SOC environment
✔ Fixed Windows admin password issues
✔ Enabled local Administrator login
✔ Configured VirtualBox adapters correctly
✔ Achieved stable IP networking across all machines
✔ GitHub repository created for documentation
✔ Ready for log forwarding + Splunk ingestion

7. Next Phase

We will proceed with:

Phase 2: Windows Logging + Splunk Forwarding

Install Sysmon

Configure Sysmon XML

Install Splunk Universal Forwarder

Configure inputs.conf

Verify logs in Splunk

Author

Ekeoma Eneogwe
Cybersecurity Analyst (SOC / Blue Team)
Hands-on defensive security engineering projects.
