# **Windows 10 Endpoint Configuration and Security Hardening**
### **Goal of This Component**

This Windows 10 machine represents a standard enterprise user workstation in the SOC home lab.
It is monitored for security events and forwards logs to Splunk for detection, investigation, and analysis.

In a real SOC environment, this type of endpoint is where most attacks begin (phishing, credential abuse, PowerShell misuse).

## **Environment Details**

- OS: Windows 10 (64-bit)

- Hostname: WIN10-CL01

- Role: User endpoint / log source

- Domain: EKE.local

- IP Address (Host-only): 192.168.56.102

- Log Forwarding: Splunk Universal Forwarder

## **Step 1 — Configure VirtualBox Network Interfaces**
### **Network Design**

Two network adapters were configured for the Windows 10 VM:

Adapter 1	                NAT	           Internet access (updates, downloads)

Adapter 2	                Host-only	   Internal SOC network (DC01 & Splunk communication)

Expected IP addresses:

- NAT: 10.x.x.x (assigned automatically)

- Host-only: 192.168.56.102

## **Step 2 — Rename Computer and Join Domain (EKE.local)**

To integrate the endpoint into the enterprise environment, the system was renamed and joined to the Active Directory domain.

### **Steps Performed**

1. Open System Properties

2. Click Rename this PC

3. Set computer name to:

WIN10-CL01


4. Select Domain and enter:

EKE.local


5. Authenticate using domain administrator credentials

6. Restart the system

## **Step 3 — Verify Domain Connectivity**

After reboot, domain membership and connectivity were verified.

### **Commands Used**
whoami
ping dc01
ping 192.168.56.10

### **Expected Output**

- Logged-in user shows domain context (e.g. eke\win10user)

- Successful ping responses from DC01

## **Step 4 — Create Local Administrator Account**

A local administrator account was created for maintenance and recovery scenarios.

### **Commands Used**
net user LocalAdmin Pass@123 /add
net localgroup administrators LocalAdmin /add

This mirrors real-world practices where break-glass or local admin access is maintained.

## **Step 5 — Install Splunk Universal Forwarder**

The Splunk Universal Forwarder was installed to forward endpoint logs to the Splunk server.

### **Software Downloaded**

- Splunk Universal Forwarder (Windows x64)

- Download page:
https://www.splunk.com/en_us/download/universal-forwarder.html

### **Installation Notes**

- Installed as Local System

- Default install path used:

C:\Program Files\SplunkUniversalForwarder\


- No receiving port enabled (forwarder-only role)

- Splunk server configured as destination:

192.168.56.103:9997

## **Step 6 — Configure Log Collection (inputs.conf)**

Windows Event Logs were configured for collection.

### **File Location**
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf

### **Configuration Applied**
[default]
host = WIN10-CL01

[WinEventLog://Security]
disabled = 0
renderXml = true

[WinEventLog://System]
disabled = 0
renderXml = true

[WinEventLog://Application]
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true

## **Step 7 — Verify Logs Are Reaching Splunk**
### **Forwarder Verification (Windows)**
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk list forward-server


Expected output:

Active forwards:
    192.168.56.103:9997

### **Splunk Search Verification**
index=wineventlog host=WIN10-CL01

Events appearing confirmed successful ingestion.

## **Step 8 — Notes on Detection & SOC Relevance**

This endpoint provides high-value telemetry for SOC monitoring, including:

- Authentication events (logons, failures)

- PowerShell execution activity

- Application and system behavior

These logs are critical for detecting:

- Credential abuse

- Lateral movement

- Malicious scripting activity

## **Future Enhancements**

- Install Sysmon for deeper endpoint visibility

- Deploy Sysmon via GPO from DC01

- Add advanced PowerShell logging

## **Ekeoma Eneogwe**
Cybersecurity Analyst — SOC / Blue Team
Hands-on detection engineering & security monitoring projects
