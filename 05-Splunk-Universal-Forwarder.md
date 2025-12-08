Purpose of the Universal Forwarder

The Splunk Universal Forwarder (UF) is a lightweight agent installed on endpoints or servers to securely forward logs to the Splunk Indexer.
In this lab, the UF is installed on WIN10-CL01 to forward:

Security Event Logs

System Logs

Application Logs

PowerShell Operational Logs

1. Download and Install Splunk Universal Forwarder

Download UF (Windows 64-bit) from Splunk:
https://www.splunk.com/en_us/download/universal-forwarder.html

Run installer with:

User: Local System

Install Path: C:\Program Files\SplunkUniversalForwarder\

During installation:

DO NOT enable a receiving port

Enter Splunk Indexer IP: 192.168.56.20

Enter receiving port: 9997

2. Configure Data Inputs (inputs.conf)

File location:

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


Final configuration:

[default]
host = WIN10-CL01

[WinEventLog://Security]
disabled = 0
renderXml = true

[WinEventLog://Application]
disabled = 0
renderXml = true

[WinEventLog://System]
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true

3. Configure Forwarding (outputs.conf)

File location:

C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf


Final configuration:

[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.20:9997

[tcpout-server://192.168.56.20:9997]

4. Restart the Forwarder Service

Open CMD as Administrator:

net stop splunkforwarder
net start splunkforwarder

5. Validate Forwarder Connection

Check if UF is forwarding to indexer:

cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk.exe list forward-server


Expected output:

Active forwards:
    192.168.56.20:9997
Configured but inactive forwards:
    None

6. Validate Monitored Directories
splunk.exe list monitor


You should see monitored logs like:

C:\Program Files\SplunkUniversalForwarder\var\log\splunk\*

Windows Event Logs (Security, System, Application)

7. Validate Ingestion on Splunk Server
Search 1 – Check all logs from WIN10
index=* host=WIN10-CL01

Search 2 – Count by sourcetype
index=* host=WIN10-CL01 | stats count by sourcetype


Expected sourcetypes:

XmlWinEventLog:Security

XmlWinEventLog:System

XmlWinEventLog:Application

XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

Troubleshooting Notes
1. No events appearing?

Use Administrator CMD

Ensure Event Log Readers permissions are correct

Restart UF:

net stop splunkforwarder & net start splunkforwarder

2. Cannot reach Splunk server?

Verify Host-Only Network adapter IP: 192.168.56.1 / .20

Verify Splunk is listening on port 9997:

sudo netstat -plnt | grep 9997

3. Missing PowerShell logs?

Enable logging:

Microsoft-Windows-PowerShell/Operational

