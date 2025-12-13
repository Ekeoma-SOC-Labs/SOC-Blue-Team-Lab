# **Splunk Universal Forwarder (Windows 10) Configuration**
### **Goal of This Component**

The Splunk Universal Forwarder (UF) is a lightweight log collection agent installed on endpoints and servers.
Its role in this lab is to securely forward Windows logs from endpoints to the Splunk Enterprise Server for indexing, monitoring, and analysis.

In this SOC lab, the Universal Forwarder is installed on WIN10-CL01 and forwards logs to the Splunk server.

### **Environment Details**

- Operating System: Windows 10 (64-bit)

- Endpoint Name: WIN10-CL01

- Role: Log source (endpoint)

- Splunk UF Install Path:
  C:\Program Files\SplunkUniversalForwarder\

- Splunk Indexer IP: 192.168.56.20

- Receiving Port: 9997

### **Logs Forwarded by This Endpoint**

The following Windows logs are collected and forwarded:

- Security Event Logs

- System Logs

- Application Logs

- PowerShell Operational Logs

These logs are critical for SOC use cases such as:

- Authentication monitoring

- Privilege abuse detection

- PowerShell-based attack detection

- Endpoint activity analysis

## **Step 1 — Download and Install Splunk Universal Forwarder**

### **Software Downloaded**

- Splunk Universal Forwarder (Windows 64-bit)

Downloaded from the official Splunk website:

https://www.splunk.com/en_us/download/universal-forwarder.html

### **Installation Process**

The installer was executed on WIN10-CL01 with the following selections:

- Run as: Local System

- Installation Path:
  C:\Program Files\SplunkUniversalForwarder\

During installation:

- Receiving port was NOT enabled (this is an indexer-only function)

- Splunk Indexer IP entered: 192.168.56.20

- Receiving Port entered: 9997

The installation completed successfully and the SplunkForwarder service was created.

## **Step 2 — Configure Data Inputs (inputs.conf)**

To define which logs the forwarder should collect, the inputs configuration file was manually created.

### **Configuration File Location**

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf

### **Final Configuration**

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

This configuration ensures logs are collected in XML format, which improves field extraction and parsing in Splunk.

## **Step 3 — Configure Forwarding Destination (outputs.conf)**

The forwarder was configured to send logs to the Splunk Enterprise Server.

### **Configuration File Location**

C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf

### **Final Configuration**

[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.20:9997

[tcpout-server://192.168.56.20:9997]

This ensures all collected logs are forwarded to the Splunk indexer over TCP.

## **Step 4 — Restart the Universal Forwarder Service**

After configuration changes, the forwarder service was restarted.

Commands used (run in Administrator Command Prompt):

net stop splunkforwarder
net start splunkforwarder

This reloads the input and output configurations.

## **Step 5 — Validate Forwarder Connection**

To confirm that the Universal Forwarder is actively connected to the indexer:

cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk.exe list forward-server

Expected Output

Active forwards:
  192.168.56.20:9997

Configured but inactive forwards:
  None

This confirms the forwarder is successfully connected.

## **Step 6 — Validate Monitored Inputs**

To confirm what the forwarder is monitoring:

splunk.exe list monitor

Expected monitored data includes:

Windows Event Logs (Security, System, Application)

PowerShell Operational Logs

Internal Splunk UF logs under:
C:\Program Files\SplunkUniversalForwarder\var\log\splunk\

## **Step 7 — Validate Log Ingestion on Splunk Server**

### **Search 1 — Confirm Logs from WIN10-CL01**

index=* host=WIN10-CL01

### **Search 2 — Verify Sourcetypes88

index=* host=WIN10-CL01 | stats count by sourcetype

### **Expected Sourcetypes**

XmlWinEventLog:Security

XmlWinEventLog:System

XmlWinEventLog:Application

XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

## **Step 8 — Troubleshooting Notes**

### **Issue 1 — No Events Appearing**

Actions taken:

- Ensured Command Prompt was opened as Administrator

- Verified file permissions

- Restarted the forwarder service

net stop splunkforwarder
net start splunkforwarder

### **Issue 2 — Cannot Reach Splunk Server**

Checks performed:

- Verified Host-only network IP addressing

- Confirmed Splunk server IP and port

- Verified indexer was listening on port 9997:

sudo netstat -plnt | grep 9997

### **Issue 3 — Missing PowerShell Logs**

Resolution:

- Confirmed PowerShell Operational logging was enabled

- Verified correct log channel name:

Microsoft-Windows-PowerShell/Operational

## **SOC & Real-World Relevance**

Universal Forwarders are used in real SOC environments to:

- Collect endpoint telemetry at scale

- Forward logs securely with minimal overhead

- Support detection engineering and threat hunting

- Enable centralized monitoring and investigations

This configuration mirrors enterprise-grade endpoint log collection.
