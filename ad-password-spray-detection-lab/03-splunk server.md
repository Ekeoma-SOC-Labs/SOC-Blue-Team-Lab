# **Splunk Server (Ubuntu) Setup and Log Ingestion Pipeline**
## **Goal of This Component**

The goal of this server is to act as the central SIEM for my SOC home lab.
It receives logs from Windows endpoints and the domain controller, indexes them, and provides a web interface for searching, monitoring, and investigations.

## **Environment Details**

OS: Ubuntu Server (64-bit)

Role: Splunk Enterprise Server (Indexer + Search Head)

Hostname: splunk

Static IP (Host-only): 192.168.56.103

Splunk Web Port: 8000

Receiving Port: 9997

## **Step 1 — Network Configuration (Ubuntu)**
### **Network Design**

Two network adapters were configured:

Adapter	Mode	Purpose
Adapter 1	NAT	Internet access (updates, downloads)
Adapter 2	Host-only	Internal SOC lab communication
### **Static IP Configuration (Host-only)**

The Netplan configuration file was edited to assign a static IP address to the host-only adapter.

Command used: sudo nano /etc/netplan/01-netcfg.yaml

Configuration applied:

network:
  version: 2
  ethernets:
    enp0s8:
      addresses:
        - 192.168.56.103/24
      gateway4: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]

Applied the configuration: sudo netplan apply

### **Validation**

ip a

ping 192.168.56.102 (WIN10-CL01)

ping 192.168.56.10 (DC01)

## **Step 2 — Splunk Enterprise Installation (Ubuntu)**
### **Software Downloaded**

- Splunk Enterprise 10.x for Linux (64-bit)

Downloaded from the official Splunk website:

https://www.splunk.com/en_us/download/splunk-enterprise.html

Downloaded directly on the server using:

wget -O splunk.tgz https://download.splunk.com/products/splunk/releases/10.1.0/linux/splunk-10.1.0.tgz

### **Installation Process**

Extracted Splunk into /opt:

sudo tar -xvzf splunk.tgz -C /opt

Set correct ownership:

sudo chown -R splunk:splunk /opt/splunk

Started Splunk and accepted the license:

sudo -u splunk /opt/splunk/bin/splunk start --accept-license

During first startup:

- Admin username and password were created

- Splunk services started successfully

Enabled Splunk to start on boot:

sudo /opt/splunk/bin/splunk enable boot-start

## **Step 3 — Splunk Web Configuration (Remote Access)**

By default, Splunk Web binds only to localhost.
To allow access from the Windows endpoint, remote access was enabled.

Commands used:

sudo -u splunk /opt/splunk/bin/splunk set web-host 0.0.0.0
sudo /opt/splunk/bin/splunk restart

### **Access Verification**

From WIN10-CL01, Splunk Web was accessed at:

http://192.168.56.103:8000

Successful login confirmed external connectivity.

## **Step 4 — Index Creation (Log Organization)**

Indexes were created to separate and organize log sources.

Navigation path:

Settings → Indexes → New Index

Indexes created and Purpose:

wineventlog	Windows Security, System, Application logs

sysmon	Sysmon telemetry

endpoint	Generic endpoint logs

network	Network telemetry (future use)

## **Step 5 — Configure Splunk to Receive Logs**

To receive logs from Universal Forwarders, a listening port was enabled.

### **GUI Configuration**

Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port

Port configured:

9997

### **CLI Verification**

sudo /opt/splunk/bin/splunk list listen

## **Step 6 — Log Ingestion Validation**

### **Forwarder Connectivity Check**

index=_internal sourcetype=splunkd component=Metrics group=tcpin_connections

Expected sources:

- 192.168.56.102 (WIN10-CL01)

- 192.168.56.10 (DC01)

### **Windows Event Logs**

index=wineventlog host=WIN10-CL01

### **Sysmon Logs**

index=sysmon host=WIN10-CL01

## **Step 7 — Troubleshooting Observations**

Issues encountered and resolved during setup:

- Splunk Web initially unreachable due to localhost binding

- Host-only network misconfiguration caused connectivity issues

- No logs arrived until port 9997 was enabled

- Forwarder health was confirmed using internal Splunk logs

These are common real-world SIEM deployment challenges.

## **Step 8 — SOC & Real-World Relevance**

This Splunk server mirrors enterprise SOC environments by:

- Centralizing logs from endpoints and servers

- Supporting detection of malicious PowerShell and authentication abuse

- Enabling threat hunting and investigations

- Providing evidence for incident response

- Supporting MITRE ATT&CK–aligned detections


## **Ekeoma Eneogwe**
Cybersecurity Analyst — SOC / Blue Team
