04 — Splunk Server (Ubuntu) Setup & Log Ingestion Pipeline
Overview

This document covers the installation and configuration of the Splunk Enterprise Server running on Ubuntu.
It includes networking configuration, Splunk installation, index creation, input configuration, and validation of incoming logs from Windows endpoints.

The Splunk server is the central logging platform for the SOC lab and receives logs from:

Windows 10 endpoint (via Universal Forwarder)

Domain Controller (via Universal Forwarder)

Future Linux endpoints

Attack simulations (PowerShell, malware, etc.)

1. Configure Ubuntu Network Interfaces

Ubuntu uses two network adapters:

Adapter	Mode	Purpose
Adapter 1	NAT	Internet access (updates, packages)
Adapter 2	Host-only	Internal SOC network communication with Win10 and DC01

Expected IP addresses:

NAT → Assigned dynamically (10.x.x.x)

Host-only → 192.168.56.103 (static recommended)

Set Static Host-Only IP

Edit Netplan config:

sudo nano /etc/netplan/01-netcfg.yaml


Example config:

network:
  version: 2
  ethernets:
    enp0s8:
      addresses:
        - 192.168.56.103/24
      gateway4: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]


Apply:

sudo netplan apply


Validation:

ip a
ping 192.168.56.102  (Win10)
ping 192.168.56.10   (DC01)

2. Install Splunk Enterprise

Download Splunk:

wget -O splunk.tgz "https://download.splunk.com/products/splunk/releases/10.1.0/linux/splunk-10.1.0.tgz"


Extract:

sudo tar -xvf splunk.tgz -C /opt


Set Ownership:

sudo chown -R splunk:splunk /opt/splunk


Start Splunk & Accept License:

sudo -u splunk /opt/splunk/bin/splunk start --accept-license


Create admin username & password.

3. Configure Splunk Web UI Access

By default Splunk binds to localhost.

Allow remote access:

sudo -u splunk /opt/splunk/bin/splunk set web-host 0.0.0.0
sudo systemctl restart Splunkd


Access from Win10:

http://192.168.56.103:8000

4. Create Indexes for Log Ingestion

Navigate to:

Settings → Indexes → New Index

Create:

Index Name	Purpose
wineventlog	Windows logs
sysmon	Sysmon events
endpoint	Generic endpoint logs
network	Network logs (future)

(Your screenshots go under this section.)

5. Configure Splunk to Receive Logs

Enable TCP input on port 9997:

In GUI:

Settings → Forwarding and receiving → Configure receiving → New Receiving Port

Port:

9997


Enable:

splunk enable listen 9997 -auth admin:<password>

6. Validate Incoming Events

From Splunk Search:

Windows Event Logs
index=wineventlog host=WIN10-CL01

Sysmon Logs
index=sysmon host=WIN10-CL01

Check Forwarder Status
index=_internal sourcetype=splunkd component=Metrics group=tcpin_connections


Expect to see connections from:

192.168.56.102 → Win10

192.168.56.10 → DC01

7. Real-World SOC Relevance

Splunk servers are used in enterprise SOC environments to:

✔ Correlate logs across the entire network

(Domain controller, endpoints, firewalls, cloud, etc.)

✔ Detect malicious behavior

(Security logs + Sysmon + PowerShell logs)

✔ Build dashboards for threat monitoring
✔ Support threat hunting

(Mitre ATT&CK mapping)

✔ Store evidence for incident response

Your SOC lab simulates exactly how a real SIEM works.

Author

Ekeoma Eneogwe
Cybersecurity Analyst — SOC / Blue Team
Detection engineering • Monitoring • SIEM Operations
