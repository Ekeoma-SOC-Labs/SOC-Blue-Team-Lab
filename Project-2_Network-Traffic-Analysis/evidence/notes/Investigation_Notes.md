# Investigation Notes – Project 2

## Case Information
- Analyst: Ekeoma Eneogwe
- Date:
- Project: Network Traffic Analysis

## Lab Machines
- Windows Victim:
- Sensor VM:
- Attacker (if any):

## Capture Strategy
(Where traffic was captured and why)

## Findings
(To be filled step by step)

## Indicators of Compromise (IOCs)
- Domains:
- IPs:
- URIs:

## Outcome
Benign / Suspicious / Confirmed Malicious

## Lessons Learned

## Lab Roles
- Victim: Windows VM/ Server: Generates normal and suspicious traffic
- Sensor: Ubuntu Linux VM (Zeek, Suricata, Wireshark):   Captures and analyzes network traffic 
- Attacker: Kali Linux VM :  Generates controlled suspicious traffic



Network design adjustment:
Removed secondary NIC from Windows VM after driver incompatibility with virtio-net.

Final design:
- Windows Victim: single NIC (NAT)
- Ubuntu-Splunk Sensor: host-only NIC in promiscuous mode

Rationale:
Simplified architecture to ensure stable internet access and reliable traffic capture without introducing driver dependencies.

SOC relevance:
Stability and observability take priority over unnecessary architectural complexity.

Network design adjustment:
Removed secondary NIC from Windows VM after driver incompatibility with virtio-net.

Final design:
- Windows Victim: single NIC (NAT)
- Ubuntu-Splunk Sensor: host-only NIC in promiscuous mode

Rationale:
Simplified architecture to ensure stable internet access and reliable traffic capture without introducing driver dependencies.

SOC relevance:
Stability and observability take priority over unnecessary architectural complexity.

STE 3
DNS issue encountered:
Windows VM was using internal DC DNS, which cannot resolve external domains.

Resolution:
Manually set DNS servers (8.8.8.8, 8.8.4.4) on NAT interface.

SOC relevance:
Domain-joined systems may require DNS overrides for external access during investigations.

## Step 3 – Baseline Traffic Capture (Final)

- Capture Interface: enp0s8
- Capture Tool: tcpdump
- DNS Status: External DNS (8.8.8.8)
- Traffic Observed:
  - DNS queries (google.com, wikipedia.org)
  - HTTPS traffic (Wikipedia, Microsoft)
- PCAP File: baseline_lab_traffic.pcap

Outcome:
Clean baseline traffic successfully captured after resolving NAT and DNS issues.
step 4.2
Zeek installed via official OpenSUSE repository.
Binary verified using /opt/zeek/bin/zeek --version (v8.1.0).

Baseline PCAP successfully parsed with Zeek v8.1.0.
Generated core logs: conn.log, dhcp.log, weird.log.
Checksum offloading warning observed (expected in VM environments).
