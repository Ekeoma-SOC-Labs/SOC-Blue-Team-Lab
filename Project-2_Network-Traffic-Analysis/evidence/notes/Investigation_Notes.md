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

## Step 4.4.2 – Zeek Baseline Analysis (Offline)

Zeek was executed in offline mode against a freshly captured baseline PCAP 
(baseline_day2.pcap).

Command used:
/opt/zeek/bin/zeek -r /home/splunkadmin/baseline_day2.pcap
## Step 4.4.3 – Zeek Output Verification

Purpose:
To confirm that Zeek successfully generated analysis logs after processing
the fresh baseline PCAP file.

Command used:
ls -lh

Command explanation:
- ls: Lists files in the current directory
- -l: Displays detailed file information (permissions, owner, size, timestamp)
- -h: Displays file sizes in human-readable format (KB, MB)

Outcome:
Multiple Zeek log files (e.g., conn.log, dhcp.log, weird.log) were present in
the output directory, confirming successful parsing of baseline traffic.

SOC relevance:
Verifying log generation ensures that analysis is performed on valid evidence
and prevents false assumptions during incident investigation.

Status: Completed and frozen.
## Step 4.4.4 – Zeek Log Identification

Purpose:
To identify the Zeek logs generated from baseline traffic and understand
their high-level use in SOC investigations.

Command used:
ls

Command explanation:
- ls: Lists files in the current directory to identify available Zeek logs

Key log identified:
conn.log

Explanation:
conn.log records metadata about every network connection observed in the
traffic, including source and destination IPs, ports, protocol, duration,
and byte counts.

SOC relevance:
conn.log is typically the first log analyzed during investigations because
it provides a complete overview of network communications and helps identify
suspicious or anomalous connections.

Status: Completed and frozen.
## Step 4.4.5 – Baseline Sanity Check (conn.log)

Purpose:
To perform a high-level sanity check on the baseline connection log and
confirm that it reflects normal lab network behavior.

Command used:
less conn.log

Command explanation:
- less: Opens the log file in read-only mode for safe viewing
- Allows scrolling through large files without modifying evidence

Observations:
- Traffic primarily involved internal lab IP addresses
- Protocol usage was consistent with expected baseline activity
- No obvious anomalies or suspicious patterns observed

SOC relevance:
A sanity check ensures the baseline is valid before deeper analysis or
comparison with malicious traffic.

Status: Completed and frozen.
## Step 4.4 – Zeek Baseline Processing (Closed)

All sub-steps under Step 4.4 were completed successfully, including offline
PCAP processing, log verification, log identification, and baseline sanity
checks.

The baseline was confirmed to represent normal lab network behavior and is
approved for use as a comparison reference in subsequent analysis phases.

Status: Completed and frozen.
### Zeek Log Overview (Baseline)

- conn.log: Records all network connections and is the primary log for SOC investigations.
- dhcp.log: Maps IP addresses to devices using DHCP lease information.
- dns.log: Records DNS queries and responses for domain activity analysis.
- http.log: Captures web-based activity including URLs and methods.
- ssl.log / tls.log: Provides metadata about encrypted traffic.
- weird.log: Highlights unusual or malformed network behavior.
- reporter.log: Contains Zeek processing warnings and errors.

Understanding the purpose of each log allows SOC analysts to quickly pivot
during investigations and correlate findings across multiple data sources.
## Step 4.5 – conn.log Field Overview (Part 1)

Purpose:
To understand the meaning and SOC relevance of core conn.log fields.

Command used:
less conn.log

Command explanation:
- less opens the file in read-only mode for safe inspection.

Key fields reviewed:
- ts: Timestamp of connection
- uid: Unique connection identifier
- id.orig_h / id.orig_p: Source IP and port
- id.resp_h / id.resp_p: Destination IP and port
- proto: Transport protocol
- service: Application guess
- duration: Length of connection
- orig_bytes / resp_bytes: Data transferred
- conn_state: Connection outcome

SOC relevance:
These fields form the foundation of network-based detection and investigation.
Understanding them allows analysts to identify anomalies, lateral movement,
scanning, and data exfiltration patterns.

Status: In progress.
### Step 4.5 (Part 1) – conn.log Core Fields

The core fields of conn.log were reviewed and mapped to SOC investigation
use cases. The analyst demonstrated understanding of connection initiation
(id.orig_h / id.orig_p) and data transfer analysis (orig_bytes / resp_bytes).

Status: Completed and frozen.
