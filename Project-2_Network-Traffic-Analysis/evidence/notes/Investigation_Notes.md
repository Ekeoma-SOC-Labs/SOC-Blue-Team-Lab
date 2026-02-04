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

## Step 4.5 (Part 2) – Connection Behavior Analysis

Purpose:
To understand how connection behavior is represented in conn.log using
conn_state and duration fields.

Command used:
less conn.log

Command explanation:
- less opens the log file in read-only mode for safe inspection.

Key fields reviewed:
- conn_state: Indicates how a network connection ended
- duration: Shows how long the connection lasted

SOC interpretation:
- SF connections indicate normal, successful communication
- Repeated S0 or REJ states may indicate scanning or probing
- Long-lived connections may indicate tunneling or command-and-control
- Duration patterns help distinguish normal activity from anomalies

Status: In progress.
### Step 4.5 (Part 2) – Connection State & Duration

Purpose:
To understand how Zeek represents connection outcomes and behavior patterns
using conn_state and duration fields.

Command used:
less conn.log

Command explanation:
- less opens the log file in read-only mode to safely review connection data.

Key concepts:
- conn_state indicates how a connection ended
- SF represents normal successful connections
- Repeated S0 or REJ patterns may indicate scanning
- Duration patterns help detect beaconing and tunnels

Learning validation:
- Analyst correctly identified SF as normal baseline state
- Analyst recognized repeating durations as a suspicious automation pattern

Status: Completed and frozen.
### Step 4.5 (Part 2) – Connection State & Duration

Purpose:
To understand how Zeek represents connection outcomes and behavior patterns
using conn_state and duration fields.

Command used:
less conn.log

Command explanation:
- less opens the log file in read-only mode to safely review connection data.

Key concepts:
- conn_state indicates how a connection ended
- SF represents normal successful connections
- Repeated S0 or REJ patterns may indicate scanning
- Duration patterns help detect beaconing and tunnels

Learning validation:
- Analyst correctly identified SF as normal baseline state
- Analyst recognized repeating durations as a suspicious automation pattern

Status: Completed and frozen.
### Step 4.5 (Part 3) – Byte Direction Analysis

Purpose:
To understand traffic direction and volume using orig_bytes and resp_bytes
fields in conn.log.

Command used:
less conn.log

Command explanation:
- less opens the log file safely in read-only mode for inspection.

Key fields:
- orig_bytes: Data sent by connection initiator
- resp_bytes: Data sent by responder

SOC interpretation patterns:
- Small orig / large resp → normal browsing
- Large orig / small resp → possible data exfiltration
- Small both repeating → beaconing behavior
- Balanced large flows → possible tunnels or shells

SOC relevance:
Byte direction analysis helps detect data theft and command-and-control
behavior even when payloads are encrypted.

Status: In progress.

### Step 4.5 (Part 3) – Byte Direction Analysis

Purpose:
To understand traffic direction and volume using orig_bytes and resp_bytes
fields in conn.log.

Command used:
less conn.log

Command explanation:
- less opens the log file safely in read-only mode for inspection.

Key fields:
- orig_bytes: Data sent by connection initiator
- resp_bytes: Data sent by responder

SOC interpretation patterns:
- Small orig / large resp → normal browsing
- Large orig / small resp → possible data exfiltration
- Small both repeating → beaconing behavior
- Balanced large flows → possible tunnels or shells

SOC relevance:
Byte direction analysis helps detect data theft and command-and-control
behavior even when payloads are encrypted.

Status: In progress.

## Step 4.5 — conn.log Row-Level SOC Interpretation

### Objective
Practice interpreting a single Zeek connection record using SOC investigation logic.

### Command Used
less conn.log

### Command Meaning
- `less` opens the Zeek connection log in read-only mode
- This preserves forensic integrity
- Common SOC log review method

### Sample Connection Interpretation

Host 192.168.56.1 initiated a TCP connection to 192.168.56.20 on port 9997.  
The session lasted approximately 3–4 seconds.  
The initiator sent about 5 KB of data and received no response data.  
The connection state indicates a completed or attempted session depending on flag (SF/S0/SH observed in baseline traffic).  

### SOC Interpretation

This pattern is consistent with baseline service communication between internal lab systems.  
Traffic shows expected Splunk forwarder/service port behavior (9997).  
No indicators of data exfiltration or abnormal beacon timing observed in this record.

### SOC Relevance

SOC analysts must translate raw log rows into behavioral statements to support:
- incident reports
- alert triage
- threat hunting notes
- interview case scenarios

### Evidence
conn.log entry reviewed and interpreted manually.

Status: Completed and frozen.
## Step 4.6 — Source Connection Frequency Analysis

### Objective
Identify which hosts initiate the most connections in baseline traffic.

### Command Used
cat conn.log | grep -v '^#' | awk '{print $3}' | sort | uniq -c | sort -nr

### Command Explanation
- cat — reads conn.log
- grep -v '^#' — removes Zeek header lines
- awk '{print $3}' — extracts source IP field
- sort — groups identical IPs
- uniq -c — counts occurrences
- sort -nr — ranks by highest frequency

### SOC Relevance
Connection frequency helps detect:
- beaconing behavior
- scanning activity
- abnormal chatter
- service concentration

Baseline analysis establishes expected connection volume per host.

### Findings — Source Connection Frequency

Top initiating host: 192.168.56.1 (57 connections)

Interpretation:
Likely gateway / host adapter baseline chatter.

Lower counts observed for workstation host — consistent with baseline behavior.

SOC Insight:
High connection counts reveal repeated behavior patterns such as:
- beaconing
- command-and-control check-ins
- scanning
- service chatter
- lateral movement attempts
### Step 4.6.2 — Destination Connection Frequency

Command Used:
cat conn.log | grep -v '^#' | awk '{print $5}' | sort | uniq -c | sort -nr

Command Meaning:
- Extract destination IP field (column 5)
- Count how often each destination appears
- Sort from highest to lowest frequency

Purpose:
Identify connection concentration targets.

Findings:
192.168.56.20 received the majority of connections (57).

SOC Interpretation:
Destination concentration helps detect:
- service hubs
- command servers
- beacon targets
- data exfiltration endpoints

Observed pattern matches expected baseline service communication.
Step frozen.
### Step 4.6.3 — Port Frequency Analysis

Command:
cat conn.log | grep -v '^#' | awk '{print $6}' | sort | uniq -c | sort -nr

Command Meaning:
Extract destination port field and count frequency.

Findings:
Port 9997 dominated (57 connections).

SOC Interpretation:
Port 9997 corresponds to Splunk receiver service — expected baseline behavior.

Other observed ports:
- 67 → DHCP
- 134 → Windows RPC/NetBIOS chatter
- 3 → control/ICMP noise

No suspicious port concentration observed.

Step frozen.

### Step 4.6.4 — Connection Duration Analysis

Command:
cat conn.log | grep -v '^#' | awk '{print $9}' | sort -n | tail

Command Meaning:
Extract connection duration field and display longest sessions.

Findings:
Longest sessions were approximately 24 seconds.

SOC Interpretation:
Consistent duration clustering suggests normal baseline service behavior.

Duration analysis helps detect:
- beacon timing patterns
- automated C2 check-ins
- long data transfers (possible exfiltration)
- abnormal persistence sessions

Step frozen.
### Step 4.6.5.1 — Top orig_bytes Connections

Command:
cat conn.log | grep -v '^#' | awk '{print $10, $3, $6, $9, $11}' | sort -nr | head

Command Meaning:
Show connections where the initiator sent the most bytes.

Findings:
Highest byte senders were from 192.168.56.1 to port 9997 with consistent durations and zero response bytes.

SOC Interpretation:
Pattern matches Splunk ingestion traffic in the lab baseline.

Risk Note:
In real SOC environments, high orig_bytes with low response bytes on unknown ports may indicate data exfiltration.

Step frozen.
## Step 4.6.5.2 — Detect Response-Heavy Connections (Possible C2 / Beacon Replies)

Command:
cat conn.log | grep -v '^#' | awk '$11 > $10 {print $3, $5, $6, $10, $11, $9}' | head

Command Meaning:
Filters Zeek conn.log to show sessions where resp_bytes (server reply) is greater than orig_bytes (client sent data).

SOC Purpose:
Response-heavy sessions can indicate payload delivery, C2 replies, or downloads.

Result:
No output returned.

Interpretation:
No response-heavy connections were observed in this baseline capture.
This supports that baseline traffic is normal and not download/payload dominated.

Evidence:
Screenshot saved as step4_6_5_2_response_heavy_none.png
Status: Completed and frozen.
## Step 4.6.5.3 — Very Short Connection Detection

Command:
cat conn.log | grep -v '^#' | awk '$9 < 0.05 {print $3, $5, $6, $9, $12}' | head

Command Meaning:
Filters Zeek connection records to show sessions shorter than 0.05 seconds.

SOC Purpose:
Short-duration connections often indicate:
- port scanning
- service probing
- failed exploit attempts
- automated enumeration

Output Summary:
Short connections observed on ports 67 and 134 with SH and OTH states.

Interpretation:
Traffic consistent with DHCP and local network discovery behavior.
No scanning burst pattern observed.

Evidence:
step4_6_5_3_short_duration_connections.png

Status:
Completed and frozen.
## Step 4.7.1 — Source to Field Repetition Pattern

Command Used:
cat conn.log | grep -v '^#' | awk '{print $3,$9}' | sort | uniq -c | sort -nr | head

Command Meaning:
- cat conn.log → read Zeek connection log
- grep -v '^#' → remove header lines
- awk '{print $3,$9}' → extract selected fields
- sort → group identical values
- uniq -c → count repetitions
- sort -nr → show highest frequency first
- head → limit output

SOC Purpose:
Used to detect repeated behavioral patterns which may indicate:
- beaconing
- automation
- service chatter
- agent check-ins

Result Summary:
Repeated patterns observed — consistent with baseline automated service communication.

Interview Insight:
Repeated same-port traffic is not always malicious — it may indicate legitimate services such as log forwarding or monitoring agents.

Evidence:
step4_7_1_source_port_repetition.png

Status:
Completed and Frozen
## Step 4.7.2 — Service Baseline Distribution

Command Used:
cat conn.log | grep -v '^#' | awk '{print $8}' | sort | uniq -c | sort -nr

Command Meaning:
Extracts and counts detected services from Zeek connection logs.

SOC Purpose:
Identify which services appear in baseline traffic to establish expected protocol behavior.

Finding:
Most connections had no classified service (-).
DHCP appeared once — consistent with normal network lease behavior.

SOC Insight:
Baseline service distribution allows anomaly detection when new or rare services appear later.
Why Zeek Shows "-" in Service Field

Zeek displays "-" when it cannot confidently classify the application protocol.

Common reasons:
- short connections
- incomplete handshakes
- encrypted sessions
- uncommon protocols
- non-standard ports
- partial packet captures

SOC Relevance:
Attackers often attempt to hide protocol identity, so service classification gaps are important to monitor.
## Step 4.8.1 — Top Communication Pairs

Command:
cat conn.log | grep -v '^#' | awk '{print $3, $5}' | sort | uniq -c | sort -nr | head

Explanation:
Extracts source and destination IP pairs and counts frequency.

SOC Meaning:
Repeated communication pairs form behavioral clusters.

Baseline Finding:
192.168.56.1 → 192.168.56.20 dominates traffic.
Likely represents normal baseline service communication.

Detection Value:
Useful for identifying:
- Beaconing
- C2 check-ins
- Lateral movement
- Automated polling
## Step 4.8.2 — Source–Destination–Port Behavior Clusters

Command:
cat conn.log | grep -v '^#' | awk '{print $3, $5, $6}' | sort | uniq -c | sort -nr | head

Explanation:
Counts repeated source → destination → port combinations.

Baseline Finding:
192.168.56.1 → 192.168.56.20 → port 9997 is dominant.

SOC Meaning:
Represents stable baseline service communication.

Detection Value:
Repeated port patterns help detect:
- Beaconing ports
- C2 channels
- Lateral movement services
- Service hubs
## Step 4.9.1 — Duration Frequency Analysis

Command:
cat conn.log | grep -v '^#' | awk '{print $9}' | sort | uniq -c | sort -nr | head

Explanation:
Extracts connection duration values and counts how often each duration appears.

SOC Purpose:
Detects fixed timing patterns that may indicate beaconing or automated check-ins.

Baseline Finding:
Durations mostly unique with only small repetition.

Conclusion:
No strong timing-based automation detected in baseline traffic.
## Step 4.9.2 — Fixed Port Repetition Analysis

Command:
cat conn.log | grep -v '^#' | awk '{print $5 ":" $6}' | sort | uniq -c | sort -nr | head

Explanation:
Counts repeated destination IP and port combinations.

Finding:
192.168.56.20:9997 appears 57 times.

SOC Interpretation:
Port 9997 is Splunk ingestion port — repeated connections represent log forwarding behavior.

Conclusion:
Pattern consistent with baseline lab service traffic — not C2 beaconing.
## Step 4.9.3 — Multi-Port Targeting Detection

Command Used:
cat conn.log | grep -v '^#' | awk '{print $3 "->" $5 ":" $6}' | sort | uniq | awk -F':' '{print $1}' | sort | uniq -c | sort -nr | head

Command Explanation:
Extracts source → destination → port patterns, removes duplicates, and counts how many unique ports were used per target.

SOC Meaning:
Helps detect port scanning behavior where one host probes many ports on the same target.

Observation:
No high-count multi-port targeting detected.
Traffic pattern consistent with baseline service communication.

## STEP 4.10 — Detect Timing Pattern Repetition

### Command Used
cat conn.log | grep -v '^#' | awk '{print $3, $5, $9}' | sort | uniq -c | sort -nr | head

### Command Meaning
Reads Zeek connection log, removes header lines, extracts source IP, destination IP, and duration, groups repeated timing patterns, and shows the most frequent ones.

### Why This Matters (SOC Context)
Timing patterns are important because attackers can encrypt payload content but cannot easily hide timing behavior.

### Analyst Observation
Repeated duration values were observed between the same source and destination hosts.

### Analyst Interpretation
This may indicate beaconing malware or scheduled automated communication such as C2 check-ins.

### Evidence
Screenshot taken — timing pattern frequency output displayed.
## STEP 4.11 — Identify Top Talker Pairs by Frequency

### Command Used
cat conn.log | grep -v '^#' | awk '{print $3, $5, $6}' | sort | uniq -c | sort -nr | head

### Command Meaning
Reads Zeek connection log, removes header lines, extracts source IP, destination IP, and destination port, then counts how often each pair appears and shows the highest frequency pairs.

### Why This Matters (SOC Context)
Repeated communication pairs reveal behavior clusters and service hubs. High-frequency pairs may indicate beaconing, C2 check-ins, service chatter, or lateral movement patterns.

### Analyst Observation
Connection pair 192.168.56.1 → 192.168.56.20 on port 9997 appears most frequently.

### Analyst Interpretation
This is consistent with expected baseline lab service communication (Splunk ingestion port).

### Evidence
Screenshot taken — top talker pair frequency output displayed.
## Step 4.13 — Connection State Pattern Analysis

### Command Used
cat conn.log | grep -v '^#' | awk '{print $12}' | sort | uniq -c | sort -nr

### Command Meaning
Reads Zeek conn.log, removes header lines, extracts connection state field, counts frequency of each state, and sorts results by occurrence.

### Why This Matters for SOC
Connection state reveals how sessions end. Large numbers of incomplete or failed states may indicate scanning, probing, blocked ports, or unstable connections.

### Result Summary
SH = 28
S0 = 28
OTH = 4
SHR = 1

### SOC Interpretation
High S0 values indicate many unanswered SYN attempts, which may suggest scanning or unreachable services. In this baseline lab context, this likely reflects normal VM service chatter but should be monitored in real environments.

### Evidence
Screenshot: step-4-13-1-conn_state-frequency.png
## Step 4.13.2 — Source Host Generating Failed SYN Connections (S0)

### Command Used
cat conn.log | grep -v '^#' | awk '$12=="S0" {print $3}' | sort | uniq -c | sort -nr

### Command Meaning
Filters connection records with S0 state and counts which source IP generated the failed SYN attempts.

### SOC Purpose
Helps identify hosts performing scanning, probing, or failed connection attempts — useful for detecting reconnaissance behavior.

### Result
192.168.56.1 generated 28 S0 connections.

### Interpretation
Likely infrastructure or baseline service behavior in the lab network. No anomaly indicated.

### Evidence
Screenshot: step-4-13-2-s0-source-ip.png
## Step 4.13.3 — S0 Target Destination Analysis

### Command Used
cat conn.log | grep -v '^#' | awk '$12=="S0" {print $5}' | sort | uniq -c | sort -nr

### Command Meaning
Filters Zeek connection logs for S0 (failed SYN) states and counts destination IPs that received failed connection attempts.

### SOC Purpose
Identifies scan targets, unreachable services, and reconnaissance focus points.

### Result
28 192.168.56.20

### Interpretation
All failed connection attempts were directed to 192.168.56.20.  
This indicates repeated connection attempts to a non-responding or closed service port.  
In this lab context, it aligns with baseline service behavior toward the Splunk receiver port rather than malicious scanning.

### Evidence
Screenshot: step-4-13-3-s0-target-ip.png
## STEP 4.14 — Duration Pattern Clustering

### Command Used
cat conn.log | grep -v '^#' | awk '{print $9}' | sort -n | uniq -c | sort -nr | head

### Command Meaning
Extracts connection duration values from Zeek conn.log and counts repeated timing patterns.

### SOC Purpose
Timing patterns help detect beaconing and automated communications because attackers cannot easily hide timing behavior even when payload is encrypted.

### Analyst Observation
Duration values show mostly single occurrences with no strong repetition clusters.

### Analyst Interpretation
No clear beaconing or automated C2 timing pattern observed in baseline traffic.

### Evidence
Screenshot: step-4-14-1-duration-cluster.png
## STEP 4.15.1 — Largest Upload Sessions (orig_bytes)

### Command Used
cat conn.log | grep -v '^#' | awk '{print $10, $3, $5, $6}' | sort -nr | head

### Command Meaning
Extracts orig_bytes (bytes sent by the initiator) alongside source IP, destination IP, and destination port, then sorts descending to identify the largest upload sessions.

### SOC Purpose
Helps detect possible data exfiltration, abnormal uploads, or unusually large outbound transfers.

### Analyst Observation
Top upload sessions are dominated by traffic from 192.168.56.1 to 192.168.56.20 over destination port 9997.
Highest observed orig_bytes value: 22045 bytes.

### Analyst Interpretation
This pattern is consistent with baseline service communication in this lab (repeated traffic to a known service port). No clear evidence of abnormal upload or exfiltration behavior in this baseline dataset.

### Evidence
Screenshot: step-4-15-1-largest-upload.png
## STEP 4.15.2 — Largest Response Sessions (resp_bytes)

### Command Used
cat conn.log | grep -v '^#' | awk '{print $11, $3, $5, $6}' | sort -nr | head

### Command Meaning
Extracts resp_bytes (bytes returned by responder) and sorts descending to identify largest download sessions.

### SOC Purpose
Detects payload delivery, malware downloads, and abnormal response-heavy sessions.

### Analyst Observation
Top response byte values are very small and mostly zero. Observed traffic is limited to DHCP, ICMP, and baseline service chatter. No large response transfers detected.

### Analyst Interpretation
Baseline traffic shows no evidence of payload delivery or abnormal download behavior. Response sizes are consistent with normal lab service communication.

### Evidence
Screenshot: step-4-15-2-largest-response.png

## Step 4.16 — Baseline Summary Documentation (nano report)

### Command Used
nano baseline_summary.md

### Command Meaning
Opens (or creates) the baseline_summary.md file in nano text editor to document baseline traffic findings in a structured SOC report format.

### SOC Purpose
SOC analysts must convert raw packet/log evidence into a written baseline summary that can be referenced later to detect anomalies and support decision-making.

### Analyst Observation
A baseline summary report was written manually in baseline_summary.md, including:
- capture context
- key baseline findings (host pairs, port 9997 service behavior, conn_state patterns)
- analyst conclusion for baseline normal behavior

### Analyst Interpretation
The baseline report serves as the official reference point for comparison when we capture and analyze malicious traffic in Phase B.

### Evidence
Screenshot: step-4-16-final-baseline-summary.png
File created: baseline_summary.md

