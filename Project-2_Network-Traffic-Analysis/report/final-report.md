# Final Investigation Report — Project 2 Network Traffic Analysis

## Analyst
Ekeoma Eneogwe

## Project Context

This lab investigation was conducted to practice SOC-style network traffic analysis using packet captures and Zeek logs. The objective was to establish a clean baseline of normal traffic, generate controlled suspicious traffic, and compare both datasets using structured log analysis techniques.

The investigation focused on behavioral patterns rather than payload inspection, following standard SOC triage methodology.

---

## Lab Environment

**Sensor VM:** Ubuntu Server with Zeek  
**Traffic Generator:** Windows 10 VM  
**Capture Tool:** tcpdump  
**Analysis Engine:** Zeek (offline PCAP replay)  
**Network Mode:** VirtualBox NAT + Host-only (sensor in promiscuous mode)

---

## Capture Method

Two datasets were created:

**Baseline dataset**
- Normal browsing and system activity traffic
- Captured using tcpdump
- Saved as baseline PCAP
- Parsed with Zeek to generate structured logs

**Simulation dataset (Phase B)**
- Controlled ICMP burst traffic generated using Windows ping command
- Captured with tcpdump before traffic generation
- Stored as separate PCAP
- Parsed with Zeek for structured comparison

Traffic capture was started before simulation to ensure full packet visibility and preserve evidence completeness.

---

## Baseline Analysis Summary

Zeek conn.log from the baseline dataset showed:

- Multi-protocol presence (TCP, DHCP, service traffic)
- Diverse destination hosts
- Repeated service communication to port 9997 (expected Splunk ingestion behavior)
- Mixed connection states consistent with lab infrastructure chatter
- Duration values mostly unique
- Byte patterns consistent with service communication rather than exfiltration

Behavioral conclusion:
Baseline traffic showed normal service-driven patterns with protocol diversity and destination spread.

---

## Simulation (Attack) Traffic Summary

Controlled ICMP burst traffic was generated from the Windows VM using repeated ping requests.

Zeek replay of the simulation PCAP showed:

- Protocol dominance: ICMP only
- Very low destination diversity
- Repeated multicast control destinations
- Short and tightly clustered durations
- Uniform response byte sizes
- Repetitive connection patterns
- OTH connection states common for ICMP records

Behavioral conclusion:
Traffic pattern is consistent with automated, scripted generation rather than user-driven activity.

---

## Baseline vs Simulation Behavioral Contrast

| Metric | Baseline | Simulation |
|--------|----------|------------|
Protocol diversity | Multiple protocols | ICMP only |
Destination diversity | Multiple hosts | Very limited |
Timing pattern | Mostly unique durations | Clustered short durations |
Behavior pattern | Service + user mix | Automated burst |
Byte distribution | Varied | Uniform small responses |

Key detection signal:
Protocol diversity collapse combined with timing clustering and repeated destinations.

---

## Detection Reasoning

No payload inspection was required to distinguish the datasets.

Behavioral indicators alone were sufficient:

- single-protocol dominance
- repeated short sessions
- low destination diversity
- uniform response sizes
- timing clustering

These are commonly used SOC behavioral detection signals for:

- scripted probing
- automated check-ins
- beacon-style behavior
- burst scanning patterns

---

## Limitations

This was a controlled lab simulation using ICMP burst traffic. It does not represent full adversary tradecraft or real malware command-and-control behavior.

However, the workflow demonstrates correct SOC investigation process:

- capture discipline
- evidence separation
- structured log parsing
- metric-based comparison
- behavioral detection reasoning

---

## Conclusion

The investigation successfully demonstrated how structured Zeek logs can be used to distinguish normal baseline traffic from automated suspicious traffic using behavioral metrics.

The simulation dataset showed multiple deviation signals compared to baseline, supporting a classification of:

**Outcome: Suspicious (Automated Traffic Pattern — Controlled Simulation)**

This lab reinforces that protocol mix, destination diversity, timing patterns, and repetition metrics are reliable first-pass SOC detection signals even without payload visibility.

---

## Analyst Notes

This exercise strengthened practical skills in:

- packet capture discipline
- Zeek log interpretation
- connection metadata analysis
- behavioral pattern detection
- SOC-style investigation documentation
- baseline vs anomaly comparison methodology

All conclusions were drawn from measured log evidence rather than assumptions.

