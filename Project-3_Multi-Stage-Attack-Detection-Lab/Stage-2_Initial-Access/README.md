# Stage 2 — Initial Access (Detection & SIEM Analysis)

## Overview
Stage 2 of the Multi-Stage Attack Detection Lab focuses on detecting and analyzing network activity related to initial access using Zeek logs and Splunk SIEM.

In this stage, network traffic was generated between lab machines, captured using Zeek, ingested into Splunk, analyzed, and used to create a detection rule and alert.

---

## Lab Environment

| Machine | Role | IP Address |
|--------|------|-----------|
| Windows 10 | Attacker / Client | 192.168.56.102 |
| Ubuntu Server | Zeek + Splunk | 192.168.56.20 |
| Target Service | Python HTTP Server | Port 8080 |

---

## Step 2.10 — Log Ingestion into Splunk

Zeek connection logs were transferred from the Ubuntu server and uploaded into Splunk.

### Log Source
- Tool: Zeek
- Log File: `conn.log`
- Splunk Index: `main`
- Source Type: `cnnlog`

### Purpose
This step moves network telemetry into the SIEM so that it can be searched, analyzed, and used for detection.

### Result
Zeek connection events became searchable in Splunk.

---

## Step 2.11 — Detection Query Validation

### Initial Detection Query
```spl
index=main sourcetype=cnnlog id.resp_p=8080
```

### Result
No events returned.

### Analyst Finding
The logs were ingested but fields were not fully extracted, so field-based searching failed.

### Adjusted Detection Query
```spl
index=main sourcetype=cnnlog "9997"
```

### Result
This query successfully returned connection events.

### Analyst Lesson
When field extraction fails, SOC analysts can use raw log searching to validate activity before fixing field parsing.

---

## Step 2.12 — Timeline Analysis

### Queries Used

All traffic:
```spl
index=main sourcetype=cnnlog
```

Traffic over time:
```spl
index=main sourcetype=cnnlog | timechart count
```

Filtered traffic:
```spl
index=main sourcetype=cnnlog "9997"
```

### Findings
| Field | Value |
|------|------|
| Source IP | 192.168.56.102 |
| Destination IP | 192.168.56.20 |
| Destination Port | 9997 |
| Protocol | TCP |
| Activity | Multiple connections |

### Analyst Interpretation
This shows repeated connections between the Windows machine and the Ubuntu server.
In a real environment, repeated unexplained connections could indicate:
- Initial access
- Beaconing
- Lateral movement
- Service interaction
- Command & Control traffic

In this lab, the activity is benign and lab-generated, but the investigation process is the same as in a real SOC.

---

## Step 2.13 — Detection Rule Creation

A detection rule was created in Splunk to detect this network activity.

### Detection Query
```spl
index=main sourcetype=cnnlog "9997"
```

### Detection Logic
Trigger when connections to the monitored port are detected.

### Alert Configuration
| Setting | Value |
|--------|------|
| Alert Name | Suspicious Web Connection |
| Query | index=main sourcetype=cnnlog "9997" |
| Trigger | Results > 0 |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |

### Purpose
This simulates SOC monitoring where analysts are alerted when suspicious network traffic is detected.

---

## Stage 2 SOC Workflow

This stage simulates a real SOC workflow:

1. Traffic generated
2. Traffic captured (Zeek)
3. Logs stored
4. Logs ingested into SIEM (Splunk)
5. Analyst searches logs
6. Timeline reconstructed
7. Detection rule created
8. Alert configured
9. Analyst investigates activity

---

## Evidence Collected

| Evidence | Description |
|---------|------------|
| conn.log | Zeek connection log |
| Splunk Events | Ingested Zeek logs |
| Timeline | Splunk timechart |
| Detection Query | Splunk search |
| Alert | Scheduled report/alert |

---

## Analyst Conclusion

Stage 2 successfully demonstrated:

- Network traffic capture using Zeek
- Log ingestion into Splunk SIEM
- Detection engineering using Splunk search
- Timeline reconstruction
- Alert creation
- SOC investigation workflow

### Classification
Benign lab activity (simulated initial access traffic)

---

## Skills Demonstrated

- Network traffic analysis
- Zeek log analysis
- SIEM log ingestion
- Splunk search
- Detection rule creation
- Alert configuration
- SOC investigation methodology
- Timeline analysis
- Network connection analysis

---

## Stage 2 Status
STAGE 2 COMPLETE
