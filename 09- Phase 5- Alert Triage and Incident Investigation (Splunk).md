# Phase 5 Alert Triage & Incident Investigation (Splunk)

---

## Phase Overview

Phase 5 focuses on **SOC-style alert handling and investigation**, building on the detection and alert created in Phase 4.  
This phase simulates how a SOC analyst responds **after an alert fires**, emphasizing triage, validation, timeline reconstruction, and incident closure.

Unlike detection engineering, the goal here is **not to build alerts**, but to **evaluate whether an alert represents a real security incident**.

---

## Environment

- **Host System:** Windows Laptop (VirtualBox Host)
- **SIEM:** Splunk Enterprise (Ubuntu Server)
- **Domain Controller:** DC01 (Windows Server 2019)
- **Endpoint:** WIN10-CL01 (Domain-joined Windows 10)
- **Log Source:** Windows Security Logs (XmlWinEventLog:Security)

---

## Alert Context

- **Alert Name:** AD Password Spray – Failures Followed by Success
- **Detection Logic Summary:**  
  Correlates failed logons (Event ID 4625) and successful logons (Event ID 4624) within a defined time window.
- **Alert Schedule:** Every 5 minutes
- **Search Window:** 10 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Critical

---

## Step 1: Alert Intake & Initial Triage

### Objective
Understand what the alert is claiming **before investigating logs**.

### Actions
- Verified the alert was **enabled and scheduled**
- Confirmed the alert **successfully fired**
- Reviewed alert results and trigger metadata

### Key Observation
The alert triggered even though only **one failed logon event** existed.

---

## Step 2: Alert Validation

### Objective
Confirm whether the alert results accurately reflect the detection logic.

### Baseline Validation

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security
| stats count as total_events

Confirmed continuous ingestion of DC01 security logs.

### Event ID Distribution
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security (4624 OR 4625)
| rex "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID

### Results

4624 (Successful Logons): 328

4625 (Failed Logons): 1

## Step 3: Failed Logon (4625) Analysis
### Objective

Determine the source and context of the failed authentication attempt.

Investigation Query

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security 4625
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "(?s)<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| rex "(?s)<Data Name='WorkstationName'>(?<WorkstationName>[^<]+)</Data>"
| rex "(?s)<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex "(?s)<Data Name='Status'>(?<Status>[^<]+)</Data>"
| rex "(?s)<Data Name='SubStatus'>(?<SubStatus>[^<]+)</Data>"
| table _time EventID TargetUserName IpAddress WorkstationName Status SubStatus
| sort _time

### Findings
Field	Value
Event ID	4625
Time	2025-12-31 19:14:21
TargetUserName	Administrator
IpAddress	127.0.0.1
WorkstationName	DC01
Status	0xc000006d
SubStatus	0xc000006a

### Interpretation

The failed logon originated locally on the Domain Controller

Loopback address (127.0.0.1) indicates internal authentication activity

Not associated with WIN10-CL01 or the suspected attack source

## Step 4: Timeline Reconstruction
### Objective

Determine whether failed and successful logons form a single attack sequence.

Time Window Used
2025-12-31 19:00:00 → 19:30:00

Timeline Query
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security (4624 OR 4625)
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "(?s)<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| rex "(?s)<Data Name='WorkstationName'>(?<WorkstationName>[^<]+)</Data>"
| rex "(?s)<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| eval outcome=case(EventID=="4625","FAILED",EventID=="4624","SUCCESS")
| table _time outcome EventID TargetUserName IpAddress WorkstationName
| sort _time


### Timeline Conclusion

- Failed and successful logons do not share:
    - Source IP
    - Target user
    - Workstation

- No evidence of a fail-then-success attack sequence

## Step 5: Incident Classification & Closure
### Incident Type

Authentication anomaly – False Positive

### Severity

Low / Informational

### Root Cause

Alert logic allowed failedAttempts > 0

Correlation did not enforce:

- Same source IP
- Same user
- Same host
- Correct sequence ordering

### SOC Disposition

Closed – False Positive

### Lessons Learned

- Alert logic must explicitly define thresholds and correlation conditions
- Single authentication failures can be benign and unrelated
- Timeline reconstruction is critical before declaring an incident
- False positives are a normal and expected part of SOC operations

## Next Phase

### Phase 6: Detection Tuning & Hardening

### Planned improvements:

- Require multiple failed attempts (≥5)
- Enforce same source IP and target user
- Exclude loopback and internal system activity
- Validate fail-before-success sequence
