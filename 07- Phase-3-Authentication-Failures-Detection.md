# Phase 3: Authentication Failures & Detection (Splunk)

## Overview
In this phase, I focused on detecting authentication-based attacks in an Active Directory environment using Windows Security logs and Splunk.

The objective was not simply to observe failed logon events, but to understand **how authentication attacks appear in logs**, **how attackers behave**, and **how a SOC analyst builds detection logic from raw telemetry**.

This phase involved simulating failed domain logons, analyzing Event ID 4625 in Splunk, and developing basic detection logic that can later be operationalized into alerts.

---

## Objective
- Simulate failed domain authentication attempts
- Analyze Windows Security Event ID 4625 in Splunk
- Extract and analyze key authentication fields
- Identify suspicious authentication patterns
- Build basic detection logic for brute-force and password spraying attacks

---

## Lab Systems
- **Host:** Windows Laptop (16 GB RAM)
- **Hypervisor:** VirtualBox
- **Splunk Server:** Ubuntu (Splunk Enterprise)
- **DC01:** Windows Server 2019 Domain Controller (Active Directory)
- **WIN10-CL01:** Windows 10 domain-joined endpoint

---

## Prerequisites
This phase builds on Phase 2, where log ingestion and forwarding were completed.

Validation search used:
```spl
index=lab_dc host=DC01
```

This confirmed that Windows Security logs from the Domain Controller were successfully ingested into Splunk.

---

## Step 1: Enable Authentication Auditing on the Domain Controller
To detect failed and successful authentication attempts, advanced audit policies were enabled on the Domain Controller.

### Configuration Path
```
Computer Configuration
→ Policies
→ Windows Settings
→ Security Settings
→ Advanced Audit Policy Configuration
→ Audit Policies
→ Account Logon
```

### Policy Enabled
- **Audit Credential Validation**
  - Success
  - Failure

### Why This Matters
Without this policy, authentication failures may not be logged, making detection impossible. Enabling this audit category ensures visibility into both failed and successful domain logons.

---

## Step 2: Apply Group Policy Changes
After updating the audit policy, changes were applied immediately on DC01.

Command used:
```cmd
gpupdate /force
```

This ensured that authentication events generated during testing were logged correctly without waiting for policy refresh intervals.

---

## Step 3: Simulate Failed Domain Logons (Event ID 4625)
To simulate authentication attacks, multiple failed login attempts were generated against Active Directory user accounts using incorrect passwords.

### Event Validation on DC01
In Event Viewer (Windows Logs → Security), the following was confirmed:
- **Event ID:** 4625
- **Task Category:** Logon
- **Keywords:** Audit Failure

### SOC Context
Event ID 4625 represents failed authentication attempts. High volumes of these events may indicate brute-force attacks, password spraying, or misconfigured services.

---

## Step 4: Confirm Successful Authentication (Event ID 4624)
After generating failed logons, successful authentication events were also validated to confirm end-to-end visibility.

In Event Viewer:
- **Event ID:** 4624
- **Keywords:** Audit Success

### Why This Matters
Authentication attacks often involve repeated failures followed by a successful login. Detecting this pattern increases confidence in identifying real threats.

---

## Step 5: Validate Authentication Events in Splunk
Authentication events were validated in Splunk using the following searches.

### Failed Logons
```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security EventID=4625
```

### Successful Logons
```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security EventID=4624
```

These searches confirmed that authentication events were being indexed correctly.

---

## Step 6: Extract Key Authentication Fields
To enable meaningful analysis, key fields were extracted from raw Windows Security events.

### Fields Extracted
- TargetUserName
- IpAddress
- LogonType

### SPL Used
```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security EventID=4625
| rex field=_raw "(?s)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "(?s)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| rex field=_raw "(?s)<Data\s+Name='LogonType'>(?<LogonType>[^<]+)</Data>"
| table _time TargetUserName IpAddress LogonType
| sort - _time
```

### Why This Matters
Extracting these fields allows grouping and correlation, which are essential for detecting attack patterns.

---

## Step 7: Reduce Noise and Focus on Relevant Events
To avoid false positives, events with empty or non-informative values were filtered out.

```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security EventID=4625
| rex field=_raw "(?s)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "(?s)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where TargetUserName!="" AND TargetUserName!="-" AND TargetUserName!="ANONYMOUS LOGON"
| stats count as failedAttempts by TargetUserName IpAddress
| sort - failedAttempts
```

Filtering noise ensures detection logic focuses on suspicious activity rather than background authentication failures.

---

## Step 8: Build Detection Logic for Authentication Attacks
A threshold-based detection approach was used to identify suspicious authentication behavior.

```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security EventID=4625
| rex field=_raw "(?s)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "(?s)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where IpAddress!="" AND IpAddress!="-" AND TargetUserName!=""
| bin _time span=5m
| stats count as failedAttempts dc(TargetUserName) as uniqueUsers by _time IpAddress
| where failedAttempts>=5
| sort - failedAttempts
```

### Detection Logic Explained
- Multiple failures in a short time window
- Same source IP
- Potential indication of brute-force or password spraying behavior

---

## Step 9: Correlate Failed and Successful Logons
To increase detection confidence, failed logons were correlated with successful logons.

```spl
index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security (EventID=4624 OR EventID=4625)
| rex field=_raw "(?s)<Data\s+Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "(?s)<Data\s+Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where IpAddress!="" AND IpAddress!="-" AND TargetUserName!=""
| eval outcome=if(EventID==4625,"FAILED","SUCCESS")
| bin _time span=10m
| stats count(eval(outcome="FAILED")) as failedAttempts
        count(eval(outcome="SUCCESS")) as successfulLogons
        values(TargetUserName) as users
  by _time IpAddress
| where failedAttempts>=5 AND successfulLogons>=1
| sort - failedAttempts
```

### SOC Interpretation
This pattern is a strong indicator of credential compromise and would warrant further investigation in a real environment.

---

## Outcome
By the end of Phase 3:
- Authentication failures and successes were successfully logged and ingested
- Event ID 4625 and 4624 were analyzed in Splunk
- Detection logic for authentication attacks was developed
- The lab environment was prepared for alert creation and incident response activities

---

## Lessons Learned
- Proper audit policy configuration is critical for authentication visibility
- Field extraction is essential for meaningful analysis
- Threshold-based detections require tuning to avoid false positives
- Correlating failures with success significantly improves detection confidence

---

## Next Phase
Phase 4 will focus on converting these searches into **Splunk alerts**, defining severity levels, and performing SOC-style incident triage and response.

