# Phase 4: Alert Creation, Validation & Troubleshooting
## Overview

In this phase, I converted the authentication attack detection logic developed in Phase 3 into a fully functional Splunk alert.

This phase reflects real SOC work, where detections that appear correct during manual searches may fail when converted into scheduled alerts due to time synchronization issues, incorrect time windows, or field extraction challenges.

The focus was not only on creating an alert, but on understanding why alerts fail, how to troubleshoot them, and how to validate alert execution using Splunk’s built-in tools.

## Objective
- Convert authentication attack detection logic into a Splunk alert
- Validate time synchronization across all lab systems
- Troubleshoot alert execution failures
- Refine SPL for alert reliability
- Confirm alert triggering and result visibility

### Lab Systems

- Host: Windows Laptop (VirtualBox host)
- Hypervisor: VirtualBox
- Splunk Server: Ubuntu (Splunk Enterprise)
- DC01: Windows Server 2019 Domain Controller
- WIN10-CL01: Windows 10 domain-joined endpoint

### Prerequisites

This phase builds on Phase 3, where authentication events were successfully detected in Splunk.

### Baseline validation search:

index=lab_dc host=DC01


This confirmed that Windows Security logs from the Domain Controller were available in Splunk.

## Step 1: Attempt Initial Alert Creation

The correlation search from Phase 3 was first saved as an alert.

### Detection logic used:

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security
(EventID=4624 OR EventID=4625)
| eval outcome=if(EventID=4625,"FAILED","SUCCESS")
| stats
    count(eval(outcome="FAILED")) AS failedAttempts
    count(eval(outcome="SUCCESS")) AS successfulLogons
| where failedAttempts > 0 AND successfulLogons > 0


Although this search returned results manually, the alert did not fire when scheduled.

## Step 2: Identify Time Window Issues

The alert showed: No triggered events

Manual searches only returned results when the time range was expanded

This indicated a time alignment issue rather than a log ingestion problem.

## Step 3: Validate Time on the Domain Controller

The Domain Controller time source was checked.

Command used: w32tm /query /status


Initial output showed: Time source: Local CMOS Clock

Time drift relative to the host system

This mismatch explained why scheduled alerts were missing events.

## Step 4: Synchronize Time on DC01

DC01 was configured to use a reliable time source.

Commands used: 
w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:YES /update
net stop w32time
net start w32time
w32tm /resync /force


The system time was then verified to match the host laptop.

## Step 5: Validate Splunk Server Time

The Splunk server time was checked to ensure alignment with DC01.

Commands used:
date
timedatectl


NTP was enabled:
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd
timedatectl

This ensured scheduled alerts would evaluate events within the correct window.

## Step 6: Confirm Windows 10 Endpoint Time

WIN10-CL01 time was verified and already matched the host system.

This was important because authentication attempts originated from this endpoint but were logged on DC01.

## Step 7: Confirm Security Log Ingestion

To rule out ingestion issues, sourcetypes were validated again.

index=lab_dc host=DC01
| stats count by sourcetype


This confirmed that XmlWinEventLog:Security events were still being indexed correctly.

## Step 8: Identify EventID Extraction Limitations

The following search unexpectedly returned no results:

EventID=4624 OR EventID=4625


However, raw XML clearly contained these values.

### Root Cause

In this environment, EventID was not reliably extracted as a searchable field.

### Resolution

Raw XML matching with rex was used instead.

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex "<EventID>(?<EventID>\d+)</EventID>"
| table _time EventID
| sort -_time


This consistently returned authentication events.

## Step 9: Extract Key Authentication Fields

Key fields required for alert logic were extracted manually.

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "(?s)<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| rex "(?s)<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| table _time EventID IpAddress TargetUserName
| sort -_time

## Step 10: Identify the Attacking Endpoint

The source IP was confirmed on WIN10-CL01.

Command used:

ipconfig


### Result:

IPv4 Address: 192.168.56.102

This IP was used to scope alert testing and reduce background noise.

## Step 11: Build Final Alert Detection Logic

The final detection focused on failed authentication attempts followed by a successful login from the same source IP.

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security
("<EventID>4624</EventID>" OR "<EventID>4625</EventID>")
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "(?s)<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| rex "(?s)<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| search IpAddress="192.168.56.102"
| eval outcome=if(EventID="4625","FAILED","SUCCESS")
| stats
    count(eval(outcome="FAILED")) AS failedAttempts
    count(eval(outcome="SUCCESS")) AS successfulLogons
    values(TargetUserName) AS targetedUsers
  BY IpAddress

## Step 12: Create the Splunk Alert

From the search interface, the alert was created with the following configuration:

Alert type: Scheduled

Schedule: Every 5 minutes

Time range: 30-minute window

Trigger condition: Number of results > 0

Trigger actions: Add to Triggered Alerts

Severity: Critical

An error was encountered:

rt time values are not allowed


This was resolved by ensuring:

The alert was scheduled (not real-time)

A fixed time window was selected

No real-time tokens were used

## Step 13: Validate Alert Execution

Alert execution was validated using Splunk’s Trigger History.

Trigger entries appeared as expected

Viewing results confirmed correlated authentication activity

This confirmed the alert was functioning correctly.

## Outcome

By the end of Phase 4:

- Time synchronization issues were resolved
- Authentication detections were successfully converted into alerts
- Alert logic was validated through real trigger events
- The lab environment now supports operational security alerting

## Lessons Learned

- Time synchronization is critical for alert reliability
- Manual searches do not behave the same as scheduled alerts
- Field extraction issues can silently break detections
- Troubleshooting is a core SOC analyst skill

## Next Phase

Phase 5 will focus on SOC-style alert triage and investigation, including alert analysis, timeline reconstruction, and incident response documentation.

