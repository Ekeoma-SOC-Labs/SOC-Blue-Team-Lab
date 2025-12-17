# Phase 2: Log Ingestion and Forwarding Validation

## Overview
In this phase, I focused on building a reliable log ingestion pipeline for the SOC home lab.  
The objective was not just to “get logs into Splunk”, but to understand **how logs flow**, **where they can break**, and **how to troubleshoot issues the way a SOC analyst would**.

This phase involved configuring Splunk to receive logs, onboarding endpoints using the Universal Forwarder, and validating that both workstation and Active Directory logs were visible and searchable.

---

## Objective
- Configure Splunk to receive forwarded logs
- Forward Windows event logs using Splunk Universal Forwarder
- Separate endpoint and DC logs using dedicated indexes
- Validate ingestion with real search queries
- Troubleshoot ingestion failures and document the fix

---

## Lab Systems
- **WIN10-CL01** – Windows 10 endpoint
- **DC01** – Windows Server 2019 Domain Controller
- **Splunk Server** – Ubuntu 24.04
- **Splunk Universal Forwarder** – Installed on Windows hosts

---

## Step 1: Configure Splunk to Receive Logs

On the Splunk server, receiving was enabled on TCP port **9997**.

Verification command used:

sudo ss -tulnp | grep 9997

Expected output confirmed Splunk was listening on port 9997.

This port is used by Universal Forwarders to send log data to Splunk.

## Step 2: Index Creation
To ensure proper data separation and follow SOC best practices, dedicated indexes were created on the Splunk server.

Creating separate indexes allows:
- Clear distinction between endpoint and domain controller logs
- Faster searches
- More realistic enterprise-style data organization

### Indexes Created
- `lab_win10` – Windows 10 endpoint logs  
- `lab_dc` – Domain Controller (Active Directory) logs  

### Method Used
Indexes were created via Splunk Web:

Settings → Indexes → New Index


Each index was created with default settings, focusing on logical separation rather than retention tuning at this stage.

### Validation
Indexes were confirmed to exist and be selectable during searches.

---

## Step 3: Windows 10 Endpoint Log Forwarding
Splunk Universal Forwarder was installed and configured on the Windows 10 endpoint (WIN10-CL01) to forward local event logs to the Splunk server.

### Universal Forwarder Service Verification
The forwarder service was verified using PowerShell:

Get-Service | findstr Splunk

the output confirmed the service was running:

## Log Collection Configuration

A custom inputs.conf file was created on DC01:

C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


Configuration used:

[default]

host = DC01

[WinEventLog://Security]

index = lab_dc

disabled = 0

renderXml = true

[WinEventLog://System]

index = lab_dc

disabled = 0

renderXml = true

[WinEventLog://Directory Service]

index = lab_dc

disabled = 0

renderXml = true

The configuration focused on security-relevant Domain Controller telemetry.

## Step 5: Troubleshooting and Resolution

After configuration, DC01 logs did not initially appear in Splunk.

### Issue Observed

No events visible in the lab_dc index

Universal Forwarder service was running normally

### Diagnostic Command Used

To inspect active configurations, the following command was used:

splunk.exe btool inputs list --debug

The output revealed that Splunk was not loading the intended local input configuration.

### Root Cause Identified

The configuration file was mistakenly saved as:

inputs.conf.txt Instead of: inputs.conf

Because of this Windows file extension issue, Splunk ignored the file entirely.

### Resolution Steps

- Deleted the incorrectly named file

- Recreated the configuration using the correct .conf extension

- Restarted the Universal Forwarder

Restart-Service SplunkForwarder

## Step 6: Final Validation

After correcting the configuration, Domain Controller logs became visible in Splunk.

Validation was performed using the following search in Splunk Web:

index=lab_dc host=DC01


The following log sources were confirmed:

- Windows Security events
- System events
- Active Directory Directory Service events

This confirmed that the end-to-end log ingestion pipeline was functioning correctly

### Outcome

Phase 2 successfully established centralized log ingestion from both endpoint and Active Directory infrastructure.

At the end of this phase:

- All critical systems were forwarding logs
- Logs were correctly indexed and searchable
- The lab environment was ready for detection engineering and incident simulation
  
### Lessons Learned

- Small OS-level issues (such as file extensions) can silently break ingestion pipelines
- The btool command is essential for validating effective Splunk configurations
- Methodical, step-by-step troubleshooting is a critical SOC skill
