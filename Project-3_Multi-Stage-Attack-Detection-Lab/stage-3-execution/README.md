
# Stage 3 — Execution

## Executive Summary
Stage 3 focused on detecting Windows process execution activity using **Windows Security Event ID 4688** in Splunk. The investigation began by verifying whether process creation logs were present and usable in the environment. Although Event ID 4688 existed in the Windows Security logs, direct field-based searches in Splunk were initially unreliable, which required raw XML-based searching to confirm the data source.

The early dataset showed only normal Windows startup and system processes. When live user commands were executed on the Windows 10 endpoint, the expected execution events did not appear in Splunk. This led to a telemetry investigation, which identified the root cause: **Process Creation auditing was disabled** on the endpoint. After enabling the correct Windows audit policy, the environment successfully began capturing real user execution activity in Splunk, including `whoami.exe`, `hostname.exe`, `ipconfig.exe`, `net.exe`, `cmd.exe`, and `powershell.exe`.

This stage demonstrated a full SOC workflow: verifying telemetry, identifying a logging gap, fixing the root cause, validating improved visibility, reducing benign background noise, and analyzing parent-child process relationships. By the end of the stage, the lab provided reliable process creation visibility for execution detection and investigation.

---

## Project Overview
Stage 3 focused on detecting **execution activity** on a Windows endpoint using **Windows Security Event ID 4688** in Splunk. The purpose of this stage was to confirm whether process creation telemetry was available, improve its reliability, and use it to detect real user and shell execution activity on the lab endpoint.

In a SOC environment, execution detection is important because attackers must run tools, scripts, or binaries to progress through an attack. Monitoring process creation events allows analysts to identify what executed, when it executed, on which host it executed, and what parent process launched it.

---

## Objective
The objective of Stage 3 was to:

- verify that Event ID 4688 (Process Creation) was present in Splunk
- extract process names from raw Windows Security XML events
- establish a reliable query method for execution detection
- hunt for suspicious or attacker-relevant process names
- validate whether live user commands were visible in Splunk
- identify and resolve any telemetry gaps affecting process creation visibility
- detect `cmd.exe` and `powershell.exe`
- analyze parent-child process relationships for real shell execution

---

## Lab Environment

### Systems Used
- **Windows 10 Endpoint:** `WIN10-CL01`
- **Splunk Server:** Ubuntu-based Splunk Enterprise instance
- **Log Forwarding:** Splunk Universal Forwarder
- **Windows Log Source:** Security Event Logs

### Primary Data Source
- **Sourcetype:** `XmlWinEventLog:Security`
- **Index:** `lab_win10`
- **Primary Event ID:** `4688`

---

## Tools Used
- Splunk Enterprise
- Splunk Search & Reporting
- Windows 10
- Splunk Universal Forwarder
- Command Prompt
- Windows PowerShell
- `auditpol`
- Windows Security Event Logs

---

## Detection Methodology
This stage followed a structured SOC workflow:

1. Verify whether the required telemetry exists.
2. Identify the correct search method in Splunk.
3. Extract useful fields from the logs.
4. Establish a baseline of normal activity.
5. Hunt for suspicious or attacker-relevant execution.
6. Test live execution on the endpoint.
7. Investigate missing visibility when detections fail.
8. Fix the telemetry gap at the logging and audit level.
9. Re-run the detection after the fix.
10. Reduce false positives and background noise.
11. Analyze parent-child execution relationships.

---

