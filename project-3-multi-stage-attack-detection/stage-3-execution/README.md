# Stage 3 — Execution

## Executive Summary
Stage 3 focused on detecting Windows process execution activity using **Windows Security Event ID 4688** in Splunk. The stage began by verifying whether process creation logs were present and usable in the environment. Although Event ID 4688 existed in the Windows Security logs, direct field-based searches in Splunk were initially unreliable, which required raw XML-based searching to confirm the data source.

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

## Step-by-Step Execution

### Step 3.1 — Verify Event ID 4688 Exists
The first step was to confirm whether Event ID 4688 existed in Splunk. Initial field-based searches using `EventID=4688` and `EventCode=4688` returned no results. A broader raw text search for `"4688"` within Windows Security XML events returned valid results, and an expanded raw event confirmed `<EventID>4688</EventID>` from host `WIN10-CL01` in index `lab_win10`.

**Searches used:**
```spl
index=* sourcetype=XmlWinEventLog:Security EventID=4688
index=* sourcetype=XmlWinEventLog:Security EventCode=4688
index=* sourcetype=XmlWinEventLog:Security "4688"
```

**Outcome:** Event ID 4688 telemetry was present, but direct field filtering was unreliable.

---

### Step 3.2 — Retrieve Real 4688 Events
After confirming that 4688 existed in raw logs, a reliable search pattern was established using raw XML matching in the correct index.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
```

This returned valid process creation events from `WIN10-CL01`.

**Outcome:** A working query pattern for 4688 events was established.

---

### Step 3.3 — Extract Process Names
The `NewProcessName` field was extracted from the raw XML using `rex`. This made the process creation data readable and easier to analyze.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| table _time host NewProcessName
```

**Examples observed:**
- `C:\Windows\System32\lsass.exe`
- `C:\Windows\System32\winlogon.exe`
- `C:\Windows\System32\services.exe`
- `C:\Windows\System32\csrss.exe`
- `C:\Windows\System32\smss.exe`

**Outcome:** Early visible activity reflected normal Windows startup and system processes.

---

### Step 3.4 — Count Process Frequency
The extracted process names were counted to identify the most common processes and establish a baseline of normal activity.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| stats count by NewProcessName
| sort - count
```

**Most common entries included:**
- `smss.exe`
- `csrss.exe`

**Outcome:** A basic process execution baseline was established.

---

### Step 3.5 — Hunt for Suspicious Process Names
A targeted search was run for common attacker-relevant or administrative tools such as PowerShell, Command Prompt, and common Windows utilities often used during reconnaissance or execution.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" ("powershell.exe" OR "cmd.exe" OR "whoami.exe" OR "net.exe" OR "ipconfig.exe" OR "rundll32.exe")
```

The search returned no results in the initial dataset.

**Outcome:** No suspicious or user-driven execution activity was visible yet.

---

### Step 3.6 — Test Live User Commands
To validate visibility, the following commands were executed manually on `WIN10-CL01`:

- `whoami`
- `hostname`
- `ipconfig`
- `net user`

The expectation was that Splunk would capture corresponding 4688 events. However, no matching events appeared.

**Outcome:** A telemetry gap was identified. Process creation events existed, but live user command execution was not visible.

---

### Step 3.7 — Check Process Creation Audit Policy
The next step was to determine why the live commands were not appearing. Windows audit policy was checked using `auditpol`.

**Command used:**
```cmd
auditpol /get /subcategory:"Process Creation"
```

The output showed:
```text
Process Creation    No Auditing
```

**Outcome:** The root cause of the telemetry gap was identified.

---

### Step 3.8 — Enable Process Creation Auditing
Process Creation auditing was enabled to improve process creation visibility on the endpoint.

**Commands used:**
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /get /subcategory:"Process Creation"
```

The verification output changed to **Success and Failure**.

**Outcome:** The endpoint was now configured to log process creation properly.

---

### Step 3.9 — Validate User Command Visibility After the Fix
After enabling Process Creation auditing, the same user commands were executed again. This time, Splunk successfully captured the resulting process creation events.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| search NewProcessName="*whoami.exe" OR NewProcessName="*hostname.exe" OR NewProcessName="*ipconfig.exe" OR NewProcessName="*net.exe"
| table _time host NewProcessName
| sort - _time
```

**Results included:**
- `whoami.exe`
- `HOSTNAME.EXE`
- `ipconfig.exe`
- `net.exe`

**Outcome:** The telemetry gap was resolved and live user execution became visible in Splunk.

---

### Step 3.10 — Detect PowerShell and CMD Execution
With process creation auditing fixed, the next step was to test higher-value shell execution activity. A targeted search for `cmd.exe` and `powershell.exe` was run.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe"
| table _time host NewProcessName
| sort - _time
```

This returned real `cmd.exe` and `powershell.exe` execution events, but also many instances of `splunk-powershell.exe`.

**Outcome:** Meaningful shell execution visibility was achieved, but legitimate Splunk-generated background noise was also identified.

---

### Step 3.11 — Filter Splunk Noise
To improve detection quality, a refined search excluded `splunk-powershell.exe` so that only real Windows shell activity remained.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe"
| search NOT NewProcessName="*splunk-powershell.exe"
| table _time host NewProcessName
| sort - _time
```

**Remaining results:**
- `cmd.exe`
- `powershell.exe`

**Outcome:** Detection quality improved by removing benign operational noise.

---

### Step 3.12 — Analyze Parent-Child Process Relationships
The final technical step extracted both `ParentProcessName` and `NewProcessName` to understand which process launched each shell.

**Search used:**
```spl
index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"
| rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>"
| rex max_match=1 "<Data Name='ParentProcessName'>(?<ParentProcessName>[^<]+)</Data>"
| search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe"
| search NOT NewProcessName="*splunk-powershell.exe"
| table _time host ParentProcessName NewProcessName
| sort - _time
```

**Observed chains:**
- `cmd.exe` → `powershell.exe`
- `powershell.exe` → `cmd.exe`

**Outcome:** The telemetry was now detailed enough for parent-child execution analysis.

---

### Step 3.13 — Final Analyst Summary
By the end of Stage 3, the lab had moved from simple telemetry verification to practical execution detection, telemetry improvement, noise filtering, and parent-child process analysis. The Windows endpoint was now providing meaningful Event ID 4688 visibility for execution-focused SOC investigations.

---

## Key Findings
- Event ID 4688 existed in the environment but required raw XML matching for reliable searching.
- Initial visible activity was limited to Windows system processes.
- Live user command execution was not visible at first because Process Creation auditing was disabled.
- Enabling Process Creation auditing resolved the telemetry gap.
- After the fix, user-executed commands became visible in Splunk.
- PowerShell and Command Prompt execution were successfully detected.
- Splunk-generated PowerShell activity introduced legitimate background noise that required filtering.
- Parent-child process relationships could be extracted successfully after the telemetry fix.

---

## SOC Lessons Learned

### 1. Telemetry existence is not the same as telemetry usability
Having logs in Splunk does not automatically mean they are searchable or detection-ready.

### 2. Raw log inspection is a critical analyst skill
When direct filtering fails, reviewing the raw event structure can reveal how the data is actually stored.

### 3. Missing detections can point to telemetry gaps
When expected activity does not appear, the issue may be logging configuration rather than the search query.

### 4. Endpoint audit policy directly affects SIEM visibility
The root cause of the missing execution events was disabled Process Creation auditing on the Windows endpoint.

### 5. Noise reduction is part of detection engineering
Legitimate background processes such as `splunk-powershell.exe` can create false positives if not filtered properly.

### 6. Parent-child analysis adds strong investigative value
Knowing what launched a process is often more useful than simply knowing the process ran.

### 7. Entry-level analysts should build detections in layers
A practical detection workflow is:
- confirm the data source
- identify the event type
- extract the useful field
- narrow to suspicious values
- filter known benign activity
- present the result clearly

---

## Conclusion
Stage 3 successfully transformed raw Windows process creation telemetry into a usable execution-detection workflow. The stage began with basic visibility checks, uncovered a real telemetry gap, identified the root cause at the audit policy level, fixed the issue, and validated meaningful execution detection in Splunk.

By the end of this stage, the lab was able to reliably detect:
- standard user commands
- `cmd.exe`
- `powershell.exe`
- parent-child shell execution chains

This stage also demonstrated a realistic SOC lesson: effective detection depends not only on having logs, but on validating that the right audit settings are enabled and that benign background noise is properly filtered.

---

## Screenshots
- `step-3-1-confirm-4688-raw-event.png`
- `step-3-2-search-4688-events-success.png`
- `step-3-3-extract-new-process-names.png`
- `step-3-4-count-process-frequency.png`
- `step-3-5-hunt-suspicious-processes-no-results.png`
- `step-3-6-run-test-commands-win10.png`
- `step-3-6-search-test-commands-no-results.png`
- `step-3-6-check-4688-latest-timestamp.png`
- `step-3-7-check-process-creation-audit-disabled.png`
- `step-3-8-enable-process-creation-audit-success.png`
- `step-3-9-validate-command-execution-visibility-success.png`
- `step-3-10-detect-powershell-and-cmd-execution.png`
- `step-3-11-filter-real-cmd-and-powershell-execution.png`
- `step-3-12-analyze-parent-child-process-relationships.png`