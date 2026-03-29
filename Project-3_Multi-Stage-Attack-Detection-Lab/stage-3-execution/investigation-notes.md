
## Step 3.1 — Verify Event ID 4688 Exists in Splunk

### Action Performed
Verified whether Windows Security Event ID 4688 existed in Splunk by searching raw XML-based security events.

### Searches Used
- `index=* sourcetype=XmlWinEventLog:Security EventID=4688`
- `index=* sourcetype=XmlWinEventLog:Security EventCode=4688`
- `index=* sourcetype=XmlWinEventLog:Security "4688"`

### Result
Direct field-based searches for `EventID=4688` and `EventCode=4688` returned 0 events. However, searching the raw event text for `"4688"` returned results. An expanded raw event confirmed a valid Windows Security process creation event with `<EventID>4688</EventID>`.

### Key Observation
The confirmed 4688 event came from:
- Host: `WIN10-CL01`
- Index: `lab_win10`
- Sourcetype: `XmlWinEventLog:Security`

### SOC Meaning
Event ID 4688 is a critical Windows Security event because it records new process creation. This event is heavily used by SOC analysts to detect suspicious process execution, malware launch, PowerShell abuse, command-line activity, and attacker reconnaissance.

### Analyst Conclusion
Process creation telemetry exists in the lab. The issue was not missing data, but inconsistent field extraction in Splunk. For this lab, raw XML text searching is a reliable way to access 4688 events.
## Step 3.2 — Pull Real 4688 Events from the Correct Index

### Action Performed
Ran a targeted Splunk search to retrieve real Windows process creation events from the Windows 10 endpoint:

`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"`

### Purpose
To isolate valid Event ID 4688 process creation logs from the correct host and index after confirming that direct field-based filtering was unreliable.

### Result
The search returned 11 Event ID 4688 results from the `lab_win10` index. The events were associated with host `WIN10-CL01`.

### Key Observation
The raw XML events clearly contained `<EventID>4688</EventID>`, confirming valid process creation telemetry. Visible processes included:
- `C:\Windows\System32\lsass.exe`
- `C:\Windows\System32\winlogon.exe`
- `C:\Windows\System32\services.exe`

### SOC Meaning
This step established a reliable search method for identifying Windows process creation activity in Splunk. Event ID 4688 is one of the most important Windows Security events for SOC monitoring because it reveals process execution behavior on endpoints.

### Analyst Conclusion
The process creation logs are available and searchable in Splunk using raw XML matching. This provides a dependable foundation for suspicious process analysis in the next step.
## Step 3.3 — Extract Process Names from Event ID 4688

### Action Performed
Ran a Splunk search that used `rex` to extract the `NewProcessName` field from raw XML-based Event ID 4688 logs:

`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | table _time host NewProcessName`

### Purpose
To transform raw process creation XML logs into a readable table showing the actual executable names launched on the Windows 10 endpoint.

### Result
The search returned a clean table of process names from host `WIN10-CL01`.

### Processes Observed
Examples included:
- `C:\Windows\System32\lsass.exe`
- `C:\Windows\System32\winlogon.exe`
- `C:\Windows\System32\services.exe`
- `C:\Windows\System32\csrss.exe`
- `C:\Windows\System32\wininit.exe`
- `C:\Windows\System32\smss.exe`
- `C:\Windows\System32\autochk.exe`
- `Registry`

### SOC Meaning
Extracting process names from Event ID 4688 is a key SOC analysis step because it allows analysts to identify which executables were launched on an endpoint. This helps distinguish normal operating system activity from suspicious execution such as PowerShell, command prompt abuse, malware binaries, or attacker tools.

### Analyst Conclusion
The current visible process creation events appear to represent normal Windows startup and system activity. No suspicious process names were identified in this step.
## Step 3.4 — Count Process Names from Event ID 4688

### Action Performed
Ran a Splunk search to count how many times each process name appeared in the Event ID 4688 dataset:

`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | stats count by NewProcessName | sort - count`

### Purpose
To identify the most frequently created processes in the current dataset and establish a baseline view of process execution activity on the Windows 10 endpoint.

### Result
The most common processes observed were:
- `C:\Windows\System32\smss.exe` = 3
- `C:\Windows\System32\csrss.exe` = 2

Other observed processes included:
- `C:\Windows\System32\autochk.exe`
- `C:\Windows\System32\lsass.exe`
- `C:\Windows\System32\services.exe`
- `C:\Windows\System32\wininit.exe`
- `C:\Windows\System32\winlogon.exe`
- `Registry`

### SOC Meaning
Counting process creation events helps analysts identify which executables are most common within a given period. This supports baseline development and makes it easier to spot unusual or low-frequency suspicious processes later.

### Analyst Conclusion
The observed process creation activity appears consistent with normal Windows startup and system behavior. No suspicious process names were identified in this dataset.
## Step 3.5 — Hunt for Suspicious Process Names in Event ID 4688

### Action Performed
Ran a targeted Splunk search for common suspicious or attacker-relevant process names within Event ID 4688 process creation logs:

`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" ("powershell.exe" OR "cmd.exe" OR "whoami.exe" OR "net.exe" OR "ipconfig.exe" OR "rundll32.exe")`

### Purpose
To identify whether the current process creation dataset contained common attacker or administrator command-line tools often associated with execution, reconnaissance, or abuse of built-in Windows utilities.

### Result
The search returned 0 events.

### SOC Meaning
This indicates that none of the selected suspicious process names were present in the current Event ID 4688 dataset for the selected time range. The visible process creation activity remains consistent with normal Windows startup and system behavior.

### Analyst Conclusion
At this point in the investigation, there is no evidence of suspicious command-line or attacker-like process execution in the available Windows 10 process creation logs.
## Step 3.6 — Test User Command Execution Against Event ID 4688

### Action Performed
Executed the following commands on `WIN10-CL01` from a normal Command Prompt session:
- `whoami`
- `hostname`
- `ipconfig`
- `net user`

After execution, multiple Splunk searches were run against Event ID 4688 logs to detect the corresponding process creation events.

### Searches Used
- `index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" ("whoami.exe" OR "hostname.exe" OR "ipconfig.exe" OR "net.exe")`
- `index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | search NewProcessName="*whoami.exe" OR NewProcessName="*hostname.exe" OR NewProcessName="*ipconfig.exe" OR NewProcessName="*net.exe" | table _time host NewProcessName`
- `index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | stats count earliest(_time) as earliest latest(_time) as latest`

### Result
No 4688 events matching the executed user commands were found. The latest available 4688 events still appeared to belong to the previously observed Windows startup/system process activity.

### SOC Meaning
This indicates that although Event ID 4688 telemetry exists in the lab, the currently visible dataset does not yet reflect the newly executed user-driven command activity. This may be caused by delayed ingestion, limited event forwarding, or incomplete audit policy coverage for the desired process execution visibility.

### Analyst Conclusion
The lab successfully demonstrated that process creation telemetry exists, but it also revealed a telemetry gap: user-executed commands were not yet visible in the searchable 4688 dataset. This is a realistic SOC finding and highlights the importance of validating log completeness before relying on a detection.
## Step 3.7 — Verify Windows Process Creation Auditing Status

### Action Performed
Checked the Windows audit policy for Process Creation on `WIN10-CL01` using:

`auditpol /get /subcategory:"Process Creation"`

### Result
The system returned:

`Process Creation    No Auditing`

### SOC Meaning
This confirms that Windows is not currently configured to audit process creation events properly on the endpoint. This explains why user-executed commands such as `whoami`, `hostname`, `ipconfig`, and `net user` did not appear reliably in the searchable Event ID 4688 dataset in Splunk.

### Analyst Conclusion
The missing or incomplete process execution visibility observed earlier in Stage 3 is caused by disabled process creation auditing. Telemetry improvement is required before execution detections can be considered reliable.
## Step 3.8 — Enable Windows Process Creation Auditing

### Action Performed
Enabled Windows auditing for the Process Creation subcategory on `WIN10-CL01` using:

`auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

Then verified the change with:

`auditpol /get /subcategory:"Process Creation"`

### Result
The Process Creation audit setting changed from **No Auditing** to **Success and Failure**.

### SOC Meaning
This improves endpoint telemetry by ensuring Windows records process creation events more reliably. This is essential for detecting user-executed commands, suspicious binaries, PowerShell abuse, and other execution activity through Event ID 4688.

### Analyst Conclusion
The main telemetry gap identified earlier in Stage 3 has now been addressed by enabling process creation auditing on the Windows 10 endpoint.
## Step 3.9 — Validate Command Execution Visibility After Enabling Process Creation Auditing

### Action Performed
After enabling Process Creation auditing on `WIN10-CL01`, the following commands were executed from Command Prompt:
- `whoami`
- `hostname`
- `ipconfig`
- `net user`

A Splunk search was then run to detect the corresponding Event ID 4688 process creation events.

### Splunk Search Used
`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | search NewProcessName="*whoami.exe" OR NewProcessName="*hostname.exe" OR NewProcessName="*ipconfig.exe" OR NewProcessName="*net.exe" | table _time host NewProcessName | sort - _time`

### Result
The search returned four matching events from host `WIN10-CL01`:
- `C:\Windows\System32\net.exe`
- `C:\Windows\System32\ipconfig.exe`
- `C:\Windows\System32\HOSTNAME.EXE`
- `C:\Windows\System32\whoami.exe`

### SOC Meaning
This confirms that Event ID 4688 is now capturing user-executed command activity correctly. The endpoint telemetry is now strong enough to support execution-focused detections for common attacker and administrator tools.

### Analyst Conclusion
The telemetry gap identified earlier in Stage 3 has been successfully resolved. Process creation auditing is now enabled, and live command execution events are visible in Splunk for analysis and detection.
## Step 3.10 — Detect PowerShell and CMD Execution in Event ID 4688

### Action Performed
Ran a Splunk search to detect PowerShell and Command Prompt execution after enabling Process Creation auditing on `WIN10-CL01`.

### Splunk Search Used
`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe" | table _time host NewProcessName | sort - _time`

### Result
The search returned 38 events from `WIN10-CL01`, including:
- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- multiple instances of `C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe`

### SOC Meaning
This confirms that Event ID 4688 is now capturing higher-value execution activity such as PowerShell and Command Prompt launches. It also demonstrates an important SOC analysis principle: not every PowerShell-related event is suspicious. Some entries may be generated by legitimate monitoring or logging tools.

### Analyst Conclusion
The endpoint telemetry is now capable of capturing meaningful execution events. However, the dataset includes benign background activity from Splunk Universal Forwarder, so future detections must distinguish between legitimate telemetry collection processes and actual user-driven or attacker-driven execution.
## Step 3.11 — Separate Real User Execution from Splunk Background Noise

### Action Performed
Ran a filtered Splunk search to isolate real user-driven `cmd.exe` and `powershell.exe` executions while excluding Splunk Universal Forwarder background activity.

### Splunk Search Used
`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe" | search NOT NewProcessName="*splunk-powershell.exe" | table _time host NewProcessName | sort - _time`

### Result
The filtered results returned two real execution events from `WIN10-CL01`:
- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### SOC Meaning
This step demonstrates the importance of filtering out benign operational noise from endpoint telemetry. Without this filtering, detection results may contain legitimate monitoring-related processes that can be mistaken for suspicious activity.

### Analyst Conclusion
The Event ID 4688 telemetry is now both visible and clean enough to distinguish real user shell execution from Splunk-generated background activity.
## Step 3.12 — Analyze Parent-Child Relationships for CMD and PowerShell

### Action Performed
Ran a Splunk search to extract both `NewProcessName` and `ParentProcessName` from Event ID 4688 logs for real Windows `cmd.exe` and `powershell.exe` executions.

### Splunk Search Used
`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>" | rex max_match=1 "<Data Name='NewProcessName'>(?<NewProcessName>[^<]+)</Data>" | rex max_match=1 "<Data Name='ParentProcessName'>(?<ParentProcessName>[^<]+)</Data>" | search NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe" | search NOT NewProcessName="*splunk-powershell.exe" | table _time host ParentProcessName NewProcessName | sort - _time`

### Result
The search returned two real execution chains from `WIN10-CL01`:
- `powershell.exe` launched `cmd.exe`
- `cmd.exe` launched `powershell.exe`

### SOC Meaning
Parent-child process analysis is a core SOC technique used to understand execution chains and detect suspicious behavior. Many execution-based detections rely not only on the child process itself, but also on identifying unusual or risky parent processes such as Office applications, browsers, or scripting engines.

### Analyst Conclusion
The Event ID 4688 telemetry is now rich enough to support parent-child execution analysis. In this case, the observed process relationships are benign and expected because they were generated manually during lab testing.
## Step 3.13 — Stage 3 Final Analyst Summary

### Stage Objective
The objective of Stage 3 was to validate and improve Windows process execution visibility using Security Event ID 4688 in Splunk, then use that telemetry to identify real command execution activity on the Windows 10 endpoint.

### Summary of Work Completed
Stage 3 began with verification of whether Event ID 4688 existed in Splunk. Although direct field-based searches initially returned no results, raw XML searches confirmed that valid 4688 process creation events were present from host `WIN10-CL01` in the `lab_win10` index.

A working Splunk search method was then established using raw XML matching:
`index=lab_win10 sourcetype=XmlWinEventLog:Security "<EventID>4688</EventID>"`

Using this method, process names were extracted and counted. The initial dataset consisted mainly of normal Windows system processes such as:
- `smss.exe`
- `csrss.exe`
- `lsass.exe`
- `services.exe`
- `wininit.exe`
- `winlogon.exe`

A threat-hunting check for suspicious execution tools such as `powershell.exe`, `cmd.exe`, `whoami.exe`, `net.exe`, and `ipconfig.exe` initially returned no useful user-driven results. A live validation test was then performed by executing standard commands on `WIN10-CL01`, but the expected execution events did not appear in Splunk. This indicated a telemetry visibility gap.

Further investigation identified the root cause. The Windows audit policy check using:
`auditpol /get /subcategory:"Process Creation"`
showed that Process Creation auditing was set to **No Auditing**.

This issue was corrected by enabling Process Creation auditing:
`auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

After enabling the policy, the live command execution test was repeated. This time, Splunk successfully captured the executed commands as Event ID 4688 process creation events, including:
- `whoami.exe`
- `HOSTNAME.EXE`
- `ipconfig.exe`
- `net.exe`

The lab then advanced to higher-value execution testing by detecting:
- `cmd.exe`
- `powershell.exe`

At this stage, additional PowerShell-related noise generated by Splunk Universal Forwarder (`splunk-powershell.exe`) was also identified. Filtering was applied to remove this benign telemetry and isolate only the real Windows shell processes.

Finally, parent-child process analysis was performed. This showed:
- `cmd.exe` launching `powershell.exe`
- `powershell.exe` launching `cmd.exe`

These relationships were expected and benign because they were manually generated during testing, but they demonstrated that the telemetry was now rich enough to support real execution-chain analysis.

### Key SOC Findings
- Event ID 4688 telemetry existed in the environment but required raw XML matching for reliable searching.
- Initial process visibility was limited to Windows startup and system processes.
- User-driven execution events were not visible until Process Creation auditing was explicitly enabled.
- After enabling auditing, Splunk successfully captured real command execution activity.
- Splunk-generated background processes such as `splunk-powershell.exe` can introduce noise and must be filtered out during detection analysis.
- Parent-child process relationships can now be extracted and analyzed, making the dataset much more valuable for SOC investigations.

### Analyst Conclusion
Stage 3 was successful. It moved from simple telemetry verification to practical execution detection and telemetry improvement. By the end of the stage, the Windows 10 endpoint was generating useful Event ID 4688 process creation logs in Splunk, including real user-executed commands and shell activity. The lab also demonstrated an important SOC principle: detection quality depends not only on having logs, but on validating that the right audit policies are enabled and that benign background noise is filtered appropriately.

### Stage 3 Outcome
By the end of Stage 3, the lab achieved the following:
- confirmed the presence of Event ID 4688 telemetry
- established a reliable Splunk search method for XML-based process creation events
- extracted and counted process names
- identified a telemetry gap
- verified the root cause using Windows audit policy
- enabled Process Creation auditing
- validated live command execution visibility
- detected `cmd.exe` and `powershell.exe`
- filtered Splunk-related false-positive noise
- analyzed parent-child execution chains

### Readiness for Next Stage
Stage 3 is now complete and provides a strong execution-detection foundation for the next attack phase in the project. The lab is now ready to move into **Stage 4 — Persistence**, where process creation telemetry can be used to detect persistence mechanisms such as scheduled tasks, registry run keys, or startup-based execution.
