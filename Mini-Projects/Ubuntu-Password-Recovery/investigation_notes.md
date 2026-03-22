# Investigation Notes — Ubuntu Password Recovery

## Analyst
Ekeoma Eneogwe

## Project
Mini SOC Project — Ubuntu Password Recovery

## Status
Completed

---

## Scenario Summary
This mini project simulated a local Ubuntu password recovery scenario in the SOC lab. After access was restored, post-action host-based log analysis was performed to determine whether privileged activity associated with the recovery workflow left authentication traces on the Ubuntu system.

This project demonstrates a key blue-team lesson: on an unencrypted Linux system with console access, account recovery can become a security risk, and defenders should know how to validate that activity through system logs.

---

## Objective
- Recover access to Ubuntu in an authorized lab environment
- Validate whether authentication artifacts were generated after privileged activity
- Distinguish between normal root activity and analyst-initiated privileged activity
- Document findings in a SOC-style investigation note

---

## Evidence Captured
### Screenshot Reference
- `UBU-PWREC-07-authlog-root-session-text.png`

### Relevant Terminal Evidence
The strongest evidence was obtained with:

```bash
sudo grep -a "session opened for user root" /var/log/auth.log
```

Readable output included both routine CRON root sessions and a directly relevant sudo session opened by the lab user account:

```text
2026-03-22T07:43:05.054816+00:00 splunk-server sudo: pam_unix(sudo:session): session opened for user root(uid=0) by splunkadmin(uid=1000)
```

---

## Commands Executed During Analysis
```bash
sudo cat /var/log/aith.log | grep passwd
sudo cat /var/log/auth.log | grep passwd
sudo cat /var/log/auth.log | grep "session opened for user root"
sudo grep -a "session opened for user root" /var/log/auth.log
```

---

## Findings

### 1. Initial path typo corrected
The first command referenced the wrong file path:

```text
cat: /var/log/aith.log: No such file or directory
```

**Assessment:** This was a command typo, not a logging failure.

---

### 2. Direct `passwd` string search returned no visible result
The command:

```bash
sudo cat /var/log/auth.log | grep passwd
```

returned no visible matches.

**Assessment:** This does not prove that no password-related event occurred. It only shows that the exact keyword `passwd` did not return readable output in that search attempt.

Possible explanations include:
- the event was logged with different wording,
- the artifact may exist in rotated logs,
- the keyword was too narrow,
- or the event was not preserved in the visible portion of the file.

---

### 3. Binary-match behavior observed during piped grep
The command:

```bash
sudo cat /var/log/auth.log | grep "session opened for user root"
```

returned:

```text
grep: (standard input): binary file matches
```

**Assessment:** Matching content existed, but the chosen pipeline did not render it cleanly as readable text.

---

### 4. Readable root-session artifacts successfully extracted
The improved command:

```bash
sudo grep -a "session opened for user root" /var/log/auth.log
```

successfully returned readable evidence.

Two key patterns were identified:

#### Pattern A — Routine CRON root sessions
Example:

```text
CRON[3197]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
```

**Assessment:** These are expected system task entries and are not by themselves suspicious.

#### Pattern B — User-initiated sudo root session
Example:

```text
sudo: pam_unix(sudo:session): session opened for user root(uid=0) by splunkadmin(uid=1000)
```

**Assessment:** This is the most relevant SOC finding. It confirms that the `splunkadmin` account successfully opened a privileged root session via `sudo` during the exercise.

---

## SOC Interpretation
The log-analysis phase achieved its core objective.

### Confirmed
- `/var/log/auth.log` was the correct host authentication log source
- root-session activity was present and recoverable from the host log
- `splunkadmin` opened a root session via `sudo`
- privileged activity in the lab left authentication artifacts that a defender can validate

### Not directly confirmed
- a plain-text `passwd` event matching the exact keyword `passwd`

This means the recovery workflow was **meaningfully validated** from a SOC perspective even though a direct password-change string was not extracted.

---

## Why This Matters in a SOC Context
This project teaches several practical analyst lessons:

1. **Physical or console access matters.** On systems without full-disk encryption, local recovery can become a security exposure.
2. **Privileged actions leave traces.** Even if the exact password-change string is not found immediately, root-session artifacts can still validate sensitive activity.
3. **Context matters.** Not every root event is suspicious; analysts must separate routine CRON activity from user-driven sudo actions.
4. **Precision matters.** Small command errors can delay analysis or produce misleading conclusions.

---

## Incident-Style Summary
- **Event Type:** Local privileged activity validation after Ubuntu password recovery
- **Asset:** Ubuntu Splunk server VM
- **Relevant Account:** `splunkadmin`
- **Primary Log Source:** `/var/log/auth.log`
- **Strongest Evidence:** `sudo` session opened for `root` by `splunkadmin`
- **Investigation Outcome:** Successful validation of privileged-session artifacts
- **Project Status:** Complete

---

## Defensive Takeaways
- Enable **full-disk encryption (LUKS)** to reduce the risk of local password-reset abuse
- Restrict boot manipulation with **BIOS/UEFI protections**
- Maintain physical security over laptops, desktops, and lab hosts
- Monitor host authentication logs for:
  - `sudo` session openings
  - unexpected root activity
  - password or account changes
  - unusual reboot or maintenance patterns

---

## Conclusion
The Ubuntu password recovery mini project ended with successful SOC validation. Although a direct `passwd` log entry was not extracted during the commands executed, the analysis clearly confirmed privileged root-session activity tied to the `splunkadmin` account. This is sufficient to demonstrate that sensitive recovery-related actions can leave host authentication traces that are useful for defenders during investigation and post-incident validation.
