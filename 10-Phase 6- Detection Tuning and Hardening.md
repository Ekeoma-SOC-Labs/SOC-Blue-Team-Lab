## Phase 6: Detection Tuning and Hardening

### Objective
The goal of this phase was to take the working AD password spray detection from the previous phases and **tune it for reliability, accuracy, and operational use**. At this stage, the focus shifted away from “can we detect it?” to **“will this alert fire consistently and only when it should?”**

This phase mirrors what typically happens in a real SOC after an initial detection is built.

### Why Tuning Was Necessary
Although the password spray detection logic was already working, several issues were identified during testing:

- Alerts did not always trigger after simulated attacks  
- Some detections returned zero results even when events existed  
- Time-binning and scheduling caused missed correlations  
- The logic was too rigid for real-world timing variations  

These issues are common in real environments and required deliberate tuning rather than rewriting the detection.

### Key Tuning Decisions

#### 1. Event Scope Refinement
The detection was limited to the relevant Kerberos authentication events:

- **4771** – Kerberos pre-authentication failure  
- **4768** – Kerberos authentication success  

This ensured the alert focused strictly on password spray behavior and not unrelated authentication noise.

#### 2. Noise Reduction
To reduce false positives:
- Machine accounts were excluded using the `$` suffix filter
- IPv6-mapped IPv4 addresses (`::ffff:`) were normalized
- The detection was scoped to a realistic time window

This significantly improved signal quality without suppressing real attacks.

#### 3. Time Window & Binning Adjustments
Initial versions used smaller time bins that caused failures and successes to fall into different buckets, preventing correlation.

This was corrected by:
- Aligning `_time` binning with the alert time range
- Using a **15-minute aggregation window**
- Running the alert every **5 minutes**

This change alone resolved multiple missed detections.


### Hardened Detection Logic (Final)

index=lab_dc host=DC01 sourcetype=XmlWinEventLog:Security earliest=-30m latest=now
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<user>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<src>[^<]+)</Data>"
| eval src=replace(src,"::ffff:","")
| where EventID IN ("4771","4768")
| where NOT match(user,".*\\$$")
| eval outcome=case(EventID="4771","FAIL", EventID="4768","SUCCESS")
| bin _time span=15m
| stats 
    count(eval(outcome="FAIL")) as failures
    count(eval(outcome="SUCCESS")) as successes
    dc(user) as unique_users
    values(user) as users
    by _time src
| where failures>=5 AND successes>=1
| sort -failures

### Alert Configuration

The detection was converted into a scheduled alert with the following settings:

- Schedule: Every 5 minutes
- Time Range: Last 30 minutes
- Trigger Condition: Number of results > 0
- Throttle: 30 minutes
- Alert Type: Scheduled

This configuration balanced responsiveness with alert fatigue prevention.

### Validation & Testing

The alert was validated using controlled password spray simulations from a Windows client machine. Multiple failed authentication attempts followed by a successful login consistently triggered the alert once tuning was complete.

Testing confirmed:

- The alert triggers reliably
- False positives are reduced
- Legitimate password spray behavior is detected

### Outcome

At the end of this phase, the detection was no longer just “working” — it was operationally usable. The alert logic, timing, and thresholds now reflect realistic SOC conditions rather than lab-perfect assumptions.

This concludes the tuning and hardening phase of the password spray detection lifecycle.

### Lessons Learned

- Detection logic can be correct and still fail operationally
- Time binning and alert scheduling matter as much as SPL logic
- Testing alerts is just as important as testing detections
- Tuning is an iterative, sometimes frustrating, but essential process

