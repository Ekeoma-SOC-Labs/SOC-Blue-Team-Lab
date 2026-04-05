# Alert Triage Checklist

Use this checklist during every alert investigation.

## Alert Review

- [ ] Read and understand the alert
- [ ] Identify what rule triggered the alert
- [ ] Identify alert severity

## Basic Information Collection

- [ ] Identify user involved
- [ ] Identify host involved
- [ ] Identify source IP
- [ ] Identify timestamp

## Investigation Steps

- [ ] Check source IP in threat intelligence
- [ ] Review Windows Security logs (4624, 4625)
- [ ] Review Sysmon logs (process, network, file activity)
- [ ] Search SIEM for related events
- [ ] Check firewall logs
- [ ] Check Defender / EDR alerts
- [ ] Build timeline of activity
- [ ] Determine whether activity succeeded or failed
- [ ] Determine whether behavior is normal or suspicious

## Classification

- [ ] False Positive
- [ ] Benign Positive
- [ ] True Positive
- [ ] Escalate to Tier 2

## Documentation

- [ ] Write triage report
- [ ] Include timeline
- [ ] Include event IDs
- [ ] Include analyst conclusion
- [ ] Recommend action

## Response

- [ ] Close alert
- [ ] Escalate
- [ ] Isolate host
- [ ] Block IP
- [ ] Reset password
