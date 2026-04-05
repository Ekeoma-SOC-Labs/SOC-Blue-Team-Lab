# Case Study — Brute Force Attack Investigation

## Alert Summary

**Alert Name:** Multiple Failed Login Attempts on Domain Controller DC01  
**Date/Time:** 2025-04-05 09:15 UTC  
**Host:** DC01.corp.local  
**User:** admin  
**Source IP:** 203.0.113.50  
**Severity:** High

## Why the Alert Triggered

The SIEM rule was designed to trigger when more than 10 failed logins occurred within 5 minutes from a single source IP. In this case, the alert fired because 47 failed login attempts targeted the domain administrator account within the defined time window.

## Logs Reviewed

- Windows Security Log — Event ID 4625 for failed login attempts
- Windows Security Log — Event ID 4624 to confirm whether any login succeeded
- Firewall logs to check whether RDP traffic was allowed
- Threat intelligence lookup for source IP reputation
- GeoIP lookup to validate whether the location matched expected user activity

## Investigation Findings

The investigation showed repeated failed RDP logins against the `admin` account from an external IP address. No successful logins were recorded from the same source during or after the alert window. The firewall allowed access on port 3389, which increased the exposure of the domain controller. The source IP had a poor reputation and was associated with brute force reports.

## Analyst Conclusion

This activity was not normal administrative behavior. The source was external, the login pattern was rapid and repeated, the target account was privileged, and the IP was flagged in threat intelligence sources. Even though the login attempts failed, the activity represented a real attack attempt.

## Final Classification

**True Positive**

## Recommended Actions

- Block the source IP at the perimeter firewall
- Enforce MFA on privileged accounts
- Remove direct RDP exposure from the internet
- Review account lockout policy settings
- Escalate to the network or security team for access hardening
