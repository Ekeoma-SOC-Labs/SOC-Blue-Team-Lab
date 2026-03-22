# Mini SOC Project — Windows Administrator Account Recovery

## Project Overview
This mini project documents a **defensive, authorized Windows account recovery scenario** in a lab environment. The focus is not on bypassing authentication, but on understanding the difference between **approved recovery workflows** and **authentication bypass**, then analyzing the security implications, detection opportunities, and defensive controls.

In this scenario, a Windows system administrator forgets the login details for an authorized lab machine. Recovery is performed through a legitimate administrative path, and the analyst investigates the relevant Windows security artifacts afterward.

---

## Scenario
A system administrator has forgotten the password for a Windows account on an authorized lab endpoint. The machine belongs to the SOC lab, and recovery must follow an approved method.

### Safe recovery examples
- Use a **backup authorized local administrator account**
- Use **Microsoft account recovery** for a Microsoft-linked login
- Use a **domain administrator** in an AD lab to reset the account
- Rebuild/reimage the machine if recovery is not possible

For this mini project, the recommended lab setup is:
- `BackupAdmin` — authorized backup local administrator
- `PrimaryAdmin` — the account whose password is forgotten

The backup admin account is then used to reset the target account through standard Windows administration tools.

---

## Project Objective
The objectives of this mini project are to:
1. Understand the difference between approved recovery and authentication bypass.
2. Perform a legitimate Windows account recovery workflow in a lab.
3. Collect and review relevant Windows logs and artifacts.
4. Document the security risks that arise when organizations do not plan recovery safely.
5. Recommend hardening controls to reduce account takeover risk.

---

## What to Learn About Authentication Bypass
Authentication bypass means **gaining access without following the intended identity verification process**. In professional blue-team work, the goal is not to practice bypassing accounts on systems, but to understand:

- what preconditions make bypass possible,
- what evidence it leaves,
- how defenders detect it,
- and what controls stop it.

### Core concepts to understand
1. **Preconditions**
   - Physical or console access
   - Access to recovery media or boot settings
   - Lack of disk encryption
   - Weak account recovery planning
   - Excessive privileges granted to a single account

2. **Why it matters**
   - It can lead to local account takeover
   - It may expose sensitive files, cached credentials, browser data, SSH keys, tokens, and saved secrets
   - It can provide a pivot point for lateral movement

3. **What defenders should monitor**
   - Failed logon events
   - Successful administrative logons
   - Password reset/account management events
   - Local administrator group changes
   - Unexpected Safe Mode, recovery, or offline maintenance behavior

4. **What controls reduce the risk**
   - BitLocker or other full-disk encryption
   - Backup admin accounts stored and managed securely
   - LAPS or Windows LAPS
   - Separate user and administrator accounts
   - BIOS/UEFI protection and restricted boot options
   - Strong physical security

---

## Lab Setup
### Recommended endpoint accounts
- `BackupAdmin` — backup local admin
- `PrimaryAdmin` — primary admin account
- Optional standard user account for comparison

### Required tools
- Windows lab VM or endpoint you are authorized to manage
- Access to Event Viewer
- Local Users and Groups (`lusrmgr.msc`) or Computer Management
- Optional: PowerShell for event log review

---

## Approved Recovery Workflow (High Level)
1. Log in using the authorized **backup administrator account**.
2. Open **Computer Management** or **Local Users and Groups**.
3. Reset the password for the affected lab account through standard Windows administration.
4. Log out and test login to the recovered account.
5. Open Event Viewer and document the relevant evidence.

### Important note
This project intentionally focuses on **approved account recovery**, not on techniques that defeat Windows authentication.

---

## SOC Investigation Tasks
After the recovery, the analyst should investigate:

### 1. Logon activity
Look for:
- Failed logons
- Successful logons
- Administrative logons
- Logon type patterns

### 2. Account management activity
Look for:
- Password reset events
- Account changes
- User/group changes

### 3. Privilege use
Look for:
- Use of local admin accounts
- Security log events tied to privileged sessions
- Use of built-in admin tools

### 4. Timeline reconstruction
Document:
- When the lockout/forgotten-password situation was identified
- When backup admin access was used
- When the password was reset
- When the target account was successfully accessed again

---

## Windows Artifacts to Review
### Event Viewer
Primary log locations:
- **Windows Logs > Security**
- **Windows Logs > System**
- **Applications and Services Logs** (where relevant)

### Key evidence categories
- Failed logon attempts
- Successful logon events
- Account management changes
- Group membership changes
- Administrative activity tied to the recovery timeline

### Useful PowerShell / command-line review ideas
```powershell
Get-WinEvent -LogName Security -MaxEvents 50
```

```powershell
Get-LocalUser
```

```powershell
Get-LocalGroupMember -Group "Administrators"
```

These are safe administrative review commands and help support documentation.

---

## SOC Relevance
This project is useful for blue-team learning because it teaches:
- the difference between safe recovery and unsafe bypass behavior,
- how account recovery activity can appear in Windows logs,
- why BitLocker and recovery planning matter,
- and how administrators can reduce the chance of accidental insecurity when credentials are forgotten.

---

## Suggested Screenshot Checklist
Capture screenshots for:
- [ ] Windows login screen showing inability to access the target account
- [ ] Successful login to the backup admin account
- [ ] Computer Management / Local Users and Groups
- [ ] Password reset action for the target account
- [ ] Successful login to the recovered account
- [ ] Event Viewer showing relevant Security log activity
- [ ] Administrators group membership review

### Suggested screenshot names
- `WIN-PWREC-01-target-account-unavailable.png`
- `WIN-PWREC-02-backup-admin-login.png`
- `WIN-PWREC-03-computer-management-users.png`
- `WIN-PWREC-04-password-reset-action.png`
- `WIN-PWREC-05-recovered-account-login.png`
- `WIN-PWREC-06-eventviewer-security-log.png`
- `WIN-PWREC-07-admin-group-review.png`

---

## Defensive Controls
To reduce account recovery risk and account takeover exposure:
1. **Enable BitLocker** to protect offline access to the Windows disk.
2. **Maintain a secure backup admin strategy** rather than depending on a single admin account.
3. **Use Windows LAPS** or another secure local admin password management approach.
4. **Separate daily-use and administrative accounts**.
5. **Protect BIOS/UEFI settings** and restrict alternate boot paths.
6. **Monitor Security logs** for failed logons, account changes, and admin activity.
7. **Document account recovery procedures** so recovery is safe, repeatable, and auditable.

---

## Mini Incident Summary
**Incident Type:** Administrative account recovery scenario  
**Affected Asset:** Windows lab endpoint  
**Cause:** Forgotten password / lost account access  
**Recovery Method:** Approved administrative reset path  
**Primary Risk:** Unsafe recovery shortcuts could lead to account takeover exposure  
**Key Mitigation:** BitLocker, Windows LAPS, backup admin governance, and monitoring

---

## Conclusion
This mini project helps analysts understand that Windows password recovery is not just an IT support task—it is also a security issue. Organizations that fail to plan safe recovery may create pressure for insecure shortcuts. In contrast, a mature blue-team approach combines **approved recovery methods, logging, monitoring, encryption, and access governance**.

The professional lesson is simple: **learn the conditions that make authentication bypass possible, then become strong at detecting, preventing, and documenting those risks.**
