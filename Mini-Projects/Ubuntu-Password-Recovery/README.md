# Mini SOC Project — Ubuntu Password Recovery

## Project Overview
This mini project documents how to recover access to an Ubuntu system by resetting a local user password from recovery mode. In a SOC or blue-team context, this exercise helps demonstrate an important security lesson: **physical access to an unencrypted Linux endpoint can allow credential reset and unauthorized access**.

This project is intended for use **only in an authorized lab or on systems you own and are permitted to administer**.

---

## Lab Context
- **Platform:** Ubuntu VM in the SOC Blue Team Lab
- **Scenario:** The analyst lost access to the Ubuntu account password and must restore access safely
- **Objective:** Reset the password, recover access, validate the login, and document the security implications

---

## Learning Objectives
By completing this mini project, the analyst should be able to:
1. Access Ubuntu recovery mode from the GRUB boot menu.
2. Remount the root filesystem with write permissions.
3. Reset a local user password from the recovery shell.
4. Reboot and verify restored access.
5. Explain why full-disk encryption is a critical defensive control.

---

## SOC Relevance
Although password recovery is usually treated as a system administration task, it is also a security issue:
- It shows how **local physical access** can become a security risk.
- It highlights the weakness of relying only on account passwords without disk encryption.
- It helps analysts understand how attackers or insiders could abuse recovery mode.
- It reinforces the need for hardening controls such as **full-disk encryption, BIOS/UEFI protection, and restricted console access**.

---

## Tools / Requirements
- Ubuntu VM or physical Ubuntu machine you are authorized to manage
- Access to the VM console or physical keyboard/screen
- A known Ubuntu username (or ability to enumerate users)

---

## Step 1 — Open the GRUB Menu
1. Restart the Ubuntu system.
2. As the system begins to boot, hold or tap **Shift** (BIOS systems) or press **Esc** repeatedly (UEFI systems) until the **GRUB menu** appears.
3. Select **Advanced options for Ubuntu**.
4. Select the entry ending with **(recovery mode)**.

### Analyst Note
Recovery mode allows low-level maintenance. From a security perspective, this is also a possible abuse path when a device is not protected by encryption and boot restrictions.

---

## Step 2 — Drop to Root Shell
1. In the recovery menu, select **root – Drop to root shell prompt**.
2. You may see a message that the filesystem is mounted read-only.

### Why this matters
The recovery shell provides privileged access to the system. This means anyone with sufficient physical access may reach a root shell if proper protections are missing.

---

## Step 3 — Remount the Filesystem as Writable
Run:

```bash
mount -o remount,rw /
```

### Command Breakdown
- `mount` = manages mounted filesystems
- `-o` = passes mount options
- `remount,rw` = remount the existing root filesystem with **read-write** access
- `/` = the root filesystem

### Expected Outcome
The root filesystem becomes writable so system files, including password data, can be updated.

---

## Step 4 — Identify the Target Username (Optional)
If you do not remember the exact username, run:

```bash
ls /home
```

### Purpose
This shows the user home directories and can help identify the local account name.

---

## Step 5 — Reset the Password
Run:

```bash
passwd <username>
```

Example:

```bash
passwd analyst
```

You will be prompted to enter and confirm the new password.

### Expected Output
You should see a success message similar to:

```text
password updated successfully
```

### SOC Interpretation
At this point, account access has effectively been re-established without knowing the original password. This is the key security lesson of the exercise.

---

## Step 6 — Reboot the System
After the password reset is complete, reboot:

```bash
reboot
```

If `reboot` does not work from the recovery shell, you can try:

```bash
exec /sbin/init
```

or use the VM reset option from the hypervisor.

---

## Step 7 — Validate Access
1. Boot Ubuntu normally.
2. Log in with the username and the new password.
3. Confirm desktop or shell access is restored.

### Validation Checklist
- [ ] Ubuntu boots normally
- [ ] New password is accepted
- [ ] User desktop or shell opens successfully
- [ ] No account lockout or authentication errors observed

---

## Security Risk Analysis
### Observed Weakness
A local password can be reset from recovery mode when:
- the attacker has console access, and
- the disk is not protected with full-disk encryption.

### Potential Threats
- Unauthorized physical access
- Insider misuse
- Lost or stolen laptop compromise
- Privilege restoration after account lockout

### Impact
- Account takeover
- Exposure of locally stored files
- Access to cached credentials, browser data, SSH keys, notes, and lab artifacts
- Potential lateral movement if additional secrets are stored on the system

---

## Defensive Controls
To reduce this risk:
1. **Enable full-disk encryption (LUKS)** so the disk cannot be accessed or modified offline without the encryption passphrase.
2. **Set BIOS/UEFI passwords** to restrict unauthorized boot changes.
3. **Disable or restrict booting from external media**.
4. **Control physical access** to laptops, desktops, and lab hosts.
5. **Use strong account management practices** and keep sensitive secrets out of easily accessible local storage.

---

## Detection / Monitoring Ideas for a SOC Lab
Even though this attack path is largely offline/local, defenders can still monitor for:
- unexpected password changes
- suspicious use of `passwd`
- boot events into recovery or rescue mode
- filesystem integrity changes after unexpected reboots
- changes to `/etc/shadow` or `/etc/passwd`

### Example Log Hunting Ideas
Look for:
- authentication logs after reboot
- password change artifacts in `/var/log/auth.log`
- unusual root shell usage

Example commands after logging in:

```bash
sudo grep passwd /var/log/auth.log
sudo grep "session opened for user root" /var/log/auth.log
```

---

## Mini Incident-Style Summary
**Incident Type:** Unauthorized credential reset risk via recovery mode  
**Affected Asset:** Ubuntu endpoint / VM  
**Attack Precondition:** Physical or console access  
**Technique:** Boot into recovery mode and reset local password  
**Impact:** Local account compromise and data exposure  
**Primary Mitigation:** Full-disk encryption and physical access control

---

## GitHub Evidence Checklist
Capture screenshots for:
- [ ] GRUB menu
- [ ] Recovery mode selection
- [ ] Root shell prompt
- [ ] `mount -o remount,rw /`
- [ ] `passwd <username>` success output
- [ ] Successful login with new password

### Suggested Screenshot Names
- `UBU-PWREC-01-grub-menu.png`
- `UBU-PWREC-02-recovery-mode.png`
- `UBU-PWREC-03-root-shell.png`
- `UBU-PWREC-04-remount-rw.png`
- `UBU-PWREC-05-passwd-success.png`
- `UBU-PWREC-06-login-success.png`

---

## Conclusion
This mini project demonstrates a legitimate recovery workflow that is useful for system administration, but also exposes a serious physical security weakness when disk encryption is absent. In blue-team terms, the key lesson is clear: **passwords alone do not protect a system if an attacker can boot the machine and modify credentials offline or through recovery mode**.

The strongest control against this risk is **full-disk encryption combined with boot protection and physical security**.
