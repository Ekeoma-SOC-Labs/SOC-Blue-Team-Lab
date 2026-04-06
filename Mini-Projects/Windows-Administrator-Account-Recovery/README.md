# 🔐 Windows 10 VM Password Recovery & Security Hardening

![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-VirtualBox-orange?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Windows%2010-blue?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1546.008-red?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Offensive%20%2B%20Defensive-purple?style=for-the-badge)

---

> **Lab Objective:** This project covers two phases. Phase 1 documents how a locked Windows 10 VM was recovered by exploiting the Utilman.exe Accessibility Feature — a real-world local privilege escalation technique mapped to MITRE ATT&CK T1546.008. Phase 2 documents the defensive response: security hardening, BitLocker encryption, detection rules, and remediation steps a SOC analyst or system administrator should implement after such an event.

---

## ⚠️ Disclaimer

This project was conducted in a **controlled lab environment** on a personally owned virtual machine. All techniques are documented strictly for **educational and defensive security purposes**. Never attempt these methods on systems you do not own or have explicit written permission to access.

---

## 📋 Table of Contents

- [Lab Environment](#-lab-environment)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [PHASE 1 — Offensive: Password Recovery](#phase-1--offensive-password-recovery)
  - [Step 1 — Triggering WinRE](#step-1--triggering-windows-recovery-environment)
  - [Step 2 — WinRE CMD Blocked](#step-2--winre-cmd-access-blocked)
  - [Step 3 — ISO Boot Method](#step-3--iso-boot-method)
  - [Step 4 — Locating the Windows Drive](#step-4--locating-the-windows-drive)
  - [Step 5 — Executing the Utilman Exploit](#step-5--executing-the-utilman-exploit)
  - [Step 6 — Password Reset via SYSTEM Shell](#step-6--password-reset-via-system-shell)
  - [Step 7 — Access Restored](#step-7--access-restored)
- [PHASE 2 — Defensive: Security Hardening](#phase-2--defensive-security-hardening)
  - [Restore Utilman.exe](#1-restore-utilmanexe)
  - [Enable BitLocker](#2-enable-bitlocker-encryption)
  - [BIOS Boot Protection](#3-bios--uefi-boot-protection)
  - [Account Hardening](#4-account-hardening)
  - [Enable Audit Logging](#5-enable-audit-logging--siem-detection)
- [SOC Detection Analysis](#-soc-detection-analysis)
- [Key Lessons Learned](#-key-lessons-learned)

---

## 🖥️ Lab Environment

| Component | Details |
|-----------|---------|
| **Hypervisor** | Oracle VirtualBox |
| **Guest OS** | Windows 10 (Version 10.0.19041) |
| **Target Account** | Win10User (Local Account) |
| **Recovery Media** | Windows 10 22H2 ISO |
| **Attack Type** | Local Privilege Escalation / Authentication Bypass |
| **Date Performed** | April 5, 2026 |

---

## 🗺️ MITRE ATT&CK Mapping

| Field | Details |
|-------|---------|
| **Tactic** | Persistence / Privilege Escalation |
| **Technique** | T1546.008 — Accessibility Features |
| **Platform** | Windows |
| **Permissions Required** | SYSTEM (at execution) |
| **Defense Bypassed** | Windows Authentication |
| **Detection** | File Monitoring, Process Monitoring, Windows Event Logs |

---

## PHASE 1 — Offensive: Password Recovery

### Attack Chain
```
Force 3x Boot Interruption
        ↓
Automatic Repair Screen → WinRE
        ↓
WinRE CMD Blocked (password required)
        ↓
Boot from Windows 10 ISO
        ↓
ISO Recovery CMD (no password required)
        ↓
Locate Windows Drive (D:)
        ↓
move utilman.exe → utilman.exe.bak
copy /y syswow64\cmd.exe → system32\utilman.exe
        ↓
Reboot → Login Screen
        ↓
Click Accessibility Icon → SYSTEM Shell
        ↓
net user Win10User [newpassword]
        ↓
Full Access Restored ✅
```

---

### Step 1 — Triggering Windows Recovery Environment

**Method:** Force Restart 3 Times

When Windows boot is interrupted three consecutive times, it automatically launches the **Windows Recovery Environment (WinRE)**.

**Steps Performed:**
1. Started the Win10 VM in VirtualBox
2. During boot (spinning dots visible) → **Machine → Reset** in VirtualBox
3. Repeated 3 times
4. 4th boot → **Automatic Repair** screen launched automatically

![Automatic Repair Screen](screenshots/01_automatic_repair.png)
*Windows Automatic Repair screen triggered after 3 forced boot interruptions — entry point into WinRE.*

**SOC Interpretation — Windows Events Generated:**

| Event ID | Description |
|----------|-------------|
| 41 | Kernel-Power — system rebooted without clean shutdown |
| 6008 | Unexpected system shutdown |
| 1001 | Windows Error Reporting — boot failure |

> 🔴 Multiple Event ID 41 entries in rapid succession = potential forced WinRE access attempt.

---

### Step 2 — WinRE CMD Access Blocked

Navigating to **Troubleshoot → Advanced Options → Command Prompt** prompted for the **Win10User password** — the same forgotten password.

![Advanced Options](screenshots/02_advanced_options.png)
*WinRE Advanced Options menu — Command Prompt requires account credentials before granting access.*

> ✅ **Defensive Win:** The WinRE password prompt successfully blocked the first attempt — showing that local account passwords do provide an extra layer of protection in the recovery environment.

**Resolution:** ISO boot method used as fallback — bypasses WinRE password entirely.

---

### Step 3 — ISO Boot Method

**VirtualBox Configuration:**
1. Powered off VM → **Settings → Storage**
2. Mounted `Win10_22H2_English_x64v1.iso` as optical drive
3. **Settings → System → Motherboard** → moved **Optical to top** of boot order

![VirtualBox Storage](screenshots/03_virtualbox_storage.png)
*VirtualBox Storage settings — Windows 10 ISO mounted as virtual optical drive.*

![Boot Order](screenshots/05_boot_order_optical_first.png)
*Boot order set with Optical first — forces VM to boot from ISO.*

![Windows Setup](screenshots/08_windows_setup.png)
*Windows Setup loaded from ISO. Navigation path: Next → Repair your computer → Troubleshoot → Advanced Options → Command Prompt.*

**Result:** CMD opened as Administrator with **NO password prompt** ✅

> 🔴 **Critical SOC Finding:** Booting from external media bypasses WinRE access controls entirely. Without **BitLocker** and **BIOS boot protection**, any bootable ISO can access and modify system files without credentials.

---

### Step 4 — Locating the Windows Drive

In recovery environments, drive letters are reassigned. The command was used to identify the correct Windows drive:

```cmd
dir d:\windows\system32\utilman.exe
```

**Output:**
```
Directory of d:\windows\system32
12/06/2025  05:29 AM    236,544 utilman.exe
1 File(s)   236,544 bytes
```

**Finding:** Windows confirmed on **D: drive** ✅

![CMD Utilman Found](screenshots/09_cmd_utilman_found.png)
*Recovery CMD confirming utilman.exe exists on D:\windows\system32 — Windows drive identified.*

> 💡 In recovery environments, the Windows drive is often **D:** because the recovery partition takes **C:**. Always verify the drive letter before running commands.

---

### Step 5 — Executing the Utilman Exploit

#### Step 5a — Backup Original Utilman.exe

```cmd
move d:\windows\system32\utilman.exe d:\windows\system32\utilman.exe.bak
```

| Part | Explanation |
|------|-------------|
| `move` | Renames/moves a file |
| `utilman.exe` | Original Windows accessibility executable |
| `utilman.exe.bak` | Backup copy with .bak extension |

**Output:** `1 file(s) moved.` ✅

---

#### Step 5b — Replace Utilman with CMD

```cmd
copy /y d:\windows\syswow64\cmd.exe d:\windows\system32\utilman.exe
```

| Part | Explanation |
|------|-------------|
| `copy` | Copies a file from source to destination |
| `/y` | Suppresses overwrite confirmation — must be placed immediately after `copy` |
| `syswow64\cmd.exe` | Source — avoids file-lock conflicts with the system32 version |
| `system32\utilman.exe` | Destination — cmd.exe placed with utilman's exact filename |

**Output:** `1 file(s) copied.` ✅

> ⚠️ **Key Syntax Lesson:** `copy /y source destination` — the `/y` flag MUST come immediately after `copy`. Placing it at the end does not suppress the overwrite prompt in recovery environments.

> 🔴 **SOC Alert:** Any modification to `utilman.exe` in `C:\Windows\System32\` should trigger an immediate **File Integrity Monitoring (FIM)** alert. Sysmon Event ID 11 (FileCreate) and hash mismatch detection would catch this.

---

### Step 6 — Password Reset via SYSTEM Shell

After rebooting to the login screen, clicking the **Ease of Access button** (bottom-right) launched **cmd.exe as NT AUTHORITY\SYSTEM** — because utilman.exe had been replaced.

![Login Screen Ease of Access](screenshots/06_login_screen_ease_of_access.png)
*Login screen showing "Ease of access" tooltip — clicking this now launches SYSTEM-level CMD.*

**Password Reset Command:**
```cmd
net user Win10User Reign+R1
```

| Part | Explanation |
|------|-------------|
| `net user` | Windows built-in local account management command |
| `Win10User` | Target account whose password is being reset |
| `Reign+R1` | New password — no knowledge of old password required |

**Output:** `The command completed successfully.` ✅

![Password Reset Success](screenshots/10_password_reset_success.png)
*SYSTEM-level CMD (title bar confirms C:\Windows\system32\utilman.exe) — password reset completed successfully without knowledge of original credentials.*

**SOC Events Generated:**

| Event ID | Description | Significance |
|----------|-------------|-------------|
| 4724 | Account password reset | Generated when SYSTEM resets a local account password |
| 4625 | Failed logon (prior) | No successful logon before the reset |

> 🔴 **High-Confidence IOC:** Event ID 4724 triggered by **NT AUTHORITY\SYSTEM** with no preceding Event ID 4624 (successful logon) is a near-definitive indicator of the Utilman exploit being used.

---

### Step 7 — Access Restored

![Desktop Access Restored](screenshots/12_desktop_access_restored.png)
*Windows 10 desktop fully accessible — April 5, 2026, 8:16 PM. Recovery complete.*

---

## PHASE 2 — Defensive: Security Hardening

> Now that access has been recovered, a responsible SOC analyst or system administrator must immediately remediate the vulnerabilities exploited and harden the system to prevent recurrence.

---

### 1. Restore Utilman.exe

The modified `utilman.exe` must be restored immediately to close the SYSTEM shell backdoor.

**Command (run as Administrator):**
```cmd
sfc /scannow
```

This scans and restores all corrupted or modified Windows system files to their original state, including `utilman.exe`.

**Or manually restore from backup:**
```cmd
copy /y c:\windows\syswow64\utilman.exe c:\windows\system32\utilman.exe
```

**Verify restoration:**
```cmd
dir c:\windows\system32\utilman.exe
```

> ✅ Once restored, clicking the Accessibility icon at the login screen will return to the normal Ease of Access menu — not CMD.

**Risk if NOT restored:**

| Risk | Impact |
|------|--------|
| Anyone with VM/physical access | Can get SYSTEM shell instantly at login screen |
| No credentials required | Complete authentication bypass permanently active |
| Persistent backdoor | Survives reboots until manually remediated |

---

### 2. Enable BitLocker Encryption

BitLocker is the most critical control against this attack. With BitLocker enabled, the drive cannot be read or modified by external boot media without the encryption key — making the ISO boot method completely ineffective.

**Enable BitLocker on Windows 10:**

1. Open **Control Panel → System and Security → BitLocker Drive Encryption**
2. Click **"Turn on BitLocker"** on the C: drive
3. Choose how to unlock: **Password** or **USB key**
4. Choose where to save the recovery key:
   - **Microsoft account** (recommended)
   - **USB flash drive**
   - **Print the recovery key**
5. Choose encryption mode: **"Encrypt entire drive"** (recommended for existing drives)
6. Click **"Start encrypting"**

**Or via PowerShell (as Administrator):**
```powershell
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector
```

**Verify BitLocker status:**
```powershell
Get-BitLockerVolume
```

> ✅ With BitLocker enabled, booting from an ISO or any external media will show an encrypted drive — no files can be read or modified without the BitLocker key.

**SOC Relevance:** BitLocker status can be monitored via:
- **Event ID 24620** — BitLocker enabled
- **Event ID 24658** — BitLocker suspended
- **Microsoft Intune / Endpoint Manager** for enterprise environments

---

### 3. BIOS / UEFI Boot Protection

Prevents unauthorized boot order changes that enable the ISO boot method.

**Steps:**
1. Restart the VM/PC → press **F2, F10, DEL, or ESC** during boot to enter BIOS
2. Navigate to **Security** tab
3. Set a **BIOS/UEFI Administrator Password**
4. Navigate to **Boot** tab
5. **Disable booting from:**
   - USB devices
   - Optical drives (CD/DVD)
   - Network/PXE boot
6. Set **Hard Drive as the only boot device**
7. Enable **Secure Boot** if available
8. Save and exit

**In VirtualBox (for lab hardening):**
1. VM **Settings → System → Motherboard**
2. Uncheck **Optical** from Boot Device Order
3. Leave only **Hard Disk** checked
4. Click **OK**

> ✅ Without the ability to change boot order, an attacker cannot boot from external media even with physical access to the machine.

---

### 4. Account Hardening

#### 4a — Set a Strong Password Policy
```powershell
# Minimum password length
net accounts /minpwlen:12

# Password complexity
secedit /export /cfg C:\secpolicy.cfg
# Edit cfg to set PasswordComplexity=1
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpolicy.cfg

# Account lockout after 5 failed attempts
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30
```

#### 4b — Disable the Built-in Administrator Account
```cmd
net user Administrator /active:no
```

#### 4c — Rename the Administrator Account
```cmd
wmic useraccount where name='Administrator' rename 'LabAdmin2026'
```

#### 4d — Create a Separate Standard User Account
```cmd
net user StandardUser Password123! /add
```

> ✅ Using a standard account for daily tasks reduces the blast radius if credentials are compromised.

#### 4e — Review Local Administrators Group
```powershell
Get-LocalGroupMember -Group "Administrators"
```

Remove any unnecessary accounts from the Administrators group.

---

### 5. Enable Audit Logging & SIEM Detection

#### Enable Advanced Audit Policy
```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
```

#### Install Sysmon for Enhanced Logging
Download Sysmon from Microsoft Sysinternals and install:
```cmd
sysmon -accepteula -i sysmonconfig.xml
```

Sysmon will now generate:
- **Event ID 11** — FileCreate (catches utilman.exe replacement)
- **Event ID 1** — ProcessCreate (catches cmd.exe spawned by winlogon.exe)

#### SIEM Detection Queries

**Splunk — Detect Utilman Exploit:**
```spl
index=wineventlog EventCode=4724
| where SubjectUserName="SYSTEM"
| table _time, ComputerName, TargetUserName, SubjectUserName
| sort -_time
```

**KQL (Microsoft Sentinel) — Detect Password Reset by SYSTEM:**
```kql
SecurityEvent
| where EventID == 4724
| where SubjectUserName == "SYSTEM"
| where TargetUserName != "SYSTEM"
| project TimeGenerated, Computer, TargetUserName, SubjectUserName
| order by TimeGenerated desc
```

**Splunk — Detect CMD Spawned by Winlogon:**
```spl
index=sysmon EventCode=1 ParentImage="*winlogon.exe" Image="*cmd.exe"
| table _time, ComputerName, Image, ParentImage, CommandLine
```

---

## 🔍 SOC Detection Analysis

### Full Detection Coverage Summary

| Attack Stage | Detection Method | Event/Log |
|-------------|-----------------|-----------|
| Forced reboots | Kernel-Power alerts | Event ID 41, 6008 |
| WinRE access | Boot event monitoring | Event ID 1074 |
| File replacement | File Integrity Monitoring | Sysmon Event ID 11 |
| Hash mismatch | EDR / FIM alert | utilman.exe hash change |
| SYSTEM password reset | Security log | Event ID 4724 |
| CMD at login screen | Process monitoring | Sysmon Event ID 1 |
| No prior logon | Correlation rule | 4724 without 4624 |

### Detection Gap Without Hardening
Without Sysmon, FIM, or SIEM rules, this entire attack chain produces **minimal visible alerts** in a default Windows 10 configuration — demonstrating why layered security monitoring is critical.

---

## 📚 Key Lessons Learned

**1. Physical Access = Game Over Without Encryption**
Without BitLocker, anyone with physical or hypervisor access can recover any local Windows account in under 10 minutes.

**2. `/y` Flag Syntax in Recovery Environments**
```cmd
copy /y source destination  ✅ Correct — suppresses overwrite prompt
copy source destination /y  ❌ Incorrect — /y at end doesn't work
```

**3. Drive Letters Change in Recovery Environments**
Always use `dir [drive]:\windows\system32\utilman.exe` to identify the correct drive before executing commands.

**4. WinRE Password is Insufficient Alone**
The WinRE password prompt blocked the first attempt but was bypassed completely via ISO boot. Defense in depth requires multiple controls.

**5. SYSTEM Password Resets are High-Fidelity IOCs**
Event ID 4724 from SYSTEM without a preceding 4624 is one of the highest-confidence indicators of this attack. This should be a priority detection rule in any SIEM.

**6. Remediation Must Be Immediate**
Leaving `utilman.exe` modified creates a permanent backdoor that survives reboots. Always remediate immediately after any recovery exercise.

---

## 🛡️ Hardening Checklist

```
[ ] utilman.exe restored to original (sfc /scannow)
[ ] BitLocker enabled on all drives
[ ] BIOS/UEFI password set
[ ] USB/Optical boot disabled in BIOS
[ ] Strong password policy enforced (min 12 chars, complexity)
[ ] Account lockout policy configured (5 attempts, 30 min)
[ ] Built-in Administrator account disabled or renamed
[ ] Sysmon installed and configured
[ ] Audit policies enabled (Logon, Account Management, Privilege Use)
[ ] SIEM detection rules created for Event ID 4724 from SYSTEM
[ ] File Integrity Monitoring enabled on C:\Windows\System32\
```

---

## 📁 Screenshots Index

| # | Filename | Description |
|---|----------|-------------|
| 1 | `01_automatic_repair.png` | Automatic Repair screen — WinRE triggered |
| 2 | `02_advanced_options.png` | WinRE Advanced Options menu |
| 3 | `03_virtualbox_storage.png` | VirtualBox Storage — ISO mounted |
| 4 | `05_boot_order_optical_first.png` | Boot order — Optical first |
| 5 | `06_login_screen_ease_of_access.png` | Login screen — Ease of Access button |
| 6 | `08_windows_setup.png` | Windows Setup loaded from ISO |
| 7 | `09_cmd_utilman_found.png` | Recovery CMD — exploit commands executed |
| 8 | `10_password_reset_success.png` | SYSTEM CMD — password reset successful |
| 9 | `12_desktop_access_restored.png` | Windows desktop — full access restored |

---

## 🔗 References

- [MITRE ATT&CK T1546.008 — Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)
- [Microsoft Event ID 4724](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724)
- [BitLocker Overview — Microsoft](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)
- [Sysmon — Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Recovery Environment — Microsoft](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-recovery-environment--windows-re--technical-reference)

---

*Part of the SOC Blue Team Lab | Ekeoma-SOC-Labs | April 2026*
