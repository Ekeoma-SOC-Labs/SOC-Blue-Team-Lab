# SOC-Blue-Team-Lab
A hands-on SOC (Security Operations Center) lab including Splunk, Windows 10 endpoint, Ubuntu SIEM, and Active Directory for detection engineering.


This repo is my personal SOC (Security Operations Center) home lab.  
I’m building everything from scratch in VirtualBox so I can practice blue-team work: collecting logs, sending them to a SIEM, and later doing detections and investigations.

## Lab Architecture
Right now the lab has three main VMs:

- **DC01** – Windows Server (domain controller, DNS)
- **WIN10-CL01** – Windows 10 client joined to the domain
- **Splunk Server** – Ubuntu server running Splunk Enterprise
- **Splunk Universal Forwarder** – installed on WIN10-CL01 to send Windows event logs into Splunk

---

## What I actually did (step by step)

This is a short story of how I built the lab, in the order I did it.

### 1. Planning the lab

1. Decided to simulate a small Windows network:
   - 1 domain controller (DC01)
   - 1 Windows 10 endpoint (WIN10-CL01)
   - 1 Linux server for Splunk
2. Created a VirtualBox network so all VMs can talk to each other on a private subnet.
3. Wrote down IP addresses I wanted to use so nothing would clash later.

### 2. Building the domain controller (DC01)

1. Created a new VM in VirtualBox and installed **Windows Server**.
2. Gave it a static IP address and renamed the machine to `DC01`.
3. Installed **Active Directory Domain Services** and **DNS**.
4. Promoted it to a **domain controller** and created a new domain for the lab.
5. Tested that DNS and the domain were working by:
   - Joining a test machine
   - Logging in with a domain account.

All the screenshots and details for this part are in `03-DC01-Setup.md`.

### 3. Building the Windows 10 endpoint (WIN10-CL01)

1. Created a new VM and installed **Windows 10**.
2. Set a static IP and pointed the DNS to **DC01**.
3. Joined the machine to the domain and renamed it to `WIN10-CL01`.
4. Tested login with a domain user and basic network connectivity (pinging DC01 and the Splunk server once it was up).

More step-by-step notes are in `02-Win10-Endpoint.md`.

### 4. Installing Splunk on Ubuntu (Splunk Server)

1. Created an **Ubuntu** VM and gave it a static IP.
2. Copied the Splunk Enterprise installer into `/opt` and installed it.
3. Enabled Splunk to run as a service and set the admin username and password.
4. Logged into the Splunk Web UI on port **8000** from the Windows 10 VM to confirm:
   - The web interface works
   - The management port and web port are reachable.
5. Configured Splunk to **receive data** on port **9997** (for the Universal Forwarder).

The detailed walkthrough is in `04-Splunk-Server.md`.

### 5. Installing and configuring the Splunk Universal Forwarder (UF) on WIN10-CL01

This part took the most troubleshooting.

1. Downloaded and installed the **Splunk Universal Forwarder** on `WIN10-CL01`.
2. Confirmed the Windows service **SplunkForwarder** was running.
3. Configured the forwarder to send data to the Splunk server:
   - Edited `outputs.conf` so the forwarder knows the Splunk server IP and port (`9997`).
4. Created an `inputs.conf` to collect:
   - `WinEventLog://Security`
   - `WinEventLog://Application`
   - `WinEventLog://System`
   - `WinEventLog://Microsoft-Windows-PowerShell/Operational`
5. Gave the forwarder permission to read the event logs:
   - Added **NT SERVICE\SplunkForwarder** to the **Event Log Readers** group.
6. Restarted the SplunkForwarder service and used:
   - `splunk.exe list forward-server` – to check that the Splunk server was listed as an active forwarder.
   - `splunk.exe btool inputs list --debug` – to confirm Splunk could see my inputs config.
7. On the Splunk server, I ran searches like:
   - `index=* host=WIN10-CL01`
   - `index=* sourcetype="WinEventLog:Security" host=WIN10-CL01`
   to confirm events were arriving.

Full notes and commands are in `05-Splunk-Universal-Forwarder.md`.

---

## What’s inside this repo

- `02-Win10-Endpoint.md` – how I built and configured `WIN10-CL01`
- `03-DC01-Setup.md` – how I installed and configured `DC01` (AD, DNS)
- `04-Splunk-Server.md` – how I installed Splunk Enterprise on Ubuntu
- `05-Splunk-Universal-Forwarder.md` – how I installed and fixed the UF on Windows 10
- `screenshots/` – raw screenshots from the lab, organised by VM

Each markdown file is written as a walkthrough I can follow again in the future if I need to rebuild the lab from zero.

---

## Next steps

Now that the lab is stable and logs from `WIN10-CL01` are flowing into Splunk, my next goals are:

1. Create **detection use cases** in Splunk (e.g., suspicious PowerShell, failed logons, privilege escalation).
2. Simulate attacks in the lab and investigate them using Splunk searches.
3. Document each SOC project as a separate markdown file in this repo.
