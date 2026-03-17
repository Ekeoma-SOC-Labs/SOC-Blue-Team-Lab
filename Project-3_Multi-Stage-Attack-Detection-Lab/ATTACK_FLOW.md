# Attack Flow – Multi-Stage Attack Simulation

## Overview

This document describes the simulated attack chain used in the **Multi-Stage Attack Detection Lab**.  
The purpose is to replicate a realistic attacker workflow and observe how each phase generates detectable telemetry in the SOC monitoring environment.

The attack progresses through multiple stages aligned with common attacker behavior models such as the **Cyber Kill Chain** and **MITRE ATT&CK**.

---

# Attack Stages

## Stage 1 – Reconnaissance

The attacker scans the network to discover active hosts and exposed services.

Activities performed:

- Host discovery
- Network enumeration
- Port scanning

Tools used:

- Nmap
- Netdiscover
- Wireshark

Objective:

Identify potential targets and open services that could be exploited.

---

## Stage 2 – Initial Access

The attacker attempts to gain access to the target system using discovered services.

Possible techniques:

- Credential attacks
- Exploiting exposed services
- Weak authentication

Objective:

Gain a foothold inside the network.

---

## Stage 3 – Execution

Once access is obtained, the attacker executes commands or payloads on the compromised machine.

Possible techniques:

- Command execution
- Script execution
- PowerShell activity

Objective:

Run attacker-controlled commands on the victim system.

---

## Stage 4 – Persistence

The attacker attempts to maintain access even if the system reboots or credentials change.

Possible techniques:

- Scheduled tasks
- Registry persistence
- Service installation

Objective:

Maintain long-term access to the system.

---

## Stage 5 – Lateral Movement

The attacker attempts to move from the compromised system to other machines in the network.

Possible techniques:

- SMB access
- Remote command execution
- Credential reuse

Objective:

Expand access across the network.

---

# Detection Opportunities

Each stage generates detectable activity that security analysts can investigate.

Examples include:

- Port scanning patterns
- Suspicious authentication attempts
- Abnormal network traffic
- Unusual command execution
- Lateral movement indicators

Monitoring tools used in this lab:

- Splunk (log monitoring)
- Zeek (network monitoring)
- Wireshark (packet analysis)

---

# Attack Chain Summary

Recon → Initial Access → Execution → Persistence → Lateral Movement

This chain demonstrates how attackers gradually move from **external discovery to full internal compromise**.

Understanding these stages allows SOC analysts to **detect and interrupt attacks early in the kill chain**.
