
# Project 3 – Multi-Stage Attack Detection Lab

## Overview

This project simulates a **multi-stage cyber attack scenario** within a controlled home SOC lab environment.  
The objective is to demonstrate how different phases of an attack can be identified, monitored, and investigated using security monitoring tools.

The lab environment is designed to replicate a small enterprise network where an attacker attempts to compromise systems through multiple stages including reconnaissance, initial access, execution, persistence, and lateral movement.

This project focuses on:

- Understanding attacker behavior
- Generating realistic attack telemetry
- Detecting malicious activity using security monitoring tools
- Practicing SOC investigation workflows

---

## Lab Environment

The lab environment consists of several virtual machines connected within a controlled internal network.

### Virtual Machines

| Machine | Role |
|------|------|
| Kali Linux | Attacker machine |
| Windows 10 | Target workstation |
| Windows Server 2019 | Domain Controller |
| Ubuntu Server | Splunk SIEM |

The machines communicate through a **VirtualBox internal network**, allowing traffic monitoring and attack simulation.

---

## Monitoring and Analysis Tools

The following tools are used for monitoring and analysis:

- **Splunk Enterprise** – Security Information and Event Management (SIEM)
- **Zeek** – Network security monitoring
- **Wireshark** – Packet capture and traffic inspection

These tools allow visibility into both host activity and network traffic.

---

## Attack Simulation Stages

The project is divided into multiple stages that simulate the typical phases of an attack lifecycle.

### Stage 1 – Reconnaissance
The attacker gathers information about the network, identifies active hosts, and scans open ports.

Tools used:

- Nmap
- Netdiscover
- Wireshark

---

### Stage 2 – Initial Access

The attacker attempts to gain access to the target system using discovered services.


---

### Stage 3 – Execution

Malicious commands or payloads are executed on the compromised system.

---

### Stage 4 – Persistence

The attacker attempts to maintain long-term access to the compromised system.

---

### Stage 5 – Lateral Movement

The attacker attempts to move through the network and access additional systems.

---

## Detection Objectives

This project aims to demonstrate how security analysts can detect attacker behavior using:

- Network traffic monitoring
- Log analysis
- SIEM alerts
- Packet inspection

The analysis focuses on identifying abnormal patterns and correlating events across multiple data sources.

---

## Project Goal

The goal of this project is to simulate a realistic attack chain and practice the **SOC investigation process**, including:

- Attack detection
- Event analysis
- Traffic investigation
- Documentation of findings

---

## Author

Ekeoma Eneogwe  
SOC / Blue Team Cybersecurity Analyst  
Vilnius, Lithuania

GitHub:  
https://github.com/Ekeoma-SOC-Labs
