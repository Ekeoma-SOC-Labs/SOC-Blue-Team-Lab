# Lab Setup – Multi-Stage Attack Detection Lab

## Host System
HP Laptop running VirtualBox.

## Virtual Machines

- Kali Linux – Attacker machine
- Windows 10 – Target workstation
- Windows Server 2019 – Domain Controller
- Ubuntu Server – Splunk SIEM

## Network Configuration

All VMs connected using VirtualBox Internal Network to allow controlled communication and traffic monitoring.

## Monitoring Tools

- Splunk Enterprise – SIEM log analysis
- Zeek – Network security monitoring
- Wireshark – Packet analysis

## Offensive Environment

The attacker environment is Kali Linux which contains multiple security testing tools used across different stages of the attack simulation.

Examples include:

- Nmap
- Netdiscover
- Hydra
- Metasploit
- SMB utilities
