# Project 2 — SOC Blue Team Lab: Network Traffic Behavioral Analysis (Zeek)

## Objective

This project simulates a SOC-style network investigation using controlled traffic generation and offline PCAP analysis.  
The goal was to distinguish baseline network behavior from simulated malicious activity using structured Zeek logs and behavioral pattern analysis.

The investigation followed an evidence-first SOC workflow with strict step validation and baseline vs attack comparison.

---

## Scenario Summary

Two traffic datasets were analyzed:

- Baseline network traffic (normal behavior)
- Phase B simulated malicious traffic (controlled ICMP burst)

Traffic was captured with tcpdump and analyzed using Zeek offline replay.  
Detection conclusions were based on behavioral metrics, not payload inspection.

---

## Skills Demonstrated

- PCAP capture and evidence preservation
- Zeek offline replay analysis (`zeek -r`)
- conn.log behavioral interpretation
- Protocol distribution analysis
- Destination diversity analysis
- Duration clustering detection
- Automation pattern recognition
- Baseline vs attack metric comparison
- SOC-style investigation documentation
- Multi-signal detection reasoning

---

## Tools Actually Used

- Zeek (offline PCAP analysis)
- tcpdump (packet capture)
- Linux CLI analysis tools (awk, sort, uniq, wc)
- VirtualBox lab environment
- Markdown SOC investigation notes.

---

## Lab Architecture (Actual)

- Windows 10 VM — generated controlled ICMP burst traffic
- Ubuntu VM — Zeek sensor and analysis platform
- NAT network used for capture visibility
- PCAP replay used for repeatable analysis

---

## Detection Method Used

Detection was based on correlated behavioral signals:

- protocol diversity collapse
- destination diversity collapse
- repeated targeting patterns
- tight duration clustering
- uniform response sizes

Baseline metrics were measured first and used as comparison reference.

---

## Key Finding

The Phase B dataset showed clear automated traffic characteristics consistent with scripted ICMP burst behavior and clearly different from baseline user-driven traffic.

Detection confidence: High (multi-metric behavioral correlation).

---


