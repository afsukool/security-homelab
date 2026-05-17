# Security Home Lab

## Overview

This project documents my enterprise-style cybersecurity home lab built for hands-on practice in:

- Active Directory Security
- Windows Hardening
- Detection Engineering
- Vulnerability Assessment
- Penetration Testing
- Security Monitoring

The lab simulates a small enterprise environment with Windows systems, domain services, SIEM logging, and attack simulation.

---

## Lab Architecture

### Systems

| Machine | Role |
|---|---|
| Kali Linux | Attacker machine |
| Windows Server | Domain Controller |
| Windows 10/11 Client | Domain-joined victim machine |
| Splunk Server | SIEM & log monitoring |

---

## Tools Used

- Active Directory
- Kali Linux
- Splunk
- Sysmon
- BloodHound
- Nmap
- Burp Suite
- Wireshark
- Nessus
- Impacket
- PowerShell

---

## Security Use Cases

### Offensive Security
- Enumeration
- Vulnerability scanning
- Web testing basics
- Privilege escalation practice
- Active Directory attack paths

### Defensive Security
- Windows hardening
- Log monitoring
- Detection engineering
- Event analysis
- Alerting

---

## Attack Simulations Planned

- Password spraying
- Kerberoasting
- BloodHound enumeration
- Pass-the-Hash
- PowerShell logging abuse detection

---

## Detection Scenarios

- Failed login monitoring
- Suspicious PowerShell execution
- New admin account creation
- Lateral movement indicators
- Event ID correlation

---

## Hardening Tasks

- Firewall configuration
- Defender tuning
- RDP hardening
- Password policies
- Local security policy review

---

## Active Directory Security Analysis

BloodHound was used to identify:

- Kerberoastable accounts
- Privilege escalation paths
- Tier 0 assets
- Organizational Units and AD object relationships

Key findings:
- Service account exposure
- Privileged group attack paths
- Identity attack surface visibility

---

## Project Status

🚧 In progress — continuously updated with new attack simulations, detections, hardening tasks, and automation scripts.

---

## Related Projects

- Active Directory Security Lab
- Windows Hardening Project
- Security Automation Scripts
- Pentest Writeups
