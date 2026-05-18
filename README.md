# 🛡️ Enterprise Active Directory Security Lab

![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Domain](https://img.shields.io/badge/Domain-CORP.LOCAL-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-orange)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202019-0078D4?logo=windows)
![Attacker](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94?logo=kali-linux)

A hands-on enterprise-grade cybersecurity lab simulating real-world Active Directory attack and defence scenarios. Built to develop and demonstrate practical skills in SOC analysis, detection engineering, and incident response.

> 📄 **[Full SOC Incident Report →](docs/Afsar_Kuttiyassan_SOC_Incident_Report.pdf)**  
> Documents a complete multi-stage AD attack simulation with MITRE ATT&CK mapping, Splunk detections, and BloodHound analysis.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CORP.LOCAL Domain                        │
│                                                                 │
│  ┌──────────────────┐        ┌──────────────────────────────┐  │
│  │  DC01            │        │  WIN10-CLIENT                │  │
│  │  192.168.56.10   │◄──────►│  192.168.56.20               │  │
│  │  Windows Server  │        │  Domain-joined Workstation   │  │
│  │  2019 (DC/DNS/   │        └──────────────────────────────┘  │
│  │  Kerberos/LDAP)  │                                           │
│  └──────────────────┘        ┌──────────────────────────────┐  │
│                               │  SPLUNKSERVER                │  │
│  ┌──────────────────┐        │  192.168.56.40               │  │
│  │  KALI            │        │  Ubuntu — Splunk Enterprise  │  │
│  │  192.168.56.30   │───────►│  (SIEM, log aggregation)     │  │
│  │  Attacker Host   │        └──────────────────────────────┘  │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

| Machine | OS | IP | Role |
|---|---|---|---|
| DC01 | Windows Server 2019 | 192.168.56.10 | Domain Controller, DNS, Kerberos KDC |
| WIN10-CLIENT | Windows 10 | 192.168.56.20 | Domain-joined victim endpoint |
| SPLUNKSERVER | Ubuntu 22.04 | 192.168.56.40 | Splunk Enterprise SIEM |
| KALI | Kali Linux 2024 | 192.168.56.30 | Attacker — Impacket, BloodHound |

---

## Tools & Stack

| Category | Tools |
|---|---|
| **SIEM** | Splunk Enterprise |
| **Endpoint Telemetry** | Sysmon v15 |
| **AD Enumeration** | BloodHound, SharpHound |
| **Offensive** | Impacket, CrackMapExec, Kali Linux |
| **Log Sources** | Windows Event Logs, PowerShell Script Block Logging |
| **Scanning** | Nmap, Nessus |
| **Network Analysis** | Wireshark |
| **Web Testing** | Burp Suite |

---

## Completed Attack Simulations

### Phase 1 — Password Spraying `T1110.003`

SMB-based credential guessing against multiple domain accounts, paced below lockout thresholds.

**Detection:** Splunk alert on `EventCode=4625` — multiple failed logons from a single source IP across multiple accounts within a short time window.

```spl
index=windows EventCode=4625
| bucket span=5m _time
| stats dc(user) as unique_users count by _time, src_ip
| where unique_users >= 3 AND count >= 10
| sort -count
```

---

### Phase 2 — Kerberoasting `T1558.003`

SPN-enabled service account (`SQLSVC`) targeted with Impacket's `GetUserSPNs.py` to extract RC4-encrypted TGS tickets for offline cracking.

**Detection:** Splunk alert on `EventCode=4769` with `Ticket_Encryption_Type=0x17` (RC4-HMAC).

```spl
index=windows EventCode=4769
Ticket_Encryption_Type=0x17 NOT Service_Name="*$"
| stats count by src_ip, Service_Name, Account_Name
| where count > 2
| sort -count
```

**Key indicators:** `sqlsvc` account, client IP `192.168.56.30`, RC4 encryption type.

---

### Phase 3 — AD Attack Path Enumeration `T1069` `T1482`

BloodHound + SharpHound used to ingest and graph AD objects, enumerate privileged group relationships, and identify shortest paths to Tier-0 assets.

**Findings:**
- Kerberoastable service accounts with weak passwords identified
- `ADMINISTRATORS`, `DOMAIN ADMINS`, and `ENTERPRISE ADMINS` groups held `AllExtendedRights` / `GenericAll` on `CORP.LOCAL`
- Multiple privilege escalation paths confirmed to `DC01` (WriteOwner, AddKeyCredentialLink, GenericAll)
- Full OU structure mapped: Domain Controllers, Users, Servers, Workstations, Service Accounts, Admins

---

### Phase 4 — Obfuscated PowerShell Execution `T1059.001`

Encoded PowerShell commands (`-EncodedCommand`, `IEX`, Base64 payloads) simulating fileless malware and C2 download cradle patterns, captured by Sysmon Event ID 1.

**Detection:**

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*IEX*"
  OR CommandLine="*DownloadString*"
| table _time, User, ParentImage, CommandLine
```

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Phase |
|---|---|---|
| T1110.003 | Password Spraying | Initial Access |
| T1558.003 | Kerberoasting | Credential Access |
| T1069 | Permission Group Discovery | Discovery |
| T1482 | Domain Trust Discovery | Discovery |
| T1059.001 | PowerShell | Execution |

---

## Detection Engineering

All detections were built in Splunk and validated against live lab telemetry. Log sources:

- **Windows Security Event Log** — 4624, 4625, 4769, 4776
- **Sysmon** — Event ID 1 (process creation), ID 3 (network connections)
- **PowerShell** — Event ID 4104 (Script Block Logging)

| Detection | Event ID | Trigger |
|---|---|---|
| Password spray | 4625 | >5 failures/min, single src IP, multiple users |
| Kerberoasting | 4769 | RC4 encryption type on TGS request |
| Encoded PowerShell | Sysmon 1 | `-enc`, `IEX`, or `DownloadString` in cmdline |
| New admin account | 4720 + 4732 | Account created and added to admin group |
| Suspicious parent-child | Sysmon 1 | Unexpected process spawning `powershell.exe` |

---

## Active Directory Hardening

Applied and documented against the lab environment:

- **Kerberos:** Disabled RC4 (0x17) encryption, enforced AES256 in Group Policy
- **Service accounts:** Migrated to Group Managed Service Accounts (gMSA), rotated passwords
- **PowerShell:** Enabled Constrained Language Mode, Script Block Logging, module logging
- **Account policies:** Lockout threshold (5 failures), 30-minute lockout duration
- **Privileged groups:** Audited and reduced Domain Admins membership
- **Tiered admin model:** Implemented Tier 0/1/2 separation for administrative access
- **Attack Surface Reduction:** Configured ASR rules via Microsoft Defender

---

## Project Structure

```
security-home-lab/
├── docs/
│   └── Afsar_Kuttiyassan_SOC_Incident_Report.pdf
├── detections/
│   ├── password_spraying.spl
│   ├── kerberoasting.spl
│   └── powershell_abuse.spl
├── scripts/
│   └── (automation and setup scripts)
├── screenshots/
│   ├── splunk-4625-spray.png
│   ├── splunk-4769-kerberoasting.png
│   ├── bloodhound-domain-admins-path.png
│   ├── bloodhound-ou-structure.png
│   ├── bloodhound-dc01-escalation.png
│   ├── bloodhound-sqlsvc-properties.png
│   └── bloodhound-privileged-groups.png
└── README.md
```

---

## Skills Demonstrated

**Offensive**
- Active Directory attack chain simulation (spray → Kerberoast → enumerate → execute)
- Impacket tooling (`GetUserSPNs.py`)
- BloodHound attack path analysis

**Defensive**
- Splunk SIEM — detection query authoring, alert tuning, event correlation
- Sysmon telemetry configuration and analysis
- Windows event log analysis (Security, System, PowerShell)
- MITRE ATT&CK framework mapping

**SOC Operations**
- Incident triage, severity classification, root cause analysis
- Structured incident report writing (professional portfolio standard)
- Detection engineering from attacker TTPs

---

## Author

**Afsar Kuttiyassan**  
Cybersecurity / SOC Analyst  
*This lab is a portfolio project demonstrating practical skills in enterprise security monitoring, Active Directory security, and detection engineering.*
