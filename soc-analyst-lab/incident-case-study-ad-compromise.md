# SOC Incident Case Study: Active Directory Attack Chain Detection

## Executive Summary

This case study simulates a full Active Directory attack chain observed in a lab environment. The attack includes password spraying, Kerberoasting, and post-exploitation activity detected through Splunk and Sysmon logs.

The objective is to demonstrate SOC-level detection, correlation, and incident response thinking.

---

## Environment

- Domain: CORP.LOCAL
- Domain Controller: DC01 (Windows Server 2019)
- Endpoint: WIN10-Client
- SIEM: Splunk (Ubuntu Server)
- Attacker: Kali Linux
- Logging: Sysmon + Windows Security Logs

---

# 🔴 Incident Timeline

## Phase 1: Password Spraying Attempt

### Observations
- Multiple failed login attempts (Event ID 4625)
- Same source IP targeting multiple usernames
- One successful login observed

### Detection Query

```spl
index=windows EventCode=4625
| stats count values(TargetUserName) as users by Source_Network_Address
```

### Result
- Multiple authentication failures across different accounts
- One valid credential compromised

### Severity: HIGH

---

## Phase 2: Kerberoasting Activity

### Observations
- Service Ticket Requests detected (Event ID 4769)
- Service account: SQLSVC
- SPN-enabled account targeted

### Detection Query

```spl
index=windows EventCode=4769
| stats count by Account_Name Service_Name Client_Address
```

### Result
- Kerberos service ticket requested for SQL service account
- Kerberoastable hash extracted in lab simulation

### Severity: HIGH

---

## Phase 3: Active Directory Attack Path Discovery

### Observations (BloodHound Analysis)
- Kerberoastable account identified: SQLSVC@CORP.LOCAL
- Multiple Tier 0 privileged groups identified:
  - Domain Admins
  - Enterprise Admins
  - Key Admins

### Impact
- Potential escalation path from service account → domain compromise

### Severity: CRITICAL

---

## Phase 4: Post-Exploitation Activity (Simulated Endpoint Behavior)

### Observations
- Suspicious PowerShell execution detected (Sysmon Event ID 1)
- Encoded PowerShell commands observed
- Download cradle behavior detected (IEX usage)

### Detection Query

```spl
index=windows EventCode=1
| search Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*IEX*"
```

### Result
- Indicators of malicious post-exploitation behavior
- Possible payload execution attempt

### Severity: HIGH

---

## Correlation Analysis

When correlating all events:

| Phase | Activity | Severity |
|------|--------|---------|
| 1 | Password Spray | High |
| 2 | Kerberoasting | High |
| 3 | AD Attack Path Discovery | Critical |
| 4 | PowerShell Execution | High |

### Final Assessment:
This represents a **multi-stage Active Directory compromise attempt simulation**.

---

## Root Cause Analysis

- Weak password protection enabled successful spray
- SPN-enabled service account exposed to Kerberoasting
- Lack of segmentation between service accounts and privileged groups
- Insufficient monitoring of PowerShell execution behavior

---

## Impact

If this were a real environment:

- Domain credentials could be compromised
- Privilege escalation to Domain Admin possible
- Full Active Directory takeover risk

---

## Detection Gaps Identified

- No account lockout enforcement for spray attack
- Lack of real-time Kerberos anomaly detection
- No alerting on service account abuse
- Insufficient PowerShell logging configuration

---

## Recommendations

### Immediate Actions
- Reset compromised credentials
- Disable or rotate service account passwords
- Investigate affected endpoints

### Hardening
- Implement MFA for privileged accounts
- Use Group Managed Service Accounts (gMSA)
- Enforce account lockout policies
- Disable RC4 where possible in Kerberos

### Monitoring Improvements
- Alert on Event ID 4625 spikes
- Monitor Event ID 4769 anomalies
- Enable PowerShell Script Block Logging
- Implement SIEM correlation rules

---

## Lessons Learned

This exercise demonstrates:

- End-to-end Active Directory attack chain understanding
- SOC-level log correlation across multiple attack phases
- Detection engineering using Splunk
- Incident response thinking and prioritization

---

## Conclusion

This simulated incident demonstrates how multiple low-to-medium severity events can combine into a critical Active Directory compromise scenario.

Proper correlation across authentication logs, Kerberos activity, and endpoint telemetry is essential for early detection of advanced attacks.
