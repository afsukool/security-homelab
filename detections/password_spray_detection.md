# Password Spray Detection in Active Directory using Splunk

## Objective

Detect password spraying attempts against Active Directory accounts using Windows Security logs ingested into Splunk.

Password spraying is a common attack where a single password is tested against multiple usernames to avoid account lockouts.

---

## Lab Environment

| Hostname | Role |
|---|---|
| DC01 | Windows Server 2019 Domain Controller |
| WINCLIENT | Windows 10 Domain Client |
| SPLUNKSERVER | Ubuntu Splunk Server |
| Kali Linux | Attacker machine |

---

## Attack Simulation

A password spray simulation was performed from Kali Linux against SMB on the domain controller.

### Attack Method
- Protocol: SMB
- Target: Domain Controller
- Authentication attempts using multiple usernames
- Single password tested across accounts

Example attack behavior:
- Multiple failed logons
- One successful authentication

Sensitive usernames, IP addresses, and passwords have been sanitized.

---

## Relevant Windows Event IDs

| Event ID | Description |
|---|---|
| 4625 | Failed logon |
| 4624 | Successful logon |

---

## Splunk Detection Query

```spl
index=windows EventCode=4625
| stats count values(TargetUserName) as targeted_users by Source_Network_Address
| where count > 5
```

### Detection Logic

This query identifies:

- Multiple failed logons
- Same source IP
- Multiple targeted usernames

Potential indicator:
- Password spraying activity

---

## Sample Detection Output

Observed indicators:

- High count of failed logon attempts
- Multiple targeted accounts from same source
- Authentication anomalies visible in DC Security logs

Example findings:
- Repeated failed authentication attempts
- One account eventually authenticated successfully

---

## Investigation Steps

1. Identify source IP generating failed logons
2. Review targeted usernames
3. Correlate with successful logons (Event ID 4624)
4. Investigate account activity after successful authentication
5. Reset potentially compromised credentials

---

## Mitigation Recommendations

- Enable account lockout thresholds
- Enforce MFA
- Monitor repeated failed authentication attempts
- Restrict SMB exposure
- Alert on abnormal authentication patterns

---

## Lessons Learned

This exercise demonstrated:

- Windows Security log monitoring
- Splunk detection engineering
- Password spraying detection methodology
- AD authentication attack visibility

---

## Status

✅ Attack simulated  
✅ Logs collected in Splunk  
✅ Detection query validated  
✅ Detection documented
