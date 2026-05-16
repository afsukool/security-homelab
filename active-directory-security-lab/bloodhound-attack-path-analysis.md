# Active Directory Attack Path Analysis (BloodHound)

## Objective

Analyze Active Directory attack paths to identify privilege escalation opportunities, Kerberoastable accounts, and high-value administrative targets.

This exercise demonstrates how attackers map Active Directory environments before exploitation.

---

## Lab Environment

- Domain: CORP.LOCAL
- Domain Controller: DC01
- Tools: BloodHound, Kali Linux, Windows Server 2019

---

## Key Findings

### Kerberoastable Account

- Account: SQLSVC@CORP.LOCAL
- Status: SPN-enabled service account
- Risk: Vulnerable to Kerberoasting attack

### Impact

Attackers can:
- Request Kerberos service tickets (TGS)
- Extract encrypted hashes
- Perform offline password cracking

---

## Privileged Groups Identified

The following high-value AD groups were discovered:

- Domain Admins
- Enterprise Admins
- Key Admins
- Enterprise Key Admins
- Built-in Administrators

---

## Attack Path Analysis

BloodHound analysis shows:

- Presence of multiple Tier 0 administrative groups
- Direct high-value group exposure in domain structure
- Kerberoastable service account exists within domain scope

---

## Security Implications

This environment presents the following risks:

- Kerberoasting attack surface exists (SQLSVC)
- Tier 0 groups represent full domain compromise if abused
- Service account misconfiguration increases credential attack risk
- Attackers can escalate from low-privilege to domain-level access via AD misconfigurations

---

## Mitigation Recommendations

### Kerberoasting Defense
- Use strong, random service account passwords
- Prefer Group Managed Service Accounts (gMSA)
- Restrict SPN usage where possible

### Active Directory Hardening
- Limit membership of Tier 0 groups
- Apply tiered administration model (Tier 0 / 1 / 2)
- Monitor service ticket requests (Event ID 4769)

### Monitoring
- Detect abnormal Kerberos TGS requests
- Alert on service accounts used from non-server hosts
- Monitor privileged group changes

---

## Lessons Learned

This exercise demonstrates:

- Active Directory attack surface mapping
- Identification of Kerberoastable accounts
- Privilege escalation risk analysis
- Real-world enterprise AD security exposure

---

## Conclusion

BloodHound analysis revealed a Kerberoastable service account and multiple Tier 0 administrative groups, indicating potential privilege escalation paths within the domain.

This highlights the importance of secure service account configuration and strict AD tiering models.
