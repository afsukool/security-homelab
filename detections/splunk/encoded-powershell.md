# Encoded PowerShell Detection

## SPL

```spl
index=sysmon EventCode=1 CommandLine="*-enc*"
```

## MITRE ATT&CK

- T1059.001 — PowerShell
