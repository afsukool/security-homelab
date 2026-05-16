# Windows Security Baseline & Telemetry Analysis

## Overview

This document defines normal Windows security telemetry observed in the lab environment. It helps distinguish between baseline system behavior and meaningful security events.

---

## Security State Events

### Windows Defender Status

- Host: DC01
- Event: WinDefend service entered running state
- Status: SECURITY_PRODUCT_STATE_ON

### Interpretation

✔ Defender is active  
✔ System is in a protected state  
✔ Normal expected behavior in enterprise environments  

---

## Security Center Events

- Host: WIN10-Client
- Event: Security Center service started

### Interpretation

✔ Standard Windows service initialization  
✔ Occurs during boot or service restart  
✔ Not an indicator of compromise  

---

## COM Permission Warnings

Observed messages:

- SecurityCenter.SecurityAppBroker
- SecurityCenter.WscBrokerManager
- SecurityCenter.WscDataProtection
- Local Launch permission not granted (DCOM)

### Interpretation

✔ Windows DCOM permission misconfiguration  
✔ Common in lab / VM environments  
✔ Not directly indicative of attack activity  

---

## SOC Analysis Principle

> “Not all logs are alerts. Most logs are noise. The analyst’s job is correlation, not reaction.”

---

## Correlation Context

These events become relevant ONLY when combined with:

- Process execution anomalies (Sysmon Event ID 1)
- Authentication failures (Event ID 4625)
- Privilege escalation attempts
- PowerShell abuse activity
- Disabled security services

---

## Conclusion

These logs represent baseline Windows security telemetry and system configuration artifacts. They are valuable for establishing normal behavior profiles in detection engineering.
