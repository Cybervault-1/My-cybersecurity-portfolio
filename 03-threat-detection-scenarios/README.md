# Threat Detection Scenarios

## Overview
This section demonstrates how to build detection rules that automatically 
identify suspicious and malicious activity in a SIEM environment. Rather 
than waiting for an analyst to manually spot an attack after it has 
already happened, detection rules run continuously in the background and 
fire alerts the moment suspicious behaviour crosses a defined threshold.

Each case in this section covers a real world attack scenario with a 
working SPL detection query tested against real log data, a breakdown 
of the detection logic, and recommended response actions when the alert 
fires.

---

## Why Detection Rules Matter

Investigation skills tell you what happened after an attack. Detection 
rules stop the attack while it is happening.

The three cases in this section are directly linked to the Splunk 
investigations completed earlier in this portfolio. In those 
investigations the attacks had already succeeded before they were 
discovered. These detection rules would have caught each attack in 
real time and prevented the breach from happening at all.

---

## Detection Cases

### Case 01 — Brute Force Attack Detection
Detects repeated failed login attempts from a single source IP against 
the same account within a 60 second window. Fires before the attacker 
succeeds giving the analyst time to block the attacking IP.

[View Case 01](case-01-brute-force-detection/README.md)

---

### Case 02 — Suspicious PowerShell Detection
Detects encoded PowerShell commands executed via cmd.exe. This 
combination is a strong indicator of malicious activity and fires 
early enough to allow isolation of the affected machine before 
malware is deployed.

[View Case 02](case-02-powershell-detection/README.md)

---

### Case 03 — Password Spray Detection
Detects a single source IP hitting multiple different user accounts 
within a short time window. This cross-account detection catches 
spray attacks that deliberately stay below standard lockout thresholds 
and would otherwise go completely unnoticed.

[View Case 03](case-03-password-spray-detection/README.md)
