# Splunk SIEM Lab

This section demonstrates hands-on experience using Splunk for log 
analysis, threat detection and security monitoring across three 
realistic attack scenarios.

---

## Detection Cases

### Case 01 — Brute Force Attack Detection
Detecting multiple failed login attempts identifying suspicious 
authentication behaviour and confirming lateral movement.

- [View Case 01](case-01-brute-force-detection/README.md)
- [Download Log File](case-01-brute-force-detection/logs/brute-force-logs.csv)

---

### Case 02 — Suspicious PowerShell Activity
Detecting encoded PowerShell commands backdoor creation malware 
download and post-exploitation reconnaissance.

- [View Case 02](case-02-suspicious-powershell/README.md)
- [Download Log File](case-02-suspicious-powershell/logs/powershell-logs.csv)

---

### Case 03 — Password Spray Attack Detection
Detecting synchronized failed login attempts across multiple accounts 
from a single source IP and tracing lateral movement after breach.

- [View Case 03](case-03-failed-logins-spike/README.md)
- [Download Log File](case-03-failed-logins-spike/logs/password-spray-logs.csv)

---

### SOC Investigation Dashboard
Combined visual dashboard showing findings from all three investigations.

- [View Dashboard](soc-dashboard/README.md)
