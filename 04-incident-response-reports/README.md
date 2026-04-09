# Incident Response Reports

## Overview
This section contains formal incident response reports written for 
confirmed security breaches investigated in the Splunk SIEM lab. 
Each report follows the standard incident response lifecycle covering 
identification, containment, eradication, recovery and lessons learned.

These reports are written at a business level — suitable for SOC 
managers, CISOs and legal teams — while referencing the technical 
investigation reports for deeper analysis.

---

## Incident Reports

### IR-001 — Brute Force Attack Against Admin Account
A brute force attack resulted in two confirmed breaches of the admin 
account and lateral movement across three critical servers including 
the domain controller and backup server.

[View IR-001](IR-001-brute-force-attack/README.md)   

---

### IR-002 — Suspicious PowerShell Activity on WKSTN-04
An attacker used encoded PowerShell commands to compromise a workstation, 
create a hidden administrator backdoor account, download and execute 
malware, and conduct post-exploitation reconnaissance.

[View IR-002](IR-002-powershell-compromise/README.md)

---

### IR-003 — Password Spray Attack Against Multiple User Accounts
A password spray attack successfully compromised one user account and 
resulted in lateral movement across five internal servers including 
the domain controller and backup server within 68 minutes.

[View IR-003](IR-003-password-spray-attack/README.md)
