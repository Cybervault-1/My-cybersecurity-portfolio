# IR-002 — Suspicious PowerShell Activity on WKSTN-04

**Incident ID:** IR-002
**Date Reported:** 2026-04-08
**Date Resolved:** 2026-04-08
**Severity:** Critical
**Status:** Closed
**Analyst:** Adetayo Adedeji

---

## 1. Incident Summary

A suspicious PowerShell attack was detected on workstation WKSTN-04 
at SecureCore Ltd. The attacker used encoded PowerShell commands to 
hide their activity, created a hidden administrator account to maintain 
access, downloaded malware from an external server and executed it. 
After the malware ran, the attacker began exploring the system to 
prepare for further damage. The attack went undetected for 25 minutes 
because there was no PowerShell monitoring in place.

---

## 2. Timeline of Events

| Date/Time | Event |
|-----------|-------|
| 2026-04-08 09:20:00 | First encoded PowerShell command runs on WKSTN-04 via cmd.exe |
| 2026-04-08 09:21:00 | Second encoded PowerShell command runs |
| 2026-04-08 09:22:00 | Third encoded PowerShell command runs |
| 2026-04-08 09:23:00 | Attacker creates hidden local account named backdoor |
| 2026-04-08 09:25:00 | Backdoor account added to Administrators group |
| 2026-04-08 09:27:00 | Malware downloaded from http://malicious.site/payload.exe |
| 2026-04-08 09:30:00 | Malware executed from C:\Windows\Temp\payload.exe |
| 2026-04-08 09:35:00 | Attacker lists all local user accounts |
| 2026-04-08 09:40:00 | Attacker checks network configuration |
| 2026-04-08 09:45:00 | Attacker lists running processes |
| 2026-04-08 09:45:00 | Incident detected and investigation initiated |

---

## 3. Affected Systems

| System | Role | Impact |
|--------|------|--------|
| WKSTN-04 | Employee workstation | Fully compromised. Malware executed and backdoor created |

---

## 4. Evidence Collected

| Evidence | Detail |
|----------|--------|
| PowerShell logs | 16 events recorded on WKSTN-04 between 09:20 and 09:45 |
| Encoded commands | 3 Base64 encoded commands executed via cmd.exe |
| Backdoor account | Local account named backdoor created and added to Administrators group |
| Malware source | http://malicious.site/payload.exe |
| Malware location | C:\Windows\Temp\payload.exe |
| Parent process | cmd.exe used to launch PowerShell throughout the attack |
| Post-exploitation | User enumeration, network reconnaissance and process enumeration confirmed |

---

## 5. Root Cause Analysis

The attack succeeded because of two security failures.

**Primary Cause: No PowerShell Monitoring**
The organisation had no PowerShell script block logging or execution 
monitoring in place. Had this been enabled, the encoded commands would 
have been automatically decoded and logged the moment they ran. The 
attack would have been detected immediately instead of going unnoticed 
for 25 minutes.

**Secondary Cause: No Restrictions on PowerShell Execution**
PowerShell was running in unrestricted mode on WKSTN-04. This allowed 
the attacker to run any command including encoded ones without any 
policy blocking them. Restricting PowerShell to only allow signed 
scripts would have stopped this attack before it started.

**Contributing Factor: PowerShell Launched from cmd.exe**
Launching PowerShell from cmd.exe is an unusual pattern that no 
legitimate user or administrator would normally do. An alert for 
this behaviour would have flagged the attack at the very first command.

---

## 6. Containment Actions

Actions taken to stop the attack from spreading:

- Isolated WKSTN-04 from the network immediately
- Disabled the backdoor local account
- Blocked http://malicious.site at the firewall
- Searched all other machines for payload.exe in C:\Windows\Temp
- Reset admin credentials across all systems as a precaution

---

## 7. Eradication Actions

Actions taken to remove the threat completely:

- Deleted the backdoor local account from WKSTN-04
- Removed payload.exe from C:\Windows\Temp
- Scanned WKSTN-04 for any additional malware or persistence mechanisms
- Reviewed all other machines for similar encoded PowerShell activity
- Verified no other accounts were created or modified during the attack window

---

## 8. Recovery Actions

Actions taken to restore normal operations:

- Rebuilt WKSTN-04 from a clean image after forensic investigation
- Verified the machine was clean before returning it to the user
- Confirmed no other machines were affected
- Monitored the environment closely for 72 hours post-recovery
- Confirmed normal operations resumed without issues

---

## 9. Recommendations

| Priority | Recommendation |
|----------|---------------|
| Critical | Enable PowerShell script block logging across all machines immediately |
| Critical | Set PowerShell execution policy to only allow signed scripts |
| High | Create a SIEM alert for any encoded PowerShell execution |
| High | Create a SIEM alert for PowerShell launched from cmd.exe |
| High | Search all machines for payload.exe in C:\Windows\Temp |
| Medium | Implement application whitelisting to prevent unauthorised executables |
| Medium | Block direct internet access from workstations where possible |
| Low | Train IT staff to recognise PowerShell abuse patterns |

---

## 10. Lessons Learned

This attack worked entirely because PowerShell had no monitoring or 
restrictions on it. The attacker used a built-in Windows tool to do 
everything they needed without bringing any external software onto 
the machine. This made the attack harder to detect with traditional 
antivirus tools.

The backdoor account was the most dangerous part of this incident. 
Even if the malware had been removed without finding the backdoor, 
the attacker could have returned at any time using that account. 
This is why eradication must go beyond just removing malware. Every 
persistence mechanism the attacker created must be found and removed.

The post-exploitation activity at the end showed the attacker was 
planning to go further. They were mapping the network and checking 
running processes to prepare for their next move. Catching this early 
prevented what could have been a much larger breach.

Key lessons from this incident:

- Encoded PowerShell commands are almost always malicious. Any 
  occurrence should be treated as a critical alert.
- PowerShell launched from cmd.exe is a strong indicator of an 
  attack. Monitor for this pattern at all times.
- Backdoor accounts must be actively hunted during every incident 
  response. Removing malware without finding persistence mechanisms 
  leaves the door open for the attacker to return.
- Saving files to C:\Windows\Temp is a common attacker technique. 
  Monitor this location for unexpected executables.
- Post-exploitation reconnaissance means the attacker is planning 
  to go deeper. Early detection at this stage prevents much larger damage.

---

## 11. References

- [Splunk Investigation — Case 02 Suspicious PowerShell Activity](../../02-splunk-siem-lab/case-02-suspicious-powershell/README.md)
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
- MITRE ATT&CK T1136.001 — Create Local Account
- MITRE ATT&CK T1105 — Ingress Tool Transfer
