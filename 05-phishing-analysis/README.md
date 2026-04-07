# Phishing Analysis

## Overview
Phishing is one of the most common attack vectors in cybersecurity. 
Over 90% of successful cyberattacks begin with a phishing email. This 
section demonstrates the process of investigating suspicious emails 
reported by employees to identify whether they are malicious and 
extract all relevant indicators of compromise.

A phishing investigation in a real SOC typically involves:

- Reading the email carefully for obvious red flags
- Analysing email headers to trace the sending infrastructure
- Checking sending IPs on AbuseIPDB for reputation
- Checking links on VirusTotal without clicking them
- Extracting all IOCs for blocking and further investigation
- Advising on remediation steps

---

## Tools Used
- AbuseIPDB
- VirusTotal
- Manual email header analysis

---

## Cases

### Case 01 — Suspicious Email Investigation
A phishing email impersonating Microsoft was reported by an employee. 
The investigation confirmed the email was sent through a known malicious 
Tor exit node and contained a credential harvesting link pointing to a 
Russian domain. Full IOC extraction and analysis was performed.

### Case 02 — Malicious Link Analysis
A phishing email impersonating GitHub was reported by a developer.
The investigation identified typosquatting, Telegram infrastructure
abuse and a credential harvesting page targeting developer credentials.

[View Case 02](case-02-malicious-link/README.md)
