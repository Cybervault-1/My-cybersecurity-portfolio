# Endpoint Analysis

## Overview
Endpoint analysis focuses on investigating suspicious activity at the 
system level on individual machines. Using Sysmon logs analysts can 
see exactly which processes are running, what network connections they 
are making, what files they are creating and what registry changes they 
are making.

This level of visibility goes much deeper than network traffic analysis 
or authentication logs. It tells you not just that something suspicious 
happened but exactly which program on which machine did it and what it 
did next.

## Tools Used
- Splunk Enterprise
- Sysmon event logs
- SPL (Search Processing Language)

## Cases

### Case 01 — Suspicious Process Detection
A malware infection was investigated on WKSTN-07 using Sysmon logs. 
The investigation traced the complete attack chain from a malicious 
browser download through C2 communication, persistence creation, 
reconnaissance and lateral movement attempt.

[View Case 01](case-01-suspicious-process/README.md)
