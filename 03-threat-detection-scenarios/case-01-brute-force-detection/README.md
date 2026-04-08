# Case 01 — Brute Force Attack Detection Rule

## Overview
This detection rule identifies brute force attacks in real time by 
monitoring for repeated failed login attempts from a single source IP 
against the same user account within a 60 second window. When the 
threshold is crossed an alert fires immediately giving the analyst 
time to respond before the attacker succeeds.

---

## Scenario
The SecureCore Ltd SOC team wants to ensure that any future brute 
force attack is caught automatically rather than discovered after 
the breach has already happened. The detection rule must fire early 
enough to allow containment before the attacker gains access.

---

## Detection Logic

A brute force attack shows these characteristics:
- Same source IP making repeated attempts
- Same user account being targeted
- Attempts arriving every few seconds
- Volume far exceeding normal user behaviour

The rule triggers when a single source IP generates more than 5 failed 
login attempts against the same account within a 60 second window.

---

## SPL Detection Query

```
index=main source="brute-force-logs.csv" EventCode=4625
| bucket _time span=60s
| stats count by _time, user, src_ip
| where count > 5
| table _time, user, src_ip, count
| rename count as "Failed Attempts"
```

## Query Breakdown

| Line | What it does |
|------|-------------|
| `EventCode=4625` | Filter only failed Windows login events |
| `bucket _time span=60s` | Group events into 60 second time windows |
| `stats count by _time, user, src_ip` | Count failures per user per IP within each window |
| `where count > 5` | Only return results exceeding the threshold |
| `table` | Display as a clean readable table |
| `rename` | Make the count column more descriptive |

---

## Test Results

The query was run against the brute force investigation log file. 
The screenshot below shows the detection firing on two separate 
60 second windows confirming the rule works correctly.

![Brute force detection rule firing showing admin account targeted 
by 192.168.1.10 with 20 failed attempts per 
window](screenshots/01-brute-force-detection-rule.png)

The rule detected 20 failed attempts in the 09:58 window and 20 
in the 09:59 window — both well above the threshold of 5. In a 
real environment this alert would have fired at 09:58 giving the 
analyst time to block the attacking IP before the breach occurred 
at 10:00:03.

---

## Alert Configuration

In a production Splunk environment this query would be saved as a 
scheduled alert running every 5 minutes checking the last 5 minutes 
of log data. When results are returned Splunk would:

- Send an email notification to the on-duty analyst
- Create a ticket in the incident management system
- Log the alert for audit purposes

---

## Response Actions When Alert Fires

1. Identify the attacking source IP from the alert
2. Check the IP on AbuseIPDB for reputation
3. Block the IP at the perimeter firewall immediately
4. Monitor whether the targeted account was successfully breached
5. If breached disable the account and begin incident response
6. Document findings and actions taken

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Brute Force — Password Guessing | T1110.001 |
