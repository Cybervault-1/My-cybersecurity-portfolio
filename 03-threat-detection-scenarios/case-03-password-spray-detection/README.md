# Case 03 — Password Spray Detection Rule

## Overview
This detection rule identifies password spray attacks by monitoring for 
a single source IP hitting multiple different user accounts within a 
short time window. Unlike brute force detection which looks at one 
account being hit many times, this rule looks across all accounts 
simultaneously to catch the low and slow spray pattern that standard 
lockout policies miss entirely.

---

## Scenario
The SecureCore Ltd SOC team wants to ensure that password spray attacks 
are caught automatically even though no single account accumulates enough 
failures to trigger a standard lockout alert. The detection must look 
at the bigger picture across all accounts rather than monitoring each 
account individually.

---

## Detection Logic

A password spray attack shows these characteristics:
- One source IP targeting many different accounts
- Very few attempts per account — usually 1 to 3
- All attempts happening within a short time window
- Synchronized pattern across accounts — only possible with automation

The rule triggers when a single source IP hits more than 3 different 
user accounts within a 60 second window.

---

## SPL Detection Query

```
index=main source="password-spray-logs.csv" status=failed
| bucket _time span=60s
| stats dc(user) as unique_accounts, count as total_attempts by _time, src_ip
| where unique_accounts > 3
| table _time, src_ip, unique_accounts, total_attempts
| rename unique_accounts as "Accounts Targeted" total_attempts as "Total Failed Attempts"
```

## Query Breakdown

| Line | What it does |
|------|-------------|
| `status=failed` | Filter only failed login attempts |
| `bucket _time span=60s` | Group events into 60 second time windows |
| `dc(user)` | Count distinct unique user accounts hit — dc means distinct count |
| `where unique_accounts > 3` | Only fire when more than 3 different accounts are hit in one minute |
| `table` | Display as a clean readable table |
| `rename` | Make columns more readable |

---

## Why dc(user) Is the Key to This Detection

`dc` stands for distinct count. It counts how many unique different 
values appear rather than the total number of events.

Without dc(user) the query would count total failed attempts which 
could all be against the same account. With dc(user) we specifically 
count how many different accounts were targeted which is the defining 
characteristic of a spray attack.

This is what separates spray detection from brute force detection:

| Detection Type | Key Field | What it measures |
|---------------|-----------|-----------------|
| Brute force | count | Total attempts against one account |
| Password spray | dc(user) | Number of different accounts targeted |

---

## Test Results

The query was run against the password spray investigation log file. 
The screenshot below shows the detection firing on both spray waves.

![Password spray detection rule firing showing 192.168.1.77 targeting 
9 accounts in the first wave and 8 in the 
second](screenshots/03-password-spray-detection-rule.png)

The rule detected 192.168.1.77 hitting 9 accounts in the 14:00 window 
and 8 accounts in the 14:01 window. In a real environment this alert 
firing at 14:00 would have given the analyst time to block 192.168.1.77 
before the jsmith account was breached at 14:02:07.

---

## Alert Configuration

In a production Splunk environment this query would be saved as a 
scheduled alert running every 5 minutes. When results are returned 
Splunk would:

- Send an immediate notification to the on-duty analyst
- Create a ticket in the incident management system
- Log the alert for audit purposes

This detection is particularly important because password spray attacks 
are specifically designed to avoid triggering standard security alerts. 
Without this cross-account detection rule the attack would go completely 
unnoticed until after a breach occurs.

---

## Response Actions When Alert Fires

1. Identify the attacking source IP from the alert
2. Check the IP on AbuseIPDB for reputation
3. Block the IP at the perimeter firewall immediately
4. Review all accounts that were targeted for successful logins
5. If any account shows a success treat it as compromised immediately
6. Reset credentials for all targeted accounts as a precaution
7. Enable MFA on all affected accounts if not already active
8. Document findings and actions taken

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Password Spraying | T1110.003 |
| Valid Accounts | T1078 |
