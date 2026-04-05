
markdown# Case 01 — Brute Force Attack Detection

## Executive Summary
A brute force attack was detected against the admin account at SecureCore Ltd.
The attacker at IP 192.168.1.77 made 33 failed login attempts before 
successfully breaching the account and moving laterally across three critical 
servers including the domain controller, file server and backup server.

---

## Scenario
It is Monday morning at SecureCore Ltd. The SOC team receives an alert 
indicating multiple failed login attempts on the domain controller DC01. 
A SOC analyst is tasked with investigating whether this is a user who forgot 
their password or an active brute force attack against a privileged account.

The analyst has access to Windows authentication logs ingested into Splunk 
and must determine the full scope of the attack, identify the source, confirm 
whether the attack succeeded, and trace any post-breach activity.

## Objective
Investigate suspicious authentication activity using Splunk, identify the 
attacking source, determine whether the attack succeeded, and trace any 
post-breach lateral movement across the network.

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)

## Dataset
- File: brute-force-logs.csv
- Index: main
- Total Events: 124
- Log Fields: time, host, user, src_ip, dest_ip, EventCode, LogonType,
  ProcessName, status, description, domain

---

## Background — What is a Brute Force Attack?
A brute force attack is when an attacker repeatedly attempts different 
passwords against a single account until one succeeds. Key characteristics:

- Same account targeted repeatedly
- Many failed attempts in a short time window
- Often followed by a successful login
- Privileged accounts like admin are the primary target

The danger of brute force attacks is that once the attacker succeeds, 
they have legitimate credentials — making their activity harder to 
distinguish from normal user behaviour.

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs
The dataset was loaded into Splunk and raw logs were reviewed first to 
understand the full scope of activity before running any detection queries.

**Query used:**
```
index=main
```

**Why this query:**
Always start with raw unfiltered data. This gives you a complete picture 
of everything in the dataset before narrowing your focus. Running targeted 
queries too early can cause you to miss important context.

**What to look for:**
Total event count, field names available, spread of users and IP addresses, 
any immediately obvious patterns.

**Finding:**
124 total events were present across multiple users and IP addresses.
Initial review of the raw logs immediately revealed a high concentration 
of failed login activity. The left panel showed user field with 8 unique 
values and status field with only 2 values — failed and success — 
providing a quick overview of the authentication landscape.

![Figure 1 — Raw log overview showing 124 events across all users and 
IP addresses](screenshots/01-raw-logs.png)

**Figure 1** confirms the dataset was successfully loaded into Splunk 
with all fields correctly parsed including time, user, src_ip, dest_ip, 
status and description.

---

### Step 2 — Identify the Most Targeted Account
Failed logins were isolated and grouped by user to identify which account 
was being targeted the most.

**Query used:**
```
index=main status=failed
| stats count by user
| sort -count
```

**Why this query:**
`status=failed` filters only failed login events. The `stats count by user` 
command groups and counts failures per user. `sort -count` puts the highest 
number first so the most targeted account appears immediately at the top. 
This query is the first step in any authentication investigation.

**What pattern to expect:**
In a brute force attack you expect one account to have significantly more 
failures than all others combined. Normal failed logins are spread evenly 
across users — 1 to 3 failures each from people mistyping passwords.

**Finding:**
| User | Failed Attempts |
|------|----------------|
| admin | 33 |
| tbrady | 2 |
| user2 | 2 |
| mwilliams | 1 |

The admin account had 33 failed attempts compared to a maximum of 2 for 
any other user. This extreme concentration on a single privileged account 
is a definitive indicator of a targeted brute force attack rather than 
random user mistakes.

![Figure 2 — Failed login count grouped by user showing admin with 33 
failures compared to maximum 2 for all other accounts](screenshots/02-failed-logins-by-user.png)

**Figure 2** visually demonstrates the disproportionate targeting of the 
admin account. The bar chart makes the anomaly immediately obvious — 
admin's bar dwarfs every other account.

---

### Step 3 — Identify the Attacking IP Address
Failed login attempts against the admin account were filtered and grouped 
by source IP to identify the origin of the attack.

**Query used:**
```
index=main user=admin status=failed
| stats count by src_ip
| sort -count
```

**Why this query:**
Adding `user=admin` narrows the search specifically to admin account 
failures. Grouping by `src_ip` reveals whether the attack is coming from 
one location — a targeted attack — or many locations — a distributed attack. 
This distinction affects the remediation response.

**What pattern to expect:**
A classic brute force attack comes from a single IP using an automated 
tool. Multiple IPs suggest either a botnet or multiple coordinated attackers.

**Finding:**
| Source IP | Failed Attempts |
|-----------|----------------|
| 192.168.1.10 | 30 |
| 192.168.1.99 | 3 |

Two suspicious IP addresses were identified targeting the admin account. 
192.168.1.10 was the primary attacker with 30 failed attempts. 
192.168.1.99 appeared separately with 3 unusual login attempts described 
as "Unknown login attempt" — suggesting a second actor or different 
attack tool.

![Figure 3 — Failed login attempts against admin account grouped by 
source IP confirming two attacking IPs](screenshots/03-attacking-ip.png)

**Figure 3** confirms that 192.168.1.10 was the primary attacker 
responsible for 30 of the 33 failed attempts, with a secondary suspicious 
IP 192.168.1.99 contributing 3 additional unknown attempts.

---

### Step 4 — Reconstruct the Full Attack Timeline
All admin account activity was retrieved and sorted chronologically to 
reconstruct the complete sequence of events from first attack to final 
lateral movement.

**Query used:**
```
index=main user=admin
| table time, user, src_ip, dest_ip, status, description
| sort time
```

**Why this query:**
Removing the status filter shows ALL admin activity — both failed and 
successful. The `table` command presents results in a clean readable 
format. Sorting by time reconstructs the chronological story of the 
attack from beginning to end.

**What pattern to expect:**
A successful brute force attack shows a block of failures followed by 
a success event. After success, further logins to different destination 
IPs indicate lateral movement.

**Finding:**

**Phase 1 — Initial Brute Force (April 1st, 10:00 AM)**
192.168.1.10 began attacking the admin account with repeated failed 
attempts every 4 to 6 seconds. After 10 consecutive failures the 
attacker successfully authenticated at 10:01:00. The entire attack 
from first attempt to breach lasted approximately 60 seconds.

**Phase 2 — Second Actor (April 1st, 10:30 AM)**
192.168.1.99 appeared 29 minutes after the initial breach making exactly 
3 attempts described as "Unknown login attempt". This timing and behaviour 
suggests possible credential sharing between two coordinated attackers.

**Phase 3 — Return Attack (April 6th, 09:58 AM)**
192.168.1.10 returned 5 days later launching another wave of brute force 
attempts before successfully breaching the admin account again at 10:00:03.

![Figure 4 — Complete attack timeline showing all admin account activity 
from first failure through lateral movement across multiple 
servers](screenshots/04-full-attack-timeline.png)

**Figure 4** shows the complete chronological story of the attack — the 
pattern of failures followed by success is clearly visible, confirming 
the brute force methodology.

---

### Step 5 — Investigate the Second IP Address
The second suspicious IP address was investigated separately to understand 
its behaviour and possible relationship to the primary attacker.

**Query used:**
```
index=main src_ip=192.168.1.99
| table time, user, src_ip, dest_ip, status, description
| sort time
```

**Why this query:**
Isolating a specific IP address shows everything that IP did in the 
environment. This helps determine whether 192.168.1.99 was an independent 
attacker, a coordinated partner, or a false positive.

**What pattern to expect:**
If coordinated with 192.168.1.10, activity from 192.168.1.99 should 
appear shortly after the initial breach — suggesting credential sharing 
or communication between attackers.

**Finding:**
192.168.1.99 made exactly 3 failed attempts against the admin account 
within a 20 second window on April 1st at 10:30 — exactly 29 minutes 
after 192.168.1.10 successfully breached the account. The description 
"Unknown login attempt" differs from standard Windows failed login 
messages, suggesting a different tool or protocol was used.

![Figure 5 — Second IP investigation showing 3 unknown login attempts 
29 minutes after the initial breach](screenshots/05-second-ip-investigation.png)

**Figure 5** highlights the suspicious timing and unusual description 
of 192.168.1.99's activity, supporting the theory of a coordinated 
two-actor attack.

---

### Step 6 — Trace Lateral Movement
Successful admin logins were isolated and sorted by time to determine 
whether the attacker moved across the network after the initial breach.

**Query used:**
```
index=main user=admin status=success
| table time, user, src_ip, dest_ip, status
| sort time
```

**Why this query:**
Filtering for successful logins only shows where the attacker actually 
went after gaining access. Multiple destination IPs in a short time 
window indicates lateral movement — the attacker using compromised 
credentials to access additional systems.

**What pattern to expect:**
A normal user logs into one or two systems consistently. An attacker 
with stolen admin credentials will access multiple different servers 
in rapid succession — especially high value targets like file servers 
and backup servers.

**Finding:**
After breaching the admin account the attacker moved laterally across 
the network accessing multiple critical systems:

| Time | Destination IP | Server Role |
|------|---------------|-------------|
| 2026-04-01 10:01:00 | 10.0.0.5 | Domain Controller |
| 2026-04-06 10:00:03 | 10.0.0.5 | Domain Controller |
| 2026-04-06 10:30:00 | 10.0.0.5 | Domain Controller |
| 2026-04-06 10:45:00 | 10.0.0.20 | File Server |
| 2026-04-06 10:47:00 | 10.0.0.30 | Backup Server |

Access to the backup server is particularly critical — attackers 
commonly destroy backups to prevent recovery during ransomware attacks.

![Figure 6 — Lateral movement showing attacker accessing domain 
controller, file server and backup server using compromised admin 
credentials](screenshots/06-lateral-movement.png)

**Figure 6** confirms lateral movement across three different servers 
within 47 minutes of the second breach, demonstrating the attacker's 
intent to expand their foothold across the network.

---

## Attack Timeline

| Time | Event |
|------|-------|
| 2026-04-01 10:00:01 | First brute force attempt from 192.168.1.10 |
| 2026-04-01 10:00:45 | 10th consecutive failed attempt |
| 2026-04-01 10:01:00 | ⚠️ Admin account breached — first success |
| 2026-04-01 10:30:00 | Second IP 192.168.1.99 appears — 3 unknown attempts |
| 2026-04-06 09:58:01 | Attacker returns — new wave of brute force begins |
| 2026-04-06 10:00:03 | ⚠️ Admin account breached again |
| 2026-04-06 10:30:00 | Attacker accesses domain controller |
| 2026-04-06 10:45:00 | Attacker accesses file server |
| 2026-04-06 10:47:00 | ⚠️ Attacker accesses backup server — critical |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Targeted account | admin |
| Primary attacking IP | 192.168.1.10 |
| Secondary suspicious IP | 192.168.1.99 |
| Total failed attempts | 33 |
| Total successful breaches | 5 |
| First breach | 2026-04-01 10:01:00 |
| Attack returned | 2026-04-06 09:58:01 |
| Servers accessed | 10.0.0.5, 10.0.0.20, 10.0.0.30 |
| Attack type | Brute force with lateral movement |
| Weakness exploited | No account lockout policy |

---

## MITRE ATT&CK Mapping

| Technique | ID | Explanation |
|-----------|-----|-------------|
| Brute Force | T1110.001 | Attacker repeatedly guessed the admin password using automated attempts until gaining access |
| Valid Accounts | T1078 | After succeeding, the attacker used legitimate admin credentials making their activity blend in with normal traffic |
| Lateral Movement via Remote Services | T1021 | Attacker used compromised admin credentials to authenticate to multiple servers across the network |
| Credential Access | T1110 | The core technique — systematically attempting passwords to crack account access |

---

## Conclusion
This investigation confirmed a successful brute force attack against the 
admin account at SecureCore Ltd. The attacker at 192.168.1.10 exploited 
the absence of an account lockout policy — a fundamental security 
weakness — to make 33 repeated authentication attempts without being 
blocked.

The attack succeeded on two separate occasions five days apart, suggesting 
the attacker retained access and returned deliberately. Following each 
breach, the attacker moved laterally across the network accessing the 
domain controller, file server and critically the backup server — 
representing a critical severity incident with potential for complete 
network compromise, data theft and ransomware deployment.

The appearance of a second IP address 192.168.1.99 with unusual login 
attempt descriptions 29 minutes after the initial breach raises the 
possibility of a coordinated two-actor attack involving credential sharing.

The primary weakness exploited in this incident was the absence of an 
account lockout policy, which would have blocked the attack after 3 to 5 
failed attempts — preventing the breach entirely.

## Recommended Actions
- Immediately disable and reset the admin account credentials
- Block 192.168.1.10 and 192.168.1.99 at the firewall
- Investigate all activity on 10.0.0.20 and 10.0.0.30 for signs of 
  data theft or tampering
- Implement account lockout policy — lock after 5 failed attempts
- Enable multi-factor authentication on all privileged accounts
- Review backup server integrity immediately
- Investigate the relationship between 192.168.1.10 and 192.168.1.99
- Enable real-time alerting for more than 5 failed logins against any 
  single account within 60 seconds
