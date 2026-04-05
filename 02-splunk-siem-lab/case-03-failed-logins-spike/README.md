## Summary
A password spray attack was detected against SecureCore Ltd targeting 9 user 
accounts simultaneously from a single IP address 192.168.1.77. The attacker 
deliberately stayed under the account lockout threshold — attempting only 2 
failures per account. The attack succeeded against jsmith whose weak seasonal 
password Summer2026! was correctly guessed, resulting in lateral movement 
across 5 critical servers including the domain controller and backup server.

---

## Scenario
It is Friday afternoon at SecureCore Ltd. The SOC dashboard shows an unusual 
pattern — failed login attempts are appearing across 8 different user accounts 
almost simultaneously. Unlike a normal brute force attack, no single account 
has enough failures to trigger an account lockout alert. A SOC analyst is 
tasked with investigating whether this is a coordinated attack or a system 
malfunction.

The analyst has access to Windows authentication logs ingested into Splunk 
and must prove this is a password spray attack, identify the compromised 
account, and trace all post-breach activity.

## Objective
Investigate suspicious authentication activity using Splunk, identify the 
password spray pattern, determine which account was compromised, trace 
post-breach lateral movement, and document all findings professionally.

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)

## Dataset
- File: password-spray-logs.csv
- Index: main
- Total Events: 30
- Log Fields: time, host, user, src_ip, dest_ip, EventCode,
  password_attempted, status, description, domain

---

## Background — Brute Force vs Password Spraying

Understanding the difference between these two attacks is critical for 
correct detection and classification:

| | Brute Force | Password Spraying |
|--|-------------|-------------------|
| **Approach** | Many passwords against one account | One password against many accounts |
| **Speed** | Fast and aggressive | Slow and deliberate |
| **Detection difficulty** | Easy — one account spikes | Hard — spread across many accounts |
| **Lockout risk** | High — triggers lockout quickly | Low — stays under lockout threshold |
| **Why attackers use it** | When targeting a specific person | To avoid triggering security alerts |

Password spraying is significantly harder to detect because no single 
account accumulates enough failures to trigger standard lockout alerts. 
The attack blends into normal background noise of everyday user mistakes.

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs
The dataset was loaded into Splunk and raw logs were reviewed first to 
understand the full scope of authentication activity before running 
any detection queries.

**Query used:**
```
index=main source="password-spray-logs.csv"
```

**Why this query:**
Always begin with raw unfiltered data to establish your baseline. 
Clicking on the password_attempted field in the left panel immediately 
revealed that one password — Summer2026! — appeared in 83.3% of all 
events. This was the first and most critical early indicator of 
password spraying activity.

**What to look for:**
Total event count, unique users, unique IP addresses, and any field 
that shows disproportionate concentration on a single value.

**Finding:**
30 total authentication events were present. Reviewing the 
password_attempted field revealed 6 unique passwords — but Summer2026! 
accounted for 25 of 30 events — 83.3% of all activity. All other 
passwords appeared exactly once each — consistent with legitimate 
users logging in with their own unique credentials.

![Figure 1 — Raw log overview showing 30 events with password_attempted 
field revealing Summer2026! used in 83.3% of all 
events](screenshots/01-raw-logs.png)

**Figure 1** establishes the baseline dataset and immediately highlights 
the disproportionate use of a single password across the environment — 
the earliest indicator of a spray attack.

---

### Step 2 — Full Dataset Overview
All events were organised into a clean structured table to visualise 
the complete authentication picture across the environment.

**Query used:**
```
index=main source="password-spray-logs.csv"
| table time, user, src_ip, dest_ip, password_attempted, status, 
  description
| sort time
```

**Why this query:**
Including src_ip, user and password_attempted in the same table allows 
you to immediately see the spray pattern — one IP, many users, same 
password. Sorting by time shows the chronological sequence of the attack 
versus normal logins.

**What pattern to expect:**
A spray attack shows one IP address appearing repeatedly across many 
different user rows within a short time window. Legitimate logins show 
different IPs for different users — each person logging in from their 
own machine.

**Finding:**
The table clearly exposed the spray pattern — IP address 192.168.1.77 
appeared repeatedly across 9 different user accounts within a 2 minute 
window. All legitimate user logins came from their own individual IP 
addresses. The contrast between 192.168.1.77 appearing across all 
accounts versus each legitimate user having their own unique IP was 
immediately visible.

![Figure 2 — Full dataset table showing 192.168.1.77 targeting multiple 
accounts simultaneously contrasted against normal single-IP user 
logins](screenshots/02-full-table-overview.png)

**Figure 2** makes the spray pattern immediately visible — one IP 
address appearing across every user account is impossible to explain 
as normal behaviour and is definitive evidence of an automated attack.

---

### Step 3 — Identify the Spray Pattern and Compromised Account
All events using the spray password were isolated and grouped by user 
and status to identify exactly which account was successfully compromised.

**Query used:**
```
index=main source="password-spray-logs.csv" 
password_attempted="Summer2026!"
| stats count by user, status
| sort user
```

**Why this query:**
Filtering by the spray password and grouping by both user and status 
simultaneously shows two critical things — which accounts were targeted 
and which one succeeded. The count per account reveals the deliberate 
pattern of exactly 2 attempts per account.

**What pattern to expect:**
A password spray shows exactly 1 to 3 failures per account — deliberately 
staying under the lockout threshold. One account shows a success — the 
account whose real password matched the spray attempt.

**Finding:**
| User | Status | Count |
|------|--------|-------|
| admin | failed | 2 |
| helpdesk | failed | 2 |
| jdoe | failed | 2 |
| jsmith | success | 7 |
| mwilliams | failed | 2 |
| svc_backup | failed | 2 |
| tbrady | failed | 2 |
| user1 | failed | 2 |
| user2 | failed | 2 |

Every account received exactly 2 failed attempts — a deliberate pattern 
to avoid triggering account lockout policies. jsmith was the only account 
to show success — confirming Summer2026! was jsmith's actual password. 
The 7 successful events indicate the attacker used jsmith's credentials 
extensively after the initial breach.

![Figure 3 — Spray pattern showing exactly 2 failures per account with 
jsmith as the only success — confirming the compromised 
account](screenshots/03-spray-pattern-by-user.png)

**Figure 3** is the definitive proof of password spraying — the uniform 
2-failure pattern across every account is statistically impossible 
without an automated tool deliberately limiting attempts per account.

---

### Step 4 — Confirm Single Source IP
Failed login attempts were grouped by source IP to confirm all attack 
activity originated from a single location.

**Query used:**
```
index=main source="password-spray-logs.csv" status=failed
| stats count by src_ip
| sort -count
```

**Why this query:**
Grouping failures by source IP confirms whether this is a single 
targeted attacker or a distributed attack from multiple sources. 
A single IP responsible for failures across all accounts is definitive 
proof of an automated spray tool rather than coincidental user mistakes.

**What pattern to expect:**
A password spray attack originates from one IP — the attacker's machine 
running an automated spray tool. Random user mistakes would come from 
many different IPs.

**Finding:**
All 18 failed login attempts across 9 different user accounts originated 
exclusively from IP address 192.168.1.77. Not a single failed login came 
from any other IP address. One IP targeting 9 accounts simultaneously is 
statistically impossible as random user behaviour — confirming this was 
an automated attack tool.

![Figure 4 — All 18 failed attempts confirmed as originating from single 
IP 192.168.1.77](screenshots/04-attacking-ip.png)

**Figure 4** eliminates any possibility of this being coincidental 
activity. A single IP responsible for all failures across all accounts 
is definitive confirmation of an automated password spray attack.

---

### Step 5 — Trace Lateral Movement
Successful logins using jsmith's compromised credentials were isolated 
and sorted chronologically to trace the attacker's movement across 
the network after the initial breach.

**Query used:**
```
index=main source="password-spray-logs.csv" user=jsmith status=success
| table time, user, src_ip, dest_ip, status
| sort time
```

**Why this query:**
Filtering for jsmith's successful logins specifically from 192.168.1.77 
— the attacker's IP — shows every system the attacker accessed using 
the stolen credentials. Multiple destination IPs in quick succession 
confirms lateral movement.

**What pattern to expect:**
A normal employee logs into 1 or 2 consistent systems. An attacker with 
stolen credentials accesses many different servers rapidly — especially 
high value targets. The source IP remaining as 192.168.1.77 throughout 
confirms this is the attacker using jsmith's credentials rather than 
jsmith themselves.

**Finding:**
After compromising jsmith's account at 14:02:07 the attacker moved 
laterally across the network accessing 5 different servers within 
one hour:

| Time | Destination IP | Server Role | Risk |
|------|---------------|-------------|------|
| 14:02:07 | 10.0.0.5 | Domain Controller | Critical |
| 14:05:00 | 10.0.0.5 | Domain Controller again | Critical |
| 14:10:00 | 10.0.0.20 | File Server | High |
| 14:15:00 | 10.0.0.30 | Backup Server | Critical |
| 15:00:00 | 10.0.0.40 | Unknown Server | High |
| 15:05:00 | 10.0.0.50 | Unknown Server | High |
| 15:10:00 | 10.0.0.20 | File Server revisited | High |

Domain controller access is the most critical finding — an attacker 
with domain controller access can reset passwords, create accounts and 
control every machine on the network. Backup server access raises the 
risk of ransomware deployment as attackers commonly destroy backups 
to prevent recovery.

![Figure 5 — Lateral movement showing attacker accessing 5 servers 
using jsmith credentials within one hour of initial 
breach](screenshots/05-jsmith-lateral-movement.png)

**Figure 5** confirms the full scope of the breach — from a single 
guessed password the attacker reached the domain controller, file 
server, backup server and two additional unknown systems within 
68 minutes.

---

### Step 6 — Visualize the Spray Pattern Over Time
A timechart was used to visualize failed login activity over time, 
providing clear visual proof of the synchronized spray pattern that 
is impossible to explain as normal user behaviour.

**Query used:**
```
index=main source="password-spray-logs.csv" status=failed
| timechart span=1m count by user
```

**Why this query:**
The `timechart` command is one of the most powerful detection tools in 
Splunk — it plots activity over time grouped by a field. Visualizing 
failed logins by user over time immediately reveals whether failures 
are random and scattered — normal — or synchronized and simultaneous 
— an attack. This type of visualization is used in real SOC dashboards 
for continuous monitoring.

**What pattern to expect:**
Normal failed logins appear as scattered random bars at different times 
for different users. A password spray appears as synchronized clusters 
where every user account shows a failure at exactly the same time — 
only possible with an automated tool cycling through accounts.

**Finding:**
The visualization revealed three distinct synchronized waves of failed 
login attempts at 14:00, 14:01 and 14:02 — every user account being 
hit simultaneously in each wave. This perfectly synchronized pattern 
across 9 accounts is statistically impossible as random user behaviour 
and is definitive visual proof of an automated password spray tool.

![Figure 6 — Timechart visualization showing three synchronized waves 
of failed logins across all accounts simultaneously — definitive visual 
proof of automated password spraying](screenshots/06-spray-timechart-visualization.png)

**Figure 6** is the most powerful visual in this investigation. The 
synchronized clustering of failures across all accounts at exactly the 
same time intervals is impossible to explain as coincidence — this 
pattern could only be produced by an automated attack tool.

---

## Attack Timeline

| Time | Event |
|------|-------|
| 2026-04-10 14:00:01 | First spray wave begins — admin targeted |
| 2026-04-10 14:00:01—14:00:57 | Wave 1 — all 9 accounts hit once each |
| 2026-04-10 14:01:04—14:01:53 | Wave 2 — all accounts hit second time |
| 2026-04-10 14:02:00 | Wave 3 begins — admin hit again |
| 2026-04-10 14:02:07 | ⚠️ jsmith account breached — Summer2026! succeeds |
| 2026-04-10 14:02:07 | Attacker accesses domain controller 10.0.0.5 |
| 2026-04-10 14:10:00 | Attacker accesses file server 10.0.0.20 |
| 2026-04-10 14:15:00 | ⚠️ Attacker accesses backup server 10.0.0.30 |
| 2026-04-10 15:00:00 | Attacker accesses unknown server 10.0.0.40 |
| 2026-04-10 15:05:00 | Attacker accesses unknown server 10.0.0.50 |
| 2026-04-10 15:10:00 | Attacker returns to file server 10.0.0.20 |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Attack type | Password spraying |
| Attacking IP | 192.168.1.77 |
| Accounts targeted | 9 accounts |
| Total failed attempts | 18 |
| Attempts per account | 2 — deliberately under lockout threshold |
| Compromised account | jsmith |
| Compromise time | 2026-04-10 14:02:07 |
| Servers accessed | 10.0.0.5, 10.0.0.20, 10.0.0.30, 10.0.0.40, 10.0.0.50 |
| Attack duration | Spray lasted 2 minutes, lateral movement lasted 68 minutes |
| Root cause | Weak seasonal password — Summer2026! |
| Weakness exploited | No MFA, weak password policy, no spray detection alert |

---

## MITRE ATT&CK Mapping

| Technique | ID | Explanation |
|-----------|-----|-------------|
| Password Spraying | T1110.003 | The attacker attempted one common password against many accounts simultaneously — deliberately staying under lockout thresholds to avoid detection |
| Valid Accounts | T1078 | After guessing jsmith's password the attacker used legitimate credentials — making their activity appear as normal user logins to the network |
| Lateral Movement via Remote Services | T1021 | The attacker used jsmith's credentials to authenticate to 5 different servers across the network — expanding their foothold beyond the initial compromise |
| Remote Services — SMB/Windows Admin Shares | T1021.002 | Network logons were used to access remote servers using standard Windows authentication protocols |

---

## Conclusion
This investigation confirmed a successful password spray attack against 
SecureCore Ltd launched from IP address 192.168.1.77. The attacker used 
an automated tool to attempt the password Summer2026! against 9 user 
accounts in three synchronized waves — deliberately limiting attempts 
to 2 per account to stay below the account lockout threshold.

The attack succeeded because jsmith used a weak seasonal password that 
matched the attacker's spray attempt. This is a common and preventable 
failure — seasonal passwords such as Summer2026!, Winter2025! and 
Welcome123! are among the first passwords tested in spray attacks.

Following the breach the attacker moved laterally across 5 servers 
within 68 minutes — including the domain controller and backup server — 
representing a critical severity incident. Domain controller access 
means the attacker potentially had the ability to control every machine 
and account in the organisation. Backup server access raises the 
immediate risk of ransomware deployment with no recovery path.

The timechart visualization provides definitive visual proof that this 
was an automated coordinated attack — the perfectly synchronized failure 
pattern across all 9 accounts simultaneously is statistically impossible 
as random user behaviour.

The primary weaknesses exploited were the absence of multi-factor 
authentication, a weak password policy that allowed seasonal passwords, 
and no SIEM alert for a single IP targeting multiple accounts within 
a short time window.

## Recommended Actions
- Immediately disable jsmith's account and reset credentials
- Block 192.168.1.77 at the firewall immediately
- Investigate all 5 servers accessed for signs of data theft or tampering
- Check domain controller logs for new account creation or permission 
  changes made during the breach window
- Verify backup server integrity immediately
- Force organisation-wide password reset with complexity requirements
- Ban seasonal and common passwords using a password blacklist
- Enable multi-factor authentication on all accounts — priority on 
  privileged accounts
- Implement account lockout after 3 failed attempts
- Create SIEM alert — single IP targeting more than 3 accounts within 
  60 seconds
- Educate employees on password security — specifically the risk of 
  seasonal and predictable passwords
