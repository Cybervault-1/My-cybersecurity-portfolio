##  Summary
An attacker used an automated tool to try one common password against every 
user account at SecureCore Ltd. By keeping the number of attempts low per 
account they stayed under the lockout threshold and avoided triggering any 
alerts. The attack worked against one account whose password matched the 
guess. After getting in the attacker moved across five internal servers 
including the domain controller and backup server within just over an hour.

---

## Scenario
It is Friday afternoon at SecureCore Ltd. The SOC dashboard starts showing 
failed login attempts appearing across several different user accounts at 
almost exactly the same time. No single account has enough failures to 
trigger a lockout alert which makes this easy to miss. As the analyst on 
duty the task is to work out whether this is a real attack or just a 
coincidence and if it is an attack to find out which account was hit and 
what happened after.

The investigation uses Windows authentication logs loaded into Splunk to 
prove the spray pattern, identify the compromised account and trace the 
attacker's movement through the network.

## Objective
Use Splunk to investigate the suspicious authentication pattern, prove this 
is a password spray attack, identify which account was compromised, trace 
the post-breach lateral movement, and produce a clear professional report 
of the findings.

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
These two attacks look very different in logs and require different detection 
approaches. Understanding the difference is important for getting the 
classification right.

| | Brute Force | Password Spraying |
|--|-------------|-------------------|
| How it works | Many passwords tried against one account | One password tried against many accounts |
| Speed | Fast and aggressive | Slow and spread out |
| Failures per account | High | Low, usually 1 to 3 |
| Lockout risk | High | Low by design |
| Why attackers use it | Targeting one specific person | Avoiding security alerts while covering many accounts |

Password spraying is harder to catch because the failures are spread across 
accounts rather than concentrated on one. Each account looks like a normal 
user mistake on its own. The pattern only becomes obvious when you zoom out 
and look at everything together.

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs

**Query used:**
```
index=main source="password-spray-logs.csv"
```

**What this does and why:**
This loads the full dataset without any filters. The first thing to do 
is get a feel for the data before running any specific queries. At this 
stage the goal is to look at the available fields and check if anything 
stands out straight away.

Clicking on the password_attempted field in the left panel is particularly 
useful here. In a spray attack one password appears far more frequently 
than anything else because the same guess is being used across every account.

**What was found:**
30 total events. Clicking on the password_attempted field revealed that 
Summer2026! appeared in 25 of those 30 events which is 83% of all activity. 
Every other password appeared exactly once. That single data point was 
enough to flag this as highly suspicious before running a single detection 
query. The screenshot below shows the full raw dataset in Splunk.

![Raw log overview showing 30 events with Summer2026! appearing in 
83% of all authentication activity](screenshots/01-raw-logs.png)

---

### Step 2 — Full Dataset Overview

**Query used:**
```
index=main source="password-spray-logs.csv"
| table time, user, src_ip, dest_ip, password_attempted, status,
  description
| sort time
```

**What this does and why:**
Putting the key fields into a clean table and sorting by time lets you 
read the events in the order they happened. Including src_ip and user 
in the same view makes the spray pattern easy to spot. In a spray attack 
you expect to see one IP address appearing repeatedly next to many 
different user accounts within a short time window.

**What was found:**
The table showed 192.168.1.77 appearing next to every single user account 
within a two minute window. All the legitimate logins in the dataset came 
from different IPs, one per user. Only 192.168.1.77 appeared across 
multiple accounts and it showed up at regular intervals suggesting 
automated tooling. The screenshot below shows the full table with the 
spray pattern clearly visible.

![Full dataset table showing 192.168.1.77 targeting every user account 
within a two minute window](screenshots/02-full-table-overview.png)

---

### Step 3 — Identify the Spray Pattern and Compromised Account

**Query used:**
```
index=main source="password-spray-logs.csv"
password_attempted="Summer2026!"
| stats count by user, status
| sort user
```

**What this does and why:**
Filtering to only the spray password and grouping by user and status 
shows two things at once. It confirms which accounts were targeted and 
which one actually succeeded. The count per account also reveals whether 
the attacker was deliberately limiting attempts to stay under the lockout 
threshold.

**What was found:**
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

Every account got exactly 2 failures. That is not a coincidence. The 
attacker deliberately kept it at 2 to avoid triggering any lockout 
policy. jsmith was the only account that showed a success which means 
Summer2026! was jsmith's actual password. The 7 successful events for 
jsmith show the attacker used that account extensively after getting in. 
The screenshot below shows this result.

![Spray pattern showing exactly 2 failures per account with jsmith 
as the only compromised account](screenshots/03-spray-pattern-by-user.png)

---

### Step 4 — Confirm Single Source IP

**Query used:**
```
index=main source="password-spray-logs.csv" status=failed
| stats count by src_ip
| sort -count
```

**What this does and why:**
Grouping all failed logins by source IP confirms whether the attack came 
from one place or many. This matters because a single IP responsible for 
failures across all accounts rules out the possibility that these were 
just random user mistakes happening at the same time. It can only be 
explained by one automated tool targeting every account.

**What was found:**
Every single one of the 18 failed login attempts came from 192.168.1.77. 
Not one failure in the dataset came from any other IP address. One source 
hitting nine different accounts in the same time window is impossible to 
explain as normal behaviour. The screenshot below confirms this finding.

![All 18 failed attempts confirmed as originating from a single 
IP address 192.168.1.77](screenshots/04-attacking.png)

---

### Step 5 — Trace Lateral Movement

**Query used:**
```
index=main source="password-spray-logs.csv" user=jsmith status=success
| table time, user, src_ip, dest_ip, status
| sort time
```

**What this does and why:**
Looking at only jsmith's successful logins in time order shows every 
server the attacker accessed after getting in. A normal employee logs 
into one or two consistent systems. If the same account suddenly starts 
appearing on five different servers within an hour that is a strong sign 
someone else is using those credentials.

The source IP is important here too. jsmith's own machine has a different 
IP. If all these successful logins are still coming from 192.168.1.77 
that confirms it is the attacker using the stolen credentials rather 
than jsmith logging in normally.

**What was found:**
After compromising jsmith's account at 14:02 the attacker moved through 
the network accessing five different servers over the next hour:

| Time | Server IP | What it is |
|------|-----------|------------|
| 14:02:07 | 10.0.0.5 | Domain Controller |
| 14:05:00 | 10.0.0.5 | Domain Controller again |
| 14:10:00 | 10.0.0.20 | File Server |
| 14:15:00 | 10.0.0.30 | Backup Server |
| 15:00:00 | 10.0.0.40 | Unknown server |
| 15:05:00 | 10.0.0.50 | Unknown server |
| 15:10:00 | 10.0.0.20 | File Server again |

Getting into the domain controller is the most serious finding here. 
Whoever has access to that has access to every account and machine in 
the organisation. The backup server access is also critical because 
attackers often destroy backups before launching ransomware to remove 
the victim's ability to recover. The screenshot below shows all seven 
successful logins and the servers accessed.

![jsmith successful logins showing lateral movement across five servers 
within 68 minutes of the initial breach](screenshots/05-jsmith-lateral-movement.png)

---

### Step 6 — Visualize the Spray Pattern Over Time

**Query used:**
```
index=main source="password-spray-logs.csv" status=failed
| timechart span=1m count by user
```

**What this does and why:**
The timechart command plots activity over time grouped by user. This 
turns the numbers into a visual that makes the spray pattern impossible 
to miss. In a spray attack all accounts get hit at the same time in 
synchronized waves. Normal failed logins look scattered and random. 
The difference between the two is immediately obvious on a chart.

This type of visualization is used in real SOC dashboards to monitor 
for spray attacks in real time because the pattern stands out so clearly 
compared to normal authentication noise.

**What was found:**
The chart showed three distinct waves of failed logins at 14:00, 14:01 
and 14:02 where every single user account was hit at the same time in 
each wave. That level of synchronization across nine different accounts 
is not possible through normal user behaviour. It can only happen with 
an automated tool cycling through every account on a timer. The screenshot 
below shows the chart with the three waves clearly visible.

![Timechart showing three synchronized waves of failed logins across 
all accounts confirming automated password spraying](screenshots/06-spray-timechart-visualization.png)

---

## 🕒 Attack Timeline

| Time | What happened |
|------|--------------|
| 2026-04-10 14:00:01 | First spray wave begins with every account hit once in quick succession |
| 2026-04-10 14:01:04 | Second wave starts with all accounts hit a second time |
| 2026-04-10 14:02:00 | Third wave begins |
| 2026-04-10 14:02:07 | ⚠️ jsmith account breached as Summer2026! matches the real password |
| 2026-04-10 14:02:07 | Attacker immediately accesses domain controller using jsmith credentials |
| 2026-04-10 14:10:00 | Attacker accesses file server |
| 2026-04-10 14:15:00 | ⚠️ Attacker accesses backup server |
| 2026-04-10 15:00:00 | Attacker accesses unknown server 10.0.0.40 |
| 2026-04-10 15:05:00 | Attacker accesses unknown server 10.0.0.50 |
| 2026-04-10 15:10:00 | Attacker returns to file server |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Attack type | Password spraying |
| Attacking IP | 192.168.1.77 |
| Accounts targeted | 9 |
| Total failed attempts | 18 |
| Attempts per account | 2 deliberately kept under lockout threshold |
| Compromised account | jsmith |
| Compromise time | 2026-04-10 14:02:07 |
| Servers accessed | 10.0.0.5, 10.0.0.20, 10.0.0.30, 10.0.0.40, 10.0.0.50 |
| Attack duration | Spray lasted 2 minutes, lateral movement lasted 68 minutes |
| Root cause | Weak seasonal password with no MFA |
| Severity | Critical |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Password Spraying | T1110.003 | One password was tried against every account in a synchronized automated pattern deliberately designed to stay under account lockout thresholds |
| Valid Accounts | T1078 | After guessing jsmith's password the attacker used real credentials meaning all their subsequent activity appeared as normal authorised logins |
| Lateral Movement via Remote Services | T1021 | The stolen jsmith credentials were used to access five different internal servers across the network within 68 minutes of the initial breach |
| Remote Services | T1021.002 | Standard Windows network authentication was used to move between servers making the lateral movement blend in with normal traffic |

---

## Conclusion
This attack worked because of two things. jsmith had a weak password that 
was easy to guess, and there was nothing in place to detect or slow down 
an attacker trying the same password across every account.

The spray technique was chosen deliberately. By keeping attempts to two 
per account the attacker avoided triggering any lockout alerts. From the 
outside each account looked like a normal user mistake. The attack only 
becomes obvious when you look at all the accounts together and notice 
that the same IP hit all of them at the same time.

Once in, the attacker moved quickly. Within eight minutes of guessing 
jsmith's password they were already on the domain controller. By the 
end of the first hour they had touched five different servers. The backup 
server access is the most concerning finding because it suggests the 
attacker may have been preparing for a ransomware deployment.

The organisation had no detection in place for this type of attack. A 
simple alert watching for one IP hitting more than three accounts within 
60 seconds would have caught this during the first wave before the 
attacker even succeeded.

---

## 🔑 Key Takeaways

- Password spraying is designed to be invisible at the account level. 
  You only see it when you look across all accounts at the same time
- One IP hitting nine accounts in two minutes is not a coincidence. 
  That pattern only comes from an automated tool
- Exactly two failures per account was not random. The attacker knew 
  the lockout threshold and stayed just below it
- A weak seasonal password brought down one account and that was enough 
  to reach five servers including the domain controller
- The spray to lateral movement gap was eight minutes. Attacks move 
  fast once they succeed
- Backup server access means ransomware risk. Always verify backup 
  integrity when this server is touched by a suspicious account

---

## Recommended Actions
- Disable jsmith's account and reset credentials immediately
- Block 192.168.1.77 at the firewall
- Check all five servers accessed for signs of data access or changes
- Review domain controller logs for any new accounts or permission 
  changes made during the breach window
- Verify backup server integrity immediately
- Force a password reset across the entire organisation
- Put a password policy in place that blocks seasonal and common passwords
- Turn on multi-factor authentication for all accounts starting with 
  privileged ones
- Set account lockout to trigger after 3 failed attempts
- Create a SIEM alert for any single IP hitting more than 3 accounts 
  within 60 seconds
