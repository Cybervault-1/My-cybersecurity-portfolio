## Summary
An attacker repeatedly tried to break into the admin account at SecureCore 
Ltd by guessing passwords over and over until one worked. After getting in, 
they came back five days later and used the same account to access three 
critical servers, the domain controller, file server and backup server. 
This was a serious breach that could have been prevented with basic security 
controls that were not in place.

---

## Scenario
It is Monday morning at SecureCore Ltd. The SOC team gets an alert about 
multiple failed login attempts hitting the domain controller DC01. As the 
analyst on duty, the task is to figure out whether this is just a user who 
forgot their password or something more serious.

The investigation uses Windows authentication logs already loaded into 
Splunk to find out what happened, who did it, whether they got in, and 
what they did after.

## Objective
Use Splunk to investigate the suspicious login activity, find the source 
of the attack, confirm if the attacker succeeded, trace where they went 
after getting in, and write up the findings clearly.

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
A brute force attack is when someone uses a tool to automatically try 
hundreds of passwords against one account until something works. It is 
not sophisticated — it is just persistence. But it works when there are 
no controls to stop it.

The main signs that separate brute force from a user just mistyping 
their password:

| | Normal user mistake | Brute force attack |
|--|--------------------|--------------------|
| Number of failures | 1 to 3 | 10 or more |
| Speed | Minutes between attempts | Seconds between attempts |
| Source | Their own machine | One external IP |
| Target | Their own account | A specific privileged account |

Once the attacker gets in they have real credentials — so everything 
they do afterwards looks like normal user activity, which makes it 
harder to spot.

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs

**Query used:**
```
index=main
```

**What this does and why:**
This pulls everything in the dataset without any filters. Before doing 
anything else it is important to see the full picture, how many events 
are there, what fields exist, and does anything jump out straight away. 
Going straight to specific queries too early can cause you to miss 
important context.

One of the first things to check is the ratio of failed to successful 
logins. A healthy network has very few failures. If failures are making 
up most of the events something is wrong. 
The screenshot below shows the full raw dataset as it 
appeared in Splunk with all fields correctly loaded.
124 events in total.

![Raw log overview showing 124 total events across all users and IP 
addresses](screenshots/01-raw-logs.png)

---

### Step 2 — Identify the Most Targeted Account

**Query used:**
```
index=main status=failed
| stats count by user
| sort -count
```

**What this does and why:**
This filters to only failed logins and counts how many each user got, 
putting the highest number at the top. The point here is to see whether 
failures are spread evenly across users which would suggest normal 
mistakes — or piled up on one account, which would suggest someone is 
deliberately targeting that account.

In a brute force attack the targeted account stands out immediately 
because it has dramatically more failures than everyone else.

**What was found:**
| User | Failed Attempts |
|------|----------------|
| admin | 33 |
| tbrady | 2 |
| user2 | 2 |
| mwilliams | 1 |

The admin account had 33 failures. Every other account had 2 or less. 
That gap is too large to be a coincidence. The screenshot below shows 
this clearly the bar next to admin is far longer than anything else 
on the logs, making the targeting obvious at a glance.

![Failed login count per user showing admin as the clear primary 
target with 33 failures](screenshots/02-failed-logins-by-user.png)

---

### Step 3 — Identify the Attacking IP Address

**Query used:**
```
index=main user=admin status=failed
| stats count by src_ip
| sort -count
```

**What this does and why:**
This narrows down to only failed logins against the admin account and 
groups them by where they came from. Knowing whether the attack is 
coming from one place or many changes how you respond. One IP means 
a single attacker using an automated tool. Multiple IPs could mean 
a botnet or a group working together.

**What was found:**
| Source IP | Failed Attempts |
|-----------|----------------|
| 192.168.1.10 | 30 |
| 192.168.1.99 | 3 |

Two IPs showed up. 192.168.1.10 was responsible for 30 of the 33 
failures, clearly the main attacker. Then 192.168.1.99 appeared 
with 3 attempts that were described as "Unknown login attempt",
a different description from the standard Windows failure message, 
which suggests this second IP was using a different tool or method. 
The screenshot below shows both IPs and their attempt counts.

![Failed login attempts against admin grouped by source IP showing 
two suspicious sources](screenshots/03-attacking-ip.png)

---

### Step 4 — Reconstruct the Full Attack Timeline

**Query used:**
```
index=main user=admin
| table time, user, src_ip, dest_ip, status, description
| sort time
```

**What this does and why:**
This pulls all admin account activities both failures and successes  
in time order. Removing the status filter is important here because 
you need to see everything, not just the failures. The moment failures 
turn into a success is the breach point. What happens in the dest_ip 
column after that tells you where the attacker went.

**What was found:**
Two separate attack phases showed up across different dates.

On April 1st, failures started arriving from 192.168.1.10 at 10:00:01, 
one every few seconds, which is too fast to be manual. After 10 
failures the admin account was successfully accessed at 10:01:00. Then 
29 minutes later the second IP 192.168.1.99 showed up with its 3 
unknown attempts — arriving only after the first attacker had already 
got in, which looks like the two were working together.

Five days later on April 6th the same attacker came back, launched 
another wave of attempts, and got in again at 10:00:03, meaning 
whatever was done to fix things the first time was not enough.

The screenshot below shows the full timeline from first failure to 
lateral movement across servers.

![Full admin account timeline showing failures, breach points and 
post-breach server access](screenshots/04-full-attack-timeline.png)

---

### Step 5 — Investigate the Second IP Address

**Query used:**
```
index=main src_ip=192.168.1.99
| table time, user, src_ip, dest_ip, status, description
| sort time
```

**What this does and why:**
This pulls everything that 192.168.1.99 did in the environment. The 
goal is to understand if this IP was acting independently or in 
coordination with the primary attacker. The timing is the key thing 
to look at here.

**What was found:**
192.168.1.99 made exactly 3 attempts within 20 seconds, all targeting 
admin, all on April 1st at 10:30, which is 29 minutes after 192.168.1.10 
already successfully got in. It made a small number of attempts, stopped, 
and never came back. The fact that it only appeared after the breach 
and used a different attempt description strongly suggests it was 
testing credentials passed to it by the first attacker. The screenshot 
below shows the three attempts and their timing.

![Second IP activity showing 3 unknown login attempts arriving 29 
minutes after the confirmed breach](screenshots/05-second-ip-investigation.png)

---

### Step 6 — Trace Lateral Movement

**Query used:**
```
index=main user=admin status=success
| table time, user, src_ip, dest_ip, status
| sort time
```

**What this does and why:**
This looks only at successful admin logins and maps them to destination 
IPs in time order. A normal user logs into one or two consistent systems. 
An attacker with stolen credentials jumps between servers quickly — 
especially the ones that matter most like domain controllers, file 
servers and backup servers.

**What was found:**
After getting back into the admin account on April 6th the attacker 
moved across the network hitting three different servers within 47 minutes:

| Time | Server IP | What it is |
|------|-----------|------------|
| 10:00:03 | 10.0.0.5 | Domain Controller |
| 10:30:00 | 10.0.0.5 | Domain Controller again |
| 10:45:00 | 10.0.0.20 | File Server |
| 10:47:00 | 10.0.0.30 | Backup Server |

Getting into the domain controller is the worst possible outcome,
whoever controls that controls everything on the network. Getting into 
the backup server is also critical because attackers destroy backups 
before launching ransomware to make sure the victim cannot recover. 
The screenshot below shows all five successful logins and the servers 
accessed.

![Successful admin logins showing lateral movement across domain 
controller, file server and backup server](screenshots/06-lateral-movement.png)

---

## 🕒 Attack Timeline

| Time | What happened |
|------|--------------|
| 2026-04-01 10:00:01 | First failed login attempt from 192.168.1.10 — automated attempts begin every few seconds |
| 2026-04-01 10:00:45 | 10th consecutive failure — attack continues because there is no lockout policy to stop it |
| 2026-04-01 10:01:00 | ⚠️ Admin account breached — attacker gets in for the first time |
| 2026-04-01 10:30:00 | Second IP 192.168.1.99 shows up with 3 unknown attempts — 29 minutes after the breach |
| 2026-04-06 09:58:01 | Attacker returns five days later — starts another round of attempts |
| 2026-04-06 10:00:03 | ⚠️ Admin account breached again — original fix was not enough |
| 2026-04-06 10:30:00 | Attacker logs into domain controller |
| 2026-04-06 10:45:00 | Attacker logs into file server |
| 2026-04-06 10:47:00 | ⚠️ Attacker logs into backup server — ransomware risk now critical |

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
| Weakness exploited | No account lockout policy, no MFA |
| Severity | Critical |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Brute Force — Password Guessing | T1110.001 | An automated tool made 33 repeated password attempts against the admin account — only possible because there was no lockout policy to block it |
| Valid Accounts | T1078 | After getting the password right the attacker used real admin credentials — meaning their activity looked like normal authorised logins to anyone watching |
| Lateral Movement via Remote Services | T1021 | The stolen admin credentials were used to log into three different servers across the network within 47 minutes of the second breach |
| Credential Access | T1110 | The speed and volume of attempts — one every few seconds — confirms an automated credential access tool was used rather than someone guessing manually |

---

## Conclusion
This was a straightforward brute force attack that worked because the 
basics were not in place. The attacker did not do anything clever — they 
just kept trying passwords until one worked. The only reason they 
succeeded is that there was nothing to stop them.

An account lockout policy set to 5 attempts would have ended this attack 
before it started. Multi-factor authentication would have meant a correct 
password still was not enough to get in. Neither was in place.

What made this worse is that the attacker came back five days later and 
got in again through the same route — meaning the first incident was 
never properly fixed. By the time the second breach was detected the 
attacker had already reached the domain controller and the backup server, 
which puts the entire organisation at risk.

This needs to be treated as a full network compromise until a forensic 
investigation confirms exactly what was accessed and whether anything 
was changed or stolen.

---

## 🔑 Key Takeaways

- A lockout policy after 5 failed attempts would have stopped this 
  entirely — it is one of the simplest controls to put in place
- Brute force is easy to spot in logs once you know what to look for — 
  rapid failures from one IP against one account is a clear pattern
- The moment an attacker gets a successful login the severity jumps 
  immediately — this is no longer just an attempt, it is a breach
- One compromised account reached three critical servers in under an 
  hour — lateral movement happens fast
- Coming back five days later and getting in again shows the first 
  response was incomplete — always verify the full attack path is closed
- Backup server access means ransomware is a real possibility — 
  verify backup integrity immediately when this happens

---

## Recommended Actions
- Disable and reset the admin account credentials immediately
- Block 192.168.1.10 and 192.168.1.99 at the firewall
- Check all activity on 10.0.0.20 and 10.0.0.30 for signs of 
  data access or tampering
- Verify the backup server has not been modified or deleted from
- Set up account lockout after 5 failed attempts
- Turn on multi-factor authentication for all privileged accounts
- Set up a SIEM alert for more than 5 failed logins against any 
  account within 60 seconds
- Run a full forensic review of all servers the attacker accessed
