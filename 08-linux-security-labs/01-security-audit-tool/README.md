# Automated Security Audit Tool

## Scenario

Following a two-week contractor engagement at **NexaCore Technologies**, the internal security team flagged anomalous activity on a critical Linux server , including unrecognised user accounts, unauthorised services, and unusual system configurations. A post-access security audit was initiated to assess the integrity of the system before it was returned to production.

As the Security Analyst assigned to the case, the objective was to develop an automated audit tool capable of systematically enumerating system security posture, identifying misconfigurations, and producing a structured report for the incident response team.

## Objective

Design and deploy a bash-based security audit script that automates the enumeration of a Linux system across eight critical security domains, reduces manual investigation time, and outputs a timestamped structured report suitable for security team review and incident documentation.

## Script Overview

The audit script performs sequential enumeration across eight security categories using native Linux tools. Each section writes output simultaneously to the terminal and to a timestamped report file using the `tee` command, ensuring a complete audit trail.

| Command | Purpose |
|---|---|
| `uname -a` / `hostname` | System fingerprinting |
| `who` | Active session detection |
| `cat /etc/passwd` / `cut` | Full user account enumeration |
| `grep` against `/etc/group` | Privilege escalation surface mapping |
| `ss -tuln` | Exposed network port detection |
| `systemctl list-units` | Running service enumeration |
| `find` with `-perm -0002` | World-writable file detection |
| `find` with `-perm -4000` | SUID binary identification |

The script uses `tee -a` to append each section to a persistent report file, enabling offline analysis and documentation after execution.

## Audit Findings — NexaCore Server

| Finding | Risk Level | Why It Matters | Recommendation |
|---|---|---|---|
| 50+ user accounts detected | Medium | Large attack surface; legacy or orphaned accounts may be leveraged for unauthorised access | Conduct user access review; disable or remove inactive accounts |
| kali and Cybervault hold sudo privileges | Medium | Multiple sudo-enabled accounts increase privilege escalation risk | Apply principle of least privilege; restrict sudo to authorised administrators only |
| No exposed network ports | Low | Reduces external attack surface; no immediate network-based threat vector identified | Maintain current firewall and port management policy |
| 18 active services running | Medium | Unnecessary services increase attack surface and persistence opportunities | Audit each service; disable non-essential services |
| No world-writable files detected | Low | Eliminates a common vector for unauthorised file modification or script injection | Maintain regular permission audits |
| SUID binaries identified, kismet, fusermount3, ssh-keysign | Medium | SUID binaries can be abused for local privilege escalation if misconfigured or vulnerable | Review SUID binaries against approved baseline; remove unnecessary SUID flags |

## Analyst Interpretation

**Privilege Escalation Risk**
Two accounts holding sudo privileges on a server recently accessed by an external contractor represents an elevated risk. Any account compromise, particularly through credential theft or brute force could result in full root-level access and complete system compromise.

**Attack Surface — Running Services**
Eighteen active services were identified at the time of audit. Each running service represents a potential entry point. Services such as `mysql`, `redis`, and `postgres` detected during enumeration should be reviewed to confirm they are required, patched, and not externally accessible.

**SUID Binary Abuse**
SUID files execute with the privileges of the file owner rather than the user running them. Tools such as `kismet` holding SUID flags present a potential local privilege escalation vector, particularly if the binary contains known vulnerabilities or is accessible to low-privileged users.

**Contractor Access Review**
Given the context of this audit, a post-contractor system review — particular attention should be paid to any accounts, services, or scheduled tasks created during the engagement period that fall outside approved configurations.

## Skills Demonstrated

- Linux Security Auditing
- System Enumeration and Reconnaissance
- Privilege Escalation Detection
- Network Exposure Analysis
- File Permission Auditing
- SUID Binary Analysis
- Bash Scripting and Automation
- Security Audit Reporting and Documentation
- Incident Response Support

## How to Run

```bash
git clone https://github.com/Cybervault-1/My-cybersecurity-portfolio.git
cd My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool
chmod +x scripts/security_audit.sh
./scripts/security_audit.sh
```

The script prints all findings to the terminal in real time and saves a complete timestamped report to the `reports/` directory upon completion.

## Future Improvements

- Integrate JSON output format for ingestion into SIEM platforms such as Microsoft Sentinel or Splunk
- Implement automated alerting via email or Slack webhook when high-risk findings are detected
- Add CVE cross-referencing for identified SUID binaries against the NIST NVD database
- Schedule automated weekly audits using cron for continuous monitoring
- Extend scope to include failed login attempts, SSH configuration review, and firewall rule analysis

## Screenshots

### Script Execution — Top
![Script Top](screenshots/01-script-top.png)

### Script Execution — Middle
![Script Middle](screenshots/02-script-middle.png)

### Audit Complete
![Script Bottom](screenshots/03-script-bottom.png)

## Author

**Adedeji adetayo**
Cybersecurity Analyst
[GitHub](https://github.com/Cybervault-1)
