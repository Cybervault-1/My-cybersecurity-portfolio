

## 📋 Scenario

You've just joined **NexaCore Technologies** as a Security Analyst. On your first day, your manager pulls you aside.

> *"We had a contractor working on this Linux server for the past two weeks. He's gone now, but before he left, one of our engineers noticed some strange behaviour — unfamiliar user accounts, unusual open ports, and services running that nobody recognises. We don't have time to check it manually. I need you to build a script that automatically audits this server and gives us a full security report."*

Your job: build an automated script that scans the server for security risks and produces a structured report for the security team.

---

## 🎯 Objective

Develop a bash script that systematically audits a Linux system across 8 security categories and automatically generates a timestamped report.

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|---|---|
| Kali Linux | Operating environment |
| Bash Scripting | Script development |
| `uname` / `hostname` | System identification |
| `who` / `cat /etc/passwd` | User enumeration |
| `grep` | Privilege detection |
| `ss` | Network port scanning |
| `systemctl` | Service enumeration |
| `find` | File permission auditing |

---

## 🔍 What the Script Audits

| # | Section | Description |
|---|---|---|
| 1 | System Information | OS version, kernel, hostname |
| 2 | Logged In Users | Active sessions on the system |
| 3 | All User Accounts | Every account registered on the machine |
| 4 | Sudo/Root Privileges | Accounts with elevated access |
| 5 | Open Ports | Exposed network ports |
| 6 | Running Services | All active background services |
| 7 | World-Writable Files | Files any user can modify — security risk |
| 8 | SUID Files | Files that execute with root privileges |

---

## 📊 Audit Findings — NexaCore Server

| Finding | Detail | Risk Level |
|---|---|---|
| User Accounts | 50+ accounts found including mysql, redis, postgres | ⚠️ Medium |
| Sudo Access | kali and Cybervault have sudo privileges | ⚠️ Medium |
| Open Ports | No exposed ports detected | ✅ Low |
| Running Services | 18 active services detected | ⚠️ Medium |
| World-Writable Files | None detected | ✅ Low |
| SUID Files | Multiple found — kismet, fusermount3, ssh-keysign | ⚠️ Medium |

---

## 📂 Project Structure
08-linux-security-labs/
└── 01-security-audit-tool/
├── README.md
├── scripts/
│   └── security_audit.sh
├── reports/
│   └── audit_report_2026-04-15.txt
└── screenshots/
├── 01-script-top.png
└── 02-script-bottom.png

---

## 🚀 How to Run

```bash
# Clone the repository
git clone https://github.com/Cybervault-1/My-cybersecurity-portfolio.git

# Navigate to the project
cd My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool

# Make the script executable
chmod +x scripts/security_audit.sh

# Run the audit
./scripts/security_audit.sh
```

The script will print all findings to the terminal and automatically save a full report to the `reports/` folder.

---

## 💡 Key Concepts Demonstrated

- Bash scripting and automation
- Linux user and group management
- File permission auditing
- Network port analysis
- Service monitoring
- Security audit reporting

---

## 📸 Screenshots

### Script Running
![Script Running](screenshots/01-script-top.png)

### Audit Complete
![Audit Complete](screenshots/02-script-bottom.png)

---

## 👤 Author

**Cybervault**  
Cybersecurity Analyst  
[GitHub](https://github.com/Cybervault-1)
