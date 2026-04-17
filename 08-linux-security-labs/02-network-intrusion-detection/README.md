# Network Intrusion Detection System

## Scenario

Following the security audit conducted on NexaCore Technologies' internal Linux server, the security team began receiving reports of unusual network activity. With suspicions that the contractor may have left behind a backdoor or that an unauthorised party had retained access, management escalated the investigation.

As the Security Analyst assigned to the case, you were tasked with building a Network Intrusion Detection script capable of monitoring live traffic, detecting port scans, identifying brute force attempts, and logging all suspicious activity for the incident response team.

## Objective

Develop a bash-based network monitoring script that continuously enumerates active connections, detects suspicious behaviour across multiple attack vectors, and generates a timestamped log file for security team review.

## Attack Simulation

To validate the detection capability of the script, controlled attack simulations were performed in an isolated lab environment against localhost.

| Attack | Tool | Target |
|---|---|---|
| Port Scan | nmap | 127.0.0.1 |
| SSH Brute Force | hydra | 127.0.0.1:22 |

All simulations were conducted in a safe, isolated environment with no impact on external systems or networks.

## Script Overview

The monitoring script performs sequential enumeration across eight network security categories using native Linux tools.

| Command | Purpose |
|---|---|
| `ip link show` | Active network interface detection |
| `ss -tunap` | Active connection enumeration |
| `ss -tuln` | Listening port identification |
| `ss -tn` with `uniq -c` | Port scan detection via connection frequency |
| `grep` against `/var/log/auth.log` | Failed SSH login attempt detection |
| `ss -tn` with `grep ESTAB` | Suspicious outbound connection detection |
| `uniq -c` with `sort -rn` | Top talker identification |
| `cat /proc/net/dev` | Network interface traffic statistics |

## Findings — Post Attack Simulation

| Finding | Risk Level | Why It Matters | Recommendation |
|---|---|---|---|
| SSH port 22 listening | Medium | Exposes SSH service to brute force and credential attacks | Restrict SSH access to authorised IPs using firewall rules |
| Brute force attempts detected on SSH | High | 8 login attempts using common passwords — clear credential attack | Implement fail2ban, disable root SSH login, enforce key-based authentication |
| Active outbound connections to 34.107.243.93 | Medium | Unrecognised external IP with established connection | Investigate IP reputation and verify connection legitimacy |
| No port scan activity detected | Low | Port scan threshold not triggered during simulation | Lower detection threshold for increased sensitivity |

## Analyst Interpretation

**Brute Force Attack**
The hydra simulation generated 8 failed login attempts against the SSH service using a common password wordlist. This mirrors real-world credential stuffing and brute force attacks. The script successfully captured these attempts from the auth log, demonstrating detection capability against one of the most common attack vectors targeting Linux servers.

**SSH Exposure**
Port 22 was found listening on all interfaces following the SSH service being started for simulation purposes. In a production environment, SSH should be restricted to specific trusted IP addresses and key-based authentication should be enforced to eliminate password-based attacks entirely.

**Outbound Connection Analysis**
An established outbound connection to an external IP was identified during monitoring. While this was browser traffic in the lab environment, in a production scenario this would warrant immediate IP reputation analysis and investigation for potential command and control communication.

## Skills Demonstrated

- Network Traffic Analysis
- Intrusion Detection and Alert Triage
- Brute Force Attack Detection
- Port Scan Detection
- SSH Security Monitoring
- Bash Scripting and Automation
- Attack Simulation in Isolated Lab Environment
- Security Log Analysis and Reporting

## How to Run

```bash
git clone https://github.com/Cybervault-1/My-cybersecurity-portfolio.git
cd My-cybersecurity-portfolio/08-linux-security-labs/02-network-intrusion-detection
chmod +x scripts/network_monitor.sh
sudo ./scripts/network_monitor.sh
```

The script prints all findings to the terminal in real time and saves a complete timestamped log to the `logs/` directory upon completion.

## Future Improvements

- Implement real-time continuous monitoring loop with configurable scan intervals
- Integrate with fail2ban to automatically block detected brute force IPs
- Add IP reputation lookup against threat intelligence feeds
- Export findings in JSON format for SIEM ingestion
- Extend detection to include ICMP flood and SYN scan identification

## Screenshots

### Baseline Scan — Clean System
![Baseline](screenshots/01-baseline.png)

### Attack Simulation — Port Scan
![Port Scan](screenshots/02-portscan-attack.png)

### Attack Simulation — Brute Force Wordlist
![Wordlist](screenshots/03-wordlist.png)

### Attack Simulation — SSH Brute Force
![Brute Force](screenshots/04-bruteforce-attack.png)

### Detection Results — Post Attack
![Detection](screenshots/05-detection-results.png)

## Author

**Adedeji Adetayo**
Cybersecurity Analyst
[GitHub](https://github.com/Cybervault-1)
