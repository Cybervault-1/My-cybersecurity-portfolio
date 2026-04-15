#!/bin/bash

# ============================================
# Automated Security Audit Tool
# NexaCore Technologies
# Author: Cybervault
# ============================================

REPORT_FILE=~/My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool/reports/audit_report_$(date +%F).txt

echo "============================================" | tee $REPORT_FILE
echo "       NEXACORE SECURITY AUDIT REPORT       " | tee -a $REPORT_FILE
echo "       Date: $(date)                        " | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE

# --- SECTION 1: System Information ---
echo "" | tee -a $REPORT_FILE
echo "[*] SYSTEM INFORMATION" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
uname -a | tee -a $REPORT_FILE
hostname | tee -a $REPORT_FILE

# --- SECTION 2: Logged In Users ---
echo "" | tee -a $REPORT_FILE
echo "[*] CURRENTLY LOGGED IN USERS" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
who | tee -a $REPORT_FILE

# --- SECTION 3: All User Accounts ---
echo "" | tee -a $REPORT_FILE
echo "[*] ALL USER ACCOUNTS ON SYSTEM" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
cat /etc/passwd | cut -d: -f1 | tee -a $REPORT_FILE

# --- SECTION 4: Users with Root Privileges ---
echo "" | tee -a $REPORT_FILE
echo "[*] USERS WITH ROOT/SUDO PRIVILEGES" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' '\n' | tee -a $REPORT_FILE

# --- SECTION 5: Open Ports ---
echo "" | tee -a $REPORT_FILE
echo "[*] OPEN PORTS" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
ss -tuln | tee -a $REPORT_FILE

# --- SECTION 6: Running Services ---
echo "" | tee -a $REPORT_FILE
echo "[*] RUNNING SERVICES" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
systemctl list-units --type=service --state=running | tee -a $REPORT_FILE

# --- SECTION 7: World-Writable Files ---
echo "" | tee -a $REPORT_FILE
echo "[*] WORLD-WRITABLE FILES (SECURITY RISK)" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
find / -xdev -type f -perm -0002 2>/dev/null | tee -a $REPORT_FILE

# --- SECTION 8: SUID Files ---
echo "" | tee -a $REPORT_FILE
echo "[*] SUID FILES (CAN RUN AS ROOT)" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
find / -xdev -type f -perm -4000 2>/dev/null | tee -a $REPORT_FILE

echo "" | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE
echo "         AUDIT COMPLETE                     " | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE
echo ""
echo "[+] Report saved to: $REPORT_FILE"
