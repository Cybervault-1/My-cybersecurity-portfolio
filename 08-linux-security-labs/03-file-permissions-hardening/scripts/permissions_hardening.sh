#!/bin/bash

# ============================================
# Linux File Permissions Hardening Tool
# NexaCore Technologies
# Author: Adedeji Adetayo
# ============================================

REPORT_FILE=/home/Cybervault/My-cybersecurity-portfolio/08-linux-security-labs/03-file-permissions-hardening/reports/hardening_report_$(date +%F).txt

echo "============================================" | tee $REPORT_FILE
echo "     NEXACORE PERMISSIONS HARDENING REPORT  " | tee -a $REPORT_FILE
echo "     Date: $(date)                          " | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE

# --- SECTION 1: Sensitive File Permissions Audit ---
echo "" | tee -a $REPORT_FILE
echo "[*] SENSITIVE FILE PERMISSIONS AUDIT" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    if [ -f "$file" ]; then
        perms=$(stat -c "%a %n" $file)
        echo "[INFO] $perms" | tee -a $REPORT_FILE
    fi
done

# --- SECTION 2: Fix /etc/passwd Permissions ---
echo "" | tee -a $REPORT_FILE
echo "[*] FIXING /etc/passwd PERMISSIONS" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
chmod 644 /etc/passwd
echo "[FIXED] /etc/passwd set to 644" | tee -a $REPORT_FILE

# --- SECTION 3: Fix /etc/shadow Permissions ---
echo "" | tee -a $REPORT_FILE
echo "[*] FIXING /etc/shadow PERMISSIONS" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
chmod 640 /etc/shadow
echo "[FIXED] /etc/shadow set to 640" | tee -a $REPORT_FILE

# --- SECTION 4: World-Writable Files ---
echo "" | tee -a $REPORT_FILE
echo "[*] SCANNING FOR WORLD-WRITABLE FILES" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
WW_FILES=$(find / -xdev -type f -perm -0002 2>/dev/null)
if [ -z "$WW_FILES" ]; then
    echo "[OK] No world-writable files found" | tee -a $REPORT_FILE
else
    echo "[ALERT] World-writable files detected:" | tee -a $REPORT_FILE
    echo "$WW_FILES" | tee -a $REPORT_FILE
    echo "" | tee -a $REPORT_FILE
    echo "[*] FIXING WORLD-WRITABLE FILES" | tee -a $REPORT_FILE
    echo "$WW_FILES" | while read f; do
        chmod o-w "$f"
        echo "[FIXED] Removed world-write from: $f" | tee -a $REPORT_FILE
    done
fi

# --- SECTION 5: SUID Files Audit ---
echo "" | tee -a $REPORT_FILE
echo "[*] SCANNING FOR UNNECESSARY SUID FILES" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
find / -xdev -type f -perm -4000 2>/dev/null | tee -a $REPORT_FILE

# --- SECTION 6: Remove SUID from Kismet ---
echo "" | tee -a $REPORT_FILE
echo "[*] REMOVING SUID FROM HIGH RISK BINARIES" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
for binary in /usr/bin/kismet /usr/bin/kismet_cap_ti_cc_2540 /usr/bin/kismet_cap_rz_killerbee; do
    if [ -f "$binary" ]; then
        chmod u-s "$binary"
        echo "[FIXED] Removed SUID from: $binary" | tee -a $REPORT_FILE
    else
        echo "[SKIP] Not found: $binary" | tee -a $REPORT_FILE
    fi
done

# --- SECTION 7: Inactive User Accounts ---
echo "" | tee -a $REPORT_FILE
echo "[*] CHECKING FOR INACTIVE USER ACCOUNTS" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
lastlog | grep "Never logged in" | tee -a $REPORT_FILE

# --- SECTION 8: Password Policy Enforcement ---
echo "" | tee -a $REPORT_FILE
echo "[*] ENFORCING PASSWORD EXPIRY POLICY" | tee -a $REPORT_FILE
echo "--------------------------------------------" | tee -a $REPORT_FILE
chage --maxdays 90 --mindays 7 --warndays 14 kali
echo "[FIXED] Password policy enforced for kali account" | tee -a $REPORT_FILE
chage -l kali | tee -a $REPORT_FILE

echo "" | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE
echo "         HARDENING COMPLETE                 " | tee -a $REPORT_FILE
echo "============================================" | tee -a $REPORT_FILE
echo ""
echo "[+] Report saved to: $REPORT_FILE"
