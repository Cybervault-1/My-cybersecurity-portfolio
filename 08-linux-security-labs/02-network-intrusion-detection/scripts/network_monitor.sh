#!/bin/bash

# ============================================
# Network Intrusion Detection Tool
# NexaCore Technologies
# Author: Adedeji Adetayo
# ============================================

LOG_FILE=~/My-cybersecurity-portfolio/08-linux-security-labs/02-network-intrusion-detection/logs/network_monitor_$(date +%F).log
ALERT_THRESHOLD=10

echo "============================================" | tee $LOG_FILE
echo "     NEXACORE NETWORK MONITOR REPORT        " | tee -a $LOG_FILE
echo "     Date: $(date)                          " | tee -a $LOG_FILE
echo "============================================" | tee -a $LOG_FILE

# --- SECTION 1: Active Network Interfaces ---
echo "" | tee -a $LOG_FILE
echo "[*] ACTIVE NETWORK INTERFACES" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
ip link show | grep "UP" | tee -a $LOG_FILE

# --- SECTION 2: Active Connections ---
echo "" | tee -a $LOG_FILE
echo "[*] ACTIVE NETWORK CONNECTIONS" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
ss -tunap | tee -a $LOG_FILE

# --- SECTION 3: Listening Ports ---
echo "" | tee -a $LOG_FILE
echo "[*] LISTENING PORTS" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
ss -tuln | tee -a $LOG_FILE

# --- SECTION 4: Port Scan Detection ---
echo "" | tee -a $LOG_FILE
echo "[*] PORT SCAN DETECTION" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
SCAN_SUSPECTS=$(ss -tn | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | awk -v threshold=$ALERT_THRESHOLD '$1 > threshold {print $2, "connections:", $1}')
if [ -z "$SCAN_SUSPECTS" ]; then
    echo "[OK] No port scan activity detected" | tee -a $LOG_FILE
else
    echo "[ALERT] Possible port scan detected from:" | tee -a $LOG_FILE
    echo "$SCAN_SUSPECTS" | tee -a $LOG_FILE
fi

# --- SECTION 5: Failed SSH Login Attempts ---
echo "" | tee -a $LOG_FILE
echo "[*] FAILED SSH LOGIN ATTEMPTS" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
if [ -f /var/log/auth.log ]; then
    FAILED_SSH=$(grep "Failed password" /var/log/auth.log | tail -20)
    if [ -z "$FAILED_SSH" ]; then
        echo "[OK] No failed SSH login attempts detected" | tee -a $LOG_FILE
    else
        echo "[ALERT] Failed SSH login attempts detected:" | tee -a $LOG_FILE
        echo "$FAILED_SSH" | tee -a $LOG_FILE
    fi
else
    echo "[INFO] Auth log not available" | tee -a $LOG_FILE
fi

# --- SECTION 6: Suspicious Outbound Connections ---
echo "" | tee -a $LOG_FILE
echo "[*] SUSPICIOUS OUTBOUND CONNECTIONS" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
SUSPICIOUS=$(ss -tn | grep ESTAB | awk '{print $5}' | cut -d: -f1 | grep -v "^$" | sort -u)
if [ -z "$SUSPICIOUS" ]; then
    echo "[OK] No suspicious outbound connections detected" | tee -a $LOG_FILE
else
    echo "[INFO] Active outbound connections to:" | tee -a $LOG_FILE
    echo "$SUSPICIOUS" | tee -a $LOG_FILE
fi

# --- SECTION 7: Top Talkers ---
echo "" | tee -a $LOG_FILE
echo "[*] TOP TALKERS (MOST ACTIVE IPs)" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
ss -tn | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v "^$" | sort | uniq -c | sort -rn | head -10 | tee -a $LOG_FILE

# --- SECTION 8: Network Interface Statistics ---
echo "" | tee -a $LOG_FILE
echo "[*] NETWORK INTERFACE STATISTICS" | tee -a $LOG_FILE
echo "--------------------------------------------" | tee -a $LOG_FILE
cat /proc/net/dev | tee -a $LOG_FILE

echo "" | tee -a $LOG_FILE
echo "============================================" | tee -a $LOG_FILE
echo "         MONITORING COMPLETE                " | tee -a $LOG_FILE
echo "============================================" | tee -a $LOG_FILE
echo ""
echo "[+] Log saved to: $LOG_FILE"
