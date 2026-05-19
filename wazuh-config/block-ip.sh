#!/bin/bash
# AutoShield Active Response: IP Blocking Script
# Location: /var/ossec/active-response/bin/block-ip.sh

LOG_FILE="/var/ossec/logs/active-responses.log"

read -r INPUT_JSON
ACTION=$(echo "$INPUT_JSON" | grep -oP '(?<="command":")[^"]+')
IP=$(echo "$INPUT_JSON" | grep -oP '(?<="srcip":")[^"]+')

if [ -z "$IP" ] || [ "$IP" == "null" ]; then
    # Fallback for different alert structures
    IP=$(echo "$INPUT_JSON" | grep -oP '(?<="address":")[^"]+')
fi

if [ -z "$IP" ]; then
    echo "$(date) - [ERROR] No IP found in input" >> "$LOG_FILE"
    exit 1
fi

if [ "$ACTION" == "add" ]; then
    iptables -I INPUT -s "$IP" -j DROP
    echo "$(date) - [ADD] Blocked malicious IP: $IP" >> "$LOG_FILE"
elif [ "$ACTION" == "delete" ]; then
    iptables -D INPUT -s "$IP" -j DROP
    echo "$(date) - [DELETE] Unblocked IP: $IP" >> "$LOG_FILE"
else
    echo "$(date) - [ERROR] Unknown action: $ACTION" >> "$LOG_FILE"
fi

exit 0
