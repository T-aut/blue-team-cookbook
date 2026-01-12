# Blue Team Defense & Incident Response

**Author**: Tautvydas Jackevičius

A quick reference for most of the commands and set-ups needed for Blue Team.

> [!NOTE]
> This repository is not a "final" version. This initial version was drafted for submission for the CS course, and covers most of what was learned in class. This repository is intended to be updated for the final week Red/Blue team exercise, as I discover more tools and techniques.

---

## System Hardening

### Initial Lockdown Script

```bash name=initial-lockdown.sh
#!/bin/bash
# Quick system lockdown for attack-defense CTF
# Mainly for systems that use `apt`

echo "[*] Starting system lockdown..."

# Update and patch critical services
echo "[+] Updating system packages..."
apt update && apt upgrade -y

# Change default passwords
echo "[+] Force password changes..."
passwd root  # Set strong password
for user in $(awk -F:  '$3 >= 1000 {print $1}' /etc/passwd); do
    echo "Changing password for $user"
    passwd $user
done

# 3. Disable unnecessary services
echo "[+] Disabling unnecessary services..."
systemctl disable avahi-daemon # apple
systemctl disable cups
systemctl disable bluetooth
systemctl stop avahi-daemon cups bluetooth
# Add more services deemed unnecessary

# Configure firewall
echo "[+] Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  # SSH
ufw allow 80/tcp  # HTTP
ufw allow 443/tcp # HTTPS
# Add more ports here if needed

# Secure SSH
echo "[+] Hardening SSH..."
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
systemctl restart sshd

# Enable process accounting
echo "[+] Enabling process accounting..."
apt install -y acct
systemctl enable acct
systemctl start acct

# Set secure permissions
echo "[+] Securing sensitive files..."
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group

# Enable audit logging
echo "[+] Enabling auditd..."
apt install -y auditd audispd-plugins
systemctl enable auditd
systemctl start auditd

echo "[*] Basic lockdown complete!"
```

### Quick Password Reset Script

```bash name=reset-all-passwords.sh
#!/bin/bash
# Emergency password reset for all users

NEW_PASS="TempP@ss$(date +%s)"
LOGFILE="/root/password_reset.log"

echo "[*] Resetting all user passwords..." | tee -a $LOGFILE
echo "[*] New temporary password: $NEW_PASS" | tee -a $LOGFILE

# Reset all human users
for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    echo "[+] Resetting password for:  $user" | tee -a $LOGFILE
    echo "$user:$NEW_PASS" | chpasswd
    passwd -e $user  # Force change on next login
done

# Reset root
echo "[+] Resetting root password" | tee -a $LOGFILE
echo "root:$NEW_PASS" | chpasswd

echo "[*] All passwords reset. Details logged to $LOGFILE"
echo "[! ] Secure this file:  chmod 600 $LOGFILE"
chmod 600 $LOGFILE
```

---

## Wazuh Setup & Configuration

### Wazuh Installation (Quick)

Remember, that for most up-to-date information refer to the official installation guide, found at:

https://documentation.wazuh.com/current/installation-guide/index.html

```bash
#!/bin/bash
# Wazuh Agent installation on Ubuntu/Debian

# Install dependencies
apt update
apt install -y curl apt-transport-https lsb-release gnupg

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh. gpg --import && chmod 644 /usr/share/keyrings/wazuh. gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh. gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# Install Wazuh agent
apt update
apt install -y wazuh-agent

# Configure manager IP
WAZUH_MANAGER="10.0.0.10"  # Change to manager IP
sed -i "s/<address>MANAGER_IP<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "[*] Wazuh agent installed and started"
echo "[*] Check status: systemctl status wazuh-agent"
```

### Custom Wazuh Rules

```xml name=local_rules.xml url=/var/ossec/etc/rules/local_rules.xml
<!-- Custom rules for attack-defense CTF -->

<!-- SSH Brute Force Detection -->
<group name="syslog,sshd,">
  <rule id="100100" level="10">
    <if_sid>5716</if_sid>
    <description>Multiple SSH authentication failures</description>
    <same_source_ip />
    <frequency>5</frequency>
    <timeframe>120</timeframe>
  </rule>
</group>

<!-- Web Shell Detection -->
<group name="web,attack,">
  <rule id="100200" level="12">
    <if_sid>31100</if_sid>
    <match>eval\(|base64_decode|system\(|exec\(|shell_exec</match>
    <description>Possible web shell execution detected</description>
  </rule>
</group>

<!-- Reverse Shell Detection -->
<group name="attack,">
  <rule id="100300" level="15">
    <if_sid>530</if_sid>
    <match>/dev/tcp|nc -e|bash -i|sh -i|/bin/sh|/bin/bash</match>
    <description>Possible reverse shell command detected</description>
  </rule>
</group>

<!-- Privilege Escalation Attempts -->
<group name="privilege_escalation,">
  <rule id="100400" level="12">
    <if_sid>5402</if_sid>
    <match>sudo su|sudo -i|sudo /bin/bash|sudo /bin/sh</match>
    <description>Privilege escalation attempt detected</description>
  </rule>
</group>

<!-- File Integrity Monitoring Alert -->
<group name="syscheck,">
  <rule id="100500" level="10">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers|/root/. ssh</match>
    <description>Critical system file modified</description>
  </rule>
</group>

<!-- Suspicious Network Connections -->
<group name="network,">
  <rule id="100600" level="12">
    <decoded_as>netstat</decoded_as>
    <match>ESTABLISHED</match>
    <description>New network connection established</description>
  </rule>
</group>

<!-- Password Cracking Tools -->
<group name="attack,">
  <rule id="100700" level="12">
    <if_sid>530</if_sid>
    <match>john|hashcat|hydra|medusa|ncrack</match>
    <description>Password cracking tool executed</description>
  </rule>
</group>

<!-- Scanning Detection -->
<group name="recon,">
  <rule id="100800" level="10">
    <if_sid>530</if_sid>
    <match>nmap|masscan|unicornscan|zmap</match>
    <description>Network scanning tool detected</description>
  </rule>
</group>
```

### Wazuh Active Response Configuration

```xml name=ossec. conf url=/var/ossec/etc/ossec.conf
<!-- Add to ossec.conf -->

<ossec_config>
  <!-- File Integrity Monitoring -->
  <syscheck>
    <frequency>300</frequency>
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/root</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts. deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
  </syscheck>

  <!-- Log Analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- Active Response -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100,100200,100300,100700,100800</rules_id>
    <timeout>1800</timeout>
  </active-response>

  <active-response>
    <command>disable-account</command>
    <location>local</location>
    <rules_id>100400</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <command>
    <name>block-connection</name>
    <executable>block-connection.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>block-connection</command>
    <location>local</location>
    <rules_id>100600</rules_id>
  </active-response>
</ossec_config>
```

### Custom Active Response Scripts

```bash name=block-connection.sh url=/var/ossec/active-response/bin/block-connection.sh
#!/bin/bash
# Block suspicious network connections
# Location: /var/ossec/active-response/bin/block-connection.sh

LOCAL=$(dirname $0)
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

# Logging
LOG="/var/ossec/logs/active-responses.log"
echo "`date` $0 $1 $2 $3 $4 $5" >> $LOG

# Get source IP from alert
SOURCE_IP=$(echo $IP | cut -d'-' -f2)

if [ "x${ACTION}" = "xadd" ]; then
    # Block the IP
    iptables -I INPUT -s ${SOURCE_IP} -j DROP
    echo "`date` Blocked IP: ${SOURCE_IP}" >> $LOG

    # Kill any existing connections from this IP
    ss -K dst ${SOURCE_IP}

elif [ "x${ACTION}" = "xdelete" ]; then
    # Unblock after timeout
    iptables -D INPUT -s ${SOURCE_IP} -j DROP
    echo "`date` Unblocked IP: ${SOURCE_IP}" >> $LOG
fi

exit 0
```

```bash name=kill-process.sh url=/var/ossec/active-response/bin/kill-process.sh
#!/bin/bash
# Kill suspicious processes
# Location: /var/ossec/active-response/bin/kill-process.sh

ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

LOG="/var/ossec/logs/active-responses.log"
echo "`date` $0 $1 $2 $3 $4 $5" >> $LOG

# List of suspicious process names
SUSPICIOUS_PROCS=("nc" "ncat" "netcat" "socat" "python -c" "perl -e" "bash -i" "sh -i")

if [ "x${ACTION}" = "xadd" ]; then
    for proc in "${SUSPICIOUS_PROCS[@]}"; do
        PIDS=$(pgrep -f "$proc")
        if [ ! -z "$PIDS" ]; then
            echo "`date` Killing suspicious process: $proc (PIDs: $PIDS)" >> $LOG
            kill -9 $PIDS
        fi
    done
fi

exit 0
```

```bash name=backup-and-remove-webshell.sh url=/var/ossec/active-response/bin/backup-and-remove-webshell.sh
#!/bin/bash
# Backup and remove detected web shells
# Location: /var/ossec/active-response/bin/backup-and-remove-webshell.sh

ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
FILENAME=$6

LOG="/var/ossec/logs/active-responses. log"
BACKUP_DIR="/var/ossec/quarantine"

mkdir -p $BACKUP_DIR

echo "`date` $0 $1 $2 $3 $4 $5 $6" >> $LOG

if [ "x${ACTION}" = "xadd" ]; then
    if [ -f "$FILENAME" ]; then
        # Backup the file
        BACKUP_NAME="${BACKUP_DIR}/$(basename ${FILENAME})_$(date +%s)"
        cp "$FILENAME" "$BACKUP_NAME"
        echo "`date` Backed up suspicious file: $FILENAME to $BACKUP_NAME" >> $LOG

        # Remove the malicious file
        rm -f "$FILENAME"
        echo "`date` Removed malicious file: $FILENAME" >> $LOG
    fi
fi

exit 0
```

**Make scripts executable:**

```bash
chmod 750 /var/ossec/active-response/bin/block-connection.sh
chmod 750 /var/ossec/active-response/bin/kill-process.sh
chmod 750 /var/ossec/active-response/bin/backup-and-remove-webshell.sh
chown root:wazuh /var/ossec/active-response/bin/*. sh
```

---

## Suricata IDS/IPS Setup

### Suricata Installation

Same as for Wazuh, for most up-to-date information refer to the official documentation and set-up guides:

https://docs.suricata.io/en/latest/quickstart.html

```bash
#!/bin/bash
# Install Suricata IDS/IPS

apt update
apt install -y software-properties-common
add-apt-repository ppa: oisf/suricata-stable -y
apt update
apt install -y suricata jq

# Update rules
suricata-update

# Enable and start
systemctl enable suricata
systemctl start suricata

echo "[*] Suricata installed"
echo "[*] Config:  /etc/suricata/suricata.yaml"
echo "[*] Rules: /var/lib/suricata/rules/"
```

### Custom Suricata Rules

```bash name=local. rules url=/etc/suricata/rules/local.rules
# Custom rules for attack-defense CTF

# Detect Nmap SYN scan
alert tcp any any -> $HOME_NET any (msg:"SCAN Nmap SYN scan detected"; flags:S,12; threshold:  type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)

# Detect Nmap NULL scan
alert tcp any any -> $HOME_NET any (msg:"SCAN Nmap NULL scan detected"; flags: 0; threshold: type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)

# Detect common reverse shells
alert tcp $HOME_NET any -> any any (msg:"MALWARE Reverse shell /bin/bash"; flow:established,to_server; content:"/bin/bash"; nocase; sid:1000010; rev:1;)

alert tcp $HOME_NET any -> any any (msg:"MALWARE Reverse shell /bin/sh"; flow:established,to_server; content:"/bin/sh"; nocase; sid:1000011; rev:1;)

alert tcp $HOME_NET any -> any any (msg:"MALWARE Python reverse shell"; flow:established,to_server; content:"import socket"; content:"socket.socket"; distance: 0; sid:1000012; rev:1;)

# Detect Netcat reverse shell
alert tcp $HOME_NET any -> any any (msg:"MALWARE Netcat reverse shell"; flow:established,to_server; content:"nc -e"; nocase; sid:1000013; rev:1;)

# Web shell detection
alert http any any -> $HOME_NET any (msg:"WEBSHELL Possible PHP web shell upload"; flow:established,to_server; content:"POST"; http_method; content: ". php"; http_uri; content:"<? php"; http_client_body; sid:1000020; rev:1;)

alert http any any -> $HOME_NET any (msg:"WEBSHELL system() command in HTTP"; flow:established; content:"system("; http_uri; sid:1000021; rev:1;)

alert http any any -> $HOME_NET any (msg:"WEBSHELL eval() in HTTP request"; flow:established; content:"eval("; http_uri; sid:1000022; rev:1;)

alert http any any -> $HOME_NET any (msg:"WEBSHELL base64_decode in HTTP"; flow:established; content:"base64_decode"; http_uri; sid:1000023; rev:1;)

# SQL Injection attempts
alert http any any -> $HOME_NET any (msg:"SQLI SQL injection attempt - UNION"; flow:established,to_server; content:"UNION"; nocase; http_uri; sid:1000030; rev:1;)

alert http any any -> $HOME_NET any (msg:"SQLI SQL injection - OR 1=1"; flow:established,to_server; content:"OR"; nocase; content:"1=1"; distance:0; http_uri; sid:1000031; rev:1;)

alert http any any -> $HOME_NET any (msg:"SQLI SQL comment in URI"; flow:established,to_server; content:"--"; http_uri; sid:1000032; rev:1;)

# Command injection
alert http any any -> $HOME_NET any (msg:"ATTACK Command injection pipe |"; flow:established,to_server; content: "|"; http_uri; sid:1000040; rev:1;)

alert http any any -> $HOME_NET any (msg:"ATTACK Command injection semicolon"; flow:established,to_server; content: ";"; http_uri; content:"ls"; distance:0; http_uri; sid:1000041; rev:1;)

# Directory traversal
alert http any any -> $HOME_NET any (msg:"ATTACK Directory traversal attempt"; flow:established,to_server; content:"../"; http_uri; threshold:  type both, track by_src, count 3, seconds 60; sid:1000050; rev:1;)

# Metasploit detection
alert tcp any any -> $HOME_NET any (msg:"EXPLOIT Metasploit meterpreter session"; flow:established; content:"meterpreter"; nocase; sid:1000060; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"EXPLOIT Metasploit reverse_tcp"; flow:established; content:"reverse_tcp"; nocase; sid: 1000061; rev:1;)

# Brute force detection
alert tcp any any -> $HOME_NET 22 (msg:"BRUTEFORCE SSH connection flood"; flags:S; threshold: type both, track by_src, count 20, seconds 60; sid:1000070; rev:1;)

alert http any any -> $HOME_NET any (msg:"BRUTEFORCE HTTP POST flood to login"; flow:established,to_server; content:"POST"; http_method; content:"login"; http_uri; threshold: type both, track by_src, count 10, seconds 60; sid:1000071; rev:1;)

# Suspicious outbound traffic
alert dns $HOME_NET any -> any 53 (msg:"MALWARE Possible DNS tunneling"; dns_query; content: "|00|"; depth:100; threshold: type both, track by_src, count 50, seconds 60; sid:1000080; rev:1;)

alert tcp $HOME_NET any -> any [4444,4445,1234,31337] (msg:"MALWARE Outbound connection to common backdoor ports"; flow:established,to_server; sid:1000081; rev:1;)

# Privilege escalation
alert tcp $HOME_NET any -> $HOME_NET any (msg:"ATTACK sudo command execution"; flow:established; content:"sudo su"; nocase; sid:1000090; rev:1;)

# File downloads from common hosting
alert http $HOME_NET any -> any any (msg:"SUSPICIOUS Download from pastebin"; flow:established,to_server; content:"pastebin. com"; http_host; sid:1000100; rev:1;)

alert http $HOME_NET any -> any any (msg:"SUSPICIOUS Download from github raw"; flow:established,to_server; content:"raw.githubusercontent.com"; http_host; sid:1000101; rev:1;)

# LinPEAS/WinPEAS detection
alert http any any -> $HOME_NET any (msg:"RECON LinPEAS download detected"; flow:established; content:"linpeas.sh"; http_uri; sid:1000110; rev:1;)

alert http any any -> $HOME_NET any (msg:"RECON WinPEAS download detected"; flow:established; content:"winPEAS"; nocase; http_uri; sid:1000111; rev:1;)
```

### Suricata Configuration

```yaml name=suricata.yaml url=/etc/suricata/suricata.yaml
# Key configurations for attack-defense

# Set network
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]" # Change to your network
    EXTERNAL_NET: "! $HOME_NET"

# Enable IPS mode (inline)
af-packet:
  - interface: eth0 # Change to used interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Outputs
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh

# Rules
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - local.rules # Your custom rules
```

### Auto-Block IPs Script (Suricata + iptables) python

```python name=suricata-autoblock.py
#!/usr/bin/env python3
"""
Monitor Suricata eve.json and auto-block attacking IPs
"""

import json
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timedelta

EVE_LOG = "/var/log/suricata/eve.json"
BLOCK_THRESHOLD = 5  # Number of alerts before blocking
TIME_WINDOW = 60  # Seconds
BLOCKED_IPS = set()

# Track alerts per IP
ip_alerts = defaultdict(list)

def block_ip(ip):
    """Block IP using iptables"""
    if ip in BLOCKED_IPS:
        return

    try:
        subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        BLOCKED_IPS.add(ip)
        print(f"[{datetime.now()}] BLOCKED: {ip}")

        # Log to file
        with open('/var/log/suricata/blocked_ips.log', 'a') as f:
            f.write(f"{datetime.now()} - Blocked IP: {ip}\n")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking {ip}: {e}")

def process_alert(alert):
    """Process Suricata alert and check if IP should be blocked"""
    if alert. get('event_type') != 'alert':
        return

    src_ip = alert.get('src_ip')
    if not src_ip:
        return

    # Don't block local IPs
    if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'):
        return

    timestamp = datetime.now()
    ip_alerts[src_ip].append(timestamp)

    # Remove old alerts outside time window
    cutoff = timestamp - timedelta(seconds=TIME_WINDOW)
    ip_alerts[src_ip] = [t for t in ip_alerts[src_ip] if t > cutoff]

    # Check if threshold exceeded
    if len(ip_alerts[src_ip]) >= BLOCK_THRESHOLD:
        block_ip(src_ip)
        ip_alerts[src_ip] = []  # Reset counter

def tail_eve_log():
    """Tail eve.json and process alerts in real-time"""
    print(f"[*] Monitoring Suricata alerts from {EVE_LOG}")
    print(f"[*] Threshold: {BLOCK_THRESHOLD} alerts in {TIME_WINDOW} seconds")

    with open(EVE_LOG, 'r') as f:
        # Go to end of file
        f.seek(0, 2)

        while True:
            line = f. readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                alert = json.loads(line)
                process_alert(alert)
            except json.JSONDecodeError:
                continue

if __name__ == '__main__':
    try:
        tail_eve_log()
    except KeyboardInterrupt:
        print("\n[*] Stopping Suricata auto-block")
        print(f"[*] Total blocked IPs: {len(BLOCKED_IPS)}")
```

### Auto-block IPS (just iptables, if suricata not present)

```bash name=suricata-autoblock.sh
#!/bin/bash
# Simple bash-based auto-blocking using iptables
# Monitors auth.log for SSH attacks

LOGFILE="/var/log/auth.log"
BLOCKED_LOG="/var/log/blocked_ips.log"
THRESHOLD=5
TIME_WINDOW=120  # seconds

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root"
    exit 1
fi

echo "[*] Starting iptables auto-block monitor"
echo "[*] Threshold: $THRESHOLD failed attempts in $TIME_WINDOW seconds"
echo "[*] Monitoring:  $LOGFILE"
echo "[*] Press Ctrl+C to stop"
echo ""

# Create temporary file for tracking
TEMP_DIR="/tmp/iptables-autoblock"
mkdir -p "$TEMP_DIR"

# Function to block IP
block_ip() {
    local IP=$1
    local REASON=$2

    # Check if already blocked
    iptables -C INPUT -s "$IP" -j DROP 2>/dev/null
    if [ $? -ne 0 ]; then
        # Not blocked yet, block it
        iptables -I INPUT -s "$IP" -j DROP
        iptables -I OUTPUT -d "$IP" -j DROP

        echo -e "\033[91m[$(date '+%Y-%m-%d %H:%M:%S')] BLOCKED: $IP - $REASON\033[0m"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Blocked:  $IP - $REASON" >> "$BLOCKED_LOG"

        # Kill existing connections
        ss -K src "$IP" 2>/dev/null
    fi
}

# Function to check threshold
check_threshold() {
    local IP=$1
    local TRACK_FILE="$TEMP_DIR/${IP//\. /_}"

    # Add current timestamp
    echo "$(date +%s)" >> "$TRACK_FILE"

    # Remove old entries outside time window
    CUTOFF=$(($(date +%s) - TIME_WINDOW))
    grep -v "^[0-9]*$" "$TRACK_FILE" 2>/dev/null > "${TRACK_FILE}.tmp" || touch "${TRACK_FILE}.tmp"
    awk -v cutoff="$CUTOFF" '$1 > cutoff' "$TRACK_FILE" >> "${TRACK_FILE}.tmp"
    mv "${TRACK_FILE}.tmp" "$TRACK_FILE"

    # Count events
    COUNT=$(wc -l < "$TRACK_FILE")

    if [ "$COUNT" -ge "$THRESHOLD" ]; then
        block_ip "$IP" "Exceeded threshold ($COUNT events)"
        rm -f "$TRACK_FILE"  # Reset counter
    fi
}

# Clean up on exit
cleanup() {
    echo ""
    echo "[*] Stopping auto-block monitor"
    echo "[*] Blocked IPs logged to: $BLOCKED_LOG"
    rm -rf "$TEMP_DIR"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Monitor auth.log in real-time
tail -F "$LOGFILE" 2>/dev/null | while read -r line; do
    # Check for failed password attempts
    if echo "$line" | grep -q "Failed password"; then
        IP=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        if [ ! -z "$IP" ] && [[ !  "$IP" =~ ^(192\.168\.|10\.|127\.) ]]; then
            echo -e "\033[93m[$(date '+%Y-%m-%d %H:%M:%S')] Failed password from:  $IP\033[0m"
            check_threshold "$IP"
        fi
    fi

    # Check for invalid user
    if echo "$line" | grep -q "Invalid user"; then
        IP=$(echo "$line" | grep -oE '([0-9]{1,3}\. ){3}[0-9]{1,3}' | head -1)
        if [ ! -z "$IP" ] && [[ ! "$IP" =~ ^(192\.168\.|10\.|127\.) ]]; then
            echo -e "\033[93m[$(date '+%Y-%m-%d %H:%M:%S')] Invalid user from: $IP\033[0m"
            check_threshold "$IP"
        fi
    fi

    # Check for break-in attempts
    if echo "$line" | grep -q "POSSIBLE BREAK-IN ATTEMPT"; then
        IP=$(echo "$line" | grep -oE '([0-9]{1,3}\. ){3}[0-9]{1,3}' | head -1)
        if [ ! -z "$IP" ] && [[ ! "$IP" =~ ^(192\.168\.|10\.|127\.) ]]; then
            echo -e "\033[91m[$(date '+%Y-%m-%d %H:%M:%S')] BREAK-IN ATTEMPT from: $IP\033[0m"
            # Immediate block for break-in attempts
            block_ip "$IP" "Break-in attempt detected"
        fi
    fi
done
```

**Run the script:**

```bash
chmod +x suricata-autoblock.py
# -- or --
chmod +x suricata-autoblock.sh
# Run in background
nohup python3 suricata-autoblock.py &
# -- or --
nohup suricata-autoblock.sh
```

---

## Atomic Red Team (ART) Testing

### ART Installation

```powershell
# Windows - Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

```bash
# Linux - Install Atomic Red Team
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
```

### Running ART Tests

```powershell
# Windows - Test detection
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# Test T1003 - Credential Dumping
Invoke-AtomicTest T1003.001

# Test T1059 - Command and Scripting Interpreter
Invoke-AtomicTest T1059.001

# Test T1087 - Account Discovery
Invoke-AtomicTest T1087.001
```

```bash
# Linux - Manual testing
# T1087 - Account Discovery
cat /etc/passwd

# T1069 - Permission Groups Discovery
groups
id

# T1082 - System Information Discovery
uname -a
cat /etc/issue
```

### Validation Script

```bash name=test-detection.sh
#!/bin/bash
# Test blue team detection capabilities

echo "[*] Testing Blue Team Detection Capabilities"
echo "[*] Check Wazuh/Suricata for alerts"
echo ""

# Test 1: Network scanning detection
echo "[TEST 1] Network scanning simulation"
ping -c 5 127.0.0.1
sleep 2

# Test 2: SSH brute force simulation
echo "[TEST 2] Failed SSH authentication (safe)"
for i in {1..5}; do
    ssh invalid@localhost 2>/dev/null
    sleep 1
done

# Test 3: Suspicious command execution
echo "[TEST 3] Suspicious command patterns"
echo "id" | bash
echo "whoami" | bash
sleep 2

# Test 4: File integrity test
echo "[TEST 4] Modify monitored file"
touch /tmp/test_file_$(date +%s)
sleep 2

# Test 5: Suspicious network connection attempt
echo "[TEST 5] Network connection test"
timeout 2 nc -zv 8.8.8.8 4444 2>/dev/null || true
sleep 2

echo ""
echo "[*] Tests complete - Check logs:"
echo "    Wazuh: /var/ossec/logs/alerts/alerts.log"
echo "    Suricata: /var/log/suricata/fast.log"
```

---

## Incident Response Scripts

### Emergency Response Script

```bash name=emergency-response.sh
#!/bin/bash
# Emergency incident response - Run when attack detected

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INCIDENT_DIR="/root/incident_$TIMESTAMP"

echo "[! ] INCIDENT RESPONSE INITIATED:  $TIMESTAMP"

# Create incident directory
mkdir -p "$INCIDENT_DIR"

# Network snapshot
echo "[+] Capturing network state..."
netstat -antup > "$INCIDENT_DIR/netstat.txt"
ss -tulpn > "$INCIDENT_DIR/ss. txt"
iptables -L -n -v > "$INCIDENT_DIR/iptables.txt"
arp -a > "$INCIDENT_DIR/arp.txt"

# Process snapshot
echo "[+] Capturing running processes..."
ps auxf > "$INCIDENT_DIR/processes.txt"
lsof > "$INCIDENT_DIR/lsof.txt"
pstree -p > "$INCIDENT_DIR/pstree.txt"

# User activity
echo "[+] Capturing user activity..."
w > "$INCIDENT_DIR/who.txt"
last -100 > "$INCIDENT_DIR/last.txt"
lastlog > "$INCIDENT_DIR/lastlog.txt"

# File system changes
echo "[+] Checking for recent file changes..."
find / -type f -mmin -30 2>/dev/null > "$INCIDENT_DIR/recent_files.txt"
find /tmp -type f -mmin -60 2>/dev/null > "$INCIDENT_DIR/tmp_files.txt"
find /var/www -type f -mmin -60 2>/dev/null > "$INCIDENT_DIR/www_files.txt"

# Check for webshells
echo "[+] Scanning for web shells..."
grep -r "system(" /var/www/ 2>/dev/null > "$INCIDENT_DIR/webshell_scan.txt"
grep -r "eval(" /var/www/ 2>/dev/null >> "$INCIDENT_DIR/webshell_scan.txt"
grep -r "base64_decode" /var/www/ 2>/dev/null >> "$INCIDENT_DIR/webshell_scan.txt"

# Check for suspicious cron jobs
echo "[+] Checking scheduled tasks..."
crontab -l > "$INCIDENT_DIR/crontab_user.txt" 2>/dev/null
cat /etc/crontab > "$INCIDENT_DIR/crontab_system.txt" 2>/dev/null

# Check for SUID/SGID changes
echo "[+] Checking SUID/SGID files..."
find / -perm -4000 -o -perm -2000 2>/dev/null > "$INCIDENT_DIR/suid_files.txt"

# Memory dump (if enough space)
echo "[+] Creating memory dump..."
cat /proc/kcore > "$INCIDENT_DIR/memory_dump" 2>/dev/null || echo "Memory dump failed"

# Copy logs
echo "[+] Copying logs..."
cp -r /var/log "$INCIDENT_DIR/logs/"
cp /var/ossec/logs/alerts/alerts. log "$INCIDENT_DIR/" 2>/dev/null
cp /var/log/suricata/fast.log "$INCIDENT_DIR/" 2>/dev/null

# Network capture (30 seconds)
echo "[+] Starting packet capture (30 seconds)..."
timeout 30 tcpdump -i any -w "$INCIDENT_DIR/capture.pcap" 2>/dev/null &

echo ""
echo "[*] Incident data collected in:  $INCIDENT_DIR"
echo "[*] Next steps:"
echo "    1. Review collected data"
echo "    2. Identify attack vector"
echo "    3. Execute containment measures"
echo "    4. Run cleanup script"
```

### Kill Suspicious Connections

```bash name=kill-connections.sh
#!/bin/bash
# Kill all suspicious network connections

echo "[! ] Killing suspicious network connections..."

# Kill connections to common C2 ports
SUSPICIOUS_PORTS="4444 4445 1234 31337 8080 8888"

for port in $SUSPICIOUS_PORTS; do
    echo "[+] Killing connections to port $port..."
    ss -K dst : $port 2>/dev/null
done

# Kill connections from suspicious IPs (add your list)
SUSPICIOUS_IPS="1.2.3.4 5.6.7.8"

for ip in $SUSPICIOUS_IPS; do
    echo "[+] Killing connections from $ip..."
    ss -K src $ip 2>/dev/null
done

# Block the IPs
for ip in $SUSPICIOUS_IPS; do
    echo "[+] Blocking $ip with iptables..."
    iptables -I INPUT -s $ip -j DROP
    iptables -I OUTPUT -d $ip -j DROP
done

echo "[*] Suspicious connections terminated"
echo "[*] Review:  netstat -antup"
```

### Find and Remove Backdoors

```bash name=remove-backdoors.sh
#!/bin/bash
# Search and remove common backdoor mechanisms

REPORT="/root/backdoor_removal_report_$(date +%s).txt"

echo "[*] Searching for backdoors..." | tee -a $REPORT

# Check for unauthorized SSH keys
echo "" >> $REPORT
echo "[+] Checking SSH authorized_keys..." | tee -a $REPORT
find /home -name "authorized_keys" -exec ls -la {} \; >> $REPORT 2>&1
find /root -name "authorized_keys" -exec ls -la {} \; >> $REPORT 2>&1

# Check for suspicious cron jobs
echo "" >> $REPORT
echo "[+] Checking cron jobs..." | tee -a $REPORT
cat /etc/crontab >> $REPORT
ls -la /etc/cron. * >> $REPORT
crontab -l >> $REPORT 2>&1

# Remove suspicious cron entries (manual review recommended)
# crontab -r  # Use with caution!

# Check for web shells
echo "" >> $REPORT
echo "[+] Scanning for web shells..." | tee -a $REPORT
find /var/www -type f -name "*.php" -exec grep -l "eval(" {} \; >> $REPORT 2>&1
find /var/www -type f -name "*.php" -exec grep -l "system(" {} \; >> $REPORT 2>&1
find /var/www -type f -name "*.php" -exec grep -l "base64_decode" {} \; >> $REPORT 2>&1

# Check for SUID backdoors
echo "" >> $REPORT
echo "[+] Checking for suspicious SUID files..." | tee -a $REPORT
find / -perm -4000 -type f 2>/dev/null | grep -v -E "bin/(su|sudo|passwd|mount)" >> $REPORT

# Check systemd services
echo "" >> $REPORT
echo "[+] Checking systemd services..." | tee -a $REPORT
systemctl list-units --type=service --state=running >> $REPORT

# Check for hidden files in tmp
echo "" >> $REPORT
echo "[+] Checking /tmp for hidden files..." | tee -a $REPORT
ls -laR /tmp >> $REPORT 2>&1
ls -laR /var/tmp >> $REPORT 2>&1

# Check for unusual listening ports
echo "" >> $REPORT
echo "[+] Checking listening ports..." | tee -a $REPORT
netstat -tlpn >> $REPORT 2>&1

# Check bash history for evidence
echo "" >> $REPORT
echo "[+] Checking bash history..." | tee -a $REPORT
cat /root/.bash_history >> $REPORT 2>&1

echo ""
echo "[*] Backdoor scan complete. Report:  $REPORT"
echo "[! ] Review report and manually remove identified backdoors"
```

---

## Blue Team Checklist

All of the necessary pre-conditions and actions that should be taken in different phases of the CTF exercise (preparation, during attack, and what to do when an attack is detected).

```markdown
## Pre-Game Preparation

- [ ] All services identified and documented
- [ ] All default passwords changed
- [ ] Unnecessary services disabled
- [ ] Firewall configured and enabled
- [ ] Wazuh agent installed and configured
- [ ] Suricata installed with custom rules
- [ ] File integrity monitoring configured
- [ ] Active response scripts tested
- [ ] Incident response scripts ready
- [ ] Backup of critical configurations
- [ ] Monitoring dashboard running

## During Attack-Defense

- [ ] Monitor Wazuh alerts continuously
- [ ] Monitor Suricata IDS alerts
- [ ] Check dashboard every 2-3 minutes
- [ ] Review active network connections
- [ ] Check for new users/modifications
- [ ] Monitor web server logs
- [ ] Watch for file changes in /var/www
- [ ] Check running processes regularly
- [ ] Document all incidents
- [ ] Maintain communication with team

## When Attack Detected

- [ ] Run emergency-response. sh script
- [ ] Identify attack vector
- [ ] Block attacker IP immediately
- [ ] Kill suspicious connections
- [ ] Check for persistence mechanisms
- [ ] Remove backdoors if found
- [ ] Patch vulnerability if identified
- [ ] Restore from backup if needed
- [ ] Document incident timeline
- [ ] Update defenses to prevent recurrence

## Post-Incident

- [ ] Review all collected evidence
- [ ] Analyze attack techniques used
- [ ] Update Wazuh rules if needed
- [ ] Update Suricata signatures
- [ ] Patch any identified vulnerabilities
- [ ] Strengthen weak security controls
- [ ] Document lessons learned
- [ ] Update playbooks
```

## REMEMBER!!!

- **Logging Space**: Monitor disk space - logs can grow quickly
- **Active Response**: Test thoroughly - poorly configured can cause self-DoS
- **Documentation**: Document all changes made during defense
