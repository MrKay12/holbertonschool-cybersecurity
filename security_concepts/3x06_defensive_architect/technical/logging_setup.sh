#!/bin/bash

# Nexus Financial - Centralized Logging Setup
# Ubuntu 20.04+

set -e

CENTRAL_LOG_SERVER="10.0.1.30"
RSYSLOG_CONFIG="/etc/rsyslog.d/60-nexus-forwarding.conf"
AUDIT_RULES="/etc/audit/rules.d/nexus.rules"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Starting Nexus Financial logging setup..."

# ---------------------------------------------------------
# 1. Install required packages
# ---------------------------------------------------------

echo "[+] Installing rsyslog and auditd..."

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    rsyslog \
    auditd \
    audispd-plugins

# ---------------------------------------------------------
# 2. Enable services
# ---------------------------------------------------------

echo "[+] Enabling logging services..."

systemctl enable rsyslog
systemctl enable auditd

systemctl restart rsyslog
systemctl restart auditd

# ---------------------------------------------------------
# 3. Configure rsyslog forwarding
# ---------------------------------------------------------

echo "[+] Configuring centralized rsyslog forwarding..."

cat > "$RSYSLOG_CONFIG" << EOF
# Nexus Financial centralized logging

# Forward warning, error, critical, alert and emergency logs
*.warning @@10.0.1.30:514

# Authentication logs
auth,authpriv.* @@10.0.1.30:514

# Kernel logs
kern.* @@10.0.1.30:514
EOF

# Validate rsyslog configuration
rsyslogd -N1

systemctl restart rsyslog

# ---------------------------------------------------------
# 4. Configure auditd rules
# ---------------------------------------------------------

echo "[+] Configuring auditd rules..."

cat > "$AUDIT_RULES" << EOF
# Nexus Financial audit rules

# Remove previous rules
-D

# Increase audit buffer
-b 8192

# Monitor identity files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_changes

# Monitor network configuration
-w /etc/hosts -p wa -k network_changes
-w /etc/resolv.conf -p wa -k network_changes

# Monitor privileged command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged_commands

# Make audit rules immutable until reboot
-e 2
EOF

# ---------------------------------------------------------
# 5. Load audit rules
# ---------------------------------------------------------

echo "[+] Loading auditd rules..."

augenrules --load

systemctl restart auditd || true

# ---------------------------------------------------------
# 6. Verify configuration
# ---------------------------------------------------------

echo
echo "[+] Logging configuration completed."
echo
echo "------------------------------------------"
echo "Central log server : $CENTRAL_LOG_SERVER"
echo "Rsyslog forwarding : ENABLED"
echo "Auditd             : ENABLED"
echo "Sensitive files    : MONITORED"
echo "Root commands       : MONITORED"
echo "Audit immutable     : ENABLED (-e 2)"
echo "------------------------------------------"
echo

echo "[+] Current audit status:"
auditctl -s || true