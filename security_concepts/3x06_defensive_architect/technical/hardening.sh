#!/bin/bash

# Nexus Financial - System Hardening
# Ubuntu 20.04+

set -e

SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_FILE="/etc/sysctl.d/99-nexus-hardening.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Starting Nexus Financial hardening..."

# ---------------------------------------------------------
# 1. Update system packages
# ---------------------------------------------------------

echo "[+] Updating system packages..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y

# ---------------------------------------------------------
# 2. Install security packages
# ---------------------------------------------------------

echo "[+] Installing security packages..."

apt-get install -y \
    fail2ban \
    auditd \
    audispd-plugins \
    unattended-upgrades \
    ufw

# ---------------------------------------------------------
# 3. SSH hardening
# ---------------------------------------------------------

echo "[+] Hardening SSH..."

cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup" 2>/dev/null || true

# Disable root SSH login
sed -i '/^[#[:space:]]*PermitRootLogin[[:space:]]/d' "$SSHD_CONFIG"
echo "PermitRootLogin no" >> "$SSHD_CONFIG"

# Disable password authentication
sed -i '/^[#[:space:]]*PasswordAuthentication[[:space:]]/d' "$SSHD_CONFIG"
echo "PasswordAuthentication no" >> "$SSHD_CONFIG"

# Enable public key authentication
sed -i '/^[#[:space:]]*PubkeyAuthentication[[:space:]]/d' "$SSHD_CONFIG"
echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"

# Disable empty passwords
sed -i '/^[#[:space:]]*PermitEmptyPasswords[[:space:]]/d' "$SSHD_CONFIG"
echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG"

# Disable X11 forwarding
sed -i '/^[#[:space:]]*X11Forwarding[[:space:]]/d' "$SSHD_CONFIG"
echo "X11Forwarding no" >> "$SSHD_CONFIG"

# Limit authentication attempts
sed -i '/^[#[:space:]]*MaxAuthTries[[:space:]]/d' "$SSHD_CONFIG"
echo "MaxAuthTries 3" >> "$SSHD_CONFIG"

# Reduce login grace time
sed -i '/^[#[:space:]]*LoginGraceTime[[:space:]]/d' "$SSHD_CONFIG"
echo "LoginGraceTime 30" >> "$SSHD_CONFIG"

# Validate SSH configuration
sshd -t

if systemctl list-unit-files | grep -q '^ssh.service'; then
    systemctl restart ssh
elif systemctl list-unit-files | grep -q '^sshd.service'; then
    systemctl restart sshd
fi

# ---------------------------------------------------------
# 4. Password policy
# ---------------------------------------------------------

echo "[+] Configuring password policy..."

sed -i '/^PASS_MAX_DAYS/d' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/d' /etc/login.defs
sed -i '/^PASS_WARN_AGE/d' /etc/login.defs

echo "PASS_MAX_DAYS   90" >> /etc/login.defs
echo "PASS_MIN_DAYS   1" >> /etc/login.defs
echo "PASS_WARN_AGE   7" >> /etc/login.defs

# ---------------------------------------------------------
# 5. Kernel hardening
# ---------------------------------------------------------

echo "[+] Applying kernel hardening..."

cat > "$SYSCTL_FILE" << EOF
# Nexus Financial security baseline

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable SYN cookie protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

sysctl --system >/dev/null

# ---------------------------------------------------------
# 6. Firewall baseline
# ---------------------------------------------------------

echo "[+] Configuring firewall..."

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow 22/tcp

# HTTP
ufw allow 80/tcp

# HTTPS
ufw allow 443/tcp

# PostgreSQL 5432 is intentionally NOT opened publicly

ufw --force enable

# ---------------------------------------------------------
# 7. Fail2ban
# ---------------------------------------------------------

echo "[+] Configuring Fail2ban..."

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------
# 8. Auditd
# ---------------------------------------------------------

echo "[+] Configuring auditd..."

AUDIT_RULES="/etc/audit/rules.d/nexus.rules"

cat > "$AUDIT_RULES" << EOF
# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_changes
EOF

systemctl enable auditd
systemctl restart auditd

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
fi

# ---------------------------------------------------------
# 9. Remove insecure packages
# ---------------------------------------------------------

echo "[+] Removing insecure packages..."

apt-get purge -y \
    telnet \
    rsh-client \
    rsh-redone-client \
    talk \
    2>/dev/null || true

apt-get autoremove -y

# ---------------------------------------------------------
# 10. Disable unnecessary services
# ---------------------------------------------------------

echo "[+] Disabling unnecessary services..."

UNUSED_SERVICES="
telnet
rsh
rlogin
rexec
"

for SERVICE in $UNUSED_SERVICES; do
    if systemctl list-unit-files | grep -q "^${SERVICE}"; then
        systemctl disable --now "$SERVICE" 2>/dev/null || true
    fi
done

# ---------------------------------------------------------
# 11. Automatic security updates
# ---------------------------------------------------------

echo "[+] Enabling automatic security updates..."

cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ---------------------------------------------------------
# 12. Secure sensitive file permissions
# ---------------------------------------------------------

echo "[+] Securing sensitive files..."

chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 640 /etc/shadow
chmod 640 /etc/gshadow

chown root:root /etc/passwd
chown root:root /etc/group
chown root:shadow /etc/shadow
chown root:shadow /etc/gshadow

# ---------------------------------------------------------
# 13. Revoke shared nexus_master.pem key
# ---------------------------------------------------------

echo "[+] Searching for shared nexus_master.pem..."

find /home /root \
    -type f \
    -name "nexus_master.pem" \
    -exec chmod 000 {} \; \
    -exec mv {} {}.revoked \; \
    2>/dev/null || true

# ---------------------------------------------------------
# 14. Final status
# ---------------------------------------------------------

echo
echo "[+] Hardening completed successfully."
echo
echo "----------------------------------------"
echo "Root SSH login: disabled"
echo "SSH password authentication: disabled"
echo "SSH key authentication: enabled"
echo "Password policy: configured"
echo "System packages: updated"
echo "Fail2ban: enabled"
echo "Auditd: enabled"
echo "Firewall: enabled"
echo "Legacy packages: removed"
echo "Automatic updates: enabled"
echo "nexus_master.pem: revoked if found"
echo "----------------------------------------"