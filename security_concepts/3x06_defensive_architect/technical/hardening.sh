```bash
#!/bin/bash

# Nexus Financial - System Hardening Script
# Ubuntu 20.04+
# Purpose:
# Apply a secure baseline to Nexus Financial Linux servers.

set -e

SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_FILE="/etc/sysctl.d/99-nexus-hardening.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Starting Nexus Financial system hardening..."

# ---------------------------------------------------------
# 1. System update
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
    ufw \
    fail2ban \
    auditd \
    audispd-plugins \
    unattended-upgrades

# ---------------------------------------------------------
# 3. SSH hardening
# ---------------------------------------------------------

echo "[+] Hardening SSH..."

cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup" 2>/dev/null || true

set_ssh_option()
{
    OPTION="$1"
    VALUE="$2"

    if grep -Eq "^[#[:space:]]*${OPTION}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i -E \
            "s|^[#[:space:]]*${OPTION}[[:space:]].*|${OPTION} ${VALUE}|" \
            "$SSHD_CONFIG"
    else
        echo "${OPTION} ${VALUE}" >> "$SSHD_CONFIG"
    fi
}

set_ssh_option "PermitRootLogin" "no"
set_ssh_option "PasswordAuthentication" "no"
set_ssh_option "PubkeyAuthentication" "yes"
set_ssh_option "PermitEmptyPasswords" "no"
set_ssh_option "X11Forwarding" "no"
set_ssh_option "MaxAuthTries" "3"
set_ssh_option "LoginGraceTime" "30"

sshd -t

systemctl restart ssh

# ---------------------------------------------------------
# 4. Password policy
# ---------------------------------------------------------

echo "[+] Configuring password policy..."

if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
else
    echo "PASS_MAX_DAYS   90" >> /etc/login.defs
fi

if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
else
    echo "PASS_MIN_DAYS   1" >> /etc/login.defs
fi

if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
else
    echo "PASS_WARN_AGE   7" >> /etc/login.defs
fi

# ---------------------------------------------------------
# 5. Kernel hardening
# ---------------------------------------------------------

echo "[+] Applying kernel hardening..."

cat > "$SYSCTL_FILE" << EOF
# Nexus Financial security baseline

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

sysctl --system >/dev/null

# ---------------------------------------------------------
# 6. Firewall
# ---------------------------------------------------------

echo "[+] Configuring UFW firewall..."

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow 22/tcp

# HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# PostgreSQL is deliberately NOT exposed publicly.
# Access should later be limited to an internal/VPN subnet.

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

echo "[+] Enabling audit logging..."

systemctl enable auditd
systemctl restart auditd

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

augenrules --load

# ---------------------------------------------------------
# 9. Disable unused services
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
# 10. Remove insecure packages
# ---------------------------------------------------------

echo "[+] Removing insecure legacy packages..."

apt-get purge -y \
    telnet \
    rsh-client \
    rsh-redone-client \
    2>/dev/null || true

apt-get autoremove -y

# ---------------------------------------------------------
# 11. Automatic security updates
# ---------------------------------------------------------

echo "[+] Enabling automatic security updates..."

dpkg-reconfigure -f noninteractive unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ---------------------------------------------------------
# 12. File permissions
# ---------------------------------------------------------

echo "[+] Securing sensitive system files..."

chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 640 /etc/shadow
chmod 640 /etc/gshadow

chown root:root /etc/passwd
chown root:root /etc/group
chown root:shadow /etc/shadow
chown root:shadow /etc/gshadow

# ---------------------------------------------------------
# 13. Remove shared Nexus SSH key if found
# ---------------------------------------------------------

echo "[+] Searching for deprecated nexus_master.pem..."

find /home /root \
    -type f \
    -name "nexus_master.pem" \
    -exec chmod 000 {} \; \
    -exec mv {} {}.revoked \; \
    2>/dev/null || true

# ---------------------------------------------------------
# 14. Final checks
# ---------------------------------------------------------

echo
echo "[+] Hardening complete."
echo
echo "Status:"
echo "----------------------------------------"
echo "SSH root login: disabled"
echo "SSH password login: disabled"
echo "Firewall: enabled"
echo "Fail2ban: enabled"
echo "Auditd: enabled"
echo "Automatic updates: enabled"
echo "PostgreSQL public exposure: not allowed"
echo "Shared nexus_master.pem: revoked if found"
echo "----------------------------------------"
```
