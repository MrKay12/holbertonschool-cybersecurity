#!/bin/bash
# 10-configure_fail2ban.sh
# Install fail2ban and ban IPs with 5 failed SSH logins in 10 minutes for
# 1 hour. Complements pam_faillock (per account) with per-IP banning.
#
# - Localhost and the admin's current SSH client IP are never banned.
# - If /var/log/auth.log does not exist (journald-only systems), the jail
#   reads the systemd journal instead (backend = systemd).

lock_files="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== fail2ban Configuration ==="
echo

# ---- apt/dpkg preparation (same as 2-password_complexity.sh) ---------------
pkg_busy() {
    pgrep -x 'apt|apt-get|aptitude|dpkg|unattended-upgr' >/dev/null && return 0
    fuser $lock_files >/dev/null 2>&1 && return 0
    return 1
}
prepare_apt() {
    local i l
    for i in $(seq 1 60); do
        pkg_busy || break
        [ "$i" -eq 1 ] && echo "  Waiting for running apt/dpkg to finish..."
        sleep 5
    done
    if pkg_busy; then
        echo "  Error: apt/dpkg still running after 5 minutes, aborting" >&2
        exit 1
    fi
    for l in $lock_files; do [ -e "$l" ] && rm -f "$l"; done
    [ -n "$(dpkg --audit 2>/dev/null)" ] && dpkg --configure -a >/dev/null 2>&1
    if ! apt-get check >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y -qq >/dev/null 2>&1
    fi
    if [ -n "$(dpkg --audit 2>/dev/null)" ] || ! apt-get check >/dev/null 2>&1; then
        echo "  Error: broken packages remain (see: dpkg --audit; apt-get check)" >&2
        exit 1
    fi
}

# ---- 1. Install ------------------------------------------------------------
echo "Installing fail2ban..."
if dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -q "ok installed"; then
    echo "  fail2ban: Already installed"
else
    prepare_apt
    if DEBIAN_FRONTEND=noninteractive apt install -y fail2ban >/dev/null 2>&1; then
        echo "  fail2ban: Installed"
    else
        echo "  Error: failed to install fail2ban" >&2
        exit 1
    fi
fi
echo

# ---- 2. jail.local ---------------------------------------------------------
# jail.local overrides jail.conf and survives package upgrades
echo "Creating /etc/fail2ban/jail.local..."
[ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak

# Never ban localhost or the IP this admin session comes from
admin_ip=$(who -m 2>/dev/null | sed -nE 's/.*\(([0-9a-fA-F.:]+)\).*/\1/p')
# keep only a real IPv4/IPv6 address (not a local display such as ":0")
echo "$admin_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F:]*$' \
    || admin_ip=""
ignoreip="127.0.0.1/8 ::1${admin_ip:+ $admin_ip}"

if [ -f /var/log/auth.log ]; then
    logsrc="logpath = /var/log/auth.log"
else
    logsrc="backend = systemd"
fi

cat > /etc/fail2ban/jail.local <<EOF
# Managed by 10-configure_fail2ban.sh
[DEFAULT]
ignoreip = $ignoreip

[sshd]
enabled = true
port = ssh
filter = sshd
$logsrc
maxretry = 5
findtime = 600
bantime = 3600
EOF
chmod 644 /etc/fail2ban/jail.local

echo
echo "[sshd] configuration:"
echo "  enabled = true"
echo "  port = ssh"
echo "  filter = sshd"
echo "  $logsrc"
echo "  maxretry = 5"
echo "  findtime = 600 (10 minutes)"
echo "  bantime = 3600 (1 hour)"
[ -n "$admin_ip" ] && echo "  ignoreip includes your SSH client: $admin_ip"
echo

# Validate before (re)starting: a bad config would leave fail2ban down
if ! fail2ban-client -t >/dev/null 2>&1; then
    echo "Error: invalid fail2ban configuration (fail2ban-client -t)" >&2
    [ -f /etc/fail2ban/jail.local.bak ] && cp /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
    exit 1
fi

# ---- 3. Service ------------------------------------------------------------
echo "Starting fail2ban..."
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
# Wait for the server socket and the sshd jail to come up
for i in $(seq 1 15); do
    fail2ban-client status sshd >/dev/null 2>&1 && break
    sleep 1
done
if systemctl is-active --quiet fail2ban; then
    echo "  fail2ban.service: Active"
else
    echo "  fail2ban.service: FAILED (journalctl -u fail2ban)" >&2
    exit 1
fi
echo

# ---- 4. Status -------------------------------------------------------------
status=$(fail2ban-client status sshd 2>/dev/null)
if [ -z "$status" ]; then
    echo "Error: sshd jail not running (fail2ban-client status sshd)" >&2
    exit 1
fi
current=$(echo "$status" | awk -F: '/Currently banned/ {gsub(/[[:space:]]/, "", $2); print $2}')
total=$(echo "$status" | awk -F: '/Total banned/ {gsub(/[[:space:]]/, "", $2); print $2}')
echo "Current status:"
echo "  Jail: sshd"
echo "  Currently banned: ${current:-0}"
echo "  Total banned: ${total:-0}"
echo

echo "fail2ban: ACTIVE"
echo "IP addresses with 5+ failures in 10 min will be banned for 1 hour."
