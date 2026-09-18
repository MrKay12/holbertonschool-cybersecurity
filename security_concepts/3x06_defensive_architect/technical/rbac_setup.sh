#!/bin/bash

# Nexus Financial - RBAC Setup
# Ubuntu 20.04+

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Configuring RBAC..."

# ---------------------------------------------------------
# 1. Create groups
# ---------------------------------------------------------

echo "[+] Creating groups..."

if ! getent group devs >/dev/null 2>&1; then
    groupadd devs
fi

if ! getent group ops >/dev/null 2>&1; then
    groupadd ops
fi

if ! getent group auditors >/dev/null 2>&1; then
    groupadd auditors
fi

# ---------------------------------------------------------
# 2. Create dummy users
# ---------------------------------------------------------

echo "[+] Creating users..."

if ! id sarah >/dev/null 2>&1; then
    useradd -m -s /bin/bash sarah
fi

if ! id dave >/dev/null 2>&1; then
    useradd -m -s /bin/bash dave
fi

if ! id auditor >/dev/null 2>&1; then
    useradd -m -s /bin/bash auditor
fi

# ---------------------------------------------------------
# 3. Assign users to groups
# ---------------------------------------------------------

echo "[+] Assigning users to groups..."

usermod -aG devs,ops sarah
usermod -aG devs,auditors dave
usermod -aG auditors auditor

# ---------------------------------------------------------
# 4. Configure sudoers
# ---------------------------------------------------------

echo "[+] Configuring sudoers..."

SUDOERS_FILE="/etc/sudoers.d/nexus-rbac"

cat > "$SUDOERS_FILE" << EOF
# Nexus Financial RBAC Policy

# OPS can manage nginx without full root access
%ops ALL=(root) /bin/systemctl restart nginx
%ops ALL=(root) /bin/systemctl start nginx
%ops ALL=(root) /bin/systemctl stop nginx
%ops ALL=(root) /bin/systemctl status nginx
EOF

chmod 440 "$SUDOERS_FILE"

if ! visudo -cf "$SUDOERS_FILE"; then
    echo "Error: invalid sudoers configuration."
    rm -f "$SUDOERS_FILE"
    exit 1
fi

# ---------------------------------------------------------
# 5. Protect nginx configuration
# ---------------------------------------------------------

echo "[+] Protecting nginx configuration..."

if [ -d /etc/nginx ]; then
    chown -R root:root /etc/nginx
    find /etc/nginx -type d -exec chmod 755 {} \;
    find /etc/nginx -type f -exec chmod 644 {} \;
fi

# ---------------------------------------------------------
# 6. Read-only log access for auditors
# ---------------------------------------------------------

echo "[+] Configuring nginx log access..."

if [ -d /var/log/nginx ]; then
    chown -R root:auditors /var/log/nginx
    find /var/log/nginx -type d -exec chmod 750 {} \;
    find /var/log/nginx -type f -exec chmod 640 {} \;
fi

# ---------------------------------------------------------
# 7. Secure home directories
# ---------------------------------------------------------

echo "[+] Securing home directories..."

if [ -d /home/sarah ]; then
    chown sarah:sarah /home/sarah
    chmod 700 /home/sarah
fi

if [ -d /home/dave ]; then
    chown dave:dave /home/dave
    chmod 700 /home/dave
fi

if [ -d /home/auditor ]; then
    chown auditor:auditor /home/auditor
    chmod 700 /home/auditor
fi

# ---------------------------------------------------------
# 8. Remove unrestricted sudo access
# ---------------------------------------------------------

echo "[+] Removing unrestricted sudo access..."

if id -nG sarah | grep -qw sudo; then
    gpasswd -d sarah sudo || true
fi

if id -nG dave | grep -qw sudo; then
    gpasswd -d dave sudo || true
fi

if id -nG auditor | grep -qw sudo; then
    gpasswd -d auditor sudo || true
fi

# ---------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------

echo
echo "[+] RBAC configuration completed."
echo
echo "Groups created:"
echo "  devs"
echo "  ops"
echo "  auditors"
echo
echo "Users:"
echo "  sarah   -> devs, ops"
echo "  dave    -> devs, auditors"
echo "  auditor -> auditors"
echo
echo "Permissions:"
echo "  ops      -> nginx service management through sudo"
echo "  auditors -> read-only nginx logs"
echo "  homes    -> chmod 700"