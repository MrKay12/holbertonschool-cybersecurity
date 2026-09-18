```bash
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

for group in devs ops auditors; do
    if ! getent group "$group" >/dev/null 2>&1; then
        groupadd "$group"
        echo "[+] Group created: $group"
    else
        echo "[=] Group already exists: $group"
    fi
done

# ---------------------------------------------------------
# 2. Create dummy users
# ---------------------------------------------------------

echo "[+] Creating users..."

create_user()
{
    USERNAME="$1"

    if ! id "$USERNAME" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$USERNAME"
        echo "[+] User created: $USERNAME"
    else
        echo "[=] User already exists: $USERNAME"
    fi
}

create_user "sarah"
create_user "dave"
create_user "auditor"

# ---------------------------------------------------------
# 3. Assign users to RBAC groups
# ---------------------------------------------------------

echo "[+] Assigning users to groups..."

# Sarah: developer + operations
usermod -aG devs,ops sarah

# Dave: developer + read-only audit access
usermod -aG devs,auditors dave

# Auditor: audit access only
usermod -aG auditors auditor

# ---------------------------------------------------------
# 4. Configure sudo permissions
# ---------------------------------------------------------

echo "[+] Configuring sudoers..."

SUDOERS_FILE="/etc/sudoers.d/nexus-rbac"

cat > "$SUDOERS_FILE" << EOF
# Nexus Financial RBAC Policy

# OPS members may restart and check Nginx
%ops ALL=(root) /bin/systemctl restart nginx
%ops ALL=(root) /bin/systemctl start nginx
%ops ALL=(root) /bin/systemctl stop nginx
%ops ALL=(root) /bin/systemctl status nginx

# Developers have no unrestricted root access
# Auditors have no sudo permissions
EOF

chmod 440 "$SUDOERS_FILE"

# Validate sudoers configuration
if ! visudo -cf "$SUDOERS_FILE"; then
    echo "Error: invalid sudoers configuration."
    rm -f "$SUDOERS_FILE"
    exit 1
fi

# ---------------------------------------------------------
# 5. Protect Nginx configuration
# ---------------------------------------------------------

echo "[+] Protecting Nginx configuration..."

if [ -d /etc/nginx ]; then
    chown -R root:root /etc/nginx

    find /etc/nginx -type d -exec chmod 755 {} \;
    find /etc/nginx -type f -exec chmod 644 {} \;

    echo "[+] Nginx configuration protected."
fi

# ---------------------------------------------------------
# 6. Configure read-only access to Nginx logs
# ---------------------------------------------------------

echo "[+] Configuring log access..."

if [ -d /var/log/nginx ]; then

    # Root owns the files, auditors may read them
    chown -R root:auditors /var/log/nginx

    # Directories: auditors can enter/read
    find /var/log/nginx -type d -exec chmod 750 {} \;

    # Files: root read/write, auditors read only
    find /var/log/nginx -type f -exec chmod 640 {} \;

    echo "[+] Auditors now have read-only access to Nginx logs."
fi

# ---------------------------------------------------------
# 7. Secure home directories
# ---------------------------------------------------------

echo "[+] Securing home directories..."

for user in sarah dave auditor; do

    HOME_DIR=$(getent passwd "$user" | cut -d: -f6)

    if [ -d "$HOME_DIR" ]; then
        chown "$user:$user" "$HOME_DIR"
        chmod 700 "$HOME_DIR"

        echo "[+] Secured: $HOME_DIR"
    fi
done

# ---------------------------------------------------------
# 8. Remove dangerous sudo access
# ---------------------------------------------------------

echo "[+] Removing users from unrestricted sudo groups..."

for user in sarah dave auditor; do

    if id -nG "$user" | grep -qw sudo; then
        gpasswd -d "$user" sudo || true
    fi

    if id -nG "$user" | grep -qw admin; then
        gpasswd -d "$user" admin || true
    fi

done

# ---------------------------------------------------------
# 9. Final summary
# ---------------------------------------------------------

echo
echo "[+] RBAC configuration completed."
echo
echo "------------------------------------------"
echo "Groups:"
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
echo "  Sarah:"
echo "    - Can restart/start/stop/status Nginx"
echo "    - No unrestricted root access"
echo
echo "  Dave:"
echo "    - Can read Nginx logs"
echo "    - Cannot modify Nginx configuration"
echo "    - No sudo access"
echo
echo "  Auditor:"
echo "    - Can read Nginx logs"
echo "    - No sudo access"
echo
echo "Home directories:"
echo "  chmod 700"
echo "------------------------------------------"
```
