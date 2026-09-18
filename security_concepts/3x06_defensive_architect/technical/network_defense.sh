```bash id="f9t0gc"
#!/bin/bash

# Nexus Financial - Network Defense
# Ubuntu 20.04+

set -e

WEB_SERVER_IP="10.0.1.10"
BASTION_IP="10.0.1.20"
DB_PORT="5432"
SSH_PORT="22"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Configuring UFW network defense..."

# ---------------------------------------------------------
# 1. Install UFW if needed
# ---------------------------------------------------------

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y ufw
fi

# ---------------------------------------------------------
# 2. Reset firewall rules
# ---------------------------------------------------------

ufw --force reset

# ---------------------------------------------------------
# 3. Default deny policy
# ---------------------------------------------------------

ufw default deny incoming
ufw default allow outgoing

# ---------------------------------------------------------
# 4. Block public PostgreSQL access
# ---------------------------------------------------------

echo "[+] Blocking public PostgreSQL access..."

ufw deny 5432/tcp

# ---------------------------------------------------------
# 5. Allow PostgreSQL only from web server
# ---------------------------------------------------------

echo "[+] Allowing PostgreSQL from web server only..."

ufw allow from "$WEB_SERVER_IP" to any port 5432 proto tcp

# ---------------------------------------------------------
# 6. Allow SSH only from bastion host
# ---------------------------------------------------------

echo "[+] Allowing SSH from bastion host only..."

ufw allow from "$BASTION_IP" to any port 22 proto tcp

# ---------------------------------------------------------
# 7. Allow web traffic
# ---------------------------------------------------------

ufw allow 80/tcp
ufw allow 443/tcp

# ---------------------------------------------------------
# 8. Enable firewall
# ---------------------------------------------------------

ufw --force enable

# ---------------------------------------------------------
# 9. Display status
# ---------------------------------------------------------

echo
echo "[+] Network defense configuration completed."
echo
echo "------------------------------------------"
echo "Default incoming policy: DENY"
echo "PostgreSQL public access: BLOCKED"
echo "PostgreSQL allowed from: $WEB_SERVER_IP"
echo "SSH allowed from bastion: $BASTION_IP"
echo "HTTP/HTTPS: ALLOWED"
echo "------------------------------------------"

ufw status verbose
```
