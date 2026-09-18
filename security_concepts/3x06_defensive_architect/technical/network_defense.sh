#!/bin/bash

# Nexus Financial - Network Defense
# Ubuntu 20.04+
# Default Deny network security policy

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Starting Nexus Financial network defense..."

# ---------------------------------------------------------
# 1. Install UFW if necessary
# ---------------------------------------------------------

echo "[+] Checking UFW..."

if ! command -v ufw >/dev/null 2>&1; then
    echo "[+] Installing UFW..."

    apt-get update -y
    apt-get install -y ufw
fi

# ---------------------------------------------------------
# 2. Reset existing firewall configuration
# ---------------------------------------------------------

echo "[+] Resetting existing UFW rules..."

ufw --force reset

# ---------------------------------------------------------
# 3. Default Deny policy
# ---------------------------------------------------------

echo "[+] Applying Default Deny policy..."

ufw default deny incoming
ufw default allow outgoing

# ---------------------------------------------------------
# 4. Block PostgreSQL from the public Internet
# ---------------------------------------------------------

echo "[+] Blocking public PostgreSQL access..."

ufw deny 5432/tcp

# ---------------------------------------------------------
# 5. Allow PostgreSQL only from Web Server
# ---------------------------------------------------------

echo "[+] Allowing PostgreSQL from Web Server..."

# Web Server private IP: 10.0.1.10
ufw allow from 10.0.1.10 to any port 5432 proto tcp

# ---------------------------------------------------------
# 6. Allow SSH only from Bastion Host
# ---------------------------------------------------------

echo "[+] Restricting SSH to Bastion Host..."

# Bastion Host private IP: 10.0.1.20
ufw allow from 10.0.1.20 to any port 22 proto tcp

# ---------------------------------------------------------
# 7. Allow public HTTP traffic
# ---------------------------------------------------------

echo "[+] Allowing HTTP..."

ufw allow 80/tcp

# ---------------------------------------------------------
# 8. Allow public HTTPS traffic
# ---------------------------------------------------------

echo "[+] Allowing HTTPS..."

ufw allow 443/tcp

# ---------------------------------------------------------
# 9. Enable UFW
# ---------------------------------------------------------

echo "[+] Enabling UFW..."

ufw --force enable

# ---------------------------------------------------------
# 10. Display firewall configuration
# ---------------------------------------------------------

echo
echo "[+] Network defense configuration completed."
echo
echo "------------------------------------------"
echo "Default incoming traffic : DENY"
echo "Default outgoing traffic : ALLOW"
echo "PostgreSQL 5432 public   : DENY"
echo "PostgreSQL 5432 allowed  : 10.0.1.10"
echo "SSH 22 allowed           : 10.0.1.20"
echo "HTTP 80                  : ALLOW"
echo "HTTPS 443                : ALLOW"
echo "------------------------------------------"
echo

ufw status verbose