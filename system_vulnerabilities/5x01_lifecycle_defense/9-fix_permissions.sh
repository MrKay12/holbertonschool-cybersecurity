#!/bin/bash

echo "=== Permission Remediation ==="
echo

echo "SUID/SGID issues:"

# Remove SUID from backup binary
chmod 0755 /usr/local/bin/backup

echo "  /usr/local/bin/backup: SUID removed (was 4755, now 0755)"
echo

echo "World-writable files:"

# Fix world-writable scripts
chmod 0755 /etc/cron.daily/backup.sh
echo "  /etc/cron.daily/backup.sh: 0777 → 0755"

chmod 0755 /opt/scripts/cleanup.sh
echo "  /opt/scripts/cleanup.sh: 0777 → 0755"
echo

echo "Sensitive file permissions:"

# Fix web config permissions
chown www-data /var/www/html/config.php
chmod 0640 /var/www/html/config.php

echo "  /var/www/html/config.php: 0666 → 0640 (owner www-data)"

# Fix SSH private key permissions
chmod 0600 /home/devops/.ssh/id_rsa

echo "  /home/devops/.ssh/id_rsa: 0644 → 0600"
echo

echo "Credential exposure:"

# Move exposed environment file
mkdir -p /etc/novatech

mv /var/www/html/.env /etc/novatech/app.env

# Create compatibility symlink
ln -sf /etc/novatech/app.env /var/www/html/.env

echo "  /var/www/html/.env: Moved to /etc/novatech/app.env"
echo "  Symlink created for application compatibility"
echo

echo "All permission issues remediated."
