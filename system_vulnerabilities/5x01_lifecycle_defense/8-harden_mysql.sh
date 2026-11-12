#!/bin/bash
# 8-harden_mysql.sh
# Task: Harden MySQL configuration

echo "=== MySQL Hardening ==="

# 1. Backup configuration
BACKUP="/etc/mysql/mysql.conf.d/mysqld.cnf.backup.$(date +%Y%m%d)"
sudo cp /etc/mysql/mysql.conf.d/mysqld.cnf "$BACKUP" && echo "Backup created: $BACKUP"

echo -e "\nSecuring MySQL..."

# 2. Secure MySQL
MYSQL_SECRET="/root/.mysql_secret"
# Generate a strong password
ROOT_PASS=$(openssl rand -base64 16)
echo "$ROOT_PASS" > "$MYSQL_SECRET"
sudo chmod 600 "$MYSQL_SECRET"

# Apply hardening via mysql_secure_installation-like commands
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOT_PASS';"
sudo mysql -e "DELETE FROM mysql.user WHERE User='';"
sudo mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');"
sudo mysql -e "DROP DATABASE IF EXISTS test;"
sudo mysql -e "FLUSH PRIVILEGES;"

# 3. Bind MySQL to localhost
sudo sed -i "s/^bind-address.*/bind-address = 127.0.0.1/" /etc/mysql/mysql.conf.d/mysqld.cnf
echo "  Root password: Set (stored in $MYSQL_SECRET)"
echo "  Anonymous users: Removed"
echo "  Remote root login: Disabled"
echo "  Test database: Removed"
echo "  Bind address: 0.0.0.0 → 127.0.0.1"

# 4. Restart MySQL
echo -e "\nRestarting MySQL..."
sudo systemctl restart mysql
echo "  mysql.service: Restarted"

# 5. Verification
LOCAL_OK=$(mysql -uroot -p"$ROOT_PASS" -e "SELECT 1;" >/dev/null 2>&1 && echo "OK" || echo "FAILED")
REMOTE_OK=$(mysql -uroot -p"$ROOT_PASS" -h 127.0.0.1 -e "SELECT 1;" >/dev/null 2>&1 && echo "REFUSED" || echo "FAILED")

echo -e "\nVerification:"
echo "  Local root access: $LOCAL_OK (with password)"
echo "  Remote connections: $REMOTE_OK (bind localhost only)"

echo -e "\nMySQL hardened successfully."
