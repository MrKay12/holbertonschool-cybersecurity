#!/bin/bash
# 18-notification_setup.sh
# Configure logging and notifications for unattended-upgrades

CONFIG_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"

echo "=== Notification Configuration ==="

# Ensure the config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found. Make sure unattended-upgrades is installed."
    exit 1
fi

# Backup the config
sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d)"

# Configure email notifications
sudo sed -i '/^\/\/Unattended-Upgrade::Mail/c\Unattended-Upgrade::Mail "root";' "$CONFIG_FILE"
sudo sed -i '/^\/\/Unattended-Upgrade::MailOnlyOnError/c\Unattended-Upgrade::MailOnlyOnError "false";' "$CONFIG_FILE"
sudo sed -i '/^\/\/Unattended-Upgrade::MailReport/c\Unattended-Upgrade::MailReport "on-change";' "$CONFIG_FILE"

# Configure logging to syslog
sudo sed -i '/^\/\/Unattended-Upgrade::SyslogEnable/c\Unattended-Upgrade::SyslogEnable "true";' "$CONFIG_FILE"
sudo sed -i '/^\/\/Unattended-Upgrade::SyslogFacility/c\Unattended-Upgrade::SyslogFacility "daemon";' "$CONFIG_FILE"

echo -e "\nEmail settings:"
echo '  Mail::OnlyOnError: "false"'
echo '  Mail::Report: "on-change"'
echo '  Recipient: root (local delivery)'

echo -e "\nLogging settings:"
echo '  Syslog::Enable: "true"'
echo '  Syslog::Facility: "daemon"'

echo -e "\nLog locations:"
echo '  /var/log/unattended-upgrades/unattended-upgrades.log'
echo '  /var/log/unattended-upgrades/unattended-upgrades-dpkg.log'

echo -e "\nNotification system configured."
echo "All update activity will be logged and reported."
