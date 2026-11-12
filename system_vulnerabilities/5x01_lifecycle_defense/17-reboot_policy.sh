#!/bin/bash
# 17-reboot_policy.sh
# Configure automatic reboot for kernel updates

echo "=== Automatic Reboot Policy ==="
echo -e "\nConfiguring /etc/apt/apt.conf.d/50unattended-upgrades..."

# Path to unattended-upgrades config
CONFIG_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"

# Ensure the file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found. Make sure unattended-upgrades is installed."
    exit 1
fi

# Backup the config
sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d)"

# Apply reboot policy
sudo sed -i '/^\/\/Unattended-Upgrade::Automatic-Reboot/c\Unattended-Upgrade::Automatic-Reboot "true";' "$CONFIG_FILE"
sudo sed -i '/^\/\/Unattended-Upgrade::Automatic-Reboot-Time/c\Unattended-Upgrade::Automatic-Reboot-Time "04:00";' "$CONFIG_FILE"
sudo sed -i '/^\/\/Unattended-Upgrade::Automatic-Reboot-WithUsers/c\Unattended-Upgrade::Automatic-Reboot-WithUsers "false";' "$CONFIG_FILE"

echo -e "\nReboot settings:"
echo '  Automatic-Reboot: "true"'
echo '  Automatic-Reboot-Time: "04:00"'
echo '  Automatic-Reboot-WithUsers: "false"'

echo -e "\nAdditional safeguards:"
echo "  Reboot only when required (kernel/libc updates)"
echo "  Skip reboot if users are logged in"

echo -e "\nReboot policy configured."
echo "System will auto-reboot at 04:00 when required."
