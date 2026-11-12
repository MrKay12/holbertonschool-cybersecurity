#!/bin/bash
# 13-setup_unattended.sh
# Configure automatic security updates via APT and systemd

echo "=== Unattended Upgrades Setup ==="

# Ensure unattended-upgrades package is installed
sudo apt-get update
sudo apt-get install -y unattended-upgrades

# Enable automatic updates in 20auto-upgrades
AUTO_UPGRADES="/etc/apt/apt.conf.d/20auto-upgrades"

echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee "$AUTO_UPGRADES" > /dev/null
echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a "$AUTO_UPGRADES" > /dev/null

echo "Configured $AUTO_UPGRADES:"
cat "$AUTO_UPGRADES"

# Enable systemd timers
sudo systemctl enable --now apt-daily.timer
sudo systemctl enable --now apt-daily-upgrade.timer

# Verify the timers are active
echo -e "\nSystemd timers status:"
systemctl list-timers | grep apt-daily

echo -e "\nUnattended upgrades setup complete."
