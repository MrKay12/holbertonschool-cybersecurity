#!/bin/bash
# 15-blacklist_packages.sh
# Prevent critical packages from being auto-updated

CONFIG_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"

echo "=== Package Blacklist Configuration ==="
echo -e "\nAdding to Unattended-Upgrade::Package-Blacklist:"

CRITICAL_PACKAGES=(
    "apache2"
    "apache2-bin"
    "mysql-server"
    "mysql-server-*"
    "nginx"
    "docker-ce"
)

# Backup existing configuration
sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d)"

# Add packages to blacklist
for pkg in "${CRITICAL_PACKAGES[@]}"; do
    echo "  + \"$pkg\""
done

# Insert blacklist into unattended-upgrades config
# Remove previous Package-Blacklist section if exists
sudo sed -i '/Unattended-Upgrade::Package-Blacklist {/,/};/d' "$CONFIG_FILE"

# Add new blacklist
sudo tee -a "$CONFIG_FILE" > /dev/null <<EOF

Unattended-Upgrade::Package-Blacklist {
EOF

for pkg in "${CRITICAL_PACKAGES[@]}"; do
    sudo tee -a "$CONFIG_FILE" > /dev/null <<< "    \"$pkg\";"
done

sudo tee -a "$CONFIG_FILE" > /dev/null <<< "};"

echo -e "\nBlacklist written to $CONFIG_FILE"
echo -e "\nThese packages will NOT be automatically upgraded."
echo "Manual review required for security updates."
