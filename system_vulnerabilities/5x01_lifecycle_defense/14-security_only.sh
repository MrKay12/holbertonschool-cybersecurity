#!/bin/bash
# 14-security_only.sh
# Configure unattended-upgrades to apply only security updates

CONFIG_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"

echo "=== Security-Only Configuration ==="
echo -e "\nConfiguring $CONFIG_FILE..."

# Backup existing configuration
sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d)"

# Configure Allowed-Origins
sudo tee "$CONFIG_FILE" > /dev/null <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Origins-Pattern {
};
Unattended-Upgrade::Package-Blacklist {
};
EOF

# Disable non-security sources
sudo sed -i '/-updates;/s/^/\/\/ /' "$CONFIG_FILE"
sudo sed -i '/-backports;/s/^/\/\/ /' "$CONFIG_FILE"

# Display configured Allowed-Origins with enabled/disabled
echo -e "\nAllowed-Origins:"
grep -E 'security|updates|backports' "$CONFIG_FILE" | while read -r line; do
    if [[ "$line" == *"security"* ]]; then
        echo "  [ENABLED]  $line"
    else
        echo "  [DISABLED] $line"
    fi
done

echo -e "\nSecurity-only filter applied."
echo "Only security updates will be installed automatically."
