#!/bin/bash
# 16-maintenance_window.sh
# Configure APT automatic updates to run during low-traffic hours

echo "=== Maintenance Window Configuration ==="
echo -e "\nConfiguring systemd timer overrides..."

# Directory for overrides
OVERRIDE_DIR="/etc/systemd/system"

# apt-daily.timer override
sudo mkdir -p "$OVERRIDE_DIR/apt-daily.timer.d"
sudo tee "$OVERRIDE_DIR/apt-daily.timer.d/override.conf" > /dev/null <<EOF
[Timer]
OnCalendar=*-*-* 02:00
RandomizedDelaySec=30min
EOF

echo -e "\napt-daily.timer:"
echo "  OnCalendar: *-*-* 02:00"
echo "  RandomizedDelaySec: 30min"

# apt-daily-upgrade.timer override
sudo mkdir -p "$OVERRIDE_DIR/apt-daily-upgrade.timer.d"
sudo tee "$OVERRIDE_DIR/apt-daily-upgrade.timer.d/override.conf" > /dev/null <<EOF
[Timer]
OnCalendar=*-*-* 03:00
RandomizedDelaySec=60min
EOF

echo -e "\napt-daily-upgrade.timer:"
echo "  OnCalendar: *-*-* 03:00"
echo "  RandomizedDelaySec: 60min"

echo -e "\nTimer configuration:"
echo "  Package list update: 02:00-02:30"
echo "  Package installation: 03:00-04:00"

# Reload systemd to apply changes
sudo systemctl daemon-reload

echo -e "\nReloading systemd..."
echo "Maintenance window configured."
