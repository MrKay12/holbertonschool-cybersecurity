#!/bin/bash
# 24-backup_config.sh
# Backup all patch management configuration to a timestamped archive

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups"
ARCHIVE_NAME="patch-config-$TIMESTAMP.tar.gz"
ARCHIVE_PATH="$BACKUP_DIR/$ARCHIVE_NAME"

CONFIG_FILES=(
    "/etc/apt/apt.conf.d/20auto-upgrades"
    "/etc/apt/apt.conf.d/50unattended-upgrades"
    "/etc/apt/sources.list"
    "/etc/apt/sources.list.d"
    "/etc/systemd/system/apt-daily.timer.d"
    "/etc/systemd/system/apt-daily-upgrade.timer.d"
    "/var/log/package_holds.log"
)

echo "=== Configuration Backup ==="
echo
echo "Collecting configuration files..."
for f in "${CONFIG_FILES[@]}"; do
    if [ -e "$f" ]; then
        echo "  $f"
    else
        echo "  $f: Not found, skipping"
    fi
done

# Ensure backup directory exists
sudo mkdir -p "$BACKUP_DIR"

echo
echo "Creating archive..."
sudo tar -czf "$ARCHIVE_PATH" "${CONFIG_FILES[@]}" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Failed to create archive"
    exit 1
fi
echo "  $ARCHIVE_PATH"
echo

# List archive contents
FILE_COUNT=$(tar -tzf "$ARCHIVE_PATH" 2>/dev/null | wc -l)
TOTAL_SIZE=$(du -h "$ARCHIVE_PATH" | awk '{print $1}')
echo "Archive contents:"
echo "  $FILE_COUNT files, $TOTAL_SIZE total"
echo

# Compute SHA256
SHA256=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
echo "SHA256: $SHA256"
echo
echo "Backup complete."
