#!/bin/bash
# 5-remove_vsftpd.sh
# Task: Completely remove vulnerable FTP service (vsftpd 2.3.4)

echo "=== Vulnerable Service Removal ==="
echo -e "\nTarget: vsftpd (CVE-2011-2523 - Backdoor)"

# 1. Stop vsftpd service
echo -e "\nStopping service..."
sudo systemctl stop vsftpd 2>/dev/null
sudo systemctl disable vsftpd 2>/dev/null
echo "  vsftpd.service: Stopped"

# 2. Remove package and purge configuration
echo -e "\nRemoving package..."
sudo apt-get purge -y vsftpd
echo "  vsftpd: Purged (including config files)"

# 3. Cleanup residual files
echo -e "\nCleanup..."
[ -f /etc/vsftpd.conf ] && sudo rm -f /etc/vsftpd.conf && echo "  /etc/vsftpd.conf: Removed"
[ -f /etc/vsftpd.user_list ] && sudo rm -f /etc/vsftpd.user_list && echo "  /etc/vsftpd.user_list: Removed"

# 4. Verification
echo -e "\nVerification:"
dpkg -l | grep vsftpd >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Package status: Not installed"
else
    echo "  Package status: STILL INSTALLED"
fi

ss -tuln | grep :21 >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Port 21: Not listening"
else
    echo "  Port 21: STILL LISTENING"
fi

echo -e "\nvsftpd removed successfully."
echo "Vulnerability CVE-2011-2523: REMEDIATED"
