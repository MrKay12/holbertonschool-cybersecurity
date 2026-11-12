#!/bin/bash
# 4-restore_apache.sh
# Task: Validate Apache config and restore service

echo "=== Apache Recovery ==="

# 1. Configuration test
echo -e "\nConfiguration test..."
apache2ctl -t

# 2. Start Apache
echo -e "\nStarting Apache service..."
sudo systemctl restart apache2
systemctl is-active apache2

# 3. Health check
echo -e "\nHealth check..."
curl -o /dev/null -s -w "HTTP GET /: %{http_code}\n" http://localhost/

echo -e "\nApache restored successfully."
