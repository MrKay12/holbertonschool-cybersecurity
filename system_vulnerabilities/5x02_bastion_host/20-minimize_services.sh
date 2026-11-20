#!/bin/bash
# 20-minimize_services.sh
# Identify and disable services a web server does not need.
# Essential services (SSH + web server) are left untouched.

# "unit|label|reason"
UNNEEDED="cups.service|Printing|Not needed on web server
cups-browsed.service|Printer discovery|Not needed on web server
avahi-daemon.service|mDNS|Not needed on web server
bluetooth.service|Bluetooth|Not needed on server
ModemManager.service|Modem|Not needed on server
rpcbind.service|RPC|Not needed on web server
nfs-server.service|NFS|Not needed on web server
smbd.service|Samba|Not needed on web server
nmbd.service|NetBIOS|Not needed on web server
vsftpd.service|FTP|Insecure, not needed
xinetd.service|Legacy inetd|Insecure, not needed
snmpd.service|SNMP|Not needed on web server
isc-dhcp-server.service|DHCP server|Not needed on web server"

ESSENTIAL="sshd.service apache2.service nginx.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

# exists UNIT: true if the unit file is installed
exists() {
    systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q .
}

echo "=== Service Minimization ==="
echo
echo "Checking for unnecessary services..."
echo

FOUND=""
echo "Unnecessary services found:"
while IFS='|' read -r unit label reason; do
    exists "$unit" || continue
    # Skip units already disabled and stopped
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null && ! systemctl is-active --quiet "$unit"; then
        continue
    fi
    echo "  $unit ($label) - $reason"
    FOUND="$FOUND $unit"
done <<< "$UNNEEDED"
[ -z "$FOUND" ] && echo "  None"

if [ -n "$FOUND" ]; then
    echo
    echo "Disabling services..."
    for unit in $FOUND; do
        # Socket units would restart the service on demand
        sock="${unit%.service}.socket"
        exists "$sock" && systemctl disable --now "$sock" >/dev/null 2>&1
        if systemctl disable --now "$unit" >/dev/null 2>&1; then
            echo "  $unit: Disabled and stopped"
        else
            echo "  $unit: FAILED to disable"
        fi
    done
fi

echo
echo "Essential services preserved:"
for unit in $ESSENTIAL; do
    exists "$unit" || continue
    if systemctl is-active --quiet "$unit"; then
        echo "  $unit: Running ✓"
    else
        echo "  $unit: Not running ✗"
    fi
done

echo
echo "Services reduced. Attack surface minimized."
