#!/bin/bash
# 11-restrict_nettools.sh
# Restrict network tools to root only (root:root, mode 0750).

TOOLS="/usr/bin/nc /usr/bin/netcat /usr/bin/ncat /usr/bin/nmap /usr/sbin/tcpdump /usr/bin/tcpdump /usr/bin/socat /usr/bin/tshark"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

echo "=== Network Tools Restriction ==="
echo
echo "Restricting access (root only)..."

DONE=""
FOUND=""
for t in $TOOLS; do
    [ -e "$t" ] || continue
    FOUND="$FOUND $t"
    real=$(readlink -f "$t")    # follow alternatives symlinks (nc -> nc.openbsd)
    case " $DONE " in *" $real "*) echo "  $t: 0750 (same binary as above)"; continue ;; esac
    old=$(stat -c '%04a' "$real")
    chown root:root "$real"
    chmod 0750 "$real"
    echo "  $t: $(stat -c '%04a' "$real") (was $old)"
    DONE="$DONE $real"
done

if [ -z "$FOUND" ]; then
    echo "  No network tools found."
    exit 0
fi

echo
echo "Verification:"
OK=1
for t in $FOUND; do
    perms=$(stat -L -c '%A %U %G' "$t")
    echo "  $(basename "$t"): $perms"
    [ "$perms" = "-rwxr-x--- root root" ] || OK=0
done

echo
if [ "$OK" -eq 1 ]; then
    echo "Network tools restricted to root."
    echo "Regular users can no longer execute these binaries."
else
    echo "Some tools are still accessible to regular users."
    exit 1
fi
