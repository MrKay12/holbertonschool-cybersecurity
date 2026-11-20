#!/bin/bash
# 19-verify_filesystem.sh
# Prove that /tmp, /var/tmp and /dev/shm block execution and SUID.

PASS=1

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

# test_exec FILE: try to run FILE; it must be blocked
test_exec() {
    printf "  Attempting execution... "
    if "$1" >/dev/null 2>&1; then
        echo "ALLOWED ✗"
        PASS=0
    else
        echo "BLOCKED ✓"
    fi
}

# test_dir DIR TYPE: create a test script or binary in DIR and try to run it
test_dir() {
    f="$1/.fs_test_$$"
    echo "Testing $1 restrictions:"
    if [ "$2" = "binary" ]; then
        printf "  Creating test binary... "
        cp /bin/true "$f"
    else
        printf "  Creating test script... "
        printf '#!/bin/sh\nexit 0\n' > "$f"
    fi
    chmod 755 "$f" && echo "Done"
    test_exec "$f"

    if [ "$1" = "/tmp" ]; then
        # Root-owned SUID copy of id, run as 'nobody': euid must not be 0
        printf "  Testing SUID... "
        s="$1/.suid_test_$$"
        cp /usr/bin/id "$s"
        chmod 4755 "$s"
        EUID_OUT=$(su -s /bin/sh nobody -c "$s -u" 2>/dev/null)
        if [ "$EUID_OUT" = "0" ]; then
            echo "ACTIVE ✗"
            PASS=0
        else
            echo "IGNORED ✓"
        fi
        rm -f "$s"
    fi

    printf "  Cleanup... "
    rm -f "$f" && echo "Done"
    echo
}

echo "=== Filesystem Hardening Verification ==="
echo
test_dir /tmp script
test_dir /var/tmp script
test_dir /dev/shm binary

echo "Mount options verified:"
for m in /tmp /var/tmp /dev/shm; do
    o=$(findmnt -n -o OPTIONS -T "$m")
    if echo "$o" | grep -qw noexec && echo "$o" | grep -qw nosuid && echo "$o" | grep -qw nodev; then
        echo "  $m: noexec,nosuid,nodev ✓"
    else
        MISS=""
        for opt in noexec nosuid nodev; do
            echo "$o" | grep -qw "$opt" || MISS="$MISS $opt"
        done
        echo "  $m: missing$MISS ✗"
        PASS=0
    fi
done

echo
if [ "$PASS" -eq 1 ]; then
    echo "All filesystem restrictions: ACTIVE"
else
    echo "Filesystem restrictions: INCOMPLETE"
    exit 1
fi
