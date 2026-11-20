#!/bin/bash
# 10-remove_compilers.sh
# Remove development tools. If removing a package would also remove
# other (non development) packages, restrict its binaries to root instead.

PKGS="gcc g++ make"
# Packages that may be removed together with the compilers
DEV_RE='^(gcc|g\+\+|cpp|make|build-essential|dpkg-dev|libc6-dev|libc-dev-bin|linux-libc-dev|lib.*-dev|.*-(gcc|g\+\+|cpp)(-[0-9.]+)?|gcc-[0-9.]+.*|g\+\+-[0-9.]+.*|cpp-[0-9.]+.*)$'

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# Binaries related to a package (the command and its versioned variants)
binaries() {
    case "$1" in
        gcc) ls /usr/bin/gcc /usr/bin/cc /usr/bin/gcc-[0-9]* /usr/bin/*-linux-gnu-gcc* 2>/dev/null ;;
        g++) ls /usr/bin/g++ /usr/bin/c++ /usr/bin/g++-[0-9]* /usr/bin/*-linux-gnu-g++* 2>/dev/null ;;
        make) ls /usr/bin/make 2>/dev/null ;;
    esac
}

REMOVE=""
RESTRICT=""

echo "=== Development Tools Removal ==="
echo
echo "Checking dependencies before removal..."
for p in $PKGS; do
    if ! is_installed "$p"; then
        echo "  $p: Not installed"
        continue
    fi
    # Simulate the removal and list packages that are not dev tools
    OTHERS=$(apt-get -s remove "$p" 2>/dev/null | awk '/^Remv/ {print $2}' | grep -Ev "$DEV_RE")
    if [ -z "$OTHERS" ]; then
        echo "  $p: Can be safely removed"
        REMOVE="$REMOVE $p"
    else
        echo "  $p: Required by $(echo "$OTHERS" | head -3 | tr '\n' ' ')- will restrict instead"
        RESTRICT="$RESTRICT $p"
    fi
done

if [ -n "$REMOVE" ]; then
    echo
    echo "Removing packages..."
    for p in $REMOVE; do
        if DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p" >/dev/null 2>&1; then
            echo "  $p: Removed"
        else
            echo "  $p: Removal failed - will restrict instead"
            RESTRICT="$RESTRICT $p"
        fi
    done

    echo
    echo "Cleanup..."
    echo "  Removing orphaned dependencies..."
    AUTO=$(apt-get -s autoremove 2>/dev/null | grep -c '^Remv')
    DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y >/dev/null 2>&1
    echo "  $AUTO packages auto-removed"
fi

if [ -n "$RESTRICT" ]; then
    echo
    echo "Restricting access to root only..."
    for p in $RESTRICT; do
        for b in $(binaries "$p"); do
            real=$(readlink -f "$b")
            chown root:root "$real"
            chmod 0700 "$real"
        done
        echo "  $p: Restricted (root only)"
    done
fi

echo
echo "Verification:"
OK=1
for p in $PKGS; do
    BIN=$(binaries "$p" | head -1)
    if [ -z "$BIN" ]; then
        echo "  $p: Not found"
    elif [ "$(stat -c '%a %U' "$(readlink -f "$BIN")")" = "700 root" ]; then
        echo "  $p: Restricted (root only)"
    else
        echo "  $p: Still accessible"
        OK=0
    fi
done

echo
if [ "$OK" -eq 1 ] && [ -z "$RESTRICT" ]; then
    echo "Compilers removed successfully."
elif [ "$OK" -eq 1 ]; then
    echo "Compilers removed or restricted to root."
else
    echo "Some compilers are still accessible."
    exit 1
fi
