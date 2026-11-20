#!/bin/bash
# 9-package_audit.sh
# Identify packages that should not be on a production web server.

# is_installed PKG: true if dpkg reports the package as installed
is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# audit "pkg|description" ...: print found packages, return the count
audit() {
    count=0
    for entry in "$@"; do
        pkg=${entry%%|*}
        desc=${entry#*|}
        if is_installed "$pkg"; then
            echo "  [FOUND] $pkg ($desc)"
            count=$((count + 1))
        fi
    done
    [ "$count" -eq 0 ] && echo "  None found"
    return "$count"
}

if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "Error: dpkg-query not found (Debian/Ubuntu only)" >&2
    exit 1
fi

echo "=== Package Security Audit ==="
echo
echo "Checking for development tools..."
audit "gcc|GNU C Compiler" \
      "g++|GNU C++ Compiler" \
      "make|Build automation" \
      "gdb|Debugger" \
      "build-essential|Build toolchain" \
      "strace|System call tracer"
DEV=$?

echo
echo "Checking for network tools..."
audit "netcat-openbsd|Network Swiss Army Knife" \
      "netcat-traditional|Network Swiss Army Knife" \
      "ncat|Network Swiss Army Knife" \
      "nmap|Network scanner" \
      "tcpdump|Packet capture" \
      "wireshark|Packet analyzer" \
      "tshark|Packet analyzer"
NET=$?

echo
echo "Checking for remote access tools..."
audit "telnet|Insecure remote access" \
      "telnetd|Insecure remote access server" \
      "rsh-client|Insecure remote shell" \
      "rsh-server|Insecure remote shell server" \
      "ftp|Insecure file transfer" \
      "vsftpd|FTP server" \
      "xinetd|Legacy super-server"
REM=$?

echo
echo "Summary:"
echo "  Development tools: $DEV found"
echo "  Network tools: $NET found"
echo "  Remote access: $REM found"
echo

if [ $((DEV + NET + REM)) -gt 0 ]; then
    echo "Recommendation: Review and remove unnecessary packages."
else
    echo "Recommendation: No unnecessary packages detected."
fi
