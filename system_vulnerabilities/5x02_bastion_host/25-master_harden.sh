#!/bin/bash
# =============================================================================
# 25-master_harden.sh - NovaTech bastion / web server hardening
# =============================================================================
# Applies every control from tasks 2-22 on a fresh Ubuntu 20.04+ server:
#
#   1. kernel      - sysctl network hardening (tasks 2-8)
#   2. packages    - remove compilers, restrict network tools (tasks 9-11)
#   3. suid        - strip SUID from non-essential binaries (tasks 13-15)
#   4. filesystem  - /tmp, /var/tmp, /dev/shm noexec,nosuid,nodev (17-19)
#   5. services    - disable unneeded services (task 20)
#   6. access      - lock root, disable root SSH, legal banner (21-22)
#
# Properties:
#   - Idempotent : every step checks the current state before changing it,
#                  config files are updated in place (never duplicated).
#   - Logged     : every action goes to /var/log/hardening/master-<date>.log
#   - Safe       : backups of edited files, sshd config tested before reload,
#                  root is only locked if the calling user has working sudo.
#
# Usage:
#   sudo ./25-master_harden.sh              # apply all modules
#   sudo ./25-master_harden.sh --dry-run    # show what would change
#   sudo ./25-master_harden.sh kernel suid  # run selected modules only
# =============================================================================

set -u

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
LOGDIR="/var/log/hardening"
LOGFILE="$LOGDIR/master-$(date +%Y%m%d-%H%M%S).log"
BACKUPDIR="$LOGDIR/backups"
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
FSTAB="/etc/fstab"
SSHD_CONFIG="/etc/ssh/sshd_config"
BANNER_FILE="/etc/issue.net"

# key=value pairs applied by the kernel module
SYSCTL_SETTINGS="
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
"

COMPILERS="gcc g++ make"
NET_TOOLS="/usr/bin/nc /usr/bin/netcat /usr/bin/ncat /usr/bin/nmap /usr/sbin/tcpdump /usr/bin/tcpdump /usr/bin/socat"
SUID_KEEP="/usr/bin/sudo /usr/bin/passwd /usr/bin/su"
UNNEEDED_SERVICES="cups cups-browsed avahi-daemon bluetooth ModemManager rpcbind nfs-server smbd nmbd vsftpd xinetd snmpd isc-dhcp-server"

ALL_MODULES="kernel packages suid filesystem services access"

DRY_RUN=0
CHANGES=0
ERRORS=0

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# log LEVEL MESSAGE: print to screen and append to the log file
log() {
    printf '%s [%-5s] %s\n' "$(date '+%F %T')" "$1" "$2" >> "$LOGFILE"
    case "$1" in
        HEAD) echo; echo "=== $2 ===" ;;
        OK)   echo "  [OK]     $2" ;;
        FIX)  echo "  [FIXED]  $2" ;;
        SKIP) echo "  [SKIP]   $2" ;;
        WARN) echo "  [WARN]   $2" ;;
        ERR)  echo "  [ERROR]  $2" ;;
        *)    echo "  $2" ;;
    esac
}

# run CMD...: execute a command (or only log it in dry-run mode)
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log INFO "(dry-run) $*"
        return 0
    fi
    echo "\$ $*" >> "$LOGFILE"
    if "$@" >> "$LOGFILE" 2>&1; then
        return 0
    fi
    ERRORS=$((ERRORS + 1))
    return 1
}

# backup FILE: keep a timestamped copy before the first edit of this run
backup() {
    [ -f "$1" ] || return 0
    dest="$BACKUPDIR/$(basename "$1").$(date +%Y%m%d-%H%M%S)"
    [ -f "$dest" ] || run cp -p "$1" "$dest"
}

# set_line FILE MATCH_REGEX LINE: replace the first matching line or append
set_line() {
    file=$1; regex=$2; line=$3
    if grep -qxF "$line" "$file" 2>/dev/null; then
        return 1    # already present: nothing to do
    fi
    backup "$file"
    if grep -qE "$regex" "$file" 2>/dev/null; then
        run sed -i -E "0,/$regex/s|$regex.*|$line|" "$file"
    else
        if [ "$DRY_RUN" -eq 1 ]; then
            log INFO "(dry-run) append '$line' to $file"
        else
            echo "$line" >> "$file"
        fi
    fi
    CHANGES=$((CHANGES + 1))
    return 0
}

is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

unit_exists() {
    systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q .
}

# ----------------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------------
preflight() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: run as root (sudo $0)" >&2
        exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Error: this script targets Ubuntu/Debian (apt-get missing)" >&2
        exit 1
    fi
    mkdir -p "$LOGDIR" "$BACKUPDIR"
    chmod 700 "$LOGDIR"
    touch "$LOGFILE"
    chmod 600 "$LOGFILE"

    log HEAD "NovaTech Master Hardening"
    log INFO "Host: $(hostname) - $(. /etc/os-release && echo "$PRETTY_NAME")"
    log INFO "Log file: $LOGFILE"
    [ "$DRY_RUN" -eq 1 ] && log WARN "DRY-RUN mode: no change will be made"
}

# ----------------------------------------------------------------------------
# Module 1 - Kernel / network (sysctl)
# ----------------------------------------------------------------------------
mod_kernel() {
    log HEAD "Kernel hardening (sysctl)"
    [ -f "$SYSCTL_CONF" ] || run touch "$SYSCTL_CONF"

    for kv in $SYSCTL_SETTINGS; do
        key=${kv%%=*}
        val=${kv#*=}
        # Skip keys missing on this kernel (e.g. IPv6 disabled)
        if ! sysctl -n "$key" >/dev/null 2>&1; then
            log SKIP "$key not available on this kernel"
            continue
        fi
        set_line "$SYSCTL_CONF" "^[[:space:]]*$key[[:space:]]*=" "$key = $val"
        if [ "$(sysctl -n "$key")" = "$val" ]; then
            log OK "$key = $val"
        else
            run sysctl -w "$key=$val" && log FIX "$key = $val"
        fi
    done
}

# ----------------------------------------------------------------------------
# Module 2 - Packages (compilers, network tools)
# ----------------------------------------------------------------------------
mod_packages() {
    log HEAD "Software attack surface"

    for p in $COMPILERS; do
        if ! is_installed "$p"; then
            log OK "$p not installed"
            continue
        fi
        # Only remove if nothing else (non dev) depends on it
        others=$(apt-get -s remove "$p" 2>/dev/null | awk '/^Remv/ {print $2}' |
                 grep -Ev '^(gcc|g\+\+|cpp|make|build-essential|dpkg-dev|lib.*-dev|.*-dev|gcc-.*|g\+\+-.*|cpp-.*)$')
        if [ -z "$others" ]; then
            run env DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p" && log FIX "$p removed"
            CHANGES=$((CHANGES + 1))
        else
            bin=$(command -v "$p")
            real=$(readlink -f "$bin")
            if [ "$(stat -c '%a' "$real")" = "700" ]; then
                log OK "$p kept (dependencies) and already root-only"
            else
                run chmod 0700 "$real" && log FIX "$p restricted to root (needed by: $(echo $others | cut -c1-40))"
                CHANGES=$((CHANGES + 1))
            fi
        fi
    done
    run env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y

    for t in $NET_TOOLS; do
        [ -e "$t" ] || continue
        real=$(readlink -f "$t")
        if [ "$(stat -c '%a %U %G' "$real")" = "750 root root" ]; then
            log OK "$t already 0750 root:root"
        else
            run chown root:root "$real"
            run chmod 0750 "$real" && log FIX "$t set to 0750 root:root"
            CHANGES=$((CHANGES + 1))
        fi
    done
}

# ----------------------------------------------------------------------------
# Module 3 - SUID neutralization
# ----------------------------------------------------------------------------
mod_suid() {
    log HEAD "SUID neutralization"
    before=0
    while IFS= read -r f; do
        before=$((before + 1))
        case " $SUID_KEEP " in
            *" $f "*) log OK "$f kept (essential)"; continue ;;
        esac
        run chmod u-s "$f" && log FIX "$f: SUID removed"
        CHANGES=$((CHANGES + 1))
    done < <(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort)
    log INFO "SUID binaries found: $before"
}

# ----------------------------------------------------------------------------
# Module 4 - Filesystem (/tmp, /var/tmp, /dev/shm)
# ----------------------------------------------------------------------------
mod_filesystem() {
    log HEAD "Filesystem mount options"

    set_line "$FSTAB" "^[^#]*[[:space:]]/tmp[[:space:]]" \
        "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0" && log FIX "/tmp entry written to fstab"
    set_line "$FSTAB" "^[^#]*[[:space:]]/var/tmp[[:space:]]" \
        "/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0" && log FIX "/var/tmp entry written to fstab"
    set_line "$FSTAB" "^[^#]*[[:space:]]/dev/shm[[:space:]]" \
        "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" && log FIX "/dev/shm entry written to fstab"
    run systemctl daemon-reload

    # /tmp
    if ! mountpoint -q /tmp; then
        run mount -t tmpfs -o defaults,noexec,nosuid,nodev,mode=1777 tmpfs /tmp
    fi
    # /var/tmp bind mount
    if ! mountpoint -q /var/tmp; then
        run mount --bind /tmp /var/tmp
    fi

    for m in /tmp /var/tmp /dev/shm; do
        o=$(findmnt -n -o OPTIONS "$m" 2>/dev/null)
        if echo "$o" | grep -qw noexec && echo "$o" | grep -qw nosuid && echo "$o" | grep -qw nodev; then
            log OK "$m: noexec,nosuid,nodev"
        else
            if [ "$m" = "/var/tmp" ]; then
                run mount -o remount,bind,noexec,nosuid,nodev "$m"
            else
                run mount -o remount,noexec,nosuid,nodev "$m"
            fi
            log FIX "$m remounted noexec,nosuid,nodev"
            CHANGES=$((CHANGES + 1))
        fi
    done
}

# ----------------------------------------------------------------------------
# Module 5 - Services
# ----------------------------------------------------------------------------
mod_services() {
    log HEAD "Service minimization"
    for s in $UNNEEDED_SERVICES; do
        unit="$s.service"
        unit_exists "$unit" || continue
        if ! systemctl is-enabled --quiet "$unit" 2>/dev/null && ! systemctl is-active --quiet "$unit"; then
            log OK "$unit already disabled"
            continue
        fi
        unit_exists "$s.socket" && run systemctl disable --now "$s.socket"
        run systemctl disable --now "$unit" && log FIX "$unit disabled and stopped"
        CHANGES=$((CHANGES + 1))
    done
    for e in ssh apache2 nginx; do
        unit_exists "$e.service" || continue
        if systemctl is-active --quiet "$e.service"; then
            log OK "$e.service running (essential)"
        else
            log WARN "$e.service is not running"
        fi
    done
}

# ----------------------------------------------------------------------------
# Module 6 - Access control (root, SSH, banner)
# ----------------------------------------------------------------------------
mod_access() {
    log HEAD "Access control"

    # Root account: lock only if the caller has working sudo
    if [ "$(passwd -S root | awk '{print $2}')" = "L" ]; then
        log OK "root password already locked"
    elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] &&
         sudo -l -U "$SUDO_USER" 2>/dev/null | grep -qE '\(ALL( : ALL)?\) (NOPASSWD: )?ALL' &&
         visudo -c >/dev/null 2>&1; then
        run passwd -l root && log FIX "root password locked (sudo verified for $SUDO_USER)"
        CHANGES=$((CHANGES + 1))
    else
        log WARN "root NOT locked: run via sudo from an admin account"
    fi

    if [ ! -f "$SSHD_CONFIG" ]; then
        log SKIP "openssh-server not installed"
        return
    fi

    # Legal banner
    BANNER="=====================================
AUTHORIZED ACCESS ONLY

This system is the property of NovaTech Solutions.
Unauthorized access is prohibited and will be prosecuted.
All activities are monitored and logged.
====================================="
    if [ "$(cat "$BANNER_FILE" 2>/dev/null)" = "$BANNER" ]; then
        log OK "$BANNER_FILE up to date"
    else
        backup "$BANNER_FILE"
        if [ "$DRY_RUN" -eq 0 ]; then
            echo "$BANNER" > "$BANNER_FILE"
            chmod 644 "$BANNER_FILE"
        fi
        log FIX "$BANNER_FILE written"
        CHANGES=$((CHANGES + 1))
    fi

    # sshd settings
    SSH_CHANGED=0
    set_line "$SSHD_CONFIG" "^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]" "PermitRootLogin no" && SSH_CHANGED=1
    set_line "$SSHD_CONFIG" "^[[:space:]]*#?[[:space:]]*Banner[[:space:]]" "Banner $BANNER_FILE" && SSH_CHANGED=1

    if [ "$SSH_CHANGED" -eq 1 ]; then
        mkdir -p /run/sshd
        if sshd -t >> "$LOGFILE" 2>&1; then
            run systemctl reload ssh && log FIX "sshd: PermitRootLogin no, Banner $BANNER_FILE (reloaded)"
        else
            log ERR "sshd config invalid - NOT reloaded (backup in $BACKUPDIR)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log OK "sshd: PermitRootLogin no, Banner $BANNER_FILE"
    fi
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
MODULES=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        kernel|packages|suid|filesystem|services|access) MODULES="$MODULES $arg" ;;
        *) echo "Unknown option: $arg (see --help)" >&2; exit 1 ;;
    esac
done
MODULES=${MODULES:-$ALL_MODULES}

preflight
for m in $MODULES; do
    "mod_$m"
done

log HEAD "Summary"
log INFO "Modules run: $(echo $MODULES)"
log INFO "Changes applied: $CHANGES"
log INFO "Errors: $ERRORS"
log INFO "Full log: $LOGFILE"
if [ "$ERRORS" -eq 0 ]; then
    log INFO "Hardening complete. Re-run anytime: already-hardened items are skipped."
else
    log WARN "Hardening finished with errors - check the log."
    exit 1
fi
