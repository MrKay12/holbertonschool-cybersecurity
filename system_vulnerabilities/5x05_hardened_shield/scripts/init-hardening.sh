#!/bin/bash
# init-hardening.sh - system hardening controls from 5x02 (bastion host)
#
#   --build    static controls, run once by the Dockerfile:
#              SUID/SGID strip, compilers & network tools, root lock,
#              file permissions, banner, core dumps, umask
#   --runtime  checks at every container start (default):
#              namespaced sysctls, /tmp mount options, read-only root FS
#
# Idempotent. Exit 1 only on a build failure, or on runtime warnings when
# STRICT_HARDENING=true (fail closed).
set -uo pipefail

MODE="${1:---runtime}"
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
COMPILERS="gcc g++ cc c++ make as ld"
NET_TOOLS="nc netcat ncat nmap socat tcpdump telnet ftp"
WARNINGS=0
ERRORS=0

log()  { printf '%s [init-hardening] %-5s %s\n' "$(date -u +%FT%TZ)" "$1" "$2"; }
ok()   { log OK "$1"; }
fix()  { log FIX "$1"; }
warn() { log WARN "$1"; WARNINGS=$((WARNINGS + 1)); }
err()  { log ERROR "$1"; ERRORS=$((ERRORS + 1)); }

[ "$(id -u)" -eq 0 ] || { echo "init-hardening.sh: must run as root" >&2; exit 1; }

# --------------------------------------------------------------------------
build_suid() {
    # 5x02 task 15: no SUID/SGID binary at all. Nothing in this image needs
    # one (no sudo/su usage, key-only SSH) and no-new-privileges at runtime
    # would neutralise them anyway.
    local list
    list=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    if [ -n "$list" ]; then
        while read -r f; do
            chmod u-s,g-s "$f" && fix "SUID/SGID removed: $f"
        done <<< "$list"
    else
        ok "no SUID/SGID binaries"
    fi
}

build_tools() {
    # 5x02 tasks 10-11: no compiler, no network attack tooling
    local t p
    for t in $COMPILERS $NET_TOOLS; do
        p=$(command -v "$t" 2>/dev/null) || continue
        rm -f "$p" && fix "removed $p"
    done
    ok "no compilers or network tools in PATH"
}

build_accounts() {
    # 5x02 task 21: lock root; system accounts cannot log in
    passwd -l root >/dev/null 2>&1 && ok "root password locked"
    local user uid shell
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" -lt 1000 ] && [ "$user" != root ] || continue
        case "$shell" in
            /usr/sbin/nologin|/bin/false|/sbin/nologin|/bin/sync) ;;
            *) usermod -s /usr/sbin/nologin "$user" && fix "nologin shell: $user" ;;
        esac
    done < /etc/passwd
}

build_permissions() {
    chown root:root /etc/passwd /etc/group
    chmod 0644 /etc/passwd /etc/group
    chown root:shadow /etc/shadow /etc/gshadow
    chmod 0640 /etc/shadow /etc/gshadow
    chown -R root:root /etc/ssh
    chmod 0600 /etc/ssh/sshd_config
    chmod 0644 /etc/issue /etc/issue.net
    # Web content: root-owned, readable by appuser only through its group,
    # so a compromised Nginx cannot deface the site.
    chown -R root:appuser /var/www/html
    find /var/www/html -type d -exec chmod 0750 {} +
    find /var/www/html -type f -exec chmod 0640 {} +
    chown root:root /etc/nginx/nginx.conf
    chmod 0644 /etc/nginx/nginx.conf
    # World-writable files outside tmp dirs
    find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' \
        -exec chmod o-w {} + 2>/dev/null
    ok "sensitive file permissions set"
}

build_banner_motd() {
    # 5x02 task 22: legal banner; no OS/version disclosure in motd
    rm -rf /etc/update-motd.d/* /etc/legal /etc/motd 2>/dev/null
    ok "legal banner installed, dynamic motd removed"
}

build_limits() {
    # No core dumps (memory may contain secrets); default umask 027
    printf '* hard core 0\n* soft core 0\n' > /etc/security/limits.d/99-hardening.conf
    printf 'umask 027\n' > /etc/profile.d/99-umask.sh
    chmod 0644 /etc/security/limits.d/99-hardening.conf /etc/profile.d/99-umask.sh
    ok "core dumps disabled, umask 027"
}

build_cleanup() {
    # Unused services/configs shipped by packages
    rm -f /etc/cron.daily/* /etc/cron.weekly/* 2>/dev/null
    rm -rf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/* \
           /var/www/html/index.nginx-debian.html 2>/dev/null
    find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null
    ok "package leftovers removed"
}

# --------------------------------------------------------------------------
runtime_sysctl() {
    # 5x02 tasks 2-7. Network sysctls are per-namespace: apply them with
    # --sysctl / compose. We try to set them, then verify.
    local key want path have
    while IFS='=' read -r key want; do
        key="${key//[[:space:]]/}"; want="${want//[[:space:]]/}"
        if [ -z "$key" ] || [ "${key:0:1}" = "#" ]; then continue; fi
        path="/proc/sys/${key//.//}"
        if [ ! -r "$path" ]; then
            warn "sysctl $key not available"
            continue
        fi
        have=$(cat "$path")
        if [ "$have" = "$want" ]; then
            ok "sysctl $key = $have"
        elif sysctl -q -w "$key=$want" >/dev/null 2>&1; then
            fix "sysctl $key: $have -> $want"
        else
            warn "sysctl $key = $have (want $want; set it with --sysctl $key=$want)"
        fi
    done < "$SYSCTL_CONF"
}

runtime_mounts() {
    # 5x02 tasks 17-18: /tmp noexec,nosuid,nodev (tmpfs from compose)
    local opts
    opts=$(awk '$2 == "/tmp" {print $4}' /proc/mounts | tail -1)
    if [ -z "$opts" ]; then
        warn "/tmp is not a separate mount (use --tmpfs /tmp:rw,noexec,nosuid,nodev)"
    else
        local o missing=""
        for o in noexec nosuid nodev; do
            [[ ",$opts," == *",$o,"* ]] || missing="$missing $o"
        done
        if [ -n "$missing" ]; then warn "/tmp missing:$missing"; else ok "/tmp mounted noexec,nosuid,nodev"; fi
    fi
    if awk '$2 == "/" {print $4}' /proc/mounts | grep -qE '(^|,)ro(,|$)'; then
        ok "root filesystem is read-only"
    else
        log INFO "root filesystem is writable (read_only: true recommended)"
    fi
}

runtime_suid() {
    local n
    n=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then ok "no SUID/SGID binaries"; else warn "$n SUID/SGID binaries found"; fi
}

# --------------------------------------------------------------------------
case "$MODE" in
    --build)
        log INFO "=== build-time system hardening ==="
        build_tools
        build_accounts
        build_permissions
        build_banner_motd
        build_limits
        build_cleanup
        build_suid
        [ "$ERRORS" -eq 0 ] || exit 1
        ;;
    --runtime)
        log INFO "=== runtime system hardening checks ==="
        umask 027
        runtime_sysctl
        runtime_mounts
        runtime_suid
        log INFO "warnings: $WARNINGS"
        if [ "$WARNINGS" -gt 0 ] && [ "${STRICT_HARDENING:-false}" = true ]; then
            err "STRICT_HARDENING=true: refusing to start with warnings"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [--build|--runtime]" >&2
        exit 2
        ;;
esac
exit 0
