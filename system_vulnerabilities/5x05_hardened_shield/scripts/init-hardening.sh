#!/bin/bash
# =============================================================================
# init-hardening.sh - NovaTech Hardened Shield: system hardening (5x02)
# =============================================================================
# Controls
#   1. Kernel parameters    network sysctls (forwarding, redirects, rp_filter,
#                           source routing, SYN cookies, ICMP, martians)
#   2. Filesystem security  /tmp & /dev/shm mount options, sensitive file
#                           permissions, world-writable files, sticky bits,
#                           unowned files, read-only root, no core dumps, umask
#   3. Service minimization unneeded packages/services purged, no compilers,
#                           no network attack tools, no cron jobs, only the
#                           expected daemons (sshd, nginx, fail2ban)
#   4. SUID/SGID audit      inventory written to $REPORT_DIR, bits removed
#                           unless allow-listed (SUID_ALLOW)
#   5. Legal banner         /etc/issue, /etc/issue.net, no motd disclosure,
#                           root password locked, system accounts nologin
#
# Modes
#   --build     apply every control that can live in the image (Dockerfile)
#   --runtime   at container start (default): apply/verify what can only be
#               set at runtime (sysctls, mounts), re-verify the rest
#   --check     audit only, change nothing; non-compliance = exit 1
#
# Idempotent: a second run changes nothing and reports only [OK].
#
# Exit codes
#   0  compliant (all controls applied or already in place)
#   1  a control failed, or non-compliance found in --check mode,
#      or warnings at runtime with STRICT_HARDENING=true (fail closed)
#   2  usage error / not run as root
#
# Environment
#   STRICT_HARDENING=true   runtime warnings become fatal (default false)
#   SUID_ALLOW="..."        space-separated paths that keep SUID/SGID (default none)
#   REPORT_DIR=...          where the SUID audit is written (default /var/log/hardening)
# =============================================================================
set -uo pipefail

MODE="--runtime"
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
REPORT_DIR="${REPORT_DIR:-/var/log/hardening}"
SUID_ALLOW="${SUID_ALLOW:-}"

UNNEEDED_PKGS="telnet ftp rsh-client rsh-server talk xinetd inetutils-inetd \
openbsd-inetd vsftpd tftpd-hpa avahi-daemon cups cups-browsed rpcbind \
nfs-kernel-server samba snmpd isc-dhcp-server bind9 postfix exim4-base \
rsync cron anacron at netcat-openbsd netcat-traditional ncat nmap socat \
tcpdump gcc g++ make build-essential"
COMPILERS="gcc g++ cc c++ make as ld"
NET_TOOLS="nc netcat ncat nmap socat tcpdump telnet ftp tftp rsh"
FORBIDDEN_DAEMONS="cron crond atd anacron rsyslogd inetd xinetd telnetd in.telnetd \
vsftpd ftpd tftpd avahi-daemon cupsd rpcbind rpc.statd nfsd smbd nmbd snmpd \
dhcpd named master exim4 postfix dnsmasq"

# Kernel parameters (net.* = per network namespace, settable for a container)
SYSCTL_SETTINGS="
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
"

BANNER='*******************************************************************
*                     AUTHORIZED ACCESS ONLY                      *
*                                                                 *
* This system is the property of NovaTech Solutions. Access is    *
* restricted to authorized personnel. All activity is monitored   *
* and logged. Unauthorized access or use is prohibited and may    *
* result in disciplinary action and/or civil and criminal         *
* penalties. By continuing, you consent to this monitoring.       *
*******************************************************************'

OKS=0; FIXES=0; WARNINGS=0; ERRORS=0

log()  { printf '%s [init-hardening] %-5s %s\n' "$(date -u +%FT%TZ)" "$1" "$2"; }
ok()   { log OK "$1";    OKS=$((OKS + 1)); }
fix()  { log FIX "$1";   FIXES=$((FIXES + 1)); }
warn() { log WARN "$1";  WARNINGS=$((WARNINGS + 1)); }
err()  { log ERROR "$1"; ERRORS=$((ERRORS + 1)); }
head_() { log INFO "--- $1 ---"; }

checking() { [ "$MODE" = "--check" ]; }

# Report a deviation: in --check mode it is a finding, otherwise run the fix.
#   remediate "description" command args...
remediate() {
    local what="$1"; shift
    if checking; then
        err "non-compliant: $what"
        return 1
    fi
    if "$@" >/dev/null 2>&1; then
        fix "$what"
    else
        err "failed: $what"
        return 1
    fi
}

# ensure_perm PATH OWNER:GROUP MODE  (only touches what differs)
ensure_perm() {
    local path="$1" owner="$2" mode="$3" cur_owner cur_mode
    [ -e "$path" ] || return 0
    cur_owner=$(stat -c '%U:%G' "$path")
    cur_mode=$(stat -c '%a' "$path")
    if [ "$cur_owner" = "$owner" ] && [ "$cur_mode" = "${mode#0}" ]; then
        ok "$path $owner $mode"
        return 0
    fi
    if [ "$cur_owner" != "$owner" ]; then
        remediate "$path owner $cur_owner -> $owner" chown "$owner" "$path"
    fi
    if [ "$cur_mode" != "${mode#0}" ]; then
        remediate "$path mode $cur_mode -> $mode" chmod "$mode" "$path"
    fi
}

# write_file PATH MODE CONTENT  (only rewrites when the content differs)
write_file() {
    local path="$1" mode="$2" content="$3"
    if [ -f "$path" ] && [ "$(cat "$path")" = "$content" ]; then
        ok "$path up to date"
    else
        remediate "write $path" bash -c 'printf "%s\n" "$2" > "$1" && chmod "$3" "$1"' _ "$path" "$content" "$mode"
    fi
}

# =============================================================================
# 1. Kernel parameters
# =============================================================================
kernel_config() {
    head_ "kernel parameters: $SYSCTL_CONF"
    local content
    content="# NovaTech kernel network hardening (5x02) - managed by init-hardening.sh
# Per network namespace: apply to the container with --sysctl / compose sysctls.
$(printf '%s\n' "$SYSCTL_SETTINGS" | sed '/^$/d')"
    # Keep a custom file if it already defines every key; else write ours.
    local key missing=0
    while read -r key; do
        grep -qE "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$SYSCTL_CONF" 2>/dev/null || missing=1
    done < <(printf '%s\n' "$SYSCTL_SETTINGS" | awk -F= 'NF==2 {gsub(/ /,"",$1); print $1}')
    if [ "$missing" -eq 0 ]; then
        ok "$SYSCTL_CONF defines every hardened key"
    else
        write_file "$SYSCTL_CONF" 0644 "$content"
    fi
}

kernel_runtime() {
    head_ "kernel parameters: live values"
    # The reference list is built into this script, so a missing or edited
    # $SYSCTL_CONF cannot silently weaken the check.
    [ -f "$SYSCTL_CONF" ] || warn "$SYSCTL_CONF missing (written at build time)"
    local key want path have
    while IFS='=' read -r key want; do
        key="${key//[[:space:]]/}"; want="${want//[[:space:]]/}"
        if [ -z "$key" ] || [ "${key:0:1}" = "#" ]; then continue; fi
        path="/proc/sys/${key//.//}"
        if [ ! -r "$path" ]; then
            warn "sysctl $key not available in this kernel/namespace"
            continue
        fi
        have=$(cat "$path")
        if [ "$have" = "$want" ]; then
            ok "sysctl $key = $have"
        elif checking; then
            err "non-compliant: sysctl $key = $have (want $want)"
        elif sysctl -q -w "$key=$want" >/dev/null 2>&1; then
            fix "sysctl $key: $have -> $want"
        else
            # /proc/sys is read-only in an unprivileged container: the value
            # must come from docker run --sysctl / compose "sysctls:".
            warn "sysctl $key = $have (want $want): set it with --sysctl $key=$want"
        fi
    done <<< "$SYSCTL_SETTINGS"
}

# =============================================================================
# 2. Filesystem security
# =============================================================================
fs_permissions() {
    head_ "filesystem: sensitive file permissions"
    ensure_perm /etc/passwd   root:root   0644
    ensure_perm /etc/group    root:root   0644
    ensure_perm /etc/shadow   root:shadow 0640
    ensure_perm /etc/gshadow  root:shadow 0640
    ensure_perm /etc/login.defs root:root 0644
    ensure_perm /etc/ssh      root:root   0755
    ensure_perm /etc/ssh/sshd_config root:root 0600
    ensure_perm /etc/sysctl.d/99-hardening.conf root:root 0644
    ensure_perm /etc/nginx/nginx.conf root:root 0644
    ensure_perm /root         root:root   0700
    ensure_perm /tmp          root:root   1777
    ensure_perm /var/tmp      root:root   1777
    # Web content: root-owned, readable by appuser through its group only,
    # so a compromised Nginx cannot modify the site.
    if [ -d /var/www/html ] && getent group appuser >/dev/null; then
        local bad
        bad=$(find /var/www/html \( ! -user root -o ! -group appuser \
              -o \( -type d ! -perm 0750 \) -o \( -type f ! -perm 0640 \) \) 2>/dev/null | head -1)
        if [ -z "$bad" ]; then
            ok "/var/www/html root:appuser 0750/0640"
        else
            remediate "/var/www/html ownership/modes" bash -c '
                chown -R root:appuser /var/www/html &&
                find /var/www/html -type d -exec chmod 0750 {} + &&
                find /var/www/html -type f -exec chmod 0640 {} +'
        fi
    fi
}

fs_world_writable() {
    head_ "filesystem: world-writable files, sticky bits, unowned files"
    local files dirs unowned
    files=$(find / -xdev -type f -perm -0002 2>/dev/null)
    if [ -z "$files" ]; then
        ok "no world-writable files"
    else
        remediate "remove o+w from $(wc -l <<< "$files") world-writable file(s)" \
            bash -c 'xargs -d "\n" chmod o-w <<< "$1"' _ "$files"
    fi
    dirs=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null)
    if [ -z "$dirs" ]; then
        ok "every world-writable directory has the sticky bit"
    else
        remediate "add sticky bit to $(wc -l <<< "$dirs") world-writable dir(s)" \
            bash -c 'xargs -d "\n" chmod +t <<< "$1"' _ "$dirs"
    fi
    unowned=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null)
    if [ -z "$unowned" ]; then
        ok "no unowned files"
    else
        remediate "chown root:root $(wc -l <<< "$unowned") unowned file(s)" \
            bash -c 'xargs -d "\n" chown root:root <<< "$1"' _ "$unowned"
    fi
}

fs_limits() {
    head_ "filesystem: core dumps and umask"
    write_file /etc/security/limits.d/99-hardening.conf 0644 \
'# NovaTech: no core dumps (memory may hold secrets)
* hard core 0
* soft core 0'
    write_file /etc/profile.d/99-umask.sh 0644 'umask 027'
}

fs_mounts() {
    head_ "filesystem: mount options"
    local mp opts o missing
    for mp in /tmp /dev/shm; do
        opts=$(awk -v m="$mp" '$2 == m {print $4}' /proc/mounts | tail -1)
        if [ -z "$opts" ]; then
            warn "$mp is not a separate mount (use --tmpfs $mp:rw,noexec,nosuid,nodev)"
            continue
        fi
        missing=""
        for o in noexec nosuid nodev; do
            [[ ",$opts," == *",$o,"* ]] || missing="$missing $o"
        done
        if [ -z "$missing" ]; then
            ok "$mp mounted noexec,nosuid,nodev"
        elif ! checking && mount -o "remount,noexec,nosuid,nodev" "$mp" 2>/dev/null; then
            fix "$mp remounted noexec,nosuid,nodev"
        else
            warn "$mp missing:$missing (set it in the tmpfs options)"
        fi
    done
    if awk '$2 == "/" {print $4}' /proc/mounts | grep -qE '(^|,)ro(,|$)'; then
        ok "root filesystem is read-only"
    else
        log INFO "root filesystem is writable (read_only: true recommended)"
    fi
}

# =============================================================================
# 3. Service minimization
# =============================================================================
svc_packages() {
    head_ "services: unneeded packages"
    local p installed=""
    for p in $UNNEEDED_PKGS; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' \
            && installed="$installed $p"
    done
    if [ -z "$installed" ]; then
        ok "no unneeded service/tool package installed"
    else
        remediate "purge:$installed" bash -c \
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove $installed"
    fi
}

svc_binaries() {
    head_ "services: compilers and network tools"
    local t p found=0
    for t in $COMPILERS $NET_TOOLS; do
        p=$(command -v "$t" 2>/dev/null) || continue
        found=1
        remediate "remove $p" rm -f "$p"
    done
    [ "$found" -eq 0 ] && ok "no compiler or network attack tool in PATH"
}

svc_autostart() {
    head_ "services: autostart and scheduled jobs"
    local keep="ssh nginx fail2ban procps" f name extra=""
    for f in /etc/init.d/*; do
        [ -e "$f" ] || continue
        name=$(basename "$f")
        [[ " $keep " == *" $name "* ]] || extra="$extra $f"
    done
    if [ -z "$extra" ]; then
        ok "only ssh, nginx, fail2ban init scripts present"
    else
        remediate "remove init scripts:$extra" rm -f $extra
    fi
    local jobs
    jobs=$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
                /etc/cron.monthly -type f ! -name .placeholder 2>/dev/null)
    if [ -z "$jobs" ]; then
        ok "no scheduled jobs"
    else
        remediate "remove $(wc -l <<< "$jobs") cron job(s)" bash -c 'xargs -d "\n" rm -f <<< "$1"' _ "$jobs"
    fi
    if [ -n "$(ls -A /etc/nginx/sites-enabled 2>/dev/null)" ]; then
        remediate "disable default nginx site" bash -c 'rm -f /etc/nginx/sites-enabled/*'
    else
        ok "no extra nginx site enabled"
    fi
    if [ -e /var/www/html/index.nginx-debian.html ]; then
        remediate "remove nginx default page (version disclosure)" rm -f /var/www/html/index.nginx-debian.html
    fi
}

svc_running() {
    head_ "services: running daemons"
    local d comm found=""
    for d in /proc/[0-9]*; do
        comm=$(cat "$d/comm" 2>/dev/null) || continue
        [[ " $FORBIDDEN_DAEMONS " == *" $comm "* ]] && found="$found $comm"
    done
    if [ -z "$found" ]; then
        ok "no unneeded daemon running (expected: sshd, nginx, fail2ban)"
    else
        warn "unneeded daemons running:$found"
    fi
}

# =============================================================================
# 4. SUID/SGID audit
# =============================================================================
suid_audit() {
    head_ "SUID/SGID audit"
    local list f keep removed=0 kept=0 report=""
    list=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
    if [ "$MODE" = "--build" ] && install -d -m 0750 "$REPORT_DIR" 2>/dev/null; then
        report="$REPORT_DIR/suid_audit.txt"
        {
            echo "# SUID/SGID audit - $(date -u +%FT%TZ)"
            echo "# allow-list: ${SUID_ALLOW:-<none>}"
            if [ -n "$list" ]; then
                while read -r f; do stat -c '%A %U:%G %n' "$f"; done <<< "$list"
            else
                echo "(none)"
            fi
        } > "$report"
        chmod 0640 "$report"
        log INFO "inventory written to $report"
    fi
    if [ -z "$list" ]; then
        ok "no SUID/SGID binaries"
        return
    fi
    while read -r f; do
        keep=0
        for a in $SUID_ALLOW; do [ "$f" = "$a" ] && keep=1; done
        if [ "$keep" -eq 1 ]; then
            ok "allow-listed: $(stat -c '%A %n' "$f")"
            kept=$((kept + 1))
        else
            remediate "strip SUID/SGID: $(stat -c '%A %n' "$f")" chmod u-s,g-s "$f" \
                && removed=$((removed + 1))
        fi
    done <<< "$list"
    log INFO "SUID/SGID: $removed removed, $kept allow-listed"
}

# =============================================================================
# 5. Legal banner and account lock-down
# =============================================================================
banner() {
    head_ "legal banner"
    local f
    for f in /etc/issue /etc/issue.net; do
        if grep -q 'AUTHORIZED ACCESS ONLY' "$f" 2>/dev/null; then
            ok "$f contains the legal banner"
        else
            write_file "$f" 0644 "$BANNER"
        fi
        ensure_perm "$f" root:root 0644
    done
    if [ -n "$(ls -A /etc/update-motd.d 2>/dev/null)" ] || [ -s /etc/motd ] || [ -e /etc/legal ]; then
        remediate "remove dynamic motd (OS/version disclosure)" \
            bash -c 'rm -rf /etc/update-motd.d/* /etc/legal; : > /etc/motd'
    else
        ok "no motd information disclosure"
    fi
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -qE '^[[:space:]]*Banner[[:space:]]+/etc/issue\.net' /etc/ssh/sshd_config; then
            ok "sshd displays /etc/issue.net"
        else
            warn "sshd_config has no 'Banner /etc/issue.net' (set by init-identity.sh / config)"
        fi
    fi
}

accounts() {
    head_ "accounts: root and system users"
    local status user uid shell
    status=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [ "$status" = "L" ]; then
        ok "root password locked"
    else
        remediate "lock root password" passwd -l root
    fi
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" -lt 1000 ] && [ "$user" != root ] || continue
        case "$shell" in
            /usr/sbin/nologin|/sbin/nologin|/bin/false|/bin/sync) ;;
            *) remediate "nologin shell for system account $user" usermod -s /usr/sbin/nologin "$user" ;;
        esac
    done < /etc/passwd
    ok "system accounts cannot log in"
}

# =============================================================================
usage() {
    awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
    exit 0
}

case "${1:-}" in
    ""|--runtime) MODE="--runtime" ;;
    --build)      MODE="--build" ;;
    --check)      MODE="--check" ;;
    -h|--help)    usage ;;
    *)            echo "Usage: $0 [--build|--runtime|--check]" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "init-hardening.sh: must run as root" >&2
    exit 2
fi
umask 027

log INFO "=== system hardening ($MODE) ==="
case "$MODE" in
    --build)
        kernel_config
        svc_packages
        svc_binaries
        svc_autostart
        fs_permissions
        fs_world_writable
        fs_limits
        banner
        accounts
        suid_audit          # last: after every package change
        ;;
    --runtime)
        kernel_runtime
        fs_mounts
        fs_permissions
        suid_audit
        banner
        svc_running
        ;;
    --check)
        kernel_runtime
        fs_mounts
        fs_permissions
        fs_world_writable
        svc_packages
        svc_binaries
        suid_audit
        banner
        accounts
        ;;
esac

log INFO "summary: ok=$OKS fixed=$FIXES warnings=$WARNINGS errors=$ERRORS"

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
if [ "$MODE" = "--runtime" ] && [ "$WARNINGS" -gt 0 ] && [ "${STRICT_HARDENING:-false}" = true ]; then
    log ERROR "STRICT_HARDENING=true: refusing to start with $WARNINGS warning(s)"
    exit 1
fi
exit 0
