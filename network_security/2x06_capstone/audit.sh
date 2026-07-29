#!/usr/bin/env bash

# LogiCorp Gateway - Comprehensive Technical Audit
# Collects runtime evidence, configuration files, suspicious artifacts and flags.
# No system configuration is modified.

set -u

REPORT="AUDIT_REPORT.md"
EVIDENCE_DIR="audit_evidence"
FLAGS_FILE="recovered_flags.txt"
AUDIT_DATE="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

SYSTEM_DIR="$EVIDENCE_DIR/01_system"
NETWORK_DIR="$EVIDENCE_DIR/02_network"
SURFACE_DIR="$EVIDENCE_DIR/03_attack_surface"
SECURITY_DIR="$EVIDENCE_DIR/04_security_controls"
USERS_DIR="$EVIDENCE_DIR/05_users_access"
SSH_DIR="$EVIDENCE_DIR/06_ssh"
SERVICES_DIR="$EVIDENCE_DIR/07_services"
PERSISTENCE_DIR="$EVIDENCE_DIR/08_persistence"
FTP_DIR="$EVIDENCE_DIR/09_ftp"
DATA_DIR="$EVIDENCE_DIR/10_sensitive_data"
LOGS_DIR="$EVIDENCE_DIR/11_logs"
INTRUSION_DIR="$EVIDENCE_DIR/12_intrusion_analysis"
FLAGS_DIR="$EVIDENCE_DIR/13_flags"
MISC_DIR="$EVIDENCE_DIR/14_misc"

# Remove evidence from a previous run so stale files cannot affect the audit.
rm -rf "$EVIDENCE_DIR"
mkdir -p \
    "$SYSTEM_DIR" \
    "$NETWORK_DIR" \
    "$SURFACE_DIR" \
    "$SECURITY_DIR" \
    "$USERS_DIR" \
    "$SSH_DIR" \
    "$SERVICES_DIR" \
    "$PERSISTENCE_DIR" \
    "$FTP_DIR" \
    "$DATA_DIR" \
    "$LOGS_DIR" \
    "$INTRUSION_DIR" \
    "$FLAGS_DIR" \
    "$MISC_DIR"
: > "$FLAGS_FILE"

evidence_path()
{
    local name="$1"

    case "$name" in
        system_*) printf '%s/%s\n' "$SYSTEM_DIR" "$name" ;;
        network_addresses*|network_arp.txt|network_bridges_vlans.txt|network_configurations.txt|network_dns.txt|network_forwarding.txt|network_hosts.txt|network_links.txt|network_neighbors.txt|network_routes*|network_rules.txt)
            printf '%s/%s\n' "$NETWORK_DIR" "$name" ;;
        ports_*|connections_all.txt|active_connections_targets.txt|network_processes.txt|process_command_lines.txt)
            printf '%s/%s\n' "$SURFACE_DIR" "$name" ;;
        firewall_*|security_*) printf '%s/%s\n' "$SECURITY_DIR" "$name" ;;
        users_*|suid_sgid_files.txt)
            printf '%s/%s\n' "$USERS_DIR" "$name" ;;
        ssh_*) printf '%s/%s\n' "$SSH_DIR" "$name" ;;
        services_*|telnet_artifacts.txt) printf '%s/%s\n' "$SERVICES_DIR" "$name" ;;
        cron_*|persistence_files.txt) printf '%s/%s\n' "$PERSISTENCE_DIR" "$name" ;;
        ftp_flag_search.txt) printf '%s/%s\n' "$FLAGS_DIR" "$name" ;;
        ftp_*) printf '%s/%s\n' "$FTP_DIR" "$name" ;;
        logicorp_*|sensitive_content_search.txt|world_readable_sensitive_files.txt) printf '%s/%s\n' "$DATA_DIR" "$name" ;;
        authentication_logs.txt|all_recent_logs.txt|logs_flag_search.txt|ftp_logs.txt)
            printf '%s/%s\n' "$LOGS_DIR" "$name" ;;
        startup_security_analysis.txt|startup_injected_log_entries.txt|startup_password_changes.txt|authentication_logs_without_known_injections.txt|intrusion_artifact_search.txt)
            printf '%s/%s\n' "$INTRUSION_DIR" "$name" ;;
        flag_search_targeted.txt|evidence_directory_index.txt) printf '%s/%s\n' "$FLAGS_DIR" "$name" ;;
        *) printf '%s/%s\n' "$MISC_DIR" "$name" ;;
    esac
}

organize_evidence_files()
{
    local file

    # Safety net: no TXT evidence file is allowed to remain at the root.
    find "$EVIDENCE_DIR" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null |
    while IFS= read -r -d '' file; do
        mv -- "$file" "$MISC_DIR/"
    done

    find "$EVIDENCE_DIR" -mindepth 1 -maxdepth 2 -type f -printf '%p\n' 2>/dev/null |
        sort > "$FLAGS_DIR/evidence_file_index.txt"
}

command_exists()
{
    command -v "$1" >/dev/null 2>&1
}

collect()
{
    local name="$1"
    shift

    {
        echo "Command: $*"
        echo
        "$@" 2>&1 || true
    } > "$(evidence_path "$name")"
}

collect_shell()
{
    local name="$1"
    local cmd="$2"

    {
        echo "Command: $cmd"
        echo
        bash -c "$cmd" 2>&1 || true
    } > "$(evidence_path "$name")"
}

extract_flags()
{
    grep -RhoE 'FLAG\{[^}]+\}' \
        "$EVIDENCE_DIR" \
        /etc/logicorp \
        /opt/logicorp \
        /srv/ftp \
        /var/ftp \
        /home/ftp \
        /etc/vsftpd.conf \
        /etc/vsftpd \
        /etc/ftpusers \
        /etc/pam.d/vsftpd \
        /var/log/vsftpd.log \
        /var/log/xferlog \
        /var/log/proftpd \
        /etc/cron.d \
        /var/log \
        2>/dev/null |
        sort -u > "$FLAGS_FILE"
}

echo "[+] Starting LogiCorp technical audit"

###############################################################################
# 1. SYSTEM INFORMATION
###############################################################################

echo "[+] System information"

collect "system_hostname.txt" hostname
collect "system_uname.txt" uname -a
collect "system_os.txt" cat /etc/os-release
collect "system_uptime.txt" uptime
collect "system_identity.txt" id
collect "system_pid1.txt" ps -p 1 -o pid,ppid,user,group,comm,args
collect "system_processes.txt" ps auxwwf
collect "system_environment.txt" env
collect "system_mounts.txt" mount
collect "system_disks.txt" df -hT
collect "system_block_devices.txt" lsblk -f

collect_shell "system_startup_scripts.txt" '
for file in \
    /etc/run.sh \
    /entrypoint.sh \
    /docker-entrypoint.sh \
    /usr/local/bin/entrypoint.sh
do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        ls -l "$file"
        sed -n "1,300p" "$file"
        echo
    fi
done
'


collect_shell "startup_security_analysis.txt" '
for file in /etc/run.sh /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh; do
    [ -r "$file" ] || continue

    echo "===== $file ====="

    grep -nE     "fake attack log|brute force source|chpasswd|passwd[[:space:]]|nft[[:space:]]+flush[[:space:]]+ruleset|ttyd|openvscode-server|code-server|setup_ssh|auth\.log|suricata/fast\.log"     "$file" 2>/dev/null || true

    echo
done
'

collect_shell "startup_injected_log_entries.txt" '
for file in /etc/run.sh /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh; do
    [ -r "$file" ] || continue

    echo "===== $file ====="
    grep -nE     "echo .*(auth\.log|secure|syslog|messages|suricata/fast\.log)"     "$file" 2>/dev/null || true
    echo
done
'

collect_shell "startup_password_changes.txt" '
for file in /etc/run.sh /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh; do
    [ -r "$file" ] || continue

    echo "===== $file ====="
    grep -nE     "chpasswd|passwd[[:space:]]|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)"     "$file" 2>/dev/null || true
    echo
done
'

###############################################################################
# 2. NETWORK TOPOLOGY
###############################################################################

echo "[+] Network topology"

collect "network_addresses.txt" ip address show
collect "network_addresses_short.txt" ip -br address show
collect "network_links.txt" ip -details link show
collect "network_routes.txt" ip route show table all
collect "network_routes_ipv6.txt" ip -6 route show table all
collect "network_rules.txt" ip rule show
collect "network_neighbors.txt" ip neigh show

collect_shell "network_arp.txt" '
cat /proc/net/arp 2>/dev/null || true
'

collect_shell "network_dns.txt" '
cat /etc/resolv.conf 2>/dev/null || true
'

collect_shell "network_hosts.txt" '
cat /etc/hosts 2>/dev/null || true
'

collect_shell "network_forwarding.txt" '
printf "IPv4 forwarding: "
cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

printf "IPv6 forwarding: "
cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
'

collect_shell "network_bridges_vlans.txt" '
ip -d link show type bridge 2>/dev/null || true
echo
ip -d link show type vlan 2>/dev/null || true
echo
bridge link 2>/dev/null || true
echo
bridge vlan show 2>/dev/null || true
'

collect_shell "network_configurations.txt" '
for file in \
    /etc/network/interfaces \
    /etc/network/interfaces.d/* \
    /etc/netplan/*.yaml \
    /etc/netplan/*.yml
do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        cat "$file"
        echo
    fi
done
'

###############################################################################
# 3. ATTACK SURFACE
###############################################################################

echo "[+] Attack surface"

if command_exists ss; then
    collect "ports_listening.txt" ss -tulpen
    collect "ports_tcp.txt" ss -ltnp
    collect "ports_udp.txt" ss -lunp
    collect "connections_all.txt" ss -antup
elif command_exists netstat; then
    collect "ports_listening.txt" netstat -tulpen
    collect "connections_all.txt" netstat -antup
fi

collect_shell "network_processes.txt" '
ps auxww |
grep -Ei \
"[s]shd|[v]sftpd|[p]roftpd|[p]ure-ftpd|[t]tyd|[o]penvscode|[c]ode-server|[a]pache|[n]ginx|[m]ysql|[m]ariadb|[p]ostgres|[s]uricata|[s]nort|[d]nsmasq|[n]amed|[s]quid|[t]elnet|[c]url|[w]get" || true
'

collect_shell "process_command_lines.txt" '
for process in /proc/[0-9]*; do
    [ -r "$process/cmdline" ] || continue

    pid="${process##*/}"
    cmd="$(tr "\0" " " < "$process/cmdline" 2>/dev/null)"

    if [ -n "$cmd" ]; then
        printf "%s: %s\n" "$pid" "$cmd"
    fi
done
'

collect_shell "active_connections_targets.txt" '
ss -antup 2>/dev/null |
grep -vE "127\.0\.0\.1|::1" || true
'

###############################################################################
# 4. FIREWALL AND SECURITY CONTROLS
###############################################################################

echo "[+] Security controls"

collect_shell "firewall_nftables.txt" '
if command -v nft >/dev/null 2>&1; then
    nft list ruleset
else
    echo "nft unavailable"
fi
'

collect_shell "firewall_iptables.txt" '
if command -v iptables >/dev/null 2>&1; then
    echo "===== FILTER ====="
    iptables -L -n -v --line-numbers
    echo
    iptables -S
    echo

    echo "===== NAT ====="
    iptables -t nat -L -n -v --line-numbers
    echo
    iptables -t nat -S
    echo

    echo "===== MANGLE ====="
    iptables -t mangle -L -n -v --line-numbers
else
    echo "iptables unavailable"
fi
'

collect_shell "firewall_ufw.txt" '
if command -v ufw >/dev/null 2>&1; then
    ufw status verbose
else
    echo "ufw unavailable"
fi
'

collect_shell "security_selinux.txt" '
if command -v getenforce >/dev/null 2>&1; then
    getenforce
    sestatus 2>/dev/null || true
else
    echo "SELinux unavailable"
fi
'

collect_shell "security_apparmor.txt" '
if command -v aa-status >/dev/null 2>&1; then
    aa-status
elif [ -r /sys/module/apparmor/parameters/enabled ]; then
    cat /sys/module/apparmor/parameters/enabled
else
    echo "AppArmor unavailable"
fi
'

collect_shell "security_fail2ban.txt" '
if [ -d /etc/fail2ban ]; then
    find /etc/fail2ban \
        -maxdepth 4 \
        -type f \
        -print \
        -exec sh -c '\''
            echo "===== $1 ====="
            sed -n "1,300p" "$1"
        '\'' sh {} \;
else
    echo "Fail2ban configuration directory unavailable"
fi
'

collect_shell "security_suricata.txt" '
if [ -d /etc/suricata ]; then
    find /etc/suricata \
        -maxdepth 3 \
        -type f \
        -print 2>/dev/null
fi

ps auxww | grep -E "[s]uricata" || true
'

###############################################################################
# 5. USER ACCOUNTS AND SSH
###############################################################################

echo "[+] User accounts and SSH"

collect "users_passwd.txt" cat /etc/passwd
collect "users_groups.txt" cat /etc/group

collect_shell "users_login_capable.txt" '
awk -F: '\''
$7 !~ /(nologin|false|sync|shutdown|halt)$/ {
    print $1 ":" $3 ":" $4 ":" $6 ":" $7
}'\'' /etc/passwd
'

collect_shell "users_uid0.txt" '
awk -F: '\''$3 == 0 {print}'\'' /etc/passwd
'

collect_shell "users_admin_groups.txt" '
getent group sudo 2>/dev/null || true
getent group wheel 2>/dev/null || true
getent group adm 2>/dev/null || true
getent group docker 2>/dev/null || true
'

collect_shell "users_sudoers.txt" '
for file in /etc/sudoers /etc/sudoers.d/*; do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        grep -vE "^[[:space:]]*(#|$)" "$file" 2>/dev/null || true
        echo
    fi
done
'

collect_shell "users_ssh_keys.txt" '
find /root /home \
    -xdev \
    -type f \
    \( -name authorized_keys -o -name authorized_keys2 \) \
    -printf "%M %u:%g %p\n" \
    -exec sh -c '\''
        echo "===== $1 ====="
        cat "$1"
        echo
    '\'' sh {} \; 2>/dev/null
'

collect_shell "ssh_configuration.txt" '
for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        cat "$file"
        echo
    fi
done
'

collect_shell "ssh_effective.txt" '
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>&1
else
    echo "sshd unavailable"
fi
'

collect_shell "ssh_security_values.txt" '
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null |
    grep -E \
    "^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|denyusers|denygroups|maxauthtries)"
fi
'

###############################################################################
# 6. RUNNING SERVICES
###############################################################################

echo "[+] Running services"

collect_shell "services_status.txt" '
if command -v service >/dev/null 2>&1; then
    service --status-all
else
    echo "service command unavailable"
fi
'

collect "services_processes.txt" ps auxwwf

collect_shell "services_startup.txt" '
find /etc/init.d /etc/rc*.d \
    -maxdepth 2 \
    \( -type f -o -type l \) \
    -printf "%M %u:%g %p -> %l\n" 2>/dev/null |
    sort
'

collect_shell "services_installed_relevant.txt" '
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W 2>/dev/null |
    grep -Ei \
    "ssh|ftp|vsftpd|proftpd|telnet|ttyd|code|mysql|mariadb|postgres|nginx|apache|cron|suricata|snort|fail2ban|iptables|nftables|ufw"
fi
'

###############################################################################
# 7. SCHEDULED TASKS AND PERSISTENCE
###############################################################################

echo "[+] Scheduled tasks and persistence"

collect_shell "cron_current_user.txt" '
crontab -l 2>&1 || true
'

collect_shell "cron_root.txt" '
crontab -u root -l 2>&1 || true
'

collect_shell "cron_all_users.txt" '
while IFS=: read -r user _; do
    echo "===== $user ====="
    crontab -u "$user" -l 2>/dev/null || true
done < /etc/passwd
'

collect_shell "cron_system.txt" '
for file in /etc/crontab /etc/cron.d/*; do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        ls -l "$file"
        cat "$file"
        echo
    fi
done

for directory in \
    /etc/cron.hourly \
    /etc/cron.daily \
    /etc/cron.weekly \
    /etc/cron.monthly
do
    if [ -d "$directory" ]; then
        echo "===== $directory ====="
        find "$directory" \
            -maxdepth 1 \
            -type f \
            -printf "%M %u:%g %p\n" \
            -exec sed -n "1,300p" {} \;
        echo
    fi
done
'

collect_shell "cron_runtime_processes.txt" '
ps auxww |
grep -Ei \
"[c]ron|[c]url|[w]get|192\.168\.1\.200" || true
'

collect_shell "persistence_files.txt" '
find \
    /etc/cron.d \
    /etc/init.d \
    /etc/rc.local \
    /etc/profile \
    /etc/profile.d \
    /root \
    /home \
    -maxdepth 4 \
    -type f \
    -print 2>/dev/null
'

###############################################################################
# 8. APPLICATION AND SENSITIVE FILE DISCOVERY
###############################################################################

echo "[+] Application and sensitive files"

collect_shell "logicorp_directories.txt" '
for directory in \
    /etc/logicorp \
    /opt/logicorp \
    /srv/ftp \
    /var/lib/logicorp \
    /usr/local/logicorp
do
    if [ -e "$directory" ]; then
        echo "===== $directory ====="
        find "$directory" \
            -maxdepth 6 \
            -printf "%M %u:%g %s %p\n" 2>/dev/null
        echo
    fi
done
'

collect_shell "logicorp_readable_files.txt" '
for directory in \
    /etc/logicorp \
    /opt/logicorp \
    /srv/ftp \
    /var/lib/logicorp \
    /usr/local/logicorp
do
    [ -d "$directory" ] || continue

    find "$directory" \
        -maxdepth 6 \
        -type f \
        -readable \
        -size -5M \
        -print \
        -exec sh -c '\''
            echo "===== $1 ====="
            sed -n "1,500p" "$1"
            echo
        '\'' sh {} \; 2>/dev/null
done
'

collect_shell "world_readable_sensitive_files.txt" '
find /etc /opt /srv /var/backups /home \
    -xdev \
    -type f \
    -perm -004 \
    \( \
        -iname "*.sql" \
        -o -iname "*.bak" \
        -o -iname "*.backup" \
        -o -iname "*.conf" \
        -o -iname "*.ini" \
        -o -iname "*.env" \
        -o -iname "*.key" \
        -o -iname "*.pem" \
        -o -iname "*password*" \
        -o -iname "*credential*" \
    \) \
    -printf "%M %u:%g %s %p\n" 2>/dev/null
'

collect_shell "sensitive_content_search.txt" '
grep -RniE \
"FLAG\{|password|passwd|credential|secret|token|api[_-]?key|root_password|PermitRootLogin|PasswordAuthentication" \
/etc/logicorp \
/opt/logicorp \
/srv/ftp \
/var/ftp \
/home/ftp \
/etc/vsftpd.conf \
/etc/vsftpd \
/etc/ftpusers \
/etc/pam.d/vsftpd \
/var/log/vsftpd.log \
/var/log/xferlog \
/var/log/proftpd \
/etc/cron.d \
/etc/fail2ban \
/var/backups \
2>/dev/null || true
'

###############################################################################
# 9. SUID, SGID AND LEGACY COMPONENTS
###############################################################################

echo "[+] Privileged and legacy components"

collect_shell "suid_sgid_files.txt" '
find / \
    -xdev \
    -type f \
    \( -perm -4000 -o -perm -2000 \) \
    -printf "%M %u:%g %p\n" 2>/dev/null |
    sort
'

collect_shell "telnet_artifacts.txt" '
getent passwd telnetd 2>/dev/null || true

find /etc /usr /var \
    -xdev \
    \( -iname "*telnet*" -o -iname "*rsh*" -o -iname "*rexec*" \) \
    -printf "%M %u:%g %p\n" 2>/dev/null
'


###############################################################################
# 10. FTP SECURITY AUDIT
###############################################################################

echo "[+] FTP security audit"

collect_shell "ftp_service.txt" '
echo "===== PROCESSES ====="
ps auxww | grep -E "[v]sftpd|[p]roftpd|[p]ure-ftpd" || true

echo
echo "===== LISTENING PORTS ====="
ss -ltnp 2>/dev/null | grep -E "(:21[[:space:]]|:20[[:space:]])" || true

echo
echo "===== INSTALLED PACKAGES ====="
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W vsftpd proftpd-basic pure-ftpd 2>/dev/null || true
fi
'

collect_shell "ftp_configuration.txt" '
for file in \
    /etc/vsftpd.conf \
    /etc/vsftpd/*.conf \
    /etc/proftpd/proftpd.conf \
    /etc/pure-ftpd/pure-ftpd.conf \
    /etc/ftpusers \
    /etc/vsftpd.user_list \
    /etc/vsftpd.chroot_list \
    /etc/pam.d/vsftpd
do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        ls -l "$file"
        sed -n "1,500p" "$file"
        echo
    fi
done
'

collect_shell "ftp_effective_security.txt" '
if [ -r /etc/vsftpd.conf ]; then
    echo "===== EFFECTIVE VSFTPD SETTINGS ====="

    grep -Ev "^[[:space:]]*(#|$)" /etc/vsftpd.conf |
    grep -Ei \
    "^(listen|listen_ipv6|anonymous_enable|local_enable|write_enable|anon_upload_enable|anon_mkdir_write_enable|anon_other_write_enable|chroot_local_user|allow_writeable_chroot|ssl_enable|force_local_logins_ssl|force_local_data_ssl|rsa_cert_file|rsa_private_key_file|pasv_enable|pasv_min_port|pasv_max_port|local_root|anon_root|hide_ids|download_enable|dirlist_enable|file_open_mode|local_umask|xferlog_enable|dual_log_enable|log_ftp_protocol|ftpd_banner|banner_file|userlist_enable|userlist_deny)=" || true
else
    echo "/etc/vsftpd.conf unavailable"
fi
'

collect_shell "ftp_files_permissions.txt" '
for directory in \
    /srv/ftp \
    /var/ftp \
    /home/ftp
do
    if [ -e "$directory" ]; then
        echo "===== $directory ====="

        find "$directory" \
            -maxdepth 8 \
            -printf "%M %u:%g %s %p\\n" 2>/dev/null

        echo
        echo "===== READABLE CONTENT ====="

        find "$directory" \
            -maxdepth 8 \
            -type f \
            -readable \
            -size -10M \
            -print \
            -exec sh -c '\''
                echo "----- $1 -----"
                sed -n "1,1000p" "$1"
                echo
            '\'' sh {} \; 2>/dev/null
    fi
done
'

collect_shell "ftp_logs.txt" '
for file in \
    /var/log/vsftpd.log \
    /var/log/xferlog \
    /var/log/proftpd/proftpd.log \
    /var/log/auth.log \
    /var/log/syslog
do
    if [ -r "$file" ]; then
        echo "===== $file ====="

        grep -Ei \
        "ftp|vsftpd|login|anonymous|upload|download|connect|failed|success|FLAG\\{" \
        "$file" 2>/dev/null |
        tail -n 1000

        echo
    fi
done
'

collect_shell "ftp_security_findings.txt" '
if [ -r /etc/vsftpd.conf ]; then
    anonymous_enable="$(
        awk -F= '\''
        /^[[:space:]]*anonymous_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        '\'' /etc/vsftpd.conf
    )"

    ssl_enable="$(
        awk -F= '\''
        /^[[:space:]]*ssl_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        '\'' /etc/vsftpd.conf
    )"

    write_enable="$(
        awk -F= '\''
        /^[[:space:]]*write_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        '\'' /etc/vsftpd.conf
    )"

    echo "anonymous_enable=${anonymous_enable:-DEFAULT/UNKNOWN}"
    echo "ssl_enable=${ssl_enable:-DEFAULT/UNKNOWN}"
    echo "write_enable=${write_enable:-DEFAULT/UNKNOWN}"

    if [ "$anonymous_enable" = "YES" ]; then
        echo "[HIGH] Anonymous FTP access is enabled"
    fi

    if [ "$ssl_enable" != "YES" ]; then
        echo "[HIGH] FTP communications are not protected by TLS"
    fi

    if [ "$write_enable" = "YES" ]; then
        echo "[MEDIUM] FTP write operations are enabled"
    fi
fi

if find /srv/ftp /var/ftp /home/ftp \
    -type d \
    -perm -0002 \
    -print -quit 2>/dev/null |
    grep -q .
then
    echo "[CRITICAL] A world-writable FTP directory was detected"
fi
'

collect_shell "ftp_flag_search.txt" '
grep -RniE \
"FLAG\\{[^}]+\\}" \
/etc/vsftpd.conf \
/etc/vsftpd \
/etc/ftpusers \
/etc/pam.d/vsftpd \
/srv/ftp \
/var/ftp \
/home/ftp \
/var/log/vsftpd.log \
/var/log/xferlog \
/var/log/proftpd \
2>/dev/null || true
'

###############################################################################
# 11. LOGS AND AUTHENTICATION EVIDENCE
###############################################################################

echo "[+] Authentication and security logs"

collect_shell "authentication_logs.txt" '
for file in \
    /var/log/auth.log \
    /var/log/secure \
    /var/log/syslog \
    /var/log/messages
do
    if [ -r "$file" ]; then
        echo "===== $file ====="

        grep -Ei \
        "accepted|failed|invalid user|root|sudo|authentication failure|session opened|session closed|blocked|ban|unban|FLAG\{" \
        "$file" 2>/dev/null |
        tail -n 500

        echo
    fi
done
'


collect_shell "authentication_logs_without_known_injections.txt" '
for file in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    [ -r "$file" ] || continue

    echo "===== $file ====="

    grep -Ei     "accepted|failed|invalid user|root|sudo|authentication failure|session opened|session closed|blocked|ban|unban"     "$file" 2>/dev/null |
    grep -Fv "Failed password for root from 10.10.10.10 port 5555 ssh2" |
    grep -Fv "Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2" |
    grep -Fv "Accepted password for root from 192.168.1.99 port 5555 ssh2" |
    tail -n 1000

    echo
done
'

collect_shell "intrusion_artifact_search.txt" '
grep -RniE "(chpasswd|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)|/dev/tcp|bash[[:space:]]+-i|nc[[:space:]].*(-e|--exec)|socat.*EXEC|curl.+\|[[:space:]]*(sh|bash)|wget.+\|[[:space:]]*(sh|bash))" /opt /usr/local /srv /root /home /tmp /var/tmp /etc/cron.d /etc/profile.d 2>/dev/null || true
'

collect_shell "all_recent_logs.txt" '
find /var/log \
    -maxdepth 3 \
    -type f \
    -readable \
    -printf "%M %u:%g %s %p\n" 2>/dev/null
'

collect_shell "logs_flag_search.txt" '
grep -RniE "FLAG\{" /var/log 2>/dev/null || true
'

###############################################################################
# 12. GLOBAL FLAG SEARCH
###############################################################################

echo "[+] Recovering audit flags"

collect_shell "flag_search_targeted.txt" '
grep -RniE \
"FLAG\{[^}]+\}" \
/etc/logicorp \
/opt/logicorp \
/srv/ftp \
/etc/cron.d \
/etc/fail2ban \
/var/log \
/var/backups \
/root \
/home \
2>/dev/null || true
'

extract_flags
cp "$FLAGS_FILE" "$FLAGS_DIR/recovered_flags.txt" 2>/dev/null || true

cat > "$EVIDENCE_DIR/README.md" <<EOF
# Audit evidence directory

This directory contains the evidence collected by \`audit.sh\`. Files are grouped
by audit domain to simplify navigation and review.

| Directory | Contents |
|---|---|
| \`01_system/\` | Host identity, OS, processes, mounts and startup scripts |
| \`02_network/\` | Interfaces, routes, neighbors, DNS, bridges and VLANs |
| \`03_attack_surface/\` | Listening ports, active connections and exposed processes |
| \`04_security_controls/\` | Firewall, SELinux, AppArmor, Fail2Ban and Suricata |
| \`05_users_access/\` | Accounts, privileges, keys and sensitive permissions |
| \`06_ssh/\` | SSH configuration and effective security settings |
| \`07_services/\` | Running, installed and legacy services |
| \`08_persistence/\` | Cron jobs and persistence mechanisms |
| \`09_ftp/\` | FTP service, configuration, permissions and findings |
| \`10_sensitive_data/\` | LogiCorp files and exposed secrets |
| \`11_logs/\` | Authentication, system and application logs |
| \`12_intrusion_analysis/\` | Injected events and unexplained intrusion indicators |
| \`13_flags/\` | Recovered flags, targeted searches and evidence index |

## Important

Files in \`12_intrusion_analysis/\` distinguish laboratory-generated events
from unexplained evidence. Injected log lines must not be treated as independent
proof of a real compromise.
EOF

find "$EVIDENCE_DIR" -mindepth 2 -maxdepth 2 -type f \
    -printf '%p\n' 2>/dev/null | sort > "$FLAGS_DIR/evidence_file_index.txt"

###############################################################################
# 13. REPORT GENERATION
###############################################################################

echo "[+] Generating AUDIT_REPORT.md"

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo Unknown)"
KERNEL_VALUE="$(uname -r 2>/dev/null || echo Unknown)"
ARCH_VALUE="$(uname -m 2>/dev/null || echo Unknown)"
UPTIME_VALUE="$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo Unknown)"
CURRENT_USER="$(id -un 2>/dev/null || echo Unknown)"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    OS_VALUE="${PRETTY_NAME:-Unknown}"
else
    OS_VALUE="Unknown"
fi

INTERFACES="$(
    ip -br address show 2>/dev/null |
    sed 's/`/\\`/g'
)"

ROUTES="$(
    ip route show 2>/dev/null |
    sed 's/`/\\`/g'
)"

PORTS="$(
    if command_exists ss; then
        ss -tulpen 2>/dev/null
    else
        netstat -tulpen 2>/dev/null
    fi |
    sed 's/`/\\`/g'
)"

SSH_ROOT_LOGIN="$(
    sshd -T 2>/dev/null |
    awk '$1 == "permitrootlogin" {print $2; exit}'
)"

SSH_PASSWORD_AUTH="$(
    sshd -T 2>/dev/null |
    awk '$1 == "passwordauthentication" {print $2; exit}'
)"

FIREWALL_RESULT="No active firewall rules confirmed"

if command_exists nft &&
   nft list ruleset 2>/dev/null |
   grep -qE "hook (input|forward|output)"; then
    FIREWALL_RESULT="nftables rules detected"
fi

if command_exists iptables &&
   iptables -S 2>/dev/null |
   grep -qE "^-A |^-P "; then
    FIREWALL_RESULT="iptables configuration detected"
fi

FLAGS_CONTENT="$(cat "$FLAGS_FILE" 2>/dev/null)"


LAB_SIMULATION_STATUS="No explicit log injection detected in startup scripts"
if grep -qiE "fake attack log|brute force source" "$(evidence_path "startup_security_analysis.txt")" 2>/dev/null ||
   grep -qE "auth\\.log|suricata/fast\\.log" "$(evidence_path "startup_injected_log_entries.txt")" 2>/dev/null; then
    LAB_SIMULATION_STATUS="Startup scripts explicitly inject simulated attack events into log files"
fi

PASSWORD_INIT_STATUS="No startup password change detected"
if grep -qiE "chpasswd|passwd|usermod|useradd" "$(evidence_path "startup_password_changes.txt")" 2>/dev/null; then
    PASSWORD_INIT_STATUS="A startup script changes account passwords; context and intent must be verified"
fi

FILTERED_AUTH_COUNT="$(
    grep -Eci "accepted|failed|invalid user|authentication failure" \
    "$(evidence_path "authentication_logs_without_known_injections.txt")" 2>/dev/null || true
)"

INTRUSION_ARTIFACT_COUNT="$(
    grep -cE "^[^C].*:[0-9]+:" "$(evidence_path "intrusion_artifact_search.txt")" 2>/dev/null || true
)"

INTRUSION_ASSESSMENT="No intrusion can be confirmed or excluded from this automated audit alone"
if [ "$INTRUSION_ARTIFACT_COUNT" -gt 0 ] 2>/dev/null || [ "$FILTERED_AUTH_COUNT" -gt 0 ] 2>/dev/null; then
    INTRUSION_ASSESSMENT="Unexplained indicators remain after known simulated events are excluded; manual correlation is required"
elif [ "$LAB_SIMULATION_STATUS" != "No explicit log injection detected in startup scripts" ]; then
    INTRUSION_ASSESSMENT="The visible attack-log entries are explained by laboratory initialization; no independent compromise is confirmed"
fi

cat > "$REPORT" <<EOF
# Audit Report - LogiCorp Gateway

## Executive Overview

A live technical assessment was performed directly on the LogiCorp gateway.
The audit examined the runtime environment, network topology, exposed services,
security controls, user access, scheduled tasks, application files, logs and
potential persistence mechanisms.

The assessment was conducted in read-only mode. Because the environment does
not necessarily use systemd as PID 1, findings are based primarily on process
inspection, network sockets, configuration files, startup scripts and runtime
artifacts.

The audit also distinguishes observed runtime activity from events deliberately
written into logs by laboratory initialization scripts. Injected log lines are
not treated as independent proof of a real intrusion.

## Scope and Method

- Assessment type: black-box technical audit
- Collection date: $AUDIT_DATE
- Current user: $CURRENT_USER
- Evidence directory: \`$EVIDENCE_DIR/\`

## Evidence directory structure

| Directory | Contents |
|---|---|
| \`01_system/\` | Host, operating system, processes, mounts and startup scripts |
| \`02_network/\` | Interfaces, routes, neighbors, DNS, bridges and VLANs |
| \`03_attack_surface/\` | Listening ports, active connections and exposed processes |
| \`04_security_controls/\` | Firewall, SELinux, AppArmor, Fail2Ban and Suricata |
| \`05_users_access/\` | Accounts, privileges, SSH keys and sensitive permissions |
| \`06_ssh/\` | SSH configuration and effective security settings |
| \`07_services/\` | Running and installed services, including legacy services |
| \`08_persistence/\` | Cron jobs and other persistence mechanisms |
| \`09_ftp/\` | FTP service, configuration, permissions and findings |
| \`10_sensitive_data/\` | LogiCorp files and exposed secrets |
| \`11_logs/\` | Authentication, system and application logs |
| \`12_intrusion_analysis/\` | Injected events, unexplained activity and intrusion artifacts |
| \`13_flags/\` | Targeted flag searches and evidence index |
- System modifications: none

## 1. System Information

- Hostname: \`$HOSTNAME_VALUE\`
- OS: \`$OS_VALUE\`
- Kernel: \`$KERNEL_VALUE\`
- Architecture: \`$ARCH_VALUE\`
- Uptime: \`$UPTIME_VALUE\`

### PID 1

\`\`\`text
$(cat "$(evidence_path "system_pid1.txt")")
\`\`\`


### Startup Script Security Analysis

- Lab simulation assessment: \`$LAB_SIMULATION_STATUS\`
- Password initialization assessment: \`$PASSWORD_INIT_STATUS\`

\`\`\`text
$(cat "$(evidence_path "startup_security_analysis.txt")")
\`\`\`

### Log Entries Injected by Startup Scripts

\`\`\`text
$(cat "$(evidence_path "startup_injected_log_entries.txt")")
\`\`\`

The presence of commands such as \`chpasswd\`, \`nft flush ruleset\`, \`ttyd\`
or \`openvscode-server\` in a startup script confirms insecure initialization
or exposure. It does not, by itself, prove that an external attacker executed
the commands.

## 2. Network Topology

### Interfaces

\`\`\`text
$INTERFACES
\`\`\`

### Routes

\`\`\`text
$ROUTES
\`\`\`

### ARP and Neighbor Table

\`\`\`text
$(cat "$(evidence_path "network_neighbors.txt")")
\`\`\`

### Topology Observations

The observed interfaces, addresses, routes and neighbors must be compared with
the documented flat network in \`192.168.1.0/24\`. Any different ranges,
additional interfaces, bridges or VLANs constitute documentation discrepancies.

## 3. Attack Surface

### Listening TCP and UDP Ports

\`\`\`text
$PORTS
\`\`\`

### Network-Facing Processes

\`\`\`text
$(cat "$(evidence_path "network_processes.txt")")
\`\`\`

### Full Process Arguments

\`\`\`text
$(sed -n '1,300p' "$(evidence_path "process_command_lines.txt")")
\`\`\`

## 4. Security Controls

- Firewall observation: \`$FIREWALL_RESULT\`
- SSH PermitRootLogin: \`${SSH_ROOT_LOGIN:-Unknown}\`
- SSH PasswordAuthentication: \`${SSH_PASSWORD_AUTH:-Unknown}\`

### nftables

\`\`\`text
$(cat "$(evidence_path "firewall_nftables.txt")")
\`\`\`

### iptables

\`\`\`text
$(cat "$(evidence_path "firewall_iptables.txt")")
\`\`\`

### SELinux

\`\`\`text
$(cat "$(evidence_path "security_selinux.txt")")
\`\`\`

### AppArmor

\`\`\`text
$(cat "$(evidence_path "security_apparmor.txt")")
\`\`\`

## 5. Access Control and Identity

### Login-Capable Users

\`\`\`text
$(cat "$(evidence_path "users_login_capable.txt")")
\`\`\`

### UID 0 Accounts

\`\`\`text
$(cat "$(evidence_path "users_uid0.txt")")
\`\`\`

### Administrative Groups

\`\`\`text
$(cat "$(evidence_path "users_admin_groups.txt")")
\`\`\`

### Effective SSH Security Settings

\`\`\`text
$(cat "$(evidence_path "ssh_security_values.txt")")
\`\`\`

## 6. Running Services

\`\`\`text
$(cat "$(evidence_path "services_status.txt")")
\`\`\`

### Relevant Runtime Processes

\`\`\`text
$(cat "$(evidence_path "network_processes.txt")")
\`\`\`

## 7. Scheduled Tasks and Persistence

### System Cron Files

\`\`\`text
$(cat "$(evidence_path "cron_system.txt")")
\`\`\`

### Runtime Cron-Related Processes

\`\`\`text
$(cat "$(evidence_path "cron_runtime_processes.txt")")
\`\`\`

Any undocumented root cron command, repeated outbound connection, downloaded
script or command contacting an unexpected system should be treated as a
potential persistence or beaconing mechanism.

## 8. Sensitive Data Exposure

### LogiCorp Files

\`\`\`text
$(sed -n '1,500p' "$(evidence_path "logicorp_readable_files.txt")")
\`\`\`

### Sensitive Content Matches

\`\`\`text
$(sed -n '1,500p' "$(evidence_path "sensitive_content_search.txt")")
\`\`\`

## 9. FTP Security Assessment

### FTP Configuration

\`\`\`text
$(cat "$(evidence_path "ftp_effective_security.txt")")
\`\`\`

### FTP Security Findings

\`\`\`text
$(cat "$(evidence_path "ftp_security_findings.txt")")
\`\`\`

### FTP Files and Permissions

\`\`\`text
$(sed -n '1,500p' "$(evidence_path "ftp_files_permissions.txt")")
\`\`\`

### FTP Log Evidence

\`\`\`text
$(sed -n '1,500p' "$(evidence_path "ftp_logs.txt")")
\`\`\`

## 10. Authentication and Intrusion Evidence

### Raw Authentication Evidence

\`\`\`text
$(sed -n '1,500p' "$(evidence_path "authentication_logs.txt")")
\`\`\`

### Authentication Evidence After Excluding Known Lab Injections

\`\`\`text
$(sed -n '1,1000p' "$(evidence_path "authentication_logs_without_known_injections.txt")")
\`\`\`

### Additional Intrusion Artifact Search

\`\`\`text
$(sed -n '1,1000p' "$(evidence_path "intrusion_artifact_search.txt")")
\`\`\`

### Assessment

- Filtered authentication indicators: \`$FILTERED_AUTH_COUNT\`
- Additional suspicious artifact matches: \`$INTRUSION_ARTIFACT_COUNT\`
- Conclusion: **$INTRUSION_ASSESSMENT**

Authentication records that are reproduced verbatim by \`/etc/run.sh\` or
another startup script must be classified as simulated laboratory evidence.
Only events remaining after this exclusion should be correlated with file
timestamps, process activity, SSH keys, cron jobs and network connections.

## 11. Discrepancies vs Documentation

The following documentation items must be compared with runtime evidence:

- documented network \`192.168.1.0/24\` versus observed addressing;
- documented SSH exposure versus actual listening interfaces;
- documented FTP requirement versus actual FTP configuration;
- claimed absence of firewall versus observed rules;
- documented services versus additional ports and processes;
- claimed absence of segmentation versus detected interfaces, bridges or VLANs;
- documented administration methods versus remote shell or development tools;
- documented operational tasks versus actual cron jobs and startup scripts.

## 12. Risk Matrix

### Critical

- Independently verified unauthorized root SSH login
- Unauthorized root scheduled task or unexplained outbound beacon
- Exposed remote shell service
- Database exposed to unauthorized networks
- Sensitive administrative credentials in readable files

### High

- Cleartext FTP
- No effective firewall enforcement
- Development tools exposed on all interfaces
- World-readable backup or configuration files
- Unknown SSH keys, privileged accounts or unexplained password changes

### Medium

- Legacy Telnet components
- Missing SELinux or AppArmor enforcement
- Undocumented services or scheduled tasks
- Incomplete security monitoring

### Low

- Documentation and network topology drift

## 13. Flags Recovered During Audit

\`\`\`text
${FLAGS_CONTENT:-No FLAG value recovered}
\`\`\`

## 14. Preliminary Recommendations

1. Disable direct SSH root login.
2. Disable SSH password authentication where possible.
3. Restrict administrative access through a VPN or trusted source ranges.
4. Remove unauthorized remote shell and development services.
5. Investigate all undocumented root cron jobs.
6. Apply a default-deny firewall policy.
7. Isolate Finance, Guest, internal systems and the database.
8. Protect the legacy FTP workflow with a secure tunnel or VPN.
9. Rotate credentials exposed in configuration or backup files.
10. Remove world-readable permissions from sensitive files.
11. Separate simulated laboratory log entries from genuine authentication events.
12. Review all authentication activity remaining after known injected events are removed.
13. Replace the predictable root-password initialization mechanism with a secure secret.
14. Correct startup redirections such as \`2&>1\` to \`>/dev/null 2>&1\` where intended.
15. Establish centralized logging and monitoring with tamper-resistant log collection.

## Conclusion

The live audit provides technical evidence of the actual state of the LogiCorp
gateway and identifies discrepancies that cannot be discovered from
documentation alone.

The startup configuration demonstrates that some apparent attack evidence is
artificially generated by the laboratory. Consequently, those injected SSH and
Suricata entries do not confirm a real intrusion. The same startup script still
confirms serious security weaknesses, including predictable root-password
initialization, firewall removal and exposed remote administration services.

This audit cannot prove that no intrusion occurred. A compromise should only be
confirmed when independent evidence remains after known simulated events are
excluded and correlated across authentication logs, processes, files, cron,
SSH keys and network activity.
EOF

echo
echo "[+] Audit complete"
echo "[+] Report: $REPORT"
organize_evidence_files

echo "[+] Evidence tree:"
find "$EVIDENCE_DIR" -maxdepth 2 -type f | sort
echo
echo "[+] Evidence: $EVIDENCE_DIR/"
echo "[+] Flags: $FLAGS_FILE"
echo

cat "$FLAGS_FILE"