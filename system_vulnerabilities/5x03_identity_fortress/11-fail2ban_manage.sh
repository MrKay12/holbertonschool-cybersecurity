#!/bin/bash
# 11-fail2ban_manage.sh
# Manage fail2ban jails and bans.
#
# Usage: sudo ./11-fail2ban_manage.sh status       service + per-jail stats
#        sudo ./11-fail2ban_manage.sh banned       banned IPs with ban times
#        sudo ./11-fail2ban_manage.sh unban <ip>   unban an IP from every jail

usage() {
    echo "Usage: $0 status | banned | unban <ip>" >&2
    exit 1
}

[ $# -ge 1 ] || usage
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0 $*)" >&2
    exit 1
fi
export LC_ALL=C

# fail2ban must be running for any command
if ! systemctl is-active --quiet fail2ban || ! fail2ban-client ping >/dev/null 2>&1; then
    echo "Error: fail2ban is not running (run 10-configure_fail2ban.sh)" >&2
    exit 1
fi

# "Jail list:  sshd, recidive" -> "sshd recidive"
jails() {
    fail2ban-client status | sed -nE 's/.*Jail list:[[:space:]]*//p' | tr -d ',' | xargs
}

# Value of a "<label>:  <value>" line from `fail2ban-client status <jail>`
stat() {
    echo "$1" | awk -F':' -v k="$2" '$1 ~ k {sub(/^[[:space:]]+/, "", $2); print $2; exit}'
}

if [[ $1 = "status" ]]; then
    echo "=== fail2ban Status ==="
    echo
    echo "Service: Active"
    list=$(jails)
    echo "Jails: $(echo "$list" | sed 's/ /, /g')"
    for jail in $list; do
        s=$(fail2ban-client status "$jail")
        echo
        echo "[$jail] Statistics:"
        echo "  Currently banned: $(stat "$s" 'Currently banned')"
        echo "  Total banned: $(stat "$s" 'Total banned')"
        echo "  Currently failed: $(stat "$s" 'Currently failed')"
    done

elif [[ $1 = "banned" ]]; then
    echo "=== Banned IPs ==="
    for jail in $(jails); do
        echo
        echo "Jail: $jail"
        # fail2ban >= 0.11: "IP <tab> YYYY-MM-DD HH:MM:SS + secs = YYYY-MM-DD HH:MM:SS"
        timed=$(fail2ban-client get "$jail" banip --with-time 2>/dev/null)
        if [ $? -eq 0 ] && echo "$timed" | grep -q ' = '; then
            # fields: 1=IP 2,3=ban date/time 4=+ 5=secs 6== 7,8=expiry date/time
            echo "$timed" | awk 'NF >= 8 {
                printf "  %s (banned at %s, expires %s)\n", $1, substr($3, 1, 5), substr($8, 1, 5)
            }'
        else
            # older fail2ban: IPs only
            ips=$(stat "$(fail2ban-client status "$jail")" 'Banned IP list')
            for ip in $ips; do echo "  $ip"; done
            timed=$ips
        fi
        [ -z "$(echo "$timed" | tr -d '[:space:]')" ] && echo "  None"
    done

elif [[ $1 = "unban" ]]; then
    ip="$2"
    [ -n "$ip" ] || usage
    if ! echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$'; then
        echo "Error: not an IP address: $ip" >&2
        exit 1
    fi
    found=0
    for jail in $(jails); do
        banned=$(stat "$(fail2ban-client status "$jail")" 'Banned IP list')
        echo " $banned " | grep -q " $ip " || continue
        found=1
        fail2ban-client set "$jail" unbanip "$ip" >/dev/null
        # Verify it is really gone
        banned=$(stat "$(fail2ban-client status "$jail")" 'Banned IP list')
        if echo " $banned " | grep -q " $ip "; then
            echo "IP $ip: unban from jail $jail FAILED" >&2
            exit 1
        fi
        echo "IP $ip unbanned from jail $jail"
    done
    if [ "$found" -eq 0 ]; then
        echo "IP $ip is not banned in any jail"
    fi

else
    usage
fi
