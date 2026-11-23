#!/bin/bash
# 9-faillock_manage.sh
# Manage pam_faillock lockouts.
#
# Usage: sudo ./9-faillock_manage.sh status          list locked accounts
#        sudo ./9-faillock_manage.sh show <user>     failures + lock state
#        sudo ./9-faillock_manage.sh reset <user>    clear the lock
#
# A user is locked when it has at least <deny> valid failures within
# <fail_interval> seconds; the lock lasts <unlock_time> seconds after the
# last failure (0 = until an admin reset). Values come from faillock.conf.

CONF="/etc/security/faillock.conf"

usage() {
    echo "Usage: $0 status | show <user> | reset <user>" >&2
    exit 1
}

[ $# -ge 1 ] || usage
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0 $*)" >&2
    exit 1
fi

# faillock.conf value, or the pam_faillock default
conf() {
    local v
    v=$(awk -F= -v k="$1" '{gsub(/[[:space:]]/, "", $1)} $1 == k {gsub(/[[:space:]]/, "", $2); v = $2} END {print v}' \
        "$CONF" 2>/dev/null)
    echo "${v:-$2}"
}
DENY=$(conf deny 3)
UNLOCK=$(conf unlock_time 600)
INTERVAL=$(conf fail_interval 900)

# Records of `faillock` output as: user|YYYY-MM-DD HH:MM:SS|type|source|V/I
records() {
    LC_ALL=C faillock "$@" 2>/dev/null | awk '
        /^[^[:space:]]+:$/ { user = substr($0, 1, length($0) - 1); next }
        /^When/            { next }
        /^[0-9]{4}-[0-9]{2}-[0-9]{2} / {
            valid = $NF
            src = (NF >= 5) ? $4 : "-"           # TTY/RHOST/SVC source
            print user "|" $1 " " $2 "|" $3 "|" src "|" valid
        }'
}

# Lock state of one user from its records on stdin.
# Prints: <failures> <locked 0/1> <unlock epoch, 0 = admin reset only>
lock_state() {
    local now last=0 t fails=0 user when type src valid
    now=$(date +%s)
    local times=()
    while IFS='|' read -r user when type src valid; do
        [ "$valid" = "V" ] || continue
        t=$(date -d "$when" +%s) || continue
        times+=("$t")
        [ "$t" -gt "$last" ] && last=$t
    done
    # valid failures inside the window ending at the last failure
    for t in "${times[@]}"; do
        [ "$t" -ge $((last - INTERVAL)) ] && fails=$((fails + 1))
    done
    if [ "$fails" -ge "$DENY" ] && { [ "$UNLOCK" -eq 0 ] || [ $((last + UNLOCK)) -gt "$now" ]; }; then
        if [ "$UNLOCK" -eq 0 ]; then echo "$fails 1 0"; else echo "$fails 1 $((last + UNLOCK))"; fi
    else
        echo "$fails 0 0"
    fi
}

check_user() {
    [ -n "$1" ] || usage
    if ! id "$1" >/dev/null 2>&1; then
        echo "Error: no such user: $1" >&2
        exit 1
    fi
}

case "$1" in
    status)
        echo "=== Faillock Status ==="
        echo
        echo "Locked accounts:"
        found=0
        all=$(records)
        for user in $(echo "$all" | cut -d'|' -f1 | sort -u); do
            read -r fails locked until <<< "$(echo "$all" | awk -F'|' -v u="$user" '$1 == u' | lock_state)"
            [ "$locked" -eq 1 ] || continue
            found=1
            if [ "$until" -eq 0 ]; then
                echo "  $user: $fails failures (locked until admin reset)"
            else
                echo "  $user: $fails failures (locked until $(date -d "@$until" +%H:%M:%S))"
            fi
        done
        [ "$found" -eq 0 ] && echo "  None"
        ;;

    show)
        user="$2"
        check_user "$user"
        echo "=== Faillock Details: $user ==="
        echo
        recs=$(records --user $user)
        echo "Recent failures:"
        if [ -z "$recs" ]; then
            echo "  None"
        fi
        while IFS='|' read -r _ when type src valid; do
            [ -n "$when" ] || continue
            case "$type" in
                RHOST) how="from $src" ;;
                TTY)   how="on $src" ;;
                *)     how="via $src" ;;
            esac
            note=""; [ "$valid" = "V" ] || note=" (expired)"
            echo "  $when - Failed auth $how$note"
        done <<< "$recs"
        echo
        read -r fails locked until <<< "$(echo "$recs" | lock_state)"
        if [ "$locked" -eq 1 ]; then
            echo "Status: LOCKED"
            if [ "$until" -eq 0 ]; then
                echo "Unlocks automatically at: never (admin reset required)"
            else
                echo "Unlocks automatically at: $(date -d "@$until" +%H:%M:%S)"
            fi
        else
            echo "Status: NOT LOCKED ($fails/$DENY failures)"
        fi
        ;;

    reset)
        user="$2"
        check_user "$user"
        faillock --user $user --reset
        # Verify: no valid failure left
        if [ -z "$(records --user $user | grep '|V$')" ]; then
            echo "Account $user: Lock cleared"
        else
            echo "Account $user: reset FAILED" >&2
            exit 1
        fi
        ;;

    *)
        usage
        ;;
esac
