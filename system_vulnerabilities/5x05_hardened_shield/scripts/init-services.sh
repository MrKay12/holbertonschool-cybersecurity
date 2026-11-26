#!/bin/bash
# init-services.sh - container entrypoint (runs under tini as PID 1's child)
#
# 1. runtime hardening checks  (init-hardening.sh --runtime)
# 2. runtime identity setup    (init-identity.sh --runtime)
# 3. prepares writable runtime dirs (works with --read-only + tmpfs)
# 4. validates sshd and nginx configs, then starts:
#      sshd      root (privilege separation), logs to stdout + /var/log/ssh/auth.log
#      nginx     entirely as appuser on :8080 (setpriv, no root process)
#      fail2ban  only when iptables is usable (cap NET_ADMIN), FAIL2BAN_ENABLED!=false
# 5. supervises: if any service exits, the others are stopped and the
#    container exits non-zero so the restart policy brings it back.
# No manual step is needed after "docker run".
set -euo pipefail

STATE_DIR="/run/hardened-shield"
SSH_LOG="/var/log/ssh/auth.log"
PIDS=()

log() { printf '%s [init-services] %s\n' "$(date -u +%FT%TZ)" "$*"; }

[ "$(id -u)" -eq 0 ] || { log "must start as root: sshd needs it, nginx is dropped to appuser"; exit 1; }
umask 027

# If a command is given (docker run IMAGE audit.py), run it instead.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

/usr/local/sbin/init-hardening.sh --runtime
/usr/local/sbin/init-identity.sh --runtime

APP_UID=$(id -u appuser)
APP_GID=$(id -g appuser)

# Runtime directories (recreated on every start: /run, /var/log and
# /var/lib/nginx may be tmpfs on a read-only root filesystem)
install -d -m 0755 -o root -g root /run/sshd
install -d -m 0750 -o root -g adm /var/log/ssh
touch "$SSH_LOG" && chown root:adm "$SSH_LOG" && chmod 0640 "$SSH_LOG"
install -d -m 0750 -o appuser -g appuser /run/nginx /var/log/nginx /var/lib/nginx
for d in body proxy fastcgi uwsgi scgi; do
    install -d -m 0700 -o appuser -g appuser "/var/lib/nginx/$d"
done
install -d -m 0755 -o root -g root /var/run/faillock

mapfile -t SSHD_ARGS < "$STATE_DIR/sshd.args"

as_app() {
    setpriv --reuid="$APP_UID" --regid="$APP_GID" --init-groups \
            --no-new-privs --inh-caps=-all -- "$@"
}

log "validating configurations"
/usr/sbin/sshd -t "${SSHD_ARGS[@]}"
as_app /usr/sbin/nginx -t -q

# sshd -e writes to stderr without timestamps: add them so fail2ban (and
# humans) can use the log, and copy every line to docker logs.
HOST=$(hostname)
ssh_logger() {
    local line
    while IFS= read -r line; do
        printf '%(%b %e %H:%M:%S)T %s sshd[1]: %s\n' -1 "$HOST" "$line"
    done | tee -a "$SSH_LOG"
}

stop_all() {
    log "stopping services"
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    wait || true
}
trap 'stop_all; exit 0' TERM INT

log "starting sshd"
/usr/sbin/sshd -D -e "${SSHD_ARGS[@]}" 2> >(ssh_logger) &
PIDS+=("$!")

log "starting nginx as appuser (uid $APP_UID) on :8080"
as_app /usr/sbin/nginx -g 'daemon off;' &
PIDS+=("$!")

if [ "${FAIL2BAN_ENABLED:-auto}" != false ] && iptables -n -L >/dev/null 2>&1; then
    install -d -m 0750 -o root -g root /run/fail2ban /var/lib/fail2ban
    log "starting fail2ban"
    /usr/bin/fail2ban-server -xf start &
    PIDS+=("$!")
else
    log "fail2ban not started (needs NET_ADMIN/NET_RAW or FAIL2BAN_ENABLED=false); faillock + MaxAuthTries still apply"
fi

log "ready: web :8080, ssh :22 - run 'audit.py' for a compliance check"

set +e
wait -n "${PIDS[@]}"
rc=$?
log "a service exited (code $rc): shutting down"
stop_all
exit $(( rc == 0 ? 1 : rc ))
