#!/bin/bash
# =============================================================================
# init-services.sh - NovaTech Hardened Shield: service management
# =============================================================================
# Container entrypoint (under tini) and service control tool.
#
# Services
#   sshd      remote administration, :22, root (privilege separation, PAM)
#   nginx     web server, :8080, master AND workers as appuser (no root)
#   fail2ban  optional: only when iptables works (cap NET_ADMIN + NET_RAW)
#             and FAIL2BAN_ENABLED is not "false"
#
# Modes
#   (none) | --start   entrypoint: runtime hardening + identity checks,
#                      config tests, start every service that is not already
#                      running, verify them, then supervise in the foreground.
#                      If a service dies the others are stopped and the
#                      container exits 1, so the restart policy recovers it.
#   --status           human-readable state of every service
#   --health           health checks only, quiet (Docker HEALTHCHECK)
#   --reload           test configs, then reload nginx and sshd in place
#   --stop             graceful stop of every service
#   -h | --help        this help
#   <command>          anything else is executed instead (docker run IMAGE audit.py)
#
# Idempotent: a service that is already running and healthy is never started
# twice; --status / --health change nothing.
#
# Health checks
#   sshd   process alive (pidfile + name), port open, SSH-2.0 banner answered
#   nginx  process alive, port open, GET /health = 200 "OK", no nginx
#          process running as root
#   fail2ban (when started) "fail2ban-client ping" answers pong
#
# Exit codes
#   0  success / healthy / clean shutdown
#   1  a service failed to start, is unhealthy, or died
#   2  usage error / not run as root
#   3  pre-start checks failed (init-hardening, init-identity, config test)
#
# Environment
#   WEB_PORT=8080  SSH_PORT=22  START_TIMEOUT=20  FAIL2BAN_ENABLED=auto|false
# =============================================================================
set -uo pipefail

WEB_PORT="${WEB_PORT:-8080}"
SSH_PORT="${SSH_PORT:-22}"
START_TIMEOUT="${START_TIMEOUT:-20}"
APP_USER="appuser"

STATE_DIR="/run/hardened-shield"
SSHD_PIDFILE="/run/sshd.pid"
NGINX_PIDFILE="/run/nginx/nginx.pid"
F2B_PIDFILE="/run/fail2ban/fail2ban.pid"
SSH_LOG="/var/log/ssh/auth.log"

PIDS=()          # children started by this process (supervision)
QUIET=0
FAILS=0

log()  { [ "$QUIET" -eq 1 ] || printf '%s [init-services] %-5s %s\n' "$(date -u +%FT%TZ)" "$1" "$2"; }
ok()   { log OK "$1"; }
bad()  { log FAIL "$1"; FAILS=$((FAILS + 1)); }
info() { log INFO "$1"; }

# =============================================================================
# Helpers
# =============================================================================
# pid_of NAME PIDFILE -> prints the PID if the pidfile points to a live NAME
pid_of() {
    local name="$1" file="$2" pid
    [ -r "$file" ] || return 1
    pid=$(tr -dc '0-9' < "$file")
    # /proc rather than kill -0: kill -0 fails with EPERM on another user's
    # process, which would report a live service as dead.
    [ -n "$pid" ] && [ -d "/proc/$pid" ] || return 1
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "$name" ] || return 1
    echo "$pid"
}

port_open() {   # port_open PORT
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

ssh_banner() {  # prints the SSH identification string
    local banner=""
    exec 3<>"/dev/tcp/127.0.0.1/$SSH_PORT" 2>/dev/null || return 1
    IFS= read -r -t 3 banner <&3
    exec 3<&- 3>&-
    banner="${banner%$'\r'}"
    [[ "$banner" == SSH-2.0-* ]] && echo "$banner"
}

as_app() {
    setpriv --reuid="$(id -u "$APP_USER")" --regid="$(id -g "$APP_USER")" \
            --init-groups --no-new-privs --inh-caps=-all -- "$@"
}

sshd_args() {
    SSHD_ARGS=()
    if [ -r "$STATE_DIR/sshd.args" ]; then
        mapfile -t SSHD_ARGS < "$STATE_DIR/sshd.args"
    fi
}

f2b_wanted() {
    [ "${FAIL2BAN_ENABLED:-auto}" != false ] && iptables -n -L >/dev/null 2>&1
}

# =============================================================================
# Health checks (no side effects)
# =============================================================================
check_sshd() {
    local pid banner
    if pid=$(pid_of sshd "$SSHD_PIDFILE"); then
        ok "sshd running (pid $pid, user $(ps -o user= -p "$pid" | xargs))"
    else
        bad "sshd not running"
        return 1
    fi
    if banner=$(ssh_banner); then
        ok "sshd answers on :$SSH_PORT ($banner)"
    else
        bad "sshd: no SSH-2.0 banner on :$SSH_PORT"
        return 1
    fi
}

check_nginx() {
    local pid body root_procs
    if pid=$(pid_of nginx "$NGINX_PIDFILE"); then
        ok "nginx running (master pid $pid, user $(ps -o user= -p "$pid" | xargs))"
    else
        bad "nginx not running"
        return 1
    fi
    root_procs=$(ps -C nginx -o user=,pid= | awk '$1 == "root" {print $2}' | xargs)
    if [ -z "$root_procs" ]; then
        ok "nginx: no process running as root"
    else
        bad "nginx processes running as root: $root_procs"
    fi
    if ! port_open "$WEB_PORT"; then
        bad "nginx: port $WEB_PORT closed"
        return 1
    fi
    if body=$(curl -fsS --max-time 3 "http://127.0.0.1:$WEB_PORT/health" 2>/dev/null) \
       && [ "${body//[$'\r\n']/}" = "OK" ]; then
        ok "nginx: GET /health -> 200 OK on :$WEB_PORT"
    else
        bad "nginx: /health check failed on :$WEB_PORT"
        return 1
    fi
}

check_fail2ban() {
    local pid
    if ! pid=$(pid_of fail2ban-server "$F2B_PIDFILE"); then
        if f2b_wanted; then bad "fail2ban not running"; return 1; fi
        info "fail2ban not started (no NET_ADMIN or FAIL2BAN_ENABLED=false)"
        return 0
    fi
    if fail2ban-client ping 2>/dev/null | grep -q pong; then
        ok "fail2ban running (pid $pid), $(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/ {gsub(/^[ \t]+/, "", $2); print "jails: " $2}')"
    else
        bad "fail2ban: server does not answer ping"
        return 1
    fi
}

check_all() {
    FAILS=0
    check_sshd
    check_nginx
    check_fail2ban
    [ "$FAILS" -eq 0 ]
}

# =============================================================================
# Start (each step skips a service that is already running)
# =============================================================================
prepare_dirs() {
    # Recreated on every start: /run, /var/log and /var/lib/nginx may be
    # tmpfs on a read-only root filesystem.
    install -d -m 0755 -o root -g root /run/sshd /var/run/faillock
    install -d -m 0750 -o root -g adm /var/log/ssh
    touch "$SSH_LOG" && chown root:adm "$SSH_LOG" && chmod 0640 "$SSH_LOG"
    install -d -m 0750 -o "$APP_USER" -g "$APP_USER" /run/nginx /var/log/nginx /var/lib/nginx
    local d
    for d in body proxy fastcgi uwsgi scgi; do
        install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "/var/lib/nginx/$d"
    done
}

test_configs() {
    sshd_args
    if /usr/sbin/sshd -t "${SSHD_ARGS[@]}"; then
        ok "sshd configuration valid"
    else
        bad "sshd configuration invalid"; return 1
    fi
    if as_app /usr/sbin/nginx -t -q; then
        ok "nginx configuration valid"
    else
        bad "nginx configuration invalid"; return 1
    fi
}

# sshd -e logs to stderr without timestamps: add them (fail2ban needs them)
# and copy every line to docker logs.
ssh_logger() {
    local line host
    host=$(hostname)
    while IFS= read -r line; do
        printf '%(%b %e %H:%M:%S)T %s sshd[1]: %s\n' -1 "$host" "$line"
    done | tee -a "$SSH_LOG"
}

start_sshd() {
    local pid
    if pid=$(pid_of sshd "$SSHD_PIDFILE"); then
        ok "sshd already running (pid $pid): not started again"
        return 0
    fi
    info "starting sshd on :$SSH_PORT"
    /usr/sbin/sshd -D -e "${SSHD_ARGS[@]}" 2> >(ssh_logger) &
    PIDS+=("$!")
}

start_nginx() {
    local pid
    if pid=$(pid_of nginx "$NGINX_PIDFILE"); then
        ok "nginx already running (pid $pid): not started again"
        return 0
    fi
    info "starting nginx as $APP_USER on :$WEB_PORT"
    as_app /usr/sbin/nginx -g 'daemon off;' &
    PIDS+=("$!")
}

start_fail2ban() {
    local pid
    if ! f2b_wanted; then
        info "fail2ban skipped (needs NET_ADMIN/NET_RAW, or FAIL2BAN_ENABLED=false); faillock + MaxAuthTries still apply"
        return 0
    fi
    if pid=$(pid_of fail2ban-server "$F2B_PIDFILE"); then
        ok "fail2ban already running (pid $pid): not started again"
        return 0
    fi
    install -d -m 0750 -o root -g root /run/fail2ban /var/lib/fail2ban
    info "starting fail2ban"
    /usr/bin/fail2ban-server -xf start &
    PIDS+=("$!")
}

# Poll until every service passes its health check or START_TIMEOUT expires.
wait_healthy() {
    local deadline=$((SECONDS + START_TIMEOUT)) p
    QUIET=1
    while [ "$SECONDS" -lt "$deadline" ]; do
        for p in "${PIDS[@]}"; do
            kill -0 "$p" 2>/dev/null || { QUIET=0; bad "a service exited during start-up (pid $p)"; return 1; }
        done
        check_all && break
        sleep 1
    done
    QUIET=0
    info "post-start verification:"
    check_all
}

stop_children() {
    local p
    [ "${#PIDS[@]}" -gt 0 ] || return 0
    info "stopping services"
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
    wait "${PIDS[@]}" 2>/dev/null
}

do_start() {
    # Already up (e.g. run twice by mistake): report, never duplicate.
    QUIET=1
    if check_all; then
        QUIET=0
        info "all services already running and healthy: nothing to start"
        check_all
        return 0
    fi
    QUIET=0

    info "=== pre-start checks ==="
    /usr/local/sbin/init-hardening.sh --runtime || { bad "init-hardening.sh failed"; return 3; }
    /usr/local/sbin/init-identity.sh --runtime  || { bad "init-identity.sh failed"; return 3; }
    prepare_dirs || { bad "cannot prepare runtime directories"; return 3; }
    test_configs || return 3

    info "=== starting services ==="
    trap 'info "signal received"; stop_children; exit 0' TERM INT
    start_sshd
    start_nginx
    start_fail2ban

    if ! wait_healthy; then
        bad "services not healthy after ${START_TIMEOUT}s"
        stop_children
        return 1
    fi
    info "ready: web http://0.0.0.0:$WEB_PORT  ssh :$SSH_PORT  (audit: docker exec <ctr> audit.py)"

    # Supervision: the first child to exit brings the container down.
    [ "${#PIDS[@]}" -gt 0 ] || return 0
    wait -n "${PIDS[@]}"
    local rc=$?
    bad "a service exited (code $rc): stopping the others"
    stop_children
    return 1
}

do_reload() {
    local pid rc=0
    test_configs || return 3
    if pid=$(pid_of nginx "$NGINX_PIDFILE"); then
        kill -HUP "$pid" && ok "nginx reloaded (pid $pid)"
    else
        bad "nginx not running"; rc=1
    fi
    if pid=$(pid_of sshd "$SSHD_PIDFILE"); then
        kill -HUP "$pid" && ok "sshd reloaded (pid $pid)"
    else
        bad "sshd not running"; rc=1
    fi
    sleep 1
    check_all || rc=1
    return "$rc"
}

do_stop() {
    local name file pid
    for name in nginx sshd fail2ban-server; do
        case "$name" in
            nginx) file="$NGINX_PIDFILE" ;; sshd) file="$SSHD_PIDFILE" ;; *) file="$F2B_PIDFILE" ;;
        esac
        if pid=$(pid_of "$name" "$file"); then
            kill -TERM "$pid" && ok "$name stopped (pid $pid)"
        else
            info "$name not running"
        fi
    done
    return 0
}

usage() {
    awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
}

# =============================================================================
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    ""|--start|--status|--health|--reload|--stop) ;;
    -*) echo "Usage: $0 [--start|--status|--health|--reload|--stop|--help]" >&2; exit 2 ;;
    *)  exec "$@" ;;      # docker run IMAGE <command>
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "init-services.sh: must run as root (sshd needs it; nginx is dropped to $APP_USER)" >&2
    exit 2
fi
umask 027

case "${1:-}" in
    ""|--start) do_start; exit $? ;;
    --status)   info "=== service status ==="; check_all; rc=$?
                info "$([ $rc -eq 0 ] && echo HEALTHY || echo "UNHEALTHY ($FAILS failure(s))")"
                exit $((rc == 0 ? 0 : 1)) ;;
    --health)   QUIET=1; check_all; exit $(( $? == 0 ? 0 : 1 )) ;;
    --reload)   do_reload; exit $? ;;
    --stop)     do_stop; exit $? ;;
esac
