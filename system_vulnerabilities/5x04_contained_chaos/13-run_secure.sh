#!/bin/bash
# 13-run_secure.sh - Run the hardened image with every recommended runtime
# security option (tasks 10-13 combined).
#
#   --security-opt=no-new-privileges:true  setuid/setgid binaries and file
#                                          capabilities cannot raise privileges
#   --security-opt=seccomp=builtin         Docker's default seccomp profile:
#                                          ~44 dangerous syscalls blocked
#                                          (mount, kexec_load, bpf, ptrace on
#                                          old kernels, keyctl, ...). Named
#                                          explicitly so a daemon started with
#                                          seccomp disabled can't silently drop it.
#   --cap-drop=ALL  --read-only  --user=appuser
#   + tmpfs for /tmp and /app/logs, memory/CPU/PID limits.
#
# The container is left running.
# Env: IMAGE (default devstream-secure:v1, built from ./Dockerfile.app if missing),
#      CONTAINER (default devstream-secure), PORT (default 5000)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-secure:v1}"
CONTAINER="${CONTAINER:-devstream-secure}"
PORT="${PORT:-5000}"
APP_USER=appuser
APP_UID=1000

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.app" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $IMAGE"
fi

# Docker CLI 20.10+ names the default profile "builtin". Older clients only
# know a JSON file path or "unconfined"; there, the default profile is applied
# implicitly when no seccomp option is given.
SECCOMP_OPT=(--security-opt seccomp=builtin)

run_container() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    docker run -d --name "$CONTAINER" \
        --security-opt no-new-privileges:true \
        "${SECCOMP_OPT[@]}" \
        --cap-drop=ALL \
        --read-only \
        --user="$APP_USER" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --tmpfs "/app/logs:rw,noexec,nosuid,nodev,size=16m,uid=${APP_UID},gid=${APP_UID},mode=0750" \
        --memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=50 \
        -p "127.0.0.1:${PORT}:5000" \
        "$IMAGE" 2>&1 >/dev/null
}

if ! err=$(run_container); then
    if grep -qi seccomp <<<"$err"; then
        SECCOMP_OPT=()   # old client: rely on the implicit default profile
        err=$(run_container) || die "cannot start $CONTAINER: $err"
    else
        die "cannot start $CONTAINER: $err"
    fi
fi

echo "Security options applied:"
echo "  --security-opt=no-new-privileges:true"
echo "    (Process cannot gain new privileges via setuid, etc.)"
if [ ${#SECCOMP_OPT[@]} -gt 0 ]; then
    echo "  --security-opt=seccomp=builtin"
else
    echo "  seccomp: Docker default profile (implicit, old client)"
fi
echo "    (Syscall filtering enabled)"
echo "Additional hardening:"
echo "  --cap-drop=ALL"
echo "  --read-only"
echo "  --user=$APP_USER"
echo "  --tmpfs /tmp, /app/logs (noexec)"
echo "  --memory=256m --cpus=0.5 --pids-limit=50"
echo "Container started with maximum hardening."

# --- Verification (from the kernel's point of view, PID 1 of the container) ---
echo "Security verification:"
fail=0
status=$(docker exec "$CONTAINER" cat /proc/1/status 2>/dev/null)
[ -n "$status" ] || die "cannot read /proc/1/status in $CONTAINER"
field() { awk -v k="$1:" '$1 == k { print $2 }' <<<"$status"; }

# NoNewPrivs: 1 = the no_new_privs bit is set
if [ "$(field NoNewPrivs)" = "1" ]; then
    echo "  New privileges: BLOCKED"
else
    echo "  New privileges: ALLOWED ✗"
    fail=1
fi

# Seccomp: 0 = disabled, 1 = strict, 2 = filter (Docker profile)
case "$(field Seccomp)" in
    2) echo "  Seccomp: ENABLED (filter mode, $(field Seccomp_filters) filter(s))" ;;
    1) echo "  Seccomp: ENABLED (strict mode)" ;;
    *) echo "  Seccomp: DISABLED ✗"; fail=1 ;;
esac

# Not UID 0, and no capability left in any set
uid=$(field Uid)
caps_left=$(grep -E '^Cap(Prm|Eff|Bnd|Amb):' <<<"$status" | awk '$2 !~ /^0+$/' | wc -l)
if [ "$uid" != "0" ] && [ "$caps_left" -eq 0 ]; then
    echo "  Root access: NONE (UID $uid, 0 capabilities)"
else
    echo "  Root access: PRESENT ✗ (UID $uid, $caps_left capability set(s) not empty)"
    fail=1
fi

if [ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")" = "true" ]; then
    echo "  Root filesystem: READ-ONLY"
else
    echo "  Root filesystem: WRITABLE ✗"
    fail=1
fi

ok=0
for _ in $(seq 1 15); do
    if docker exec "$CONTAINER" curl -fs http://localhost:5000/health >/dev/null 2>&1; then
        ok=1; break
    fi
    sleep 1
done
if [ "$ok" -eq 1 ]; then
    echo "  Application status: Running normally"
else
    echo "  Application status: NOT responding ✗ (docker logs $CONTAINER)"
    fail=1
fi

exit "$fail"
