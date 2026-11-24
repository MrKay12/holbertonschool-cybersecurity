#!/bin/bash
# 11-run_readonly.sh - Run the hardened image with a read-only root filesystem.
#
# --read-only mounts the image's filesystem read-only: nobody in the container,
# root included, can modify binaries, config or the application code, or drop
# tools on disk. The app gets two small in-memory (tmpfs) writable areas:
#   /tmp       temporary files   (noexec: nothing written there can be run)
#   /app/logs  application logs  (owned by appuser, noexec)
# Also keeps the task 10 controls: no capabilities, no-new-privileges.
#
# The container is left running.
# Env: IMAGE (default devstream-secure:v1, built from ./Dockerfile.app if missing),
#      CONTAINER (default devstream-secure), PORT (default 5000)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-secure:v1}"
CONTAINER="${CONTAINER:-devstream-secure}"
PORT="${PORT:-5000}"
APP_UID=1000   # appuser in Dockerfile.app

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.app" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $IMAGE"
fi

echo "Starting container with:"
echo "  --read-only"
echo "  --tmpfs /tmp (for temporary files)"
echo "  --tmpfs /app/logs (for application logs)"

docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --tmpfs "/app/logs:rw,noexec,nosuid,nodev,size=16m,uid=${APP_UID},gid=${APP_UID},mode=0750" \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -p "127.0.0.1:${PORT}:5000" \
    "$IMAGE" >/dev/null || die "cannot start $CONTAINER"

# --- Verification -------------------------------------------------------------
# Writes to the root FS are attempted as root: root owns /etc and /app, so the
# only thing that can stop it is the read-only mount, not file permissions.
echo "Verification:"
fail=0

as_root() { docker exec --user root "$CONTAINER" sh -c "$1" 2>&1; }
as_app()  { docker exec "$CONTAINER" sh -c "$1" 2>&1; }

check_blocked() {   # $1 = directory
    local out
    if out=$(as_root "echo pwned > $1/.ro_test"); then
        echo "  Attempt to write to $1: ALLOWED ✗"
        as_root "rm -f $1/.ro_test" >/dev/null
        fail=1
    elif grep -qi 'read-only' <<<"$out"; then
        echo "  Attempt to write to $1: BLOCKED"
    else
        echo "  Attempt to write to $1: BLOCKED (${out##*: })"
    fi
}
check_blocked /etc
check_blocked /app

if as_app 'echo test > /tmp/.rw_test && rm /tmp/.rw_test' >/dev/null; then
    echo "  Attempt to write to /tmp: ALLOWED"
else
    echo "  Attempt to write to /tmp: FAILED ✗"
    fail=1
fi

# Something dropped in /tmp cannot be executed (noexec)
if as_app 'printf "#!/bin/sh\necho ran\n" > /tmp/.x && chmod +x /tmp/.x && /tmp/.x' \
        | grep -qx ran; then
    echo "  Execute a dropped file in /tmp: ALLOWED ✗"
    fail=1
else
    echo "  Execute a dropped file in /tmp: BLOCKED (noexec)"
fi
as_app 'rm -f /tmp/.x' >/dev/null

# The application user can write and read back its logs
line="healthcheck $(date +%s)"
if as_app "echo '$line' >> /app/logs/app.log && tail -n 1 /app/logs/app.log" \
        | grep -qxF "$line"; then
    echo "  Application logging: WORKING"
else
    echo "  Application logging: FAILED ✗"
    fail=1
fi

# The app itself still serves requests
ok=0
for _ in $(seq 1 15); do
    if as_app 'curl -fs http://localhost:5000/health' >/dev/null; then ok=1; break; fi
    sleep 1
done
if [ "$ok" -eq 1 ]; then
    echo "  Application status: Running normally"
else
    echo "  Application status: NOT responding ✗ (docker logs $CONTAINER)"
    fail=1
fi

ro=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")
if [ "$ro" = "true" ] && [ "$fail" -eq 0 ]; then
    echo "Root filesystem: READ-ONLY"
    echo "Attackers cannot modify system files or drop tools."
else
    echo "Root filesystem: NOT fully protected (ReadonlyRootfs=$ro)"
    exit 1
fi
