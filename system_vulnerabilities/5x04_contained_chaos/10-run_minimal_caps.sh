#!/bin/bash
# 10-run_minimal_caps.sh - Run the hardened image with no Linux capabilities.
#
# --cap-drop=ALL removes every capability (Docker keeps 14 by default:
# CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, NET_RAW, ...). Nothing is added
# back: the app listens on 5000 (> 1024, so no NET_BIND_SERVICE), does not
# change file ownership, users or the network. no-new-privileges stops setuid
# binaries from regaining privileges.
#
# The container is left running (other hardening tasks build on it).
# Env: IMAGE (default devstream-secure:v1, built from ./Dockerfile.app if missing),
#      CONTAINER (default devstream-secure), PORT (default 5000)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-secure:v1}"
CONTAINER="${CONTAINER:-devstream-secure}"
PORT="${PORT:-5000}"
# Capabilities the app really needs. Empty for this Flask app; e.g. a server
# on port 80 would need NET_BIND_SERVICE.
CAP_ADD=()

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.app" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $IMAGE"
fi

echo "Dropping all capabilities..."
echo "Adding back only required capabilities:"
add_args=()
if [ ${#CAP_ADD[@]} -eq 0 ]; then
    echo "  (none needed for this application)"
else
    for cap in "${CAP_ADD[@]}"; do
        echo "  $cap"
        add_args+=(--cap-add="$cap")
    done
fi

echo "Starting container..."
docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" \
    --cap-drop=ALL "${add_args[@]}" \
    --security-opt no-new-privileges:true \
    -p "127.0.0.1:${PORT}:5000" \
    "$IMAGE" >/dev/null || die "cannot start $CONTAINER"

echo "  Container: $CONTAINER"
dropped=$(docker inspect --format '{{join .HostConfig.CapDrop ","}}' "$CONTAINER")
added=$(docker inspect --format '{{join .HostConfig.CapAdd ","}}' "$CONTAINER")
if [ "${dropped^^}" = "ALL" ] && [ -z "$added" ]; then
    echo "  Capabilities: NONE"
else
    echo "  Capabilities: dropped=${dropped:-none} added=${added:-none}"
fi

# --- Verification -------------------------------------------------------------
echo "Verification:"
echo "  \$ docker exec $CONTAINER cat /proc/1/status | grep Cap"
caps=$(docker exec "$CONTAINER" cat /proc/1/status 2>/dev/null | grep '^Cap')
[ -n "$caps" ] || die "cannot read /proc/1/status in $CONTAINER"
# Permitted, effective, and the bounding set (the ceiling: even a setuid-root
# binary could not get a capability outside it)
grep -E '^Cap(Prm|Eff|Bnd):' <<<"$caps" | tr -s '\t ' ' ' | sed 's/^/  /'

nonzero=$(awk '$2 !~ /^0+$/ { print $1 }' <<<"$caps" | tr -d ':' | paste -sd' ' -)

# Application still works (give it a few seconds to start)
ok=0
for _ in $(seq 1 15); do
    if docker exec "$CONTAINER" curl -fs "http://localhost:5000/health" >/dev/null 2>&1 \
        || docker exec "$CONTAINER" python -c \
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)" \
            >/dev/null 2>&1; then
        ok=1
        break
    fi
    sleep 1
done

if [ "$ok" -eq 1 ]; then
    echo "Application status: Running normally ✓"
else
    echo "Application status: NOT responding ✗ (docker logs $CONTAINER)"
fi

if [ ${#CAP_ADD[@]} -eq 0 ] && [ -z "$nonzero" ]; then
    echo "The container has ZERO elevated capabilities."
    echo "Even if compromised, the attacker's abilities are limited."
elif [ -n "$nonzero" ]; then
    echo "Remaining capability sets: $nonzero"
fi

[ "$ok" -eq 1 ] || exit 1
