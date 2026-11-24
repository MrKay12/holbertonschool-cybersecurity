#!/bin/bash
# 6-run_with_secrets.sh - Run the hardened image with secrets supplied at
# runtime, never baked into the image.
#
# Secrets come from, in this order:
#   1. an env file given as argument (must not be readable by group/others)
#        ./6-run_with_secrets.sh ./devstream.env
#   2. DB_HOST / DB_USER / DB_PASSWORD already exported in the shell
#        DB_HOST=myhost DB_USER=myuser DB_PASSWORD=mypass ./6-run_with_secrets.sh
#   3. an interactive prompt (password typed without echo)
#
# They are handed to Docker through a private (chmod 600) temporary env file,
# so they never appear on a command line, in "ps" output or in shell history.
# The script then proves: the image holds no secret, the container receives
# them, it runs as appuser and the app answers.
#
# Env: IMAGE (default devstream-nosecrets:v1), CONTAINER, PORT (5000),
#      KEEP=1 to leave the container running afterwards.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-nosecrets:v1}"
CONTAINER="${CONTAINER:-devstream-nosecrets}"
PORT="${PORT:-5000}"
VARS=(DB_HOST DB_USER DB_PASSWORD)

die() { echo "ERROR: $*" >&2; exit 1; }

# Show only the first character of a secret
mask() { [ -n "$1" ] && printf '%s****' "${1:0:1}" || printf '(empty)'; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

ENV_FILE="$(mktemp)" || die "cannot create a temporary file"
chmod 600 "$ENV_FILE"
cleanup() {
    rm -f "$ENV_FILE"
    [ "${KEEP:-0}" = "1" ] || docker rm -f "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

# --- 1. Image (no secrets inside) ----------------------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR" >/dev/null \
        || die "build failed"
fi

# --- 2. Collect the secrets --------------------------------------------------
echo "Loading secrets..."
if [ $# -ge 1 ]; then
    src="$1"
    [ -f "$src" ] || die "env file not found: $src"
    perms=$(stat -c '%a' "$src")
    if [ "${perms: -2}" != "00" ]; then
        echo "  WARNING: $src is readable by others (mode $perms), run: chmod 600 $src"
    fi
    # keep only the variables the app needs, ignore comments and anything else
    grep -E "^($(IFS='|'; echo "${VARS[*]}"))=" "$src" > "$ENV_FILE"
    echo "  Source: env file $src"
else
    from_shell=1
    for v in "${VARS[@]}"; do
        [ -n "${!v:-}" ] || from_shell=0
    done
    if [ "$from_shell" -eq 1 ]; then
        echo "  Source: shell environment"
    elif [ -t 0 ]; then
        echo "  Source: interactive prompt"
        [ -n "${DB_HOST:-}" ] || read -r -p "  DB_HOST: " DB_HOST
        [ -n "${DB_USER:-}" ] || read -r -p "  DB_USER: " DB_USER
        if [ -z "${DB_PASSWORD:-}" ]; then
            read -r -s -p "  DB_PASSWORD: " DB_PASSWORD
            echo
        fi
    else
        die "no secrets: pass an env file or export ${VARS[*]}"
    fi
    for v in "${VARS[@]}"; do
        printf '%s=%s\n' "$v" "${!v:-}" >> "$ENV_FILE"
    done
fi

for v in "${VARS[@]}"; do
    grep -q "^$v=." "$ENV_FILE" || die "$v is missing or empty"
done

# --- 3. Run -------------------------------------------------------------------
echo "Starting container..."
docker rm -f "$CONTAINER" >/dev/null 2>&1
# Equivalent to: docker run -e DB_HOST=... -e DB_USER=... -e DB_PASSWORD=...
# but the values never appear on the command line.
docker run -d --name "$CONTAINER" \
    --env-file "$ENV_FILE" \
    -p "127.0.0.1:${PORT}:5000" \
    "$IMAGE" >/dev/null || die "cannot start $CONTAINER"
rm -f "$ENV_FILE"   # Docker has read it, it is no longer needed on disk
echo "  Container: $CONTAINER ($IMAGE)"
echo "  Command:   docker run -d --env-file <private file> -p 127.0.0.1:${PORT}:5000 $IMAGE"

# --- 4. Verify ----------------------------------------------------------------
echo "Verification:"
fail=0

# a. Nothing secret in the image itself
leak=$( { docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE"
          docker history --no-trunc --format '{{.CreatedBy}}' "$IMAGE"; } \
        | grep -E 'DB_(HOST|USER|PASSWORD)=|chpasswd' )
if [ -z "$leak" ]; then
    echo "  Image config/history: no secrets [OK]"
else
    echo "  Image config/history: SECRETS FOUND [FAIL]"
    fail=1
fi

# b. The container received them at runtime (wait for the app to start)
for _ in $(seq 1 15); do
    body=$(docker exec "$CONTAINER" python -c \
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5000/', timeout=2).read().decode())" \
        2>/dev/null) && break
    sleep 1
done

c_host=$(docker exec "$CONTAINER" printenv DB_HOST 2>/dev/null)
c_user=$(docker exec "$CONTAINER" printenv DB_USER 2>/dev/null)
c_pass=$(docker exec "$CONTAINER" printenv DB_PASSWORD 2>/dev/null)
echo "  Runtime DB_HOST:     ${c_host:-(missing)}"
echo "  Runtime DB_USER:     ${c_user:-(missing)}"
echo "  Runtime DB_PASSWORD: $(mask "$c_pass")"
[ -n "$c_host" ] && [ -n "$c_user" ] && [ -n "$c_pass" ] || fail=1

# c. Least privilege
c_id=$(docker exec "$CONTAINER" id -un 2>/dev/null)
if [ "$c_id" = "appuser" ]; then
    echo "  Running as: appuser [OK]"
else
    echo "  Running as: ${c_id:-unknown} [FAIL]"
    fail=1
fi

# d. The app works with the runtime configuration
if [ -n "${body:-}" ]; then
    echo "  App response: $body"
else
    echo "  App response: none [FAIL]"
    fail=1
fi

echo "NOTE: runtime values are still visible to anyone allowed to run"
echo "      'docker inspect $CONTAINER'. In production use a secrets manager"
echo "      (Docker/Swarm secrets, Kubernetes Secrets, Vault) and protect the Docker socket."
if [ "${KEEP:-0}" = "1" ]; then
    echo "Container left running on http://127.0.0.1:${PORT} (docker rm -f $CONTAINER)"
fi

[ "$fail" -eq 0 ] && echo "Result: secrets provided safely at runtime" \
    || { echo "Result: FAILED"; exit 1; }
