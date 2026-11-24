#!/bin/bash
# 2-inspect_history.sh - Show how secrets leak through Docker image history.
#
# Reads the build history of an image (docker history --no-trunc), lists its
# layers oldest first, flags the ones that carry secrets, then extracts them.
# Only needs read access to the image: no container is started.
#
# Usage: ./2-inspect_history.sh <image> [base-image]
#   base-image  collapses the base image's own layers into one "FROM" line.
#               Default: the FROM of vulnerable_app/Dockerfile when inspecting
#               devstream-vulnerable, else every layer is listed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }

[ $# -ge 1 ] || { echo "Usage: $0 <image> [base-image]" >&2; exit 1; }
IMAGE="$1"
BASE="${2:-}"

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image not found: $IMAGE"

if [ -z "$BASE" ] && [[ "$IMAGE" == devstream-vulnerable* ]] \
        && [ -f "$SCRIPT_DIR/vulnerable_app/Dockerfile" ]; then
    BASE=$(awk 'toupper($1) == "FROM" { print $2; exit }' \
        "$SCRIPT_DIR/vulnerable_app/Dockerfile")
fi

# Turn a raw "CreatedBy" entry into the Dockerfile instruction that made it.
#   legacy builder: /bin/sh -c #(nop)  ENV A=B      -> ENV A=B
#                   /bin/sh -c apt-get ...          -> RUN apt-get ...
#   BuildKit:       RUN /bin/sh -c apt-get ... # buildkit -> RUN apt-get ...
normalize() {
    sed -E \
        -e 's/[[:space:]]+# buildkit$//' \
        -e 's@^/bin/sh -c #\(nop\)[[:space:]]+@@' \
        -e 's@^\|[0-9]+ ([^ ]+=[^ ]* )*/bin/sh -c @RUN @' \
        -e 's@^/bin/sh -c @RUN @' \
        -e 's@^RUN /bin/sh -c @RUN @' \
        -e 's/[[:space:]]+/ /g' -e 's/ $//'
}

# Oldest layer first (docker history lists newest first).
mapfile -t history < <(docker history --no-trunc --format '{{.CreatedBy}}' "$IMAGE" \
    | tac | normalize)

skip=0
if [ -n "$BASE" ] && docker image inspect "$BASE" >/dev/null 2>&1; then
    skip=$(docker history -q "$BASE" | wc -l)
    # Sanity check: the base must really be the bottom of this image.
    [ "$skip" -lt "${#history[@]}" ] || skip=0
fi

echo "Image: $IMAGE"
echo "Layer History:"

n=0
if [ "$skip" -gt 0 ]; then
    n=1
    echo "  Layer $n: FROM $BASE"
fi

secret_re='^ENV [A-Za-z_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Za-z_]*='
for (( i = skip; i < ${#history[@]}; i++ )); do
    line="${history[i]}"
    [ -n "$line" ] || continue
    n=$((n + 1))

    marker=""
    if [[ "$line" =~ chpasswd|--password|passwd[[:space:]] ]]; then
        marker="  ← PASSWORD EXPOSED"
    elif [[ "$line" =~ $secret_re ]]; then
        marker="  ← SECRET EXPOSED"
    fi

    # Shorten long build commands, never the ones carrying a secret.
    shown="$line"
    if [ -z "$marker" ] && [ ${#shown} -gt 60 ]; then
        shown="${shown%%&&*}"
        shown="${shown% }"
        shown="${shown:0:60}..."
    fi
    echo "  Layer $n: $shown$marker"
done

echo "Extracting secrets from history..."
found=0
for line in "${history[@]}"; do
    # echo 'user:password' | chpasswd
    if [[ "$line" =~ chpasswd ]] \
            && [[ "$line" =~ ([A-Za-z_][A-Za-z0-9_-]*):([^\'\"[:space:]|]+) ]]; then
        user="${BASH_REMATCH[1]}"
        pass="${BASH_REMATCH[2]}"
        if [ "$user" = "root" ]; then
            echo "  Root password: $pass"
        else
            echo "  Password for $user: $pass"
        fi
        found=1
    fi
    # ENV NAME=value with a secret-looking name
    if [[ "$line" =~ $secret_re ]]; then
        kv="${line#ENV }"
        name="${kv%%=*}"
        value="${kv#*=}"
        if [ "$name" = "DB_PASSWORD" ]; then
            echo "  DB Password: $value"
        else
            echo "  $name: $value"
        fi
        found=1
    fi
done
[ "$found" -eq 1 ] || echo "  (no secrets found in history)"

echo "CRITICAL: All ENV and RUN commands are permanently"
echo "visible in image layers. Never put secrets here!"
