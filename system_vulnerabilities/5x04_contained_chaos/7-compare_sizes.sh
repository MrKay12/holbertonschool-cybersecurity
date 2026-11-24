#!/bin/bash
# 7-compare_sizes.sh - Compare the single-stage vulnerable image with the
# multi-stage hardened one, and prove no build tooling reached production.
#
# Builds what is missing:
#   devstream-vulnerable:latest  (via 1-build_vulnerable.sh)
#   devstream-multistage:v1      (Dockerfile in this folder)
#
# Env: SINGLE, MULTI (image names), REBUILD=1 to rebuild the multi-stage image

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGLE="${SINGLE:-devstream-vulnerable:latest}"
MULTI="${MULTI:-devstream-multistage:v1}"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

# --- Build ------------------------------------------------------------------
if ! docker image inspect "$SINGLE" >/dev/null 2>&1; then
    echo "Building single-stage image ($SINGLE)..."
    "$SCRIPT_DIR/1-build_vulnerable.sh" >/dev/null || die "cannot build $SINGLE"
fi
if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect "$MULTI" >/dev/null 2>&1; then
    echo "Building multi-stage image ($MULTI)..."
    docker build -q -t "$MULTI" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $MULTI"
fi

# --- Sizes ------------------------------------------------------------------
size_mb() {   # docker CLI units: 1 MB = 1000 * 1000 bytes
    echo $(( $(docker image inspect --format '{{.Size}}' "$1") / 1000000 ))
}
single_mb=$(size_mb "$SINGLE")
multi_mb=$(size_mb "$MULTI")

echo "Single-stage image: ${single_mb} MB"
echo "Multi-stage image: ${multi_mb} MB"
if [ "$single_mb" -gt 0 ]; then
    echo "Reduction: $(( (single_mb - multi_mb) * 100 / single_mb ))%"
fi

# Run a shell command in the final image, as root so every path is readable
in_multi() {
    docker run --rm --user root --entrypoint sh "$MULTI" -c "$1" 2>/dev/null
}

# --- What the final image contains --------------------------------------------
echo "Packages in final image:"
pyver=$(docker run --rm --entrypoint python "$MULTI" -c \
    'import sys; print("python%d.%d" % sys.version_info[:2])' 2>/dev/null)
echo "  ${pyver:-python (unknown version)}"

# Application packages = what lives in the app's virtualenv (minus the venv's
# own pip/setuptools). flask first, then its dependencies.
pkgs=$(docker run --rm --entrypoint python "$MULTI" -c '
import importlib.metadata as m
skip = {"pip", "setuptools", "wheel"}
names = sorted({d.metadata["Name"].lower() for d in m.distributions()} - skip)
print("\n".join(names))' 2>/dev/null)
if grep -qx flask <<<"$pkgs"; then
    echo "  flask"
    deps=$(grep -vx flask <<<"$pkgs" | paste -sd, - | sed 's/,/, /g')
    [ -n "$deps" ] && echo "    (dependencies: $deps)"
else
    sed 's/^/  /' <<<"$pkgs"
fi
echo "  (minimal runtime only)"

# --- Build tooling must be absent ---------------------------------------------
echo "Build tools excluded:"
fail=0
for tool in gcc make; do
    if in_multi "command -v $tool >/dev/null"; then
        echo "  $tool ✗ (present: $(in_multi "command -v $tool"))"
        fail=1
    else
        echo "  $tool ✓"
    fi
done

caches=$(in_multi 'find / -xdev -type d -path "*/.cache/pip" 2>/dev/null')
if [ -z "$caches" ]; then
    echo "  pip (caches cleared) ✓"
else
    echo "  pip (caches cleared) ✗ ($(tr '\n' ' ' <<<"$caches"))"
    fail=1
fi

exit "$fail"
