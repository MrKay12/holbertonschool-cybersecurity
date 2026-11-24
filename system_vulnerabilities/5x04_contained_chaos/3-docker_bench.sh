#!/bin/bash
# 3-docker_bench.sh - Audit the vulnerable DevStream container with
# docker-bench-security (CIS Docker Benchmark).
#
# 1. Fetches docker-bench-security into ./docker-bench-security (git clone)
# 2. Starts devstream-vulnerable:latest the way DevStream ran it: as root,
#    default capabilities, writable root FS, no restart policy, no limits
# 3. Runs the "Container Images" (4.x) and "Container Runtime" (5.x) checks
#    against it, saves the full report, prints the key findings and a score
# 4. Removes the test container (KEEP=1 to keep it running)
#
# Usage: ./3-docker_bench.sh [-a]
#   -a  print every 4.x / 5.x result, not only the key findings
# Env:   IMAGE, CONTAINER, BENCH_DIR, BENCH_REF (git branch/tag), KEEP=1
#
# docker-bench-security reads host files (daemon config, /etc/...), so it runs
# through sudo when the script is not started as root.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-vulnerable:latest}"
CONTAINER="${CONTAINER:-devstream-vulnerable}"
BENCH_DIR="${BENCH_DIR:-$SCRIPT_DIR/docker-bench-security}"
BENCH_REPO="https://github.com/docker/docker-bench-security.git"
BENCH_REF="${BENCH_REF:-master}"
REPORT="$SCRIPT_DIR/3-docker_bench_report.txt"
SHOW_ALL=0
[ "${1:-}" = "-a" ] && SHOW_ALL=1

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || die "image $IMAGE not found, run ./1-build_vulnerable.sh first"

if [ "$EUID" -eq 0 ]; then
    SUDO=()
else
    command -v sudo >/dev/null 2>&1 || die "run as root (sudo not available)"
    SUDO=(sudo)
fi

# --- 1. docker-bench-security -------------------------------------------------
if [ ! -f "$BENCH_DIR/docker-bench-security.sh" ]; then
    command -v git >/dev/null 2>&1 || die "git is required to fetch docker-bench-security"
    echo "Fetching docker-bench-security ($BENCH_REF)..."
    git clone --quiet --depth 1 --branch "$BENCH_REF" "$BENCH_REPO" "$BENCH_DIR" \
        || die "cannot clone $BENCH_REPO"
fi

# --- 2. Vulnerable container, run the insecure way ------------------------------
cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1
    fi
}
trap cleanup EXIT

docker rm -f "$CONTAINER" >/dev/null 2>&1
# Port published on localhost only: the app is vulnerable on purpose.
docker run -d --name "$CONTAINER" -p 127.0.0.1:5000:5000 "$IMAGE" >/dev/null \
    || die "cannot start $CONTAINER"

# --- 3. Benchmark ---------------------------------------------------------------
echo "Running docker-bench-security..."
raw=$(cd "$BENCH_DIR" && "${SUDO[@]}" sh docker-bench-security.sh -b \
        -c container_images,container_runtime \
        -i "${CONTAINER},${IMAGE%%:*}" \
        -l "$BENCH_DIR/log/devstream.log" 2>&1)
status=$?

# Plain text, one line per result. Keep top-level checks ("[WARN] 4.1 - ..."),
# drop the per-container detail lines ("[WARN]      * Running as root: ...").
clean=$(sed -E 's/\x1b\[[0-9;]*m//g' <<<"$raw")
printf '%s\n' "$clean" > "$REPORT"
results=$(grep -E '^\[(PASS|WARN|INFO|NOTE)\] [0-9]+\.[0-9]+ - ' <<<"$clean" \
    | sed -E 's/ \((Automated|Manual|Scored|Not Scored)\)$//')

[ -n "$results" ] || {
    echo "  docker-bench-security produced no results (exit $status)."
    echo "  Full output saved to $REPORT"
    exit 1
}

# Key CIS controls for this engagement, matched by title so the script works
# whatever the benchmark version numbers them (5.3 in CIS 1.2 is 5.4 in 1.6...).
key_images=(
    'user for the container has been created'
    'Content trust for Docker is Enabled'
    'HEALTHCHECK instructions have been added'
    'update instructions are not used alone'
    'COPY is used instead of ADD'
    'secrets are not stored in Dockerfiles'
)
key_runtime=(
    'Linux kernel capabilities are restricted'
    'privileged containers are not used'
    'root filesystem is mounted as read only'
    'on-failure'
    'acquiring additional privileges'
)

show() {   # $1 = section number, rest = title patterns
    local section="$1"; shift
    local lines
    lines=$(grep -E "^\[[A-Z]+\] ${section}\.[0-9]+ - " <<<"$results")
    if [ "$SHOW_ALL" -eq 1 ]; then
        printf '%s\n' "$lines"
        return
    fi
    local pat
    for pat in "$@"; do
        grep -iF -- "$pat" <<<"$lines" | head -n 1
    done
}

show 4 "${key_images[@]}"
echo "Container Runtime Checks:"
show 5 "${key_runtime[@]}"

# --- 4. Summary and score -------------------------------------------------------
count() { grep -c "^\[$1\] " <<<"$results"; }
pass=$(count PASS)
warn=$(count WARN)
info=$(count INFO)
note=$(count NOTE)

echo "Summary:"
echo "  PASS: $pass"
echo "  WARN: $warn"
echo "  INFO: $info"
echo "  NOTE: $note"

# Score = share of scored checks (PASS + WARN) that pass
total=$((pass + warn))
if [ "$total" -eq 0 ]; then
    echo "Score: n/a"
    exit 0
fi
score=$((pass * 100 / total))
if   [ "$score" -lt 50 ]; then verdict="CRITICAL - Do not deploy"
elif [ "$score" -lt 70 ]; then verdict="POOR - Fix before deploying"
elif [ "$score" -lt 90 ]; then verdict="FAIR - Review warnings"
else                            verdict="GOOD"
fi
echo "Score: ${score}% ($verdict)"
echo "Full report: $REPORT"
