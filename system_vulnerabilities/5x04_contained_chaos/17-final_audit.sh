#!/bin/bash
# 17-final_audit.sh - Audit the secure dev environment with docker-bench-security
# and compare it with the vulnerable DevStream baseline.
#
# Two runs of the CIS "Container Images" (4.x) and "Container Runtime" (5.x)
# checks, each limited to one container:
#   1. devstream-vulnerable:latest run as DevStream did (root, defaults)
#   2. secure-python-dev:v1 run with the docker-compose.yml hardening
#      (user 1000, read-only + tmpfs, cap-drop ALL, no-new-privileges,
#      memory/CPU/PID limits, restart on-failure:5)
# Score = PASS / (PASS + WARN). Remaining warnings of the secure run are
# listed with the reason they are accepted, or flagged as to fix.
#
# Builds missing images (task 1 script, ./Dockerfile), fetches
# docker-bench-security like task 3, runs it through sudo when not root.
# Env: BENCH_DIR, BENCH_REF, KEEP=1 (keep the audit containers)
# Full reports: 17-audit_vulnerable.txt, 17-audit_secure.txt

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_IMAGE="devstream-vulnerable:latest"
VULN_CT="devstream-vulnerable"
SEC_IMAGE="secure-python-dev:v1"
SEC_CT="secure-python-dev"
BENCH_DIR="${BENCH_DIR:-$SCRIPT_DIR/docker-bench-security}"
BENCH_REPO="https://github.com/docker/docker-bench-security.git"
BENCH_REF="${BENCH_REF:-master}"
READY_SCORE=80   # minimum score for "PRODUCTION READY"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

if [ "$EUID" -eq 0 ]; then
    SUDO=()
else
    command -v sudo >/dev/null 2>&1 || die "run as root (sudo not available)"
    SUDO=(sudo)
fi

# --- Prerequisites ------------------------------------------------------------
if ! docker image inspect "$VULN_IMAGE" >/dev/null 2>&1; then
    echo "Building $VULN_IMAGE..."
    "$SCRIPT_DIR/1-build_vulnerable.sh" >/dev/null || die "cannot build $VULN_IMAGE"
fi
if ! docker image inspect "$SEC_IMAGE" >/dev/null 2>&1; then
    echo "Building $SEC_IMAGE..."
    docker build -q -t "$SEC_IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $SEC_IMAGE"
fi
if [ ! -f "$BENCH_DIR/docker-bench-security.sh" ]; then
    command -v git >/dev/null 2>&1 || die "git is required to fetch docker-bench-security"
    echo "Fetching docker-bench-security ($BENCH_REF)..."
    git clone --quiet --depth 1 --branch "$BENCH_REF" "$BENCH_REPO" "$BENCH_DIR" \
        || die "cannot clone $BENCH_REPO"
fi

cleanup() {
    [ "${KEEP:-0}" = "1" ] || docker rm -f "$VULN_CT" "$SEC_CT" >/dev/null 2>&1
}
trap cleanup EXIT

# Run docker-bench on one container/image, print its top-level results
# ("[WARN] 4.1 - title"), save the full report to $2.
bench() {   # $1 = name pattern, $2 = report file
    local raw
    raw=$(cd "$BENCH_DIR" && "${SUDO[@]}" sh docker-bench-security.sh -b \
            -c container_images,container_runtime \
            -i "$1" \
            -l "$BENCH_DIR/log/final_audit.log" 2>&1)
    raw=$(sed -E 's/\x1b\[[0-9;]*m//g' <<<"$raw")
    printf '%s\n' "$raw" > "$2"
    grep -E '^\[(PASS|WARN|INFO|NOTE)\] [0-9]+\.[0-9]+ - ' <<<"$raw" \
        | sed -E 's/ \((Automated|Manual|Scored|Not Scored)\)$//'
}

count() { grep -c "^\[$1\] " <<<"$2"; }
score() {   # $1 = pass, $2 = warn
    local total=$(( $1 + $2 ))
    [ "$total" -gt 0 ] && echo $(( $1 * 100 / total )) || echo 0
}

# --- 1. Vulnerable baseline ---------------------------------------------------
docker rm -f "$VULN_CT" "$SEC_CT" >/dev/null 2>&1
docker run -d --name "$VULN_CT" -p 127.0.0.1:5000:5000 "$VULN_IMAGE" >/dev/null \
    || die "cannot start $VULN_CT"
v_res=$(bench "$VULN_CT" "$SCRIPT_DIR/17-audit_vulnerable.txt")
docker rm -f "$VULN_CT" >/dev/null 2>&1
[ -n "$v_res" ] || die "no results for $VULN_CT, see 17-audit_vulnerable.txt"

v_pass=$(count PASS "$v_res"); v_warn=$(count WARN "$v_res")
v_score=$(score "$v_pass" "$v_warn")
echo "Vulnerable Image (${VULN_IMAGE%%:*}):"
echo "  PASS: $v_pass"
echo "  WARN: $v_warn"
echo "  Score: ${v_score}%"

# --- 2. Secure environment, hardened as in docker-compose.yml -----------------
# "sleep infinity" keeps the dev container up long enough to be audited.
docker run -d --name "$SEC_CT" \
    --user 1000:1000 \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    --memory=2g --memory-swap=2g --cpus=2 --cpu-shares=512 --pids-limit=256 \
    --restart=on-failure:5 \
    "$SEC_IMAGE" sleep infinity >/dev/null || die "cannot start $SEC_CT"
s_res=$(bench "$SEC_CT" "$SCRIPT_DIR/17-audit_secure.txt")
[ -n "$s_res" ] || die "no results for $SEC_CT, see 17-audit_secure.txt"

s_pass=$(count PASS "$s_res"); s_warn=$(count WARN "$s_res")
s_score=$(score "$s_pass" "$s_warn")
echo "Secure Image (${SEC_IMAGE%%:*}):"
echo "  PASS: $s_pass"
echo "  WARN: $s_warn"
echo "  Score: ${s_score}%"

diff=$(( s_score - v_score ))
[ "$diff" -ge 0 ] && sign="+" || sign=""
echo "Improvement: ${sign}${diff} percentage points"

# --- 3. Remaining warnings ------------------------------------------------------
# Warnings that depend on the host or registry, not on this image/container,
# are accepted with their reason. Anything else must be fixed.
reason_for() {
    case "$1" in
        *"Content trust"*)            echo "infrastructure decision: signed images need a Notary-enabled registry" ;;
        *AppArmor*|*SELinux*)         echo "host decision: LSM not enabled on this host" ;;
        *"trusted base images"*|*"unnecessary packages"*|*"scanned and rebuilt"*|*"setuid and setgid"*)
                                      echo "manual review, see 14-design_document.md" ;;
        *)                            echo "" ;;
    esac
}

echo "Remaining warnings:"
to_fix=0
while IFS= read -r line; do
    [ -n "$line" ] || continue
    reason=$(reason_for "$line")
    if [ -n "$reason" ]; then
        echo "  $line ($reason)"
    else
        echo "  $line (TO FIX)"
        to_fix=$((to_fix + 1))
    fi
done < <(grep '^\[WARN\]' <<<"$s_res")
[ "$s_warn" -gt 0 ] || echo "  (none)"

# Seccomp: no explicit option means Docker's default profile; confirm the
# kernel really filters syscalls for the container (Seccomp: 2).
sec_opt=$(docker inspect --format '{{join .HostConfig.SecurityOpt " "}}' "$SEC_CT")
seccomp=$(docker exec "$SEC_CT" sh -c "awk '/^Seccomp:/ {print \$2}' /proc/1/status" 2>/dev/null)
if [[ "$sec_opt" == *seccomp=unconfined* ]] || [ "$seccomp" = "0" ]; then
    echo "  [WARN] seccomp disabled (TO FIX)"
    to_fix=$((to_fix + 1))
elif [[ "$sec_opt" != *seccomp=* ]]; then
    echo "  [INFO] Using default seccomp profile"
fi

# --- 4. Verdict ---------------------------------------------------------------
if [ "$to_fix" -eq 0 ] && [ "$s_score" -ge "$READY_SCORE" ]; then
    echo "Container Security: PRODUCTION READY"
else
    echo "Container Security: NEEDS WORK ($to_fix warning(s) to fix, score ${s_score}%, target ${READY_SCORE}%)"
    exit 1
fi
