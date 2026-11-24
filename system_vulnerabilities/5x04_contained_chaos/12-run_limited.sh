#!/bin/bash
# 12-run_limited.sh - Run the hardened image with CPU, memory and PID limits.
#
# Without limits a compromised or buggy container (memory leak, crypto-miner,
# fork bomb) can starve the host and every other container. Limits applied:
#   --memory=256m       hard RAM cap, the kernel OOM-kills the container above it
#   --memory-swap=256m  same value as --memory: no swap on top of the RAM cap
#   --cpus=0.5          at most half of one CPU core
#   --pids-limit=50     at most 50 processes/threads: stops fork bombs
# Keeps the earlier controls: no capabilities, no-new-privileges, read-only
# root filesystem with tmpfs for /tmp and /app/logs.
#
# The container is left running.
# Env: IMAGE (default devstream-secure:v1, built from ./Dockerfile if missing),
#      CONTAINER (default devstream-limited), PORT (default 5001, so it can run
#      next to devstream-secure), MEMORY, CPUS, PIDS

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-devstream-secure:v1}"
CONTAINER="${CONTAINER:-devstream-limited}"
PORT="${PORT:-5001}"
MEMORY="${MEMORY:-256m}"
CPUS="${CPUS:-0.5}"
PIDS="${PIDS:-50}"
APP_UID=1000

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE..."
    docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR" >/dev/null \
        || die "cannot build $IMAGE"
fi

mem_mb=${MEMORY%[mM]}
cpu_pct=$(awk -v c="$CPUS" 'BEGIN { printf "%g", c * 100 }')

echo "Applying limits:"
echo "  --memory=$MEMORY (max ${mem_mb}MB RAM)"
echo "  --memory-swap=$MEMORY (no swap)"
echo "  --cpus=$CPUS (max ${cpu_pct}% of one CPU)"
echo "  --pids-limit=$PIDS (max $PIDS processes)"

docker rm -f "$CONTAINER" >/dev/null 2>&1
run_err=$(docker run -d --name "$CONTAINER" \
    --memory="$MEMORY" \
    --memory-swap="$MEMORY" \
    --cpus="$CPUS" \
    --pids-limit="$PIDS" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --tmpfs "/app/logs:rw,noexec,nosuid,nodev,size=16m,uid=${APP_UID},gid=${APP_UID},mode=0750" \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -p "127.0.0.1:${PORT}:5000" \
    "$IMAGE" 2>&1 >/dev/null) || die "cannot start $CONTAINER: $run_err"
echo "Container started: $CONTAINER"

# --- Verification -------------------------------------------------------------
# 1. What Docker recorded, 2. what the kernel enforces (cgroup files seen from
#    inside the container).
echo "Verification:"
fail=0

read -r mem swap nano pids <<<"$(docker inspect --format \
    '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}' \
    "$CONTAINER")"

mem_set=$(( mem / 1024 / 1024 ))
cpu_set=$(awk -v n="$nano" 'BEGIN { printf "%g", n / 1e9 }')

echo "  Memory limit: ${mem_set}MB"
[ "$mem_set" -eq "$mem_mb" ] || fail=1
if [ "$swap" = "$mem" ]; then
    echo "  Swap: none (memory-swap = memory)"
else
    echo "  Swap: $(( (swap - mem) / 1024 / 1024 ))MB allowed ✗"
    fail=1
fi
echo "  CPU limit: ${cpu_set} cores"
[ "$cpu_set" = "$(awk -v c="$CPUS" 'BEGIN { printf "%g", c }')" ] || fail=1
echo "  PID limit: ${pids}"
[ "$pids" = "$PIDS" ] || fail=1

# Kernel side (cgroup v2, then v1). Informational: skipped if not readable.
cg() { docker exec "$CONTAINER" cat "$1" 2>/dev/null; }
k_mem=$(cg /sys/fs/cgroup/memory.max || cg /sys/fs/cgroup/memory/memory.limit_in_bytes)
k_pids=$(cg /sys/fs/cgroup/pids.max || cg /sys/fs/cgroup/pids/pids.max)
k_cpu=$(cg /sys/fs/cgroup/cpu.max)
if [ -n "$k_mem$k_pids$k_cpu" ]; then
    echo "  Kernel cgroup: memory.max=${k_mem:-?} pids.max=${k_pids:-?} cpu.max=${k_cpu:-?}"
fi

# The app still runs inside its limits
ok=0
for _ in $(seq 1 15); do
    if docker exec "$CONTAINER" curl -fs http://localhost:5000/health >/dev/null 2>&1; then
        ok=1; break
    fi
    sleep 1
done
if [ "$ok" -eq 1 ]; then
    usage=$(docker stats --no-stream --format '{{.MemUsage}}, CPU {{.CPUPerc}}, PIDs {{.PIDs}}' \
        "$CONTAINER" 2>/dev/null)
    echo "  Application status: Running normally${usage:+ ($usage)}"
else
    echo "  Application status: NOT responding ✗ (docker logs $CONTAINER)"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "Resource limits active."
    echo "Container cannot exhaust host resources."
else
    echo "Resource limits NOT fully applied."
    exit 1
fi
