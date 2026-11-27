#!/bin/bash
# =============================================================================
# NovaTech Hardened Shield - integration validation
# =============================================================================
# Validates the complete solution end to end against the 6 criteria:
#   1. docker build succeeds
#   2. docker compose up starts the container (and it becomes healthy)
#   3. web server responds on port 80
#   4. SSH accessible on port 22 (key login works, root/password refused)
#   5. audit.py reports a passing score
#   6. security controls verifiable (runtime profile, users, headers, checks)
#
# Usage (from the project directory, as a user allowed to run docker):
#   scripts/integration-test.sh            build, start, test, leave running
#   scripts/integration-test.sh --down     ... then stop the stack
#   SSH_HOST_PORT=2222 scripts/integration-test.sh   host sshd already on 22
#
# A throwaway ed25519 key is generated for the SSH tests. The audit report is
# copied to ./audit_result.md only with --save-report.
# Exit codes: 0 all checks passed, 1 at least one check failed, 2 setup error.
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
SERVICE=shield
CONTAINER=hardened-shield
IMAGE=novatech/hardened-shield:1.0.0
HTTP_PORT=80
export SSH_HOST_PORT="${SSH_HOST_PORT:-22}"
DOWN=false
SAVE=false
for a in "$@"; do
    case "$a" in
        --down) DOWN=true ;;
        --save-report) SAVE=true ;;
        -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=; R=; B=; N=; fi
PASSED=0; FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '  %s[PASS]%s %s\n' "$G" "$N" "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  %s[FAIL]%s %s\n' "$R" "$N" "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
section() { printf '\n%s%s%s\n' "$B" "$1" "$N"; }

command -v docker >/dev/null || { echo "docker not found" >&2; exit 2; }
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null; then COMPOSE=(docker-compose)
else echo "docker compose / docker-compose not found" >&2; exit 2; fi
for t in curl ssh ssh-keygen; do command -v "$t" >/dev/null || { echo "$t not found" >&2; exit 2; }; done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ssh-keygen -q -t ed25519 -N '' -C integration-test -f "$TMP/id" || exit 2
export SSH_ADMIN_PUBKEY="$(cat "$TMP/id.pub")"
SSH_OPTS=(-p "$SSH_HOST_PORT" -o BatchMode=yes -o ConnectTimeout=5
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o IdentitiesOnly=yes -o LogLevel=ERROR)
dexec() { docker exec "$CONTAINER" "$@"; }

# --- 1. build ---------------------------------------------------------------
section "1. docker build"
if "${COMPOSE[@]}" build >"$TMP/build.log" 2>&1; then
    pass "image builds (Dockerfile + init-hardening/identity --build)"
else
    fail "image build failed" "last lines:"; tail -n 20 "$TMP/build.log" | sed 's/^/         /'
    exit 1
fi
size=$(docker image inspect "$IMAGE" --format '{{.Size}}' 2>/dev/null || echo 0)
if [ "$size" -gt 0 ] && [ "$size" -lt 524288000 ]; then
    pass "image size $((size / 1048576)) MB < 500 MB"
else
    fail "image size $((size / 1048576)) MB (limit 500 MB)"
fi
labels=$(docker image inspect "$IMAGE" --format '{{json .Config.Labels}}')
check "OCI labels present" grep -q 'org.opencontainers.image.version' <<<"$labels"
check "HEALTHCHECK defined" test -n "$(docker image inspect "$IMAGE" --format '{{if .Config.Healthcheck}}x{{end}}')"
hist=$(docker image history --no-trunc "$IMAGE" --format '{{.CreatedBy}}')
if grep -qiE '(password|passwd|secret|token|api_key)=[^ ]' <<<"$hist"; then
    fail "no hardcoded secrets in image history"
else
    pass "no hardcoded secrets in image history"
fi

# --- 2. compose up ----------------------------------------------------------
section "2. docker compose up"
if "${COMPOSE[@]}" up -d --force-recreate >"$TMP/up.log" 2>&1; then
    pass "stack started"
else
    fail "compose up failed"; sed 's/^/         /' "$TMP/up.log"; exit 1
fi
state=starting
for _ in $(seq 1 45); do
    state=$(docker inspect "$CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null)
    [ "$state" = healthy ] && break
    [ "$state" = exited ] || [ "$state" = unhealthy ] && break
    sleep 2
done
if [ "$state" = healthy ]; then
    pass "container healthy"
else
    fail "container not healthy (state: $state)" "container logs:"
    docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/         /'
    exit 1
fi

# --- 3. web on port 80 ------------------------------------------------------
section "3. Web server on port $HTTP_PORT"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$HTTP_PORT/")
[ "$code" = 200 ] && pass "GET / -> 200" || fail "GET / -> $code (expected 200)"
body=$(curl -s "http://localhost:$HTTP_PORT/health")
[ "$body" = OK ] && pass "GET /health -> OK" || fail "GET /health -> '$body'"
hdrs=$(curl -sI "http://localhost:$HTTP_PORT/")
grep -qiE '^server: nginx/[0-9]' <<<"$hdrs" && fail "Server header leaks the version" || pass "Server header without version"
for h in X-Frame-Options X-Content-Type-Options Content-Security-Policy Referrer-Policy; do
    check "header $h" grep -qi "^$h:" <<<"$hdrs"
done
for m in "TRACE 405" "PUT 403" "DELETE 403"; do
    set -- $m
    c=$(curl -s -o /dev/null -w '%{http_code}' -X "$1" "http://localhost:$HTTP_PORT/")
    [ "$c" = "$2" ] && pass "$1 -> $c" || fail "$1 -> $c (expected $2)"
done
c=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$HTTP_PORT/.git/config")
[ "$c" = 404 ] && pass "dotfiles hidden (/.git -> 404)" || fail "/.git -> $c (expected 404)"
n429=0
for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$HTTP_PORT/")" = 429 ] && n429=$((n429 + 1))
done
[ "$n429" -gt 0 ] && pass "rate limiting ($n429/60 burst requests -> 429)" || fail "rate limiting never answered 429"

# --- 4. SSH on port 22 ------------------------------------------------------
section "4. SSH on port $SSH_HOST_PORT"
banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$SSH_HOST_PORT && head -c 64 <&3" 2>/dev/null | head -n1)
[[ "$banner" == SSH-2.0-* ]] && pass "SSH banner: ${banner%$'\r'}" || fail "no SSH banner on port $SSH_HOST_PORT"
out=$(ssh -n "${SSH_OPTS[@]}" -i "$TMP/id" sysadmin@127.0.0.1 'id -un; id -Gn' 2>&1)
grep -q '^sysadmin$' <<<"$out" && pass "key login as sysadmin" || fail "key login as sysadmin" "$out"
grep -qw sshusers <<<"$out" && pass "sysadmin is in sshusers" || fail "sysadmin not in sshusers"
if ssh -n "${SSH_OPTS[@]}" -i "$TMP/id" root@127.0.0.1 true 2>/dev/null; then
    fail "root login refused"
else pass "root login refused"; fi
auth=$(ssh -n -p "$SSH_HOST_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no \
       -o PreferredAuthentications=password,keyboard-interactive sysadmin@127.0.0.1 true 2>&1)
grep -q 'Permission denied (publickey)' <<<"$auth" && pass "password authentication refused (publickey only)" \
    || fail "password authentication not refused as expected" "$auth"
if ssh -n "${SSH_OPTS[@]}" -i "$TMP/id" sysadmin@127.0.0.1 'su -c true root </dev/null' >/dev/null 2>&1; then
    fail "su to root denied"
else pass "su to root denied"; fi

# --- 5. audit ---------------------------------------------------------------
section "5. audit.py"
dexec audit.py -q --no-color -o /tmp/audit_result.md --note "integration-test.sh under Docker"
rc=$?
docker cp "$CONTAINER:/tmp/audit_result.md" "$TMP/audit_result.md" >/dev/null 2>&1
score=$(grep -m1 -oE 'Overall result: [^*]*' "$TMP/audit_result.md" 2>/dev/null)
[ "$rc" = 0 ] && pass "audit PASS (exit 0) - ${score:-see report}" || fail "audit exit $rc - ${score:-no report}"
if $SAVE && [ -s "$TMP/audit_result.md" ]; then
    cp "$TMP/audit_result.md" audit_result.md && cp audit_result.md scripts/audit_result.md \
        && pass "report saved to audit_result.md and scripts/audit_result.md"
fi

# --- 6. security controls ---------------------------------------------------
section "6. Security controls"
fmt() { docker inspect "$CONTAINER" --format "$1"; }
[ "$(fmt '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] && pass "cap_drop ALL" || fail "cap_drop is $(fmt '{{json .HostConfig.CapDrop}}')"
capadd=$(fmt '{{json .HostConfig.CapAdd}}')
extra=$(tr -d '[]"' <<<"$capadd" | tr ',' '\n' | sed 's/^CAP_//' \
        | grep -vxE 'CHOWN|SETUID|SETGID|SYS_CHROOT|NET_BIND_SERVICE|KILL' | tr '\n' ' ')
[ -z "$extra" ] && pass "only the 6 approved capabilities ($capadd)" || fail "extra capabilities: $extra"
check "no-new-privileges" grep -q 'no-new-privileges' <<<"$(fmt '{{json .HostConfig.SecurityOpt}}')"
[ "$(fmt '{{.HostConfig.ReadonlyRootfs}}')" = true ] && pass "read-only root filesystem" || fail "root filesystem writable"
[ "$(fmt '{{.HostConfig.Privileged}}')" = false ] && pass "not privileged" || fail "privileged container"
mem=$(fmt '{{.HostConfig.Memory}}'); pids=$(fmt '{{.HostConfig.PidsLimit}}'); cpu=$(fmt '{{.HostConfig.NanoCpus}}')
[ "${mem:-0}" -gt 0 ] && pass "memory limit $((mem / 1048576)) MB" || fail "no memory limit"
[ "${pids:-0}" -gt 0 ] 2>/dev/null && pass "pids limit $pids" || fail "no pids limit"
[ "${cpu:-0}" -gt 0 ] && pass "cpu limit $(awk "BEGIN{print $cpu/1e9}") CPU" || fail "no cpu limit"
check "volume mounted on /var/lib/ssh-hostkeys" grep -q '/var/lib/ssh-hostkeys' <<<"$(fmt '{{json .Mounts}}')"
ports=$(fmt '{{json .NetworkSettings.Ports}}')
check "port 80 -> 8080 published" grep -q '"8080/tcp":\[{[^]]*"HostPort":"80"' <<<"$ports"
check "port $SSH_HOST_PORT -> 22 published" grep -q "\"22/tcp\":\[{[^]]*\"HostPort\":\"$SSH_HOST_PORT\"" <<<"$ports"
rootweb=$(dexec ps -eo user=,comm= | awk '$2 == "nginx" && $1 == "root"' | wc -l)
webusers=$(dexec ps -eo user=,comm= | awk '$2 == "nginx" {print $1}' | sort -u | tr '\n' ' ')
[ "$rootweb" = 0 ] && [ -n "$webusers" ] && pass "nginx runs as non-root ($webusers)" || fail "nginx root processes: $rootweb"
check "PID 1 is tini" test "$(dexec cat /proc/1/comm)" = tini
check "write to / refused (read-only)" bash -c "! docker exec $CONTAINER touch /rootfs-write-test"
check "/tmp is noexec" bash -c "docker exec $CONTAINER findmnt -no OPTIONS /tmp | grep -q noexec"
suid=$(dexec find / -xdev -perm /6000 -type f 2>/dev/null | wc -l)
[ "$suid" = 0 ] && pass "no SUID/SGID binaries" || fail "$suid SUID/SGID binaries found"
check "root password locked" bash -c "docker exec $CONTAINER passwd -S root | awk '{exit \$2 != \"L\"}'"
check "init-hardening.sh --check compliant" dexec /usr/local/sbin/init-hardening.sh --check
check "init-identity.sh --check compliant" dexec /usr/local/sbin/init-identity.sh --check
check "init-services.sh --health" dexec /usr/local/sbin/init-services.sh --health
bnr=$(ssh -n -p "$SSH_HOST_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$TMP/id" sysadmin@127.0.0.1 true 2>&1)
check "legal banner shown before login" grep -qi 'authorized' <<<"$bnr"

# --- summary ----------------------------------------------------------------
TOTAL=$((PASSED + FAILED))
printf '\n%s==> %d/%d checks passed%s\n' "$B" "$PASSED" "$TOTAL" "$N"
if $DOWN; then "${COMPOSE[@]}" down >/dev/null 2>&1 && echo "stack stopped"; fi
if [ "$FAILED" -eq 0 ]; then
    printf '%sINTEGRATION VALIDATION: PASS%s\n' "$G$B" "$N"; exit 0
fi
printf '%sINTEGRATION VALIDATION: FAIL (%d failed)%s\n' "$R$B" "$FAILED" "$N"; exit 1
