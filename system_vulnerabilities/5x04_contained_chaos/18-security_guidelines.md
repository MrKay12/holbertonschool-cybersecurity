# DevStream Container Security Guidelines

| | |
|---|---|
| **Version** | 1.0 |
| **Owner** | Security Engineering (prepared by CyberShield Consulting) |
| **Applies to** | Every Dockerfile, image and container built or run by DevStream: production, staging, CI and developer machines |
| **Based on** | CIS Docker Benchmark, NIST SP 800-190, the DevStream container incident post-mortem |
| **Review** | Every 6 months, or after any container-related incident |

## Why these rules exist

Last month an attacker exploited a bug in our Flask application. Because the
container ran as root, with every default capability and the Docker socket
mounted "for convenience", the attacker read our volumes, started a privileged
container and took over the host. The database admin password was readable by
anyone who could pull the image.

Each rule below closes one of the doors that attacker used. The rules are
mandatory: **MUST** / **MUST NOT** are enforced in CI and code review,
**SHOULD** needs a good reason to skip. Anything that can't follow a MUST goes
through the [exception process](#6-exception-process).

The reference implementation is in this repository: `Dockerfile.app`
(production app image), `Dockerfile` (secure dev environment),
`docker-compose.yml` and scripts `10` to `13` (runtime flags).

## 1. Dockerfile rules

### Do

| # | Rule | Example |
|---|------|---------|
| D1 | **MUST** start from an approved, pinned base image (see [section 2](#2-base-image-policy)) | `FROM python:3.11-slim-bookworm@sha256:...` |
| D2 | **MUST** create a dedicated non-root user with a fixed UID and switch to it before `CMD` | `RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser` then `USER appuser` |
| D3 | **MUST** use multi-stage builds when anything is compiled or built: compilers stay in the `builder` stage | `FROM python:3.11-slim AS builder` ... `COPY --from=builder /opt/venv /opt/venv` |
| D4 | **MUST** copy only the files the app needs, and keep them owned by root | `COPY app.py requirements.txt ./` (never `COPY . .` without an allow-list `.dockerignore`) |
| D5 | **MUST** have a `.dockerignore` that excludes `.git`, `.env*`, keys, tests data, local venvs | allow-list style: `*` then `!app.py` |
| D6 | **MUST** pin dependency versions: Python packages in `requirements.txt` (with hashes for production), apt packages where possible | `flask==3.0.0`, `pip install --require-hashes -r requirements.txt` |
| D7 | **MUST** install packages without caches or extras | `apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*`, `pip install --no-cache-dir` |
| D8 | **MUST** define a `HEALTHCHECK` for long-running services | `HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:5000/health \|\| exit 1` |
| D9 | **MUST** use `COPY`, not `ADD` (no remote URLs, no silent archive extraction) | `COPY app.py .` |
| D10 | **SHOULD** use the exec form for `CMD` / `ENTRYPOINT` so signals reach the app | `CMD ["python", "app.py"]` |
| D11 | **SHOULD** set OCI `LABEL`s: title, version, owner, source | `LABEL org.opencontainers.image.title="..."` |
| D12 | **SHOULD** expose an unprivileged port (> 1024) so no capability is needed | `EXPOSE 5000` |

### Avoid

| # | Never | Why |
|---|-------|-----|
| A1 | `FROM ...:latest` or any unpinned tag | Builds change silently; a re-pushed tag can ship an attacker's image |
| A2 | No `USER` instruction, or `USER root` in the final stage | A single app bug gives root in the container, one kernel bug away from root on the host |
| A3 | `ENV`/`ARG` with passwords, tokens, keys | Readable by anyone with the image (`docker history --no-trunc`, `docker inspect`), forever |
| A4 | `RUN echo 'root:...' \| chpasswd`, installing `sudo` or `openssh-server` | Backdoors and privilege escalation paths |
| A5 | Debug and attacker-friendly tools in the final image: `curl`/`wget` (unless the healthcheck needs it), `vim`, `net-tools`, `nmap`, `gcc`, `make` | They are the attacker's toolkit, preinstalled |
| A6 | `COPY . /app` without a `.dockerignore` | Ships `.git` history, `.env` files and keys inside the image |
| A7 | `RUN curl ... \| sh` | Runs unverified code from the internet at build time |
| A8 | `chmod 777`, or app code owned by the app user | Lets a compromised app rewrite itself and persist |

### Enforcement

- `hadolint` runs in CI on every Dockerfile: **errors block the merge**,
  warnings must be fixed or justified in the pull request.
- Every Dockerfile change needs a review from a second developer, using the
  checklist in this section.

## 2. Base image policy

### Approved images

| Use | Approved image | Notes |
|-----|----------------|-------|
| Python services (default) | `python:3.x-slim-bookworm` | Official Docker image, glibc, small |
| Python services (hardened) | `gcr.io/distroless/python3-debian12` | No shell, no package manager; preferred when the app needs nothing else |
| Static binaries (Go, Rust) | `gcr.io/distroless/static-debian12`, `scratch` | |
| Node.js | `node:<lts>-bookworm-slim` | |
| Build stages only | `python:3.x-bookworm`, `golang:<version>` | Never as the final stage |
| Utilities / sidecars | `alpine:3.x` | Only when musl libc is not a problem |

Rules:

- **MUST** come from the Docker Official Images, Verified Publishers, Google
  Distroless, or DevStream's internal registry (which mirrors these).
- **MUST** be pinned to a version **and** a digest in production Dockerfiles:
  `python:3.11-slim-bookworm@sha256:<digest>`.
- **MUST NOT** use: `ubuntu`, `debian` or `centos` full images for an app that
  only needs a language runtime; community images from unknown publishers;
  images with no update in the last 6 months.
- Language versions **MUST** be within upstream support (e.g. Python versions
  still receiving security fixes).

### Update requirements

| Event | Required action | Deadline |
|-------|-----------------|----------|
| Routine | Renovate/Dependabot opens a pull request to bump base digests and dependencies; merge after CI passes | Weekly |
| New CRITICAL vulnerability with a fix in the base image or a dependency | Rebuild and redeploy | 7 days |
| New HIGH vulnerability with a fix | Rebuild and redeploy | 30 days |
| Base image or language version reaches end of life | Migrate to a supported version | Before end-of-life date |
| Any image in production | Rebuilt from an up-to-date base | At least every 30 days, even with no code change |

A new image (one not listed above) is approved by Security Engineering after
a Trivy scan and a review of its publisher and update history; it is then
added to this table.

## 3. Secret management

### Rules

| # | Rule |
|---|------|
| S1 | **MUST NOT** put secrets in a Dockerfile (`ENV`, `ARG`, `RUN`), in the image (copied config files, `.env`), in `docker-compose.yml`, or in git |
| S2 | **MUST** inject secrets at runtime only |
| S3 | Production **MUST** use the secrets manager (Vault / cloud secrets manager / Docker or Kubernetes secrets) and mount secrets as files in `/run/secrets/` (tmpfs), read by the app at start-up |
| S4 | Local development **MAY** use an `--env-file .env` that is `chmod 600`, listed in `.gitignore` and `.dockerignore`, and holds development credentials only, never production ones |
| S5 | Build-time secrets (private package index tokens) **MUST** use BuildKit secret mounts, which never reach a layer |
| S6 | **MUST NOT** pass production secrets with `docker run -e NAME=value` on the command line (shell history, process list) |
| S7 | Each service **MUST** have its own credentials with the minimum rights it needs (no shared `admin` account) |
| S8 | Secrets **MUST** be rotated at least every 90 days, and **immediately** when exposed |

### How to

```bash
# Development: private env file, never committed
cp .env.example .env && chmod 600 .env
docker run --env-file .env devstream-app:1.4.2

# Build-time secret (BuildKit): never stored in the image
#   Dockerfile:  RUN --mount=type=secret,id=pip_token \
#                    PIP_INDEX_URL="https://__token__:$(cat /run/secrets/pip_token)@pypi.internal/simple" \
#                    pip install --no-cache-dir -r requirements.txt
docker build --secret id=pip_token,src=./pip_token.txt -t devstream-app:1.4.2 .

# Production (Docker Swarm example): secret mounted as a file
printf '%s' "$DB_PASSWORD" | docker secret create db_password -
docker service create --secret db_password -e DB_PASSWORD_FILE=/run/secrets/db_password devstream-app:1.4.2
```

### Detection and response

- `detect-secrets` runs as a pre-commit hook and in CI; a finding blocks the
  merge.
- Images are checked before release: `docker history --no-trunc` and
  `trivy image --scanners secret` must find nothing
  (`2-inspect_history.sh` automates the history check).
- **A leaked secret is a burnt secret.** If a secret ever reaches git, an
  image, a log or a ticket: rotate it first, then clean up, then report it to
  Security Engineering. Deleting the commit or the image is not enough: copies
  exist in clones, caches and registries.

## 4. Runtime requirements

Required for every production container. The reference command
(`13-run_secure.sh`):

```bash
docker run -d --name devstream-app \
  --user 10001:10001 \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=50 \
  --restart=on-failure:5 \
  -p 127.0.0.1:5000:5000 \
  devstream-app:1.4.2
```

| # | Requirement | Flag | CIS |
|---|-------------|------|-----|
| R1 | Run as a non-root user | `--user` (and `USER` in the image) | 4.1 |
| R2 | Drop all capabilities, add back only what is justified (e.g. `NET_BIND_SERVICE` for a port < 1024) | `--cap-drop=ALL [--cap-add=...]` | 5.3 / 5.4 |
| R3 | Block privilege escalation | `--security-opt no-new-privileges:true` | 5.25 / 5.26 |
| R4 | Keep the default seccomp profile (or a stricter custom one) | never `seccomp=unconfined` | 5.21 / 5.22 |
| R5 | Keep AppArmor/SELinux enabled with the default (or a custom) profile where the host supports it | never `apparmor=unconfined` / `label=disable` | 5.1 / 5.2 |
| R6 | Read-only root filesystem; writable paths only as tmpfs or volumes, `noexec` where possible | `--read-only --tmpfs /tmp:...,noexec` | 5.12 / 5.13 |
| R7 | Memory limit with no extra swap | `--memory=X --memory-swap=X` | 5.10 / 5.11 |
| R8 | CPU limit | `--cpus=N` | 5.11 / 5.12 |
| R9 | Process limit | `--pids-limit=N` | 5.28 / 5.29 |
| R10 | Restart policy limited to on-failure | `--restart=on-failure:5` | 5.14 / 5.15 |
| R11 | Publish ports on a specific interface only; internal services use internal networks | `-p 127.0.0.1:...` or a user-defined network | 5.13 / 5.14 |
| R12 | Health check active | `HEALTHCHECK` in the image | 5.26 / 5.27 |

The CIS column gives the check number in docker-bench-security (CIS 1.2 /
CIS 1.6 numbering).

**Forbidden in production**, no exception possible:

- `--privileged`
- mounting `/var/run/docker.sock` (or any container runtime socket)
- `--pid=host`, `--ipc=host`, `--network=host`, `--uts=host`, `--userns=host`
- mounting sensitive host paths: `/`, `/etc`, `/proc`, `/sys`, `/boot`, `/dev`,
  `/var/lib/docker`, users' home folders
- `--cap-add=SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `NET_ADMIN`, `DAC_READ_SEARCH`
- `seccomp=unconfined`, `apparmor=unconfined`

**Host requirements** (owned by the platform team): Docker kept up to date,
user namespace remapping enabled where possible, access to the Docker group
limited to administrators (membership equals root), daemon `live-restore` and
`icc=false` per CIS section 2.

## 5. Audit requirements

| When | What | Tool | Pass criteria |
|------|------|------|---------------|
| Every pull request touching a Dockerfile | Dockerfile lint | `hadolint` | No errors |
| Every image build in CI | Vulnerability and secret scan | `trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`, `trivy --scanners secret` | No fixable CRITICAL/HIGH, no secret |
| Every image build in CI | History check | `2-inspect_history.sh` | No secret in layers |
| Before first production release of a service | Full CIS audit of image and runtime flags | `docker-bench-security -c container_images,container_runtime` (`17-final_audit.sh`) | Score ≥ 80 %, every remaining WARN accepted in writing |
| Monthly | Re-scan every image running in production (new CVEs appear after release) | `trivy` against the registry | Findings handled within the deadlines of [section 2](#update-requirements) |
| Quarterly | Host and daemon audit on every Docker host | full `docker-bench-security` | No WARN in sections 1-3 without an exception |
| After any security incident or major Docker upgrade | Full audit | all of the above | |

How to run the CIS audit:

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh -c container_images,container_runtime -i devstream-app
```

Read the result like this:

- **[WARN]** a failed check: fix it, or request an exception.
- **[PASS]** compliant.
- **[INFO] / [NOTE]** informational or manual checks: review them, record the
  answer in the audit report.

Audit reports (tool output, score, accepted warnings with their exception
IDs) are stored in the security wiki for 1 year. The service owner is
responsible for fixing findings; Security Engineering tracks the deadlines.

## 6. Exception process

Sometimes a rule can't be followed (a legacy app that must write to its
install folder, a network tool that needs `NET_RAW`). Exceptions are allowed
for MUST rules, **never** for the "forbidden in production" list in
[section 4](#4-runtime-requirements).

### How to request one

1. **Open a ticket** in the Security project, type "Container exception",
   with:
   - the service and image
   - the exact rule (e.g. "R2: needs `--cap-add=NET_RAW`")
   - why it is needed, and what was tried to avoid it
   - the risk: what an attacker could do with this exception
   - compensating controls (e.g. "network policy limits the container to
     the monitoring subnet", "AppArmor profile restricts raw sockets")
   - the requested duration (maximum 6 months)
   - a plan to remove the exception
2. **Review:** Security Engineering answers within 5 business days.
3. **Approval:**

   | Risk | Approver |
   |------|----------|
   | Low (SHOULD rule, dev/CI only) | Tech lead of the team |
   | Medium (MUST rule in staging or production) | Security Engineering |
   | High (MUST rule affecting isolation: user, capabilities, read-only FS in production) | Security Engineering lead and CTO |

4. **Record:** the approved exception gets an ID (`CSE-YYYY-NNN`). The ID goes
   in a comment next to the exception in the Dockerfile or compose file, and in
   the audit report:
   ```dockerfile
   # EXCEPTION CSE-2026-004: NET_RAW needed for ICMP health probes, expires 2027-05-31
   ```
5. **Expiry:** exceptions expire on their end date. Renewing one requires a new
   request. CI fails when it finds an expired exception ID.

### Emergency exceptions

During an incident, the on-call engineer may apply a temporary exception for
up to 72 hours. It must be logged in the incident ticket and go through the
normal process within those 72 hours, or be removed.

## Quick checklist

Before merging a Dockerfile or deploying a container:

- [ ] Approved base image, pinned by version and digest
- [ ] Multi-stage build, no compilers or debug tools in the final image
- [ ] Non-root `USER` with a fixed UID, app files owned by root
- [ ] No secret anywhere in the Dockerfile, image, compose file or git
- [ ] `.dockerignore` present, explicit `COPY` only
- [ ] Dependencies pinned, no package caches
- [ ] `HEALTHCHECK` defined
- [ ] `hadolint` clean, `trivy` with no fixable CRITICAL/HIGH
- [ ] Runs with `--cap-drop=ALL`, `no-new-privileges`, `--read-only`, memory/CPU/PID limits, `on-failure` restart
- [ ] No `--privileged`, no Docker socket, no host namespaces
- [ ] Any exception has an approved, unexpired `CSE-` ID
