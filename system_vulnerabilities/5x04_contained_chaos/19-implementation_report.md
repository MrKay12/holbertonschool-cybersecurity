# DevStream Container Security: Implementation Report

| | |
|---|---|
| **Prepared for** | DevStream leadership (CEO, CTO, Head of Engineering) |
| **Prepared by** | CyberShield Consulting, Security Engineering |
| **Engagement** | Container security audit and hardening after the container escape incident |
| **Scope** | DevStream's Flask application image and runtime, developer environment, team guidelines |
| **Classification** | Confidential, internal |

## 1. Executive summary

**What happened.** Last month an attacker exploited a vulnerability in
DevStream's Flask application. The container ran as root, with all default
Linux capabilities and the Docker socket mounted. From the application the
attacker read mounted volumes, used the Docker socket to start a privileged
container and escaped to the host. Incident response took three weeks.

**What we found.** The application image was insecure by design, not by
accident. Our review of the Dockerfile found **15 security issues**, 3 of them
critical:

- the application runs as **root**;
- the **production database admin password** is written in the image, readable
  by anyone who can pull it, in seconds, without attacking anything;
- the **root password** is set to a weak value stored in the image history.

The image was also 800+ MB of general-purpose Linux with compilers, network
tools and `sudo` preinstalled: a ready-made toolkit for an attacker.

**What we did.**

- Rebuilt the application image: minimal official base, multi-stage build,
  non-root user, no secrets, health check. **Image size reduced by about 80 %.**
- Defined the runtime configuration that removes every privilege the attacker
  used: no capabilities, no privilege escalation, syscall filtering, read-only
  filesystem, CPU/memory/process limits, no Docker socket.
- Built a **secure Python development environment** (image + one-command
  compose file) so developers get the secure setup by default.
- Wrote **Container Security Guidelines** with an exception process, and
  **automated audit scripts** to keep it that way.

**Result.** On the CIS Docker Benchmark (docker-bench-security, image and
runtime sections) the hardened setup moves from a failing score to above the
80 % production threshold; the only remaining warnings are infrastructure
decisions (image signing, host AppArmor). Every step the attacker took during
the incident is now blocked by at least two independent controls (see
[section 4](#4-security-measures-implemented)).

**What leadership must do now.**

1. **Rotate the leaked database password today** and treat every image built
   from the old Dockerfile as compromised (delete it from registries).
2. **Remove the Docker socket mount** from every container, everywhere.
3. **Adopt the guidelines** (`18-security_guidelines.md`) as mandatory, with
   CI enforcement, and assign an owner for the monthly audit.

## 2. Initial assessment

Full analysis: `0-insecure_analysis.md`. Evidence: `1-build_vulnerable.sh`,
`2-inspect_history.sh`, `3-docker_bench.sh`.

### The original Dockerfile

```dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip curl wget vim \
    net-tools iputils-ping gcc make sudo
RUN echo 'root:devstream123' | chpasswd
ENV DB_HOST=prod-db.devstream.internal
ENV DB_USER=admin
ENV DB_PASSWORD=Sup3rS3cr3t!Pr0d
WORKDIR /app
COPY . /app
RUN pip3 install -r requirements.txt
EXPOSE 5000
CMD ["python3", "app.py"]
```

### Findings

| # | Issue | Severity | Impact |
|---|-------|----------|--------|
| 1 | Runs as root (no `USER`) | Critical | Any app bug = root in the container, one kernel/runtime bug away from root on the host |
| 2 | Production DB admin credentials in `ENV` | Critical | Anyone with registry access reads them with `docker inspect`; every process in the container sees them |
| 3 | Root password `devstream123` set in the image | Critical | Backdoor; password and hash stored in image layers |
| 4 | `sudo` installed | High | Ready privilege escalation path (e.g. CVE-2021-3156) |
| 5 | `ubuntu:latest`, unpinned | High | Unreproducible builds, supply-chain risk |
| 6 | Full OS image for a small Python app (800+ MB) | High | Hundreds of packages, hundreds of potential CVEs |
| 7 | `gcc`, `make` in the final image | High | Attacker compiles kernel exploits on the target |
| 8 | `curl`, `wget`, `net-tools`, `ping`, `vim` installed | High | Download payloads, exfiltrate data, map the internal network, talk to the Docker socket |
| 9 | `COPY . /app` with no `.dockerignore` | High | `.git` history, `.env`, keys copied into the image |
| 10 | Dependencies not pinned or verified | Medium | Malicious or vulnerable package versions installed as root |
| 11 | No `--no-install-recommends`, apt cache kept | Medium | Extra packages and size |
| 12 | App code writable by the app process | Medium | Persistent web shell |
| 13 | Internal hostname disclosed | Low | Reconnaissance |
| 14 | No `HEALTHCHECK` | Low | Hung or hijacked app goes unnoticed |
| 15 | Single-stage build | Low | Root cause of 6, 7 and 11 |

Runtime issues (from the incident): Docker socket mounted, all default
capabilities, no `no-new-privileges`, writable filesystem, no resource limits.

### Proof

- **Secrets are public to anyone with the image.** `2-inspect_history.sh`
  extracts the root password and the database password from the image history
  alone, without running the container.
- **Root by default.** `1-build_vulnerable.sh` shows the container process runs
  as `root (UID 0)`.
- **Benchmark.** `3-docker_bench.sh` (CIS sections 4 and 5) gives the baseline
  a score of about **34 %**: no user, no health check, secrets in the
  Dockerfile, capabilities not restricted, writable root filesystem, no
  restart policy, privilege escalation possible.

## 3. Remediation steps

| Step | What we did | How | Deliverable |
|------|-------------|-----|-------------|
| 1 | Removed root | Dedicated `appuser` (UID/GID 1000), no password, `nologin` shell, `USER appuser` before `CMD`; app files owned by root so the app can't rewrite itself | `Dockerfile.app` (task 5) |
| 2 | Removed secrets | All `ENV DB_*` lines and `chpasswd` deleted; secrets injected at runtime from a private env file (`chmod 600`, deleted after start), never on the command line; documented production path (secrets manager) and BuildKit secret mounts | `Dockerfile.app`, `6-run_with_secrets.sh` |
| 3 | Shrank the image | Multi-stage build: compilers and pip work in a `builder` stage, the runtime stage gets only the Python virtualenv and `app.py`; `python:3.11-slim` base; `.dockerignore` allow-list | `Dockerfile.app` (task 7), `7-compare_sizes.sh` |
| 4 | Added health monitoring | `HEALTHCHECK` on `/health` every 30 s, 10 s timeout, 3 retries | `Dockerfile.app` (task 8) |
| 5 | Removed capabilities | `--cap-drop=ALL`, nothing added back (port 5000 needs none); verified `CapPrm`/`CapEff`/`CapBnd` all zero | `10-run_minimal_caps.sh` |
| 6 | Read-only filesystem | `--read-only`, writable `tmpfs` only for `/tmp` and `/app/logs`, both `noexec`; verified that root can't write to `/etc` or `/app` and that dropped files can't run | `11-run_readonly.sh` |
| 7 | Resource limits | 256 MB RAM, no swap, 0.5 CPU, 50 processes; verified in the kernel cgroups | `12-run_limited.sh` |
| 8 | Security options | `no-new-privileges`, Docker default seccomp profile, explicit `--user`; verified `NoNewPrivs: 1`, `Seccomp: 2` | `13-run_secure.sh` |
| 9 | Secure dev environment | Designed then built: Python 3.11 with pylint, black, pytest, mypy (pinned), `devuser` UID 1000, OCI labels, health check, no secrets; compose file applying every runtime control, with `dev`, `test` (no network), `lint`, `format`, `app` services | `14-design_document.md`, `Dockerfile`, `docker-compose.yml` |
| 10 | Final audit | docker-bench-security before/after with automatic classification of remaining warnings | `17-final_audit.sh` |
| 11 | Guidelines | Rules, base image policy, secrets, runtime, audits, exceptions | `18-security_guidelines.md` |

## 4. Security measures implemented

### Image (build time)

| Control | Application image | Dev image |
|---------|-------------------|-----------|
| Official minimal base | `python:3.11-slim` | `python:3.11-slim` |
| Multi-stage build | yes (`builder` → `runtime`) | yes |
| Non-root user, fixed UID | `appuser` 1000 | `devuser` 1000 |
| App/tool files owned by root | yes | yes (`/opt/venv`) |
| No secrets (`ENV`, `ARG`, files) | yes | yes |
| `.dockerignore` allow-list | yes | yes |
| No compilers / `sudo` / `wget` / `vim` in final image | yes | yes |
| Pinned dependencies, no pip/apt caches | yes | yes |
| `HEALTHCHECK` | `curl -f /health` | toolchain import check |
| OCI `LABEL` metadata | n/a | yes |

### Container (runtime)

| Control | Flag | Blocks |
|---------|------|--------|
| Non-root | `--user` | root-level actions inside the container |
| No capabilities | `--cap-drop=ALL` | `CHOWN`, `DAC_OVERRIDE`, `SETUID`, `NET_RAW`... |
| No privilege escalation | `--security-opt no-new-privileges:true` | setuid binaries |
| Syscall filtering | default seccomp profile (explicit `builtin`) | `mount`, `kexec_load`, `bpf`, `keyctl`... |
| Read-only root FS | `--read-only` + `noexec` tmpfs | dropping and running tools, modifying code |
| Memory / CPU / PIDs | `--memory`, `--memory-swap`, `--cpus`, `--pids-limit` | resource exhaustion, fork bombs |
| Restart policy | `--restart=on-failure:5` | restart loops |
| Local-only ports | `-p 127.0.0.1:...` | exposing a dev/debug server to the network |
| No Docker socket, no host namespaces, no `--privileged` | (never set) | the escape path used in the incident |

### The incident, replayed against the new setup

| Attacker step | Before | After |
|---------------|--------|-------|
| RCE in the Flask app | root shell | unprivileged `appuser`, no shell login, no capabilities |
| Read secrets | DB admin password in `env` and in the image | not in the image; runtime secrets scoped per service, production via secrets manager |
| Download tools | `curl`, `wget` ready | read-only FS, `/tmp` is `noexec`, no `wget`/compiler |
| Use the Docker socket | mounted | not mounted (forbidden by the guidelines, no exception) |
| Start a privileged container / escape | possible | no socket, no capabilities, `no-new-privileges`, seccomp |
| Exhaust the host | no limits | memory, CPU and PID limits |

## 5. Audit results

Tool: docker-bench-security, CIS sections 4 (images and build file) and 5
(container runtime), each run limited to the audited container. Score =
PASS / (PASS + WARN). Reproduce with `./17-final_audit.sh`; full reports are
saved to `17-audit_vulnerable.txt` and `17-audit_secure.txt`.

### Scores

The scores below are the project's reference measurements. Counts depend on
the docker-bench-security version and the host, so re-run
`17-final_audit.sh` and record the actual figures before sharing this report
outside the engineering team.

| | Vulnerable baseline | Hardened environment |
|---|---|---|
| PASS | 12 | 31 |
| WARN | 23 | 4 |
| Score | **34 %** (critical, do not deploy) | **89 %** (production ready) |
| Change | | **+55 percentage points** |

### Key controls, before and after

| CIS control (1.2 / 1.6 numbering) | Before | After | Fixed by |
|---|---|---|---|
| 4.1 User created for the container | WARN | PASS | `USER appuser` / `devuser` |
| 4.6 HEALTHCHECK in the image | WARN | PASS | `HEALTHCHECK` |
| 4.7 `update` not used alone | PASS | PASS | |
| 4.9 COPY instead of ADD | PASS | PASS | |
| 4.10 No secrets in Dockerfiles | WARN | PASS | secrets removed |
| 5.3 / 5.4 Capabilities restricted | WARN | PASS | `--cap-drop=ALL` |
| 5.4 / 5.5 No privileged container | PASS | PASS | |
| 5.10 Memory limited | WARN | PASS | `--memory` |
| 5.11 CPU priority set | WARN | PASS | `--cpus`, `--cpu-shares` |
| 5.12 / 5.13 Read-only root FS | WARN | PASS | `--read-only` |
| 5.14 / 5.15 `on-failure` restart policy | WARN | PASS | `--restart=on-failure:5` |
| 5.25 / 5.26 No new privileges | WARN | PASS | `no-new-privileges` |
| 5.28 / 5.29 PIDs limit | WARN | PASS | `--pids-limit` |
| 4.5 Content trust enabled | WARN | WARN | accepted: infrastructure decision (see below) |

### Other measurements

| Measure | Before | After | Script |
|---------|--------|-------|--------|
| Image size | ~850 MB | ~140 MB (about -80 %) | `7-compare_sizes.sh` |
| Secrets in image history | DB password, root password | none | `2-inspect_history.sh` |
| Process UID | 0 (root) | 1000 | `1-build_vulnerable.sh`, `13-run_secure.sh` |
| Effective capabilities | Docker default set (14) | 0 | `10-run_minimal_caps.sh` |
| `gcc` / `make` in image | present | absent | `7-compare_sizes.sh` |

### Remaining warnings (accepted)

| Warning | Why accepted | Owner / next step |
|---------|--------------|-------------------|
| 4.5 Content trust not enabled | Requires signed images and a registry with signing (Docker Content Trust / Notary, or Sigstore cosign). An infrastructure decision, not an image defect | Platform team: introduce image signing in CI, then enforce verification at deploy |
| AppArmor profile (5.1 / 5.2), on hosts without AppArmor | Depends on the host's Linux security module | Platform team: enable AppArmor (or SELinux) on Docker hosts |
| Default seccomp profile (INFO) | Docker's default profile is active and verified (`Seccomp: 2`); a custom, stricter profile is an optimisation | Security Engineering: evaluate a tailored profile per service |

## 6. Recommendations

### Immediately (this week)

1. **Rotate** the database password that was in the image, and the root
   password pattern. Check database logs for use of the `admin` account since
   the image was first pushed.
2. **Delete** every image built from the old Dockerfile from all registries
   and caches.
3. **Remove the Docker socket mount** and `--privileged` from every container,
   on every environment.
4. **Replace** the shared `admin` DB account with per-service accounts with
   minimal rights.

### Short term (next 30 days)

5. Deploy the hardened image and the runtime flags of `13-run_secure.sh` to
   production.
6. Add to CI: `hadolint` (blocking), `trivy image` (blocking on fixable
   CRITICAL/HIGH), secret scanning (`detect-secrets`, `trivy --scanners secret`).
7. Move production secrets to a secrets manager, mounted as files in
   `/run/secrets`.
8. Roll out the secure dev environment (`docker-compose.yml`) to all
   developers and retire ad-hoc dev images.
9. Pin base images by digest and enable Renovate/Dependabot for base image
   and dependency updates.

### Ongoing

10. Enforce `18-security_guidelines.md`: every exception through the formal
    process, with an expiry date.
11. Rebuild every production image at least every 30 days; patch CRITICAL
    vulnerabilities within 7 days, HIGH within 30.
12. Run `17-final_audit.sh` (or its CI equivalent) before every first release
    and monthly; full host audit quarterly.
13. Infrastructure: image signing and verification, AppArmor/SELinux on all
    Docker hosts, user namespace remapping, Docker group restricted to
    administrators.
14. Consider a runtime detection tool (e.g. Falco) to alert on shells spawned
    in containers, unexpected network connections and writes to sensitive
    paths.
15. Train developers on these guidelines (1-hour session using this
    incident as the case study), and add container security to onboarding.

## 7. Appendix

### A. Deliverables

| File | Task | Purpose |
|------|------|---------|
| `0-insecure_analysis.md` | 0 | Analysis of the original Dockerfile, 15 issues |
| `1-build_vulnerable.sh` | 1 | Builds the vulnerable image, shows root and exposed secrets |
| `2-inspect_history.sh` | 2 | Extracts secrets from image history |
| `3-docker_bench.sh` | 3 | CIS benchmark of the vulnerable container |
| `Dockerfile.app` | 5-8 | Hardened application image |
| `app.py`, `requirements.txt`, `.dockerignore` | 5 | Application and build context |
| `6-run_with_secrets.sh` | 6 | Runs with runtime-injected secrets |
| `7-compare_sizes.sh` | 7 | Single vs multi-stage size, build tools absent |
| `10-run_minimal_caps.sh` | 10 | Zero capabilities |
| `11-run_readonly.sh` | 11 | Read-only root filesystem |
| `12-run_limited.sh` | 12 | Resource limits |
| `13-run_secure.sh` | 13 | All runtime security options |
| `14-design_document.md` | 14 | Secure dev environment design |
| `Dockerfile`, `15-Dockerfile.securedev` | 15 | Secure dev environment image |
| `docker-compose.yml` | 16 | One-command dev environment |
| `17-final_audit.sh` | 17 | Before/after CIS audit |
| `18-security_guidelines.md` | 18 | Team guidelines |
| `19-implementation_report.md` | 19 | This report |

Scripts are not reproduced here; they are in the repository next to this
report, each with a usage header. The configurations below are copied from
the repository as delivered.

### B. `Dockerfile.app`

Hardened application image (tasks 5-8).

```dockerfile
# DevStream - hardened APP image (tasks 5-8): multi-stage, non-root user, no secrets
# (Dockerfile in this folder is the task 15 secure dev environment)
#
# Build:  docker build -t devstream-multistage:v1 -f Dockerfile.app .
#         (same file for tasks 5 and 6: devstream-nonroot:v1, devstream-nosecrets:v1)
# Check:  docker run --rm devstream-multistage:v1 id
#         uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
#
# ---------------------------------------------------------------------------
# SECRETS: NEVER IN THIS FILE
# ---------------------------------------------------------------------------
# Every ENV, ARG and RUN line is stored in the image config and layers and can
# be read by anyone who pulls the image (docker history --no-trunc,
# docker inspect). The old DB_HOST / DB_USER / DB_PASSWORD lines are removed:
# the leaked password must be considered burnt and rotated.
#
# The image reads its configuration from the environment at RUNTIME:
#   DB_HOST       database host
#   DB_USER       database user
#   DB_PASSWORD   database password
#
# How to pass them, from acceptable to best:
#   1. -e flags (quick tests only: the values end up in shell history and in
#      the host's process list):
#        docker run -e DB_HOST=myhost -e DB_USER=myuser -e DB_PASSWORD=mypass \
#            devstream-nosecrets:v1
#   2. An env file readable only by its owner (chmod 600), never committed
#      (add it to .gitignore and .dockerignore):
#        docker run --env-file ./devstream.env devstream-nosecrets:v1
#      This is what 6-run_with_secrets.sh does.
#   3. Production: a secrets manager (Docker/Swarm secrets, Kubernetes
#      Secrets, Vault, AWS Secrets Manager...), mounted as a file in
#      /run/secrets/ on tmpfs instead of an environment variable.
#
# Values passed with -e / --env-file are not in the image, but they are still
# visible to anyone who can run "docker inspect" on the container: restrict
# access to the Docker socket.
#
# Build-time secrets (private package index token...) use BuildKit secret
# mounts, which never reach a layer:
#   RUN --mount=type=secret,id=pip_token PIP_TOKEN="$(cat /run/secrets/pip_token)" pip install ...
#   docker build --secret id=pip_token,src=./pip_token.txt ...
#
# NEVER: ENV DB_PASSWORD=..., ARG DB_PASSWORD=..., RUN echo 'user:pass' | chpasswd,
#        COPY .env, or secrets in requirements.txt / config files copied in.
# ---------------------------------------------------------------------------

# ===========================================================================
# Stage 1 - builder: compilers and pip, thrown away after the build
# ===========================================================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build dependencies, needed to compile packages with C extensions.
# They exist only in this stage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc make libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies go into a self-contained virtualenv that is copied as a whole
# into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && find /opt/venv -type d -name '__pycache__' -prune -exec rm -rf {} +

# ===========================================================================
# Stage 2 - runtime: Python interpreter, the venv and the app, nothing else
# ===========================================================================
# Official slim image instead of ubuntu:latest (no compilers, no curl/wget/sudo)
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# curl is the only extra package, for the HEALTHCHECK below. Unprivileged user
# with a fixed UID/GID, no password, no login shell.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin appuser

# Only the installed dependencies come from the builder: no gcc, no make, no
# headers, no pip cache. Owned by root, so appuser cannot modify them.
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Only the files the app needs (no COPY . /app). They stay owned by root:
# appuser can read them but not rewrite its own code.
COPY app.py .

# Drop root for everything that runs from here on
USER appuser

EXPOSE 5000

# Health monitoring (task 8): GET /health every 30s, 10s timeout, the
# container is marked "unhealthy" after 3 consecutive failures. curl -f turns
# any HTTP error (4xx/5xx) into a failure. Runs as appuser like the app.
# Check: docker inspect devstream-health:v1 --format='{{json .Config.Healthcheck}}'
#        docker ps  ->  Up ... (healthy)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "app.py"]
```

### C. `Dockerfile`

Secure Python development environment (task 15).

```dockerfile
# secure-python-dev - hardened Python 3.11 development environment
# (implements 14-design_document.md)
#
# Build:
#   docker build -t secure-python-dev:v1 -f 15-Dockerfile.securedev .
# Check:
#   docker run --rm secure-python-dev:v1 id              # uid=1000(devuser) ...
#   docker run --rm secure-python-dev:v1 python --version
#   docker run --rm secure-python-dev:v1 pylint --version
#
# Daily use (project mounted, every runtime control from tasks 10-13):
#   docker run --rm -it \
#     -v "$PWD":/workspace \
#     -v secure-python-dev-home:/home/devuser \
#     --cap-drop=ALL --security-opt no-new-privileges:true \
#     --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
#     --memory=2g --memory-swap=2g --cpus=2 --pids-limit=256 \
#     -p 127.0.0.1:5000:5000 \
#     secure-python-dev:v1
#
#   Inside:  black .  |  pylint src/  |  mypy .  |  pytest
#            python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
#
# Secrets: none in this image. Pass them at runtime with --env-file .env
# (chmod 600, git-ignored). Never mount ~/.ssh, ~/.aws or /var/run/docker.sock.
#
# 15-Dockerfile.securedev is an identical copy, kept for the task's build command.

# ===========================================================================
# Stage 1 - builder: installs the tools into a self-contained virtualenv
# ===========================================================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Pinned versions: reproducible builds, no surprise upgrade from PyPI
RUN pip install --no-cache-dir \
        pylint==3.3.1 \
        black==24.10.0 \
        pytest==8.3.3 \
        mypy==1.13.0 \
    && find /opt/venv -type d -name '__pycache__' -prune -exec rm -rf {} +

# ===========================================================================
# Stage 2 - runtime: Python 3.11 + the tool venv + an unprivileged user
# ===========================================================================
FROM python:3.11-slim AS runtime

ARG VERSION=1.0.0

LABEL org.opencontainers.image.title="secure-python-dev" \
      org.opencontainers.image.description="Hardened Python 3.11 development environment: pylint, black, pytest, mypy; non-root, no secrets" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="CyberShield Consulting" \
      org.opencontainers.image.authors="CyberShield Consulting Security Engineering" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim" \
      security.non-root="true" \
      security.user="devuser" \
      security.secrets="none" \
      security.recommended-run-flags="--cap-drop=ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

# devuser: fixed UID/GID 1000 (matches the usual host user, so files written
# to the mounted project belong to the developer), no password, no sudo.
# /workspace is where the project gets mounted.
RUN groupadd --gid 1000 devuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash devuser \
    && mkdir /workspace \
    && chown devuser:devuser /workspace

# Tools owned by root: devuser can run them but cannot modify them.
# Python 3.11, pip and venv come from the official base image.
COPY --from=builder /opt/venv /opt/venv

USER devuser
WORKDIR /workspace

# The toolchain is healthy when the interpreter and every tool start.
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import pylint, black, pytest, mypy, venv, pip" || exit 1

CMD ["/bin/bash"]
```

### D. `docker-compose.yml`

One-command development environment with every runtime control (task 16).

```yaml
# docker-compose.yml - secure Python development environment (task 16)
#
# Image: secure-python-dev:v1, built from ./Dockerfile (task 15).
#
# Usage:
#   docker-compose build                              # build the image once
#   docker-compose run --rm dev                       # interactive shell in /workspace
#   docker-compose run --rm dev python my_script.py
#   docker-compose run --rm dev pytest tests/
#   docker-compose run --rm dev pylint my_module/
#   docker-compose run --rm dev black --check .
#   docker-compose run --rm dev mypy .
#
# Shortcuts (same image, same hardening, preset command):
#   docker-compose run --rm test        # pytest, with NO network
#   docker-compose run --rm lint        # pylint + black --check + mypy
#   docker-compose run --rm format      # black .
#   docker-compose up app               # python app.py on http://127.0.0.1:5000
#
# Code directory: the current folder by default, or another one with
#   CODE_DIR=../my-project docker-compose run --rm dev pytest
#
# Secrets: never in this file or in the image. Put them in a git-ignored
# .env (chmod 600) and pass it explicitly:
#   docker-compose run --rm --env-file .env dev python my_script.py

# Every runtime control from tasks 10-13, shared by all services
x-hardening: &hardening
  image: secure-python-dev:v1
  build:
    context: .
    dockerfile: Dockerfile
  user: "1000:1000"                    # devuser, never root
  working_dir: /workspace
  volumes:
    - ${CODE_DIR:-.}:/workspace        # the code, and nothing else from the host
    - dev-home:/home/devuser           # shell history, caches, project venv
  read_only: true                      # image filesystem cannot be modified
  tmpfs:
    - /tmp:rw,noexec,nosuid,nodev,size=256m
  cap_drop:
    - ALL                              # no Linux capabilities at all
  security_opt:
    - no-new-privileges:true           # setuid binaries cannot raise privileges
    # Docker's default seccomp profile applies: never set seccomp=unconfined
  privileged: false
  init: true                           # reaps zombies, forwards Ctrl-C
  mem_limit: 2g
  memswap_limit: 2g                    # = mem_limit: no swap
  cpus: 2.0
  pids_limit: 256                      # fork bomb protection
  environment:
    PYTHONDONTWRITEBYTECODE: "1"
    PYTHONUNBUFFERED: "1"
  # Never add: /var/run/docker.sock, ~/.ssh, ~/.aws, network_mode: host,
  # pid: host, privileged: true, cap_add: SYS_ADMIN

services:
  # General purpose: docker-compose run --rm dev <command>
  dev:
    <<: *hardening
    stdin_open: true
    tty: true
    command: ["/bin/bash"]

  # Unit tests, cut off from every network (no exfiltration, no call to prod)
  test:
    <<: *hardening
    network_mode: none
    command: ["pytest", "-q"]

  # Static checks
  lint:
    <<: *hardening
    network_mode: none
    command: ["sh", "-c", "pylint --recursive=y . && black --check . && mypy ."]

  # Auto-format the code (writes to the mounted folder)
  format:
    <<: *hardening
    network_mode: none
    command: ["black", "."]

  # Run the Flask app; port published on localhost only. The image only has
  # the dev tools, so the project's requirements go into a venv kept on the
  # dev-home volume (created on first run, reused afterwards).
  app:
    <<: *hardening
    command:
      - sh
      - -c
      - >-
        [ -x /home/devuser/.venv/bin/python ] || python -m venv /home/devuser/.venv;
        /home/devuser/.venv/bin/pip install -q -r requirements.txt &&
        exec /home/devuser/.venv/bin/python app.py
    ports:
      - "127.0.0.1:5000:5000"

volumes:
  dev-home:
```

### E. `.dockerignore`

Build context allow-list.

```text
# Keep the build context to what the image needs: no git history, no
# secrets, no audit tooling or reports.
*
!app.py
!requirements.txt
```

### F. `requirements.txt`

Application dependencies.

```text
flask==3.0.0
```

### G. Production run command

What `13-run_secure.sh` runs for the application image, with its values
filled in:

```bash
docker run -d --name devstream-secure \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=builtin \
  --cap-drop=ALL \
  --read-only \
  --user=appuser \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /app/logs:rw,noexec,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0750 \
  --memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=50 \
  -p 127.0.0.1:5000:5000 \
  devstream-secure:v1
```

For production, add `--restart=on-failure:5` and pass secrets through the
secrets manager (see `18-security_guidelines.md`, section 3).
