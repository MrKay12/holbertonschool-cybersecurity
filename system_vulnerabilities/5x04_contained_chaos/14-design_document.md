# 14. Secure Python Development Environment: Design Document

**Author:** CyberShield Consulting, Security Engineering
**Client:** DevStream
**Status:** Design, to be implemented as a reusable template
**Scope:** Local development container for Python (Flask) projects

## Goals and non-goals

DevStream's developers run everything in Docker. Their current habits (root,
`ubuntu:latest`, secrets in the Dockerfile, Docker socket mounted "for
convenience") come from the dev environment and leak into production. The
template must make the secure way the easy way.

| Goals | Non-goals |
|-------|-----------|
| Same hardening as production (non-root, no capabilities, read-only root FS) | Running production workloads |
| All the tools a Python developer needs, pinned and ready | Being a general-purpose Linux box (no `sudo`, no `apt` at runtime) |
| Fast feedback: edit on the host, run inside, caches kept between runs | Docker-in-Docker or access to the host's Docker |
| One command to start, test, lint, audit | Supporting every IDE (VS Code + plain shell are covered) |

## Threat model

What the dev environment protects against:

| Threat | Example | Control |
|--------|---------|---------|
| Malicious or compromised dependency | typosquatted package runs code in `setup.py` or at import | non-root user, no capabilities, no host secrets mounted, hashes pinned, `pip-audit` |
| Vulnerable app code under test | SSTI / RCE in the Flask app during manual testing | ports bound to `127.0.0.1`, read-only root FS, seccomp |
| Container escape | kernel or runtime CVE | no root, no capabilities, `no-new-privileges`, seccomp, no Docker socket |
| Secret leakage | DB password in image layers or in git | no secrets in images, `.env` git-ignored and injected at runtime |
| Resource exhaustion | runaway test, fork bomb, memory leak | memory / CPU / PID limits |
| Host tampering | script writes to `~/.ssh`, `~/.bashrc` | only the project folder is mounted, nothing from `$HOME` |

## 1. Base image selection

**Choice:** `python:3.11-slim-bookworm`, pinned by digest in the Dockerfile:

```dockerfile
FROM python:3.11-slim-bookworm@sha256:<digest> AS base
```

| Candidate | Size | Verdict |
|-----------|------|---------|
| `ubuntu:latest` + apt Python | ~800 MB with tools | Rejected: huge attack surface, moving tag, system Python blocked by PEP 668 |
| `python:3.11` (full Debian) | ~1 GB | Rejected: ships compilers, headers, hundreds of unneeded packages |
| `python:3.11-alpine` | ~50 MB | Rejected for dev: musl libc means many wheels (numpy, cryptography, psycopg) must be compiled from source, slow builds and behaviour different from prod (glibc) |
| **`python:3.11-slim-bookworm`** | ~130 MB | **Selected**: official image, glibc (prebuilt wheels work), small, Debian security updates, same base as the production image from tasks 5-13 |
| `gcr.io/distroless/python3` | ~50 MB | Kept for production only: no shell and no package manager, unusable for development |

Why this choice:

- **Official and maintained:** Docker Official Image, rebuilt for every Python
  and Debian security release.
- **Same base as production:** code that works in dev works in prod, no
  musl/glibc surprises.
- **Pinned:** a fixed minor version (`3.11`), a fixed Debian release
  (`bookworm`) and a digest. The digest makes builds reproducible and stops a
  hijacked or re-pushed tag from reaching developers. Renovate/Dependabot
  updates the digest weekly through a reviewed pull request.

## 2. Included tools

All Python tools are pinned in `requirements-dev.txt` with hashes
(`pip install --require-hashes`) and installed into a virtualenv at
`/opt/venv`, owned by root (developers use them but can't modify them).

| Category | Tool | Purpose |
|----------|------|---------|
| Linting | `ruff` | Fast linter (pyflakes, pycodestyle, isort, bugbear rules) |
| Formatting | `black` | Consistent formatting, no style debates |
| Type checking | `mypy` | Static typing |
| Testing | `pytest`, `pytest-cov` | Unit tests and coverage |
| Security (code) | `bandit` | Python SAST: `eval`, `shell=True`, hardcoded passwords, weak crypto |
| Security (deps) | `pip-audit` | Known CVEs in installed packages (PyPI advisory DB / OSV) |
| Secrets | `detect-secrets` | Blocks commits that contain keys and passwords |
| Git hooks | `pre-commit` | Runs ruff, black, bandit, detect-secrets before every commit |
| Interactive | `ipython` | Better REPL for debugging |

System packages in the dev image, kept to the minimum, installed with
`--no-install-recommends` and pinned versions, apt lists removed:

| Package | Why |
|---------|-----|
| `git` | needed by `pre-commit` and for version info |
| `curl` | `HEALTHCHECK` and manual API testing against the app |
| `make` | runs the standard targets (`make test`, `make lint`) |

Not included, on purpose: `sudo`, `gcc` in the final stage (wheels are built
in a builder stage), `ssh`, `wget`, `net-tools`, `vim`. Editing happens on the
host with the developer's own editor.

Image-level tools, run in CI and by `make audit`, outside the container:

- `hadolint` lints the Dockerfile (must pass with no errors)
- `trivy image` scans the built image (fails on CRITICAL/HIGH with a fix)
- `docker-bench-security` audits the host/runtime setup periodically

## 3. User configuration

```dockerfile
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN groupadd --gid "${DEV_GID}" devuser \
    && useradd --uid "${DEV_UID}" --gid devuser \
       --create-home --home-dir /home/devuser \
       --shell /bin/bash devuser
USER devuser
WORKDIR /workspace
```

| Decision | Reason |
|----------|--------|
| Dedicated user `devuser` | Never run as root (CIS 4.1). A compromised package runs as an unprivileged user |
| UID/GID as build args, default 1000 | Matches the host user (`--build-arg DEV_UID=$(id -u)`), so files created in the bind-mounted project belong to the developer, not to root, and no `chown` is ever needed |
| No password, no `sudo`, not in any extra group | No way back to root from inside. Need a new system package? Change the Dockerfile and rebuild: reviewed and reproducible |
| Login shell `/bin/bash` (unlike prod's `nologin`) | Developers need an interactive shell; root still has none they can reach |
| Home directory on a named volume | Holds caches and shell history, survives restarts, isolated from the host's real `$HOME` |
| Tools in `/opt/venv` owned by root | `devuser` can run them but can't tamper with them |
| `USER` set in the image *and* `--user` at runtime | Defence in depth: a missing `USER` line can't silently bring root back |

## 4. Volume strategy

| Mount | Type | Mode | Contents |
|-------|------|------|----------|
| `./` → `/workspace` | bind mount | read-write | The project source only. Edited on the host, run in the container |
| `devstream-home` → `/home/devuser` | named volume | read-write | Shell history, tool caches (ruff, mypy, pytest, pre-commit) |
| `devstream-venv` → `/workspace/.venv` | named volume | read-write | Project dependencies (`pip install -r requirements.txt`), so `pip install` works without a writable root FS and stays off the host |
| `/tmp` | tmpfs | `rw,noexec,nosuid,nodev,size=256m` | Temporary files, wiped on stop, nothing in it can be executed |

Rules:

- **Mount the project, never more.** No `$HOME`, `~/.ssh`, `~/.aws`, `~/.kube`,
  `~/.gitconfig` with tokens. A malicious dependency should find nothing to
  steal.
- **Never mount `/var/run/docker.sock`.** Access to the socket is root on the
  host: it is exactly how DevStream was breached. Image builds happen on the
  host, not from inside the container.
- **Bind mounts use `:z`** on SELinux hosts and are flagged `nosuid` by Docker
  by default.
- **Git commits** happen on the host (where the developer's signing keys and
  credentials live), or inside the container with only `user.name` /
  `user.email` passed as environment variables, never credentials.
- **Mounted code is not baked in:** the dev image contains tools only. The
  production image (task 7 Dockerfile) copies code explicitly.

## 5. Security measures

Every control from tasks 5 to 13, applied to the dev environment:

### Build time (Dockerfile)

| Control | Implementation |
|---------|----------------|
| Minimal, pinned, official base | `python:3.11-slim-bookworm@sha256:...` |
| Multi-stage build | `builder` stage has `gcc` for wheels, final stage gets the venv only |
| Non-root user | `devuser`, `USER devuser` |
| No secrets in the image | No `ENV`/`ARG` secrets, `.dockerignore` excludes `.env`, `.git`, keys. Build-time tokens via `RUN --mount=type=secret` |
| Pinned dependencies | `requirements-dev.txt` with `--require-hashes`, `pip --no-cache-dir` |
| Minimal packages | `--no-install-recommends`, apt lists removed, no `sudo`/`ssh`/`wget` |
| Health check | `HEALTHCHECK CMD curl -f http://localhost:5000/health \|\| exit 1` |
| Lint and scan | `hadolint` (no errors) and `trivy` in CI before an image is published |

### Runtime (`docker run` / compose)

| Control | Flag | Effect |
|---------|------|--------|
| No capabilities | `--cap-drop=ALL` | Even a root process would have no privileges. Nothing added back (dev server on port 5000 > 1024) |
| No privilege escalation | `--security-opt no-new-privileges:true` | setuid binaries and file capabilities are ignored |
| Syscall filtering | `--security-opt seccomp=builtin` | Docker's default profile: `mount`, `kexec_load`, `bpf`, `keyctl`... blocked |
| Read-only root FS | `--read-only` | Tools and system files can't be modified or replaced. Writable areas are only `/workspace`, the home and venv volumes, and `/tmp` |
| Explicit user | `--user devuser` | Defence in depth |
| Resource limits | `--memory=2g --memory-swap=2g --cpus=2 --pids-limit=256` | A runaway test or fork bomb can't freeze the laptop. Higher than prod (tests, mypy and IDE servers need room) but still bounded |
| Local-only ports | `-p 127.0.0.1:5000:5000` | The dev server (often running in debug mode) is never reachable from the network |
| Network isolation for tests | `--network none` for `make test` | Unit tests can't call out (no exfiltration, no accidental calls to prod) |
| Never | `--privileged`, `--pid=host`, `--network=host`, Docker socket mount | Each of these defeats container isolation |
| Secrets at runtime | `--env-file .env` (`chmod 600`, git-ignored) | Values stay out of the image and out of shell history |

### Process

- `pre-commit` hooks run `ruff`, `black`, `bandit` and `detect-secrets` on every
  commit.
- `make audit` runs `pip-audit`, `bandit -r`, `hadolint` and `trivy`.
- The image is rebuilt weekly so Debian and Python security fixes are picked up.
- docker-bench-security is run on developer machines quarterly; findings in
  section 4 (images) and 5 (runtime) must be WARN-free for the dev container.

### Trade-offs accepted

| Restriction | Developer impact | Mitigation |
|-------------|------------------|------------|
| No `sudo`, no `apt` at runtime | Can't install a system package on the fly | Add it to the Dockerfile, rebuild (`make build`): reviewed and shared with the team |
| Read-only root FS | `pip install --user` into the image fails | Project venv on a named volume: `pip install` works there |
| No Docker socket | Can't build images from inside | Build from the host with `make build` |
| `--network none` for tests | Integration tests can't reach services | Integration tests use a separate compose profile with a private network and a throwaway database |
| `curl` and `bash` present | Slightly larger attack surface than prod | Dev only. The production image stays minimal |

## 6. Developer experience

Security only works if developers use it. The template gives one entry point
for everything.

### Planned files

| File | Role |
|------|------|
| `Dockerfile.dev` | Multi-stage dev image described above |
| `requirements-dev.txt` | Pinned dev tools with hashes |
| `docker-compose.dev.yml` | All runtime flags, volumes and limits in one place, so nobody has to remember them |
| `Makefile` | Short commands wrapping compose |
| `.devcontainer/devcontainer.json` | VS Code "Reopen in Container" with the same image and flags |
| `.pre-commit-config.yaml` | ruff, black, bandit, detect-secrets |
| `.env.example` | Variable names with placeholder values, copied to `.env` (git-ignored) |
| `.dockerignore` | Keeps `.git`, `.env`, `.venv`, keys and caches out of the build context |

### Daily workflow

```bash
cp .env.example .env && chmod 600 .env   # once: fill in local values
make build                               # build the image with your UID/GID
make shell                               # interactive shell in /workspace as devuser
make run                                 # Flask dev server on http://127.0.0.1:5000
make test                                # pytest + coverage, no network
make lint                                # ruff + black --check + mypy
make format                              # ruff --fix + black
make audit                               # bandit, pip-audit, hadolint, trivy
make clean                               # stop and remove containers (volumes kept)
```

### Making it pleasant

- **Edit on the host, run in the container:** the bind mount gives instant
  reloads (`flask --debug` auto-reloader), developers keep their own editor.
- **Fast restarts:** tool caches and the project venv live in named volumes,
  so a new container doesn't reinstall or re-analyse everything.
- **No permission fights:** UID/GID match the host user, files created in the
  container belong to the developer.
- **Same everywhere:** pinned image and tools mean "works on my machine"
  becomes "works in the container", identical in CI.
- **Clear errors:** when a write fails because of the read-only root FS, the
  README explains where writable paths are and why.
- **Discoverable:** `make help` lists every target, the README explains each
  security flag in one line so developers understand why it's there instead
  of removing it.

### Definition of done for the template

- `hadolint Dockerfile.dev` reports no errors
- `trivy image` reports no fixable CRITICAL/HIGH vulnerability
- `docker run ... id` shows `uid=1000(devuser)`, never root
- `/proc/1/status` in the container: `CapEff` 0, `NoNewPrivs: 1`, `Seccomp: 2`
- `make test` and `make lint` pass on the DevStream Flask app
- No secret in `docker history --no-trunc` (checked with task 2's script)
