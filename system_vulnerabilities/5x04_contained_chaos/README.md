# 5x04 — Contained Chaos

Container security audit and hardening for DevStream, a SaaS startup whose
Flask application container was used to escape to the host (root user, full
capabilities, mounted Docker socket, hardcoded production credentials).

## Objectives

- **Analyze:** understand what makes the current Dockerfile dangerous
- **Audit:** quantify the problems with docker-bench-security (CIS Docker Benchmark)
- **Remediate:** rewrite the Dockerfile following security best practices
- **Build:** a secure Python development environment template
- **Harden:** runtime controls (capabilities, read-only FS, resource limits, no-new-privileges, seccomp)
- **Document:** container security guidelines for the development team

## Tasks

| File | Description |
|------|-------------|
| `0-insecure_analysis.md` | Analysis of DevStream's Dockerfile: 15 security issues (root user, hardcoded DB credentials, weak root password, sudo, `ubuntu:latest`, full-OS image, build tools and attacker tooling in the image, `COPY .` of the whole context, unpinned dependencies, apt hygiene, writable code, info disclosure, no healthcheck, single-stage build), each with the problem, why it's dangerous and how an attacker exploits it, plus related runtime issues and a remediation summary |
| `1-build_vulnerable.sh` | Writes `app.py`, `requirements.txt` and DevStream's insecure Dockerfile into `vulnerable_app/` (override with `APP_DIR=`), builds `devstream-vulnerable:latest`, then reports the image size, base image, the real runtime user (`id` inside the container: root, UID 0) and the `DB_*` credentials readable from the image config. Only change to the Dockerfile: `PIP_BREAK_SYSTEM_PACKAGES=1`, since `ubuntu:latest` (24.04) otherwise refuses the system-wide `pip3 install` (PEP 668) |
| `2-inspect_history.sh` | `./2-inspect_history.sh <image> [base-image]` reads `docker history --no-trunc` (no container started), lists the layers oldest first as Dockerfile instructions (base image collapsed into one `FROM` line; handles both BuildKit and legacy builder formats), flags `chpasswd` lines and secret-named `ENV` (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`...), then extracts the root password and DB password from the history |
| `3-docker_bench.sh` | Clones docker-bench-security (git-ignored), starts `devstream-vulnerable:latest` the way DevStream ran it (root, default capabilities, writable FS, no restart policy; port bound to 127.0.0.1 only), runs the CIS "Container Images" (4.x) and "Container Runtime" (5.x) checks on it through sudo, prints the key findings (matched by title, so CIS 1.2 and 1.6 numbering both work), PASS/WARN/INFO/NOTE counts and a score (PASS / (PASS + WARN), under 50% = CRITICAL). Full report in `3-docker_bench_report.txt`; the container is removed at the end (`KEEP=1` keeps it). `-a` prints every 4.x / 5.x result |
| `Dockerfile` | Multi-stage (task 7): `builder` stage installs `gcc`/`make`/`libc6-dev` and the dependencies into a `/opt/venv` virtualenv (`--no-cache-dir`); `runtime` stage starts again from `python:3.11-slim` and only copies `/opt/venv` and `app.py`, so no compiler, headers or pip cache reach production. No secrets (tasks 5 and 6). The header documents why secrets never go in `ENV`/`ARG`/`RUN`, the runtime variables (`DB_HOST`, `DB_USER`, `DB_PASSWORD`) and how to pass them: `-e` for quick tests, a `chmod 600` `--env-file`, a secrets manager mounted in `/run/secrets` in production, BuildKit `--mount=type=secret` for build-time secrets. Non-root image: `python:3.11-slim`, user `appuser` (UID/GID 1000, no password, `nologin` shell), `WORKDIR /app`, dependencies installed as root with `--no-cache-dir`, only `app.py` / `requirements.txt` copied and left root-owned (the app can't rewrite its code), `USER appuser`, `HEALTHCHECK` on `/health`, no secrets. `docker build -t devstream-nonroot:v1 -f Dockerfile .` then `docker run --rm devstream-nonroot:v1 id` gives `uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)` |
| `6-run_with_secrets.sh` | Runs `devstream-nosecrets:v1` (built from `Dockerfile` if missing) with secrets from an env file argument, the shell environment, or a no-echo prompt. They go through a temporary `chmod 600` `--env-file` (deleted right after start), never on the command line. Then checks the image config/history hold no secret, the container gets the values (password masked), runs as `appuser` and the app answers. Removes the container at the end (`KEEP=1` keeps it). Env files are git-ignored |
| `7-compare_sizes.sh` | Builds what is missing (`devstream-vulnerable:latest` through task 1, `devstream-multistage:v1` from `Dockerfile`; `REBUILD=1` forces the latter), prints both sizes and the reduction, the Python version and the app's packages in the final image (flask and its dependencies, read from the venv), then checks inside the final image that `gcc`, `make` and any `.cache/pip` directory are absent. Exits 1 if one is found |
| `app.py`, `requirements.txt` | The DevStream Flask app (`flask==3.0.0`), build context for `Dockerfile` |
| `.dockerignore` | Allow-list: only `app.py` and `requirements.txt` are sent to the build |
