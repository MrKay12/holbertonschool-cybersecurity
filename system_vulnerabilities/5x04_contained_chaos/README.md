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
