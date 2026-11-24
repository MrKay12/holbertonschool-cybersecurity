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
