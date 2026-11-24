#!/bin/bash
# 1-build_vulnerable.sh - Build and inspect DevStream's vulnerable image.
#
# Creates the Flask app, requirements.txt and the insecure Dockerfile in
# ./vulnerable_app (next to this script), builds devstream-vulnerable:latest,
# then reports its size, base image, runtime user and the secrets baked in.
#
# Usage: ./1-build_vulnerable.sh
#        APP_DIR=/some/dir ./1-build_vulnerable.sh

set -uo pipefail

IMAGE="devstream-vulnerable:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$SCRIPT_DIR/vulnerable_app}"
BUILD_LOG="$(mktemp /tmp/devstream-build.XXXXXX.log)"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker info >/dev/null 2>&1 \
    || die "cannot reach the Docker daemon (is it running? are you in the docker group?)"

mkdir -p "$APP_DIR" || die "cannot create $APP_DIR"

# --- 1. Application files ---------------------------------------------------
echo "Creating application files..."

cat > "$APP_DIR/app.py" <<'EOF'
from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return f"Hello from DevStream! DB: {os.environ.get('DB_HOST', 'unknown')}"

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF
[ -s "$APP_DIR/app.py" ] && echo "  app.py: Created" || die "app.py not created"

cat > "$APP_DIR/requirements.txt" <<'EOF'
flask==3.0.0
EOF
[ -s "$APP_DIR/requirements.txt" ] && echo "  requirements.txt: Created" \
    || die "requirements.txt not created"

# DevStream's Dockerfile, kept as-is on purpose (it is the thing under study).
# Only change: ubuntu:latest is now 24.04, whose system Python is marked
# "externally managed" (PEP 668) and makes the original pip3 line fail.
# PIP_BREAK_SYSTEM_PACKAGES=1 restores the old behaviour so the image builds.
cat > "$APP_DIR/Dockerfile" <<'EOF'
# DevStream's "production" Dockerfile
# DO NOT USE IN PRODUCTION (but they did...)

FROM ubuntu:latest

# Install everything we might need
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    vim \
    net-tools \
    iputils-ping \
    gcc \
    make \
    sudo

# Set root password (for debugging)
RUN echo 'root:devstream123' | chpasswd

# Database credentials
ENV DB_HOST=prod-db.devstream.internal
ENV DB_USER=admin
ENV DB_PASSWORD=Sup3rS3cr3t!Pr0d

# Copy application
WORKDIR /app
COPY . /app

# Install Python dependencies
# (lab addition: Ubuntu 24.04+ blocks system-wide pip installs, PEP 668)
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install -r requirements.txt

# Run as root because it's easier
EXPOSE 5000

CMD ["python3", "app.py"]
EOF
[ -s "$APP_DIR/Dockerfile" ] && echo "  Dockerfile: Created" || die "Dockerfile not created"

# --- 2. Build ---------------------------------------------------------------
echo "Building image..."
echo "  Image: $IMAGE"
if docker build -t "$IMAGE" "$APP_DIR" >"$BUILD_LOG" 2>&1; then
    echo "  Build: SUCCESS"
else
    echo "  Build: FAILED (last lines of $BUILD_LOG below)"
    tail -n 20 "$BUILD_LOG" | sed 's/^/    /'
    exit 1
fi

# --- 3. Image analysis ------------------------------------------------------
echo "Image Analysis:"

size_bytes=$(docker image inspect --format '{{.Size}}' "$IMAGE")
# docker CLI reports sizes in decimal units (1 MB = 1000 * 1000 bytes)
echo "  Size: $(( size_bytes / 1000000 )) MB"

base=$(awk 'toupper($1) == "FROM" { print $2; exit }' "$APP_DIR/Dockerfile")
echo "  Base: ${base:-unknown}"

# Check the real runtime identity, not just the image metadata
uid=$(docker run --rm --entrypoint id "$IMAGE" -u 2>/dev/null)
uname=$(docker run --rm --entrypoint id "$IMAGE" -un 2>/dev/null)
cfg_user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE")
if [ -n "$uid" ]; then
    echo "  User: ${uname:-unknown} (UID $uid)"
else
    echo "  User: ${cfg_user:-root (UID 0, no USER instruction)}"
fi

# --- 4. Secrets visible in the image config ---------------------------------
echo "Environment Variables (EXPOSED SECRETS):"
secrets=$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" \
    | grep -E '^DB_')
if [ -n "$secrets" ]; then
    sed 's/^/  /' <<<"$secrets"
    echo "WARNING: This image contains hardcoded credentials!"
else
    echo "  (none found)"
fi
