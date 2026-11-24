# DevStream - hardened image, step 1: run as a non-root user
#
# Build:  docker build -t devstream-nonroot:v1 -f Dockerfile .
# Check:  docker run --rm devstream-nonroot:v1 id
#         uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
# Run:    docker run -d -p 127.0.0.1:5000:5000 -e DB_HOST=... devstream-nonroot:v1
#
# No secrets here: DB_HOST / DB_USER / DB_PASSWORD are supplied at runtime.

# Official slim image instead of ubuntu:latest (no compilers, no curl/wget/sudo)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Unprivileged user with a fixed UID/GID, no password, no login shell
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin appuser

WORKDIR /app

# Dependencies are installed by root into the system site-packages,
# so the application user cannot modify them.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only the files the app needs (no COPY . /app). They stay owned by root:
# appuser can read them but not rewrite its own code.
COPY app.py .

# Drop root for everything that runs from here on
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)"]

CMD ["python", "app.py"]
