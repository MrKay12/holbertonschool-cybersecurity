#!/bin/bash

set -e

CERT_DIR="/etc/squid/ssl_cert"
CERT_FILE="$CERT_DIR/myCA.pem"
DB_DIR="/var/lib/ssl_db"

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

mkdir -p "$CERT_DIR"

openssl req -new -newkey rsa:2048 \
    -sha256 \
    -days 3650 \
    -nodes \
    -x509 \
    -keyout "$CERT_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=Squid Proxy CA"

mkdir -p "$DB_DIR"

if command -v security_file_certgen >/dev/null 2>&1; then
    security_file_certgen -c -s "$DB_DIR" -M 4MB
elif [ -x /usr/lib/squid/security_file_certgen ]; then
    /usr/lib/squid/security_file_certgen -c -s "$DB_DIR" -M 4MB
elif [ -x /usr/libexec/squid/security_file_certgen ]; then
    /usr/libexec/squid/security_file_certgen -c -s "$DB_DIR" -M 4MB
fi

chown -R proxy:proxy "$CERT_DIR" "$DB_DIR" 2>/dev/null || true
chmod 700 "$DB_DIR"
chmod 600 "$CERT_FILE"