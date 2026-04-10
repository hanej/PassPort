#!/usr/bin/env bash
set -euo pipefail

# Ensure logs directory exists with correct ownership
mkdir -p /opt/passport/logs

# Fix ownership on data and config directories
chown -R passport:passport /opt/passport
chown -R passport:passport /etc/passport

# Generate master encryption key if it doesn't already exist
if [ ! -f /etc/passport/key ]; then
    openssl rand -base64 32 > /etc/passport/key
    chmod 600 /etc/passport/key
    chown passport:passport /etc/passport/key
fi

# Create a placeholder environment file for the master key if absent
if [ ! -f /etc/passport/env ]; then
    cat > /etc/passport/env <<'EOF'
# PassPort environment variables
# Uncomment to supply the master encryption key via environment variable
# instead of using a key file:
# APP_MASTER_KEY=<base64-encoded-32-byte-key>
EOF
    chmod 600 /etc/passport/env
    chown passport:passport /etc/passport/env
fi

# Generate a self-signed TLS certificate if one does not already exist.
# Replace /etc/passport/tls/cert.pem with a CA-signed certificate for production.
TLS_DIR=/etc/passport/tls
if [ ! -f "${TLS_DIR}/cert.pem" ]; then
    mkdir -p "${TLS_DIR}"
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "${TLS_DIR}/key.pem" \
        -out    "${TLS_DIR}/cert.pem" \
        -subj   "/CN=${HOSTNAME}" \
        -addext "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 640 "${TLS_DIR}/key.pem"
    chmod 644 "${TLS_DIR}/cert.pem"
    chown passport:passport "${TLS_DIR}/key.pem" "${TLS_DIR}/cert.pem"
fi
chown passport:passport "${TLS_DIR}"

systemctl daemon-reload
systemctl enable passport
