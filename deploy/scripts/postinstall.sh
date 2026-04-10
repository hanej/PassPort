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

systemctl daemon-reload
systemctl enable passport
