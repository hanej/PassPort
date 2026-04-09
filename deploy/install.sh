#!/usr/bin/env bash
set -euo pipefail

# PassPort — Installation Script
# Run as root or with sudo

APP_NAME="passport"
APP_DIR="/opt/passport"
BIN_DIR="${APP_DIR}/bin"
CONF_DIR="/etc/passport"
SERVICE_USER="passport"

echo "=== PassPort Installation ==="

# Create system user (no login shell, no home directory)
if ! id -u "${SERVICE_USER}" &>/dev/null; then
    echo "Creating system user: ${SERVICE_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# Create directories
echo "Creating directories..."
mkdir -p "${BIN_DIR}"
mkdir -p "${APP_DIR}/uploads"
mkdir -p "${CONF_DIR}"

# Copy binary
if [ -f "bin/passport" ]; then
    echo "Installing binary..."
    cp bin/passport "${BIN_DIR}/passport"
    chmod 755 "${BIN_DIR}/passport"
else
    echo "ERROR: No binary found. Run 'make build' first."
    exit 1
fi

# Generate master key if it doesn't exist
if [ ! -f "${CONF_DIR}/key" ]; then
    echo "Generating master encryption key..."
    openssl rand 32 > "${CONF_DIR}/key"
    chmod 600 "${CONF_DIR}/key"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${CONF_DIR}/key"
    echo "  Key saved to: ${CONF_DIR}/key"
fi

# Create environment file for the master key (alternative to file-based key)
if [ ! -f "${CONF_DIR}/env" ]; then
    echo "Creating environment file..."
    cat > "${CONF_DIR}/env" <<'EOF'
# PassPort environment variables
# Uncomment to use an environment variable for the master key instead of /etc/passport/key
# APP_MASTER_KEY=<base64-encoded-32-byte-key>
EOF
    chmod 600 "${CONF_DIR}/env"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${CONF_DIR}/env"
fi

# Set ownership
echo "Setting permissions..."
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CONF_DIR}"

# Install systemd unit
echo "Installing systemd service..."
cp deploy/passport.service /etc/systemd/system/passport.service
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Directory layout:"
echo "  Binary:     ${BIN_DIR}/passport"
echo "  Config:     ${APP_DIR}/config.yaml (created on first start)"
echo "  Database:   ${APP_DIR}/passport.db (created on first start)"
echo "  Uploads:    ${APP_DIR}/uploads/"
echo "  Master key: ${CONF_DIR}/key"
echo "  Systemd:    /etc/systemd/system/passport.service"
echo ""
echo "Next steps:"
echo "  1. Review the config:     vim ${APP_DIR}/config.yaml"
echo "  2. Start the service:     systemctl start passport"
echo "  3. Enable on boot:        systemctl enable passport"
echo "  4. Check status:          systemctl status passport"
echo "  5. View logs:             journalctl -u passport -f"
echo ""
echo "The initial admin password will be printed in the logs on first start."
