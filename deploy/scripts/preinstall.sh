#!/usr/bin/env bash
set -euo pipefail

# Create the passport system user if it doesn't already exist
if ! id -u passport &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin passport
fi

# On upgrade ($1 >= 2), record whether the service is enabled and running before
# the outgoing package's preremove runs. Packages up to v1.3.1 stop and disable
# the service in preremove even on upgrade; posttrans uses these markers to put
# it back the way it was.
STATE_DIR=/var/lib/rpm-state/passport
rm -rf "${STATE_DIR}"
if [ "${1:-1}" -ge 2 ] 2>/dev/null; then
    mkdir -p "${STATE_DIR}"
    if systemctl is-enabled --quiet passport 2>/dev/null; then
        touch "${STATE_DIR}/enabled"
    fi
    if systemctl is-active --quiet passport 2>/dev/null; then
        touch "${STATE_DIR}/active"
    fi
fi
