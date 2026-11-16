#!/usr/bin/env bash
set -euo pipefail

# Runs once the whole RPM transaction is done, after the outgoing package's
# preremove. On upgrade, restore the service to the state preinstall recorded
# and restart it so the new binary is running.
STATE_DIR=/var/lib/rpm-state/passport
[ -d "${STATE_DIR}" ] || exit 0

systemctl daemon-reload
if [ -f "${STATE_DIR}/enabled" ]; then
    systemctl enable passport
fi
if [ -f "${STATE_DIR}/active" ]; then
    systemctl restart passport
fi
rm -rf "${STATE_DIR}"
