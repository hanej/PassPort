#!/usr/bin/env bash
set -euo pipefail

# RPM passes 0 when the package is being erased and 1 when it is being replaced
# by an upgrade. Only stop and disable the service on a real removal; on upgrade
# the new package's posttrans restarts it.
if [ "${1:-0}" = "0" ]; then
    systemctl stop    passport 2>/dev/null || true
    systemctl disable passport 2>/dev/null || true
fi
