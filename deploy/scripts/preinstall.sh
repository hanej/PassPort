#!/usr/bin/env bash
set -euo pipefail

# Create the passport system user if it doesn't already exist
if ! id -u passport &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin passport
fi
