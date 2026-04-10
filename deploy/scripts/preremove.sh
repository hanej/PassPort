#!/usr/bin/env bash
set -euo pipefail

systemctl stop    passport 2>/dev/null || true
systemctl disable passport 2>/dev/null || true
