#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$ROOT/lib/controller.py" user "$@"
