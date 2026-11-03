#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
if (($# == 0)); then exec python3 "$ROOT/lib/controller.py"; fi
exec python3 "$ROOT/lib/controller.py" node "$@"
