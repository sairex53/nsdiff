#!/usr/bin/env bash
set -euo pipefail
binary="${1:-build/src/nsdiff}"
iterations="${2:-1000}"
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$root/scripts/stress.py" "$binary" "$iterations"
