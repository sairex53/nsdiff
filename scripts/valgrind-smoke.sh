#!/usr/bin/env bash
set -euo pipefail
binary="${1:-build/src/nsdiff}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fixture="$root/tests/fixtures/portable-v1.json"
vg=(valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all)
"${vg[@]}" "$binary" --convert-snapshot "$fixture" "$work/native" --snapshot-format native
"${vg[@]}" "$binary" --snapshots "$fixture" "$work/native" --quiet
"${vg[@]}" "$binary" --semantic-id "$fixture"
"${vg[@]}" "$binary" --snapshot-manifest "$work/native" --json
printf '%s' '{"schema_version":' > "$work/bad"
set +e
"${vg[@]}" "$binary" --verify-snapshot "$work/bad" --json
rc=$?
set -e
[[ "$rc" == 2 ]]
