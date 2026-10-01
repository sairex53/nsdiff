#!/usr/bin/env bash
# Verification only: source mutation and tag creation are deliberately separate.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
[[ -z "$(git status --porcelain)" ]] || { echo 'release: commit/review all changes first'; exit 1; }
git diff --check
git diff --cached --check
head="$(git rev-parse HEAD)"
for command in gcc clang meson ninja python3 valgrind; do command -v "$command" >/dev/null; done
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for compiler in gcc clang; do
  CC="$compiler" meson setup "$work/$compiler" -Dbuildtype=debug -Db_sanitize=address,undefined -Db_lundef=false -Dwerror=true
  meson compile -C "$work/$compiler"
  meson test -C "$work/$compiler" --print-errorlogs
  python3 scripts/check-registration.py "$work/$compiler"
  python3 - "$work/$compiler/meson-logs/testlog.json" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    t=json.loads(line)
    if t['result'] not in ('OK','EXPECTEDFAIL'): raise SystemExit('release: a test was skipped or failed: '+t['name'])
PY
done
meson setup "$work/release" -Dbuildtype=release -Dwerror=true
meson compile -C "$work/release"
meson test -C "$work/release" --print-errorlogs
version="$("$work/release/src/nsdiff" --version | awk '{print $2}')"
python3 - "$version" "$work/release" <<'PY'
import json, subprocess, sys
info=json.loads(subprocess.check_output(['meson','introspect','--projectinfo',sys.argv[2]]))
assert info['version']==sys.argv[1]
PY
scripts/valgrind-smoke.sh "$work/release/src/nsdiff"
scripts/check-hardening.sh "$work/release/src/nsdiff"
scripts/install-smoke.sh "$work/release"
scripts/static-check.sh "$work/release" --strict
scripts/stress.sh "$work/release/src/nsdiff" 1000
CC=clang meson setup "$work/fuzz" -Dfuzz=true -Dbuildtype=debug -Db_lundef=false
meson compile -C "$work/fuzz"
scripts/fuzz-smoke.sh "$work/fuzz" 10
meson dist -C "$work/release"
[[ "$(git rev-parse HEAD)" == "$head" && -z "$(git status --porcelain)" ]]
printf 'All release gates passed at %s. No commit, tag or push performed.\n' "$head"
printf 'After reviewing, tag this exact commit: git tag -a v%s %s -m "nsdiff %s"\n' "$version" "$head" "$version"
