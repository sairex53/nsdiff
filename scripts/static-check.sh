#!/usr/bin/env bash
set -euo pipefail
build="${1:-build}"
strict="${2:-}"
root="$(cd "$(dirname "$0")/.." && pwd)"
missing=0
if command -v cppcheck >/dev/null; then
  cppcheck --enable=warning,performance,portability --error-exitcode=1 --inline-suppr --project="$build/compile_commands.json" --suppress=missingIncludeSystem
else echo 'NOT RUN: cppcheck is unavailable'; missing=1; fi
if command -v clang >/dev/null; then
  python3 - "$build/compile_commands.json" <<'PY'
import json, shlex, subprocess, sys
for entry in json.load(open(sys.argv[1])):
    if '/src/' not in entry['file']: continue
    args=shlex.split(entry['command']); filtered=[]; skip=False
    for arg in args[1:]:
        if skip: skip=False; continue
        if arg in ('-o','-MF','-MT','-MQ'): skip=True; continue
        if arg in ('-c','-MD','-MMD'): continue
        filtered.append(arg)
    subprocess.run(['clang','--analyze','-Xanalyzer','-analyzer-output=text','-Xanalyzer','-analyzer-werror',*filtered], cwd=entry['directory'], check=True)
PY
else echo 'NOT RUN: clang analyzer is unavailable'; missing=1; fi
if command -v clang-tidy >/dev/null; then
  for file in "$root"/src/*.c; do
    clang-tidy --quiet -p "$build" --checks='-*,clang-analyzer-core.*,clang-analyzer-unix.*,clang-analyzer-deadcode.*,clang-analyzer-security.FloatLoopCounter,bugprone-sizeof-expression,bugprone-suspicious-memset-usage,bugprone-string-constructor' --warnings-as-errors='*' "$file"
  done
else echo 'NOT RUN: clang-tidy is unavailable'; missing=1; fi
if [[ "$strict" == --strict && "$missing" == 1 ]]; then exit 1; fi
