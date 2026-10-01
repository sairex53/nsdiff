#!/usr/bin/env bash

set -euo pipefail


if (( $# != 1 )); then
    echo "usage: $0 NSDIFF" >&2
    exit 1
fi


NSDIFF_ARG="$1"

if [[ "$NSDIFF_ARG" = /* ]]; then
    NSDIFF="$NSDIFF_ARG"
else
    NSDIFF="$PWD/$NSDIFF_ARG"
fi


fail()
{
    echo "snapshot-export test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-export.XXXXXX
)"

child_pid=""
ready_file="$tmpdir/ready"

snapshot="$tmpdir/process.nsnap"
broken_snapshot="$tmpdir/broken.nsnap"

json_file="$tmpdir/export.json"
stderr_file="$tmpdir/stderr.txt"

secret='SUPER_SECRET_EXPORT_NSDIFF_8f34c1'


cleanup()
{
    local pid="${child_pid:-}"

    if [[ -n "$pid" ]]; then
        kill "$pid" \
            2>/dev/null || true

        wait "$pid" \
            2>/dev/null || true
    fi

    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


#
# Create a live process whose environment contains:
#
#   - a known non-sensitive LANG value, which must survive export;
#   - a known proxy secret, which must never appear in exported JSON.
#

env \
    LANG=nsdiff_EXPORT_TEST \
    HTTP_PROXY="http://user:${secret}@127.0.0.1:8080/" \
    sh -c '
        ready_file="$1"

        printf "ready\n" > "$ready_file"

        exec sleep 10
    ' \
    sh \
    "$ready_file" &

child_pid=$!


#
# Wait until the child has completed exec and its environment is stable.
#

ready=0

for _ in {1..200}; do

    if [[ -f "$ready_file" ]]; then
        ready=1
        break
    fi

    if ! kill -0 \
        "$child_pid" \
        2>/dev/null; then

        break
    fi

    sleep 0.01
done


if (( ready != 1 )); then
    fail \
        "child did not become ready"
fi


#
# Capture the live process.
#

if "$NSDIFF" \
    --capture \
    "$snapshot" \
    "$child_pid" \
    >/dev/null; then

    capture_rc=0

else

    capture_rc=$?
fi


if (( capture_rc != 0 )); then
    fail \
        "capture returned $capture_rc instead of 0"
fi


if [[ ! -s "$snapshot" ]]; then
    fail \
        "capture did not create a non-empty snapshot"
fi


#
# The export must work after the original process is gone.
#

kill "$child_pid" \
    2>/dev/null || true

wait "$child_pid" \
    2>/dev/null || true

child_pid=""


#
# Export native .nsnap to JSON.
#

if "$NSDIFF" \
    --export-snapshot-json \
    "$snapshot" \
    >"$json_file" \
    2>"$stderr_file"; then

    export_rc=0

else

    export_rc=$?
fi


if (( export_rc != 0 )); then

    cat \
        "$stderr_file" \
        >&2 || true

    fail \
        "JSON export returned $export_rc instead of 0"
fi


if [[ ! -s "$json_file" ]]; then
    fail \
        "JSON export produced an empty file"
fi


#
# The exported document must be valid schema-v1 comparison JSON.
#
# v0.0.15 deliberately renders the loaded snapshot against itself,
# so summary.differences must be zero and A/B process identity must match.
#

python3 - \
    "$json_file" <<'PY' \
    || fail \
        "exported JSON structure is invalid"
import json
import re
import sys

path = sys.argv[1]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1

version = data["tool_version"]
assert isinstance(version, str)
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)

assert isinstance(data["pid_a"], int)
assert isinstance(data["pid_b"], int)
assert data["pid_a"] == data["pid_b"]

assert data["starttime_a"] == data["starttime_b"]

summary = data["summary"]

assert isinstance(summary["comparable_fields"], int)
assert summary["comparable_fields"] > 0

assert summary["differences"] == 0

fields = data["fields"]

assert isinstance(fields, list)
assert len(fields) > 0

by_path = {
    field["path"]: field
    for field in fields
}

assert "environment.LANG" in by_path
assert "environment.HTTP_PROXY" in by_path

lang = by_path["environment.LANG"]

assert lang["state"] == "same"
assert lang["status_a"] == "ok"
assert lang["status_b"] == "ok"
assert lang["redacted"] is False
assert lang["a"] == "nsdiff_EXPORT_TEST"
assert lang["b"] == "nsdiff_EXPORT_TEST"

proxy = by_path["environment.HTTP_PROXY"]

assert proxy["state"] == "same"
assert proxy["status_a"] == "ok"
assert proxy["status_b"] == "ok"
assert proxy["redacted"] is True
PY


#
# A sensitive proxy value must never appear in portable output.
#

if grep -Fq \
    "$secret" \
    "$json_file"; then

    fail \
        "proxy secret leaked into exported JSON"
fi


#
# The known non-sensitive value must actually be present.
#

grep -Fq \
    'nsdiff_EXPORT_TEST' \
    "$json_file" \
    || fail \
        "LANG value is missing from exported JSON"


#
# Ensure the output can also be consumed by a normal JSON tool.
#

python3 -m json.tool \
    "$json_file" \
    >/dev/null \
    || fail \
        "python json.tool rejected exported JSON"


#
# Corrupted native snapshots must not be exported.
#

cp \
    "$snapshot" \
    "$broken_snapshot"


python3 - \
    "$broken_snapshot" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

if len(data) < 128:
    raise SystemExit("snapshot unexpectedly small")

data[len(data) // 2] ^= 0x5A

path.write_bytes(data)
PY


if "$NSDIFF" \
    --export-snapshot-json \
    "$broken_snapshot" \
    >/dev/null \
    2>&1; then

    broken_rc=0

else

    broken_rc=$?
fi


if (( broken_rc != 2 )); then
    fail \
        "corrupt snapshot export returned $broken_rc instead of 2"
fi


#
# Missing snapshot file must fail.
#

if "$NSDIFF" \
    --export-snapshot-json \
    "$tmpdir/does-not-exist.nsnap" \
    >/dev/null \
    2>&1; then

    missing_rc=0

else

    missing_rc=$?
fi


if (( missing_rc != 2 )); then
    fail \
        "missing snapshot export returned $missing_rc instead of 2"
fi


#
# This is a standalone snapshot operation, so positional PIDs are invalid.
#

if "$NSDIFF" \
    --export-snapshot-json \
    "$snapshot" \
    "$$" \
    >/dev/null \
    2>&1; then

    extra_arg_rc=0

else

    extra_arg_rc=$?
fi


if (( extra_arg_rc != 2 )); then
    fail \
        "export with an extra positional argument returned $extra_arg_rc instead of 2"
fi


#
# Snapshot export must not accept comparison output/scoping modifiers.
#

if "$NSDIFF" \
    --export-snapshot-json \
    "$snapshot" \
    --section environment \
    >/dev/null \
    2>&1; then

    section_rc=0

else

    section_rc=$?
fi


if (( section_rc != 2 )); then
    fail \
        "export with --section returned $section_rc instead of 2"
fi


if "$NSDIFF" \
    --export-snapshot-json \
    "$snapshot" \
    --summary \
    >/dev/null \
    2>&1; then

    output_mode_rc=0

else

    output_mode_rc=$?
fi


if (( output_mode_rc != 2 )); then
    fail \
        "export with --summary returned $output_mode_rc instead of 2"
fi


trap - EXIT

cleanup


echo "snapshot-export tests passed"
