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
    echo "snapshot-stream test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-stream.XXXXXX
)"

snapshot="$tmpdir/stream.nsnap"
json_file="$tmpdir/stream.json"
capture_stderr="$tmpdir/capture.stderr"


cleanup()
{
    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


current_format="$(
    "$NSDIFF" \
        --snapshot-schema \
        --json |
    python3 -c '
import json
import sys
print(json.load(sys.stdin)["native_snapshot"]["current_format"])
'
)"


if [[ ! "$current_format" =~ ^[0-9]+$ ]]; then
    fail \
        "snapshot schema returned invalid current format: $current_format"
fi


#
# Capture a binary snapshot to stdout.
# Status text must go to stderr and must not corrupt stdout.
#

"$NSDIFF" \
    --capture \
    - \
    "$$" \
    >"$snapshot" \
    2>"$capture_stderr" \
    || fail \
        "capture to stdout failed"


if [[ ! -s "$snapshot" ]]; then
    fail \
        "capture to stdout produced an empty snapshot"
fi


grep -Fq \
    'captured PID' \
    "$capture_stderr" \
    || fail \
        "capture status was not written to stderr"


grep -Fq \
    'to stdout' \
    "$capture_stderr" \
    || fail \
        "capture stderr does not identify stdout destination"


#
# The streamed bytes must be a normal valid current-format snapshot.
#

"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    >/dev/null \
    || fail \
        "stdout snapshot does not verify as a normal file"


#
# Read snapshot from stdin.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --verify-snapshot \
        - \
        >/dev/null \
    || fail \
        "verification from stdin failed"


info="$(
    cat \
        "$snapshot" |
        "$NSDIFF" \
            --snapshot-info \
            -
)"


grep -Eq \
    "^[[:space:]]*format[[:space:]]+$current_format$" \
    <<<"$info" \
    || fail \
        "snapshot-info from stdin did not report format $current_format"


grep -Eq \
    '^[[:space:]]*checksum[[:space:]]+ok$' \
    <<<"$info" \
    || fail \
        "snapshot-info from stdin did not validate checksum"


#
# JSON export must also accept stdin.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --export-snapshot-json \
        - \
        >"$json_file" \
    || fail \
        "JSON export from stdin failed"


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "JSON exported from stdin is invalid"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["pid_a"] == data["pid_b"]
assert data["summary"]["differences"] == 0
PY


#
# A streamed snapshot can be one side of a snapshot comparison.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshots \
        - \
        "$snapshot" \
        --quiet \
    || fail \
        "stdin/file snapshot comparison failed"


cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshots \
        "$snapshot" \
        - \
        --quiet \
    || fail \
        "file/stdin snapshot comparison failed"


#
# A streamed snapshot can be compared with the live process.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --against \
        - \
        "$$" \
        --quiet \
    || fail \
        "stdin/live comparison failed"


#
# Direct pipeline: capture stdout directly into verification stdin.
#

"$NSDIFF" \
    --capture \
    - \
    "$$" \
    2>/dev/null |
    "$NSDIFF" \
        --verify-snapshot \
        - \
        >/dev/null \
    || fail \
        "direct capture/verify pipeline failed"


#
# stdin cannot represent both snapshots simultaneously.
#

if cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshots \
        - \
        - \
        --quiet \
        >/dev/null \
        2>&1; then

    double_stdin_rc=0

else

    double_stdin_rc=$?
fi


if (( double_stdin_rc != 2 )); then
    fail \
        "--snapshots - - returned $double_stdin_rc instead of 2"
fi


#
# Invalid stream must fail normally.
#

if printf '%s\n' \
    'not a snapshot' |
    "$NSDIFF" \
        --verify-snapshot \
        - \
        >/dev/null \
        2>&1; then

    invalid_rc=0

else

    invalid_rc=$?
fi


if (( invalid_rc != 2 )); then
    fail \
        "invalid stdin snapshot returned $invalid_rc instead of 2"
fi


trap - EXIT

cleanup


echo "snapshot-stream tests passed"
