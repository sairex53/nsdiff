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
    echo "snapshot test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-test.XXXXXX
)"

child_pid=""
ready_file=""


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

    child_pid=""
}


trap cleanup EXIT


snapshot_a="$tmpdir/a.nsnap"
snapshot_b="$tmpdir/b.nsnap"
snapshot_bad="$tmpdir/bad.nsnap"


#
# Capture the test shell.
#

"$NSDIFF" \
    --capture \
    "$snapshot_a" \
    "$$" \
    >/dev/null


if [[ ! -s "$snapshot_a" ]]; then
    fail \
        "capture did not create a snapshot"
fi


#
# Snapshot against the same live process.
#

if "$NSDIFF" \
    --against \
    "$snapshot_a" \
    --quiet \
    "$$"; then

    against_same_rc=0

else

    against_same_rc=$?
fi


if (( against_same_rc != 0 )); then
    fail \
        "snapshot against original process returned $against_same_rc"
fi


#
# Same snapshot against itself.
#

if "$NSDIFF" \
    --snapshots \
    "$snapshot_a" \
    "$snapshot_a" \
    --quiet; then

    same_rc=0

else

    same_rc=$?
fi


if (( same_rc != 0 )); then
    fail \
        "same snapshot comparison returned $same_rc"
fi


#
# Spawn a process with controlled environment differences.
#

ready_file="$tmpdir/ready"


env \
    LANG=nsdiff_SNAPSHOT_TEST \
    TMPDIR=/tmp/nsdiff-snapshot-value \
    sh -c '
        ready_file="$1"

        printf "ready\n" > "$ready_file"

        exec sleep 10
    ' \
    sh \
    "$ready_file" &

child_pid=$!


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
        "snapshot child did not become ready"
fi


"$NSDIFF" \
    --capture \
    "$snapshot_b" \
    "$child_pid" \
    >/dev/null


#
# We no longer need the live child.
# Everything below must work offline.
#

kill "$child_pid" \
    2>/dev/null || true

wait "$child_pid" \
    2>/dev/null || true

child_pid=""


#
# Offline comparison must detect differences.
#

if "$NSDIFF" \
    --snapshots \
    "$snapshot_a" \
    "$snapshot_b" \
    --quiet; then

    different_rc=0

else

    different_rc=$?
fi


if (( different_rc != 1 )); then
    fail \
        "different snapshots returned $different_rc instead of 1"
fi


#
# Environment scope must differ.
#

if "$NSDIFF" \
    --snapshots \
    "$snapshot_a" \
    "$snapshot_b" \
    --section environment \
    --quiet; then

    environment_rc=0

else

    environment_rc=$?
fi


if (( environment_rc != 1 )); then
    fail \
        "offline environment scope returned $environment_rc instead of 1"
fi


#
# Network inherited from the same parent should be identical.
#

if "$NSDIFF" \
    --snapshots \
    "$snapshot_a" \
    "$snapshot_b" \
    --section network \
    --quiet; then

    network_rc=0

else

    network_rc=$?
fi


if (( network_rc != 0 )); then
    fail \
        "offline network scope returned $network_rc instead of 0"
fi


#
# Compact offline output.
#

offline_output=""

if offline_output="$(
    "$NSDIFF" \
        --snapshots \
        "$snapshot_a" \
        "$snapshot_b" \
        --section environment \
        --only-differences
)"; then

    offline_rc=0

else

    offline_rc=$?
fi


if (( offline_rc != 1 )); then
    fail \
        "offline compact comparison returned $offline_rc"
fi


grep -Fq \
    'environment.LANG' \
    <<<"$offline_output" \
    || fail \
        "offline output did not contain environment.LANG"


grep -Fq \
    'nsdiff_SNAPSHOT_TEST' \
    <<<"$offline_output" \
    || fail \
        "offline output lost captured LANG value"


#
# JSON from offline snapshots.
#

json_output=""

if json_output="$(
    "$NSDIFF" \
        --snapshots \
        "$snapshot_a" \
        "$snapshot_b" \
        --json
)"; then

    json_rc=0

else

    json_rc=$?
fi


if (( json_rc != 1 )); then
    fail \
        "offline JSON comparison returned $json_rc"
fi


python3 -c '
import json
import sys

data = json.load(sys.stdin)

assert data["schema_version"] == 1
assert data["summary"]["differences"] > 0
' <<<"$json_output" \
    || fail \
        "offline JSON output is invalid"


#
# Corruption must be detected.
#

cp \
    "$snapshot_a" \
    "$snapshot_bad"


python3 - \
    "$snapshot_bad" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

if len(data) < 128:
    raise SystemExit("snapshot unexpectedly small")

index = len(data) // 2
data[index] ^= 0xFF

path.write_bytes(data)
PY


if "$NSDIFF" \
    --snapshots \
    "$snapshot_bad" \
    "$snapshot_a" \
    --quiet \
    >/dev/null \
    2>&1; then

    corrupt_rc=0

else

    corrupt_rc=$?
fi


if (( corrupt_rc != 2 )); then
    fail \
        "corrupt snapshot returned $corrupt_rc instead of 2"
fi


#
# Random files must not be accepted.
#

printf \
    'this is not an nsdiff snapshot\n' \
    >"$snapshot_bad"


if "$NSDIFF" \
    --snapshots \
    "$snapshot_bad" \
    "$snapshot_a" \
    --quiet \
    >/dev/null \
    2>&1; then

    invalid_rc=0

else

    invalid_rc=$?
fi


if (( invalid_rc != 2 )); then
    fail \
        "invalid snapshot returned $invalid_rc instead of 2"
fi


trap - EXIT

rm -rf \
    "$tmpdir"


echo "snapshot tests passed"
