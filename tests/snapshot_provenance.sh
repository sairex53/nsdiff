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
    echo "snapshot-provenance test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-provenance.XXXXXX
)"

snapshot="$tmpdir/process.nsnap"


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


"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture failed"


info="$(
    "$NSDIFF" \
        --snapshot-info \
        "$snapshot"
)"


grep -Eq \
    "format[[:space:]]+$current_format$" \
    <<<"$info" \
    || fail \
        "snapshot format is not v2"


grep -Eq \
    'checksum[[:space:]]+ok$' \
    <<<"$info" \
    || fail \
        "checksum is not reported as valid"


grep -Eq \
    'captured[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$' \
    <<<"$info" \
    || fail \
        "capture timestamp is missing or malformed"


kernel="$(
    uname -r
)"

machine="$(
    uname -m
)"


grep -Fq \
    "kernel          $kernel" \
    <<<"$info" \
    || fail \
        "kernel release provenance is incorrect"


grep -Fq \
    "architecture    $machine" \
    <<<"$info" \
    || fail \
        "architecture provenance is incorrect"


"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    >/dev/null \
    || fail \
        "v2 snapshot verification failed"


"$NSDIFF" \
    --snapshots \
    "$snapshot" \
    "$snapshot" \
    --quiet \
    || fail \
        "v2 snapshot self-comparison failed"


mode="$(
    stat \
        -c '%a' \
        "$snapshot"
)"


if [[ "$mode" != "600" ]]; then
    fail \
        "snapshot mode is $mode instead of 600"
fi


trap - EXIT

cleanup


echo "snapshot-provenance tests passed"
