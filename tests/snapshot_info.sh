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
    echo "snapshot-info test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-info.XXXXXX
)"

snapshot="$tmpdir/process.nsnap"
corrupt="$tmpdir/corrupt.nsnap"
invalid="$tmpdir/invalid.nsnap"


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


#
# Capture a current-format snapshot.
#

"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture failed"


#
# Inspect it.
#

info="$(
    "$NSDIFF" \
        --snapshot-info \
        "$snapshot"
)"


grep -Eq \
    '^Snapshot$' \
    <<<"$info" \
    || fail \
        "Snapshot heading missing"


grep -Eq \
    "^[[:space:]]*format[[:space:]]+$current_format$" \
    <<<"$info" \
    || fail \
        "snapshot format missing"


grep -Eq \
    '^[[:space:]]*ABI[[:space:]]+1$' \
    <<<"$info" \
    || fail \
        "snapshot ABI missing"


version="$(
    "$NSDIFF" \
        --version |
    awk '{print $2}'
)"


grep -Fq \
    "  producer        nsdiff $version" \
    <<<"$info" \
    || fail \
        "snapshot producer missing"


grep -Eq \
    '^[[:space:]]*PID[[:space:]]+[1-9][0-9]*$' \
    <<<"$info" \
    || fail \
        "snapshot PID missing"


grep -Eq \
    '^[[:space:]]*starttime[[:space:]]+[1-9][0-9]*$' \
    <<<"$info" \
    || fail \
        "snapshot starttime missing"


grep -Eq \
    '^[[:space:]]*payload bytes[[:space:]]+[1-9][0-9]*$' \
    <<<"$info" \
    || fail \
        "snapshot payload size missing"


grep -Eq \
    '^[[:space:]]*checksum[[:space:]]+ok$' \
    <<<"$info" \
    || fail \
        "snapshot checksum status missing"


grep -Eq \
    '^[[:space:]]*sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+\[ok\]$' \
    <<<"$info" \
    || fail \
        "snapshot SHA-256 missing"


grep -Eq \
    '^[[:space:]]*captured[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$' \
    <<<"$info" \
    || fail \
        "snapshot capture time missing"


kernel="$(
    uname -r
)"

machine="$(
    uname -m
)"


grep -Fq \
    "  kernel          $kernel" \
    <<<"$info" \
    || fail \
        "snapshot kernel provenance missing"


grep -Fq \
    "  architecture    $machine" \
    <<<"$info" \
    || fail \
        "snapshot architecture provenance missing"


#
# Verification of a valid snapshot must succeed.
#

"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    >/dev/null \
    || fail \
        "valid snapshot verification failed"


#
# Corrupt one byte in the payload/extension area.
#

cp \
    "$snapshot" \
    "$corrupt"


python3 - \
    "$corrupt" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

if len(data) < 256:
    raise SystemExit("snapshot unexpectedly small")

# Flip a byte near the end so the header remains parseable and
# checksum validation is what rejects the snapshot.
data[-32] ^= 0x5A

path.write_bytes(data)
PY


if "$NSDIFF" \
    --verify-snapshot \
    "$corrupt" \
    >/dev/null \
    2>&1; then

    corrupt_rc=0

else

    corrupt_rc=$?
fi


if (( corrupt_rc != 2 )); then
    fail \
        "corrupt snapshot verification returned $corrupt_rc instead of 2"
fi


#
# Completely invalid input must also fail with exit 2.
#

printf '%s\n' \
    'this is not an nsdiff snapshot' \
    >"$invalid"


if "$NSDIFF" \
    --snapshot-info \
    "$invalid" \
    >/dev/null \
    2>&1; then

    invalid_rc=0

else

    invalid_rc=$?
fi


if (( invalid_rc != 2 )); then
    fail \
        "invalid snapshot inspection returned $invalid_rc instead of 2"
fi


trap - EXIT

cleanup


echo "snapshot-info tests passed"
