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
    echo "snapshot-schema test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-schema.XXXXXX
)"

text_file="$tmpdir/schema.txt"
json_file="$tmpdir/schema.json"
snapshot="$tmpdir/process.nsnap"


cleanup()
{
    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


#
# Text schema output.
#

"$NSDIFF" \
    --snapshot-schema \
    >"$text_file" \
    || fail \
        "text schema command failed"


grep -Fxq \
    'Snapshot schema' \
    "$text_file" \
    || fail \
        "text schema heading missing"


grep -Eq \
    '^[[:space:]]*native current[[:space:]]+3$' \
    "$text_file" \
    || fail \
        "current native format missing"


grep -Eq \
    '^[[:space:]]*native supported[[:space:]]+1-3$' \
    "$text_file" \
    || fail \
        "supported native formats missing"


grep -Eq \
    '^[[:space:]]*ABI[[:space:]]+1$' \
    "$text_file" \
    || fail \
        "native ABI missing"


grep -Eq \
    '^[[:space:]]*endian marker[[:space:]]+0x01020304$' \
    "$text_file" \
    || fail \
        "endian marker missing"


grep -Eq \
    '^[[:space:]]*payload bytes[[:space:]]+[1-9][0-9]*$' \
    "$text_file" \
    || fail \
        "payload size missing"


grep -Eq \
    '^[[:space:]]*snapshot file mode[[:space:]]+0600$' \
    "$text_file" \
    || fail \
        "snapshot file mode missing"


#
# JSON schema output.
#

"$NSDIFF" \
    --snapshot-schema \
    --json \
    >"$json_file" \
    || fail \
        "JSON schema command failed"


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "snapshot schema JSON is invalid"
import json
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1

native = data["native_snapshot"]

assert native["current_format"] == 3
assert native["supported_formats"] == [1, 2, 3]
assert native["abi_version"] == 1
assert native["endian_marker"] == "0x01020304"
assert isinstance(native["payload_bytes"], int)
assert native["payload_bytes"] > 0

assert native["provenance"] is True
assert native["stdin_stdout"] is True
assert native["atomic_file_writes"] is True
assert native["file_mode"] == "0600"
assert native["payload_checksum"] == "fnv1a64"
assert native["payload_digest"] == "sha256"
assert native["payload_digest_since_format"] == 3

schemas = data["json"]

assert schemas["diff_schema"] == 1
assert schemas["metadata_schema"] == 1
assert schemas["compatibility_schema"] == 1

portable = data["portable_snapshot"]

assert portable == {
    "supported": True,
    "schema_version": 1,
    "import": True,
    "export": True,
}
PY


#
# payload_bytes must agree with an actual current snapshot.
#

"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture failed"


"$NSDIFF" \
    --snapshot-info \
    "$snapshot" \
    --json \
    >"$tmpdir/info.json" \
    || fail \
        "snapshot-info JSON failed"


python3 - \
    "$json_file" \
    "$tmpdir/info.json" <<'PY' \
    || fail \
        "schema payload size disagrees with snapshot metadata"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    schema = json.load(f)

with open(sys.argv[2], "r", encoding="utf-8") as f:
    info = json.load(f)

assert (
    schema["native_snapshot"]["payload_bytes"]
    == info["payload_bytes"]
)
PY


#
# The command takes no positional arguments.
#

if "$NSDIFF" \
    --snapshot-schema \
    1234 \
    >/dev/null \
    2>&1; then

    pid_rc=0

else

    pid_rc=$?
fi


if (( pid_rc != 2 )); then
    fail \
        "--snapshot-schema with PID returned $pid_rc instead of 2"
fi


#
# Only --json is a valid output modifier.
#

if "$NSDIFF" \
    --snapshot-schema \
    --summary \
    >/dev/null \
    2>&1; then

    summary_rc=0

else

    summary_rc=$?
fi


if (( summary_rc != 2 )); then
    fail \
        "--snapshot-schema --summary returned $summary_rc instead of 2"
fi


if "$NSDIFF" \
    --snapshot-schema \
    --section environment \
    >/dev/null \
    2>&1; then

    section_rc=0

else

    section_rc=$?
fi


if (( section_rc != 2 )); then
    fail \
        "--snapshot-schema --section returned $section_rc instead of 2"
fi


trap - EXIT

cleanup


echo "snapshot-schema tests passed"
