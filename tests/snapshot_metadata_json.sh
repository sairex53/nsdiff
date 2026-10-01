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
    echo "snapshot-metadata-json test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-metadata-json.XXXXXX
)"

snapshot="$tmpdir/process.nsnap"
weird_snapshot="$tmpdir/quote\"snapshot.nsnap"
corrupt="$tmpdir/corrupt.nsnap"

info_json="$tmpdir/info.json"
stdin_json="$tmpdir/stdin.json"
verify_json="$tmpdir/verify.json"
invalid_json="$tmpdir/invalid.json"


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


version="$(
    "$NSDIFF" \
        --version |
    awk '{print $2}'
)"


"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture failed"


#
# Metadata JSON for a valid snapshot.
#

"$NSDIFF" \
    --snapshot-info \
    "$snapshot" \
    --json \
    >"$info_json" \
    || fail \
        "snapshot metadata JSON failed"


python3 - \
    "$info_json" \
    "$snapshot" \
    "$version" \
    "$current_format" \
    "$(uname -r)" \
    "$(uname -m)" <<'PY' \
    || fail \
        "snapshot metadata JSON structure is invalid"
import json
import re
import sys

path, snapshot, version, current_format, kernel, machine = sys.argv[1:]
current_format = int(current_format)

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["valid"] is True
assert data["file"] == snapshot
assert data["format_version"] == current_format
assert data["abi_version"] == 1
assert data["producer"] == version

assert isinstance(data["pid"], int)
assert data["pid"] > 0

assert isinstance(data["starttime_ticks"], int)
assert data["starttime_ticks"] > 0

assert isinstance(data["payload_bytes"], int)
assert data["payload_bytes"] > 0

assert re.fullmatch(r"0x[0-9a-f]{16}", data["payload_hash"])
assert data["checksum"] == "ok"
assert re.fullmatch(r"[0-9a-f]{64}", data["sha256"])

assert re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z",
    data["captured_at"],
)

assert data["kernel"] == kernel
assert data["architecture"] == machine
PY


#
# stdin streaming must work with metadata JSON.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshot-info \
        - \
        --json \
        >"$stdin_json" \
    || fail \
        "snapshot metadata JSON from stdin failed"


python3 - \
    "$stdin_json" \
    "$current_format" <<'PY' \
    || fail \
        "stdin metadata JSON is invalid"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

current_format = int(sys.argv[2])

assert data["schema_version"] == 1
assert data["valid"] is True
assert data["file"] == "-"
assert data["format_version"] == current_format
assert data["checksum"] == "ok"
PY


#
# Verification JSON for a valid snapshot.
#

"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    --json \
    >"$verify_json" \
    || fail \
        "JSON verification of valid snapshot failed"


python3 - \
    "$verify_json" \
    "$snapshot" <<'PY' \
    || fail \
        "valid verification JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data == {
    "schema_version": 1,
    "valid": True,
    "file": sys.argv[2],
}
PY


#
# JSON escaping of the file path.
#

cp \
    "$snapshot" \
    "$weird_snapshot"


"$NSDIFF" \
    --snapshot-info \
    "$weird_snapshot" \
    --json \
    >"$info_json" \
    || fail \
        "metadata JSON for quoted path failed"


python3 - \
    "$info_json" \
    "$weird_snapshot" <<'PY' \
    || fail \
        "JSON path escaping is incorrect"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["file"] == sys.argv[2]
PY


#
# Corrupt snapshots must still emit machine-readable JSON,
# but keep the established exit code 2.
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

data[-16] ^= 0x5A
path.write_bytes(data)
PY


if "$NSDIFF" \
    --verify-snapshot \
    "$corrupt" \
    --json \
    >"$invalid_json" \
    2>/dev/null; then

    corrupt_rc=0

else

    corrupt_rc=$?
fi


if (( corrupt_rc != 2 )); then
    fail \
        "corrupt JSON verification returned $corrupt_rc instead of 2"
fi


python3 - \
    "$invalid_json" \
    "$corrupt" <<'PY' \
    || fail \
        "invalid verification JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["valid"] is False
assert data["file"] == sys.argv[2]
assert isinstance(data["error"], str)
assert data["error"]
PY


#
# snapshot-info --json also reports invalid input as JSON.
#

if "$NSDIFF" \
    --snapshot-info \
    "$corrupt" \
    --json \
    >"$invalid_json" \
    2>/dev/null; then

    info_invalid_rc=0

else

    info_invalid_rc=$?
fi


if (( info_invalid_rc != 2 )); then
    fail \
        "invalid metadata JSON returned $info_invalid_rc instead of 2"
fi


python3 - \
    "$invalid_json" <<'PY' \
    || fail \
        "invalid metadata JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["valid"] is False
assert isinstance(data["error"], str)
assert data["error"]
PY


#
# Other comparison output modes remain invalid for standalone
# metadata operations.
#

if "$NSDIFF" \
    --snapshot-info \
    "$snapshot" \
    --summary \
    >/dev/null \
    2>&1; then

    summary_rc=0

else

    summary_rc=$?
fi


if (( summary_rc != 2 )); then
    fail \
        "--snapshot-info --summary returned $summary_rc instead of 2"
fi


if "$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    --explain \
    >/dev/null \
    2>&1; then

    explain_rc=0

else

    explain_rc=$?
fi


if (( explain_rc != 2 )); then
    fail \
        "--verify-snapshot --explain returned $explain_rc instead of 2"
fi


trap - EXIT

cleanup


echo "snapshot-metadata-json tests passed"
