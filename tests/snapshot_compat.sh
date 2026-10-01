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
    echo "snapshot-compat test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-compat.XXXXXX
)"

snapshot="$tmpdir/good.nsnap"
mutated="$tmpdir/mutated.nsnap"
json_file="$tmpdir/report.json"


cleanup()
{
    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture failed"


# Current snapshot must be compatible.
"$NSDIFF" \
    --snapshot-compat \
    "$snapshot" \
    >"$tmpdir/text.txt" \
    || fail \
        "current snapshot reported incompatible"


grep -Eq \
    '^[[:space:]]*result[[:space:]]+compatible$' \
    "$tmpdir/text.txt" \
    || fail \
        "text compatibility result missing"


"$NSDIFF" \
    --snapshot-compat \
    "$snapshot" \
    --json \
    >"$json_file" \
    || fail \
        "JSON compatibility report failed"


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "valid compatibility JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["compatible"] is True
assert data["magic_valid"] is True
assert data["format_supported"] is True
assert data["abi_supported"] is True
assert data["endian_supported"] is True
assert data["snapshot_size_supported"] is True
assert data["extension_valid"] is True
assert data["payload_complete"] is True
assert data["checksum_checked"] is True
assert data["checksum_valid"] is True
assert data["trailing_data"] is False
assert data["reason"] == "compatible"
PY


# stdin must also work.
cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshot-compat \
        - \
        --json \
        >"$json_file" \
    || fail \
        "stdin compatibility probe failed"


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "stdin compatibility JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["file"] == "-"
assert data["compatible"] is True
PY


check_incompatible()
{
    local field="$1"
    local expected="$2"

    if "$NSDIFF" \
        --snapshot-compat \
        "$mutated" \
        --json \
        >"$json_file" \
        2>/dev/null; then

        rc=0

    else

        rc=$?
    fi

    if (( rc != 2 )); then
        fail \
            "incompatible snapshot returned $rc instead of 2"
    fi

    python3 - \
        "$json_file" \
        "$field" \
        "$expected" <<'PY' \
        || fail \
            "incompatible compatibility JSON is wrong"
import json
import sys

path, field, expected = sys.argv[1:]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["compatible"] is False

value = data[field]

if expected == "false":
    assert value is False
elif expected == "true":
    assert value is True
else:
    assert str(value) == expected

assert isinstance(data["reason"], str)
assert data["reason"]
PY
}


# ABI mismatch: header offset 20, uint32 little-endian on this test host.
cp "$snapshot" "$mutated"
python3 - "$mutated" <<'PY'
from pathlib import Path
import struct
import sys

p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
struct.pack_into("=I", data, 20, 99)
p.write_bytes(data)
PY
check_incompatible abi_supported false


# Endianness marker mismatch: offset 24.
cp "$snapshot" "$mutated"
python3 - "$mutated" <<'PY'
from pathlib import Path
import struct
import sys

p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
struct.pack_into("=I", data, 24, 0x11223344)
p.write_bytes(data)
PY
check_incompatible endian_supported false


# Unsupported format: offset 16.
cp "$snapshot" "$mutated"
python3 - "$mutated" <<'PY'
from pathlib import Path
import struct
import sys

p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
struct.pack_into("=I", data, 16, 99)
p.write_bytes(data)
PY
check_incompatible format_supported false


# Corrupt payload: checksum must be diagnosed rather than treated as ABI failure.
cp "$snapshot" "$mutated"
python3 - "$mutated" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
data = bytearray(p.read_bytes())

if len(data) < 256:
    raise SystemExit("snapshot unexpectedly small")

data[-1] ^= 0x5A
p.write_bytes(data)
PY
check_incompatible checksum_valid false


# Trailing bytes are reported explicitly.
cp "$snapshot" "$mutated"
printf 'TRAILING' >> "$mutated"
check_incompatible trailing_data true


# A truncated header is not probeable, but JSON output must still be valid.
printf 'short' > "$mutated"

if "$NSDIFF" \
    --snapshot-compat \
    "$mutated" \
    --json \
    >"$json_file" \
    2>/dev/null; then

    truncated_rc=0

else

    truncated_rc=$?
fi


if (( truncated_rc != 2 )); then
    fail \
        "truncated header returned $truncated_rc instead of 2"
fi


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "truncated-header compatibility JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["compatible"] is False
assert isinstance(data["error"], str)
assert data["error"]
PY


# Other output modes and sections remain invalid.
if "$NSDIFF" \
    --snapshot-compat \
    "$snapshot" \
    --summary \
    >/dev/null \
    2>&1; then

    mode_rc=0

else

    mode_rc=$?
fi


if (( mode_rc != 2 )); then
    fail \
        "--snapshot-compat --summary returned $mode_rc instead of 2"
fi


trap - EXIT
cleanup


echo "snapshot-compat tests passed"
