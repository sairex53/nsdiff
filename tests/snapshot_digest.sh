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
    echo "snapshot-digest test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-digest.XXXXXX
)"

v3="$tmpdir/v3.nsnap"
v2="$tmpdir/v2.nsnap"
v1="$tmpdir/v1.nsnap"
corrupt="$tmpdir/corrupt.nsnap"
info="$tmpdir/info.json"


cleanup()
{
    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


"$NSDIFF" \
    --capture \
    "$v3" \
    "$$" \
    >/dev/null \
    || fail \
        "v3 capture failed"


"$NSDIFF" \
    --snapshot-info \
    "$v3" \
    --json \
    >"$info" \
    || fail \
        "v3 metadata inspection failed"


python3 - \
    "$v3" \
    "$info" <<'PY' \
    || fail \
        "stored SHA-256 does not match payload"
import hashlib
import json
import struct
import sys

snapshot_path, info_path = sys.argv[1:]

data = open(snapshot_path, "rb").read()

if len(data) < 88:
    raise SystemExit("snapshot too small")

format_version = struct.unpack_from("=I", data, 16)[0]
extension_size = struct.unpack_from("=I", data, 80)[0]

assert format_version == 3
assert extension_size >= 8
assert 80 + extension_size <= len(data)

payload = data[80 + extension_size:]
expected = hashlib.sha256(payload).hexdigest()

with open(info_path, "r", encoding="utf-8") as f:
    info = json.load(f)

assert info["format_version"] == 3
assert info["checksum"] == "ok"
assert info["sha256"] == expected
PY


"$NSDIFF" \
    --verify-snapshot \
    "$v3" \
    >/dev/null \
    || fail \
        "valid v3 snapshot failed verification"


"$NSDIFF" \
    --snapshot-compat \
    "$v3" \
    --json \
    >"$info" \
    || fail \
        "valid v3 snapshot failed compatibility check"


python3 - \
    "$info" <<'PY' \
    || fail \
        "v3 compatibility digest status is wrong"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["compatible"] is True
assert data["checksum_checked"] is True
assert data["checksum_valid"] is True
assert data["sha256_checked"] is True
assert data["sha256_valid"] is True
PY


#
# Build valid legacy v2 and v1 snapshots from the same payload.
# This proves v0.0.22 still reads formats emitted by older releases.
#

python3 - \
    "$v3" \
    "$v2" \
    "$v1" <<'PY'
from pathlib import Path
import struct
import sys

src, v2_path, v1_path = map(Path, sys.argv[1:])

data = bytearray(src.read_bytes())

header_size = 80
v3_extension_size = struct.unpack_from("=I", data, header_size)[0]

if v3_extension_size < 216:
    raise SystemExit("unexpected v3 extension size")

payload = bytes(data[header_size + v3_extension_size:])

v2_extension = bytearray(data[header_size:header_size + 216])
struct.pack_into("=I", v2_extension, 0, 216)

v2_header = bytearray(data[:header_size])
struct.pack_into("=I", v2_header, 16, 2)

v2_path.write_bytes(
    bytes(v2_header)
    + bytes(v2_extension)
    + payload
)

v1_header = bytearray(data[:header_size])
struct.pack_into("=I", v1_header, 16, 1)

v1_path.write_bytes(
    bytes(v1_header)
    + payload
)
PY


"$NSDIFF" \
    --verify-snapshot \
    "$v2" \
    >/dev/null \
    || fail \
        "legacy v2 snapshot is no longer readable"


"$NSDIFF" \
    --verify-snapshot \
    "$v1" \
    >/dev/null \
    || fail \
        "legacy v1 snapshot is no longer readable"


"$NSDIFF" \
    --snapshot-info \
    "$v2" \
    --json \
    >"$info" \
    || fail \
        "legacy v2 metadata failed"


python3 - \
    "$info" <<'PY' \
    || fail \
        "legacy v2 SHA metadata is wrong"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["format_version"] == 2
assert data["checksum"] == "ok"
assert data["sha256"] is None
PY


#
# Corrupt current payload. Both checks should detect it.
#

cp \
    "$v3" \
    "$corrupt"


python3 - \
    "$corrupt" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

if len(data) < 1:
    raise SystemExit("empty snapshot")

data[-1] ^= 0x5A
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
        "corrupt v3 snapshot returned $corrupt_rc instead of 2"
fi


if "$NSDIFF" \
    --snapshot-compat \
    "$corrupt" \
    --json \
    >"$info" \
    2>/dev/null; then

    compat_rc=0

else

    compat_rc=$?
fi


if (( compat_rc != 2 )); then
    fail \
        "corrupt v3 compatibility returned $compat_rc instead of 2"
fi


python3 - \
    "$info" <<'PY' \
    || fail \
        "corrupt v3 digest diagnostics are wrong"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["compatible"] is False
assert data["checksum_checked"] is True
assert data["checksum_valid"] is False
assert data["sha256_checked"] is True
assert data["sha256_valid"] is False
PY


trap - EXIT
cleanup


echo "snapshot-digest tests passed"
