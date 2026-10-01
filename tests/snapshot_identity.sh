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
    echo "snapshot-identity test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-identity.XXXXXX
)"

v3="$tmpdir/v3.nsnap"
v2="$tmpdir/v2.nsnap"
v1="$tmpdir/v1.nsnap"
broken="$tmpdir/broken.nsnap"
json_file="$tmpdir/id.json"


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
        "capture failed"


#
# Plain output is deliberately one stable ID line.
#

id_v3="$(
    "$NSDIFF" \
        --snapshot-id \
        "$v3"
)"


if [[ ! "$id_v3" =~ ^nsdiff:sha256:[0-9a-f]{64}$ ]]; then
    fail \
        "plain snapshot ID has unexpected format: $id_v3"
fi


#
# Verify ID against an independent Python SHA-256 of the native payload.
#

python3 - \
    "$v3" \
    "$id_v3" <<'PY' \
    || fail \
        "snapshot ID does not match payload SHA-256"
import hashlib
import struct
import sys

snapshot_path, snapshot_id = sys.argv[1:]

data = open(snapshot_path, "rb").read()

header_size = 80
format_version = struct.unpack_from("=I", data, 16)[0]

if format_version == 1:
    payload_offset = header_size
else:
    extension_size = struct.unpack_from("=I", data, header_size)[0]
    payload_offset = header_size + extension_size

payload = data[payload_offset:]

expected = "nsdiff:sha256:" + hashlib.sha256(payload).hexdigest()

assert snapshot_id == expected
PY


#
# JSON output.
#

"$NSDIFF" \
    --snapshot-id \
    "$v3" \
    --json \
    >"$json_file" \
    || fail \
        "snapshot identity JSON failed"


python3 - \
    "$json_file" \
    "$id_v3" <<'PY' \
    || fail \
        "snapshot identity JSON is malformed"
import json
import re
import sys

path, expected_id = sys.argv[1:]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["valid"] is True
assert data["id"] == expected_id
assert data["algorithm"] == "sha256"
assert data["scope"] == "payload"
assert re.fullmatch(r"[0-9a-f]{64}", data["digest"])
assert expected_id == "nsdiff:sha256:" + data["digest"]
assert data["format_version"] == 3
assert isinstance(data["pid"], int)
assert data["pid"] > 0
assert isinstance(data["starttime_ticks"], int)
assert data["starttime_ticks"] > 0
PY


#
# stdin streaming.
#

id_stdin="$(
    cat \
        "$v3" |
    "$NSDIFF" \
        --snapshot-id \
        -
)"


if [[ "$id_stdin" != "$id_v3" ]]; then
    fail \
        "stdin identity differs from file identity"
fi


#
# Construct valid legacy v2/v1 containers around exactly the same
# payload. Identity must remain unchanged because it is payload-scoped.
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

payload = bytes(
    data[
        header_size + v3_extension_size:
    ]
)

v2_extension = bytearray(
    data[
        header_size:
        header_size + 216
    ]
)

struct.pack_into(
    "=I",
    v2_extension,
    0,
    216,
)

v2_header = bytearray(
    data[:header_size]
)

struct.pack_into(
    "=I",
    v2_header,
    16,
    2,
)

v2_path.write_bytes(
    bytes(v2_header)
    + bytes(v2_extension)
    + payload
)

v1_header = bytearray(
    data[:header_size]
)

struct.pack_into(
    "=I",
    v1_header,
    16,
    1,
)

v1_path.write_bytes(
    bytes(v1_header)
    + payload
)
PY


id_v2="$(
    "$NSDIFF" \
        --snapshot-id \
        "$v2"
)"

id_v1="$(
    "$NSDIFF" \
        --snapshot-id \
        "$v1"
)"


if [[ "$id_v1" != "$id_v3" ||
      "$id_v2" != "$id_v3" ]]; then

    fail \
        "same payload has different IDs across v1/v2/v3"
fi


#
# Corruption must be rejected; never assign an ID to invalid input.
#

cp \
    "$v3" \
    "$broken"


python3 - \
    "$broken" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

if not data:
    raise SystemExit("snapshot unexpectedly empty")

data[-1] ^= 0x5A

path.write_bytes(data)
PY


if "$NSDIFF" \
    --snapshot-id \
    "$broken" \
    --json \
    >"$json_file" \
    2>/dev/null; then

    broken_rc=0

else

    broken_rc=$?
fi


if (( broken_rc != 2 )); then
    fail \
        "corrupt snapshot identity returned $broken_rc instead of 2"
fi


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "invalid identity JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["valid"] is False
assert isinstance(data["error"], str)
assert data["error"]
assert "id" not in data
PY


#
# Sections and unrelated output modes are invalid.
#

if "$NSDIFF" \
    --snapshot-id \
    "$v3" \
    --summary \
    >/dev/null \
    2>&1; then

    mode_rc=0

else

    mode_rc=$?
fi


if (( mode_rc != 2 )); then
    fail \
        "--snapshot-id --summary returned $mode_rc instead of 2"
fi


if "$NSDIFF" \
    --snapshot-id \
    "$v3" \
    --section environment \
    >/dev/null \
    2>&1; then

    section_rc=0

else

    section_rc=$?
fi


if (( section_rc != 2 )); then
    fail \
        "--snapshot-id --section returned $section_rc instead of 2"
fi


trap - EXIT
cleanup


echo "snapshot-identity tests passed"
