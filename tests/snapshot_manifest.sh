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
    echo "snapshot-manifest test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-manifest.XXXXXX
)"

snapshot="$tmpdir/process.nsnap"
broken="$tmpdir/broken.nsnap"
text_file="$tmpdir/manifest.txt"
json_file="$tmpdir/manifest.json"
stdin_json="$tmpdir/stdin.json"


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


snapshot_id="$(
    "$NSDIFF" \
        --snapshot-id \
        "$snapshot"
)"


#
# Text manifest.
#

"$NSDIFF" \
    --snapshot-manifest \
    "$snapshot" \
    >"$text_file" \
    || fail \
        "text manifest failed"


grep -Fxq \
    'Snapshot manifest' \
    "$text_file" \
    || fail \
        "manifest heading missing"


grep -Fq \
    "  id              $snapshot_id" \
    "$text_file" \
    || fail \
        "manifest ID does not match --snapshot-id"


grep -Eq \
    '^[[:space:]]*format[[:space:]]+3$' \
    "$text_file" \
    || fail \
        "manifest format missing"


grep -Eq \
    '^[[:space:]]*stored sha256[[:space:]]+[0-9a-f]{64}[[:space:]]+\[ok\]$' \
    "$text_file" \
    || fail \
        "stored SHA-256 missing"


grep -Eq \
    '^[[:space:]]*result[[:space:]]+valid$' \
    "$text_file" \
    || fail \
        "manifest result missing"


#
# JSON manifest.
#

"$NSDIFF" \
    --snapshot-manifest \
    "$snapshot" \
    --json \
    >"$json_file" \
    || fail \
        "JSON manifest failed"


python3 - \
    "$json_file" \
    "$snapshot" \
    "$snapshot_id" \
    "$(uname -r)" \
    "$(uname -m)" <<'PY' \
    || fail \
        "manifest JSON structure is invalid"
import json
import re
import sys

path, snapshot, expected_id, kernel, machine = sys.argv[1:]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["document_type"] == "nsdiff-snapshot-manifest"
assert data["file"] == snapshot
assert data["valid"] is True

identity = data["identity"]

assert identity["id"] == expected_id
assert identity["algorithm"] == "sha256"
assert identity["scope"] == "payload"
assert re.fullmatch(r"[0-9a-f]{64}", identity["digest"])
assert expected_id == "nsdiff:sha256:" + identity["digest"]

native = data["native"]

assert native["format_version"] == 3
assert native["abi_version"] == 1
assert native["payload_bytes"] > 0

assert isinstance(data["producer"], str)
assert data["producer"]

process = data["process"]

assert isinstance(process["pid"], int)
assert process["pid"] > 0
assert isinstance(process["starttime_ticks"], int)
assert process["starttime_ticks"] > 0

integrity = data["integrity"]

assert integrity["verified"] is True
assert re.fullmatch(r"0x[0-9a-f]{16}", integrity["fnv1a64"])
assert re.fullmatch(r"[0-9a-f]{64}", integrity["computed_sha256"])
assert re.fullmatch(r"[0-9a-f]{64}", integrity["stored_sha256"])
assert integrity["computed_sha256"] == integrity["stored_sha256"]
assert integrity["stored_sha256_verified"] is True

provenance = data["provenance"]

assert isinstance(provenance["captured_at"], str)
assert provenance["kernel"] == kernel
assert provenance["architecture"] == machine
PY


#
# stdin is one-pass and must produce the same identity.
#

cat \
    "$snapshot" |
    "$NSDIFF" \
        --snapshot-manifest \
        - \
        --json \
        >"$stdin_json" \
    || fail \
        "stdin manifest failed"


python3 - \
    "$stdin_json" \
    "$snapshot_id" <<'PY' \
    || fail \
        "stdin manifest JSON is invalid"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["file"] == "-"
assert data["valid"] is True
assert data["identity"]["id"] == sys.argv[2]
PY


#
# Invalid snapshots must emit JSON diagnostics and exit 2.
#

cp \
    "$snapshot" \
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
    --snapshot-manifest \
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
        "invalid manifest returned $broken_rc instead of 2"
fi


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "invalid manifest JSON is malformed"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["document_type"] == "nsdiff-snapshot-manifest"
assert data["valid"] is False
assert isinstance(data["error"], str)
assert data["error"]
assert "identity" not in data
PY


#
# Schema advertises the manifest interface.
#

"$NSDIFF" \
    --snapshot-schema \
    --json \
    >"$json_file" \
    || fail \
        "snapshot schema failed"


python3 - \
    "$json_file" <<'PY' \
    || fail \
        "schema does not advertise manifest v1"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

assert data["json"]["manifest_schema"] == 1
PY


#
# Only --json is a valid output modifier.
#

if "$NSDIFF" \
    --snapshot-manifest \
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
        "--snapshot-manifest --summary returned $mode_rc instead of 2"
fi


if "$NSDIFF" \
    --snapshot-manifest \
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
        "--snapshot-manifest --section returned $section_rc instead of 2"
fi


trap - EXIT
cleanup


echo "snapshot-manifest tests passed"
