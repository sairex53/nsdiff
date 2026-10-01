#!/usr/bin/env bash
set -euo pipefail
build="${1:-build-fuzz}"
seconds="${2:-10}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
cleanup() {
  status=$?
  if [[ "$status" == 0 ]]; then rm -rf "$work"; else printf 'Fuzz corpus/artifacts retained: %s\n' "$work" >&2; fi
}
trap cleanup EXIT
mkdir -p "$work/native" "$work/portable" "$work/bytes" "$work/json"
cp "$root/tests/fixtures/portable-v1.json" "$work/portable/full"
cp "$root/tests/fixtures/portable-v1.json" "$work/json/full"
printf '%s' '{"encoding":"hex","value":"ff010a227f"}' > "$work/bytes/valid"
printf '%s' '{"schema_version":' > "$work/portable/truncated"
"$build/src/nsdiff" --convert-snapshot "$root/tests/fixtures/portable-v1.json" "$work/native/v3" --snapshot-format native
python3 - "$work/native" <<'PY'
from pathlib import Path
import struct, sys
p=Path(sys.argv[1]); raw=(p/'v3').read_bytes()
head=bytearray(raw[:80]); ext=bytearray(raw[80:336]); payload=raw[336:]
struct.pack_into('=I',head,16,1); (p/'v1').write_bytes(head+payload)
struct.pack_into('=I',head,16,2); struct.pack_into('=I',ext,0,216)
(p/'v2').write_bytes(head+ext[:216]+payload)
(p/'truncated').write_bytes(raw[:100]); (p/'corrupt').write_bytes(raw[:-1]+b'X')
PY
for target in native portable bytes json; do
  "$build/fuzz/fuzz-$target" "$work/$target" -max_total_time="$seconds" -timeout=5 -max_len=1048576 -rss_limit_mb=768 -dict="$root/fuzz/json.dict" -artifact_prefix="$work/"
done
