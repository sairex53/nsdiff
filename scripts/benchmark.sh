#!/usr/bin/env bash
set -euo pipefail
binary="${1:-build-release/src/nsdiff}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
"$binary" --convert-snapshot "$root/tests/fixtures/portable-v1.json" "$work/native" --snapshot-format native
python3 - "$binary" "$work/native" "$root/tests/fixtures/portable-v1.json" <<'PY'
import os, subprocess, sys, time
binary,native,portable=sys.argv[1:]
cases={'native load':['--snapshot-info',native], 'portable load':['--snapshot-info',portable], 'native/portable diff':['--snapshots',native,portable,'--quiet']}
if int(open('/proc/self/stat').read().split(' ',1)[0])==os.getpid(): cases['live same-process']=['--quiet',str(os.getpid()),str(os.getpid())]
else: print('NOT RUN: live benchmark requires matching PID namespace/procfs')
for name,args in cases.items():
    start=time.perf_counter()
    for _ in range(100): subprocess.run([binary,*args], stdout=subprocess.DEVNULL, check=True)
    print(f'{name}: {(time.perf_counter()-start)*10:.3f} ms/process (100 invocations; includes startup)')
PY
