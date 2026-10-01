#!/usr/bin/env bash
set -euo pipefail
binary="${1:-build-release/src/nsdiff}"
command -v readelf >/dev/null || { echo 'NOT RUN: readelf unavailable'; exit 77; }
readelf -h "$binary" | grep -E 'Type:.*DYN' >/dev/null || { echo 'missing PIE'; exit 1; }
readelf -lW "$binary" | grep GNU_RELRO >/dev/null || { echo 'missing RELRO'; exit 1; }
readelf -dW "$binary" | grep -E 'BIND_NOW|FLAGS.*NOW' >/dev/null || { echo 'missing NOW'; exit 1; }
readelf -lW "$binary" | awk '/GNU_STACK/ {found=1; if ($0 ~ /RWE/) exit 1} END {if (!found) exit 1}'
readelf -sW "$binary" | grep __stack_chk_fail >/dev/null || { echo 'missing stack protector'; exit 1; }
# Fortified calls should be present in an optimized glibc build.
if ldd "$binary" 2>/dev/null | grep libc.so.6 >/dev/null; then
  readelf -sW "$binary" | grep -E '__[a-z_]+_chk' >/dev/null || { echo 'missing FORTIFY calls'; exit 1; }
fi
echo 'PASS: PIE, RELRO/NOW, non-executable stack, stack protector, FORTIFY (glibc)'
