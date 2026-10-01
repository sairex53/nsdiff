# Verify nsdiff 0.1.0 on Linux

Run from the repository root, as an ordinary user, with `/proc` mounted for the
current PID namespace. These commands also apply to Fedora aarch64. The ZIP
contains a Git repository; the Meson tarball is a standard source distribution.
Do not interpret skipped tests as a fully verified release.

## Dependencies

Fedora:

```bash
sudo dnf install -y gcc clang clang-tools-extra meson ninja-build pkgconf-pkg-config \
  libcap-devel libmount-devel jansson-devel python3 python3-jsonschema valgrind cppcheck binutils
```

Ubuntu/Debian (Meson must be >=1.3):

```bash
sudo apt-get update
sudo apt-get install -y gcc clang clang-tidy meson ninja-build pkg-config \
  libcap-dev libmount-dev libjansson-dev python3 python3-jsonschema valgrind cppcheck binutils
```

```bash
python3 - <<'PY'
import os
from pathlib import Path
assert int(Path('/proc/self/stat').read_bytes().split(b' ', 1)[0]) == os.getpid(), 'procfs/PID namespace mismatch'
import jsonschema
print('procfs and schema test dependency OK')
PY
```

If a non-system Python shadows the distro Python, install jsonschema into that
interpreter or use a PATH selecting the distro Python. Do not bypass test skips.

## GCC and Clang, ASan/UBSan/LSan

Use fresh build directories. A previous directory can be removed or renamed only
if it contains your disposable build output.

```bash
CC=gcc meson setup build-gcc -Dbuildtype=debug -Dwerror=true \
  -Db_sanitize=address,undefined -Db_lundef=false
meson compile -C build-gcc
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  meson test -C build-gcc --print-errorlogs
python3 scripts/check-registration.py build-gcc

CC=clang meson setup build-clang -Dbuildtype=debug -Dwerror=true \
  -Db_sanitize=address,undefined -Db_lundef=false
meson compile -C build-clang
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  meson test -C build-clang --print-errorlogs
python3 scripts/check-registration.py build-clang
```

Expected: all 21 Meson tests pass, no skips, no sanitizer findings. The offline
regression prints 332 command checks in addition to binary/schema assertions.
The constrained build environment used detect_leaks=0 only because its procfs did
not expose the process namespace; this is **not** the target Linux acceptance mode.

## Release build, Valgrind, static analysis and stress

```bash
CC=gcc meson setup build-release -Dbuildtype=release -Dwerror=true
meson compile -C build-release
meson test -C build-release --print-errorlogs
scripts/check-hardening.sh build-release/src/nsdiff
scripts/valgrind-smoke.sh build-release/src/nsdiff
scripts/static-check.sh build-release --strict
scripts/stress.sh build-release/src/nsdiff 1000
scripts/benchmark.sh build-release/src/nsdiff
```

Valgrind must report 0 errors and 0 bytes in use at exit in all five scenarios.
The stress script also exercises rapidly exiting processes on a matching procfs.
Special hidepid/LSM, seccomp-blocked pidfd, memory pressure, ENOSPC and directory
fsync fault matrices require separate controlled environments; no script here
claims exhaustive fault injection.

## Fuzz smoke

```bash
CC=clang meson setup build-fuzz -Dfuzz=true -Dbuildtype=debug -Db_lundef=false
meson compile -C build-fuzz
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  scripts/fuzz-smoke.sh build-fuzz 30
```

All four targets must finish without crashes or sanitizer findings. Increase the
seconds argument for a longer run. Failure preserves its temporary corpus and
artifacts and prints their path. Minimize a discovered input and add a regression.

## Live capture, conversion, provenance and output

```bash
set -euo pipefail
bin=./build-release/src/nsdiff
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$bin" --capture "$work/native" $$
"$bin" --convert-snapshot "$work/native" "$work/portable.json" --snapshot-format portable
"$bin" --convert-snapshot "$work/portable.json" "$work/restored" --snapshot-format native
"$bin" --snapshots "$work/native" "$work/portable.json" --quiet
"$bin" --snapshots "$work/native" "$work/restored" --quiet
"$bin" --snapshot-manifest "$work/portable.json" --json
"$bin" --snapshot-info "$work/native" --json
"$bin" --verify-snapshot "$work/portable.json" --json
"$bin" --semantic-id "$work/native" > "$work/a.id"
"$bin" --semantic-id "$work/portable.json" > "$work/b.id"
cmp "$work/a.id" "$work/b.id"
"$bin" --capture - $$ --snapshot-format portable | "$bin" --verify-snapshot -
stat -c '%a %n' "$work/native" "$work/portable.json" "$work/restored"
```

Saved files must be mode 600. Comparing a fresh separate capture may legitimately
find changes; exact equivalence above intentionally uses conversion of one capture.
Never publish these real process snapshots as regression fixtures.

## Cross-architecture contract

Run on both x86_64 and aarch64 using the same checked-in synthetic portable file:

```bash
id=$(./build-release/src/nsdiff --semantic-id tests/fixtures/portable-v1.json)
test "$id" = 'nsdiff:semantic-sha256:745016f4aaf9f09a94274bbc3f13dfeaba8dae988871a9ca25b9f73b5e92f20c'
./build-release/src/nsdiff --convert-snapshot tests/fixtures/portable-v1.json /tmp/nsdiff-local-native --snapshot-format native
./build-release/src/nsdiff --snapshots tests/fixtures/portable-v1.json /tmp/nsdiff-local-native --quiet
```

For a physical exchange, convert a synthetic native fixture to portable on each
architecture and verify its semantic ID on the other. Do not exchange raw native
files as a portability check. Do not share real environment snapshots casually.

## Installation and source distribution

```bash
scripts/install-smoke.sh build-release
# Optional user-prefix install, without root or DESTDIR:
meson setup build-install --buildtype=release --prefix="$PWD/install-local"
meson compile -C build-install
meson install -C build-install
./install-local/bin/nsdiff --version
```

`install-smoke.sh` checks the binary, generated man page and three completions in a
private DESTDIR and cleans it. The second sequence leaves install-local for review;
remove it before the clean-tree release gate, or choose a prefix outside the repo.

In the ZIP's Git repository (source tarballs do not contain Git history):

```bash
git diff --check
git diff --cached --check
git status --short
meson dist -C build-release
```

Meson must rebuild, test and install the extracted archive. Do not use
`--allow-dirty` or `--no-tests` for release acceptance.

## Final release gate

Resolve the project's missing license with its author, review changes and ensure
all intended source changes are committed. The gate requires both compilers,
Valgrind, cppcheck and clang-tidy and refuses skipped tests.

```bash
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 scripts/release.sh
```

The script does not commit, tag or push. Only after it succeeds, review the exact
commit printed by the script and use its explicit annotated-tag command. CI is
configured for Ubuntu x86_64/aarch64 GCC/Clang, Fedora GCC, release and fuzz jobs;
it still needs to execute on the repository's CI service.
