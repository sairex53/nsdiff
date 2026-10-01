# nsdiff

`nsdiff` compares the execution environments of two Linux processes. It helps
explain why the same program behaves differently in a shell, service, container,
namespace or cgroup. It is a read-only CLI, not a complete `/proc` dump.

Version 0.1.0 is a hardening and portable-snapshot baseline. See
[FINAL_REPORT.md](FINAL_REPORT.md) for the checks actually run and release limitations.
**The original repository had no license. The author must choose one before public
redistribution as an open-source project. No license has been assigned here.**

## Quick start

```sh
meson setup build --buildtype=release
meson compile -C build
./build/src/nsdiff $$ 1234
./build/src/nsdiff --explain $$ 1234
./build/src/nsdiff --section environment --section limits --summary $$ 1234
./build/src/nsdiff --json $$ 1234
```

`0`: successful operation / no comparable differences; `1`: comparison found
differences; `2`: invalid invocation, invalid snapshot or fatal collection/I/O
failure. An unavailable field does **not** make a comparison fail. Thus exit 0
can also mean there were no comparable fields. Inspect the summary when this matters.

## What is compared

| Section | Scope |
|---|---|
| namespaces | mnt, net, pid, user, uts, ipc, cgroup, time identity |
| credentials | effective UID and effective GID |
| limits | NOFILE, NPROC, STACK, MEMLOCK, AS, CORE, FSIZE |
| cgroup | cgroup v2 path and eight selected controller files |
| network | interface names, IPv4 default routes, IPv6 addresses/default routes |
| mounts | total mount count and `/`, `/proc`, `/sys`, `/dev`, `/dev/shm`, `/tmp`, `/run` |
| environment | entry count and 33 watched variables; see format documentation |
| security | five capability sets, no_new_privs, seccomp mode |

Network data does not include listeners or IPv4 interface addresses. Credentials
do not compare supplementary groups. Paths and inode identifiers are machine-local:
portable serialization does not make namespace identity globally meaningful.

## Output modes

Default text, `--only-differences`, `--explain`, `--summary`, `--quiet` (`-q`),
`--json`. Output modes are mutually exclusive. `--explain` includes only differences.
`--quiet` writes no normal comparison output. `--section NAME` can repeat; `all`
selects every section. JSON with section filtering remains unsupported for compatibility.
`--` ends options before positional PIDs. File arguments immediately following
snapshot options may contain spaces, Unicode or a leading dash; quote them in the shell.

## Snapshots

```sh
# Native v3 is the default, private local storage format.
nsdiff --capture process.snap $$
nsdiff --capture process.json $$ --snapshot-format portable
nsdiff --against process.snap $$
nsdiff --snapshots process.snap process.json --quiet

# Conversion accepts native v1/v2/v3 and portable v1.
nsdiff --convert-snapshot process.snap process.json --snapshot-format portable
nsdiff --convert-snapshot process.json restored.snap --snapshot-format native
nsdiff --capture - $$ --snapshot-format portable | nsdiff --verify-snapshot -

nsdiff --snapshot-info process.json --json
nsdiff --verify-snapshot process.snap --json
nsdiff --snapshot-compat process.snap --json
nsdiff --snapshot-id process.snap
nsdiff --semantic-id process.json
nsdiff --snapshot-manifest process.json --json
nsdiff --snapshot-schema --json
nsdiff --export-snapshot-json process.snap
```

Loaders auto-detect native magic or a JSON object. `-` is stdin for reads and stdout
for capture/conversion. Two comparison inputs cannot both be `-`. Conversion writes
only data to stdout; capture status goes to stderr when its destination is stdout.

Native files depend on the originating C ABI, layout and endianness. Portable v1
stores typed semantic fields and exact bytes, and can cross x86_64/aarch64. There
is one diff engine for both. Portable snapshots are **lossless relative to the
bounded collected model**, not to the entire live process. Over-limit collected
fields have an unavailable/truncated status; missing bytes cannot be recovered.

Snapshot files may contain passwords in proxy URLs and other private data. Both
formats use 0600 and an adjacent atomic replacement. Redirecting stdout is controlled
by your shell's umask. `--export-snapshot-json` is a redacted diagnostic export,
**not an importable lossless snapshot**. Even diagnostic output may include personal
paths and non-proxy watched values: review it before sharing.

## Identities and JSON

Native `--snapshot-id` retains `nsdiff:sha256:<digest>` of raw native payload bytes.
`--semantic-id` uses `nsdiff:semantic-sha256:<digest>` for either format. For a
portable file `--snapshot-id` returns the semantic identity explicitly. Provenance,
producer version, PID, starttime and native padding are excluded from semantic IDs.
The remaining captured model (including status/presence and diagnostic identifiers)
is included. Consequently `diff` exit 0 does not imply identical semantic IDs.

A SHA-256 digest is not a signature or proof of authenticity. Portable v1 does not
store a checksum; verification checks schema and semantic validity. Native v3
also checks its stored FNV-1a and SHA-256. See [JSON contracts](docs/json-contracts.md),
[native format](docs/native-snapshot-format.md), and [portable format](docs/portable-snapshot-format.md).

## Build and install

Requires Linux, a C17 compiler, Meson >=1.3, Ninja, pkg-config, libcap, libmount and
Jansson >=2.13. Python 3, python3-jsonschema and Bash run tests; no runtime network access or downloading.
The existing libcap/libmount dependencies are retained; Jansson is a small shared
MIT-licensed dependency. See [THIRD_PARTY.md](THIRD_PARTY.md).

Fedora:

```sh
sudo dnf install gcc clang meson ninja-build pkgconf-pkg-config libcap-devel libmount-devel jansson-devel python3 python3-jsonschema valgrind
```

Debian/Ubuntu:

```sh
sudo apt install gcc clang meson ninja-build pkg-config libcap-dev libmount-dev libjansson-dev python3 python3-jsonschema valgrind
```

```sh
meson setup build --buildtype=release --prefix=/usr/local
meson compile -C build
meson test -C build --print-errorlogs
sudo meson install -C build
DESTDIR=/tmp/nsdiff-stage meson install -C build
```

Installs binary, man page and Bash/Zsh/Fish completions. PIE, stack protector,
RELRO/NOW and a non-executable stack are enabled when supported. Optimized builds
use FORTIFY_SOURCE=2. Packagers can use `-Dhardening=false` and Meson's `-Db_pie=false`
to supply their own flags.

## Development

[VERIFY_ON_LINUX.md](VERIFY_ON_LINUX.md) gives exact GCC/Clang, sanitizer, Valgrind,
fuzz, static-analysis, stress, install and distribution commands. Normal tests are
registered with `meson test`; `scripts/check-registration.py build` detects omissions.
Fuzzing is an opt-in Clang/libFuzzer build, never a normal install dependency.
`tests/fixtures/portable-v1.json` is synthetic and contains no real user data.

The release script checks a **clean committed tree** and does not stage, commit,
push or tag. Tagging is a separate last step after all gates pass. This avoids a
partial release if later checks fail. Human formatting can evolve; exit codes,
section names, format/schema versions and identity prefixes are public contracts.

Please add a regression for every bug fix, preserve native ABI fixtures, and do not
weaken parser bounds or redaction to make a test pass. See [security](docs/security.md)
for collection consistency and privilege limitations.
