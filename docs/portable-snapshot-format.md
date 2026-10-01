# Portable snapshot schema v1

UTF-8 JSON; document_type `nsdiff-portable-snapshot`; schema_version integer 1.
Producer version is informational and is never used to decide schema compatibility.
The structural field schema is [portable-snapshot-v1.schema.json](schema/portable-snapshot-v1.schema.json).
The importer additionally enforces decoded byte lengths, numeric ranges, fixed item
identities, count equality, set uniqueness and lexical resource bounds.
The synthetic full fixture is [portable-v1.json](../tests/fixtures/portable-v1.json).

Root required keys: document_type, schema_version, required_features (empty array
for v1), producer (name `nsdiff`, version string <=31 bytes), provenance, snapshot.
Unknown optional keys are ignored at every object level, but remain subject to
UTF-8, duplicate-key and resource validation. Unknown required features and unknown
schema versions are rejected. A future producer using schema 1 remains readable.
An incompatible change needs a new schema version, not a tool-version test.

Provenance is null or {captured_sec, captured_nsec, kernel, architecture}.
Seconds are a signed decimal string of Unix seconds UTC; nanoseconds an integer
0..999999999; kernel/architecture are byte strings. Conversions preserve known
capture time and provenance. Null remains null across portable conversions; native
v3 encodes unknown original provenance with an all-zero/empty sentinel.

## Scalar rules

Every potentially 64-bit/architecture-sized unsigned value is a **decimal string**:
starttime_ticks, namespace dev/ino, all UID/GID values, resource-limit values,
capability masks and shared-memory size_bytes. No floats, signs, leading zeroes
(except `"0"`) or implicit conversions are accepted. Range is checked before storing.
PIDs/counts/mount IDs/security modes are small nonnegative JSON integers; booleans
are JSON true/false, not integers. Status and kind are semantic strings, never enums.

A byte string is `{ "encoding": "utf-8", "value": "text" }` or
`{ "encoding": "hex", "value": "lowercase-even-length-hex" }`. UTF-8 is used when
valid; hex preserves invalid UTF-8 and arbitrary Linux bytes. Decoded NUL is rejected:
none of the retained Linux string fields can contain an embedded NUL. Escaped
newlines, tabs, quotes, backslashes, DEL and all other nonzero bytes round-trip.
No base64 encoding is defined by v1. Invalid encoding or malformed hex is rejected.

Statuses: ok, permission-denied, not-supported, process-gone, io-error, parse-error,
truncated. `truncated` explicitly means incomplete data, and is not comparable.
The native ABI has no extra truncation bool: the status itself carries that fact.
A field with `present:false` is unset; `present:true` with an empty byte string is
set-empty. Parent status can make all its children unavailable.

## Snapshot object and complete fields

- pid, starttime_ticks (Linux clock ticks since boot); pidfd is never serialized.
- namespaces[8]: name, status, dev, ino, target.
- proc_status: status; have_uid and uid[4]; have_gid and gid[4]; capabilities[5]
  with kind/present/mask; have_no_new_privs/no_new_privs; have_seccomp/seccomp.
  UID/GID ordering is real, effective, saved, filesystem. seccomp 0/1/2 means
  disabled/strict/filter. Capability kinds: inheritable, permitted, effective,
  bounding, ambient.
- limits: status, entries[7], each kind/status/soft/hard/units. Kinds: nofile,
  nproc, stack, memlock, as, core, fsize. Soft/hard contain unlimited bool/value.
  Value is retained even if unlimited; units are a byte string from `/proc/limits`.
- cgroup: status, v2 bool, path, files[8], each name/status/value. Fixed names:
  memory.max, memory.high, memory.swap.max, cpu.max, cpu.weight, pids.max,
  cpuset.cpus.effective, cpuset.mems.effective.
- mounts: status, total_mounts, entries[7], shm {status,size_bytes}.
  Entries: status, mounted, mount_id, target, root, fstype, source, read_only,
  nosuid, nodev, noexec. Targets are the seven paths in README.
- environment: status, total_entries, entries[33], each status/name/present/
  redact_value/value. Proxy redaction cannot be disabled by a snapshot.
- network: interfaces, ipv4_default_routes, ipv6_addresses,
  ipv6_default_routes. Each contains status/count/items, count <=64, decoded
  item <=191 bytes. These are normalized textual records, not raw netlink data.

Watched variables, in internal order:
PATH, LANG, LC_ALL, LC_CTYPE, TZ, HOME, SHELL, TMPDIR, TMP, TEMP,
XDG_RUNTIME_DIR, XDG_CONFIG_HOME, XDG_DATA_HOME, LD_LIBRARY_PATH, LD_PRELOAD,
LD_AUDIT, PYTHONPATH, PYTHONHOME, VIRTUAL_ENV, JAVA_HOME, GOMAXPROCS, DISPLAY,
WAYLAND_DISPLAY, DBUS_SESSION_BUS_ADDRESS, SSH_AUTH_SOCK, HTTP_PROXY, HTTPS_PROXY,
ALL_PROXY, NO_PROXY, http_proxy, https_proxy, all_proxy, no_proxy.
Only the final eight have mandatory redaction. Unknown environment names contribute
to the total count but are not stored. Exec-time procfs environment need not reflect
later libc setenv changes. Duplicate watched names are ambiguous/parse-error.

Fixed domain arrays may arrive in any order; their name/kind/target maps them to
canonical slots. Missing/duplicate/unknown logical items are rejected. Network sets
are sorted by unsigned byte lexicographic order; duplicate decoded portable items rejected. Legacy native duplicate set entries
are deduplicated in memory; their raw native ID remains unchanged.

## Bounds

Complete input <=8 MiB; nesting <=32; lexical string <=32768 bytes including escapes;
<=32768 lexical nodes/commas. Jansson also checks JSON grammar/UTF-8/duplicate keys,
including duplicates spelled using Unicode escapes, and integer overflow. Every
field has a separate decoded capacity (see schema). Maximum watched env value and
cgroup path: 4095 bytes; mount root/source: 255; namespace target: 63.
No allocation is sized from an unchecked declared payload length or count.

## Semantic identity v1

Validate/decode the model; restore fixed-array order; sort network items. Encode
all retained model fields using their stable names/types, always hex for byte
strings, decimal strings for wide integers. Remove pid/starttime_ticks, add
`semantic_schema:1`, sort object keys lexicographically, serialize compact ASCII
JSON with no trailing newline, then SHA-256 the exact bytes. Prefix:
`nsdiff:semantic-sha256:`. This is a specified canonical JSON encoding, not a hash
of the input document or its pretty printing. No floating point is involved.

C layout, padding, endian order, producer, timestamp, kernel, architecture and
optional unknown JSON members do not participate. Collection statuses, presence,
redaction flags, real/saved/fs credentials and diagnostic fields do participate:
identity is stronger than the currently selected diff fields. An unavailable field
is not equal to an empty available field for identity, although diff can skip it.
Changing canonicalization requires a new semantic identity namespace/version.

Portable verification means valid schema/model, not verification of a stored hash.
Semantic IDs include private environment data and can allow guessing low-entropy
values: treat IDs as potentially sensitive too. No authenticity is promised.
