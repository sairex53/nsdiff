# Native snapshot formats 1–3 (ABI 1)

This is a legacy host-layout container, **not a portable encoding**. The header,
extensions and `struct process_snapshot` use host endianness and C alignment.
No production snapshot structure member, array capacity or ABI version changed
in 0.1.0. An additional numeric collection status 6 means truncated; older readers
may label it unknown. Field status numbers 0–5 retain their meanings.

For the original LP64 x86_64/aarch64 layout the header is 80 bytes:

| Offset | Field | Native type |
|---:|---|---|
| 0 | magic `NSDIFFSNAP` followed by six zero bytes | 16 bytes |
| 16 | format_version | uint32 |
| 20 | abi_version = 1 | uint32 |
| 24 | endian_marker = 0x01020304 | uint32 |
| 28 | reserved = 0 | uint32 |
| 32 | payload size | uint64 |
| 40 | FNV-1a payload checksum | uint64 |
| 48 | NUL-terminated producer version | char[32] |

v1: header + payload. v2: header + 216-byte provenance + payload.
v3: header + 256-byte provenance/digest + payload.

Provenance offsets: size uint32 at 0; reserved uint32 at 4; signed Unix seconds
int64 at 8; nanoseconds int32 at 16; reserved uint32 at 20; NUL-terminated kernel
char[128] at 24; machine char[64] at 152. v3 adds digest algorithm uint32 at 216
(1 = SHA-256), digest length uint32 at 220 (32), digest bytes at 224.
Nanoseconds must be 0..999999999. Zero time and empty kernel/machine represent
unknown provenance when converting a legacy source without capture metadata.

Payload is exactly the ABI 1 process structure. pidfd is saved as -1 and is never
used as an OS descriptor on load. Padding is part of native hashes, not semantic
identity. New captures initialize the model; portable imports zero-initialize it.
The independent `tests/frozen_native_v024.h` records the original layout and must
not follow changes to the production header.

FNV-1a: start 14695981039346656037, xor each byte, multiply by 1099511628211 modulo
2^64. SHA-256 covers the same payload bytes. v1/v2 have no stored SHA; `--snapshot-id`
still computes it. IDs exclude the container header/provenance and retain the prefix
`nsdiff:sha256:`. Neither hash authenticates a producer, and metadata is not hashed.

Loaders reject wrong magic, unsupported version/ABI/endian/size, nonzero reserved
fields, invalid timestamp/digest metadata, truncation, trailing bytes, bad hashes,
invalid booleans/enums/counts, unterminated strings and inconsistent fixed keys.
The complete input is bounded to 8 MiB before parsing. Compatibility probing can
explain a foreign byte order or layout; it does not translate a foreign raw struct.
Convert native files to portable **on a machine that can read their native ABI**.
