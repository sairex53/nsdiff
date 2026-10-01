# JSON contracts

Existing comparison, native metadata, verification, compatibility, identity,
manifest and schema-introspection outputs keep schema_version 1 and their existing
field names/types. Additive fields are allowed. Human text has no byte-for-byte
stability guarantee. Runtime input failures for metadata/verification/identity/
manifest/compatibility with `--json` produce a complete error object and exit 2;
CLI syntax errors still use stderr. Comparison failures retain their existing
stderr contract. Successful comparison JSON returns 0 or 1.

| Command/document | Contract |
|---|---|
| comparison / diagnostic export | tool_version, pid_a/b, starttime_a/b, summary, fields[] |
| native snapshot info | valid, file, format_version, abi_version, producer, process/integrity/provenance fields |
| verification | valid, file; error when invalid |
| native compatibility | compatible, header/version/layout/checksum/digest checks, reason |
| native identity | valid, id, algorithm, scope=payload, digest, format_version, producer, pid, starttime_ticks |
| native manifest | document_type=nsdiff-snapshot-manifest, identity, native, producer, process, integrity, provenance |
| portable info/manifest | document_type=nsdiff-portable-report, format=portable, portable_schema=1, valid, file, producer, pid, starttime_ticks string, stored_digest=null, semantic_id, provenance (null or capture/kernel/architecture) |
| portable identity | valid, format=portable, scope=semantic, id |
| portable compatibility | format=portable, compatible |
| semantic identity | document_type=nsdiff-semantic-identity, valid, id |
| portable snapshot | separate lossless schema v1, never confused with diagnostic export |

Legacy v1 JSON strings retain **byte-codepoint encoding**: byte 0xNN maps to
U+00NN; control and non-ASCII bytes are escaped. Recover original bytes by decoding
JSON then encoding the string as Latin-1. This deliberately preserves existing
comparison semantics; valid UTF-8 process bytes can look like mojibake in consumers
that assume those strings are Unicode text. The same shared escaping now protects
native metadata paths. For conventional UTF-8 with explicit fallback use portable
byte objects. No output emits invalid UTF-8.

Legacy metadata/comparison starttime remains a JSON integer for compatibility;
consumers must use exact-integer parsers. Portable v1 uses decimal strings for
wide integers throughout. Formatted comparison field values are diagnostic strings,
not a reversible encoding. Proxy environment values are `<redacted>`; null may
mean unavailable or unset (consult statuses/state). `--export-snapshot-json` retains
comparison schema 1 and is always rejected by the portable loader.
