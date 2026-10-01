#ifndef NSDIFF_SNAPSHOT_INTERNAL_H
#define NSDIFF_SNAPSHOT_INTERNAL_H
#include <stdio.h>
#include <jansson.h>
#include "nsdiff/snapshot_io.h"
#define NSDIFF_DOCUMENT_MAX (8U * 1024U * 1024U)
#define NSDIFF_JSON_DEPTH_MAX 32U
#define NSDIFF_JSON_STRING_MAX 32768U
#define NSDIFF_JSON_NODES_MAX 32768U
int snapshot_validate(const struct process_snapshot *s, char *error, size_t size);
void snapshot_normalize(struct process_snapshot *s);
int nsdiff_write_private(const char *path, const void *data, size_t size, char *error, size_t error_size);
int nsdiff_native_load(FILE *stream, struct process_snapshot *s, char *error, size_t size);
int nsdiff_native_inspect(FILE *stream, struct snapshot_metadata *m, char *error, size_t size);
int nsdiff_native_identity(FILE *stream, struct snapshot_identity *id, char *error, size_t size);
int nsdiff_native_probe(FILE *stream, struct snapshot_compat_report *r, char *error, size_t size);
int nsdiff_native_save(const char *path, const struct process_snapshot *s, const struct snapshot_metadata *m, char *error, size_t size);
json_t *nsdiff_json_parse(const void *data, size_t size);
json_t *nsdiff_json_bytes(const char *value, bool canonical);
int nsdiff_json_decode_bytes(const json_t *value, char *out, size_t capacity);
int snapshot_model_decode(json_t *o, struct process_snapshot *s);
json_t *snapshot_semantic_json(const struct process_snapshot *s, bool canonical);
int snapshot_portable_decode(const void *data, size_t size, struct process_snapshot *s, struct snapshot_metadata *m, char *error, size_t error_size);
int snapshot_portable_encode(const struct process_snapshot *s, const struct snapshot_metadata *m, char **data, size_t *size, char *error, size_t error_size);
int snapshot_semantic_digest(const struct process_snapshot *s, unsigned char digest[32]);
int snapshot_load_document(const char *path, struct process_snapshot *s, struct snapshot_metadata *m, char *error, size_t size);
int snapshot_save_document(const char *path, const struct process_snapshot *s, const struct snapshot_metadata *m, bool portable, char *error, size_t size);
#endif
