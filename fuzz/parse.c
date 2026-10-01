#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "nsdiff/snapshot_internal.h"
#include "nsdiff/sha256.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > NSDIFF_DOCUMENT_MAX) return 0;
#if FUZZ_MODE == 0
    FILE *stream = fmemopen((void *)data, size, "rb");
    if (!stream) return 0;
    struct process_snapshot *s = malloc(sizeof(*s));
    struct snapshot_metadata m;
    struct snapshot_identity id;
    struct snapshot_compat_report report;
    char error[256];
    if (s) {
        (void)nsdiff_native_load(stream, s, error, sizeof(error));
        rewind(stream); (void)nsdiff_native_inspect(stream, &m, error, sizeof(error));
        rewind(stream); (void)nsdiff_native_identity(stream, &id, error, sizeof(error));
        rewind(stream); (void)nsdiff_native_probe(stream, &report, error, sizeof(error));
        free(s);
    }
    fclose(stream);
#elif FUZZ_MODE == 1
    struct process_snapshot *a = malloc(sizeof(*a)), *b = malloc(sizeof(*b));
    struct snapshot_metadata m, n;
    char error[256], *encoded = NULL;
    size_t length;
    if (a && b && !snapshot_portable_decode(data, size, a, &m, error, sizeof(error))) {
        if (!snapshot_portable_encode(a, &m, &encoded, &length, error, sizeof(error))) {
            unsigned char x[32], y[32];
            assert(!snapshot_portable_decode(encoded, length, b, &n, error, sizeof(error)));
            assert(!snapshot_semantic_digest(a, x));
            assert(!snapshot_semantic_digest(b, y));
            assert(!memcmp(x,y,32));
        }
    }
    free(encoded); free(a); free(b);
#elif FUZZ_MODE == 2
    json_t *o = nsdiff_json_parse(data, size);
    if (o) {
        char bytes[4096];
        if (!nsdiff_json_decode_bytes(o, bytes, sizeof(bytes))) {
            json_t *v = nsdiff_json_bytes(bytes, true);
            if (v) {
                char again[4096];
                assert(!nsdiff_json_decode_bytes(v, again, sizeof(again)));
                assert(!strcmp(bytes,again));
            }
            json_decref(v);
        }
        json_decref(o);
    }
#else
    json_t *o = nsdiff_json_parse(data, size);
    json_decref(o);
#endif
    return 0;
}
