#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "nsdiff/snapshot_internal.h"

struct input_document { unsigned char *data; size_t size; FILE *stream; bool portable; };
static void close_document(struct input_document *d)
{
    if (d->stream) fclose(d->stream);
    free(d->data);
}
static int open_document(const char *path, struct input_document *d, char *error, size_t error_size)
{
    memset(d, 0, sizeof(*d));
    FILE *in = !strcmp(path, "-") ? stdin : fopen(path, "rb");
    if (!in) goto fail;
    size_t cap = 4096;
    d->data = malloc(cap);
    if (!d->data) goto fail_close;
    for (;;) {
        if (d->size == cap) {
            if (cap == NSDIFF_DOCUMENT_MAX) {
                int c;
                int saved_errno;

                errno = 0;
                c = fgetc(in);

                if (c == EOF) {
                    if (!ferror(in)) {
                        break;
                    }

                    saved_errno = errno;

                    if (saved_errno == EINTR) {
                        clearerr(in);
                        continue;
                    }

                    errno = saved_errno != 0
                        ? saved_errno
                        : EIO;

                    goto fail_close;
                }

                errno = EFBIG;
                goto fail_close;
            }

            cap *= 2;

            unsigned char *p =
                realloc(d->data, cap);

            if (!p) {
                goto fail_close;
            }

            d->data = p;
        }

        errno = 0;

        size_t n =
            fread(
                d->data + d->size,
                1,
                cap - d->size,
                in
            );

        d->size += n;

        if (ferror(in)) {
            int saved_errno =
                errno;

            if (saved_errno == EINTR) {
                clearerr(in);
                continue;
            }

            errno = saved_errno != 0
                ? saved_errno
                : EIO;

            goto fail_close;
        }

        if (feof(in)) {
            break;
        }
    }
    if (in != stdin && fclose(in)) goto fail;
    in = NULL;
    size_t i = 0;
    while (i < d->size && (d->data[i] == ' ' || d->data[i] == '\t' || d->data[i] == '\n' || d->data[i] == '\r')) ++i;
    d->portable = i < d->size && d->data[i] == '{';
    d->stream = fmemopen(d->data, d->size, "rb");
    if (!d->stream) goto fail;
    return 0;
fail_close:
    { int saved = errno; if (in != stdin) fclose(in); errno = saved; }
fail:
    snprintf(error, error_size, "cannot read snapshot: %s", strerror(errno ? errno : EIO));
    close_document(d);
    memset(d, 0, sizeof(*d));
    return -1;
}

int snapshot_load_document(const char *path, struct process_snapshot *s, struct snapshot_metadata *m,
    char *error, size_t size)
{
    struct input_document d;
    int rc = -1;
    memset(s, 0, sizeof(*s));
    s->pidfd = -1;
    memset(m, 0, sizeof(*m));
    if (open_document(path, &d, error, size)) return -1;
    if (d.portable) rc = snapshot_portable_decode(d.data, d.size, s, m, error, size);
    else {
        rc = nsdiff_native_load(d.stream, s, error, size);
        if (!rc) {
            rewind(d.stream);
            rc = nsdiff_native_inspect(d.stream, m, error, size);
        }
    }
    close_document(&d);
    s->pidfd = -1; /* serialized descriptor numbers are never live descriptors */
    if (!rc) snapshot_normalize(s);
    return rc;
}
int process_snapshot_load(const char *path, struct process_snapshot *s, char *error, size_t size)
{
    struct snapshot_metadata m;
    return snapshot_load_document(path, s, &m, error, size);
}
int snapshot_save_document(const char *path, const struct process_snapshot *s,
    const struct snapshot_metadata *m, bool portable, char *error, size_t size)
{
    if (snapshot_validate(s, error, size)) return -1;
    if (!portable) return nsdiff_native_save(path, s, m, error, size);
    char *data = NULL;
    size_t length = 0;
    if (snapshot_portable_encode(s, m, &data, &length, error, size)) return -1;
    int rc = nsdiff_write_private(path, data, length, error, size);
    free(data);
    return rc;
}
int process_snapshot_save(const char *path, const struct process_snapshot *s, char *error, size_t size)
{
    return snapshot_save_document(path, s, NULL, false, error, size);
}
int process_snapshot_inspect(const char *path, struct snapshot_metadata *m, char *error, size_t size)
{
    struct process_snapshot *s = malloc(sizeof(*s));
    if (!s) { snprintf(error, size, "cannot allocate snapshot"); return -1; }
    int rc = snapshot_load_document(path, s, m, error, size);
    if (!rc && m->portable && snapshot_semantic_digest(s, m->payload_sha256)) {
        snprintf(error, size, "cannot compute semantic identity"); rc = -1;
    }
    free(s);
    return rc;
}
int process_snapshot_identity(const char *path, struct snapshot_identity *id, char *error, size_t size)
{
    struct input_document d;
    int rc;
    memset(id, 0, sizeof(*id));
    if (open_document(path, &d, error, size)) return -1;
    if (!d.portable) rc = nsdiff_native_identity(d.stream, id, error, size);
    else {
        struct process_snapshot *s = malloc(sizeof(*s));
        struct snapshot_metadata m;
        if (!s) { snprintf(error, size, "cannot allocate snapshot"); close_document(&d); return -1; }
        rc = snapshot_portable_decode(d.data, d.size, s, &m, error, size);
        if (!rc) {
            id->portable = true;
            id->format_version = 1;
            id->pid = s->pid;
            id->starttime_ticks = s->starttime_ticks;
            id->snapshot_size = d.size;
            id->have_provenance = m.have_provenance;
            id->captured_sec = m.captured_sec;
            id->captured_nsec = m.captured_nsec;
            memcpy(id->tool_version, m.tool_version, sizeof(id->tool_version));
            memcpy(id->kernel_release, m.kernel_release, sizeof(id->kernel_release));
            memcpy(id->machine, m.machine, sizeof(id->machine));
            rc = snapshot_semantic_digest(s, id->payload_sha256);
            if (rc) snprintf(error, size, "cannot compute semantic identity");
        }
        free(s);
    }
    close_document(&d);
    return rc;
}
int process_snapshot_probe(const char *path, struct snapshot_compat_report *r, char *error, size_t size)
{
    struct input_document d;
    int rc;
    memset(r, 0, sizeof(*r));
    if (open_document(path, &d, error, size)) return -1;
    if (!d.portable) {
        rc = nsdiff_native_probe(d.stream, r, error, size);
        /* A container with valid hashes can still contain invalid semantic fields. */
        if (!rc && r->compatible) {
            struct process_snapshot *s = malloc(sizeof(*s));
            if (!s) { close_document(&d); snprintf(error, size, "cannot allocate snapshot"); return -1; }
            rewind(d.stream);
            if (nsdiff_native_load(d.stream, s, error, size)) {
                r->compatible = 0;
                snprintf(r->reason, sizeof(r->reason), "invalid native semantic payload or provenance");
            }
            free(s);
        }
    } else {
        struct process_snapshot *s = malloc(sizeof(*s));
        struct snapshot_metadata m;
        if (!s) { close_document(&d); snprintf(error, size, "cannot allocate snapshot"); return -1; }
        rc = snapshot_portable_decode(d.data, d.size, s, &m, error, size);
        r->portable = true;
        r->compatible = !rc;
        r->format_version = 1;
        snprintf(r->reason, sizeof(r->reason), "%s", rc ? "invalid portable snapshot" : "compatible");
        free(s);
    }
    close_document(&d);
    return rc;
}

