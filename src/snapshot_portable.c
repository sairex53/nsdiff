#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include "config.h"
#include "nsdiff/snapshot_internal.h"

int snapshot_portable_encode(const struct process_snapshot *s, const struct snapshot_metadata *metadata,
    char **data, size_t *size, char *error, size_t error_size)
{
    struct snapshot_metadata local = {0};
    const struct snapshot_metadata *source = metadata ? metadata : &local;
    struct timespec now;
    struct utsname uts;
    json_t *provenance = NULL, *o;
    *data = NULL;
    if (snapshot_validate(s, error, error_size)) return -1;
    if (!metadata) {
        if (clock_gettime(CLOCK_REALTIME, &now) || uname(&uts)) goto fail;
        local.have_provenance = 1;
        local.captured_sec = now.tv_sec;
        local.captured_nsec = (int32_t)now.tv_nsec;
        snprintf(local.kernel_release, sizeof(local.kernel_release), "%s", uts.release);
        if (strlen(uts.machine) >= sizeof(local.machine)) goto fail;
        memcpy(local.machine, uts.machine, strlen(uts.machine)+1);
    }
    if (source->have_provenance) {
        char seconds[32];
        snprintf(seconds, sizeof(seconds), "%" PRId64, source->captured_sec);
        provenance = json_pack("{s:s,s:i,s:o,s:o}", "captured_sec", seconds,
            "captured_nsec", source->captured_nsec,
            "kernel", nsdiff_json_bytes(source->kernel_release, false),
            "architecture", nsdiff_json_bytes(source->machine, false));
    } else provenance = json_null();
    o = json_pack("{s:s,s:i,s:[],s:{s:s,s:s},s:o,s:o}",
        "document_type", "nsdiff-portable-snapshot", "schema_version", 1,
        "required_features", "producer", "name", "nsdiff", "version", NSDIFF_VERSION,
        "provenance", provenance, "snapshot", snapshot_semantic_json(s, false));
    if (!o) goto fail;
    *data = json_dumps(o, JSON_INDENT(2) | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    json_decref(o);
    if (!*data) goto fail;
    *size = strlen(*data);
    return 0;
fail:
    snprintf(error, error_size, "cannot encode portable snapshot");
    return -1;
}

int snapshot_portable_decode(const void *data, size_t size, struct process_snapshot *s,
    struct snapshot_metadata *m, char *error, size_t error_size)
{
    json_t *o = nsdiff_json_parse(data, size);
    memset(s, 0, sizeof(*s));
    s->pidfd = -1;
    memset(m, 0, sizeof(*m));
    if (!o) goto bad;
    const char *type = json_string_value(json_object_get(o, "document_type"));
    json_t *version = json_object_get(o, "schema_version");
    json_t *features = json_object_get(o, "required_features");
    json_t *producer = json_object_get(o, "producer");
    const char *name = json_string_value(json_object_get(producer, "name"));
    const char *tool_version = json_string_value(json_object_get(producer, "version"));
    if (!type || strcmp(type, "nsdiff-portable-snapshot") || !json_is_integer(version) ||
        json_integer_value(version) != 1 || !json_is_array(features) || json_array_size(features) ||
        !name || strcmp(name, "nsdiff") || !tool_version || strlen(tool_version) >= sizeof(m->tool_version)) goto bad;
    if (snapshot_model_decode(json_object_get(o, "snapshot"), s) || snapshot_validate(s, error, error_size)) goto bad;
    json_t *prov = json_object_get(o, "provenance");
    if (!prov) goto bad;
    if (!json_is_null(prov)) {
        const char *sec = json_string_value(json_object_get(prov, "captured_sec"));
        json_t *nsec = json_object_get(prov, "captured_nsec");
        uint64_t v = 0;
        bool negative = sec && sec[0] == '-';
        const char *digits = sec ? sec + negative : NULL;
        if (!digits || !*digits || (digits[0] == '0' && digits[1]) || (negative && digits[0] == '0') ||
            !json_is_integer(nsec) || json_integer_value(nsec) < 0 || json_integer_value(nsec) >= 1000000000) goto bad;
        for (const char *p = digits; *p; ++p) {
            if (*p < '0' || *p > '9' || v > ((uint64_t)INT64_MAX + negative - (unsigned)(*p-'0'))/10) goto bad;
            v = v*10 + (unsigned)(*p-'0');
        }
        m->captured_sec = negative ? -(int64_t)(v-1)-1 : (int64_t)v;
        m->captured_nsec = (int32_t)json_integer_value(nsec);
        if (nsdiff_json_decode_bytes(json_object_get(prov, "kernel"), m->kernel_release, sizeof(m->kernel_release)) ||
            nsdiff_json_decode_bytes(json_object_get(prov, "architecture"), m->machine, sizeof(m->machine))) goto bad;
        m->have_provenance = 1;
    }
    m->portable = true;
    m->format_version = 1;
    m->pid = s->pid;
    m->starttime_ticks = s->starttime_ticks;
    m->snapshot_size = size;
    memcpy(m->tool_version, tool_version, strlen(tool_version)+1);
    json_decref(o);
    return 0;
bad:
    json_decref(o);
    memset(s, 0, sizeof(*s));
    s->pidfd = -1;
    snprintf(error, error_size, "invalid portable snapshot (JSON, schema, resource limit or fields)");
    return -1;
}
