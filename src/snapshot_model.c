#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "nsdiff/snapshot_internal.h"
#include "nsdiff/sha256.h"

enum member_type { T_BOOL, T_ULL, T_ULONG, T_UINT, T_INT, T_PID,
                   T_DEV, T_INO, T_STATUS, T_LIMIT, T_CAP, T_BYTES, T_OBJECT };
struct member {
    const char *name;
    size_t offset;
    enum member_type type;
    size_t size, count;
    const struct member *children;
    bool array, dynamic;
};
#include "snapshot_members.inc"
static const char *const statuses[] = {"ok", "permission-denied", "not-supported",
    "process-gone", "io-error", "parse-error", "truncated", NULL};
static const char *const limits[] = {"nofile", "nproc", "stack", "memlock", "as", "core", "fsize", NULL};
static const char *const caps[] = {"inheritable", "permitted", "effective", "bounding", "ambient", NULL};
static const char *const namespaces[] = {"mnt", "net", "pid", "user", "uts", "ipc", "cgroup", "time"};
static const char *const mounts[] = {"/", "/proc", "/sys", "/dev", "/dev/shm", "/tmp", "/run"};
static const char *const cgroups[] = {"memory.max", "memory.high", "memory.swap.max", "cpu.max", "cpu.weight", "pids.max", "cpuset.cpus.effective", "cpuset.mems.effective"};
static const char *const envs[] = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HOME", "SHELL", "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "JAVA_HOME", "GOMAXPROCS", "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"};

static const char *const *enum_names(enum member_type t)
{
    if (t == T_STATUS) return statuses;
    if (t == T_LIMIT) return limits;
    if (t == T_CAP) return caps;
    return NULL;
}

/* Read through the declared member type, independent of endian and width. */
static uint64_t read_number(const unsigned char *p, enum member_type t)
{
#define READ(T) do { T v; memcpy(&v, p, sizeof(v)); return (uint64_t)v; } while (0)
    switch (t) {
    case T_BOOL: READ(unsigned char);
    case T_ULL: READ(unsigned long long);
    case T_ULONG: READ(unsigned long);
    case T_UINT: READ(unsigned int);
    case T_INT: READ(int);
    case T_PID: READ(pid_t);
    case T_DEV: READ(dev_t);
    case T_INO: READ(ino_t);
    case T_STATUS: READ(enum collect_status);
    case T_LIMIT: READ(enum nsdiff_limit_kind);
    case T_CAP: READ(enum nsdiff_capset_kind);
    default: return 0;
    }
#undef READ
}
static int write_number(unsigned char *p, enum member_type t, uint64_t v)
{
#define WRITE(T, MAX) do { if (v > (uint64_t)(MAX)) return -1; T x = (T)v; memcpy(p, &x, sizeof(x)); return 0; } while (0)
    switch (t) {
    case T_BOOL: WRITE(bool, 1);
    case T_ULL: WRITE(unsigned long long, ULLONG_MAX);
    case T_ULONG: WRITE(unsigned long, ULONG_MAX);
    case T_UINT: WRITE(unsigned int, UINT_MAX);
    case T_INT: WRITE(int, INT_MAX);
    case T_PID: WRITE(pid_t, INT_MAX);
    case T_DEV: WRITE(dev_t, (dev_t)-1);
    case T_INO: WRITE(ino_t, (ino_t)-1);
    case T_STATUS: WRITE(enum collect_status, COLLECT_TRUNCATED);
    case T_LIMIT: WRITE(enum nsdiff_limit_kind, NSDIFF_LIMIT_COUNT-1);
    case T_CAP: WRITE(enum nsdiff_capset_kind, NSDIFF_CAPSET_COUNT-1);
    default: return -1;
    }
#undef WRITE
}

static int validate_members(const unsigned char *p, const struct member *fields)
{
    for (const struct member *f = fields; f->name; ++f) {
        size_t n = f->count;
        if (f->dynamic) {
            n = ((const struct network_set_info *)(const void *)p)->count;
            if (n > f->count) return -1;
        }
        for (size_t i = 0; i < n; ++i) {
            const unsigned char *v = p + f->offset + i*f->size;
            if (f->type == T_OBJECT) {
                if (validate_members(v, f->children)) return -1;
            } else if (f->type == T_BYTES) {
                if (!memchr(v, 0, f->size)) return -1;
            } else {
                uint64_t x = read_number(v, f->type);
                const char *const *names = enum_names(f->type);
                if (names) {
                    size_t count = 0;
                    while (names[count]) ++count;
                    if (x >= count) return -1;
                } else if (f->type == T_BOOL && x > 1) return -1;
                else if ((f->type == T_INT || f->type == T_PID) && x > INT_MAX) return -1;
            }
        }
    }
    return 0;
}

static int compare_item(const void *a, const void *b) { return strcmp(a, b); }
static void sort_network(struct process_snapshot *s)
{
    struct network_set_info *sets[] = {&s->network.interfaces, &s->network.ipv4_default_routes,
        &s->network.ipv6_addresses, &s->network.ipv6_default_routes};
    for (size_t i = 0; i < 4; ++i)
        if (sets[i]->count <= NSDIFF_NET_SET_MAX)
            qsort(sets[i]->items, sets[i]->count, sizeof(sets[i]->items[0]), compare_item);
}

void snapshot_normalize(struct process_snapshot *s)
{
    sort_network(s);
    struct network_set_info *sets[] = {&s->network.interfaces, &s->network.ipv4_default_routes,
        &s->network.ipv6_addresses, &s->network.ipv6_default_routes};
    for (size_t j = 0; j < 4; ++j) {
        struct network_set_info *set = sets[j];
        if (set->count > NSDIFF_NET_SET_MAX) continue;
        unsigned int unique = 0;
        for (unsigned int i = 0; i < set->count; ++i) {
            if (unique && !strcmp(set->items[unique-1], set->items[i])) continue;
            if (unique != i) memcpy(set->items[unique], set->items[i], sizeof(set->items[i]));
            ++unique;
        }
        set->count = unique;
    }
}

int snapshot_validate(const struct process_snapshot *s, char *error, size_t size)
{
    if (validate_members((const unsigned char *)s, process_snapshot_members)) goto bad;
    if (s->pid <= 0 || !s->starttime_ticks || s->mounts.total_mounts < 0 ||
        s->proc_status.no_new_privs > 1 || s->proc_status.seccomp > 2) goto bad;
    for (size_t i = 0; i < NSDIFF_NAMESPACE_COUNT; ++i)
        if (strcmp(s->namespaces[i].name, namespaces[i])) goto bad;
    for (size_t i = 0; i < NSDIFF_LIMIT_COUNT; ++i)
        if (s->limits.entries[i].kind != (enum nsdiff_limit_kind)i) goto bad;
    for (size_t i = 0; i < NSDIFF_CAPSET_COUNT; ++i)
        if (s->proc_status.capabilities[i].kind != (enum nsdiff_capset_kind)i) goto bad;
    for (size_t i = 0; i < NSDIFF_WATCHED_MOUNT_COUNT; ++i)
        if (strcmp(s->mounts.entries[i].target, mounts[i])) goto bad;
    for (size_t i = 0; i < NSDIFF_CGROUP_FILE_COUNT; ++i)
        if (strcmp(s->cgroup.files[i].name, cgroups[i])) goto bad;
    for (size_t i = 0; i < NSDIFF_ENV_WATCH_COUNT; ++i) {
        if (strcmp(s->environment.entries[i].name, envs[i])) goto bad;
        /* A file must not be able to opt proxy values out of redaction. */
        if (i >= 25 && !s->environment.entries[i].redact_value) goto bad;
    }
    return 0;
bad:
    snprintf(error, size, "invalid snapshot fields (bounds, status, identity or redaction)");
    return -1;
}

static json_t *encode_members(const unsigned char *p, const struct member *fields, bool canonical);
static json_t *encode_one(const unsigned char *p, const struct member *f, bool canonical)
{
    if (f->type == T_OBJECT) return encode_members(p, f->children, canonical);
    if (f->type == T_BYTES) return nsdiff_json_bytes((const char *)p, canonical);
    uint64_t v = read_number(p, f->type);
    const char *const *names = enum_names(f->type);
    if (names) return json_string(names[v]);
    if (f->type == T_BOOL) return json_boolean(v);
    /* All potentially architecture-sized and 64-bit numbers are decimal strings. */
    if (f->type == T_ULL || f->type == T_ULONG || f->type == T_DEV || f->type == T_INO) {
        char b[32];
        snprintf(b, sizeof(b), "%" PRIu64, v);
        return json_string(b);
    }
    return json_integer((json_int_t)v);
}
static json_t *encode_members(const unsigned char *p, const struct member *fields, bool canonical)
{
    json_t *o = json_object();
    if (!o) return NULL;
    for (const struct member *f = fields; f->name; ++f) {
        size_t n = f->dynamic ? ((const struct network_set_info *)(const void *)p)->count : f->count;
        json_t *v = NULL;
        if (f->array) {
            v = json_array();
            if (!v) goto fail;
            for (size_t i = 0; i < n; ++i) {
                if (json_array_append_new(v, encode_one(p + f->offset + i*f->size, f, canonical))) {
                    json_decref(v);
                    goto fail;
                }
            }
        } else v = encode_one(p + f->offset, f, canonical);
        if (json_object_set_new(o, f->name, v)) goto fail;
    }
    return o;
fail:
    json_decref(o);
    return NULL;
}

static int decode_members(json_t *o, unsigned char *p, const struct member *fields);
static int decode_one(json_t *o, unsigned char *p, const struct member *f)
{
    if (f->type == T_OBJECT) return decode_members(o, p, f->children);
    if (f->type == T_BYTES) return nsdiff_json_decode_bytes(o, (char *)p, f->size);
    const char *const *names = enum_names(f->type);
    uint64_t v = 0;
    if (names) {
        const char *text = json_string_value(o);
        if (!text) return -1;
        for (; names[v]; ++v) if (!strcmp(text, names[v])) break;
        if (!names[v]) return -1;
    } else if (f->type == T_BOOL) {
        if (!json_is_boolean(o)) return -1;
        v = json_is_true(o);
    } else if (f->type == T_ULL || f->type == T_ULONG || f->type == T_DEV || f->type == T_INO) {
        const char *text = json_string_value(o);
        if (!text || !*text || (text[0] == '0' && text[1])) return -1;
        for (const char *c = text; *c; ++c) {
            if (*c < '0' || *c > '9' || v > (UINT64_MAX - (unsigned)(*c-'0'))/10) return -1;
            v = v*10 + (unsigned)(*c-'0');
        }
    } else {
        if (!json_is_integer(o) || json_integer_value(o) < 0) return -1;
        v = (uint64_t)json_integer_value(o);
    }
    return write_number(p, f->type, v);
}
static int decode_members(json_t *o, unsigned char *p, const struct member *fields)
{
    if (!json_is_object(o)) return -1;
    for (const struct member *f = fields; f->name; ++f) {
        json_t *v = json_object_get(o, f->name);
        size_t n = f->dynamic ? ((struct network_set_info *)(void *)p)->count : f->count;
        if (n > f->count) return -1;
        if (f->array) {
            if (!json_is_array(v) || json_array_size(v) != n) return -1;
            for (size_t i = 0; i < n; ++i)
                if (decode_one(json_array_get(v, i), p + f->offset + i*f->size, f)) return -1;
        } else if (decode_one(v, p + f->offset, f)) return -1;
    }
    return 0;
}

/* Fixed domain arrays accept arbitrary input order but reject missing/duplicate identities. */
static int reorder(void *base, size_t stride, size_t count, size_t offset, const char *const *names, enum member_type key_type)
{
    unsigned char *copy = malloc(stride*count);
    bool seen[NSDIFF_ENV_WATCH_COUNT] = {false};
    if (!copy || count > NSDIFF_ENV_WATCH_COUNT) { free(copy); return -1; }
    memcpy(copy, base, stride*count);
    for (size_t i = 0; i < count; ++i) {
        size_t slot = count;
        if (key_type != T_BYTES) slot = (size_t)read_number(copy+i*stride+offset, key_type);
        else for (size_t j = 0; j < count; ++j)
            if (!strcmp((const char *)copy+i*stride+offset, names[j])) { slot = j; break; }
        if (slot >= count || seen[slot]) { free(copy); return -1; }
        seen[slot] = true;
        memcpy((unsigned char *)base+slot*stride, copy+i*stride, stride);
    }
    free(copy);
    return 0;
}
static int reorder_snapshot(struct process_snapshot *s)
{
#define REORDER(field, type, key, names, integer) \
    if (reorder(s->field, sizeof(s->field[0]), sizeof(s->field)/sizeof(s->field[0]), offsetof(struct type, key), names, integer)) return -1
    REORDER(namespaces, namespace_info, name, namespaces, T_BYTES);
    REORDER(limits.entries, resource_limit_info, kind, NULL, T_LIMIT);
    REORDER(proc_status.capabilities, capability_set_info, kind, NULL, T_CAP);
    REORDER(cgroup.files, cgroup_file_info, name, cgroups, T_BYTES);
    REORDER(mounts.entries, mount_point_info, target, mounts, T_BYTES);
    REORDER(environment.entries, environment_entry_info, name, envs, T_BYTES);
#undef REORDER
    sort_network(s);
    const struct network_set_info *sets[] = {&s->network.interfaces, &s->network.ipv4_default_routes, &s->network.ipv6_addresses, &s->network.ipv6_default_routes};
    for (size_t j = 0; j < 4; ++j)
        for (size_t i = 1; i < sets[j]->count; ++i)
            if (!strcmp(sets[j]->items[i-1], sets[j]->items[i])) return -1;
    return 0;
}

json_t *snapshot_semantic_json(const struct process_snapshot *s, bool canonical)
{
    return encode_members((const unsigned char *)s, process_snapshot_members, canonical);
}

int snapshot_model_decode(json_t *o, struct process_snapshot *s)
{
    memset(s, 0, sizeof(*s));
    s->pidfd = -1;
    return decode_members(o, (unsigned char *)s, process_snapshot_members) || reorder_snapshot(s) ? -1 : 0;
}

int snapshot_semantic_digest(const struct process_snapshot *s, unsigned char digest[32])
{
    struct process_snapshot *copy = malloc(sizeof(*copy));
    if (!copy) return -1;
    memcpy(copy, s, sizeof(*copy));
    snapshot_normalize(copy);
    json_t *o = snapshot_semantic_json(copy, true);
    free(copy);
    if (!o) return -1;
    json_object_del(o, "pid");
    json_object_del(o, "starttime_ticks");
    if (json_object_set_new(o, "semantic_schema", json_integer(1))) { json_decref(o); return -1; }
    char *canonical = json_dumps(o, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(o);
    if (!canonical) return -1;
    nsdiff_sha256(canonical, strlen(canonical), digest);
    free(canonical);
    return 0;
}
