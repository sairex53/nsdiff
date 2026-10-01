#include "nsdiff/json_writer.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "nsdiff/render_json.h"
#include "nsdiff/render_network_json.h"


static const char *collect_status_name(
    enum collect_status status
)
{
    switch (status) {

    case COLLECT_OK:
        return "ok";

    case COLLECT_PERMISSION_DENIED:
        return "permission denied";

    case COLLECT_NOT_SUPPORTED:
        return "not supported";

    case COLLECT_PROCESS_GONE:
        return "process gone";

    case COLLECT_IO_ERROR:
        return "I/O error";

    case COLLECT_PARSE_ERROR:
        return "parse error";
    case COLLECT_TRUNCATED:
        return "truncated";

    default:
        return "unknown";
    }
}


static const char *diff_state_name(
    enum nsdiff_diff_state state
)
{
    switch (state) {

    case NSDIFF_DIFF_UNAVAILABLE:
        return "unavailable";

    case NSDIFF_DIFF_SAME:
        return "same";

    case NSDIFF_DIFF_DIFFERENT:
        return "different";

    default:
        return "unknown";
    }
}


static const char *limit_name(
    enum nsdiff_limit_kind kind
)
{
    switch (kind) {

    case NSDIFF_LIMIT_NOFILE:
        return "RLIMIT_NOFILE";

    case NSDIFF_LIMIT_NPROC:
        return "RLIMIT_NPROC";

    case NSDIFF_LIMIT_STACK:
        return "RLIMIT_STACK";

    case NSDIFF_LIMIT_MEMLOCK:
        return "RLIMIT_MEMLOCK";

    case NSDIFF_LIMIT_AS:
        return "RLIMIT_AS";

    case NSDIFF_LIMIT_CORE:
        return "RLIMIT_CORE";

    case NSDIFF_LIMIT_FSIZE:
        return "RLIMIT_FSIZE";

    default:
        return "UNKNOWN";
    }
}


static const char *capability_set_name(
    enum nsdiff_capset_kind kind
)
{
    switch (kind) {

    case NSDIFF_CAP_INHERITABLE:
        return "Inheritable";

    case NSDIFF_CAP_PERMITTED:
        return "Permitted";

    case NSDIFF_CAP_EFFECTIVE:
        return "Effective";

    case NSDIFF_CAP_BOUNDING:
        return "Bounding";

    case NSDIFF_CAP_AMBIENT:
        return "Ambient";

    default:
        return "Unknown";
    }
}


static const char *seccomp_name(
    int mode
)
{
    switch (mode) {

    case 0:
        return "disabled";

    case 1:
        return "strict";

    case 2:
        return "filter";

    default:
        return "unknown";
    }
}



static void json_write_nullable_string(
    const char *text
)
{
    if (text == NULL) {

        fputs(
            "null",
            stdout
        );

        return;
    }

    nsdiff_json_write_string(text);
}


static void emit_separator(
    bool *first
)
{
    if (*first) {

        *first = false;

    } else {

        fputs(
            ",\n",
            stdout
        );
    }
}


static void emit_field(
    bool *first,
    const char *path,
    enum nsdiff_diff_state state,
    const char *status_a,
    const char *status_b,
    const char *value_a,
    const char *value_b,
    bool redacted
)
{
    emit_separator(first);

    fputs(
        "    {\n"
        "      \"path\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    fputs(
        ",\n"
        "      \"state\": ",
        stdout
    );

    nsdiff_json_write_string(
        diff_state_name(state)
    );

    fputs(
        ",\n"
        "      \"status_a\": ",
        stdout
    );

    nsdiff_json_write_string(status_a);

    fputs(
        ",\n"
        "      \"status_b\": ",
        stdout
    );

    nsdiff_json_write_string(status_b);

    fputs(
        ",\n"
        "      \"a\": ",
        stdout
    );

    json_write_nullable_string(
        value_a
    );

    fputs(
        ",\n"
        "      \"b\": ",
        stdout
    );

    json_write_nullable_string(
        value_b
    );

    printf(
        ",\n"
        "      \"redacted\": %s\n"
        "    }",
        redacted
            ? "true"
            : "false"
    );
}


static void format_unsigned_long(
    unsigned long value,
    char *buffer,
    size_t buffer_size
)
{
    snprintf(
        buffer,
        buffer_size,
        "%lu",
        value
    );
}


static void format_unsigned_long_long(
    unsigned long long value,
    char *buffer,
    size_t buffer_size
)
{
    snprintf(
        buffer,
        buffer_size,
        "%llu",
        value
    );
}


static void format_int(
    int value,
    char *buffer,
    size_t buffer_size
)
{
    snprintf(
        buffer,
        buffer_size,
        "%d",
        value
    );
}


static void format_limit_value(
    const struct limit_value *value,
    char *buffer,
    size_t buffer_size
)
{
    if (value->unlimited) {

        snprintf(
            buffer,
            buffer_size,
            "unlimited"
        );

        return;
    }

    snprintf(
        buffer,
        buffer_size,
        "%llu",
        value->value
    );
}


static void format_limit(
    const struct resource_limit_info *limit,
    char *buffer,
    size_t buffer_size
)
{
    char soft[32];
    char hard[32];

    format_limit_value(
        &limit->soft,
        soft,
        sizeof(soft)
    );

    format_limit_value(
        &limit->hard,
        hard,
        sizeof(hard)
    );

    snprintf(
        buffer,
        buffer_size,
        "soft=%s;hard=%s;units=%s",
        soft,
        hard,
        limit->units[0] != '\0'
            ? limit->units
            : ""
    );
}


static void format_mount(
    const struct mount_point_info *mount,
    char *buffer,
    size_t buffer_size
)
{
    if (!mount->mounted) {

        snprintf(
            buffer,
            buffer_size,
            "not a separate mount"
        );

        return;
    }

    snprintf(
        buffer,
        buffer_size,
        "%s source=%s root=%s flags=%s%s%s%s",
        mount->fstype[0] != '\0'
            ? mount->fstype
            : "unknown",
        mount->source[0] != '\0'
            ? mount->source
            : "none",
        mount->root[0] != '\0'
            ? mount->root
            : "/",
        mount->read_only
            ? "ro"
            : "rw",
        mount->nosuid
            ? ",nosuid"
            : "",
        mount->nodev
            ? ",nodev"
            : "",
        mount->noexec
            ? ",noexec"
            : ""
    );
}


static void format_capability_mask(
    unsigned long long mask,
    char *buffer,
    size_t buffer_size
)
{
    snprintf(
        buffer,
        buffer_size,
        "0x%016llx",
        mask
    );
}


static const char *effective_status(
    enum collect_status parent_status,
    enum collect_status child_status
)
{
    if (parent_status !=
        COLLECT_OK) {

        return collect_status_name(
            parent_status
        );
    }

    return collect_status_name(
        child_status
    );
}


void render_json_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff
)
{
    bool first = true;

    size_t i;

    char path[256];

    char value_a[1024];
    char value_b[1024];

    /*
     * Document header.
     */

    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"tool_version\": ",
        stdout
    );

    nsdiff_json_write_string(
        NSDIFF_VERSION
    );

    printf(
        ",\n"
        "  \"pid_a\": %ld,\n"
        "  \"pid_b\": %ld,\n"
        "  \"starttime_a\": %llu,\n"
        "  \"starttime_b\": %llu,\n"
        "  \"summary\": {\n"
        "    \"comparable_fields\": %u,\n"
        "    \"differences\": %u\n"
        "  },\n"
        "  \"fields\": [\n",
        (long)a->pid,
        (long)b->pid,
        a->starttime_ticks,
        b->starttime_ticks,
        diff->comparable_fields,
        diff->differences
    );

    /*
     * Namespaces.
     */

    for (i = 0;
         i < NSDIFF_NAMESPACE_COUNT;
         i++) {

        const struct namespace_info *ns_a =
            &a->namespaces[i];

        const struct namespace_info *ns_b =
            &b->namespaces[i];

        snprintf(
            path,
            sizeof(path),
            "namespaces.%s",
            ns_a->name
        );

        emit_field(
            &first,
            path,
            diff->namespaces[i].state,
            collect_status_name(
                ns_a->status
            ),
            collect_status_name(
                ns_b->status
            ),
            ns_a->status == COLLECT_OK
                ? ns_a->target
                : NULL,
            ns_b->status == COLLECT_OK
                ? ns_b->target
                : NULL,
            false
        );
    }

    /*
     * Credentials.
     */

    if (a->proc_status.status == COLLECT_OK &&
        a->proc_status.have_uid) {

        format_unsigned_long(
            a->proc_status.uid[1],
            value_a,
            sizeof(value_a)
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->proc_status.status == COLLECT_OK &&
        b->proc_status.have_uid) {

        format_unsigned_long(
            b->proc_status.uid[1],
            value_b,
            sizeof(value_b)
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "credentials.euid",
        diff->euid.state,
        a->proc_status.status == COLLECT_OK
            ? (a->proc_status.have_uid
                ? "ok"
                : "missing")
            : collect_status_name(
                a->proc_status.status
            ),
        b->proc_status.status == COLLECT_OK
            ? (b->proc_status.have_uid
                ? "ok"
                : "missing")
            : collect_status_name(
                b->proc_status.status
            ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    if (a->proc_status.status == COLLECT_OK &&
        a->proc_status.have_gid) {

        format_unsigned_long(
            a->proc_status.gid[1],
            value_a,
            sizeof(value_a)
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->proc_status.status == COLLECT_OK &&
        b->proc_status.have_gid) {

        format_unsigned_long(
            b->proc_status.gid[1],
            value_b,
            sizeof(value_b)
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "credentials.egid",
        diff->egid.state,
        a->proc_status.status == COLLECT_OK
            ? (a->proc_status.have_gid
                ? "ok"
                : "missing")
            : collect_status_name(
                a->proc_status.status
            ),
        b->proc_status.status == COLLECT_OK
            ? (b->proc_status.have_gid
                ? "ok"
                : "missing")
            : collect_status_name(
                b->proc_status.status
            ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    /*
     * Resource limits.
     */

    for (i = 0;
         i < NSDIFF_LIMIT_COUNT;
         i++) {

        const struct resource_limit_info *limit_a =
            &a->limits.entries[i];

        const struct resource_limit_info *limit_b =
            &b->limits.entries[i];

        snprintf(
            path,
            sizeof(path),
            "limits.%s",
            limit_name(
                limit_a->kind
            )
        );

        if (a->limits.status == COLLECT_OK &&
            limit_a->status == COLLECT_OK) {

            format_limit(
                limit_a,
                value_a,
                sizeof(value_a)
            );

        } else {

            value_a[0] = '\0';
        }

        if (b->limits.status == COLLECT_OK &&
            limit_b->status == COLLECT_OK) {

            format_limit(
                limit_b,
                value_b,
                sizeof(value_b)
            );

        } else {

            value_b[0] = '\0';
        }

        emit_field(
            &first,
            path,
            diff->limits[i].state,
            effective_status(
                a->limits.status,
                limit_a->status
            ),
            effective_status(
                b->limits.status,
                limit_b->status
            ),
            value_a[0] != '\0'
                ? value_a
                : NULL,
            value_b[0] != '\0'
                ? value_b
                : NULL,
            false
        );
    }

    /*
     * cgroup v2 path.
     */

    emit_field(
        &first,
        "cgroup.path",
        diff->cgroup_path.state,
        collect_status_name(
            a->cgroup.status
        ),
        collect_status_name(
            b->cgroup.status
        ),
        a->cgroup.status == COLLECT_OK
            ? a->cgroup.path
            : NULL,
        b->cgroup.status == COLLECT_OK
            ? b->cgroup.path
            : NULL,
        false
    );

    /*
     * cgroup v2 files.
     */

    for (i = 0;
         i < NSDIFF_CGROUP_FILE_COUNT;
         i++) {

        const struct cgroup_file_info *entry_a =
            &a->cgroup.files[i];

        const struct cgroup_file_info *entry_b =
            &b->cgroup.files[i];

        snprintf(
            path,
            sizeof(path),
            "cgroup.%s",
            entry_a->name
        );

        emit_field(
            &first,
            path,
            diff->cgroup_files[i].state,
            effective_status(
                a->cgroup.status,
                entry_a->status
            ),
            effective_status(
                b->cgroup.status,
                entry_b->status
            ),
            a->cgroup.status == COLLECT_OK &&
                entry_a->status == COLLECT_OK
                ? entry_a->value
                : NULL,
            b->cgroup.status == COLLECT_OK &&
                entry_b->status == COLLECT_OK
                ? entry_b->value
                : NULL,
            false
        );
    }

	render_network_json_fields(
		a,
		b,
		diff,
		&first
	);

    /*
     * Total mount count.
     */

    if (a->mounts.status == COLLECT_OK) {

        format_int(
            a->mounts.total_mounts,
            value_a,
            sizeof(value_a)
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->mounts.status == COLLECT_OK) {

        format_int(
            b->mounts.total_mounts,
            value_b,
            sizeof(value_b)
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "mounts.total",
        diff->mount_count.state,
        collect_status_name(
            a->mounts.status
        ),
        collect_status_name(
            b->mounts.status
        ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    /*
     * Watched mounts.
     */

    for (i = 0;
         i < NSDIFF_WATCHED_MOUNT_COUNT;
         i++) {

        const struct mount_point_info *mount_a =
            &a->mounts.entries[i];

        const struct mount_point_info *mount_b =
            &b->mounts.entries[i];

        snprintf(
            path,
            sizeof(path),
            "mounts%s",
            mount_a->target
        );

        if (a->mounts.status == COLLECT_OK &&
            mount_a->status == COLLECT_OK) {

            format_mount(
                mount_a,
                value_a,
                sizeof(value_a)
            );

        } else {

            value_a[0] = '\0';
        }

        if (b->mounts.status == COLLECT_OK &&
            mount_b->status == COLLECT_OK) {

            format_mount(
                mount_b,
                value_b,
                sizeof(value_b)
            );

        } else {

            value_b[0] = '\0';
        }

        emit_field(
            &first,
            path,
            diff->mounts[i].state,
            effective_status(
                a->mounts.status,
                mount_a->status
            ),
            effective_status(
                b->mounts.status,
                mount_b->status
            ),
            value_a[0] != '\0'
                ? value_a
                : NULL,
            value_b[0] != '\0'
                ? value_b
                : NULL,
            false
        );
    }

    /*
     * /dev/shm capacity.
     */

    if (a->mounts.shm.status ==
        COLLECT_OK) {

        format_unsigned_long_long(
            a->mounts.shm.size_bytes,
            value_a,
            sizeof(value_a)
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->mounts.shm.status ==
        COLLECT_OK) {

        format_unsigned_long_long(
            b->mounts.shm.size_bytes,
            value_b,
            sizeof(value_b)
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "shared_memory.size_bytes",
        diff->shm_size.state,
        collect_status_name(
            a->mounts.shm.status
        ),
        collect_status_name(
            b->mounts.shm.status
        ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    /*
     * Environment entry count.
     */

    if (a->environment.status ==
        COLLECT_OK) {

        snprintf(
            value_a,
            sizeof(value_a),
            "%u",
            a->environment.total_entries
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->environment.status ==
        COLLECT_OK) {

        snprintf(
            value_b,
            sizeof(value_b),
            "%u",
            b->environment.total_entries
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "environment.total_entries",
        diff->environment_count.state,
        collect_status_name(
            a->environment.status
        ),
        collect_status_name(
            b->environment.status
        ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    /*
     * Watched environment variables.
     */

    for (i = 0;
         i < NSDIFF_ENV_WATCH_COUNT;
         i++) {

        const struct environment_entry_info *entry_a =
            &a->environment.entries[i];

        const struct environment_entry_info *entry_b =
            &b->environment.entries[i];

        const char *status_a;
        const char *status_b;

        const char *env_value_a = NULL;
        const char *env_value_b = NULL;

        bool redacted =
            entry_a->redact_value ||
            entry_b->redact_value;

        snprintf(
            path,
            sizeof(path),
            "environment.%s",
            entry_a->name
        );

        if (a->environment.status !=
            COLLECT_OK) {

            status_a =
                collect_status_name(
                    a->environment.status
                );

        } else {

            status_a =
                collect_status_name(
                    entry_a->status
                );
        }

        if (b->environment.status !=
            COLLECT_OK) {

            status_b =
                collect_status_name(
                    b->environment.status
                );

        } else {

            status_b =
                collect_status_name(
                    entry_b->status
                );
        }

        if (a->environment.status ==
                COLLECT_OK &&
            entry_a->status ==
                COLLECT_OK &&
            entry_a->present) {

            env_value_a =
                redacted
                    ? "<redacted>"
                    : entry_a->value;
        }

        if (b->environment.status ==
                COLLECT_OK &&
            entry_b->status ==
                COLLECT_OK &&
            entry_b->present) {

            env_value_b =
                redacted
                    ? "<redacted>"
                    : entry_b->value;
        }

        emit_field(
            &first,
            path,
            diff->environment[i].state,
            status_a,
            status_b,
            env_value_a,
            env_value_b,
            redacted
        );
    }

    /*
     * Capability sets.
     */

    for (i = 0;
         i < NSDIFF_CAPSET_COUNT;
         i++) {

        const struct capability_set_info *set_a =
            &a->proc_status.capabilities[i];

        const struct capability_set_info *set_b =
            &b->proc_status.capabilities[i];

        const char *status_a;
        const char *status_b;

        snprintf(
            path,
            sizeof(path),
            "capabilities.%s",
            capability_set_name(
                set_a->kind
            )
        );

        if (a->proc_status.status !=
            COLLECT_OK) {

            status_a =
                collect_status_name(
                    a->proc_status.status
                );

        } else {

            status_a =
                set_a->present
                    ? "ok"
                    : "missing";
        }

        if (b->proc_status.status !=
            COLLECT_OK) {

            status_b =
                collect_status_name(
                    b->proc_status.status
                );

        } else {

            status_b =
                set_b->present
                    ? "ok"
                    : "missing";
        }

        if (a->proc_status.status ==
                COLLECT_OK &&
            set_a->present) {

            format_capability_mask(
                set_a->mask,
                value_a,
                sizeof(value_a)
            );

        } else {

            value_a[0] = '\0';
        }

        if (b->proc_status.status ==
                COLLECT_OK &&
            set_b->present) {

            format_capability_mask(
                set_b->mask,
                value_b,
                sizeof(value_b)
            );

        } else {

            value_b[0] = '\0';
        }

        emit_field(
            &first,
            path,
            diff->capabilities[i].state,
            status_a,
            status_b,
            value_a[0] != '\0'
                ? value_a
                : NULL,
            value_b[0] != '\0'
                ? value_b
                : NULL,
            false
        );
    }

    /*
     * no_new_privs.
     */

    if (a->proc_status.status ==
            COLLECT_OK &&
        a->proc_status.have_no_new_privs) {

        format_int(
            a->proc_status.no_new_privs,
            value_a,
            sizeof(value_a)
        );

    } else {

        value_a[0] = '\0';
    }

    if (b->proc_status.status ==
            COLLECT_OK &&
        b->proc_status.have_no_new_privs) {

        format_int(
            b->proc_status.no_new_privs,
            value_b,
            sizeof(value_b)
        );

    } else {

        value_b[0] = '\0';
    }

    emit_field(
        &first,
        "security.no_new_privs",
        diff->no_new_privs.state,
        a->proc_status.status == COLLECT_OK
            ? (a->proc_status.have_no_new_privs
                ? "ok"
                : "missing")
            : collect_status_name(
                a->proc_status.status
            ),
        b->proc_status.status == COLLECT_OK
            ? (b->proc_status.have_no_new_privs
                ? "ok"
                : "missing")
            : collect_status_name(
                b->proc_status.status
            ),
        value_a[0] != '\0'
            ? value_a
            : NULL,
        value_b[0] != '\0'
            ? value_b
            : NULL,
        false
    );

    /*
     * seccomp.
     */

    emit_field(
        &first,
        "security.seccomp",
        diff->seccomp.state,
        a->proc_status.status == COLLECT_OK
            ? (a->proc_status.have_seccomp
                ? "ok"
                : "missing")
            : collect_status_name(
                a->proc_status.status
            ),
        b->proc_status.status == COLLECT_OK
            ? (b->proc_status.have_seccomp
                ? "ok"
                : "missing")
            : collect_status_name(
                b->proc_status.status
            ),
        a->proc_status.status == COLLECT_OK &&
            a->proc_status.have_seccomp
                ? seccomp_name(
                    a->proc_status.seccomp
                )
                : NULL,
        b->proc_status.status == COLLECT_OK &&
            b->proc_status.have_seccomp
                ? seccomp_name(
                    b->proc_status.seccomp
                )
                : NULL,
        false
    );

    fputs(
        "\n"
        "  ]\n"
        "}\n",
        stdout
    );
}
