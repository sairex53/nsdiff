#include <stdbool.h>
#include <stdio.h>

#include "config.h"

#include "nsdiff/render_compact.h"


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


static void print_escaped(
    const char *text
)
{
    const unsigned char *cursor =
        (const unsigned char *)text;

    putchar('"');

    while (*cursor != '\0') {

        unsigned char c = *cursor;

        switch (c) {

        case '\\':
            fputs("\\\\", stdout);
            break;

        case '"':
            fputs("\\\"", stdout);
            break;

        case '\n':
            fputs("\\n", stdout);
            break;

        case '\r':
            fputs("\\r", stdout);
            break;

        case '\t':
            fputs("\\t", stdout);
            break;

        default:

            if (c >= 0x20 &&
                c <= 0x7e) {

                putchar((int)c);

            } else {

                printf(
                    "\\x%02x",
                    (unsigned int)c
                );
            }

            break;
        }

        cursor++;
    }

    putchar('"');
}


static void begin_difference(
    const char *path
)
{
    printf(
        "  %s\n",
        path
    );
}


static void print_explanation(
    bool enabled,
    const char *text
)
{
    if (!enabled) {
        return;
    }

    printf(
        "    why: %s\n",
        text
    );
}


static void print_string_pair(
    const char *a,
    const char *b
)
{
    fputs(
        "    A: ",
        stdout
    );

    print_escaped(a);

    putchar('\n');

    fputs(
        "    B: ",
        stdout
    );

    print_escaped(b);

    putchar('\n');
}


static void print_limit_value(
    const struct limit_value *value
)
{
    if (value->unlimited) {

        fputs(
            "unlimited",
            stdout
        );

        return;
    }

    printf(
        "%llu",
        value->value
    );
}


static void print_limit_pair(
    const struct resource_limit_info *a,
    const struct resource_limit_info *b
)
{
    fputs(
        "    A: soft=",
        stdout
    );

    print_limit_value(
        &a->soft
    );

    fputs(
        " hard=",
        stdout
    );

    print_limit_value(
        &a->hard
    );

    if (a->units[0] != '\0') {

        printf(
            " units=%s",
            a->units
        );
    }

    putchar('\n');

    fputs(
        "    B: soft=",
        stdout
    );

    print_limit_value(
        &b->soft
    );

    fputs(
        " hard=",
        stdout
    );

    print_limit_value(
        &b->hard
    );

    if (b->units[0] != '\0') {

        printf(
            " units=%s",
            b->units
        );
    }

    putchar('\n');
}


static void print_mount_value(
    const char *label,
    const struct mount_point_info *mount
)
{
    printf(
        "    %s: ",
        label
    );

    if (!mount->mounted) {

        fputs(
            "not mounted\n",
            stdout
        );

        return;
    }

    printf(
        "%s ",
        mount->fstype
    );

    fputs(
        "source=",
        stdout
    );

    print_escaped(
        mount->source[0] != '\0'
            ? mount->source
            : "none"
    );

    fputs(
        " root=",
        stdout
    );

    print_escaped(
        mount->root[0] != '\0'
            ? mount->root
            : "/"
    );

    printf(
        " flags=%s",
        mount->read_only
            ? "ro"
            : "rw"
    );

    if (mount->nosuid) {
        fputs(",nosuid", stdout);
    }

    if (mount->nodev) {
        fputs(",nodev", stdout);
    }

    if (mount->noexec) {
        fputs(",noexec", stdout);
    }

    putchar('\n');
}


static void print_network_set(
    const char *label,
    const struct network_set_info *set
)
{
    size_t i;

    printf(
        "    %s:",
        label
    );

    if (set->count == 0) {

        fputs(
            " none\n",
            stdout
        );

        return;
    }

    putchar('\n');

    for (i = 0;
         i < set->count;
         i++) {

        fputs(
            "      - ",
            stdout
        );

        print_escaped(
            set->items[i]
        );

        putchar('\n');
    }
}


static void render_network_set_difference(
    const char *path,
    const struct network_set_info *a,
    const struct network_set_info *b,
    const struct field_diff *field,
    bool explain,
    unsigned int *shown
)
{
    if (field->state !=
        NSDIFF_DIFF_DIFFERENT) {

        return;
    }

    begin_difference(path);

    print_network_set(
        "A",
        a
    );

    print_network_set(
        "B",
        b
    );

    print_explanation(
        explain,
        "The processes see different network state."
    );

    (*shown)++;
}


static void print_environment_value(
    const char *label,
    const struct environment_entry_info *entry
)
{
    printf(
        "    %s: ",
        label
    );

    if (!entry->present) {

        fputs(
            "unset\n",
            stdout
        );

        return;
    }

    if (entry->redact_value) {

        fputs(
            "set [value hidden]\n",
            stdout
        );

        return;
    }

    print_escaped(
        entry->value
    );

    putchar('\n');
}


void render_compact_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff,
    bool explain
)
{
    size_t i;

    unsigned int shown = 0;

    char path[256];

    printf(
        "nsdiff %s\n"
        "A: PID %ld\n"
        "B: PID %ld\n"
        "\n"
        "Differences\n",
        NSDIFF_VERSION,
        (long)a->pid,
        (long)b->pid
    );

    /*
     * Namespaces.
     */

    for (i = 0;
         i < NSDIFF_NAMESPACE_COUNT;
         i++) {

        if (diff->namespaces[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "namespaces.%s",
            a->namespaces[i].name
        );

        begin_difference(path);

        print_string_pair(
            a->namespaces[i].target,
            b->namespaces[i].target
        );

        print_explanation(
            explain,
            "Different namespace objects can give the processes different kernel-visible environments."
        );

        shown++;
    }

    /*
     * Credentials.
     */

    if (diff->euid.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "credentials.euid"
        );

        printf(
            "    A: %lu\n"
            "    B: %lu\n",
            (unsigned long)a->proc_status.uid[1],
            (unsigned long)b->proc_status.uid[1]
        );

        print_explanation(
            explain,
            "The effective UID participates in ordinary Linux permission checks."
        );

        shown++;
    }

    if (diff->egid.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "credentials.egid"
        );

        printf(
            "    A: %lu\n"
            "    B: %lu\n",
            (unsigned long)a->proc_status.gid[1],
            (unsigned long)b->proc_status.gid[1]
        );

        print_explanation(
            explain,
            "The effective GID participates in ordinary Linux permission checks."
        );

        shown++;
    }

    /*
     * Resource limits.
     */

    for (i = 0;
         i < NSDIFF_LIMIT_COUNT;
         i++) {

        if (diff->limits[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "limits.%s",
            limit_name(
                a->limits.entries[i].kind
            )
        );

        begin_difference(path);

        print_limit_pair(
            &a->limits.entries[i],
            &b->limits.entries[i]
        );

        print_explanation(
            explain,
            "A resource limit can make otherwise identical programs behave differently."
        );

        shown++;
    }

    /*
     * cgroup v2.
     */

    if (diff->cgroup_path.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "cgroup.path"
        );

        print_string_pair(
            a->cgroup.path,
            b->cgroup.path
        );

        print_explanation(
            explain,
            "Different cgroup placement can imply different CPU, memory and process-count controls."
        );

        shown++;
    }

    for (i = 0;
         i < NSDIFF_CGROUP_FILE_COUNT;
         i++) {

        if (diff->cgroup_files[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "cgroup.%s",
            a->cgroup.files[i].name
        );

        begin_difference(path);

        print_string_pair(
            a->cgroup.files[i].value,
            b->cgroup.files[i].value
        );

        print_explanation(
            explain,
            "The processes are subject to different cgroup resource-control values."
        );

        shown++;
    }

    /*
     * Network.
     */

    render_network_set_difference(
        "network.interfaces",
        &a->network.interfaces,
        &b->network.interfaces,
        &diff->network_interfaces,
        explain,
        &shown
    );

    render_network_set_difference(
        "network.ipv4_default_routes",
        &a->network.ipv4_default_routes,
        &b->network.ipv4_default_routes,
        &diff->network_ipv4_default_routes,
        explain,
        &shown
    );

    render_network_set_difference(
        "network.ipv6_addresses",
        &a->network.ipv6_addresses,
        &b->network.ipv6_addresses,
        &diff->network_ipv6_addresses,
        explain,
        &shown
    );

    render_network_set_difference(
        "network.ipv6_default_routes",
        &a->network.ipv6_default_routes,
        &b->network.ipv6_default_routes,
        &diff->network_ipv6_default_routes,
        explain,
        &shown
    );

    /*
     * Mounts.
     */

    if (diff->mount_count.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "mounts.total"
        );

        printf(
            "    A: %d\n"
            "    B: %d\n",
            a->mounts.total_mounts,
            b->mounts.total_mounts
        );

        print_explanation(
            explain,
            "The mount tables contain different numbers of mounts."
        );

        shown++;
    }

    for (i = 0;
         i < NSDIFF_WATCHED_MOUNT_COUNT;
         i++) {

        if (diff->mounts[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "mounts%s",
            a->mounts.entries[i].target
        );

        begin_difference(path);

        print_mount_value(
            "A",
            &a->mounts.entries[i]
        );

        print_mount_value(
            "B",
            &b->mounts.entries[i]
        );

        print_explanation(
            explain,
            "Different mount properties can change filesystem visibility, permissions or executable behavior."
        );

        shown++;
    }

    /*
     * /dev/shm.
     */

    if (diff->shm_size.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "shared_memory.size_bytes"
        );

        printf(
            "    A: %llu\n"
            "    B: %llu\n",
            a->mounts.shm.size_bytes,
            b->mounts.shm.size_bytes
        );

        print_explanation(
            explain,
            "Different /dev/shm capacity can affect applications using POSIX shared memory or tmpfs-backed IPC."
        );

        shown++;
    }

    /*
     * Environment.
     */

    if (diff->environment_count.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "environment.total_entries"
        );

        printf(
            "    A: %u\n"
            "    B: %u\n",
            a->environment.total_entries,
            b->environment.total_entries
        );

        print_explanation(
            explain,
            "The exec-time environment contains a different number of variables."
        );

        shown++;
    }

    for (i = 0;
         i < NSDIFF_ENV_WATCH_COUNT;
         i++) {

        if (diff->environment[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "environment.%s",
            a->environment.entries[i].name
        );

        begin_difference(path);

        print_environment_value(
            "A",
            &a->environment.entries[i]
        );

        print_environment_value(
            "B",
            &b->environment.entries[i]
        );

        print_explanation(
            explain,
            "Exec-time environment variables can alter library loading, paths, runtimes, IPC endpoints and application configuration."
        );

        shown++;
    }

    /*
     * Capabilities.
     */

    for (i = 0;
         i < NSDIFF_CAPSET_COUNT;
         i++) {

        const struct capability_set_info *set_a =
            &a->proc_status.capabilities[i];

        const struct capability_set_info *set_b =
            &b->proc_status.capabilities[i];

        if (diff->capabilities[i].state !=
            NSDIFF_DIFF_DIFFERENT) {

            continue;
        }

        snprintf(
            path,
            sizeof(path),
            "capabilities.%s",
            capability_set_name(
                set_a->kind
            )
        );

        begin_difference(path);

        printf(
            "    A: 0x%016llx\n"
            "    B: 0x%016llx\n"
            "    only-A: 0x%016llx\n"
            "    only-B: 0x%016llx\n",
            set_a->mask,
            set_b->mask,
            set_a->mask & ~set_b->mask,
            set_b->mask & ~set_a->mask
        );

        print_explanation(
            explain,
            "Linux capability sets control privileged operations and are scoped by the process user namespace."
        );

        shown++;
    }

    /*
     * Security.
     */

    if (diff->no_new_privs.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "security.no_new_privs"
        );

        printf(
            "    A: %d\n"
            "    B: %d\n",
            a->proc_status.no_new_privs,
            b->proc_status.no_new_privs
        );

        print_explanation(
            explain,
            "no_new_privs changes whether execve can grant additional privilege."
        );

        shown++;
    }

    if (diff->seccomp.state ==
        NSDIFF_DIFF_DIFFERENT) {

        begin_difference(
            "security.seccomp"
        );

        print_string_pair(
            seccomp_name(
                a->proc_status.seccomp
            ),
            seccomp_name(
                b->proc_status.seccomp
            )
        );

        print_explanation(
            explain,
            "Different seccomp modes can make system calls available to one process and blocked for the other."
        );

        shown++;
    }

    if (shown == 0) {

        fputs(
            "  none\n",
            stdout
        );
    }

    printf(
        "\n"
        "Summary\n"
        "  %u comparable fields checked\n"
        "  %u differences found\n",
        diff->comparable_fields,
        diff->differences
    );
}
