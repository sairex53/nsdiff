#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "config.h"
#include <ctype.h>
#include <sys/capability.h>

#include "nsdiff/render.h"
#include "nsdiff/diff.h"
#include "nsdiff/render_network.h"

const char *collect_status_string(
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

static void print_escaped_value(
    const char *value
)
{
    const unsigned char *cursor =
        (const unsigned char *)value;

    putchar('"');

    while (*cursor != '\0') {

        unsigned char c = *cursor;

        switch (c) {

        case '\\':
            printf("\\\\");
            break;

        case '"':
            printf("\\\"");
            break;

        case '\n':
            printf("\\n");
            break;

        case '\r':
            printf("\\r");
            break;

        case '\t':
            printf("\\t");
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

static void render_environment_diff(
    const struct environment_info *a,
    const struct environment_info *b,
    const struct process_diff *diff
)
{
    size_t i;

    printf("\nEnvironment (exec-time)\n");

    /*
     * If the entire environment could not be collected,
     * individual entry statuses are meaningless.
     */
    if (a->status != COLLECT_OK ||
        b->status != COLLECT_OK) {

        printf(
            "  unavailable (A: %s, B: %s)\n",
            collect_status_string(
                a->status
            ),
            collect_status_string(
                b->status
            )
        );

        return;
    }

    switch (diff->environment_count.state) {

    case NSDIFF_DIFF_UNAVAILABLE:

        printf(
            "  total entries    unavailable\n"
        );

        break;

    case NSDIFF_DIFF_SAME:

        printf(
            "  total entries    same [%u]\n",
            a->total_entries
        );

        break;

    case NSDIFF_DIFF_DIFFERENT:

        printf(
            "  total entries    different "
            "[A %u | B %u]\n",
            a->total_entries,
            b->total_entries
        );

        break;
    }

    for (i = 0;
         i < NSDIFF_ENV_WATCH_COUNT;
         i++) {

        const struct environment_entry_info *entry_a =
            &a->entries[i];

        const struct environment_entry_info *entry_b =
            &b->entries[i];

        /*
         * Avoid noise for variables absent from
         * both environments.
         */
        if (!entry_a->present &&
            !entry_b->present) {

            continue;
        }

        printf(
            "  %-24s ",
            entry_a->name
        );

        switch (diff->environment[i].state) {

        case NSDIFF_DIFF_UNAVAILABLE:

            printf(
                "unavailable [A: %s | B: %s]\n",
                collect_status_string(
                    entry_a->status
                ),
                collect_status_string(
                    entry_b->status
                )
            );

            break;

        case NSDIFF_DIFF_SAME:

            if (entry_a->redact_value ||
                entry_b->redact_value) {

                printf(
                    "same [set, value hidden]\n"
                );

                break;
            }

            printf("same [");

            print_escaped_value(
                entry_a->value
            );

            printf("]\n");

            break;

        case NSDIFF_DIFF_DIFFERENT:

            if (entry_a->present !=
                entry_b->present) {

                printf(
                    "different [A %s | B %s]\n",
                    entry_a->present
                        ? "set"
                        : "unset",
                    entry_b->present
                        ? "set"
                        : "unset"
                );

                break;
            }

            if (entry_a->redact_value ||
                entry_b->redact_value) {

                printf(
                    "different [values hidden]\n"
                );

                break;
            }

            printf("different\n");

            printf("    A: ");

            print_escaped_value(
                entry_a->value
            );

            printf("\n");

            printf("    B: ");

            print_escaped_value(
                entry_b->value
            );

            printf("\n");

            break;
        }
    }
}

static void render_cgroup_diff(
    const struct cgroup_info *a,
    const struct cgroup_info *b,
    const struct process_diff *diff
)
{
    size_t i;

    printf("\nCgroup v2\n");

    if (a->status != COLLECT_OK ||
        b->status != COLLECT_OK) {

        printf(
            "  unavailable (A: %s, B: %s)\n",
            collect_status_string(
                a->status
            ),
            collect_status_string(
                b->status
            )
        );
    }

	if (diff->cgroup_path.state ==
		NSDIFF_DIFF_SAME) {

		printf(
			"  path             same [%s]\n",
			a->path
		);

	} else if (diff->cgroup_path.state ==
			   NSDIFF_DIFF_DIFFERENT) {

		printf(
			"  path             different\n"
			"    A: %s\n"
			"    B: %s\n",
			a->path,
			b->path
		);

	} else {

		printf(
			"  path             unavailable "
			"(A: %s, B: %s)\n",
			collect_status_string(
				a->status
			),
			collect_status_string(
				b->status
			)
		);
	}

    for (i = 0;
         i < NSDIFF_CGROUP_FILE_COUNT;
         i++) {

        const struct cgroup_file_info *entry_a =
            &a->files[i];

        const struct cgroup_file_info *entry_b =
            &b->files[i];

        printf(
            "  %-16s ",
            entry_a->name
        );

		switch (diff->cgroup_files[i].state) {

		case NSDIFF_DIFF_UNAVAILABLE:

			printf(
				"unavailable [A: %s | B: %s]\n",
				collect_status_string(
					entry_a->status
				),
				collect_status_string(
					entry_b->status
				)
			);

			break;

		case NSDIFF_DIFF_SAME:

			printf(
				"same [%s]\n",
				entry_a->value
			);

			break;

		case NSDIFF_DIFF_DIFFERENT:

			printf(
				"different\n"
				"    A: %s\n"
				"    B: %s\n",
				entry_a->value,
				entry_b->value
			);

			break;
		}
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

static unsigned int capability_count(
    unsigned long long mask
)
{
    unsigned int count = 0;

    while (mask != 0) {

        count +=
            (unsigned int)(mask & 1ULL);

        mask >>= 1;
    }

    return count;
}

static void print_capability_name(
    unsigned int capability,
    const char *indent
)
{
    char *name;
    char *cursor;

    name = cap_to_name(
        (cap_value_t)capability
    );

    if (name == NULL) {

        printf(
            "%sCAP_%u\n",
            indent,
            capability
        );

        return;
    }

    for (cursor = name;
         *cursor != '\0';
         cursor++) {

        *cursor =
            (char)toupper(
                (unsigned char)*cursor
            );
    }

    printf(
        "%s%s\n",
        indent,
        name
    );

    cap_free(name);
}

static void print_capability_mask(
    unsigned long long mask,
    const char *indent
)
{
    cap_value_t max_bits;

    unsigned int limit;
    unsigned int bit;

    if (mask == 0) {

        printf(
            "%snone\n",
            indent
        );

        return;
    }

    max_bits = cap_max_bits();

    if (max_bits <= 0 ||
        max_bits > 64) {

        limit = 64U;

    } else {

        limit =
            (unsigned int)max_bits;
    }

    for (bit = 0;
         bit < limit;
         bit++) {

        if ((mask &
             (1ULL << bit)) == 0) {

            continue;
        }

        print_capability_name(
            bit,
            indent
        );
    }
}

static void render_capabilities_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff
)
{
    size_t i;

    printf("\nCapabilities\n");

    if (a->proc_status.status != COLLECT_OK ||
        b->proc_status.status != COLLECT_OK) {

        printf(
            "  unavailable (A: %s, B: %s)\n",
            collect_status_string(
                a->proc_status.status
            ),
            collect_status_string(
                b->proc_status.status
            )
        );

        return;
    }

    /*
     * Capability authority is scoped by user namespaces.
     */
    for (i = 0;
         i < NSDIFF_NAMESPACE_COUNT;
         i++) {

        if (strcmp(
                a->namespaces[i].name,
                "user"
            ) != 0) {

            continue;
        }

        if (a->namespaces[i].status == COLLECT_OK &&
            b->namespaces[i].status == COLLECT_OK &&
            (a->namespaces[i].dev !=
                 b->namespaces[i].dev ||
             a->namespaces[i].ino !=
                 b->namespaces[i].ino)) {

            printf(
                "  note: different user namespaces; "
                "capability authority is namespace-scoped\n"
            );
        }

        break;
    }

    for (i = 0;
         i < NSDIFF_CAPSET_COUNT;
         i++) {

        const struct capability_set_info *set_a =
            &a->proc_status.capabilities[i];

        const struct capability_set_info *set_b =
            &b->proc_status.capabilities[i];

        unsigned long long only_a;
        unsigned long long only_b;

        printf(
            "  %-13s ",
            capability_set_name(
                set_a->kind
            )
        );

        switch (diff->capabilities[i].state) {

        case NSDIFF_DIFF_UNAVAILABLE:

            printf(
                "unavailable [A: %s | B: %s]\n",
                set_a->present
                    ? "available"
                    : "missing",
                set_b->present
                    ? "available"
                    : "missing"
            );

            break;

        case NSDIFF_DIFF_SAME:

            if (set_a->mask == 0) {

                printf(
                    "same [none]\n"
                );

            } else {

                printf(
                    "same [%u capabilities]\n",
                    capability_count(
                        set_a->mask
                    )
                );
            }

            break;

        case NSDIFF_DIFF_DIFFERENT:

            printf(
                "different\n"
            );

            only_a =
                set_a->mask &
                ~set_b->mask;

            only_b =
                set_b->mask &
                ~set_a->mask;

            printf(
                "    only in A:\n"
            );

            print_capability_mask(
                only_a,
                "      "
            );

            printf(
                "    only in B:\n"
            );

            print_capability_mask(
                only_b,
                "      "
            );

            break;
        }
    }
}

static void print_mount_flags(
    const struct mount_point_info *mount
)
{
    printf(
        "%s",
        mount->read_only
            ? "ro"
            : "rw"
    );

    if (mount->nosuid) {
        printf(",nosuid");
    }

    if (mount->nodev) {
        printf(",nodev");
    }

    if (mount->noexec) {
        printf(",noexec");
    }
}


static void print_mount_description(
    const char *prefix,
    const struct mount_point_info *mount
)
{
    printf(
        "%s%s source=%s root=%s flags=",
        prefix,
        mount->fstype,
        mount->source[0] != '\0'
            ? mount->source
            : "none",
        mount->root[0] != '\0'
            ? mount->root
            : "/"
    );

    print_mount_flags(mount);

    printf("\n");
}

static void render_mounts_diff(
    const struct mounts_info *a,
    const struct mounts_info *b,
    const struct process_diff *diff
)
{
    size_t i;

    printf("\nMounts\n");

    if (diff->mount_count.state ==
        NSDIFF_DIFF_SAME) {

        printf(
            "  total mounts     same [%d]\n",
            a->total_mounts
        );

    } else if (diff->mount_count.state ==
               NSDIFF_DIFF_DIFFERENT) {

        printf(
            "  total mounts     different "
            "[A %d | B %d]\n",
            a->total_mounts,
            b->total_mounts
        );

    } else {

        printf(
            "  total mounts     unavailable\n"
        );
    }

    for (i = 0;
         i < NSDIFF_WATCHED_MOUNT_COUNT;
         i++) {

        const struct mount_point_info *mount_a =
            &a->entries[i];

        const struct mount_point_info *mount_b =
            &b->entries[i];

        printf(
            "  %-16s ",
            mount_a->target
        );

        switch (diff->mounts[i].state) {

        case NSDIFF_DIFF_UNAVAILABLE:

            printf(
                "unavailable "
                "[A: %s | B: %s]\n",
                collect_status_string(
                    mount_a->status
                ),
                collect_status_string(
                    mount_b->status
                )
            );

            break;

        case NSDIFF_DIFF_SAME:

            if (!mount_a->mounted &&
                !mount_b->mounted) {

                printf(
                    "same [not a separate mount]\n"
                );

            } else {

                printf("same [");

                printf(
                    "%s ",
                    mount_a->fstype
                );

                print_mount_flags(
                    mount_a
                );

                printf("]\n");
            }

            break;

        case NSDIFF_DIFF_DIFFERENT:

            printf("different\n");

            if (mount_a->mounted) {

                print_mount_description(
                    "    A: ",
                    mount_a
                );

            } else {

                printf(
                    "    A: not a separate mount\n"
                );
            }

            if (mount_b->mounted) {

                print_mount_description(
                    "    B: ",
                    mount_b
                );

            } else {

                printf(
                    "    B: not a separate mount\n"
                );
            }

            break;
        }
    }
}

static void format_bytes(
    unsigned long long bytes,
    char *buffer,
    size_t buffer_size
)
{
    const unsigned long long kib =
        1024ULL;

    const unsigned long long mib =
        1024ULL * 1024ULL;

    const unsigned long long gib =
        1024ULL * 1024ULL * 1024ULL;

    if (bytes >= gib) {

        snprintf(
            buffer,
            buffer_size,
            "%.2f GiB",
            (double)bytes /
                (double)gib
        );

    } else if (bytes >= mib) {

        snprintf(
            buffer,
            buffer_size,
            "%.2f MiB",
            (double)bytes /
                (double)mib
        );

    } else if (bytes >= kib) {

        snprintf(
            buffer,
            buffer_size,
            "%.2f KiB",
            (double)bytes /
                (double)kib
        );

    } else {

        snprintf(
            buffer,
            buffer_size,
            "%llu bytes",
            bytes
        );
    }
}

static void render_shm_diff(
    const struct shared_memory_info *a,
    const struct shared_memory_info *b,
    const struct process_diff *diff
)
{
    char size_a[64];
    char size_b[64];

    printf("\nShared memory\n");

    format_bytes(
        a->size_bytes,
        size_a,
        sizeof(size_a)
    );

    format_bytes(
        b->size_bytes,
        size_b,
        sizeof(size_b)
    );

    switch (diff->shm_size.state) {

    case NSDIFF_DIFF_UNAVAILABLE:

        printf(
            "  /dev/shm size    unavailable "
            "[A: %s | B: %s]\n",
            collect_status_string(
                a->status
            ),
            collect_status_string(
                b->status
            )
        );

        break;

    case NSDIFF_DIFF_SAME:

        printf(
            "  /dev/shm size    same [%s]\n",
            size_a
        );

        break;

    case NSDIFF_DIFF_DIFFERENT:

        printf(
            "  /dev/shm size    different\n"
            "    A: %s (%llu bytes)\n"
            "    B: %s (%llu bytes)\n",
            size_a,
            a->size_bytes,
            size_b,
            b->size_bytes
        );

        break;
    }
}

void render_text_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
	const struct process_diff *diff
)
{
    size_t i;

	printf(
		"nsdiff %s\n",
		NSDIFF_VERSION
	);

    printf(
        "A: PID %ld\n",
        (long)a->pid
    );

    printf(
        "B: PID %ld\n",
        (long)b->pid
    );

    /*
     * Namespaces
     */

    printf("\nNamespaces\n");

    for (i = 0;
         i < NSDIFF_NAMESPACE_COUNT;
         i++) {

        const struct namespace_info *ns_a =
            &a->namespaces[i];

        const struct namespace_info *ns_b =
            &b->namespaces[i];

        printf(
            "  %-8s ",
            ns_a->name
        );

		switch (diff->namespaces[i].state) {

		case NSDIFF_DIFF_UNAVAILABLE:

			printf(
				"unavailable (A: %s, B: %s)\n",
				collect_status_string(
					ns_a->status
				),
				collect_status_string(
					ns_b->status
				)
			);

			break;

		case NSDIFF_DIFF_SAME:

			printf("same\n");

			break;

		case NSDIFF_DIFF_DIFFERENT:

			printf(
				"different  [A %s | B %s]\n",
				ns_a->target,
				ns_b->target
			);

			break;
		}
    }

    /*
     * Credentials
     */

    printf("\nCredentials\n");

	if (diff->euid.state ==
		NSDIFF_DIFF_SAME) {

		printf(
			"  euid     same  [A %lu | B %lu]\n",
			a->proc_status.uid[1],
			b->proc_status.uid[1]
		);

	} else if (diff->euid.state ==
			   NSDIFF_DIFF_DIFFERENT) {

		printf(
			"  euid     different  [A %lu | B %lu]\n",
			a->proc_status.uid[1],
			b->proc_status.uid[1]
		);

	} else {

		printf(
			"  euid     unavailable\n"
		);
	}

	if (diff->egid.state ==
		NSDIFF_DIFF_SAME) {

		printf(
			"  egid     same  [A %lu | B %lu]\n",
			a->proc_status.gid[1],
			b->proc_status.gid[1]
		);

	} else if (diff->egid.state ==
			   NSDIFF_DIFF_DIFFERENT) {

		printf(
			"  egid     different  [A %lu | B %lu]\n",
			a->proc_status.gid[1],
			b->proc_status.gid[1]
		);

	} else {

		printf(
			"  egid     unavailable\n"
		);
	}

    /*
     * Resource limits
     */

    printf("\nResource limits\n");

    if (a->limits.status != COLLECT_OK ||
        b->limits.status != COLLECT_OK) {

        printf(
            "  unavailable (A: %s, B: %s)\n",
            collect_status_string(
                a->limits.status
            ),
            collect_status_string(
                b->limits.status
            )
        );

    } else {

        for (i = 0;
             i < NSDIFF_LIMIT_COUNT;
             i++) {

            const struct resource_limit_info *limit_a =
                &a->limits.entries[i];

            const struct resource_limit_info *limit_b =
                &b->limits.entries[i];

            char soft_a[32];
            char soft_b[32];

            char hard_a[32];
            char hard_b[32];

            printf(
                "  %-16s ",
                limit_name(limit_a->kind)
            );

            if (diff->limits[i].state == NSDIFF_DIFF_UNAVAILABLE) {
                printf(
                    "unavailable (A: %s, B: %s)\n",
                    collect_status_string(
                        limit_a->status
                    ),
                    collect_status_string(
                        limit_b->status
                    )
                );

                continue;
            }

            format_limit_value(
                &limit_a->soft,
                soft_a,
                sizeof(soft_a)
            );

            format_limit_value(
                &limit_b->soft,
                soft_b,
                sizeof(soft_b)
            );

            format_limit_value(
                &limit_a->hard,
                hard_a,
                sizeof(hard_a)
            );

            format_limit_value(
                &limit_b->hard,
                hard_b,
                sizeof(hard_b)
            );

            if (diff->limits[i].state == NSDIFF_DIFF_SAME) {
                printf(
                    "same [soft %s | hard %s",
                    soft_a,
                    hard_a
                );

                if (limit_a->units[0] != '\0') {
                    printf(
                        " | %s",
                        limit_a->units
                    );
                }

                printf("]\n");

            } else {

                printf("different\n");

                printf(
                    "    soft  A: %-12s B: %s\n",
                    soft_a,
                    soft_b
                );

                printf(
                    "    hard  A: %-12s B: %s\n",
                    hard_a,
                    hard_b
                );

                if (limit_a->units[0] != '\0' ||
                    limit_b->units[0] != '\0') {

                    printf(
                        "    units A: %-12s B: %s\n",
                        limit_a->units,
                        limit_b->units
                    );
                }
            }
        }
    }

	render_cgroup_diff(
		&a->cgroup,
		&b->cgroup,
		diff
	);

	render_network_diff(
		&a->network,
		&b->network,
		diff
	);

	render_mounts_diff(
		&a->mounts,
		&b->mounts,
		diff
	);

	render_shm_diff(
		&a->mounts.shm,
		&b->mounts.shm,
		diff
	);

	render_environment_diff(
		&a->environment,
		&b->environment,
		diff
	);

	render_capabilities_diff(
		a,
		b,
		diff
	);

    /*
     * Security
     */

    printf("\nSecurity\n");

	if (diff->no_new_privs.state ==
		NSDIFF_DIFF_SAME) {

		printf(
			"  NNP      same  [A %d | B %d]\n",
			a->proc_status.no_new_privs,
			b->proc_status.no_new_privs
		);

	} else if (diff->no_new_privs.state ==
			   NSDIFF_DIFF_DIFFERENT) {

		printf(
			"  NNP      different  [A %d | B %d]\n",
			a->proc_status.no_new_privs,
			b->proc_status.no_new_privs
		);

	} else {

		printf(
			"  NNP      unavailable\n"
		);
	}

	if (diff->seccomp.state ==
		NSDIFF_DIFF_SAME) {

		printf(
			"  seccomp  same  [A %s | B %s]\n",
			seccomp_name(
				a->proc_status.seccomp
			),
			seccomp_name(
				b->proc_status.seccomp
			)
		);

	} else if (diff->seccomp.state ==
			   NSDIFF_DIFF_DIFFERENT) {

		printf(
			"  seccomp  different  [A %s | B %s]\n",
			seccomp_name(
				a->proc_status.seccomp
			),
			seccomp_name(
				b->proc_status.seccomp
			)
		);

	} else {

		printf(
			"  seccomp  unavailable\n"
		);
	}

	printf("\nSummary\n");

	printf(
		"  %u comparable field%s checked\n",
		diff->comparable_fields,
		diff->comparable_fields == 1U
			? ""
			: "s"
	);

	printf(
		"  %u difference%s found\n",
		diff->differences,
		diff->differences == 1U
			? ""
			: "s"
	);
}
