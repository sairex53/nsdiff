#include <stddef.h>
#include <string.h>

#include "nsdiff/diff_summary.h"


static void add_field(
    struct diff_section_summary *section,
    const struct field_diff *field
)
{
    switch (field->state) {

    case NSDIFF_DIFF_UNAVAILABLE:

        section->unavailable_fields++;

        break;

    case NSDIFF_DIFF_SAME:

        section->comparable_fields++;

        break;

    case NSDIFF_DIFF_DIFFERENT:

        section->comparable_fields++;
        section->differences++;

        break;
    }
}


static void add_section_to_total(
    struct process_diff_summary *summary,
    const struct diff_section_summary *section
)
{
    summary->comparable_fields +=
        section->comparable_fields;

    summary->differences +=
        section->differences;

    summary->unavailable_fields +=
        section->unavailable_fields;
}


void process_diff_summary_build_scoped(
    const struct process_diff *diff,
    nsdiff_section_mask mask,
    struct process_diff_summary *summary
)
{
    size_t i;

    memset(
        summary,
        0,
        sizeof(*summary)
    );

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NAMESPACES
        )) {

        for (i = 0;
             i < NSDIFF_NAMESPACE_COUNT;
             i++) {

            add_field(
                &summary->namespaces,
                &diff->namespaces[i]
            );
        }

        add_section_to_total(
            summary,
            &summary->namespaces
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CREDENTIALS
        )) {

        add_field(
            &summary->credentials,
            &diff->euid
        );

        add_field(
            &summary->credentials,
            &diff->egid
        );

        add_section_to_total(
            summary,
            &summary->credentials
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_LIMITS
        )) {

        for (i = 0;
             i < NSDIFF_LIMIT_COUNT;
             i++) {

            add_field(
                &summary->limits,
                &diff->limits[i]
            );
        }

        add_section_to_total(
            summary,
            &summary->limits
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CGROUP
        )) {

        add_field(
            &summary->cgroup,
            &diff->cgroup_path
        );

        for (i = 0;
             i < NSDIFF_CGROUP_FILE_COUNT;
             i++) {

            add_field(
                &summary->cgroup,
                &diff->cgroup_files[i]
            );
        }

        add_section_to_total(
            summary,
            &summary->cgroup
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NETWORK
        )) {

        add_field(
            &summary->network,
            &diff->network_interfaces
        );

        add_field(
            &summary->network,
            &diff->network_ipv4_default_routes
        );

        add_field(
            &summary->network,
            &diff->network_ipv6_addresses
        );

        add_field(
            &summary->network,
            &diff->network_ipv6_default_routes
        );

        add_section_to_total(
            summary,
            &summary->network
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_MOUNTS
        )) {

        add_field(
            &summary->mounts,
            &diff->mount_count
        );

        for (i = 0;
             i < NSDIFF_WATCHED_MOUNT_COUNT;
             i++) {

            add_field(
                &summary->mounts,
                &diff->mounts[i]
            );
        }

        add_field(
            &summary->mounts,
            &diff->shm_size
        );

        add_section_to_total(
            summary,
            &summary->mounts
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_ENVIRONMENT
        )) {

        add_field(
            &summary->environment,
            &diff->environment_count
        );

        for (i = 0;
             i < NSDIFF_ENV_WATCH_COUNT;
             i++) {

            add_field(
                &summary->environment,
                &diff->environment[i]
            );
        }

        add_section_to_total(
            summary,
            &summary->environment
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_SECURITY
        )) {

        for (i = 0;
             i < NSDIFF_CAPSET_COUNT;
             i++) {

            add_field(
                &summary->security,
                &diff->capabilities[i]
            );
        }

        add_field(
            &summary->security,
            &diff->no_new_privs
        );

        add_field(
            &summary->security,
            &diff->seccomp
        );

        add_section_to_total(
            summary,
            &summary->security
        );
    }
}


void process_diff_summary_build(
    const struct process_diff *diff,
    struct process_diff_summary *summary
)
{
    process_diff_summary_build_scoped(
        diff,
        NSDIFF_SECTION_ALL,
        summary
    );
}
