#include <stddef.h>
#include <string.h>

#include "nsdiff/scope.h"


int nsdiff_section_parse(
    const char *name,
    nsdiff_section_mask *section_out
)
{
    if (strcmp(
            name,
            "namespaces"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_NAMESPACES;

        return 0;
    }

    if (strcmp(
            name,
            "credentials"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_CREDENTIALS;

        return 0;
    }

    if (strcmp(
            name,
            "limits"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_LIMITS;

        return 0;
    }

    if (strcmp(
            name,
            "cgroup"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_CGROUP;

        return 0;
    }

    if (strcmp(
            name,
            "network"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_NETWORK;

        return 0;
    }

    if (strcmp(
            name,
            "mounts"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_MOUNTS;

        return 0;
    }

    if (strcmp(
            name,
            "environment"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_ENVIRONMENT;

        return 0;
    }

    if (strcmp(
            name,
            "security"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_SECURITY;

        return 0;
    }

    if (strcmp(
            name,
            "all"
        ) == 0) {

        *section_out =
            NSDIFF_SECTION_ALL;

        return 0;
    }

    return -1;
}


bool nsdiff_section_enabled(
    nsdiff_section_mask mask,
    nsdiff_section_mask section
)
{
    return (mask & section) != 0U;
}


static void copy_field(
    struct process_diff *target,
    struct field_diff *target_field,
    const struct field_diff *source_field
)
{
    target_field->state =
        source_field->state;

    if (source_field->state ==
        NSDIFF_DIFF_UNAVAILABLE) {

        return;
    }

    target->comparable_fields++;

    if (source_field->state ==
        NSDIFF_DIFF_DIFFERENT) {

        target->differences++;
    }
}


void process_diff_apply_scope(
    const struct process_diff *source,
    nsdiff_section_mask mask,
    struct process_diff *target
)
{
    size_t i;

    memset(
        target,
        0,
        sizeof(*target)
    );

    /*
     * Zero is NSDIFF_DIFF_UNAVAILABLE, so fields that
     * are outside the selected scope remain ignored by
     * compact renderers and by the scoped totals.
     */

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NAMESPACES
        )) {

        for (i = 0;
             i < NSDIFF_NAMESPACE_COUNT;
             i++) {

            copy_field(
                target,
                &target->namespaces[i],
                &source->namespaces[i]
            );
        }
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CREDENTIALS
        )) {

        copy_field(
            target,
            &target->euid,
            &source->euid
        );

        copy_field(
            target,
            &target->egid,
            &source->egid
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_LIMITS
        )) {

        for (i = 0;
             i < NSDIFF_LIMIT_COUNT;
             i++) {

            copy_field(
                target,
                &target->limits[i],
                &source->limits[i]
            );
        }
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CGROUP
        )) {

        copy_field(
            target,
            &target->cgroup_path,
            &source->cgroup_path
        );

        for (i = 0;
             i < NSDIFF_CGROUP_FILE_COUNT;
             i++) {

            copy_field(
                target,
                &target->cgroup_files[i],
                &source->cgroup_files[i]
            );
        }
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NETWORK
        )) {

        copy_field(
            target,
            &target->network_interfaces,
            &source->network_interfaces
        );

        copy_field(
            target,
            &target->network_ipv4_default_routes,
            &source->network_ipv4_default_routes
        );

        copy_field(
            target,
            &target->network_ipv6_addresses,
            &source->network_ipv6_addresses
        );

        copy_field(
            target,
            &target->network_ipv6_default_routes,
            &source->network_ipv6_default_routes
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_MOUNTS
        )) {

        copy_field(
            target,
            &target->mount_count,
            &source->mount_count
        );

        for (i = 0;
             i < NSDIFF_WATCHED_MOUNT_COUNT;
             i++) {

            copy_field(
                target,
                &target->mounts[i],
                &source->mounts[i]
            );
        }

        copy_field(
            target,
            &target->shm_size,
            &source->shm_size
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_ENVIRONMENT
        )) {

        copy_field(
            target,
            &target->environment_count,
            &source->environment_count
        );

        for (i = 0;
             i < NSDIFF_ENV_WATCH_COUNT;
             i++) {

            copy_field(
                target,
                &target->environment[i],
                &source->environment[i]
            );
        }
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_SECURITY
        )) {

        for (i = 0;
             i < NSDIFF_CAPSET_COUNT;
             i++) {

            copy_field(
                target,
                &target->capabilities[i],
                &source->capabilities[i]
            );
        }

        copy_field(
            target,
            &target->no_new_privs,
            &source->no_new_privs
        );

        copy_field(
            target,
            &target->seccomp,
            &source->seccomp
        );
    }
}
