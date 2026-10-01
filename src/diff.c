#include <stdbool.h>
#include <string.h>

#include "nsdiff/diff.h"


static void record_state(
    struct process_diff *diff,
    struct field_diff *field,
    enum nsdiff_diff_state state
)
{
    field->state = state;

    if (state ==
        NSDIFF_DIFF_UNAVAILABLE) {

        return;
    }

    diff->comparable_fields++;

    if (state ==
        NSDIFF_DIFF_DIFFERENT) {

        diff->differences++;
    }
}


static enum nsdiff_diff_state compare_bool(
    bool comparable,
    bool equal
)
{
    if (!comparable) {
        return NSDIFF_DIFF_UNAVAILABLE;
    }

    return equal
        ? NSDIFF_DIFF_SAME
        : NSDIFF_DIFF_DIFFERENT;
}


static bool limit_value_equal(
    const struct limit_value *a,
    const struct limit_value *b
)
{
    if (a->unlimited !=
        b->unlimited) {

        return false;
    }

    if (a->unlimited) {
        return true;
    }

    return a->value ==
           b->value;
}


static bool resource_limit_equal(
    const struct resource_limit_info *a,
    const struct resource_limit_info *b
)
{
    return
        limit_value_equal(
            &a->soft,
            &b->soft
        ) &&
        limit_value_equal(
            &a->hard,
            &b->hard
        ) &&
        strcmp(
            a->units,
            b->units
        ) == 0;
}


static bool mount_equal(
    const struct mount_point_info *a,
    const struct mount_point_info *b
)
{
    if (a->mounted !=
        b->mounted) {

        return false;
    }

    if (!a->mounted) {
        return true;
    }

    return
        strcmp(
            a->root,
            b->root
        ) == 0 &&
        strcmp(
            a->fstype,
            b->fstype
        ) == 0 &&
        strcmp(
            a->source,
            b->source
        ) == 0 &&
        a->read_only ==
            b->read_only &&
        a->nosuid ==
            b->nosuid &&
        a->nodev ==
            b->nodev &&
        a->noexec ==
            b->noexec;
}


static bool network_set_equal(
    const struct network_set_info *a,
    const struct network_set_info *b
)
{
    size_t i;

    if (a->count !=
        b->count) {

        return false;
    }

    for (i = 0;
         i < a->count;
         i++) {

        if (strcmp(
                a->items[i],
                b->items[i]
            ) != 0) {

            return false;
        }
    }

    return true;
}


static void build_network_diff(
    const struct network_info *a,
    const struct network_info *b,
    struct process_diff *diff
)
{
    bool comparable;

    comparable =
        a->interfaces.status ==
            COLLECT_OK &&
        b->interfaces.status ==
            COLLECT_OK;

    record_state(
        diff,
        &diff->network_interfaces,
        compare_bool(
            comparable,
            comparable &&
                network_set_equal(
                    &a->interfaces,
                    &b->interfaces
                )
        )
    );

    comparable =
        a->ipv4_default_routes.status ==
            COLLECT_OK &&
        b->ipv4_default_routes.status ==
            COLLECT_OK;

    record_state(
        diff,
        &diff->network_ipv4_default_routes,
        compare_bool(
            comparable,
            comparable &&
                network_set_equal(
                    &a->ipv4_default_routes,
                    &b->ipv4_default_routes
                )
        )
    );

    comparable =
        a->ipv6_addresses.status ==
            COLLECT_OK &&
        b->ipv6_addresses.status ==
            COLLECT_OK;

    record_state(
        diff,
        &diff->network_ipv6_addresses,
        compare_bool(
            comparable,
            comparable &&
                network_set_equal(
                    &a->ipv6_addresses,
                    &b->ipv6_addresses
                )
        )
    );

    comparable =
        a->ipv6_default_routes.status ==
            COLLECT_OK &&
        b->ipv6_default_routes.status ==
            COLLECT_OK;

    record_state(
        diff,
        &diff->network_ipv6_default_routes,
        compare_bool(
            comparable,
            comparable &&
                network_set_equal(
                    &a->ipv6_default_routes,
                    &b->ipv6_default_routes
                )
        )
    );
}


void process_diff_build(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    struct process_diff *diff
)
{
    size_t i;

    bool proc_status_ok;

    memset(
        diff,
        0,
        sizeof(*diff)
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

        bool comparable =
            ns_a->status == COLLECT_OK &&
            ns_b->status == COLLECT_OK;

        bool equal =
            comparable &&
            ns_a->dev == ns_b->dev &&
            ns_a->ino == ns_b->ino;

        record_state(
            diff,
            &diff->namespaces[i],
            compare_bool(
                comparable,
                equal
            )
        );
    }

    /*
     * proc/status-backed fields.
     */

    proc_status_ok =
        a->proc_status.status == COLLECT_OK &&
        b->proc_status.status == COLLECT_OK;

    record_state(
        diff,
        &diff->euid,
        compare_bool(
            proc_status_ok &&
                a->proc_status.have_uid &&
                b->proc_status.have_uid,
            a->proc_status.uid[1] ==
                b->proc_status.uid[1]
        )
    );

    record_state(
        diff,
        &diff->egid,
        compare_bool(
            proc_status_ok &&
                a->proc_status.have_gid &&
                b->proc_status.have_gid,
            a->proc_status.gid[1] ==
                b->proc_status.gid[1]
        )
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

        bool comparable =
            a->limits.status == COLLECT_OK &&
            b->limits.status == COLLECT_OK &&
            limit_a->status == COLLECT_OK &&
            limit_b->status == COLLECT_OK;

        record_state(
            diff,
            &diff->limits[i],
            compare_bool(
                comparable,
                comparable &&
                    resource_limit_equal(
                        limit_a,
                        limit_b
                    )
            )
        );
    }

    /*
     * cgroup v2.
     */

    {
        bool cgroup_ok =
            a->cgroup.status == COLLECT_OK &&
            b->cgroup.status == COLLECT_OK;

        record_state(
            diff,
            &diff->cgroup_path,
            compare_bool(
                cgroup_ok,
                cgroup_ok &&
                    strcmp(
                        a->cgroup.path,
                        b->cgroup.path
                    ) == 0
            )
        );

        for (i = 0;
             i < NSDIFF_CGROUP_FILE_COUNT;
             i++) {

            const struct cgroup_file_info *entry_a =
                &a->cgroup.files[i];

            const struct cgroup_file_info *entry_b =
                &b->cgroup.files[i];

            bool comparable =
                cgroup_ok &&
                entry_a->status == COLLECT_OK &&
                entry_b->status == COLLECT_OK;

            record_state(
                diff,
                &diff->cgroup_files[i],
                compare_bool(
                    comparable,
                    comparable &&
                        strcmp(
                            entry_a->value,
                            entry_b->value
                        ) == 0
                )
            );
        }
    }

    /*
     * Network environment.
     */

    build_network_diff(
        &a->network,
        &b->network,
        diff
    );

    /*
     * Mount environment.
     */

    {
        bool mounts_ok =
            a->mounts.status == COLLECT_OK &&
            b->mounts.status == COLLECT_OK;

        record_state(
            diff,
            &diff->mount_count,
            compare_bool(
                mounts_ok,
                mounts_ok &&
                    a->mounts.total_mounts ==
                    b->mounts.total_mounts
            )
        );

        for (i = 0;
             i < NSDIFF_WATCHED_MOUNT_COUNT;
             i++) {

            const struct mount_point_info *mount_a =
                &a->mounts.entries[i];

            const struct mount_point_info *mount_b =
                &b->mounts.entries[i];

            bool comparable =
                mounts_ok &&
                mount_a->status == COLLECT_OK &&
                mount_b->status == COLLECT_OK;

            record_state(
                diff,
                &diff->mounts[i],
                compare_bool(
                    comparable,
                    comparable &&
                        mount_equal(
                            mount_a,
                            mount_b
                        )
                )
            );
        }
    }

    /*
     * /dev/shm capacity.
     */

    {
        bool comparable =
            a->mounts.shm.status ==
                COLLECT_OK &&
            b->mounts.shm.status ==
                COLLECT_OK;

        record_state(
            diff,
            &diff->shm_size,
            compare_bool(
                comparable,
                comparable &&
                    a->mounts.shm.size_bytes ==
                    b->mounts.shm.size_bytes
            )
        );
    }

    /*
     * Environment.
     */

    {
        bool environment_ok =
            a->environment.status ==
                COLLECT_OK &&
            b->environment.status ==
                COLLECT_OK;

        record_state(
            diff,
            &diff->environment_count,
            compare_bool(
                environment_ok,
                environment_ok &&
                    a->environment.total_entries ==
                    b->environment.total_entries
            )
        );

        for (i = 0;
             i < NSDIFF_ENV_WATCH_COUNT;
             i++) {

            const struct environment_entry_info *entry_a =
                &a->environment.entries[i];

            const struct environment_entry_info *entry_b =
                &b->environment.entries[i];

            bool comparable =
                environment_ok &&
                entry_a->status == COLLECT_OK &&
                entry_b->status == COLLECT_OK;

            bool equal = false;

            if (comparable) {

                if (entry_a->present !=
                    entry_b->present) {

                    equal = false;

                } else if (!entry_a->present) {

                    equal = true;

                } else {

                    equal =
                        strcmp(
                            entry_a->value,
                            entry_b->value
                        ) == 0;
                }
            }

            record_state(
                diff,
                &diff->environment[i],
                compare_bool(
                    comparable,
                    equal
                )
            );
        }
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

        bool comparable =
            proc_status_ok &&
            set_a->present &&
            set_b->present;

        record_state(
            diff,
            &diff->capabilities[i],
            compare_bool(
                comparable,
                comparable &&
                    set_a->mask ==
                    set_b->mask
            )
        );
    }

    /*
     * no_new_privs.
     */

    record_state(
        diff,
        &diff->no_new_privs,
        compare_bool(
            proc_status_ok &&
                a->proc_status.have_no_new_privs &&
                b->proc_status.have_no_new_privs,
            a->proc_status.no_new_privs ==
                b->proc_status.no_new_privs
        )
    );

    /*
     * seccomp.
     */

    record_state(
        diff,
        &diff->seccomp,
        compare_bool(
            proc_status_ok &&
                a->proc_status.have_seccomp &&
                b->proc_status.have_seccomp,
            a->proc_status.seccomp ==
                b->proc_status.seccomp
        )
    );
}
