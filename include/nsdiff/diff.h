#ifndef NSDIFF_DIFF_H
#define NSDIFF_DIFF_H

#include "nsdiff/snapshot.h"


enum nsdiff_diff_state {
    NSDIFF_DIFF_UNAVAILABLE = 0,
    NSDIFF_DIFF_SAME,
    NSDIFF_DIFF_DIFFERENT,
};


struct field_diff {
    enum nsdiff_diff_state state;
};


struct process_diff {
    unsigned int comparable_fields;
    unsigned int differences;

    struct field_diff namespaces[
        NSDIFF_NAMESPACE_COUNT
    ];

    struct field_diff euid;
    struct field_diff egid;

    struct field_diff limits[
        NSDIFF_LIMIT_COUNT
    ];

    struct field_diff cgroup_path;

    struct field_diff cgroup_files[
        NSDIFF_CGROUP_FILE_COUNT
    ];

    struct field_diff network_interfaces;

    struct field_diff network_ipv4_default_routes;

    struct field_diff network_ipv6_addresses;

    struct field_diff network_ipv6_default_routes;

    struct field_diff mount_count;

    struct field_diff mounts[
        NSDIFF_WATCHED_MOUNT_COUNT
    ];

    struct field_diff shm_size;

    struct field_diff environment_count;

    struct field_diff environment[
        NSDIFF_ENV_WATCH_COUNT
    ];

    struct field_diff capabilities[
        NSDIFF_CAPSET_COUNT
    ];

    struct field_diff no_new_privs;
    struct field_diff seccomp;
};


void process_diff_build(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    struct process_diff *diff
);


#endif
