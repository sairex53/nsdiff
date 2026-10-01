/* Frozen from v0.0.24, for compatibility fixtures only. Do not update with production model. */
#ifndef NSDIFF_SNAPSHOT_H
#define NSDIFF_SNAPSHOT_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NSDIFF_NAMESPACE_COUNT 8
#define NSDIFF_NS_NAME_LEN 16
#define NSDIFF_NS_TARGET_LEN 64
#define NSDIFF_LIMIT_COUNT 7
#define NSDIFF_LIMIT_UNIT_LEN 16
#define NSDIFF_CGROUP_FILE_COUNT 8
#define NSDIFF_CGROUP_PATH_LEN 4096
#define NSDIFF_CGROUP_NAME_LEN 32
#define NSDIFF_CGROUP_VALUE_LEN 128
#define NSDIFF_CAPSET_COUNT 5
#define NSDIFF_WATCHED_MOUNT_COUNT 7
#define NSDIFF_MOUNT_TARGET_LEN 64
#define NSDIFF_MOUNT_ROOT_LEN 256
#define NSDIFF_MOUNT_FSTYPE_LEN 64
#define NSDIFF_MOUNT_SOURCE_LEN 256
#define NSDIFF_ENV_WATCH_COUNT 33
#define NSDIFF_ENV_NAME_LEN 32
#define NSDIFF_ENV_VALUE_LEN 4096
#define NSDIFF_NET_SET_MAX 64
#define NSDIFF_NET_ITEM_LEN 192

enum collect_status {
    COLLECT_OK = 0,
    COLLECT_PERMISSION_DENIED,
    COLLECT_NOT_SUPPORTED,
    COLLECT_PROCESS_GONE,
    COLLECT_IO_ERROR,
    COLLECT_PARSE_ERROR,
};

enum nsdiff_limit_kind {
    NSDIFF_LIMIT_NOFILE = 0,
    NSDIFF_LIMIT_NPROC,
    NSDIFF_LIMIT_STACK,
    NSDIFF_LIMIT_MEMLOCK,
    NSDIFF_LIMIT_AS,
    NSDIFF_LIMIT_CORE,
    NSDIFF_LIMIT_FSIZE,
};

struct limit_value {
    bool unlimited;
    unsigned long long value;
};

struct resource_limit_info {
    enum nsdiff_limit_kind kind;

    enum collect_status status;

    struct limit_value soft;
    struct limit_value hard;

    char units[NSDIFF_LIMIT_UNIT_LEN];
};

struct limits_info {
    enum collect_status status;

    struct resource_limit_info entries[NSDIFF_LIMIT_COUNT];
};

struct namespace_info {
    char name[NSDIFF_NS_NAME_LEN];

    enum collect_status status;

    dev_t dev;
    ino_t ino;

    char target[NSDIFF_NS_TARGET_LEN];
};

enum nsdiff_capset_kind {
    NSDIFF_CAP_INHERITABLE = 0,
    NSDIFF_CAP_PERMITTED,
    NSDIFF_CAP_EFFECTIVE,
    NSDIFF_CAP_BOUNDING,
    NSDIFF_CAP_AMBIENT,
};

struct capability_set_info {
    enum nsdiff_capset_kind kind;

    bool present;

    unsigned long long mask;
};

struct proc_status_info {
    enum collect_status status;

    bool have_uid;
    unsigned long uid[4];

    bool have_gid;
    unsigned long gid[4];

	struct capability_set_info capabilities[
		NSDIFF_CAPSET_COUNT
	];

    bool have_no_new_privs;
    int no_new_privs;

    bool have_seccomp;
    int seccomp;
};

struct cgroup_file_info {
    char name[NSDIFF_CGROUP_NAME_LEN];

    enum collect_status status;

    char value[NSDIFF_CGROUP_VALUE_LEN];
};

struct cgroup_info {
    enum collect_status status;

    bool v2;

    char path[NSDIFF_CGROUP_PATH_LEN];

    struct cgroup_file_info files[
        NSDIFF_CGROUP_FILE_COUNT
    ];
};

struct mount_point_info {
    enum collect_status status;

    bool mounted;

    int mount_id;

    char target[NSDIFF_MOUNT_TARGET_LEN];
    char root[NSDIFF_MOUNT_ROOT_LEN];
    char fstype[NSDIFF_MOUNT_FSTYPE_LEN];
    char source[NSDIFF_MOUNT_SOURCE_LEN];

    bool read_only;
    bool nosuid;
    bool nodev;
    bool noexec;
};

struct shared_memory_info {
    enum collect_status status;

    unsigned long long size_bytes;
};

struct mounts_info {
    enum collect_status status;

    int total_mounts;

    struct mount_point_info entries[
        NSDIFF_WATCHED_MOUNT_COUNT
    ];

    struct shared_memory_info shm;
};

struct environment_entry_info {
    enum collect_status status;

    char name[NSDIFF_ENV_NAME_LEN];

    bool present;
    bool redact_value;

    char value[NSDIFF_ENV_VALUE_LEN];
};

struct environment_info {
    enum collect_status status;

    unsigned int total_entries;

    struct environment_entry_info entries[
        NSDIFF_ENV_WATCH_COUNT
    ];
};

struct network_set_info {
    enum collect_status status;

    unsigned int count;

    char items[
        NSDIFF_NET_SET_MAX
    ][
        NSDIFF_NET_ITEM_LEN
    ];
};

struct network_info {
    struct network_set_info interfaces;

    struct network_set_info ipv4_default_routes;

    struct network_set_info ipv6_addresses;

    struct network_set_info ipv6_default_routes;
};

struct process_snapshot {
    pid_t pid;

    int pidfd;

    unsigned long long starttime_ticks;

    struct namespace_info namespaces[NSDIFF_NAMESPACE_COUNT];

    struct proc_status_info proc_status;

    struct limits_info limits;

	struct cgroup_info cgroup;

	struct mounts_info mounts;

	struct environment_info environment;

	struct network_info network;
};

const char *collect_status_string(enum collect_status status);

#endif
