/* Field descriptors enumerate semantic members; offsets are local accessors only.
 * No offset, sizeof value, padding or native endian bytes enter portable output. */

static const struct member limit_value_members[] = {
    {"unlimited", offsetof(struct limit_value, unlimited), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"value", offsetof(struct limit_value, value), T_ULL, sizeof(unsigned long long), 1, NULL, false, false},
    {0}
};

static const struct member resource_limit_info_members[] = {
    {"kind", offsetof(struct resource_limit_info, kind), T_LIMIT, sizeof(enum nsdiff_limit_kind), 1, NULL, false, false},
    {"status", offsetof(struct resource_limit_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"soft", offsetof(struct resource_limit_info, soft), T_OBJECT, sizeof(struct limit_value), 1, limit_value_members, false, false},
    {"hard", offsetof(struct resource_limit_info, hard), T_OBJECT, sizeof(struct limit_value), 1, limit_value_members, false, false},
    {"units", offsetof(struct resource_limit_info, units), T_BYTES, NSDIFF_LIMIT_UNIT_LEN, 1, NULL, false, false},
    {0}
};

static const struct member limits_info_members[] = {
    {"status", offsetof(struct limits_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"entries", offsetof(struct limits_info, entries), T_OBJECT, sizeof(struct resource_limit_info), NSDIFF_LIMIT_COUNT, resource_limit_info_members, true, false},
    {0}
};

static const struct member namespace_info_members[] = {
    {"name", offsetof(struct namespace_info, name), T_BYTES, NSDIFF_NS_NAME_LEN, 1, NULL, false, false},
    {"status", offsetof(struct namespace_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"dev", offsetof(struct namespace_info, dev), T_DEV, sizeof(dev_t), 1, NULL, false, false},
    {"ino", offsetof(struct namespace_info, ino), T_INO, sizeof(ino_t), 1, NULL, false, false},
    {"target", offsetof(struct namespace_info, target), T_BYTES, NSDIFF_NS_TARGET_LEN, 1, NULL, false, false},
    {0}
};

static const struct member capability_set_info_members[] = {
    {"kind", offsetof(struct capability_set_info, kind), T_CAP, sizeof(enum nsdiff_capset_kind), 1, NULL, false, false},
    {"present", offsetof(struct capability_set_info, present), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"mask", offsetof(struct capability_set_info, mask), T_ULL, sizeof(unsigned long long), 1, NULL, false, false},
    {0}
};

static const struct member proc_status_info_members[] = {
    {"status", offsetof(struct proc_status_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"have_uid", offsetof(struct proc_status_info, have_uid), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"uid", offsetof(struct proc_status_info, uid), T_ULONG, sizeof(unsigned long), 4, NULL, true, false},
    {"have_gid", offsetof(struct proc_status_info, have_gid), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"gid", offsetof(struct proc_status_info, gid), T_ULONG, sizeof(unsigned long), 4, NULL, true, false},
    {"capabilities", offsetof(struct proc_status_info, capabilities), T_OBJECT, sizeof(struct capability_set_info), NSDIFF_CAPSET_COUNT, capability_set_info_members, true, false},
    {"have_no_new_privs", offsetof(struct proc_status_info, have_no_new_privs), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"no_new_privs", offsetof(struct proc_status_info, no_new_privs), T_INT, sizeof(int), 1, NULL, false, false},
    {"have_seccomp", offsetof(struct proc_status_info, have_seccomp), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"seccomp", offsetof(struct proc_status_info, seccomp), T_INT, sizeof(int), 1, NULL, false, false},
    {0}
};

static const struct member cgroup_file_info_members[] = {
    {"name", offsetof(struct cgroup_file_info, name), T_BYTES, NSDIFF_CGROUP_NAME_LEN, 1, NULL, false, false},
    {"status", offsetof(struct cgroup_file_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"value", offsetof(struct cgroup_file_info, value), T_BYTES, NSDIFF_CGROUP_VALUE_LEN, 1, NULL, false, false},
    {0}
};

static const struct member cgroup_info_members[] = {
    {"status", offsetof(struct cgroup_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"v2", offsetof(struct cgroup_info, v2), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"path", offsetof(struct cgroup_info, path), T_BYTES, NSDIFF_CGROUP_PATH_LEN, 1, NULL, false, false},
    {"files", offsetof(struct cgroup_info, files), T_OBJECT, sizeof(struct cgroup_file_info), NSDIFF_CGROUP_FILE_COUNT, cgroup_file_info_members, true, false},
    {0}
};

static const struct member mount_point_info_members[] = {
    {"status", offsetof(struct mount_point_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"mounted", offsetof(struct mount_point_info, mounted), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"mount_id", offsetof(struct mount_point_info, mount_id), T_INT, sizeof(int), 1, NULL, false, false},
    {"target", offsetof(struct mount_point_info, target), T_BYTES, NSDIFF_MOUNT_TARGET_LEN, 1, NULL, false, false},
    {"root", offsetof(struct mount_point_info, root), T_BYTES, NSDIFF_MOUNT_ROOT_LEN, 1, NULL, false, false},
    {"fstype", offsetof(struct mount_point_info, fstype), T_BYTES, NSDIFF_MOUNT_FSTYPE_LEN, 1, NULL, false, false},
    {"source", offsetof(struct mount_point_info, source), T_BYTES, NSDIFF_MOUNT_SOURCE_LEN, 1, NULL, false, false},
    {"read_only", offsetof(struct mount_point_info, read_only), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"nosuid", offsetof(struct mount_point_info, nosuid), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"nodev", offsetof(struct mount_point_info, nodev), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"noexec", offsetof(struct mount_point_info, noexec), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {0}
};

static const struct member shared_memory_info_members[] = {
    {"status", offsetof(struct shared_memory_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"size_bytes", offsetof(struct shared_memory_info, size_bytes), T_ULL, sizeof(unsigned long long), 1, NULL, false, false},
    {0}
};

static const struct member mounts_info_members[] = {
    {"status", offsetof(struct mounts_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"total_mounts", offsetof(struct mounts_info, total_mounts), T_INT, sizeof(int), 1, NULL, false, false},
    {"entries", offsetof(struct mounts_info, entries), T_OBJECT, sizeof(struct mount_point_info), NSDIFF_WATCHED_MOUNT_COUNT, mount_point_info_members, true, false},
    {"shm", offsetof(struct mounts_info, shm), T_OBJECT, sizeof(struct shared_memory_info), 1, shared_memory_info_members, false, false},
    {0}
};

static const struct member environment_entry_info_members[] = {
    {"status", offsetof(struct environment_entry_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"name", offsetof(struct environment_entry_info, name), T_BYTES, NSDIFF_ENV_NAME_LEN, 1, NULL, false, false},
    {"present", offsetof(struct environment_entry_info, present), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"redact_value", offsetof(struct environment_entry_info, redact_value), T_BOOL, sizeof(bool), 1, NULL, false, false},
    {"value", offsetof(struct environment_entry_info, value), T_BYTES, NSDIFF_ENV_VALUE_LEN, 1, NULL, false, false},
    {0}
};

static const struct member environment_info_members[] = {
    {"status", offsetof(struct environment_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"total_entries", offsetof(struct environment_info, total_entries), T_UINT, sizeof(unsigned int), 1, NULL, false, false},
    {"entries", offsetof(struct environment_info, entries), T_OBJECT, sizeof(struct environment_entry_info), NSDIFF_ENV_WATCH_COUNT, environment_entry_info_members, true, false},
    {0}
};

static const struct member network_set_info_members[] = {
    {"status", offsetof(struct network_set_info, status), T_STATUS, sizeof(enum collect_status), 1, NULL, false, false},
    {"count", offsetof(struct network_set_info, count), T_UINT, sizeof(unsigned int), 1, NULL, false, false},
    {"items", offsetof(struct network_set_info, items), T_BYTES, NSDIFF_NET_ITEM_LEN, NSDIFF_NET_SET_MAX, NULL, true, true},
    {0}
};

static const struct member network_info_members[] = {
    {"interfaces", offsetof(struct network_info, interfaces), T_OBJECT, sizeof(struct network_set_info), 1, network_set_info_members, false, false},
    {"ipv4_default_routes", offsetof(struct network_info, ipv4_default_routes), T_OBJECT, sizeof(struct network_set_info), 1, network_set_info_members, false, false},
    {"ipv6_addresses", offsetof(struct network_info, ipv6_addresses), T_OBJECT, sizeof(struct network_set_info), 1, network_set_info_members, false, false},
    {"ipv6_default_routes", offsetof(struct network_info, ipv6_default_routes), T_OBJECT, sizeof(struct network_set_info), 1, network_set_info_members, false, false},
    {0}
};

static const struct member process_snapshot_members[] = {
    {"pid", offsetof(struct process_snapshot, pid), T_PID, sizeof(pid_t), 1, NULL, false, false},
    {"starttime_ticks", offsetof(struct process_snapshot, starttime_ticks), T_ULL, sizeof(unsigned long long), 1, NULL, false, false},
    {"namespaces", offsetof(struct process_snapshot, namespaces), T_OBJECT, sizeof(struct namespace_info), NSDIFF_NAMESPACE_COUNT, namespace_info_members, true, false},
    {"proc_status", offsetof(struct process_snapshot, proc_status), T_OBJECT, sizeof(struct proc_status_info), 1, proc_status_info_members, false, false},
    {"limits", offsetof(struct process_snapshot, limits), T_OBJECT, sizeof(struct limits_info), 1, limits_info_members, false, false},
    {"cgroup", offsetof(struct process_snapshot, cgroup), T_OBJECT, sizeof(struct cgroup_info), 1, cgroup_info_members, false, false},
    {"mounts", offsetof(struct process_snapshot, mounts), T_OBJECT, sizeof(struct mounts_info), 1, mounts_info_members, false, false},
    {"environment", offsetof(struct process_snapshot, environment), T_OBJECT, sizeof(struct environment_info), 1, environment_info_members, false, false},
    {"network", offsetof(struct process_snapshot, network), T_OBJECT, sizeof(struct network_info), 1, network_info_members, false, false},
    {0}
};
