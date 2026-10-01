#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "frozen_native_v024.h"
static const char *const namespaces[] = {"mnt", "net", "pid", "user", "uts", "ipc", "cgroup", "time"};
static const char *const mounts[] = {"/", "/proc", "/sys", "/dev", "/dev/shm", "/tmp", "/run"};
static const char *const cgroups[] = {"memory.max", "memory.high", "memory.swap.max", "cpu.max", "cpu.weight", "pids.max", "cpuset.cpus.effective", "cpuset.mems.effective"};
static const char *const envs[] = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HOME", "SHELL", "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "JAVA_HOME", "GOMAXPROCS", "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"};
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "offsets")) {
        printf("{\"bool\":%zu,\"count\":%zu,\"status\":%zu,\"redact\":%zu,\"items\":%zu,\"item_size\":%zu}\n",
            offsetof(struct process_snapshot, proc_status)+offsetof(struct proc_status_info, have_uid),
            offsetof(struct process_snapshot, network)+offsetof(struct network_info, interfaces)+offsetof(struct network_set_info, count),
            offsetof(struct process_snapshot, proc_status)+offsetof(struct proc_status_info, status),
            offsetof(struct process_snapshot, environment)+offsetof(struct environment_info, entries)+25*sizeof(struct environment_entry_info)+offsetof(struct environment_entry_info, redact_value),
            offsetof(struct process_snapshot, network)+offsetof(struct network_info, interfaces)+offsetof(struct network_set_info, items),
            sizeof(((struct network_set_info *)0)->items[0]));
        return 0;
    }
    struct process_snapshot s;
    memset(&s, 0, sizeof(s));
    s.pid = 42; s.pidfd = -1; s.starttime_ticks = 1234567890123456789ULL;
    for (size_t i = 0; i < NSDIFF_NAMESPACE_COUNT; ++i) {
        strcpy(s.namespaces[i].name, namespaces[i]);
        s.namespaces[i].dev = 4;
        s.namespaces[i].ino = 4026531840ULL+i;
        snprintf(s.namespaces[i].target, sizeof(s.namespaces[i].target), "%s:[%llu]", namespaces[i], (unsigned long long)s.namespaces[i].ino);
    }
    s.proc_status.have_uid = s.proc_status.have_gid = true;
    for (size_t i = 0; i < 4; ++i) s.proc_status.uid[i] = s.proc_status.gid[i] = 1000;
    for (size_t i = 0; i < NSDIFF_CAPSET_COUNT; ++i) {
        s.proc_status.capabilities[i].kind = (enum nsdiff_capset_kind)i;
        s.proc_status.capabilities[i].present = true;
        s.proc_status.capabilities[i].mask = 0x8000000000000000ULL;
    }
    s.proc_status.have_no_new_privs = s.proc_status.have_seccomp = true;
    s.proc_status.no_new_privs = 1; s.proc_status.seccomp = 2;
    for (size_t i = 0; i < NSDIFF_LIMIT_COUNT; ++i) {
        s.limits.entries[i].kind = (enum nsdiff_limit_kind)i;
        s.limits.entries[i].soft.value = 1024;
        s.limits.entries[i].hard.value = 18446744073709551615ULL;
        strcpy(s.limits.entries[i].units, "bytes");
    }
    s.cgroup.v2 = true; strcpy(s.cgroup.path, "/example");
    for (size_t i = 0; i < NSDIFF_CGROUP_FILE_COUNT; ++i) {
        strcpy(s.cgroup.files[i].name, cgroups[i]);
        strcpy(s.cgroup.files[i].value, "max");
    }
    s.mounts.total_mounts = 7;
    for (size_t i = 0; i < NSDIFF_WATCHED_MOUNT_COUNT; ++i) {
        strcpy(s.mounts.entries[i].target, mounts[i]);
        strcpy(s.mounts.entries[i].root, "/");
        strcpy(s.mounts.entries[i].fstype, "tmpfs");
        strcpy(s.mounts.entries[i].source, "none");
        s.mounts.entries[i].mounted = true;
        s.mounts.entries[i].mount_id = (int)i+1;
    }
    s.mounts.shm.size_bytes = 67108864;
    for (size_t i = 0; i < NSDIFF_ENV_WATCH_COUNT; ++i) {
        strcpy(s.environment.entries[i].name, envs[i]);
        s.environment.entries[i].redact_value = i >= 25;
    }
    s.environment.total_entries = 2;
    s.environment.entries[0].present = true;
    strcpy(s.environment.entries[0].value, "/bin:/usr/bin");
    s.environment.entries[25].present = true;
    strcpy(s.environment.entries[25].value, "https://user:TEST_SECRET@invalid/");
    s.network.interfaces.count = 2;
    strcpy(s.network.interfaces.items[0], "eth0");
    strcpy(s.network.interfaces.items[1], "lo");
    return fwrite(&s, 1, sizeof(s), stdout) == sizeof(s) && fflush(stdout) == 0 ? 0 : 1;
}
