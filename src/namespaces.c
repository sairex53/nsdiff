#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nsdiff/namespaces.h"

static const char *const namespace_names[
    NSDIFF_NAMESPACE_COUNT
] = {
    "mnt",
    "net",
    "pid",
    "user",
    "uts",
    "ipc",
    "cgroup",
    "time",
};

static enum collect_status status_from_errno(
    int error_number
)
{
    switch (error_number) {

    case EACCES:
    case EPERM:

        return COLLECT_PERMISSION_DENIED;

    case ENOENT:

        return COLLECT_NOT_SUPPORTED;

    case ESRCH:

        return COLLECT_PROCESS_GONE;

    default:

        return COLLECT_IO_ERROR;
    }
}

void namespaces_collect(
    pid_t pid,
    struct namespace_info entries[
        NSDIFF_NAMESPACE_COUNT
    ]
)
{
    size_t i;

    for (i = 0;
         i < NSDIFF_NAMESPACE_COUNT;
         i++) {

        struct namespace_info *entry =
            &entries[i];

        struct stat st;

        char path[128];

        ssize_t length;

        memset(
            entry,
            0,
            sizeof(*entry)
        );

        snprintf(
            entry->name,
            sizeof(entry->name),
            "%s",
            namespace_names[i]
        );

        if (snprintf(
                path,
                sizeof(path),
                "/proc/%ld/ns/%s",
                (long)pid,
                namespace_names[i]
            ) >= (int)sizeof(path)) {

            entry->status =
                COLLECT_IO_ERROR;

            continue;
        }

	/*
	 * stat() follows the /proc/PID/ns/<name> symlink.
	 *
	 * st_dev + st_ino identify the actual namespace
	 * object for comparison.
	 */

        if (stat(path, &st) != 0) {

            entry->status =
                status_from_errno(errno);

            continue;
        }

        entry->dev = st.st_dev;
        entry->ino = st.st_ino;

        /*
         * readlink() is only for human-readable output:
         *
         * mnt:[4026531841]
         */

        length = readlink(
            path,
            entry->target,
            sizeof(entry->target) - 1U
        );

        if (length < 0) {

            entry->status =
                status_from_errno(errno);

            continue;
        }

        entry->target[length] = '\0';

        entry->status = COLLECT_OK;
    }
}
