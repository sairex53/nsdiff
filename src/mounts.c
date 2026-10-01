#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/statvfs.h>

#include <libmount/libmount.h>

#include "nsdiff/mounts.h"

static const char *const watched_mounts[
    NSDIFF_WATCHED_MOUNT_COUNT
] = {
    "/",
    "/proc",
    "/sys",
    "/dev",
    "/dev/shm",
    "/tmp",
    "/run",
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
    case ENOTDIR:
        return COLLECT_NOT_SUPPORTED;

    case ESRCH:
        return COLLECT_PROCESS_GONE;

    default:
        return COLLECT_IO_ERROR;
    }
}

static int copy_string(
    char *destination,
    size_t destination_size,
    const char *source
)
{
    int written;

    if (source == NULL) {
        source = "";
    }

    written = snprintf(
        destination,
        destination_size,
        "%s",
        source
    );

    if (written < 0 ||
        written >= (int)destination_size) {

        return -1;
    }

    return 0;
}

static bool fs_has_option(
    struct libmnt_fs *fs,
    const char *name
)
{
    return mnt_fs_get_option(
        fs,
        name,
        NULL,
        NULL
    ) == 0;
}

static enum collect_status fill_mount_entry(
    struct libmnt_fs *fs,
    struct mount_point_info *entry
)
{
    if (copy_string(
            entry->root,
            sizeof(entry->root),
            mnt_fs_get_root(fs)
        ) != 0 ||
        copy_string(
            entry->fstype,
            sizeof(entry->fstype),
            mnt_fs_get_fstype(fs)
        ) != 0 ||
        copy_string(
            entry->source,
            sizeof(entry->source),
            mnt_fs_get_source(fs)
        ) != 0) {

        return COLLECT_TRUNCATED;
    }

    entry->mounted = true;

    entry->mount_id =
        mnt_fs_get_id(fs);

    entry->read_only =
        fs_has_option(fs, "ro");

    entry->nosuid =
        fs_has_option(fs, "nosuid");

    entry->nodev =
        fs_has_option(fs, "nodev");

    entry->noexec =
        fs_has_option(fs, "noexec");

    return COLLECT_OK;
}

static enum collect_status collect_shm_size(
    pid_t pid,
    struct shared_memory_info *shm
)
{
    char path[128];

    struct statvfs st;

    unsigned long long block_size;
    unsigned long long block_count;

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/root/dev/shm",
            (long)pid
        ) >= (int)sizeof(path)) {

        return COLLECT_IO_ERROR;
    }

    if (statvfs(path, &st) != 0) {
        return status_from_errno(errno);
    }

    if (st.f_frsize != 0) {

        block_size =
            (unsigned long long)st.f_frsize;

    } else {

        block_size =
            (unsigned long long)st.f_bsize;
    }

    block_count =
        (unsigned long long)st.f_blocks;

    if (block_size == 0) {
        return COLLECT_PARSE_ERROR;
    }

    if (block_count >
        ULLONG_MAX / block_size) {

        return COLLECT_PARSE_ERROR;
    }

    shm->size_bytes =
        block_size * block_count;

    return COLLECT_OK;
}

void mounts_collect(
    pid_t pid,
    struct mounts_info *info
)
{
    char path[64];

    struct libmnt_table *table = NULL;

    size_t i;

    int rc;

    memset(
        info,
        0,
        sizeof(*info)
    );

    info->shm.status = COLLECT_IO_ERROR;

    for (i = 0;
         i < NSDIFF_WATCHED_MOUNT_COUNT;
         i++) {

        struct mount_point_info *entry =
            &info->entries[i];

        entry->status =
            COLLECT_OK;

        if (copy_string(
                entry->target,
                sizeof(entry->target),
                watched_mounts[i]
            ) != 0) {

            entry->status =
                COLLECT_PARSE_ERROR;
        }
    }

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/mountinfo",
            (long)pid
        ) >= (int)sizeof(path)) {

        info->status =
            COLLECT_IO_ERROR;

        return;
    }

    table = mnt_new_table();

    if (table == NULL) {

        info->status =
            COLLECT_IO_ERROR;

        return;
    }

    rc = mnt_table_parse_file(
        table,
        path
    );

    if (rc != 0) {

        if (rc < 0) {
            info->status =
                status_from_errno(-rc);
        } else {
            info->status =
                COLLECT_PARSE_ERROR;
        }

        goto out;
    }

    info->status = COLLECT_OK;

    info->total_mounts =
        mnt_table_get_nents(table);

    for (i = 0;
         i < NSDIFF_WATCHED_MOUNT_COUNT;
         i++) {

        struct mount_point_info *entry =
            &info->entries[i];

        struct libmnt_fs *fs;

        if (entry->status != COLLECT_OK) {
            continue;
        }

        /*
         * BACKWARD is important if several mounts are stacked
         * on the same target; we want the visible top-most one.
         */
        fs = mnt_table_find_target(
            table,
            entry->target,
            MNT_ITER_BACKWARD
        );

        if (fs == NULL) {

            /*
             * This is not an error.
             *
             * For example /tmp may simply live on the root
             * filesystem rather than being a separate mount.
             */
            entry->mounted = false;

            continue;
        }

        entry->status =
            fill_mount_entry(
                fs,
                entry
            );
    }

    info->shm.status =
        collect_shm_size(
            pid,
            &info->shm
        );

out:
    mnt_unref_table(table);
}
