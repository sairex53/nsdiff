#include "nsdiff/proc_read.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsdiff/cgroup.h"

static const char *const cgroup_files[
    NSDIFF_CGROUP_FILE_COUNT
] = {
    "memory.max",
    "memory.high",
    "memory.swap.max",
    "cpu.max",
    "cpu.weight",
    "pids.max",
    "cpuset.cpus.effective",
    "cpuset.mems.effective",
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

static void trim_trailing_whitespace(
    char *text
)
{
    size_t length;

    length = strlen(text);

    while (length > 0) {

        char c = text[length - 1];

        if (c != '\n' &&
            c != '\r' &&
            c != ' ' &&
            c != '\t') {

            break;
        }

        text[length - 1] = '\0';

        length--;
    }
}

static enum collect_status read_value_file(
    const char *path,
    char *value,
    size_t value_size
)
{
    FILE *stream;

    char *line = NULL;
    size_t capacity = 0;

    ssize_t length;

    enum collect_status status;

    stream = fopen(path, "re");

    if (stream == NULL) {
        return status_from_errno(errno);
    }

    length = nsdiff_read_line(
        &line,
        &capacity,
        stream
    );

    if (length < 0) {

        if (ferror(stream) || errno != 0) {
            status = COLLECT_IO_ERROR;
        } else {
            status = COLLECT_PARSE_ERROR;
        }

        goto out;
    }

    trim_trailing_whitespace(line);

    if (snprintf(
            value,
            value_size,
            "%s",
            line
        ) >= (int)value_size) {

        status = COLLECT_PARSE_ERROR;

        goto out;
    }

    status = COLLECT_OK;

out:
    free(line);

    fclose(stream);

    return status;
}

static enum collect_status read_cgroup_v2_path(
    pid_t pid,
    char *path_out,
    size_t path_out_size
)
{
    char proc_path[64];

    FILE *stream;

    char *line = NULL;
    size_t capacity = 0;

    enum collect_status status =
        COLLECT_NOT_SUPPORTED;

    if (snprintf(
            proc_path,
            sizeof(proc_path),
            "/proc/%ld/cgroup",
            (long)pid
        ) >= (int)sizeof(proc_path)) {

        return COLLECT_IO_ERROR;
    }

    stream = fopen(
        proc_path,
        "re"
    );

    if (stream == NULL) {
        return status_from_errno(errno);
    }

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        const char *prefix = "0::";

        const size_t prefix_length =
            strlen(prefix);

        char *cgroup_path;

        if (strncmp(
                line,
                prefix,
                prefix_length
            ) != 0) {

            continue;
        }

        cgroup_path =
            line + prefix_length;

        trim_trailing_whitespace(
            cgroup_path
        );

        if (cgroup_path[0] != '/') {

            status =
                COLLECT_PARSE_ERROR;

            break;
        }

        if (snprintf(
                path_out,
                path_out_size,
                "%s",
                cgroup_path
            ) >= (int)path_out_size) {

            status =
                COLLECT_PARSE_ERROR;

            break;
        }

        status = COLLECT_OK;

        break;
    }

    if (ferror(stream) || errno != 0) {
        status = COLLECT_IO_ERROR;
    }

    free(line);

    fclose(stream);

    return status;
}

static enum collect_status collect_one_file(
    pid_t pid,
    const char *cgroup_path,
    struct cgroup_file_info *entry
)
{
    char path[
        NSDIFF_CGROUP_PATH_LEN +
        NSDIFF_CGROUP_NAME_LEN +
        128
    ];

    int written;
    /* A cgroup namespace may expose unreachable ancestors as /../. */
    if (strstr(cgroup_path, "/../") || !strcmp(cgroup_path, "/..") ||
        (strlen(cgroup_path) >= 3 && !strcmp(cgroup_path+strlen(cgroup_path)-3, "/..")))
        return COLLECT_NOT_SUPPORTED;


    if (strcmp(
            cgroup_path,
            "/"
        ) == 0) {

        written = snprintf(
            path,
            sizeof(path),
            "/proc/%ld/root/sys/fs/cgroup/%s",
            (long)pid,
            entry->name
        );

    } else {

        written = snprintf(
            path,
            sizeof(path),
            "/proc/%ld/root/sys/fs/cgroup%s/%s",
            (long)pid,
            cgroup_path,
            entry->name
        );
    }

    if (written < 0 ||
        written >= (int)sizeof(path)) {

        return COLLECT_IO_ERROR;
    }

    return read_value_file(
        path,
        entry->value,
        sizeof(entry->value)
    );
}

void cgroup_collect(
    pid_t pid,
    struct cgroup_info *info
)
{
    size_t i;

    memset(
        info,
        0,
        sizeof(*info)
    );

    for (i = 0;
         i < NSDIFF_CGROUP_FILE_COUNT;
         i++) {

        snprintf(
            info->files[i].name,
            sizeof(info->files[i].name),
            "%s",
            cgroup_files[i]
        );

        info->files[i].status =
            COLLECT_NOT_SUPPORTED;
    }

    info->status =
        read_cgroup_v2_path(
            pid,
            info->path,
            sizeof(info->path)
        );

    if (info->status != COLLECT_OK) {
        return;
    }

    info->v2 = true;

    for (i = 0;
         i < NSDIFF_CGROUP_FILE_COUNT;
         i++) {

        info->files[i].status =
            collect_one_file(
                pid,
                info->path,
                &info->files[i]
            );
    }
}
