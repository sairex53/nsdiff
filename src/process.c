#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "nsdiff/namespaces.h"
#include "nsdiff/limits.h"
#include "nsdiff/proc_status.h"
#include "nsdiff/process.h"
#include "nsdiff/cgroup.h"
#include "nsdiff/mounts.h"
#include "nsdiff/environment.h"
#include "nsdiff/network.h"

static int open_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open

    return (int)syscall(
        SYS_pidfd_open,
        pid,
        0U
    );

#else

    (void)pid;

    errno = ENOSYS;

    return -1;

#endif
}

static int read_starttime(
    pid_t pid,
    unsigned long long *starttime_out
)
{
    char path[64];

    char *line = NULL;
    size_t line_capacity = 0;

    ssize_t line_length;

    FILE *stream = NULL;

    char *right_paren;
    char *cursor;

    char *saveptr = NULL;
    char *token;

    int field = 3;
    int rc = -1;

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/stat",
            (long)pid
        ) >= (int)sizeof(path)) {

        errno = ENAMETOOLONG;
        return -1;
    }

    stream = fopen(path, "re");

    if (stream == NULL) {
        return -1;
    }

    /* comm can itself contain newlines: consume the whole stat record. */
    line_capacity = 8192;
    line = malloc(line_capacity);
    if (!line) goto out;
    line_length = (ssize_t)fread(line, 1, line_capacity-1, stream);
    if (ferror(stream) || (size_t)line_length == line_capacity-1) {
        errno = EPROTO;
        goto out;
    }
    line[line_length] = 0;

    if (line_length < 0) {
        goto out;
    }

    /*
     * /proc/PID/stat:
     *
     * field 1 = PID
     * field 2 = comm
     *
     * comm is wrapped in parentheses and may contain spaces,
     * therefore blindly splitting the complete line on spaces
     * would be incorrect.
     */

    right_paren = strrchr(line, ')');

    if (right_paren == NULL ||
        right_paren[1] != ' ') {

        errno = EPROTO;
        goto out;
    }

    cursor = right_paren + 2;

    /*
     * The first token after ')' is field 3.
     */

    token = strtok_r(
        cursor,
        " ",
        &saveptr
    );

    while (token != NULL) {

        if (field == 22) {

            char *end = NULL;

            unsigned long long value;

            errno = 0;

            value = strtoull(
                token,
                &end,
                10
            );

            if (errno != 0 ||
                end == token ||
                (*end != '\0' && *end != '\n')) {

                errno = EPROTO;
                goto out;
            }

            *starttime_out = value;

            rc = 0;

            goto out;
        }

        field++;

        token = strtok_r(
            NULL,
            " ",
            &saveptr
        );
    }

    errno = EPROTO;

out:
    free(line);

    fclose(stream);

    return rc;
}

int process_snapshot_collect(
    pid_t pid,
    struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
)
{
    unsigned long long starttime_after;

    memset(
        snapshot,
        0,
        sizeof(*snapshot)
    );

    snapshot->pid = pid;
    snapshot->pidfd = -1;

    snapshot->pidfd =
        open_pidfd(pid);

    if (snapshot->pidfd < 0 && errno != ENOSYS && errno != EINVAL &&
        errno != EPERM && errno != EACCES) {

        snprintf(
            error_buf,
            error_buf_size,
            "pidfd_open failed: %s",
            strerror(errno)
        );

        goto fail;
    }

    if (read_starttime(
            pid,
            &snapshot->starttime_ticks
        ) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "cannot read process identity: %s",
            strerror(errno)
        );

        goto fail;
    }

    namespaces_collect(
        pid,
        snapshot->namespaces
    );

    proc_status_collect(
        pid,
        &snapshot->proc_status
    );

    limits_collect(
        pid,
        &snapshot->limits
    );

    cgroup_collect(
        pid,
        &snapshot->cgroup
    );

    mounts_collect(
        pid,
        &snapshot->mounts
    );

    environment_collect(
        pid,
        &snapshot->environment
    );

    network_collect(
        pid,
        &snapshot->network
    );

    /*
     * Verify that all collectors observed the
     * same process identity.
     */
    if (read_starttime(
            pid,
            &starttime_after
        ) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "process disappeared while snapshot was being collected: %s",
            strerror(errno)
        );

        goto fail;
    }

    if (snapshot->pidfd >= 0) {
        struct pollfd watch = {.fd = snapshot->pidfd, .events = POLLIN};
        int polled;
        do { polled = poll(&watch, 1, 0); } while (polled < 0 && errno == EINTR);
        if (polled != 0) {
            snprintf(error_buf, error_buf_size, "process lifetime ended during collection");
            goto fail;
        }
    }

    if (starttime_after !=
        snapshot->starttime_ticks) {

        snprintf(
            error_buf,
            error_buf_size,
            "process identity changed while snapshot was being collected"
        );

        goto fail;
    }

    return 0;
fail:
    process_snapshot_destroy(snapshot);
    return -1;
}

void process_snapshot_destroy(
    struct process_snapshot *snapshot
)
{
    if (snapshot->pidfd >= 0) {

        close(snapshot->pidfd);

        snapshot->pidfd = -1;
    }
}
