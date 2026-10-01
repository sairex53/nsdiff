#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include "nsdiff/snapshot_internal.h"

static int write_full(int fd, const unsigned char *data, size_t size)
{
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return -1; }
        data += (size_t)n;
        size -= (size_t)n;
    }
    return 0;
}
static int sync_fd(int fd)
{
    int rc;
    do { rc = fsync(fd); } while (rc && errno == EINTR);
    return rc;
}
int nsdiff_write_private(const char *path, const void *data, size_t size, char *error, size_t error_size)
{
    char *copy = NULL, *temporary = NULL;
    const char *base, *directory;
    int dirfd = -1, fd = -1, rc = -1, saved = 0;
    bool published = false, created = false;
    if (!strcmp(path, "-")) {
        if (fflush(stdout) == 0 && write_full(STDOUT_FILENO, data, size) == 0) return 0;
        snprintf(error, error_size, "cannot write snapshot to stdout: %s", strerror(errno));
        return -1;
    }
    copy = strdup(path);
    if (!copy) goto out;
    char *slash = strrchr(copy, '/');
    if (slash) { *slash = 0; base = slash+1; directory = *copy ? copy : "/"; }
    else { base = copy; directory = "."; }
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) { errno = EINVAL; goto out; }
    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) goto out;
    /* Bind creation, rename and directory sync to the same opened directory. */
    temporary = malloc(strlen(base)+40);
    if (!temporary) goto out;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        unsigned char random[16];
        size_t used = 0;
        while (used < sizeof(random)) {
            ssize_t n = getrandom(random+used, sizeof(random)-used, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto out;
            used += (size_t)n;
        }
        size_t n = strlen(base);
        memcpy(temporary, base, n);
        memcpy(temporary+n, ".tmp.", 5);
        for (size_t i = 0; i < sizeof(random); ++i)
            snprintf(temporary+n+5+2*i, 3, "%02x", random[i]);
        fd = openat(dirfd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0) { created = true; break; }
        if (errno != EEXIST) goto out;
    }
    if (fd < 0) goto out;
    if (fchmod(fd, 0600) || write_full(fd, data, size) || sync_fd(fd)) goto out;
    if (close(fd)) { fd = -1; goto out; }
    fd = -1;
    if (renameat(dirfd, temporary, dirfd, base)) goto out;
    published = true;
    if (sync_fd(dirfd)) goto out;
    rc = 0;
out:
    saved = errno ? errno : EIO;
    if (fd >= 0) close(fd);
    if (created && !published) unlinkat(dirfd, temporary, 0);
    if (dirfd >= 0 && close(dirfd) && rc == 0) { saved = errno; rc = -1; }
    free(temporary);
    free(copy);
    if (rc) snprintf(error, error_size, "%s: %s", published ?
        "snapshot published but directory durability failed" : "cannot write snapshot atomically", strerror(saved));
    return rc;
}
