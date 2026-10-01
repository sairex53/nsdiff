#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nsdiff/environment.h"

#define NSDIFF_ENV_MAX_BYTES \
    (8U * 1024U * 1024U)

struct env_spec {
    const char *name;
    bool redact_value;
};

static const struct env_spec env_specs[] = {
    { "PATH", false },
    { "LANG", false },
    { "LC_ALL", false },
    { "LC_CTYPE", false },
    { "TZ", false },

    { "HOME", false },
    { "SHELL", false },

    { "TMPDIR", false },
    { "TMP", false },
    { "TEMP", false },

    { "XDG_RUNTIME_DIR", false },
    { "XDG_CONFIG_HOME", false },
    { "XDG_DATA_HOME", false },

    { "LD_LIBRARY_PATH", false },
    { "LD_PRELOAD", false },
    { "LD_AUDIT", false },

    { "PYTHONPATH", false },
    { "PYTHONHOME", false },
    { "VIRTUAL_ENV", false },

    { "JAVA_HOME", false },
    { "GOMAXPROCS", false },

    { "DISPLAY", false },
    { "WAYLAND_DISPLAY", false },
    { "DBUS_SESSION_BUS_ADDRESS", false },
    { "SSH_AUTH_SOCK", false },

    /*
     * Proxy URLs can contain:
     *
     *     scheme://user:password@host/
     *
     * so never print their values by default.
     */
    { "HTTP_PROXY", true },
    { "HTTPS_PROXY", true },
    { "ALL_PROXY", true },
    { "NO_PROXY", true },

    { "http_proxy", true },
    { "https_proxy", true },
    { "all_proxy", true },
    { "no_proxy", true },
};

_Static_assert(
    sizeof(env_specs) /
        sizeof(env_specs[0]) ==
        NSDIFF_ENV_WATCH_COUNT,
    "environment specification count mismatch"
);

static enum collect_status status_from_errno(
    int error_number
)
{
    switch (error_number) {

    case EACCES:
    case EPERM:
        return COLLECT_PERMISSION_DENIED;

    case ENOENT:
    case ESRCH:
        return COLLECT_PROCESS_GONE;

    default:
        return COLLECT_IO_ERROR;
    }
}

static void initialize_entries(
    struct environment_info *info
)
{
    size_t i;

    for (i = 0;
         i < NSDIFF_ENV_WATCH_COUNT;
         i++) {

        struct environment_entry_info *entry =
            &info->entries[i];

        entry->status = COLLECT_OK;

        entry->redact_value =
            env_specs[i].redact_value;

        if (snprintf(
                entry->name,
                sizeof(entry->name),
                "%s",
                env_specs[i].name
            ) >= (int)sizeof(entry->name)) {

            entry->status =
                COLLECT_PARSE_ERROR;
        }
    }
}

static enum collect_status read_environment_file(
    pid_t pid,
    unsigned char **data_out,
    size_t *size_out
)
{
    char path[64];

    unsigned char *buffer = NULL;

    size_t capacity = 4096;
    size_t total = 0;

    int fd = -1;

    enum collect_status status =
        COLLECT_IO_ERROR;

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/environ",
            (long)pid
        ) >= (int)sizeof(path)) {

        return COLLECT_IO_ERROR;
    }

    fd = open(
        path,
        O_RDONLY | O_CLOEXEC
    );

    if (fd < 0) {
        return status_from_errno(errno);
    }

    buffer = malloc(capacity);

    if (buffer == NULL) {

        close(fd);

        return COLLECT_IO_ERROR;
    }

    for (;;) {

        ssize_t result;

        if (total == capacity) {

            unsigned char *new_buffer;

            size_t new_capacity;

            if (capacity >=
                NSDIFF_ENV_MAX_BYTES) {

                status =
                    COLLECT_TRUNCATED;

                goto out;
            }

            new_capacity =
                capacity * 2;

            if (new_capacity >
                NSDIFF_ENV_MAX_BYTES) {

                new_capacity =
                    NSDIFF_ENV_MAX_BYTES;
            }

            new_buffer =
                realloc(
                    buffer,
                    new_capacity
                );

            if (new_buffer == NULL) {

                status =
                    COLLECT_IO_ERROR;

                goto out;
            }

            buffer = new_buffer;
            capacity = new_capacity;
        }

        result = read(
            fd,
            buffer + total,
            capacity - total
        );

        if (result < 0) {

            if (errno == EINTR) {
                continue;
            }

            status =
                status_from_errno(errno);

            goto out;
        }

        if (result == 0) {

            status = COLLECT_OK;

            break;
        }

        total +=
            (size_t)result;
    }

    *data_out = buffer;
    *size_out = total;

    buffer = NULL;

out:
    free(buffer);

    close(fd);

    return status;
}

static struct environment_entry_info *
find_watched_entry(
    struct environment_info *info,
    const unsigned char *name,
    size_t name_length
)
{
    size_t i;

    for (i = 0;
         i < NSDIFF_ENV_WATCH_COUNT;
         i++) {

        struct environment_entry_info *entry =
            &info->entries[i];

        size_t expected_length =
            strlen(entry->name);

        if (expected_length !=
            name_length) {

            continue;
        }

        if (memcmp(
                entry->name,
                name,
                name_length
            ) == 0) {

            return entry;
        }
    }

    return NULL;
}

static void parse_environment_entry(
    struct environment_info *info,
    const unsigned char *data,
    size_t length
)
{
    const unsigned char *equals;

    size_t name_length;
    size_t value_length;

    struct environment_entry_info *entry;

    equals = memchr(
        data,
        '=',
        length
    );

    if (equals == NULL ||
        equals == data) {

        return;
    }

    info->total_entries++;

    name_length =
        (size_t)(equals - data);

    entry =
        find_watched_entry(
            info,
            data,
            name_length
        );

    if (entry == NULL) {
        return;
    }

    /*
     * Duplicate variable names are legal at the
     * execve() ABI level but ambiguous for us.
     */
    if (entry->present) {

        entry->status =
            COLLECT_PARSE_ERROR;

        return;
    }

    entry->present = true;

    value_length =
        length -
        name_length -
        1;

    if (value_length >=
        sizeof(entry->value)) {

        entry->status =
            COLLECT_TRUNCATED;

        return;
    }

    memcpy(
        entry->value,
        equals + 1,
        value_length
    );

    entry->value[value_length] =
        '\0';
}

void environment_collect(
    pid_t pid,
    struct environment_info *info
)
{
    unsigned char *data = NULL;

    size_t size = 0;
    size_t offset = 0;

    memset(
        info,
        0,
        sizeof(*info)
    );

    initialize_entries(info);

    info->status =
        read_environment_file(
            pid,
            &data,
            &size
        );

    if (info->status != COLLECT_OK) {
        return;
    }

    while (offset < size) {

        const unsigned char *start =
            data + offset;

        const unsigned char *end;

        size_t remaining =
            size - offset;

        size_t length;

        end = memchr(
            start,
            '\0',
            remaining
        );

        if (end == NULL) {

            length = remaining;

            offset = size;

        } else {

            length =
                (size_t)(end - start);

            offset +=
                length + 1;
        }

        if (length == 0) {
            continue;
        }

        parse_environment_entry(
            info,
            start,
            length
        );
    }

    free(data);
}
