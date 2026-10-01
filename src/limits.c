#include "nsdiff/proc_read.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsdiff/limits.h"

struct limit_spec {
    enum nsdiff_limit_kind kind;
    const char *proc_name;
};

static const struct limit_spec limit_specs[] = {
    {
        NSDIFF_LIMIT_NOFILE,
        "Max open files",
    },
    {
        NSDIFF_LIMIT_NPROC,
        "Max processes",
    },
    {
        NSDIFF_LIMIT_STACK,
        "Max stack size",
    },
    {
        NSDIFF_LIMIT_MEMLOCK,
        "Max locked memory",
    },
    {
        NSDIFF_LIMIT_AS,
        "Max address space",
    },
    {
        NSDIFF_LIMIT_CORE,
        "Max core file size",
    },
    {
        NSDIFF_LIMIT_FSIZE,
        "Max file size",
    },
};

_Static_assert(
    sizeof(limit_specs) / sizeof(limit_specs[0]) ==
        NSDIFF_LIMIT_COUNT,
    "limit specification count does not match NSDIFF_LIMIT_COUNT"
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

static int parse_limit_value(
    const char *text,
    struct limit_value *value
)
{
    char *end = NULL;

    unsigned long long parsed;

    if (strcmp(text, "unlimited") == 0) {
        value->unlimited = true;
        value->value = 0;

        return 0;
    }

    errno = 0;

    parsed = strtoull(
        text,
        &end,
        10
    );

    if (errno != 0 ||
        end == text ||
        *end != '\0') {

        return -1;
    }

    value->unlimited = false;
    value->value = parsed;

    return 0;
}

static int line_matches_limit(
    const char *line,
    const char *name,
    const char **values_out
)
{
    size_t name_length;

    const char *cursor;

    name_length = strlen(name);

    if (strncmp(
            line,
            name,
            name_length
        ) != 0) {

        return 0;
    }

    cursor = line + name_length;

    /*
     * Avoid accidentally matching a longer name
     * that merely has the expected name as a prefix.
     */
    if (*cursor != ' ' &&
        *cursor != '\t') {

        return 0;
    }

    while (*cursor != '\0' &&
           isspace((unsigned char)*cursor)) {

        cursor++;
    }

    *values_out = cursor;

    return 1;
}

static void parse_limit_line(
    const char *line,
    struct limits_info *info
)
{
    size_t i;

    for (i = 0;
         i < NSDIFF_LIMIT_COUNT;
         i++) {

        struct resource_limit_info *entry =
            &info->entries[i];

        const char *values;

        char soft_text[32];
        char hard_text[32];
        char units[NSDIFF_LIMIT_UNIT_LEN];

        int fields;

        if (!line_matches_limit(
                line,
                limit_specs[i].proc_name,
                &values
            )) {

            continue;
        }

        memset(
            soft_text,
            0,
            sizeof(soft_text)
        );

        memset(
            hard_text,
            0,
            sizeof(hard_text)
        );

        memset(
            units,
            0,
            sizeof(units)
        );

        fields = sscanf(
            values,
            "%31s %31s %15s",
            soft_text,
            hard_text,
            units
        );

        if (fields < 2) {
            entry->status =
                COLLECT_PARSE_ERROR;

            return;
        }

        if (parse_limit_value(
                soft_text,
                &entry->soft
            ) != 0 ||
            parse_limit_value(
                hard_text,
                &entry->hard
            ) != 0) {

            entry->status =
                COLLECT_PARSE_ERROR;

            return;
        }

        if (fields >= 3) {
            snprintf(
                entry->units,
                sizeof(entry->units),
                "%s",
                units
            );
        }

        entry->status = COLLECT_OK;

        return;
    }
}

void limits_collect(
    pid_t pid,
    struct limits_info *info
)
{
    char path[64];

    char *line = NULL;
    size_t capacity = 0;

    FILE *stream;

    size_t i;

    memset(
        info,
        0,
        sizeof(*info)
    );

    for (i = 0;
         i < NSDIFF_LIMIT_COUNT;
         i++) {

        info->entries[i].kind =
            limit_specs[i].kind;

        info->entries[i].status =
            COLLECT_NOT_SUPPORTED;
    }

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/limits",
            (long)pid
        ) >= (int)sizeof(path)) {

        info->status =
            COLLECT_IO_ERROR;

        return;
    }

    stream = fopen(path, "re");

    if (stream == NULL) {

        info->status =
            status_from_errno(errno);

        for (i = 0;
             i < NSDIFF_LIMIT_COUNT;
             i++) {

            info->entries[i].status =
                info->status;
        }

        return;
    }

    info->status = COLLECT_OK;

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        parse_limit_line(
            line,
            info
        );
    }

    if (ferror(stream) || errno != 0) {
        info->status =
            COLLECT_IO_ERROR;
    }

    free(line);

    fclose(stream);
}
