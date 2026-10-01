#include "nsdiff/proc_read.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "nsdiff/proc_status.h"

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

static int parse_capability_mask(
    const char *text,
    struct capability_set_info *set
)
{
    char *end = NULL;

    unsigned long long value;

    errno = 0;

    value = strtoull(
        text,
        &end,
        16
    );

    if (errno != 0 ||
        end == text) {

        return -1;
    }

    while (*end != '\0' &&
           isspace((unsigned char)*end)) {

        end++;
    }

    if (*end != '\0') {
        return -1;
    }

    set->mask = value;
    set->present = true;

    return 0;
}

void proc_status_collect(
    pid_t pid,
    struct proc_status_info *info
)
{
    char path[64];

    char *line = NULL;
    size_t capacity = 0;

    FILE *stream;

    memset(
        info,
        0,
        sizeof(*info)
    );

	info->capabilities[
		NSDIFF_CAP_INHERITABLE
	].kind = NSDIFF_CAP_INHERITABLE;

	info->capabilities[
		NSDIFF_CAP_PERMITTED
	].kind = NSDIFF_CAP_PERMITTED;

	info->capabilities[
		NSDIFF_CAP_EFFECTIVE
	].kind = NSDIFF_CAP_EFFECTIVE;

	info->capabilities[
		NSDIFF_CAP_BOUNDING
	].kind = NSDIFF_CAP_BOUNDING;

	info->capabilities[
		NSDIFF_CAP_AMBIENT
	].kind = NSDIFF_CAP_AMBIENT;

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/status",
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

        return;
    }

    info->status = COLLECT_OK;

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        if (strncmp(
                line,
                "Uid:",
                4
            ) == 0) {

            if (sscanf(
                    line + 4,
                    "%lu %lu %lu %lu",
                    &info->uid[0],
                    &info->uid[1],
                    &info->uid[2],
                    &info->uid[3]
                ) == 4) {

                info->have_uid = true;
            }

        } else if (strncmp(
                       line,
                       "Gid:",
                       4
                   ) == 0) {

            if (sscanf(
                    line + 4,
                    "%lu %lu %lu %lu",
                    &info->gid[0],
                    &info->gid[1],
                    &info->gid[2],
                    &info->gid[3]
                ) == 4) {

                info->have_gid = true;
            }

        } else if (strncmp(
                       line,
                       "CapInh:",
                       7
                   ) == 0) {

            (void)parse_capability_mask(
                line + 7,
                &info->capabilities[
                    NSDIFF_CAP_INHERITABLE
                ]
            );

        } else if (strncmp(
                       line,
                       "CapPrm:",
                       7
                   ) == 0) {

            (void)parse_capability_mask(
                line + 7,
                &info->capabilities[
                    NSDIFF_CAP_PERMITTED
                ]
            );

        } else if (strncmp(
                       line,
                       "CapEff:",
                       7
                   ) == 0) {

            (void)parse_capability_mask(
                line + 7,
                &info->capabilities[
                    NSDIFF_CAP_EFFECTIVE
                ]
            );

        } else if (strncmp(
                       line,
                       "CapBnd:",
                       7
                   ) == 0) {

            (void)parse_capability_mask(
                line + 7,
                &info->capabilities[
                    NSDIFF_CAP_BOUNDING
                ]
            );

        } else if (strncmp(
                       line,
                       "CapAmb:",
                       7
                   ) == 0) {

            (void)parse_capability_mask(
                line + 7,
                &info->capabilities[
                    NSDIFF_CAP_AMBIENT
                ]
            );
        } else if (strncmp(
                       line,
                       "NoNewPrivs:",
                       11
                   ) == 0) {

            if (sscanf(
                    line + 11,
                    "%d",
                    &info->no_new_privs
                ) == 1) {

                info->have_no_new_privs =
                    true;
            }

        } else if (strncmp(
                       line,
                       "Seccomp:",
                       8
                   ) == 0) {

            if (sscanf(
                    line + 8,
                    "%d",
                    &info->seccomp
                ) == 1) {

                info->have_seccomp = true;
            }
        }
    }

    if (ferror(stream) || errno != 0) info->status = COLLECT_IO_ERROR;

    free(line);

    fclose(stream);
}
