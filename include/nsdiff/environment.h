#ifndef NSDIFF_ENVIRONMENT_H
#define NSDIFF_ENVIRONMENT_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void environment_collect(
    pid_t pid,
    struct environment_info *info
);

#endif
