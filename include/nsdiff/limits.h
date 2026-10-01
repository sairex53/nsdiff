#ifndef NSDIFF_LIMITS_H
#define NSDIFF_LIMITS_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void limits_collect(
    pid_t pid,
    struct limits_info *info
);

#endif
