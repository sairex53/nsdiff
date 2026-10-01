#ifndef NSDIFF_MOUNTS_H
#define NSDIFF_MOUNTS_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void mounts_collect(
    pid_t pid,
    struct mounts_info *info
);

#endif
