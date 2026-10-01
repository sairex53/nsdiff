#ifndef NSDIFF_CGROUP_H
#define NSDIFF_CGROUP_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void cgroup_collect(
    pid_t pid,
    struct cgroup_info *info
);

#endif
