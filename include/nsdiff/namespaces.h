#ifndef NSDIFF_NAMESPACES_H
#define NSDIFF_NAMESPACES_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void namespaces_collect(
    pid_t pid,
    struct namespace_info entries[NSDIFF_NAMESPACE_COUNT]
);

#endif
