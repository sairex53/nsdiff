#ifndef NSDIFF_NETWORK_H
#define NSDIFF_NETWORK_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void network_collect(
    pid_t pid,
    struct network_info *info
);

#endif
