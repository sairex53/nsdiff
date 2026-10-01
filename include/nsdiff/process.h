#ifndef NSDIFF_PROCESS_H
#define NSDIFF_PROCESS_H

#include <stddef.h>
#include <sys/types.h>

#include "nsdiff/snapshot.h"

int process_snapshot_collect(pid_t pid,
                             struct process_snapshot *snapshot,
                             char *error_buf,
                             size_t error_buf_size);

void process_snapshot_destroy(struct process_snapshot *snapshot);

#endif
