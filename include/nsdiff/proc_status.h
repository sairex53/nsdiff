#ifndef NSDIFF_PROC_STATUS_H
#define NSDIFF_PROC_STATUS_H

#include <sys/types.h>

#include "nsdiff/snapshot.h"

void proc_status_collect(pid_t pid, struct proc_status_info *info);

#endif
