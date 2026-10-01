#ifndef NSDIFF_RENDER_COMPACT_H
#define NSDIFF_RENDER_COMPACT_H

#include <stdbool.h>

#include "nsdiff/diff.h"
#include "nsdiff/snapshot.h"

void render_compact_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff,
    bool explain
);

#endif
