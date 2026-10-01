#ifndef NSDIFF_RENDER_H
#define NSDIFF_RENDER_H

#include "nsdiff/snapshot.h"
#include "nsdiff/diff.h"

void render_text_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff
);

#endif
