#ifndef NSDIFF_RENDER_JSON_H
#define NSDIFF_RENDER_JSON_H

#include "nsdiff/diff.h"
#include "nsdiff/snapshot.h"

void render_json_diff(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff
);

#endif
