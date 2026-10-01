#ifndef NSDIFF_RENDER_NETWORK_JSON_H
#define NSDIFF_RENDER_NETWORK_JSON_H

#include <stdbool.h>

#include "nsdiff/diff.h"
#include "nsdiff/snapshot.h"

void render_network_json_fields(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff,
    bool *first
);

#endif
