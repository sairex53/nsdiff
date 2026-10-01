#ifndef NSDIFF_RENDER_NETWORK_H
#define NSDIFF_RENDER_NETWORK_H

#include "nsdiff/diff.h"
#include "nsdiff/snapshot.h"

void render_network_diff(
    const struct network_info *a,
    const struct network_info *b,
    const struct process_diff *diff
);

#endif
