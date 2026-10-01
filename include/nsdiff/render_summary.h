#ifndef NSDIFF_RENDER_SUMMARY_H
#define NSDIFF_RENDER_SUMMARY_H

#include "nsdiff/diff_summary.h"
#include "nsdiff/scope.h"
#include "nsdiff/snapshot.h"


void render_summary(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff_summary *summary
);


void render_summary_scoped(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff_summary *summary,
    nsdiff_section_mask mask
);


#endif
