#ifndef NSDIFF_DIFF_SUMMARY_H
#define NSDIFF_DIFF_SUMMARY_H

#include "nsdiff/diff.h"
#include "nsdiff/scope.h"


struct diff_section_summary {
    unsigned int comparable_fields;
    unsigned int differences;
    unsigned int unavailable_fields;
};


struct process_diff_summary {
    struct diff_section_summary namespaces;
    struct diff_section_summary credentials;
    struct diff_section_summary limits;
    struct diff_section_summary cgroup;
    struct diff_section_summary network;
    struct diff_section_summary mounts;
    struct diff_section_summary environment;
    struct diff_section_summary security;

    unsigned int comparable_fields;
    unsigned int differences;
    unsigned int unavailable_fields;
};


void process_diff_summary_build(
    const struct process_diff *diff,
    struct process_diff_summary *summary
);


void process_diff_summary_build_scoped(
    const struct process_diff *diff,
    nsdiff_section_mask mask,
    struct process_diff_summary *summary
);


#endif
