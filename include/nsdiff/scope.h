#ifndef NSDIFF_SCOPE_H
#define NSDIFF_SCOPE_H

#include <stdbool.h>

#include "nsdiff/diff.h"


typedef unsigned int nsdiff_section_mask;


#define NSDIFF_SECTION_NAMESPACES   (1U << 0)
#define NSDIFF_SECTION_CREDENTIALS  (1U << 1)
#define NSDIFF_SECTION_LIMITS       (1U << 2)
#define NSDIFF_SECTION_CGROUP       (1U << 3)
#define NSDIFF_SECTION_NETWORK      (1U << 4)
#define NSDIFF_SECTION_MOUNTS       (1U << 5)
#define NSDIFF_SECTION_ENVIRONMENT  (1U << 6)
#define NSDIFF_SECTION_SECURITY     (1U << 7)

#define NSDIFF_SECTION_ALL          \
    (NSDIFF_SECTION_NAMESPACES  |   \
     NSDIFF_SECTION_CREDENTIALS |   \
     NSDIFF_SECTION_LIMITS      |   \
     NSDIFF_SECTION_CGROUP      |   \
     NSDIFF_SECTION_NETWORK     |   \
     NSDIFF_SECTION_MOUNTS      |   \
     NSDIFF_SECTION_ENVIRONMENT |   \
     NSDIFF_SECTION_SECURITY)


int nsdiff_section_parse(
    const char *name,
    nsdiff_section_mask *section_out
);


bool nsdiff_section_enabled(
    nsdiff_section_mask mask,
    nsdiff_section_mask section
);


void process_diff_apply_scope(
    const struct process_diff *source,
    nsdiff_section_mask mask,
    struct process_diff *target
);


#endif
