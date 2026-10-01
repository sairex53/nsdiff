#include <stdio.h>

#include "config.h"

#include "nsdiff/render_summary.h"


static void render_section(
    const char *name,
    const struct diff_section_summary *section
)
{
    printf(
        "  %-13s %3u comparable  %3u different  %3u unavailable\n",
        name,
        section->comparable_fields,
        section->differences,
        section->unavailable_fields
    );
}


void render_summary_scoped(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff_summary *summary,
    nsdiff_section_mask mask
)
{
    printf(
        "nsdiff %s\n"
        "A: PID %ld\n"
        "B: PID %ld\n"
        "\n"
        "Summary by domain\n",
        NSDIFF_VERSION,
        (long)a->pid,
        (long)b->pid
    );

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NAMESPACES
        )) {

        render_section(
            "namespaces",
            &summary->namespaces
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CREDENTIALS
        )) {

        render_section(
            "credentials",
            &summary->credentials
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_LIMITS
        )) {

        render_section(
            "limits",
            &summary->limits
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_CGROUP
        )) {

        render_section(
            "cgroup",
            &summary->cgroup
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_NETWORK
        )) {

        render_section(
            "network",
            &summary->network
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_MOUNTS
        )) {

        render_section(
            "mounts",
            &summary->mounts
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_ENVIRONMENT
        )) {

        render_section(
            "environment",
            &summary->environment
        );
    }

    if (nsdiff_section_enabled(
            mask,
            NSDIFF_SECTION_SECURITY
        )) {

        render_section(
            "security",
            &summary->security
        );
    }

    printf(
        "\n"
        "Total\n"
        "  %u comparable fields checked\n"
        "  %u differences found\n"
        "  %u unavailable fields\n",
        summary->comparable_fields,
        summary->differences,
        summary->unavailable_fields
    );
}


void render_summary(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff_summary *summary
)
{
    render_summary_scoped(
        a,
        b,
        summary,
        NSDIFF_SECTION_ALL
    );
}
