#include <stdio.h>

#include "nsdiff/render.h"
#include "nsdiff/render_network.h"


static void print_set(
    const char *prefix,
    const struct network_set_info *set
)
{
    size_t i;

    if (set->count == 0) {

        printf(
            "%snone\n",
            prefix
        );

        return;
    }

    for (i = 0;
         i < set->count;
         i++) {

        printf(
            "%s%s\n",
            prefix,
            set->items[i]
        );
    }
}


static void render_network_set(
    const char *name,
    const struct network_set_info *a,
    const struct network_set_info *b,
    const struct field_diff *field
)
{
    printf(
        "  %-22s ",
        name
    );

    switch (field->state) {

    case NSDIFF_DIFF_UNAVAILABLE:

        printf(
            "unavailable [A: %s | B: %s]\n",
            collect_status_string(
                a->status
            ),
            collect_status_string(
                b->status
            )
        );

        break;

    case NSDIFF_DIFF_SAME:

        printf(
            "same [%u entr%s]\n",
            a->count,
            a->count == 1
                ? "y"
                : "ies"
        );

        break;

    case NSDIFF_DIFF_DIFFERENT:

        printf("different\n");

        printf(
            "    A:\n"
        );

        print_set(
            "      ",
            a
        );

        printf(
            "    B:\n"
        );

        print_set(
            "      ",
            b
        );

        break;
    }
}


void render_network_diff(
    const struct network_info *a,
    const struct network_info *b,
    const struct process_diff *diff
)
{
    printf(
        "\nNetwork\n"
    );

    render_network_set(
        "interfaces",
        &a->interfaces,
        &b->interfaces,
        &diff->network_interfaces
    );

    render_network_set(
        "IPv4 default routes",
        &a->ipv4_default_routes,
        &b->ipv4_default_routes,
        &diff->network_ipv4_default_routes
    );

    render_network_set(
        "IPv6 addresses",
        &a->ipv6_addresses,
        &b->ipv6_addresses,
        &diff->network_ipv6_addresses
    );

    render_network_set(
        "IPv6 default routes",
        &a->ipv6_default_routes,
        &b->ipv6_default_routes,
        &diff->network_ipv6_default_routes
    );
}
