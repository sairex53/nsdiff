#include "nsdiff/json_writer.h"
#include <stdbool.h>
#include <stdio.h>

#include "nsdiff/render_network_json.h"


static const char *status_name(
    enum collect_status status
)
{
    switch (status) {

    case COLLECT_OK:
        return "ok";

    case COLLECT_PERMISSION_DENIED:
        return "permission denied";

    case COLLECT_NOT_SUPPORTED:
        return "not supported";

    case COLLECT_PROCESS_GONE:
        return "process gone";

    case COLLECT_IO_ERROR:
        return "I/O error";

    case COLLECT_PARSE_ERROR:
        return "parse error";
    case COLLECT_TRUNCATED:
        return "truncated";

    default:
        return "unknown";
    }
}


static const char *state_name(
    enum nsdiff_diff_state state
)
{
    switch (state) {

    case NSDIFF_DIFF_UNAVAILABLE:
        return "unavailable";

    case NSDIFF_DIFF_SAME:
        return "same";

    case NSDIFF_DIFF_DIFFERENT:
        return "different";

    default:
        return "unknown";
    }
}



static void write_set(
    const struct network_set_info *set
)
{
    size_t i;

    fputs(
        "[",
        stdout
    );

    for (i = 0;
         i < set->count;
         i++) {

        if (i != 0) {

            fputs(
                ", ",
                stdout
            );
        }

        nsdiff_json_write_string(
            set->items[i]
        );
    }

    fputs(
        "]",
        stdout
    );
}


static void render_one_set(
    bool *first,
    const char *path,
    const struct network_set_info *a,
    const struct network_set_info *b,
    const struct field_diff *field
)
{
    if (*first) {

        *first = false;

    } else {

        fputs(
            ",\n",
            stdout
        );
    }

    fputs(
        "    {\n"
        "      \"path\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    fputs(
        ",\n"
        "      \"state\": ",
        stdout
    );

    nsdiff_json_write_string(
        state_name(
            field->state
        )
    );

    fputs(
        ",\n"
        "      \"status_a\": ",
        stdout
    );

    nsdiff_json_write_string(
        status_name(
            a->status
        )
    );

    fputs(
        ",\n"
        "      \"status_b\": ",
        stdout
    );

    nsdiff_json_write_string(
        status_name(
            b->status
        )
    );

    fputs(
        ",\n"
        "      \"a\": ",
        stdout
    );

    if (a->status == COLLECT_OK) {

        write_set(a);

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        ",\n"
        "      \"b\": ",
        stdout
    );

    if (b->status == COLLECT_OK) {

        write_set(b);

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        ",\n"
        "      \"redacted\": false\n"
        "    }",
        stdout
    );
}


void render_network_json_fields(
    const struct process_snapshot *a,
    const struct process_snapshot *b,
    const struct process_diff *diff,
    bool *first
)
{
    render_one_set(
        first,
        "network.interfaces",
        &a->network.interfaces,
        &b->network.interfaces,
        &diff->network_interfaces
    );

    render_one_set(
        first,
        "network.ipv4_default_routes",
        &a->network.ipv4_default_routes,
        &b->network.ipv4_default_routes,
        &diff->network_ipv4_default_routes
    );

    render_one_set(
        first,
        "network.ipv6_addresses",
        &a->network.ipv6_addresses,
        &b->network.ipv6_addresses,
        &diff->network_ipv6_addresses
    );

    render_one_set(
        first,
        "network.ipv6_default_routes",
        &a->network.ipv6_default_routes,
        &b->network.ipv6_default_routes,
        &diff->network_ipv6_default_routes
    );
}
