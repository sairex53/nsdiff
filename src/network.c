#include "nsdiff/proc_read.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsdiff/network.h"


static enum collect_status status_from_errno(
    int error_number
)
{
    switch (error_number) {

    case EACCES:
    case EPERM:
        return COLLECT_PERMISSION_DENIED;

    case ENOENT:
    case ENOTDIR:
        return COLLECT_NOT_SUPPORTED;

    case ESRCH:
        return COLLECT_PROCESS_GONE;

    default:
        return COLLECT_IO_ERROR;
    }
}


static int item_compare(
    const void *left,
    const void *right
)
{
    return strcmp(
        (const char *)left,
        (const char *)right
    );
}


static enum collect_status add_item(
    struct network_set_info *set,
    const char *text
)
{
    for (size_t i = 0; i < set->count; ++i)
        if (!strcmp(set->items[i], text)) return COLLECT_OK;
    if (set->count >=
        NSDIFF_NET_SET_MAX) {

        return COLLECT_TRUNCATED;
    }

    if (snprintf(
            set->items[set->count],
            sizeof(set->items[set->count]),
            "%s",
            text
        ) >=
        (int)sizeof(set->items[set->count])) {

        return COLLECT_TRUNCATED;
    }

    set->count++;

    return COLLECT_OK;
}


static void sort_set(
    struct network_set_info *set
)
{
    qsort(
        set->items,
        set->count,
        sizeof(set->items[0]),
        item_compare
    );
}


static FILE *open_proc_net_file(
    pid_t pid,
    const char *name,
    enum collect_status *status_out
)
{
    char path[128];

    FILE *stream;

    if (snprintf(
            path,
            sizeof(path),
            "/proc/%ld/net/%s",
            (long)pid,
            name
        ) >= (int)sizeof(path)) {

        *status_out =
            COLLECT_IO_ERROR;

        return NULL;
    }

    stream = fopen(
        path,
        "re"
    );

    if (stream == NULL) {

        *status_out =
            status_from_errno(errno);

        return NULL;
    }

    *status_out =
        COLLECT_OK;

    return stream;
}


static enum collect_status collect_interfaces(
    pid_t pid,
    struct network_set_info *set
)
{
    FILE *stream;

    char *line = NULL;

    size_t capacity = 0;

    enum collect_status status;

    stream =
        open_proc_net_file(
            pid,
            "dev",
            &status
        );

    if (stream == NULL) {
        return status;
    }

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        char *colon;

        char *start;
        char *end;

        char name[
            NSDIFF_NET_ITEM_LEN
        ];

        size_t length;

        colon = strchr(
            line,
            ':'
        );

        if (colon == NULL) {
            continue;
        }

        start = line;

        while (*start == ' ' ||
               *start == '\t') {

            start++;
        }

        end = colon;

        while (end > start &&
               (end[-1] == ' ' ||
                end[-1] == '\t')) {

            end--;
        }

        length =
            (size_t)(end - start);

        if (length == 0 ||
            length >= sizeof(name)) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        memcpy(
            name,
            start,
            length
        );

        name[length] = '\0';

        status =
            add_item(
                set,
                name
            );

        if (status != COLLECT_OK) {
            goto out;
        }
    }

    if (ferror(stream) || errno != 0) {

        status =
            COLLECT_IO_ERROR;

        goto out;
    }

    status = COLLECT_OK;

    sort_set(set);

out:
    free(line);

    fclose(stream);

    return status;
}


static enum collect_status collect_ipv4_default_routes(
    pid_t pid,
    struct network_set_info *set
)
{
    FILE *stream;

    char *line = NULL;

    size_t capacity = 0;

    bool first_line = true;

    enum collect_status status;

    stream =
        open_proc_net_file(
            pid,
            "route",
            &status
        );

    if (stream == NULL) {
        return status;
    }

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        char iface[64];

        unsigned long destination;
        unsigned long gateway;
        unsigned long flags;

        unsigned long ref_count;
        unsigned long use;
        unsigned long metric;
        unsigned long mask;

        struct in_addr gateway_address;

        char gateway_text[
            INET_ADDRSTRLEN
        ];

        char item[
            NSDIFF_NET_ITEM_LEN
        ];

        int fields;

        if (first_line) {

            first_line = false;

            continue;
        }

        fields = sscanf(
            line,
            "%63s "
            "%lx "
            "%lx "
            "%lx "
            "%lu "
            "%lu "
            "%lu "
            "%lx",
            iface,
            &destination,
            &gateway,
            &flags,
            &ref_count,
            &use,
            &metric,
            &mask
        );

        if (fields != 8) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (destination != 0 ||
            mask != 0) {

            continue;
        }

        gateway_address.s_addr =
            (in_addr_t)(
                (uint32_t)gateway
            );

        if (inet_ntop(
                AF_INET,
                &gateway_address,
                gateway_text,
                sizeof(gateway_text)
            ) == NULL) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (snprintf(
                item,
                sizeof(item),
                "default via %s dev %s "
                "metric %lu flags 0x%lx",
                gateway_text,
                iface,
                metric,
                flags
            ) >= (int)sizeof(item)) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        status =
            add_item(
                set,
                item
            );

        if (status != COLLECT_OK) {
            goto out;
        }
    }

    if (ferror(stream) || errno != 0) {

        status =
            COLLECT_IO_ERROR;

        goto out;
    }

    status = COLLECT_OK;

    sort_set(set);

out:
    free(line);

    fclose(stream);

    return status;
}


static int hex_nibble(
    char c
)
{
    if (c >= '0' &&
        c <= '9') {

        return c - '0';
    }

    if (c >= 'a' &&
        c <= 'f') {

        return c - 'a' + 10;
    }

    if (c >= 'A' &&
        c <= 'F') {

        return c - 'A' + 10;
    }

    return -1;
}


static int decode_ipv6_hex(
    const char *text,
    struct in6_addr *address
)
{
    size_t i;

    if (strlen(text) != 32) {
        return -1;
    }

    for (i = 0;
         i < 16;
         i++) {

        int high;
        int low;

        high =
            hex_nibble(
                text[i * 2]
            );

        low =
            hex_nibble(
                text[i * 2 + 1]
            );

        if (high < 0 ||
            low < 0) {

            return -1;
        }

        address->s6_addr[i] =
            (unsigned char)(
                (high << 4) |
                low
            );
    }

    return 0;
}


static enum collect_status collect_ipv6_addresses(
    pid_t pid,
    struct network_set_info *set
)
{
    FILE *stream;

    char *line = NULL;

    size_t capacity = 0;

    enum collect_status status;

    stream =
        open_proc_net_file(
            pid,
            "if_inet6",
            &status
        );

    if (stream == NULL) {
        return status;
    }

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        char address_hex[33];
        char iface[64];

        unsigned int ifindex;
        unsigned int prefix_length;
        unsigned int scope;
        unsigned int flags;

        struct in6_addr address;

        char address_text[
            INET6_ADDRSTRLEN
        ];

        char item[
            NSDIFF_NET_ITEM_LEN
        ];

        int fields;

        fields = sscanf(
            line,
            "%32s "
            "%x "
            "%x "
            "%x "
            "%x "
            "%63s",
            address_hex,
            &ifindex,
            &prefix_length,
            &scope,
            &flags,
            iface
        );

        if (fields != 6) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (decode_ipv6_hex(
                address_hex,
                &address
            ) != 0) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (inet_ntop(
                AF_INET6,
                &address,
                address_text,
                sizeof(address_text)
            ) == NULL) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (snprintf(
                item,
                sizeof(item),
                "%s/%u dev %s "
                "ifindex %u scope 0x%x "
                "flags 0x%x",
                address_text,
                prefix_length,
                iface,
                ifindex,
                scope,
                flags
            ) >= (int)sizeof(item)) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        status =
            add_item(
                set,
                item
            );

        if (status != COLLECT_OK) {
            goto out;
        }
    }

    if (ferror(stream) || errno != 0) {

        status =
            COLLECT_IO_ERROR;

        goto out;
    }

    status = COLLECT_OK;

    sort_set(set);

out:
    free(line);

    fclose(stream);

    return status;
}


static bool ipv6_hex_is_zero(
    const char *text
)
{
    size_t i;

    for (i = 0;
         text[i] != '\0';
         i++) {

        if (text[i] != '0') {
            return false;
        }
    }

    return true;
}


static enum collect_status collect_ipv6_default_routes(
    pid_t pid,
    struct network_set_info *set
)
{
    FILE *stream;

    char *line = NULL;

    size_t capacity = 0;

    enum collect_status status;

    stream =
        open_proc_net_file(
            pid,
            "ipv6_route",
            &status
        );

    if (stream == NULL) {
        return status;
    }

    while (nsdiff_read_line(
               &line,
               &capacity,
               stream
           ) >= 0) {

        char destination[33];
        char source[33];
        char gateway[33];
        char iface[64];

        unsigned int destination_prefix;
        unsigned int source_prefix;

        unsigned long metric;
        unsigned long ref_count;
        unsigned long use;
        unsigned long flags;

        struct in6_addr gateway_address;

        char gateway_text[
            INET6_ADDRSTRLEN
        ];

        char item[
            NSDIFF_NET_ITEM_LEN
        ];

        int fields;

        fields = sscanf(
            line,
            "%32s "
            "%x "
            "%32s "
            "%x "
            "%32s "
            "%lx "
            "%lx "
            "%lx "
            "%lx "
            "%63s",
            destination,
            &destination_prefix,
            source,
            &source_prefix,
            gateway,
            &metric,
            &ref_count,
            &use,
            &flags,
            iface
        );

        if (fields != 10) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (destination_prefix != 0 ||
            !ipv6_hex_is_zero(
                destination
            )) {

            continue;
        }

        if (decode_ipv6_hex(
                gateway,
                &gateway_address
            ) != 0) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (inet_ntop(
                AF_INET6,
                &gateway_address,
                gateway_text,
                sizeof(gateway_text)
            ) == NULL) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        if (snprintf(
                item,
                sizeof(item),
                "default via %s dev %s "
                "metric %lu flags 0x%lx",
                gateway_text,
                iface,
                metric,
                flags
            ) >= (int)sizeof(item)) {

            status =
                COLLECT_PARSE_ERROR;

            goto out;
        }

        status =
            add_item(
                set,
                item
            );

        if (status != COLLECT_OK) {
            goto out;
        }
    }

    if (ferror(stream) || errno != 0) {

        status =
            COLLECT_IO_ERROR;

        goto out;
    }

    status = COLLECT_OK;

    sort_set(set);

out:
    free(line);

    fclose(stream);

    return status;
}


void network_collect(
    pid_t pid,
    struct network_info *info
)
{
    memset(
        info,
        0,
        sizeof(*info)
    );

    info->interfaces.status =
        collect_interfaces(
            pid,
            &info->interfaces
        );

    info->ipv4_default_routes.status =
        collect_ipv4_default_routes(
            pid,
            &info->ipv4_default_routes
        );

    info->ipv6_addresses.status =
        collect_ipv6_addresses(
            pid,
            &info->ipv6_addresses
        );

    info->ipv6_default_routes.status =
        collect_ipv6_default_routes(
            pid,
            &info->ipv6_default_routes
        );
}
