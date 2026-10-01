#include <stdio.h>
#include "nsdiff/json_writer.h"
void nsdiff_json_write_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p) {
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        default:
            if (*p < 32 || *p >= 127) printf("\\u%04x", (unsigned)*p);
            else putchar(*p);
        }
    }
    putchar('"');
}
