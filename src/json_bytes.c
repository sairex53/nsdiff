#include <stdlib.h>
#include <string.h>
#include "nsdiff/snapshot_internal.h"

/* A lexical resource guard, not a second JSON parser. Jansson validates grammar,
 * UTF-8, duplicates, integer range, escapes, trailing data and surrogate pairs. */
json_t *nsdiff_json_parse(const void *data, size_t size)
{
    const unsigned char *p = data;
    unsigned depth = 0, nodes = 0;
    size_t length = 0;
    bool quoted = false, escaped = false;
    json_error_t error;
    if (size == 0 || size > NSDIFF_DOCUMENT_MAX) return NULL;
    for (size_t i = 0; i < size; ++i) {
        unsigned char c = p[i];
        if (quoted) {
            if (++length > NSDIFF_JSON_STRING_MAX) return NULL;
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') {
            quoted = true;
            length = 0;
            if (++nodes > NSDIFF_JSON_NODES_MAX) return NULL;
        } else if (c == '{' || c == '[') {
            if (++depth > NSDIFF_JSON_DEPTH_MAX || ++nodes > NSDIFF_JSON_NODES_MAX) return NULL;
        } else if (c == '}' || c == ']') {
            if (depth == 0) return NULL;
            --depth;
        } else if (c == ',' && ++nodes > NSDIFF_JSON_NODES_MAX) return NULL;
    }
    if (quoted || depth) return NULL;
    return json_loadb(data, size, JSON_REJECT_DUPLICATES, &error);
}

json_t *nsdiff_json_bytes(const char *value, bool canonical)
{
    json_t *s = canonical ? NULL : json_string(value);
    const char *encoding = "utf-8";
    if (s == NULL) {
        static const char hex[] = "0123456789abcdef";
        size_t n = strlen(value);
        char *buf = malloc(n * 2 + 1);
        if (!buf) return NULL;
        for (size_t i = 0; i < n; ++i) {
            unsigned c = (unsigned char)value[i];
            buf[2*i] = hex[c >> 4];
            buf[2*i+1] = hex[c & 15];
        }
        buf[n*2] = 0;
        s = json_string(buf);
        free(buf);
        encoding = "hex";
    }
    if (!s) return NULL;
    return json_pack("{s:s,s:o}", "encoding", encoding, "value", s);
}

static int nibble(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int nsdiff_json_decode_bytes(const json_t *value, char *out, size_t capacity)
{
    const char *encoding = json_string_value(json_object_get(value, "encoding"));
    const json_t *v = json_object_get(value, "value");
    const char *text = json_string_value(v);
    size_t length = json_string_length(v);
    if (!encoding || !text || !capacity) return -1;
    if (!strcmp(encoding, "utf-8")) {
        if (length >= capacity || memchr(text, 0, length)) return -1;
        memcpy(out, text, length + 1);
        return 0;
    }
    if (strcmp(encoding, "hex") || length % 2 || length / 2 >= capacity) return -1;
    for (size_t i = 0; i < length / 2; ++i) {
        int a = nibble((unsigned char)text[2*i]);
        int b = nibble((unsigned char)text[2*i+1]);
        if (a < 0 || b < 0 || (a == 0 && b == 0)) return -1;
        out[i] = (char)((a << 4) | b);
    }
    out[length/2] = 0;
    return 0;
}
