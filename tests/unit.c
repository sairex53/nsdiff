#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "nsdiff/snapshot_internal.h"
#include "nsdiff/proc_read.h"
int main(void)
{
    char bytes[256], restored[256];
    for (unsigned i = 1; i < 256; ++i) bytes[i-1] = (char)i;
    bytes[255] = 0;
    json_t *v = nsdiff_json_bytes(bytes, false); assert(v);
    assert(!nsdiff_json_decode_bytes(v, restored, sizeof(restored)));
    assert(!memcmp(bytes, restored, sizeof(bytes)));
    json_decref(v);
    const char *cases[] = {"{\"a\":1,\"a\":2}", "{\"a\":{\"b\":0,\"\\u0062\":1}}", "{\"a\":\"\xff\"}", "{\"a\":\"\\ud800\"}", "{\"a\":\"\\u0000\"}", "{}{}", "{\"n\":999999999999999999999999999}", "[NaN]", NULL};
    for (size_t i = 0; cases[i]; ++i) assert(!nsdiff_json_parse(cases[i], strlen(cases[i])));
    char deep[100]; memset(deep, '[', 40); memset(deep+40, ']', 40);
    assert(!nsdiff_json_parse(deep, 80));
    v = json_pack("{s:s,s:s}", "encoding", "hex", "value", "00"); assert(v);
    assert(nsdiff_json_decode_bytes(v, restored, sizeof(restored)) == -1); json_decref(v);
    char *line = NULL; size_t cap = 0;
    FILE *stream = fmemopen("abc\n", 4, "r"); assert(stream);
    assert(nsdiff_read_line(&line, &cap, stream) == 4 && !strcmp(line, "abc\n"));
    assert(nsdiff_read_line(&line, &cap, stream) == -1 && errno == 0);
    fclose(stream); free(line);
    char *big = malloc(65538); assert(big); memset(big, 'a', 65538);
    stream = fmemopen(big, 65538, "r"); assert(stream); line = NULL; cap = 0;
    assert(nsdiff_read_line(&line, &cap, stream) == -1 && errno == EOVERFLOW);
    fclose(stream); free(line); free(big);
    return 0;
}
