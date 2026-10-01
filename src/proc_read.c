#include <errno.h>
#include <stdlib.h>
#include "nsdiff/proc_read.h"
#define PROC_LINE_MAX 65536U
ssize_t nsdiff_read_line(char **line, size_t *capacity, FILE *stream)
{
    size_t n = 0;
    errno = 0;
    if (*capacity < PROC_LINE_MAX+1) {
        char *p = realloc(*line, PROC_LINE_MAX+1);
        if (!p) return -1;
        *line = p; *capacity = PROC_LINE_MAX+1;
    }
    while (n < PROC_LINE_MAX) {
        int c = fgetc(stream);
        if (c == EOF) {
            if (ferror(stream) && errno == EINTR) { clearerr(stream); errno = 0; continue; }
            if (ferror(stream) || !n) return -1;
            break;
        }
        if (!c) { errno = EPROTO; return -1; }
        (*line)[n++] = (char)c;
        if (c == '\n') break;
    }
    if (n == PROC_LINE_MAX && (*line)[n-1] != '\n') { errno = EOVERFLOW; return -1; }
    (*line)[n] = 0;
    return (ssize_t)n;
}
