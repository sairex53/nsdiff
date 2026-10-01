#ifndef NSDIFF_PROC_READ_H
#define NSDIFF_PROC_READ_H
#include <stdio.h>
#include <sys/types.h>
/* Bounded Linux text line reader; errno is zero at clean EOF. */
ssize_t nsdiff_read_line(char **line, size_t *capacity, FILE *stream);
#endif
