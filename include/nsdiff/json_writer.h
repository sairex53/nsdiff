#ifndef NSDIFF_JSON_WRITER_H
#define NSDIFF_JSON_WRITER_H
/* Legacy JSON v1 maps each input byte to the same-valued Unicode code point. */
void nsdiff_json_write_string(const char *text);
#endif
