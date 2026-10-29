#ifndef IDAAS_JSONW_H
#define IDAAS_JSONW_H

#include <stddef.h>

#include "util.h"

/* Minimal JSON *writer* on top of sbuf. Members/items are separated
 * automatically. Callers must keep begin/end pairs balanced. */

void jw_obj_begin(sbuf *b, const char *key);   /* key==NULL: root/anonymous */
void jw_obj_end(sbuf *b);
void jw_arr_begin(sbuf *b, const char *key);
void jw_arr_end(sbuf *b);

void jw_str(sbuf *b, const char *key, const char *val);
void jw_long(sbuf *b, const char *key, long long v);
void jw_raw(sbuf *b, const char *key, const char *raw_json_or_number);
void jw_bool(sbuf *b, const char *key, int v);

/* String item inside an open array. */
void jw_arr_str(sbuf *b, const char *val);
/* Convenience: "key": [v0, v1, ...] */
void jw_str_arr(sbuf *b, const char *key, char *const *vals, size_t n);

#endif
