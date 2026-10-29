#include "jsonw.h"

#include <stdio.h>
#include <string.h>

static void jesc(sbuf *b, const char *s)
{
    static const char H[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"':  sbuf_adds(b, "\\\""); break;
        case '\\': sbuf_adds(b, "\\\\"); break;
        case '\b': sbuf_adds(b, "\\b"); break;
        case '\f': sbuf_adds(b, "\\f"); break;
        case '\n': sbuf_adds(b, "\\n"); break;
        case '\r': sbuf_adds(b, "\\r"); break;
        case '\t': sbuf_adds(b, "\\t"); break;
        default:
            if (c < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof tmp, "\\u00%c%c", H[c >> 4], H[c & 0xf]);
                sbuf_adds(b, tmp);
            } else {
                sbuf_addch(b, (char)c);
            }
        }
    }
}

/* Insert a member separator unless we are at the start of an object/array. */
static void sep(sbuf *b)
{
    if (b->len && b->s[b->len - 1] != '{' && b->s[b->len - 1] != '[')
        sbuf_addch(b, ',');
}

static void member_key(sbuf *b, const char *key)
{
    sep(b);
    sbuf_addch(b, '"');
    jesc(b, key);
    sbuf_adds(b, "\":");
}

void jw_obj_begin(sbuf *b, const char *key)
{
    if (key)
        member_key(b, key);
    else
        sep(b);
    sbuf_addch(b, '{');
}

void jw_obj_end(sbuf *b)
{
    sbuf_addch(b, '}');
}

void jw_arr_begin(sbuf *b, const char *key)
{
    if (key)
        member_key(b, key);
    else
        sep(b);
    sbuf_addch(b, '[');
}

void jw_arr_end(sbuf *b)
{
    sbuf_addch(b, ']');
}

void jw_str(sbuf *b, const char *key, const char *val)
{
    member_key(b, key);
    sbuf_addch(b, '"');
    jesc(b, val ? val : "");
    sbuf_addch(b, '"');
}

void jw_long(sbuf *b, const char *key, long long v)
{
    char t[32];
    snprintf(t, sizeof t, "%lld", v);
    member_key(b, key);
    sbuf_adds(b, t);
}

void jw_raw(sbuf *b, const char *key, const char *raw)
{
    member_key(b, key);
    sbuf_adds(b, raw ? raw : "null");
}

void jw_bool(sbuf *b, const char *key, int v)
{
    jw_raw(b, key, v ? "true" : "false");
}

void jw_arr_str(sbuf *b, const char *val)
{
    sep(b);
    sbuf_addch(b, '"');
    jesc(b, val ? val : "");
    sbuf_addch(b, '"');
}

void jw_str_arr(sbuf *b, const char *key, char *const *vals, size_t n)
{
    jw_arr_begin(b, key);
    for (size_t i = 0; i < n; i++)
        jw_arr_str(b, vals[i]);
    jw_arr_end(b);
}
