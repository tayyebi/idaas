#include "b64.h"

#include <string.h>

static const char ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t b64url_encode(const unsigned char *in, size_t n, char *out)
{
    size_t o = 0, i = 0;
    for (; i + 3 <= n; i += 3) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[o++] = ALPHA[(v >> 18) & 63];
        out[o++] = ALPHA[(v >> 12) & 63];
        out[o++] = ALPHA[(v >> 6) & 63];
        out[o++] = ALPHA[v & 63];
    }
    size_t rem = n - i;
    if (rem == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = ALPHA[(v >> 18) & 63];
        out[o++] = ALPHA[(v >> 12) & 63];
    } else if (rem == 2) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
        out[o++] = ALPHA[(v >> 18) & 63];
        out[o++] = ALPHA[(v >> 12) & 63];
        out[o++] = ALPHA[(v >> 6) & 63];
    }
    out[o] = 0;
    return o;
}

int b64url_decode(const char *in, size_t n, unsigned char *out, size_t outsz, size_t *outlen)
{
    /* reverse table for both the URL-safe and standard alphabets */
    static signed char T[256];
    static int init = 0;
    if (!init) {
        memset(T, -1, sizeof T);
        for (int i = 0; i < 64; i++) {
            T[(unsigned char)ALPHA[i]] = (signed char)i;
            if (ALPHA[i] == '-')
                T[(unsigned char)'+'] = 62;
            if (ALPHA[i] == '_')
                T[(unsigned char)'/'] = 63;
        }
        init = 1;
    }

    while (n > 0 && in[n - 1] == '=')
        n--; /* tolerate padding */

    unsigned acc = 0;
    int nbits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        signed char v = T[(unsigned char)in[i]];
        if (v < 0)
            return -1;
        acc = (acc << 6) | (unsigned)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o >= outsz)
                return -1;
            out[o++] = (unsigned char)((acc >> nbits) & 0xff);
        }
    }
    if (nbits >= 6)
        return -1; /* dangling single character */
    *outlen = o;
    return 0;
}
