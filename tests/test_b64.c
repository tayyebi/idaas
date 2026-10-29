#include <stdio.h>
#include <string.h>

#include "b64.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_b64(void)
{
    /* RFC 4648 test vectors (base64url, unpadded) */
    static const struct { const char *in, *out; } v[] = {
        { "", "" },
        { "f", "Zg" },
        { "fo", "Zm8" },
        { "foo", "Zm9v" },
        { "foob", "Zm9vYg" },
        { "fooba", "Zm9vYmE" },
        { "foobar", "Zm9vYmFy" },
    };
    char buf[64];
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        size_t n = b64url_encode((const unsigned char *)v[i].in, strlen(v[i].in), buf);
        CHECK(n == strlen(v[i].out));
        CHECK(strcmp(buf, v[i].out) == 0);
    }

    unsigned char out[64];
    size_t olen;
    CHECK(b64url_decode("Zm9vYmFy", 8, out, sizeof out, &olen) == 0);
    CHECK(olen == 6 && memcmp(out, "foobar", 6) == 0);
    CHECK(b64url_decode("Zm8=", 4, out, sizeof out, &olen) == 0); /* padded ok */
    CHECK(olen == 2 && out[0] == 'f' && out[1] == 'o');
    /* standard alphabet tolerated (expected bytes spelled out to dodge
     * the C11 trigraph in the ASCII spelling of this vector) */
    static const unsigned char trig[7] = { '<', '<', '?', '?', '?', '>', '>' };
    CHECK(b64url_decode("PDw/Pz8+Pg==", 12, out, sizeof out, &olen) == 0);
    CHECK(olen == 7 && memcmp(out, trig, 7) == 0);
    CHECK(b64url_decode("A!", 2, out, sizeof out, &olen) == -1);   /* bad char */
    CHECK(b64url_decode("A", 1, out, sizeof out, &olen) == -1);    /* dangling char */
    CHECK(b64url_decode("Zm9vYmFy", 8, out, 3, &olen) == -1);      /* undersized output */
    return fails;
}
