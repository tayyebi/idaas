#include <stdio.h>
#include <string.h>

#include "util.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_pkce(void)
{
    /* RFC 7636 appendix B test vector */
    const char *verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const char *expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    char challenge[44];
    CHECK(pkce_s256(verifier, challenge) == 0);
    CHECK(strcmp(challenge, expected) == 0);
    CHECK(strlen(challenge) == 43);

    /* at_hash: b64url of the first 16 bytes of sha256(token) */
    const char *access = "some-access-token";
    char ah[23];
    CHECK(at_hash(access, ah) == 0);
    CHECK(strlen(ah) == 22);
    unsigned char h[32];
    sha256_buf(access, strlen(access), h);
    char manual[64];
    size_t n = 0;
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    /* manually b64url the first 16 bytes */
    unsigned acc_ = 0;
    int nbits = 0;
    for (size_t i = 0; i < 16; i++) {
        acc_ = (acc_ << 8) | h[i];
        nbits += 8;
        while (nbits >= 6) {
            nbits -= 6;
            manual[n++] = A[(acc_ >> nbits) & 63];
        }
    }
    if (nbits > 0)
        manual[n++] = A[(acc_ << (6 - nbits)) & 63];
    manual[n] = 0;
    CHECK(strcmp(ah, manual) == 0);

    return fails;
}
