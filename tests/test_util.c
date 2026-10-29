#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "util.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_util(void)
{
    /* sbuf */
    sbuf b;
    CHECK(sbuf_init(&b, 8) == 0);
    CHECK(sbuf_adds(&b, "foo") == 0);
    CHECK(sbuf_addch(&b, '!') == 0);
    CHECK(sbuf_addf(&b, "-%d", 7) == 0);
    CHECK(strcmp(b.s, "foo!-7") == 0);
    sbuf_free(&b);

    /* sha256("abc") */
    unsigned char h[32];
    char hex[65];
    CHECK(sha256_buf("abc", 3, h) == 0);
    hex_encode(h, 32, hex);
    CHECK(strcmp(hex,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    /* constant-time compares */
    CHECK(ct_eq("x", "x", 2) == 1);
    CHECK(ct_eq("x", "y", 2) == 0);
    CHECK(secret_eq("s3cret", "s3cret") == 1);
    CHECK(secret_eq("s3cret", "s3cret2") == 0);
    CHECK(secret_eq("", "") == 1);
    CHECK(secret_eq("a", "b") == 0);

    /* url encode/decode */
    char *e = url_encode("a b/c~d");
    CHECK(e && strcmp(e, "a%20b%2Fc~d") == 0);
    free(e);
    char d[64];
    CHECK(url_decode("a+b%2Fc", 7, d, sizeof d) == 0);
    CHECK(strcmp(d, "a b/c") == 0);
    CHECK(url_decode("a%2", 3, d, sizeof d) == -1);
    CHECK(url_decode("a%ZZ", 4, d, sizeof d) == -1);

    /* strtpl */
    char *t = strtpl("x{{A}}y{{A}}!", "A", "Z", NULL);
    CHECK(t && strcmp(t, "xZyZ!") == 0);
    free(t);
    t = strtpl("no placeholders", "A", "Z", NULL);
    CHECK(t && strcmp(t, "no placeholders") == 0);
    free(t);

    /* scopes */
    CHECK(scope_has("openid profile", "profile") == 1);
    CHECK(scope_has("openid profile", "prof") == 0);
    CHECK(scope_has("openid profile", "openid") == 1);
    CHECK(scope_subset("openid email", "openid profile email") == 1);
    CHECK(scope_subset("openid admin", "openid profile email") == 0);
    CHECK(scope_subset("", "openid") == 1);

    /* CIDR parse/match (mynetworks) */
    cidr c;
    CHECK(cidr_parse("10.0.0.0/8", &c) == 0);
    CHECK(cidr_match(&c, "10.1.2.3") == 1);
    CHECK(cidr_match(&c, "11.1.2.3") == 0);
    CHECK(cidr_match(&c, "::ffff:10.1.2.3") == 1); /* v4-mapped */
    CHECK(cidr_parse("192.168.1.5", &c) == 0);     /* no prefix = /32 */
    CHECK(cidr_match(&c, "192.168.1.5") == 1);
    CHECK(cidr_match(&c, "192.168.1.6") == 0);
    CHECK(cidr_parse("172.16.0.0/12", &c) == 0);
    CHECK(cidr_match(&c, "172.31.255.254") == 1);
    CHECK(cidr_match(&c, "172.32.0.1") == 0);
    CHECK(cidr_parse("::1/128", &c) == 0);
    CHECK(cidr_match(&c, "::1") == 1);
    CHECK(cidr_match(&c, "::2") == 0);
    CHECK(cidr_match(&c, "127.0.0.1") == 0); /* family mismatch */
    CHECK(cidr_parse("0.0.0.0/0", &c) == 0);
    CHECK(cidr_match(&c, "8.8.8.8") == 1);
    CHECK(cidr_parse("10.0.0.0/33", &c) == -1);
    CHECK(cidr_parse("::/129", &c) == -1);
    CHECK(cidr_parse("300.0.0.1", &c) == -1);
    CHECK(cidr_parse("garbage", &c) == -1);
    CHECK(cidr_parse("", &c) == -1);

    return fails;
}
