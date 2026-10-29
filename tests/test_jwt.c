#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "jwt.h"
#include "jwt_verify.h"
#include "util.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_jwt(void)
{
    char dir[] = "/tmp/idaas-jwt-test-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);

    signing_key k;
    CHECK(keys_init(&k, dir) == 0);
    CHECK(strlen(k.kid) == 16);
    CHECK(k.n_b64[0] != 0 && k.e_b64[0] != 0);

    /* JWKS document */
    sbuf jw;
    CHECK(sbuf_init(&jw, 512) == 0);
    CHECK(jwks_json(&k, &jw) == 0);
    CHECK(strstr(jw.s, "\"kty\":\"RSA\"") != NULL);
    CHECK(strstr(jw.s, k.kid) != NULL);
    CHECK(strstr(jw.s, k.n_b64) != NULL);
    sbuf_free(&jw);

    /* reloading the same data dir yields the same key */
    signing_key k2;
    CHECK(keys_init(&k2, dir) == 0);
    CHECK(strcmp(k2.kid, k.kid) == 0);

    /* sign + verify roundtrip */
    char payload[512];
    snprintf(payload, sizeof payload,
             "{\"iss\":\"https://sso.example.com\",\"sub\":\"alice\",\"aud\":\"app\","
             "\"exp\":%ld,\"iat\":%ld,\"jti\":\"j1\",\"scope\":\"openid profile\","
             "\"sid\":\"s1\"}",
             (long)(time(NULL) + 600), (long)time(NULL));
    char *tok = NULL;
    CHECK(jwt_sign_rs256(&k, payload, &tok) == 0);
    CHECK(tok && strchr(tok, '.') != NULL);

    access_claims c;
    CHECK(jwt_verify_access(&k, "https://sso.example.com", tok, &c) == 0);
    CHECK(strcmp(c.sub, "alice") == 0);
    CHECK(strcmp(c.aud, "app") == 0);
    CHECK(strcmp(c.scope, "openid profile") == 0);
    CHECK(strcmp(c.jti, "j1") == 0);

    /* wrong issuer */
    CHECK(jwt_verify_access(&k, "https://other.example", tok, &c) == -1);

    /* tampered payload */
    char *p = strchr(tok, '.') + 1;
    *p = (*p == 'A') ? 'B' : 'A';
    CHECK(jwt_verify_access(&k, "https://sso.example.com", tok, &c) == -1);
    free(tok);

    /* expired token */
    snprintf(payload, sizeof payload,
             "{\"iss\":\"https://sso.example.com\",\"sub\":\"alice\",\"aud\":\"app\","
             "\"exp\":%ld,\"iat\":%ld}",
             (long)(time(NULL) - 10), (long)(time(NULL) - 20));
    CHECK(jwt_sign_rs256(&k, payload, &tok) == 0);
    CHECK(jwt_verify_access(&k, "https://sso.example.com", tok, &c) == -1);
    free(tok);

    /* garbage */
    CHECK(jwt_verify_access(&k, "https://sso.example.com", "not-a-jwt", &c) == -1);
    CHECK(jwt_verify_access(&k, "https://sso.example.com", "aaa.bbb", &c) == -1);

    return fails;
}
