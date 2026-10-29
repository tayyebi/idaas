#include "jwt_verify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "b64.h"

#define PAYLOAD_MAX 4096

static int jf_str(const char *j, const char *key, char *out, size_t n)
{
    char pat[96];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat);
    if (!p)
        return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p++ != ':')
        return -1;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p++ != '"')
        return -1;
    size_t i = 0;
    while (p[i] && p[i] != '"') {
        if (i + 1 >= n)
            return -1;
        out[i] = p[i];
        i++;
    }
    if (p[i] != '"')
        return -1;
    out[i] = 0;
    return 0;
}

static long jf_long(const char *j, const char *key, long dflt)
{
    char pat[96];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat);
    if (!p)
        return dflt;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p++ != ':')
        return dflt;
    while (*p == ' ' || *p == '\t')
        p++;
    return strtol(p, NULL, 10);
}

int jwt_verify_access(const signing_key *k, const char *issuer,
                      const char *token, access_claims *out)
{
    if (!k || !token)
        return -1;
    size_t tlen = strlen(token);
    if (tlen < 16 || tlen > 8192)
        return -1;

    const char *p1 = strchr(token, '.');
    if (!p1)
        return -1;
    const char *p2 = strchr(p1 + 1, '.');
    if (!p2 || strchr(p2 + 1, '.'))
        return -1;
    size_t plen = (size_t)(p2 - p1 - 1); /* payload segment length */
    if (plen == 0 || plen > PAYLOAD_MAX * 4 / 3)
        return -1;

    unsigned char payload[PAYLOAD_MAX + 1];
    char sig[512];
    size_t payload_len = 0, sig_len = 0;
    if (b64url_decode(p1 + 1, plen, payload, sizeof payload, &payload_len))
        return -1;
    payload[payload_len] = 0;
    if (b64url_decode(p2 + 1, strlen(p2 + 1), (unsigned char *)sig, sizeof sig - 1, &sig_len))
        return -1;

    /* verify RS256 over "<header>.<payload>" */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx &&
             EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, k->pkey) &&
             EVP_DigestVerifyUpdate(ctx, token, (size_t)(p2 - token)) &&
             EVP_DigestVerifyFinal(ctx, (unsigned char *)sig, sig_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok)
        return -1;

    memset(out, 0, sizeof *out);
    char iss[512];
    if (jf_str((const char *)payload, "iss", iss, sizeof iss) || strcmp(iss, issuer) != 0)
        return -1;
    if (jf_str((const char *)payload, "sub", out->sub, sizeof out->sub))
        return -1;
    if (jf_str((const char *)payload, "aud", out->aud, sizeof out->aud))
        return -1;
    jf_str((const char *)payload, "scope", out->scope, sizeof out->scope); /* optional */
    jf_str((const char *)payload, "jti", out->jti, sizeof out->jti);
    jf_str((const char *)payload, "sid", out->sid, sizeof out->sid);
    out->iat = jf_long((const char *)payload, "iat", 0);
    out->exp = jf_long((const char *)payload, "exp", 0);

    time_t now = time(NULL);
    if (out->exp <= now || out->iat > now + 300)
        return -1;
    return 0;
}
