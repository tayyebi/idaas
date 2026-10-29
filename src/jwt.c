#include "jwt.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "b64.h"
#include "jsonw.h"
#include "log.h"

int keys_init(signing_key *k, const char *data_dir)
{
    memset(k, 0, sizeof *k);

    char base[512], dir[540], path[768];
    if (snprintf(base, sizeof base, "%s", data_dir) >= (int)sizeof base)
        return -1;
    mkdir(base, 0700); /* ok if it exists */
    snprintf(dir, sizeof dir, "%s/keys", base);
    mkdir(dir, 0700);
    snprintf(path, sizeof path, "%s/rsa.pem", dir);

    FILE *f = fopen(path, "r");
    EVP_PKEY *pk = NULL;
    if (f) {
        pk = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if (pk)
            LOG_INFO("loaded signing key %s", path);
        else
            LOG_WARN("unreadable key at %s; regenerating", path);
    }
    if (!pk) {
        pk = EVP_RSA_gen(2048);
        if (!pk) {
            LOG_ERROR("RSA key generation failed");
            return -1;
        }
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            LOG_ERROR("cannot write %s", path);
            EVP_PKEY_free(pk);
            return -1;
        }
        FILE *wf = fdopen(fd, "w");
        int ok = wf ? PEM_write_PrivateKey(wf, pk, NULL, NULL, 0, NULL, NULL) : 0;
        if (wf)
            fclose(wf);
        if (!ok) {
            LOG_ERROR("failed to persist key to %s", path);
            EVP_PKEY_free(pk);
            return -1;
        }
        LOG_INFO("generated new signing key %s", path);
    }
    k->pkey = pk;

    /* kid: first 8 bytes of SHA-256 over the public key DER, hex-encoded */
    unsigned char *der = NULL;
    int dlen = i2d_PUBKEY(pk, &der);
    if (dlen <= 0)
        return -1;
    unsigned char h[32];
    int rc = sha256_buf(der, (size_t)dlen, h);
    OPENSSL_free(der);
    if (rc)
        return -1;
    hex_encode(h, 8, k->kid);

    /* JWK n / e */
    BIGNUM *n = NULL, *e = NULL;
    if (!EVP_PKEY_get_bn_param(pk, "n", &n) || !EVP_PKEY_get_bn_param(pk, "e", &e))
        return -1;
    unsigned char nb[512], eb[16];
    int nl = BN_num_bytes(n), el = BN_num_bytes(e);
    if (nl <= 0 || nl > (int)sizeof nb || el <= 0 || el > (int)sizeof eb) {
        BN_free(n);
        BN_free(e);
        return -1;
    }
    BN_bn2bin(n, nb);
    BN_bn2bin(e, eb);
    b64url_encode(nb, (size_t)nl, k->n_b64);
    b64url_encode(eb, (size_t)el, k->e_b64);
    BN_free(n);
    BN_free(e);
    return 0;
}

int jwt_sign_rs256(const signing_key *k, const char *payload_json, char **out)
{
    char hdr[160];
    int hl = snprintf(hdr, sizeof hdr,
                      "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"%s\"}", k->kid);
    size_t plen = strlen(payload_json);
    size_t hcap = ((size_t)hl + 2) / 3 * 4 + 8;
    size_t pcap = (plen + 2) / 3 * 4 + 8;
    char *h64 = malloc(hcap), *p64 = malloc(pcap);
    if (!h64 || !p64) {
        free(h64);
        free(p64);
        return -1;
    }
    size_t hlen = b64url_encode((const unsigned char *)hdr, (size_t)hl, h64);
    size_t plen64 = b64url_encode((const unsigned char *)payload_json, plen, p64);

    char *signing_input = malloc(hlen + plen64 + 2);
    if (!signing_input) {
        free(h64);
        free(p64);
        return -1;
    }
    snprintf(signing_input, hlen + plen64 + 2, "%s.%s", h64, p64);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sig[512];
    size_t slen = 0;
    int ok = ctx &&
             EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, k->pkey) &&
             EVP_DigestSignUpdate(ctx, signing_input, strlen(signing_input)) &&
             EVP_DigestSignFinal(ctx, NULL, &slen) &&
             slen <= sizeof sig &&
             EVP_DigestSignFinal(ctx, sig, &slen);
    EVP_MD_CTX_free(ctx);
    int rc = -1;
    if (ok) {
        size_t scap = (slen + 2) / 3 * 4 + 8;
        char *s64 = malloc(scap);
        char *res = malloc(hlen + plen64 + scap + 4);
        if (s64 && res) {
            b64url_encode(sig, slen, s64);
            snprintf(res, hlen + plen64 + scap + 4, "%s.%s.%s", h64, p64, s64);
            *out = res;
            rc = 0;
        }
        free(s64);
    }
    free(signing_input);
    free(h64);
    free(p64);
    return rc;
}

int jwks_json(const signing_key *k, sbuf *out)
{
    jw_obj_begin(out, NULL);
    jw_arr_begin(out, "keys");
    jw_obj_begin(out, NULL);
    jw_str(out, "kty", "RSA");
    jw_str(out, "use", "sig");
    jw_str(out, "alg", "RS256");
    jw_str(out, "kid", k->kid);
    jw_str(out, "n", k->n_b64);
    jw_str(out, "e", k->e_b64);
    jw_obj_end(out);
    jw_arr_end(out);
    jw_obj_end(out);
    return 0;
}
