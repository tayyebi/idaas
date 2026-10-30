#ifndef IDAAS_UTIL_H
#define IDAAS_UTIL_H

#include <stddef.h>

/* Growable string buffer. */
typedef struct sbuf {
    char *s;
    size_t len, cap;
} sbuf;

int  sbuf_init(sbuf *b, size_t cap);
void sbuf_free(sbuf *b);           /* safe on NULL / already-freed */
int  sbuf_add(sbuf *b, const char *s, size_t n);
int  sbuf_adds(sbuf *b, const char *s);
int  sbuf_addch(sbuf *b, char c);
int  sbuf_addf(sbuf *b, const char *fmt, ...);

/* SHA-256 helpers (OpenSSL EVP). */
int  sha256_buf(const void *data, size_t n, unsigned char out[32]);
void hex_encode(const unsigned char *in, size_t n, char *out); /* out: 2n+1 bytes */

/* Constant-time comparison. */
int ct_eq(const void *a, const void *b, size_t n);      /* 1 == equal */
int secret_eq(const char *a, const char *b);            /* length-independent, hashes both sides */

/* Percent-encoding (application/x-www-form-urlencoded). */
char *url_encode(const char *s);                        /* caller frees */
int   url_decode(const char *in, size_t n, char *out, size_t outsz); /* '+' and %XX */

/* HTML entity escaping (& < > " '). Caller frees. */
char *html_escape(const char *s);

/* In-place whitespace trim, returns s. */
char *str_trim(char *s);

/* Template expansion: strtpl(tpl, "KEY", val, ..., NULL) replaces {{KEY}}. Caller frees. */
char *strtpl(const char *tpl, ...);

/* PKCE S256: b64url(sha256(verifier)) -> challenge (43 chars, buffer of 44+). */
int pkce_s256(const char *verifier, char challenge[44]);

/* OIDC at_hash: b64url of the first 16 bytes of sha256(access_token) (22 chars, buffer 23+). */
int at_hash(const char *access_token, char out[23]);

/* Space-separated scope lists. */
int scope_has(const char *scopes, const char *one);
int scope_subset(const char *sub, const char *superset);

/* CIDR parsing/matching (Postfix-mynetworks style).
 * bytes[] holds 4 bytes for AF_INET, 16 for AF_INET6. */
typedef struct cidr {
    int family;
    unsigned char bytes[16];
    int bits;
} cidr;

/* Parse "10.0.0.0/8", "192.168.1.5" (no prefix = /32 or /128), "::1/128".
 * Returns 0 on success, -1 on invalid input. */
int cidr_parse(const char *spec, cidr *out);

/* 1 if ip (IPv4, IPv6, or v4-mapped IPv6) falls inside c. */
int cidr_match(const cidr *c, const char *ip);

#endif
