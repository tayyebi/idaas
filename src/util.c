#include "util.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "b64.h"

/* ---------- sbuf ---------- */

int sbuf_init(sbuf *b, size_t cap)
{
    if (cap < 64)
        cap = 64;
    b->s = malloc(cap);
    if (!b->s)
        return -1;
    b->s[0] = 0;
    b->len = 0;
    b->cap = cap;
    return 0;
}

void sbuf_free(sbuf *b)
{
    if (!b)
        return;
    free(b->s);
    b->s = NULL;
    b->len = b->cap = 0;
}

static int sbuf_grow(sbuf *b, size_t need)
{
    if (b->len + need + 1 <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap : 64;
    while (nc < b->len + need + 1)
        nc *= 2;
    char *n = realloc(b->s, nc);
    if (!n)
        return -1;
    b->s = n;
    b->cap = nc;
    return 0;
}

int sbuf_add(sbuf *b, const char *s, size_t n)
{
    if (!s || sbuf_grow(b, n))
        return -1;
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = 0;
    return 0;
}

int sbuf_adds(sbuf *b, const char *s)
{
    return s ? sbuf_add(b, s, strlen(s)) : 0;
}

int sbuf_addch(sbuf *b, char c)
{
    return sbuf_add(b, &c, 1);
}

int sbuf_addf(sbuf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0 || sbuf_grow(b, (size_t)need)) {
        va_end(ap2);
        return -1;
    }
    vsnprintf(b->s + b->len, (size_t)need + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)need;
    return 0;
}

/* ---------- hashing ---------- */

int sha256_buf(const void *data, size_t n, unsigned char out[32])
{
    return EVP_Digest(data, n, out, NULL, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

void hex_encode(const unsigned char *in, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* ---------- comparison ---------- */

int ct_eq(const void *a, const void *b, size_t n)
{
    return n == 0 || CRYPTO_memcmp(a, b, n) == 0;
}

/* Compares two secrets without leaking contents or length: hash a
 * length-prefixed encoding of each side, then compare digests. */
int secret_eq(const char *a, const char *b)
{
    unsigned char ha[32], hb[32], la[8], lb[8];
    uint64_t na = a ? strlen(a) : 0, nb = b ? strlen(b) : 0;
    for (int i = 0; i < 8; i++) {
        la[i] = (unsigned char)(na >> (56 - 8 * i));
        lb[i] = (unsigned char)(nb >> (56 - 8 * i));
    }
    if (sha256_buf(la, 8, ha) || sha256_buf(lb, 8, hb))
        return 0;
    /* fold the payload into the digest */
    EVP_MD_CTX *ca = EVP_MD_CTX_new(), *cb = EVP_MD_CTX_new();
    int ok = 0;
    if (ca && cb &&
        EVP_DigestInit_ex(ca, EVP_sha256(), NULL) && EVP_DigestInit_ex(cb, EVP_sha256(), NULL) &&
        EVP_DigestUpdate(ca, ha, 32) && EVP_DigestUpdate(cb, hb, 32) &&
        EVP_DigestUpdate(ca, a ? a : "", na) && EVP_DigestUpdate(cb, b ? b : "", nb) &&
        EVP_DigestFinal_ex(ca, ha, NULL) && EVP_DigestFinal_ex(cb, hb, NULL)) {
        ok = CRYPTO_memcmp(ha, hb, 32) == 0;
    }
    EVP_MD_CTX_free(ca);
    EVP_MD_CTX_free(cb);
    OPENSSL_cleanse(ha, 32);
    OPENSSL_cleanse(hb, 32);
    return ok;
}

/* ---------- percent-encoding ---------- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char *url_encode(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *out = malloc(3 * n + 1);
    if (!out)
        return NULL;
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = H[c >> 4];
            out[o++] = H[c & 0xf];
        }
    }
    out[o] = 0;
    return out;
}

int url_decode(const char *in, size_t n, char *out, size_t outsz)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '+') {
            if (o >= outsz) return -1;
            out[o++] = ' ';
        } else if (c == '%') {
            if (i + 2 >= n) return -1;
            int hi = hexval(in[i + 1]), lo = hexval(in[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            if (o >= outsz) return -1;
            out[o++] = (char)((hi << 4) | lo);
            i += 2;
        } else {
            if (o >= outsz) return -1;
            out[o++] = c;
        }
    }
    if (o >= outsz) return -1;
    out[o] = 0;
    return 0;
}

/* ---------- HTML escaping ---------- */

char *html_escape(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *out = malloc(6 * n + 1);
    if (!out)
        return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        switch (s[i]) {
        case '&':  memcpy(out + o, "&amp;", 5);  o += 5; break;
        case '<':  memcpy(out + o, "&lt;", 4);   o += 4; break;
        case '>':  memcpy(out + o, "&gt;", 4);   o += 4; break;
        case '"':  memcpy(out + o, "&quot;", 6); o += 6; break;
        case '\'': memcpy(out + o, "&#39;", 5);  o += 5; break;
        default:   out[o++] = s[i];
        }
    }
    out[o] = 0;
    return out;
}

/* ---------- misc ---------- */

char *str_trim(char *s)
{
    if (!s)
        return s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = 0;
    return s;
}

char *strtpl(const char *tpl, ...)
{
    char *cur = strdup(tpl ? tpl : "");
    if (!cur)
        return NULL;
    va_list ap;
    va_start(ap, tpl);
    for (;;) {
        const char *key = va_arg(ap, const char *);
        if (!key)
            break;
        const char *val = va_arg(ap, const char *);
        if (!val)
            val = "";
        char pat[128];
        snprintf(pat, sizeof pat, "{{%s}}", key);
        size_t count = 0;
        char *p = cur;
        size_t pl = strlen(pat), vl = strlen(val);
        while ((p = strstr(p, pat)) != NULL) {
            count++;
            p += pl;
        }
        if (!count)
            continue;
        size_t cl = strlen(cur);
        size_t room = cl + count * (vl > pl ? vl - pl : 0) + 1;
        char *out = malloc(room);
        if (!out) {
            free(cur);
            va_end(ap);
            return NULL;
        }
        char *w = out;
        p = cur;
        char *f;
        while ((f = strstr(p, pat)) != NULL) {
            memcpy(w, p, (size_t)(f - p));
            w += f - p;
            memcpy(w, val, vl);
            w += vl;
            p = f + pl;
        }
        strcpy(w, p);
        free(cur);
        cur = out;
    }
    va_end(ap);
    return cur;
}

/* ---------- PKCE / at_hash ---------- */

int pkce_s256(const char *verifier, char challenge[44])
{
    unsigned char h[32];
    if (!verifier || sha256_buf(verifier, strlen(verifier), h))
        return -1;
    b64url_encode(h, 32, challenge);
    return 0;
}

int at_hash(const char *access_token, char out[23])
{
    unsigned char h[32];
    if (!access_token || sha256_buf(access_token, strlen(access_token), h))
        return -1;
    b64url_encode(h, 16, out); /* 128 most-significant bits */
    return 0;
}

/* ---------- scopes ---------- */

int scope_has(const char *scopes, const char *one)
{
    size_t n = strlen(one);
    const char *p = scopes;
    while (p && *p) {
        while (*p == ' ')
            p++;
        const char *e = p;
        while (*e && *e != ' ')
            e++;
        if ((size_t)(e - p) == n && memcmp(p, one, n) == 0)
            return 1;
        p = e;
    }
    return 0;
}

int scope_subset(const char *sub, const char *superset)
{
    const char *p = sub;
    char tok[64];
    while (p && *p) {
        while (*p == ' ')
            p++;
        const char *e = p;
        while (*e && *e != ' ')
            e++;
        size_t n = (size_t)(e - p);
        if (!n)
            break;
        if (n >= sizeof tok)
            return 0;
        memcpy(tok, p, n);
        tok[n] = 0;
        if (!scope_has(superset, tok))
            return 0;
        p = e;
    }
    return 1;
}

/* ---------- CIDR (mynetworks) ---------- */

int cidr_parse(const char *spec, cidr *out)
{
    if (!spec || !*spec)
        return -1;
    char buf[64];
    if (strlen(spec) >= sizeof buf)
        return -1;
    snprintf(buf, sizeof buf, "%s", spec);
    str_trim(buf);

    char *slash = strchr(buf, '/');
    int bits = -1;
    if (slash) {
        *slash = 0;
        char *end = NULL;
        long b = strtol(slash + 1, &end, 10);
        if (!end || *end || b < 0)
            return -1;
        bits = (int)b;
    }

    memset(out, 0, sizeof *out);
    if (inet_pton(AF_INET, buf, out->bytes) == 1) {
        out->family = AF_INET;
        if (bits < 0)
            bits = 32;
        if (bits > 32)
            return -1;
    } else if (inet_pton(AF_INET6, buf, out->bytes) == 1) {
        out->family = AF_INET6;
        if (bits < 0)
            bits = 128;
        if (bits > 128)
            return -1;
    } else {
        return -1;
    }
    out->bits = bits;
    return 0;
}

int cidr_match(const cidr *c, const char *ip)
{
    if (!c || !ip)
        return 0;
    unsigned char b[16];
    int fam = 0;
    if (inet_pton(AF_INET6, ip, b) == 1) {
        fam = AF_INET6;
        /* v4-mapped (::ffff:a.b.c.d) compares as IPv4 */
        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
            b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
            b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff) {
            fam = AF_INET;
            memmove(b, b + 12, 4);
        }
    } else if (inet_pton(AF_INET, ip, b) == 1) {
        fam = AF_INET;
    } else {
        return 0;
    }
    if (fam != c->family)
        return 0;
    int full = c->bits / 8;
    int rem = c->bits % 8;
    if (full && memcmp(b, c->bytes, (size_t)full) != 0)
        return 0;
    if (rem) {
        unsigned char m = (unsigned char)((0xffu << (8 - rem)) & 0xffu);
        if ((b[full] & m) != (c->bytes[full] & m))
            return 0;
    }
    return 1;
}
