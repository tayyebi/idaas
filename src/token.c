#include "token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/crypto.h>

#include "b64.h"
#include "ctx.h"
#include "jsonw.h"
#include "jwt.h"
#include "log.h"
#include "oauth.h"
#include "rnd.h"
#include "users.h"
#include "util.h"

struct refresh_rec {
    char client_id[128];
    char sub[64];
    char scope[256];
    char sid[SESSION_TOKEN_BUF];
    time_t auth_time;
};

static void hash_key(const char *token, char key[65])
{
    unsigned char h[32];
    sha256_buf(token, strlen(token), h);
    hex_encode(h, 32, key);
}

/* RFC 6749 §2.3.1 HTTP Basic client auth (both alphabets accepted on the
 * base64 payload; the id/secret are additionally form-decoded). */
static int get_basic_auth(http_req *r, char *id, size_t idn, char *secret, size_t secn)
{
    const char *h = req_header(r, "Authorization");
    if (!h || strncasecmp(h, "Basic ", 6) != 0)
        return -1;
    h += 6;
    while (*h == ' ')
        h++;
    unsigned char raw[768];
    size_t rawlen = 0;
    if (b64url_decode(h, strlen(h), raw, sizeof raw - 1, &rawlen) != 0)
        return -1;
    raw[rawlen] = 0;
    char *colon = strchr((char *)raw, ':');
    if (!colon)
        return -1;
    *colon = 0;
    char idd[256], sec[256];
    if (url_decode((const char *)raw, strlen((const char *)raw), idd, sizeof idd) != 0)
        return -1;
    if (url_decode(colon + 1, strlen(colon + 1), sec, sizeof sec) != 0)
        return -1;
    if (!*idd || strlen(idd) >= idn || strlen(sec) >= secn)
        return -1;
    snprintf(id, idn, "%s", idd);
    snprintf(secret, secn, "%s", sec);
    OPENSSL_cleanse(raw, sizeof raw);
    OPENSSL_cleanse(sec, sizeof sec);
    return 0;
}

static void access_claims(sbuf *p, const char *sub, const oauth_client *cl,
                          const char *scope, const char *jti, const char *sid)
{
    time_t now = time(NULL);
    jw_obj_begin(p, NULL);
    jw_str(p, "iss", g_cfg.issuer);
    jw_str(p, "sub", sub);
    jw_str(p, "aud", cl->id);
    jw_long(p, "exp", (long long)(now + g_cfg.access_ttl));
    jw_long(p, "iat", (long long)now);
    jw_str(p, "jti", jti);
    jw_str(p, "scope", scope);
    jw_str(p, "sid", sid);
    jw_obj_end(p);
}

static void id_token_claims(sbuf *p, const char *sub, const oauth_client *cl,
                            const char *scope, const char *nonce, time_t auth_time,
                            const char *sid, const char *access_token)
{
    time_t now = time(NULL);
    jw_obj_begin(p, NULL);
    jw_str(p, "iss", g_cfg.issuer);
    jw_str(p, "sub", sub);
    jw_str(p, "aud", cl->id);
    jw_long(p, "exp", (long long)(now + g_cfg.access_ttl));
    jw_long(p, "iat", (long long)now);
    jw_long(p, "auth_time", (long long)auth_time);
    if (nonce && *nonce)
        jw_str(p, "nonce", nonce);
    char ah[23];
    if (access_token && at_hash(access_token, ah) == 0)
        jw_str(p, "at_hash", ah);
    jw_str(p, "sid", sid);
    users_add_claims(p, &g_cfg, sub, scope);
    jw_obj_end(p);
}

static int store_refresh(struct refresh_rec *rr, char rt_out[SESSION_TOKEN_BUF])
{
    if (rnd_token(rt_out, 32) != 0)
        return -1;
    char key[65];
    hash_key(rt_out, key);
    return store_put(g_refresh, key, rr, sizeof *rr, time(NULL) + g_cfg.refresh_ttl);
}

static int token_response(http_req *r, const char *access, const char *idt,
                          const char *refresh, const char *scope)
{
    sbuf b;
    if (sbuf_init(&b, 512) != 0)
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "access_token", access);
    jw_str(&b, "token_type", "Bearer");
    jw_long(&b, "expires_in", g_cfg.access_ttl);
    if (refresh)
        jw_str(&b, "refresh_token", refresh);
    jw_str(&b, "scope", scope);
    if (idt)
        jw_str(&b, "id_token", idt);
    jw_obj_end(&b);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

static int grant_code(http_req *r, const oauth_client *cl)
{
    const char *code = req_form(r, "code");
    const char *ruri = req_form(r, "redirect_uri");
    const char *verifier = req_form(r, "code_verifier");
    if (!code || !*code)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "code is required");

    char key[65];
    hash_key(code, key);
    struct auth_code *acp = store_take(g_codes, key);
    if (!acp)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                              "unknown or expired code");
    struct auth_code ac = *acp;
    free(acp);

    if (strcmp(ac.client_id, cl->id) != 0)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                              "code was not issued to this client");
    if (!ruri || strcmp(ac.redirect_uri, ruri) != 0)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                              "redirect_uri mismatch");
    if (ac.challenge[0]) {
        char calc[44];
        if (!verifier || pkce_s256(verifier, calc) != 0 || strcmp(calc, ac.challenge) != 0) {
            log_audit("token", ac.sub, req_peer_ip(r), "failure", "PKCE verification failed");
            return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                                  "PKCE verification failed");
        }
    } else if (client_is_public(cl)) {
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant", "PKCE required");
    }

    char jti[24];
    if (rnd_token(jti, 16) != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    sbuf pclaims;
    char *access = NULL, *idt = NULL;
    int rc;
    if (sbuf_init(&pclaims, 256) != 0)
        return MHD_NO;
    access_claims(&pclaims, ac.sub, cl, ac.scope, jti, ac.sid);
    rc = jwt_sign_rs256(&g_key, pclaims.s, &access);
    sbuf_free(&pclaims);
    if (rc != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);

    struct refresh_rec rr;
    memset(&rr, 0, sizeof rr);
    snprintf(rr.client_id, sizeof rr.client_id, "%s", cl->id);
    snprintf(rr.sub, sizeof rr.sub, "%s", ac.sub);
    snprintf(rr.scope, sizeof rr.scope, "%s", ac.scope);
    snprintf(rr.sid, sizeof rr.sid, "%s", ac.sid);
    rr.auth_time = ac.auth_time;
    char rt[SESSION_TOKEN_BUF];
    if (store_refresh(&rr, rt) != 0) {
        free(access);
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    }

    sbuf iclaims;
    if (sbuf_init(&iclaims, 256) != 0) {
        free(access);
        return MHD_NO;
    }
    id_token_claims(&iclaims, ac.sub, cl, ac.scope, ac.nonce, ac.auth_time, ac.sid, access);
    rc = jwt_sign_rs256(&g_key, iclaims.s, &idt);
    sbuf_free(&iclaims);
    if (rc != 0) {
        free(access);
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    }

    log_audit("token", ac.sub, req_peer_ip(r), "success", cl->id);
    rc = token_response(r, access, idt, rt, ac.scope);
    free(access);
    free(idt);
    return rc;
}

static int grant_refresh(http_req *r, const oauth_client *cl)
{
    const char *rt = req_form(r, "refresh_token");
    if (!rt || !*rt)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "refresh_token is required");

    char key[65];
    hash_key(rt, key);
    struct refresh_rec *rrp = store_take(g_refresh, key);
    if (!rrp)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                              "unknown or expired refresh token");
    struct refresh_rec rr = *rrp;
    free(rrp);

    if (strcmp(rr.client_id, cl->id) != 0)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_grant",
                              "token was not issued to this client");

    const char *scopereq = req_form(r, "scope");
    const char *granted = rr.scope;
    char narrowed[256];
    if (scopereq && *scopereq) {
        if (strlen(scopereq) >= sizeof narrowed || !scope_subset(scopereq, rr.scope))
            return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_scope", NULL);
        snprintf(narrowed, sizeof narrowed, "%s", scopereq);
        granted = narrowed;
    }

    char jti[24];
    if (rnd_token(jti, 16) != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    sbuf pclaims;
    char *access = NULL, *idt = NULL;
    int rc;
    if (sbuf_init(&pclaims, 256) != 0)
        return MHD_NO;
    access_claims(&pclaims, rr.sub, cl, granted, jti, rr.sid);
    rc = jwt_sign_rs256(&g_key, pclaims.s, &access);
    sbuf_free(&pclaims);
    if (rc != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);

    struct refresh_rec nr = rr;
    snprintf(nr.scope, sizeof nr.scope, "%s", granted);
    char nrt[SESSION_TOKEN_BUF];
    if (store_refresh(&nr, nrt) != 0) {
        free(access);
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    }

    sbuf iclaims;
    if (sbuf_init(&iclaims, 256) != 0) {
        free(access);
        return MHD_NO;
    }
    id_token_claims(&iclaims, rr.sub, cl, granted, NULL, rr.auth_time, rr.sid, access);
    rc = jwt_sign_rs256(&g_key, iclaims.s, &idt);
    sbuf_free(&iclaims);
    if (rc != 0) {
        free(access);
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    }

    log_audit("token", rr.sub, req_peer_ip(r), "success", "refresh");
    rc = token_response(r, access, idt, nrt, granted);
    free(access);
    free(idt);
    return rc;
}

int handle_token(http_req *r)
{
    if (strcmp(req_method(r), "POST") != 0)
        return res_error_json(r, MHD_HTTP_METHOD_NOT_ALLOWED, "invalid_request",
                              "POST required");

    char bid[128], bsec[192];
    int have_basic = get_basic_auth(r, bid, sizeof bid, bsec, sizeof bsec) == 0;
    const char *cid = have_basic ? bid : req_form(r, "client_id");
    const char *csec = have_basic ? bsec : req_form(r, "client_secret");
    if (!cid || !*cid)
        return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "invalid_client",
                              "client authentication required");
    const oauth_client *cl = config_find_client(&g_cfg, cid);
    if (!cl)
        return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "invalid_client", "unknown client");
    if (!client_is_public(cl)) {
        if (!csec || !*csec || !secret_eq(cl->secret, csec)) {
            log_audit("token", cid, req_peer_ip(r), "failure", "client auth failed");
            return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "invalid_client",
                                  "bad client credentials");
        }
    }

    const char *gt = req_form(r, "grant_type");
    if (!gt || !*gt)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "grant_type is required");
    if (strcmp(gt, "authorization_code") == 0)
        return grant_code(r, cl);
    if (strcmp(gt, "refresh_token") == 0)
        return grant_refresh(r, cl);
    return res_error_json(r, MHD_HTTP_BAD_REQUEST, "unsupported_grant_type", NULL);
}
