#include "oauth.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ctx.h"
#include "accounts.h"
#include "choose.h"
#include "login.h"
#include "log.h"
#include "rnd.h"
#include "session.h"
#include "util.h"

static void hash_key(const char *token, char key[65])
{
    unsigned char h[32];
    sha256_buf(token, strlen(token), h);
    hex_encode(h, 32, key);
}

int oauth_issue_code(http_req *r, const authorize_req *a)
{
    char code[SESSION_TOKEN_BUF];
    if (rnd_token(code, 32) != 0)
        return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                              "Token generation failed.");

    struct auth_code ac;
    memset(&ac, 0, sizeof ac);
    snprintf(ac.client_id, sizeof ac.client_id, "%s", a->client->id);
    snprintf(ac.redirect_uri, sizeof ac.redirect_uri, "%s", a->redirect_uri);
    snprintf(ac.sub, sizeof ac.sub, "%s", a->username);
    snprintf(ac.nonce, sizeof ac.nonce, "%s", a->nonce ? a->nonce : "");
    snprintf(ac.scope, sizeof ac.scope, "%s", a->scope);
    snprintf(ac.challenge, sizeof ac.challenge, "%s", a->challenge ? a->challenge : "");
    snprintf(ac.sid, sizeof ac.sid, "%s", a->sid);
    ac.auth_time = a->auth_time;

    char key[65];
    hash_key(code, key);
    if (store_put(g_codes, key, &ac, sizeof ac, time(NULL) + g_cfg.code_ttl) != 0)
        return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                              "Could not store the authorization code.");

    sbuf loc;
    if (sbuf_init(&loc, 640) != 0)
        return MHD_NO;
    sbuf_adds(&loc, a->redirect_uri);
    sbuf_addch(&loc, strchr(a->redirect_uri, '?') ? '&' : '?');
    sbuf_adds(&loc, "code=");
    sbuf_adds(&loc, code);
    if (a->state && *a->state) {
        char *st = url_encode(a->state);
        sbuf_adds(&loc, "&state=");
        sbuf_adds(&loc, st ? st : "");
        free(st);
    }
    char *iss = url_encode(g_cfg.issuer);
    sbuf_adds(&loc, "&iss=");
    sbuf_adds(&loc, iss ? iss : "");
    free(iss);

    log_audit("authorize", a->username, req_peer_ip(r), "granted", a->client->id);
    int rc = res_redirect(r, loc.s);
    sbuf_free(&loc);
    return rc;
}

int oauth_pending_req(const session *s, const char *username, time_t auth_time,
                      const char *sid, authorize_req *out)
{
    const oauth_client *cl = config_find_client(&g_cfg, s->p_client);
    if (!cl || !client_redirect_ok(cl, s->p_redirect))
        return -1;
    memset(out, 0, sizeof *out);
    out->client = cl;
    out->redirect_uri = s->p_redirect;
    out->scope = s->p_scope;
    out->state = s->p_state;
    out->nonce = s->p_nonce;
    out->challenge = s->p_challenge;
    out->username = username;
    out->auth_time = auth_time;
    out->sid = sid;
    return 0;
}

int handle_authorize(http_req *r)
{
    const char *cid = req_param(r, "client_id");
    const char *ruri = req_param(r, "redirect_uri");
    const char *rtype = req_param(r, "response_type");
    const char *scope = req_param(r, "scope");
    const char *state = req_param(r, "state");
    const char *nonce = req_param(r, "nonce");
    const char *ch = req_param(r, "code_challenge");
    const char *cm = req_param(r, "code_challenge_method");

    /* an unknown client or redirect_uri must never be redirected to */
    const oauth_client *cl = config_find_client(&g_cfg, cid);
    if (!cl)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Bad request", "Unknown client_id.");
    if (!ruri || !client_redirect_ok(cl, ruri))
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Bad request", "Invalid redirect_uri.");

#define OERR(e, d) return res_oauth_error_redirect(r, ruri, (e), (d), state)

    if (!rtype || strcmp(rtype, "code") != 0)
        OERR("unsupported_response_type", "only response_type=code is supported");

    char granted[256];
    if (scope && *scope) {
        if (strlen(scope) >= sizeof granted || !scope_subset(scope, cl->scope))
            OERR("invalid_scope", "scope exceeds the client registration");
        if (!scope_has(scope, "openid"))
            OERR("invalid_scope", "the openid scope is required");
        snprintf(granted, sizeof granted, "%s", scope);
    } else {
        snprintf(granted, sizeof granted, "%s", cl->scope);
    }

    if (client_is_public(cl) && (!ch || !*ch))
        OERR("invalid_request", "public clients must use PKCE");
    if (ch && *ch) {
        if (!cm || strcmp(cm, "S256") != 0)
            OERR("invalid_request", "code_challenge_method must be S256");
        size_t chlen = strlen(ch);
        if (chlen < 43 || chlen > 128)
            OERR("invalid_request", "bad code_challenge");
    } else {
        ch = "";
    }
    if (!nonce || !*nonce || strlen(nonce) >= 250)
        OERR("invalid_request", "a nonce (1-250 chars) is required");
    if (state && strlen(state) >= 1000)
        OERR("invalid_request", "state is too long");

#undef OERR

    char tok[SESSION_TOKEN_BUF];
    session s;
    const char *ck = req_cookie(r, SESSION_COOKIE);
    if (ck && strlen(ck) == 43 &&
        session_snap(g_sessions, g_cfg.session_idle_s, ck, &s) == 0) {
        snprintf(tok, sizeof tok, "%s", ck);
    } else {
        if (session_start(g_sessions, g_cfg.session_abs_s, tok) != 0)
            return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                                  "Session error.");
        res_set_cookie(r, SESSION_COOKIE, tok, g_cfg.session_abs_s,
                       g_cfg.cookie_secure, 1, "Lax");
        if (session_snap(g_sessions, g_cfg.session_idle_s, tok, &s) != 0)
            return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                                  "Session error.");
    }

    /* The request always stops at an interstitial page so the user explicitly
     * confirms which account continues — even with a single logged-in
     * account. The pending request travels inside the session. */
    s.has_pending = 1;
    snprintf(s.p_client, sizeof s.p_client, "%s", cl->id);
    snprintf(s.p_redirect, sizeof s.p_redirect, "%s", ruri);
    snprintf(s.p_scope, sizeof s.p_scope, "%s", granted);
    snprintf(s.p_state, sizeof s.p_state, "%s", state ? state : "");
    snprintf(s.p_nonce, sizeof s.p_nonce, "%s", nonce);
    snprintf(s.p_challenge, sizeof s.p_challenge, "%s", ch);
    session_save(g_sessions, g_cfg.session_abs_s, tok, &s);

    req_cookie_kv kv[IDAAS_MAX_ACCOUNTS];
    size_t nkv = req_cookies_prefix(r, ACCT_COOKIE_PREFIX, kv, IDAAS_MAX_ACCOUNTS);
    account_entry accts[IDAAS_MAX_ACCOUNTS];
    int n = accounts_collect(kv, nkv, g_sessions, g_cfg.session_idle_s, tok, &s,
                             accts, IDAAS_MAX_ACCOUNTS);
    if (n > 0)
        return choose_render_page(r, &s, accts, n, NULL);
    return login_render_page(r, &s, NULL);
}
