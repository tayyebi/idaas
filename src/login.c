#include "login.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "ctx.h"
#include "accounts.h"
#include "log.h"
#include "managed.h"
#include "oauth.h"
#include "pages.h"
#include "pam_auth.h"
#include "session.h"
#include "users.h"
#include "util.h"

/* ---------- login rate limiting ---------- */

struct rl_rec {
    int fails;
    time_t lock_until;
};

static void rl_key(char out[65], char kind, const char *v)
{
    char pre[320];
    snprintf(pre, sizeof pre, "%c:%s", kind, v ? v : "");
    unsigned char h[32];
    sha256_buf(pre, strlen(pre), h);
    hex_encode(h, 32, out);
}

static int rate_locked(const char *user, const char *ip)
{
    char key[65];
    struct rl_rec rec;
    time_t now = time(NULL);
    rl_key(key, 'u', user);
    if (store_get_copy(g_rl, key, &rec, sizeof rec) == 0 && now < rec.lock_until)
        return 1;
    rl_key(key, 'i', ip);
    if (store_get_copy(g_rl, key, &rec, sizeof rec) == 0 && now < rec.lock_until)
        return 1;
    return 0;
}

static void rate_fail(const char *user, const char *ip)
{
    time_t now = time(NULL);
    const char *who[2] = { user, ip };
    const char kind[2] = { 'u', 'i' };
    for (int i = 0; i < 2; i++) {
        char key[65];
        rl_key(key, kind[i], who[i] ? who[i] : "");
        struct rl_rec rec;
        memset(&rec, 0, sizeof rec);
        store_get_copy(g_rl, key, &rec, sizeof rec); /* missing is fine */
        rec.fails++;
        if (rec.fails >= 5) {
            int shift = rec.fails - 5;
            if (shift > 7)
                shift = 7;
            long backoff = 15L << shift; /* 15s, 30s, ... capped at 1920->900 */
            if (backoff > 900)
                backoff = 900;
            rec.lock_until = now + backoff;
        }
        store_put(g_rl, key, &rec, sizeof rec, now + 3600);
    }
}

static void rate_reset(const char *user, const char *ip)
{
    char key[65];
    rl_key(key, 'u', user);
    store_del(g_rl, key);
    rl_key(key, 'i', ip);
    store_del(g_rl, key);
}

/* ---------- pages ---------- */

int login_render_page(http_req *r, const session *s, const char *error)
{
    char sub[192];
    if (s->has_pending && s->p_client[0])
        snprintf(sub, sizeof sub, "Continue to %s", s->p_client);
    else
        snprintf(sub, sizeof sub, "Sign in with your Linux account");
    char *html = strtpl(PAGE_LOGIN, "SUB", sub, "ERROR", error ? error : "",
                        "CSRF", s->csrf, NULL);
    if (!html)
        return MHD_NO;
    return res_html(r, MHD_HTTP_OK, html);
}

/* ---------- handlers ---------- */

int handle_login_get(http_req *r)
{
    session s;
    const char *ck = req_cookie(r, SESSION_COOKIE);
    if (!ck || session_snap(g_sessions, g_cfg.session_idle_s, ck, &s) != 0) {
        char tok[SESSION_TOKEN_BUF];
        if (session_start(g_sessions, g_cfg.session_abs_s, tok) != 0)
            return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                                  "Session error.");
        res_set_cookie(r, SESSION_COOKIE, tok, g_cfg.session_abs_s,
                       g_cfg.cookie_secure, 1, "Lax");
        if (session_snap(g_sessions, g_cfg.session_idle_s, tok, &s) != 0)
            return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                                  "Session error.");
    }
    return login_render_page(r, &s, NULL);
}

int handle_login_post(http_req *r)
{
    const char *ck = req_cookie(r, SESSION_COOKIE);
    session s;
    if (!ck || session_snap(g_sessions, g_cfg.session_idle_s, ck, &s) != 0)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Session expired",
                              "Your login session expired. Restart the sign-in "
                              "from the application.");

    const char *csrf = req_form(r, "csrf");
    const char *user = req_form(r, "username");
    const char *pass = req_form(r, "password");
    if (!csrf || !user || !pass || !*user || !*pass)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Bad request",
                              "Missing username or password.");
    if (strlen(csrf) != strlen(s.csrf) || !ct_eq(csrf, s.csrf, strlen(s.csrf)))
        return res_error_page(r, MHD_HTTP_FORBIDDEN, "Forbidden",
                              "Form token mismatch. Reload the page and try again.");

    if (rate_locked(user, req_peer_ip(r))) {
        log_audit("login", user, req_peer_ip(r), "locked", "rate limit");
        return login_render_page(r, &s, "Too many attempts. Wait a minute and try again.");
    }

    /* private copies so the raw request buffer can be scrubbed afterwards */
    char username[64], password[256];
    snprintf(username, sizeof username, "%s", user);
    snprintf(password, sizeof password, "%s", pass);

    user_info ui;
    managed_user mu;
    auth_result ar = AUTH_INVALID;
    char detail[48] = "";
    if (managed_get(username, &mu) == 0) {
        /* API-managed account: verified locally with crypt_r, never PAM */
        if (!mu.disabled && managed_authenticate(username, password))
            ar = AUTH_OK;
        else
            snprintf(detail, sizeof detail, "managed auth failed");
    } else if (user_login_allowed(&g_cfg, username, &ui) != 0) {
        snprintf(detail, sizeof detail, "unknown or out-of-range account");
    } else {
        ar = pam_login(username, password, req_peer_ip(r));
    }

    OPENSSL_cleanse(password, sizeof password);

    if (ar != AUTH_OK) {
        rate_fail(username, req_peer_ip(r));
        if (ar == AUTH_ACCOUNT)
            snprintf(detail, sizeof detail, "account restricted");
        else if (ar == AUTH_ERROR)
            snprintf(detail, sizeof detail, "auth backend error");
        else if (!detail[0])
            snprintf(detail, sizeof detail, "bad credentials");
        log_audit("login", username, req_peer_ip(r), "failure", detail);
        /* identical message for every failure mode */
        return login_render_page(r, &s, "Invalid username or password.");
    }

    rate_reset(username, req_peer_ip(r));
    log_audit("login", username, req_peer_ip(r), "success", NULL);

    session n = s;
    n.authenticated = 1;
    snprintf(n.username, sizeof n.username, "%s", username);
    n.auth_time = time(NULL);

    /* A brand-new token (never the pre-auth one) keeps the fixation defense;
     * the old session is left intact so a remembered account that was active
     * before this login keeps its session and stays on the chooser. */
    char ntok[SESSION_TOKEN_BUF];
    if (session_fresh(g_sessions, g_cfg.session_abs_s, &n, ntok) != 0)
        return res_error_page(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Server error",
                              "Session error.");
    s.has_pending = 0; /* the pending request travels with the new session */
    session_save(g_sessions, g_cfg.session_abs_s, ck, &s);
    res_set_cookie(r, SESSION_COOKIE, ntok, g_cfg.session_abs_s,
                   g_cfg.cookie_secure, 1, "Lax");

    /* Remember the account on this browser unless the cap is exhausted. */
    req_cookie_kv kv[IDAAS_MAX_ACCOUNTS];
    size_t nkv = req_cookies_prefix(r, ACCT_COOKIE_PREFIX, kv, IDAAS_MAX_ACCOUNTS);
    account_entry accts[IDAAS_MAX_ACCOUNTS];
    int naccts = accounts_collect(kv, nkv, g_sessions, g_cfg.session_idle_s, ck, &s,
                                  accts, IDAAS_MAX_ACCOUNTS);
    int remembered = 0;
    for (int i = 0; i < naccts; i++)
        if (strcmp(accts[i].username, username) == 0)
            remembered = 1;
    if (remembered || naccts < IDAAS_MAX_ACCOUNTS) {
        char cname[32];
        acct_cookie_name(cname, username);
        res_set_cookie(r, cname, ntok, g_cfg.session_abs_s,
                       g_cfg.cookie_secure, 1, "Lax");
    }

    if (n.has_pending) {
        authorize_req arq;
        if (oauth_pending_req(&n, n.username, n.auth_time, ntok, &arq) == 0) {
            n.has_pending = 0;
            session_save(g_sessions, g_cfg.session_abs_s, ntok, &n);
            return oauth_issue_code(r, &arq);
        }
        n.has_pending = 0;
    }
    session_save(g_sessions, g_cfg.session_abs_s, ntok, &n);
    return res_error_page(r, MHD_HTTP_OK, "Signed in",
                          "You are signed in. You can close this window.");
}

int handle_logout(http_req *r)
{
    const char *ck = req_cookie(r, SESSION_COOKIE);
    session s;
    char who[64] = "";
    if (ck && session_snap(g_sessions, g_cfg.session_idle_s, ck, &s) == 0 && s.authenticated) {
        log_audit("logout", s.username, req_peer_ip(r), "success", NULL);
        snprintf(who, sizeof who, "%s", s.username);
    }
    if (ck)
        session_destroy(g_sessions, ck);
    res_set_cookie(r, SESSION_COOKIE, "", 0, g_cfg.cookie_secure, 1, "Lax");
    /* only the active account is signed out; other remembered accounts stay */
    if (who[0]) {
        char cname[32];
        acct_cookie_name(cname, who);
        res_set_cookie(r, cname, "", 0, g_cfg.cookie_secure, 1, "Lax");
    }

    const char *ppru = req_param(r, "post_logout_redirect_uri");
    const char *state = req_param(r, "state");
    /* Only registered per-client post_logout_redirect_uri entries bounce
       the browser back; anything else gets the plain signed-out page. */
    if (ppru && *ppru && config_post_logout_registered(&g_cfg, ppru)) {
        sbuf loc;
        if (sbuf_init(&loc, 512) == 0) {
            sbuf_adds(&loc, ppru);
            if (state && *state) {
                char *st = url_encode(state);
                sbuf_addch(&loc, strchr(ppru, '?') ? '&' : '?');
                sbuf_adds(&loc, "state=");
                sbuf_adds(&loc, st ? st : "");
                free(st);
            }
            int rc = res_redirect(r, loc.s);
            sbuf_free(&loc);
            return rc;
        }
    }
    return res_error_page(r, MHD_HTTP_OK, "Signed out", "You have been signed out.");
}
