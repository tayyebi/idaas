#include "choose.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "ctx.h"
#include "login.h"
#include "oauth.h"
#include "pages.h"
#include "util.h"

/* ---------- page ---------- */

static int add_account_row(sbuf *b, const session *s, const account_entry *a)
{
    char *user = html_escape(a->username);
    if (!user)
        return -1;
    char ava[2] = { (char)toupper((unsigned char)a->username[0]), 0 };
    int rc = sbuf_addf(b,
                       "<form method=\"post\" action=\"/choose\" class=\"acct\">"
                       "<input type=\"hidden\" name=\"csrf\" value=\"%s\">"
                       "<input type=\"hidden\" name=\"acct\" value=\"%s\">"
                       "<button type=\"submit\" class=\"row\">"
                       "<span class=\"ava\">%s</span><span class=\"who\">%s</span>"
                       "<span class=\"go\">&rarr;</span></button></form>",
                       s->csrf, user, ava, user);
    free(user);
    return rc;
}

int choose_render_page(http_req *r, const session *s,
                       const account_entry *accts, int n, const char *error)
{
    char sub[192];
    if (s->has_pending && s->p_client[0])
        snprintf(sub, sizeof sub, "Continue to %s", s->p_client);
    else
        snprintf(sub, sizeof sub, "Sign in with your Linux account");
    char *sub_e = html_escape(sub);

    sbuf rows;
    int ok = sbuf_init(&rows, 1024) == 0;
    for (int i = 0; ok && i < n; i++)
        ok = add_account_row(&rows, s, &accts[i]) == 0;

    char *html = NULL;
    if (ok && sub_e)
        html = strtpl(PAGE_CHOOSE, "SUB", sub_e, "ERROR", error ? error : "",
                      "ACCOUNTS", rows.s ? rows.s : "", "CSRF", s->csrf, NULL);
    free(sub_e);
    sbuf_free(&rows);
    if (!html)
        return MHD_NO;
    return res_html(r, MHD_HTTP_OK, html);
}

/* ---------- handler ---------- */

int handle_choose_post(http_req *r)
{
    const char *ck = req_cookie(r, SESSION_COOKIE);
    session s;
    if (!ck || session_snap(g_sessions, g_cfg.session_idle_s, ck, &s) != 0)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Session expired",
                              "Your login session expired. Restart the sign-in "
                              "from the application.");

    const char *csrf = req_form(r, "csrf");
    const char *acct = req_form(r, "acct");
    if (!csrf || !acct || !*acct)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Bad request",
                              "Missing account choice.");
    if (strlen(csrf) != strlen(s.csrf) || !ct_eq(csrf, s.csrf, strlen(s.csrf)))
        return res_error_page(r, MHD_HTTP_FORBIDDEN, "Forbidden",
                              "Form token mismatch. Reload the page and try again.");
    if (!s.has_pending)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Nothing to approve",
                              "Restart the sign-in from the application.");
    if (strlen(acct) >= sizeof s.username)
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Bad request",
                              "Unknown account.");

    /* The chosen account's session token is read back from the browser's own
     * Cookie header — a forged or cross-site form cannot name someone else's
     * session. The active session itself is the only fallback. */
    req_cookie_kv kv[IDAAS_MAX_ACCOUNTS];
    size_t nkv = req_cookies_prefix(r, ACCT_COOKIE_PREFIX, kv, IDAAS_MAX_ACCOUNTS);
    char chosen_tok[SESSION_TOKEN_BUF];
    session chosen;
    int from_cookie = 0;
    if (accounts_find(kv, nkv, acct, chosen_tok) == 0 &&
        session_peek(g_sessions, g_cfg.session_idle_s, chosen_tok, &chosen) == 0 &&
        chosen.authenticated && strcmp(chosen.username, acct) == 0)
        from_cookie = 1;
    if (!from_cookie && s.authenticated && strcmp(s.username, acct) == 0) {
        snprintf(chosen_tok, sizeof chosen_tok, "%s", ck);
        chosen = s;
    } else if (!from_cookie) {
        const char *err =
            "That account is no longer signed in here. Choose another account.";
        account_entry accts[IDAAS_MAX_ACCOUNTS];
        int n = accounts_collect(kv, nkv, g_sessions, g_cfg.session_idle_s, ck, &s,
                                 accts, IDAAS_MAX_ACCOUNTS);
        if (n > 0)
            return choose_render_page(r, &s, accts, n, err);
        return login_render_page(r, &s, "That account is no longer signed in here.");
    }

    authorize_req arq;
    if (oauth_pending_req(&s, chosen.username, chosen.auth_time, chosen_tok, &arq) != 0) {
        s.has_pending = 0;
        session_save(g_sessions, g_cfg.session_abs_s, ck, &s);
        return res_error_page(r, MHD_HTTP_BAD_REQUEST, "Client changed",
                              "The application's registration changed. Restart "
                              "the sign-in.");
    }
    s.has_pending = 0;
    session_save(g_sessions, g_cfg.session_abs_s, ck, &s);

    /* the chosen account becomes the active one */
    res_set_cookie(r, SESSION_COOKIE, chosen_tok, g_cfg.session_abs_s,
                   g_cfg.cookie_secure, 1, "Lax");
    if (!from_cookie) {
        /* self-heal a missing remember-cookie for the confirmed account */
        char cname[32];
        acct_cookie_name(cname, chosen.username);
        res_set_cookie(r, cname, chosen_tok, g_cfg.session_abs_s,
                       g_cfg.cookie_secure, 1, "Lax");
    }
    return oauth_issue_code(r, &arq);
}
