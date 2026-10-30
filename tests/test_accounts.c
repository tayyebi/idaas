#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "accounts.h"
#include "store.h"
#include "util.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

/* A logged-in session in st; returns a malloc'd 43-char token. idle_ago
 * seconds since last_seen (large = idle-expired). */
static char *add_account_session(store *st, const char *user, long idle_ago)
{
    char *tok = malloc(SESSION_TOKEN_BUF);
    for (int i = 0; i < SESSION_TOKEN_BUF - 2; i++) /* 43 chars, like rnd_token */
        tok[i] = (char)('a' + (i + user[0] + user[1]) % 26);
    tok[SESSION_TOKEN_BUF - 2] = 0;
    session s;
    memset(&s, 0, sizeof s);
    snprintf(s.username, sizeof s.username, "%s", user);
    strcpy(s.csrf, "csrf");
    s.authenticated = 1;
    s.auth_time = time(NULL) - 10;
    s.created = time(NULL) - 10;
    s.abs_exp = time(NULL) + 3600;
    s.last_seen = time(NULL) - idle_ago;
    unsigned char h[32];
    char key[65];
    sha256_buf(tok, strlen(tok), h);
    hex_encode(h, 32, key);
    store_put(st, key, &s, sizeof s, s.abs_exp);
    return tok;
}

static void kv_fill(req_cookie_kv *kv, const char *user, const char *token)
{
    acct_cookie_name(kv->name, user);
    snprintf(kv->value, sizeof kv->value, "%s", token);
}

int test_accounts(void)
{
    /* cookie naming: prefix + 8 hex, stable, distinct per user */
    char a[32], b[32];
    acct_cookie_name(a, "alice");
    acct_cookie_name(b, "bob");
    CHECK(strncmp(a, ACCT_COOKIE_PREFIX, strlen(ACCT_COOKIE_PREFIX)) == 0);
    CHECK(strlen(a) == strlen(ACCT_COOKIE_PREFIX) + 8);
    CHECK(strcmp(a, b) != 0);
    acct_cookie_name(b, "alice");
    CHECK(strcmp(a, b) == 0);

    store *st = store_new();

    /* html escaping is what keeps chooser rows safe */
    char *e = html_escape("a<b>&'\"c");
    CHECK(e && strcmp(e, "a&lt;b&gt;&amp;&#39;&quot;c") == 0);
    free(e);

    /* session_peek validates but does not refresh last_seen */
    char *tok_alice = add_account_session(st, "alice", 0);
    session snap;
    CHECK(session_peek(st, 3600, tok_alice, &snap) == 0);
    time_t seen = snap.last_seen;
    CHECK(session_peek(st, 3600, tok_alice, &snap) == 0);
    CHECK(snap.last_seen == seen); /* snap would have bumped it */

    /* session_fresh: new token + csrf, proto fields kept, old survives */
    session proto;
    CHECK(session_peek(st, 3600, tok_alice, &proto) == 0);
    char fresh[SESSION_TOKEN_BUF];
    CHECK(session_fresh(st, 3600, &proto, fresh) == 0);
    CHECK(strcmp(fresh, tok_alice) != 0);
    CHECK(session_peek(st, 3600, fresh, &snap) == 0);
    CHECK(snap.authenticated && strcmp(snap.username, "alice") == 0);
    CHECK(strcmp(snap.csrf, proto.csrf) != 0);
    CHECK(session_peek(st, 3600, tok_alice, &snap) == 0);

    /* accounts_collect: filters dead sessions, unauthenticated, garbage;
       dedupes by username with the active session winning */
    char *tok_bob = add_account_session(st, "bob", 0);
    char *tok_dead = add_account_session(st, "carol", 9999); /* idle-expired */
    session anon;
    memset(&anon, 0, sizeof anon);
    char tok_anon[SESSION_TOKEN_BUF] = "x";

    req_cookie_kv kv[4];
    size_t nkv = 0;
    kv_fill(&kv[nkv++], "alice", tok_alice);
    kv_fill(&kv[nkv++], "bob", tok_bob);
    kv_fill(&kv[nkv++], "carol", tok_dead);
    kv_fill(&kv[nkv++], "dave", "not-a-token");

    account_entry out[IDAAS_MAX_ACCOUNTS];
    int n = accounts_collect(kv, nkv, st, 3600, tok_anon, &anon, out, IDAAS_MAX_ACCOUNTS);
    CHECK(n == 2);
    if (n == 2) {
        CHECK(strcmp(out[0].username, "alice") == 0 &&
              strcmp(out[0].token, tok_alice) == 0);
        CHECK(strcmp(out[1].username, "bob") == 0);
    }

    /* the active session is listed first and wins the dedupe */
    session active;
    CHECK(session_peek(st, 3600, tok_bob, &active) == 0);
    n = accounts_collect(kv, nkv, st, 3600, tok_bob, &active, out, IDAAS_MAX_ACCOUNTS);
    CHECK(n == 2);
    if (n == 2) {
        CHECK(strcmp(out[0].username, "bob") == 0 &&
              strcmp(out[0].token, tok_bob) == 0);
        CHECK(strcmp(out[1].username, "alice") == 0);
    }

    /* accounts_find reads the token back from the browser's own cookies */
    char found[SESSION_TOKEN_BUF];
    CHECK(accounts_find(kv, nkv, "alice", found) == 0);
    CHECK(strcmp(found, tok_alice) == 0);
    CHECK(accounts_find(kv, nkv, "eve", found) == -1);

    free(tok_alice);
    free(tok_bob);
    free(tok_dead);
    store_free(st);
    return fails;
}
