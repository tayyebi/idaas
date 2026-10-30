#include "accounts.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

void acct_cookie_name(char out[32], const char *username)
{
    unsigned char h[32];
    char hex[65];
    sha256_buf(username ? username : "", username ? strlen(username) : 0, h);
    hex_encode(h, 32, hex);
    snprintf(out, 32, "%s%.8s", ACCT_COOKIE_PREFIX, hex);
}

int accounts_collect(const req_cookie_kv *kv, size_t nkv, store *st, long idle_s,
                     const char *active_token, const session *active,
                     account_entry out[], int max)
{
    int n = 0;
    if (active && active->authenticated && active->username[0] &&
        active_token && *active_token && n < max) {
        snprintf(out[n].username, sizeof out[n].username, "%s", active->username);
        snprintf(out[n].token, sizeof out[n].token, "%s", active_token);
        n++;
    }
    size_t pl = strlen(ACCT_COOKIE_PREFIX);
    for (size_t i = 0; i < nkv && n < max; i++) {
        if (strncmp(kv[i].name, ACCT_COOKIE_PREFIX, pl) != 0)
            continue;
        if (strlen(kv[i].value) != SESSION_TOKEN_BUF - 2)
            continue; /* not a session token */
        session s;
        if (session_peek(st, idle_s, kv[i].value, &s) != 0 ||
            !s.authenticated || !s.username[0])
            continue;
        int dup = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(out[j].username, s.username) == 0) {
                dup = 1;
                break;
            }
        if (dup)
            continue;
        snprintf(out[n].username, sizeof out[n].username, "%s", s.username);
        snprintf(out[n].token, sizeof out[n].token, "%s", kv[i].value);
        n++;
    }
    return n;
}

int accounts_find(const req_cookie_kv *kv, size_t nkv, const char *username,
                  char token_out[SESSION_TOKEN_BUF])
{
    char name[32];
    acct_cookie_name(name, username);
    for (size_t i = 0; i < nkv; i++)
        if (strcmp(kv[i].name, name) == 0) {
            snprintf(token_out, SESSION_TOKEN_BUF, "%s", kv[i].value);
            return 0;
        }
    return -1;
}
