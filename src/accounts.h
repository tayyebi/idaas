#ifndef IDAAS_ACCOUNTS_H
#define IDAAS_ACCOUNTS_H

#include <stddef.h>

#include "http.h"
#include "session.h"

/* Remembered-account cookies: one per logged-in account, named
 * ACCT_COOKIE_PREFIX + the first 8 hex chars of sha256(username), holding
 * that account's session token. idaas_sid stays "the active session". */
#define ACCT_COOKIE_PREFIX "idaas_acct_"
#define IDAAS_MAX_ACCOUNTS 5

/* out needs 32 bytes. */
void acct_cookie_name(char out[32], const char *username);

typedef struct account_entry {
    char username[64];
    char token[SESSION_TOKEN_BUF];
} account_entry;

/* Collect the browser's authenticated accounts: every idaas_acct_* cookie
 * (kv/nkv as filled by req_cookies_prefix) whose session survives a
 * read-only session_peek, plus the active session when it is authenticated.
 * Deduped by username (the active session wins). Returns the entry count. */
int accounts_collect(const req_cookie_kv *kv, size_t nkv, store *st, long idle_s,
                     const char *active_token, const session *active,
                     account_entry out[], int max);

/* This browser's own cookie for username, if present. The chosen account's
 * session token always comes from the Cookie header, never from a form. */
int accounts_find(const req_cookie_kv *kv, size_t nkv, const char *username,
                  char token_out[SESSION_TOKEN_BUF]);

#endif
