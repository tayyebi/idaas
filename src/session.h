#ifndef IDAAS_SESSION_H
#define IDAAS_SESSION_H

#include <time.h>

#include "store.h"

#define SESSION_TOKEN_BUF 45     /* 43 chars + NUL */
#define SESSION_COOKIE    "idaas_sid"

typedef struct session {
    char username[64];
    char csrf[64];
    int authenticated;
    time_t auth_time;
    time_t created;
    time_t abs_exp;
    time_t last_seen;
    /* pending authorization request (survives the login POST) */
    int has_pending;
    char p_client[128];
    char p_redirect[512];
    char p_scope[256];
    char p_state[1024];
    char p_nonce[256];
    char p_challenge[128];
} session;

/* Create a fresh session; token_out is the new cookie value. */
int  session_start(store *st, long abs_ttl_s, char token_out[SESSION_TOKEN_BUF]);
/* Fetch a snapshot; fails if missing/idle-expired/absolutely expired. */
int  session_snap(store *st, long idle_ttl_s, const char *token, session *out);
int  session_save(store *st, long abs_ttl_s, const char *token, const session *s);
/* Rotate the session id (fixation defense): stores *s under a new token and
 * removes the old one; fills new_token and refreshes s->csrf. */
int  session_rotate(store *st, long abs_ttl_s, const char *old_token,
                    session *s, char new_token[SESSION_TOKEN_BUF]);
void session_destroy(store *st, const char *token);

#endif
