#include "session.h"

#include <string.h>

#include "log.h"
#include "rnd.h"
#include "util.h"

static void key_for(const char *token, char key[65])
{
    unsigned char h[32];
    sha256_buf(token, strlen(token), h);
    hex_encode(h, 32, key);
}

int session_start(store *st, long abs_ttl_s, char token_out[SESSION_TOKEN_BUF])
{
    session s;
    memset(&s, 0, sizeof s);
    if (rnd_token(token_out, 32) || rnd_token(s.csrf, 24))
        return -1;
    time_t now = time(NULL);
    s.created = now;
    s.last_seen = now;
    s.abs_exp = now + abs_ttl_s;
    char key[65];
    key_for(token_out, key);
    return store_put(st, key, &s, sizeof s, s.abs_exp);
}

int session_snap(store *st, long idle_ttl_s, const char *token, session *out)
{
    if (session_peek(st, idle_ttl_s, token, out) != 0)
        return -1;
    char key[65];
    key_for(token, key);
    session touched = *out;
    touched.last_seen = time(NULL);
    store_put(st, key, &touched, sizeof touched, touched.abs_exp);
    return 0;
}

int session_peek(store *st, long idle_ttl_s, const char *token, session *out)
{
    if (!token || !*token)
        return -1;
    char key[65];
    key_for(token, key);
    if (store_get_copy(st, key, out, sizeof *out))
        return -1;
    time_t now = time(NULL);
    if (now >= out->abs_exp || now - out->last_seen > idle_ttl_s) {
        store_del(st, key);
        return -1;
    }
    return 0;
}

int session_save(store *st, long abs_ttl_s, const char *token, const session *s)
{
    (void)abs_ttl_s; /* the absolute deadline travels inside the session */
    char key[65];
    key_for(token, key);
    return store_put(st, key, s, sizeof *s, s->abs_exp);
}

int session_fresh(store *st, long abs_ttl_s, const session *proto,
                  char token_out[SESSION_TOKEN_BUF])
{
    session n = *proto;
    if (rnd_token(token_out, 32) || rnd_token(n.csrf, 24))
        return -1;
    time_t now = time(NULL);
    n.created = now;
    n.last_seen = now;
    n.abs_exp = now + abs_ttl_s;
    char key[65];
    key_for(token_out, key);
    return store_put(st, key, &n, sizeof n, n.abs_exp);
}

void session_destroy(store *st, const char *token)
{
    if (!token || !*token)
        return;
    char key[65];
    key_for(token, key);
    store_del(st, key);
}
