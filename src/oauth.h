#ifndef IDAAS_OAUTH_H
#define IDAAS_OAUTH_H

#include <time.h>

#include "config.h"
#include "http.h"
#include "session.h"

int handle_authorize(http_req *r);

/* Everything needed to mint one authorization code. Fields are borrowed;
 * they only need to outlive the oauth_issue_code() call. */
typedef struct authorize_req {
    const oauth_client *client;
    const char *redirect_uri;
    const char *scope;
    const char *state;     /* may be "" */
    const char *nonce;
    const char *challenge; /* may be "" */
    const char *username;
    time_t auth_time;
    const char *sid;       /* session token serving as the sid claim */
} authorize_req;

/* Authorization code record (shared with the token endpoint). Stored keyed
 * by SHA-256(code), single-use, short TTL. */
struct auth_code {
    char client_id[128];
    char redirect_uri[512];
    char sub[64];
    char nonce[256];
    char scope[256];
    char challenge[128];
    char sid[SESSION_TOKEN_BUF];
    time_t auth_time;
};

int oauth_issue_code(http_req *r, const authorize_req *a);

/* Build an authorize_req from the session's stashed pending request, for the
 * given end user. Returns -1 when the pending client/redirect is no longer
 * registered. username/auth_time/sid are borrowed and only need to outlive
 * the oauth_issue_code() call. */
int oauth_pending_req(const session *s, const char *username, time_t auth_time,
                      const char *sid, authorize_req *out);

#endif
