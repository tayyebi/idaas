#define _DEFAULT_SOURCE /* setgrent/getgrent/endgrent */
#include "users.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <grp.h>
#include <pwd.h>

#include "jsonw.h"
#include "managed.h"

int user_lookup(const char *username, user_info *out)
{
    if (!username || !*username || strlen(username) >= sizeof out->username)
        return -1;
    struct passwd pw, *res = NULL;
    char buf[16384];
    if (getpwnam_r(username, &pw, buf, sizeof buf, &res) != 0 || !res)
        return -1;
    memset(out, 0, sizeof *out);
    snprintf(out->username, sizeof out->username, "%s", username);
    out->uid = (long)pw.pw_uid;
    out->gid = (long)pw.pw_gid;
    char g[sizeof out->gecos];
    snprintf(g, sizeof g, "%s", pw.pw_gecos ? pw.pw_gecos : "");
    char *comma = strchr(g, ',');
    if (comma)
        *comma = 0;
    memcpy(out->gecos, g, strlen(g) + 1);
    return 0;
}

int user_login_allowed(const config *cfg, const char *username, user_info *out)
{
    if (user_lookup(username, out))
        return -1;
    if (out->uid < cfg->uid_min || out->uid > cfg->uid_max)
        return -1;
    return 0;
}

/* getgrent() is process-global; serialize access. */
static pthread_mutex_t g_grp_mu = PTHREAD_MUTEX_INITIALIZER;

int user_groups(const char *username, long gid, char **names, size_t maxn)
{
    size_t n = 0;
    pthread_mutex_lock(&g_grp_mu);
    setgrent();
    struct group *g;
    while ((g = getgrent()) != NULL) {
        int member = ((long)g->gr_gid == gid);
        for (char **m = g->gr_mem; !member && m && *m; m++)
            if (strcmp(*m, username) == 0)
                member = 1;
        if (member && n < maxn) {
            names[n] = strdup(g->gr_name ? g->gr_name : "");
            if (names[n])
                n++;
        }
    }
    endgrent();
    pthread_mutex_unlock(&g_grp_mu);
    return (int)n;
}

char *user_email(const config *cfg, const char *username)
{
    size_t n = strlen(username) + strlen(cfg->email_domain) + 2;
    char *e = malloc(n);
    if (e)
        snprintf(e, n, "%s@%s", username, cfg->email_domain);
    return e;
}

void users_add_claims(sbuf *b, const config *cfg, const char *username, const char *scope)
{
    /* API-managed accounts take precedence over snapshot (Linux) accounts */
    managed_user mu;
    if (managed_get(username, &mu) == 0) {
        if (scope_has(scope, "profile")) {
            jw_str(b, "preferred_username", username);
            if (mu.gecos[0])
                jw_str(b, "name", mu.gecos);
        }
        if (scope_has(scope, "email")) {
            if (mu.email[0]) {
                jw_str(b, "email", mu.email);
            } else {
                char *em = user_email(cfg, username);
                if (em) {
                    jw_str(b, "email", em);
                    free(em);
                }
            }
            jw_bool(b, "email_verified", 1);
        }
        if (scope_has(scope, "groups") && mu.groups[0]) {
            char *gn[32];
            int n = managed_split_groups(mu.groups, gn, 32);
            if (n > 0)
                jw_str_arr(b, "groups", gn, (size_t)n);
            for (int i = 0; i < n; i++)
                free(gn[i]);
        }
        return;
    }

    user_info ui;
    int have_ui = user_lookup(username, &ui) == 0;

    if (scope_has(scope, "profile")) {
        jw_str(b, "preferred_username", username);
        if (have_ui && ui.gecos[0])
            jw_str(b, "name", ui.gecos);
    }
    if (scope_has(scope, "email")) {
        char *em = user_email(cfg, username);
        if (em) {
            jw_str(b, "email", em);
            free(em);
        }
        /* the domain is operator-controlled, so treat it as verified */
        jw_bool(b, "email_verified", 1);
    }
    if (scope_has(scope, "groups") && have_ui) {
        char *gn[64];
        int n = user_groups(username, ui.gid, gn, 64);
        if (n > 0)
            jw_str_arr(b, "groups", gn, (size_t)n);
        for (int i = 0; i < n; i++)
            free(gn[i]);
    }
}
