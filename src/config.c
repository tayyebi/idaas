#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

static const char *env_str(const char *name, const char *dflt)
{
    const char *v = getenv(name);
    return (v && *v) ? v : dflt;
}

static long env_long(const char *name, long dflt)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return dflt;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (!end || *end || n < 0)
        return dflt;
    return n;
}

int config_from_env(config *c)
{
    memset(c, 0, sizeof *c);

    const char *iss = getenv("IDAAS_ISSUER");
    if (!iss || !*iss) {
        LOG_ERROR("IDAAS_ISSUER is required (external URL, e.g. https://sso.example.com)");
        return -1;
    }
    if (strlen(iss) >= sizeof c->issuer) {
        LOG_ERROR("IDAAS_ISSUER is too long");
        return -1;
    }
    snprintf(c->issuer, sizeof c->issuer, "%s", iss);
    size_t il = strlen(c->issuer);
    while (il && c->issuer[il - 1] == '/')
        c->issuer[--il] = 0;
    if (!il || (strncmp(c->issuer, "http://", 7) != 0 && strncmp(c->issuer, "https://", 8) != 0)) {
        LOG_ERROR("IDAAS_ISSUER must start with http:// or https://");
        return -1;
    }
    c->cookie_secure = strncmp(c->issuer, "https://", 8) == 0;

    snprintf(c->listen, sizeof c->listen, "%s", env_str("IDAAS_LISTEN", ":8080"));
    snprintf(c->data_dir, sizeof c->data_dir, "%s", env_str("IDAAS_DATA_DIR", "/data"));
    const char *cf = getenv("IDAAS_CLIENTS_FILE");
    if (cf && *cf)
        snprintf(c->clients_file, sizeof c->clients_file, "%s", cf);
    else
        snprintf(c->clients_file, sizeof c->clients_file, "%s/clients.conf", c->data_dir);
    snprintf(c->email_domain, sizeof c->email_domain, "%s",
             env_str("IDAAS_EMAIL_DOMAIN", "localhost"));

    c->uid_min = env_long("IDAAS_UID_MIN", 1000);
    c->uid_max = env_long("IDAAS_UID_MAX", 60000);
    c->session_idle_s = env_long("IDAAS_SESSION_IDLE", 3600);
    c->session_abs_s = env_long("IDAAS_SESSION_ABS", 28800);
    c->access_ttl = env_long("IDAAS_ACCESS_TTL", 600);
    c->refresh_ttl = env_long("IDAAS_REFRESH_TTL", 2592000);
    c->code_ttl = env_long("IDAAS_CODE_TTL", 60);
    c->trust_proxy = env_long("IDAAS_TRUST_PROXY", 0) ? 1 : 0;

    if (c->session_idle_s < 60) c->session_idle_s = 60;
    if (c->session_abs_s < 300) c->session_abs_s = 300;
    if (c->access_ttl < 30) c->access_ttl = 30;
    if (c->refresh_ttl < 60) c->refresh_ttl = 60;
    if (c->code_ttl < 10 || c->code_ttl > 600) c->code_ttl = 60;
    return 0;
}

static int add_redirect(oauth_client *cl, const char *uri)
{
    if (cl->n_redirects >= MAX_REDIRECTS) {
        LOG_WARN("client '%s': too many redirect_uri entries (max %d)", cl->id, MAX_REDIRECTS);
        return -1;
    }
    if (!uri || !*uri || strlen(uri) >= 500 ||
        (strncmp(uri, "http://", 7) != 0 && strncmp(uri, "https://", 8) != 0)) {
        LOG_WARN("client '%s': ignoring invalid redirect_uri", cl->id);
        return -1;
    }
    cl->redirect_uris[cl->n_redirects] = strdup(uri);
    if (!cl->redirect_uris[cl->n_redirects])
        return -1;
    cl->n_redirects++;
    return 0;
}

int config_load_clients(config *c)
{
    FILE *f = fopen(c->clients_file, "r");
    if (!f) {
        LOG_ERROR("cannot open clients file %s", c->clients_file);
        return -1;
    }

    char line[1024];
    int cur = -1;
    int lineno = 0;
    int bad = 0;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *s = str_trim(line);
        if (!*s || *s == '#')
            continue;

        if (*s == '[') {
            char *e = strchr(s, ']');
            if (!e || s[1] == 0) {
                LOG_WARN("clients:%d: bad section header", lineno);
                bad = 1;
                break;
            }
            *e = 0;
            char *id = str_trim(s + 1);
            if (!*id || strlen(id) >= sizeof c->clients[0].id || strchr(id, '[')) {
                LOG_WARN("clients:%d: bad client id", lineno);
                bad = 1;
                break;
            }
            if (config_find_client(c, id)) {
                LOG_WARN("clients:%d: duplicate client '%s'", lineno, id);
                bad = 1;
                break;
            }
            if (c->n_clients >= MAX_CLIENTS) {
                LOG_ERROR("too many clients (max %d)", MAX_CLIENTS);
                bad = 1;
                break;
            }
            oauth_client *cl = &c->clients[c->n_clients];
            memset(cl, 0, sizeof *cl);
            snprintf(cl->id, sizeof cl->id, "%s", id);
            snprintf(cl->scope, sizeof cl->scope, "openid profile email");
            /* empty secret means confidential until a secret is set */
            cur = (int)c->n_clients;
            c->n_clients++;
            continue;
        }

        char *eq = strchr(s, '=');
        if (eq) {
            *eq = 0;
            char *k = str_trim(s);
            char *v = str_trim(eq + 1);
            if (cur < 0) {
                LOG_WARN("clients:%d: key outside a section", lineno);
                continue;
            }
            oauth_client *cl = &c->clients[cur];
            if (strcmp(k, "secret") == 0) {
                if (!*v || strlen(v) >= sizeof cl->secret) {
                    LOG_WARN("clients:%d: bad secret for '%s'", lineno, cl->id);
                    bad = 1;
                    break;
                }
                snprintf(cl->secret, sizeof cl->secret, "%s", v);
            } else if (strcmp(k, "redirect_uri") == 0) {
                if (add_redirect(cl, v))
                    bad = 1;
            } else if (strcmp(k, "scope") == 0) {
                if (!*v || strlen(v) >= sizeof cl->scope)
                    LOG_WARN("clients:%d: bad scope for '%s'", lineno, cl->id);
                else
                    snprintf(cl->scope, sizeof cl->scope, "%s", v);
            } else {
                LOG_WARN("clients:%d: unknown key '%s'", lineno, k);
            }
        } else if (strcmp(s, "public") == 0) {
            if (cur < 0) {
                LOG_WARN("clients:%d: 'public' outside a section", lineno);
                continue;
            }
            c->clients[cur].secret[0] = 0;
        } else {
            LOG_WARN("clients:%d: unparseable line", lineno);
        }
        if (bad)
            break;
    }
    fclose(f);

    if (bad)
        return -1;

    for (size_t i = 0; i < c->n_clients; i++) {
        oauth_client *cl = &c->clients[i];
        if (cl->n_redirects == 0) {
            LOG_ERROR("client '%s' has no valid redirect_uri", cl->id);
            return -1;
        }
        if (!client_is_public(cl) && !cl->secret[0]) {
            LOG_ERROR("client '%s' needs a secret or the 'public' flag", cl->id);
            return -1;
        }
    }
    LOG_INFO("loaded %zu client(s) from %s", c->n_clients, c->clients_file);
    return 0;
}

const oauth_client *config_find_client(const config *c, const char *id)
{
    if (!id)
        return NULL;
    for (size_t i = 0; i < c->n_clients; i++)
        if (strcmp(c->clients[i].id, id) == 0)
            return &c->clients[i];
    return NULL;
}

int client_is_public(const oauth_client *c)
{
    return c->secret[0] == 0;
}

int client_redirect_ok(const oauth_client *c, const char *uri)
{
    if (!uri)
        return 0;
    for (size_t i = 0; i < c->n_redirects; i++)
        if (strcmp(c->redirect_uris[i], uri) == 0)
            return 1;
    return 0;
}

int config_redirect_registered(const config *c, const char *uri)
{
    for (size_t i = 0; i < c->n_clients; i++)
        if (client_redirect_ok(&c->clients[i], uri))
            return 1;
    return 0;
}
