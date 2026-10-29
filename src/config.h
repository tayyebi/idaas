#ifndef IDAAS_CONFIG_H
#define IDAAS_CONFIG_H

#include <stddef.h>

#define MAX_CLIENTS 32
#define MAX_REDIRECTS 8

typedef struct oauth_client {
    char id[128];
    char secret[192];         /* "" => public client (PKCE required) */
    char scope[256];
    char *redirect_uris[MAX_REDIRECTS];
    size_t n_redirects;
} oauth_client;

typedef struct config {
    char issuer[512];         /* no trailing slash */
    char listen[64];          /* ":8080" or "127.0.0.1:8080" */
    char data_dir[256];
    char clients_file[512];
    char email_domain[192];
    long uid_min, uid_max;    /* login gate on the account's uid */
    long session_idle_s, session_abs_s;
    long access_ttl, refresh_ttl, code_ttl;
    int trust_proxy;          /* honor X-Forwarded-For */
    int cookie_secure;        /* derived from issuer scheme */
    oauth_client clients[MAX_CLIENTS];
    size_t n_clients;
} config;

/* Load env vars. Returns -1 with a logged error on fatal misconfiguration. */
int config_from_env(config *c);

/* Parse the clients file (INI). Returns -1 on fatal errors. */
int config_load_clients(config *c);

const oauth_client *config_find_client(const config *c, const char *id);
int client_is_public(const oauth_client *c);
int client_redirect_ok(const oauth_client *c, const char *uri);
int config_redirect_registered(const config *c, const char *uri);

#endif
