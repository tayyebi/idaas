#include "admin.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonw.h"
#include "log.h"
#include "managed.h"
#include "util.h"

#define MAX_NETS 32

static cidr g_nets[MAX_NETS];
static int g_nnets;
static char g_token[192];

int admin_init(void)
{
    g_nnets = 0;
    g_token[0] = 0;

    const char *tok = getenv("IDAAS_ADMIN_TOKEN");
    if (tok && *tok) {
        if (strlen(tok) >= sizeof g_token) {
            LOG_ERROR("IDAAS_ADMIN_TOKEN is too long");
            return -1;
        }
        snprintf(g_token, sizeof g_token, "%s", tok);
    }

    const char *nets = getenv("IDAAS_ADMIN_NETWORKS");
    if (!nets || !*nets) {
        LOG_WARN("admin API disabled: IDAAS_ADMIN_NETWORKS is not set "
                 "(every /api request will be refused)");
        return 0;
    }

    char buf[768];
    snprintf(buf, sizeof buf, "%s", nets);
    char *save = NULL;
    for (char *p = strtok_r(buf, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        char spec[128];
        snprintf(spec, sizeof spec, "%s", str_trim(p));
        if (g_nnets >= MAX_NETS) {
            LOG_WARN("too many admin networks (max %d), ignoring the rest", MAX_NETS);
            break;
        }
        if (cidr_parse(spec, &g_nets[g_nnets]) == 0)
            g_nnets++;
        else
            LOG_WARN("ignoring invalid CIDR '%s' in IDAAS_ADMIN_NETWORKS", spec);
    }
    LOG_INFO("admin API enabled for %d network(s)%s", g_nnets,
             g_token[0] ? " (bearer token required)" : "");
    if (!g_token[0])
        LOG_WARN("IDAAS_ADMIN_TOKEN is not set; consider adding it as a second factor");
    return 0;
}

static int admin_allowed(const char *ip)
{
    if (g_nnets == 0)
        return 0;
    for (int i = 0; i < g_nnets; i++)
        if (cidr_match(&g_nets[i], ip))
            return 1;
    return 0;
}

/* ---------- validation ---------- */

static int valid_username(const char *s)
{
    return managed_valid_username(s);
}

/* printable, no ':' (field separator), no newlines/control chars */
static int clean_field(const char *s, size_t maxlen)
{
    if (!s)
        return 1;
    size_t n = strlen(s);
    if (n > maxlen)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (s[i] == ':' || c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int valid_password(const char *s)
{
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 8 || n > 128)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int valid_email(const char *s)
{
    if (!s || !*s)
        return 1; /* optional */
    size_t n = strlen(s);
    if (n > 191 || !strchr(s, '@'))
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f || s[i] == ':')
            return 0;
    }
    return 1;
}

static int valid_groups(const char *s)
{
    if (!s || !*s)
        return 1; /* optional */
    char *copy = strdup(s);
    if (!copy)
        return 0;
    int ok = 1;
    char *save = NULL;
    for (char *p = strtok_r(copy, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        size_t n = strlen(p);
        if (n < 1 || n > 32) {
            ok = 0;
            break;
        }
        for (size_t i = 0; i < n; i++) {
            char c = p[i];
            if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) {
                ok = 0;
                break;
            }
        }
        if (!ok)
            break;
    }
    free(copy);
    return ok;
}

/* ---------- JSON ---------- */

static void user_json(sbuf *b, const managed_user *u)
{
    jw_obj_begin(b, NULL);
    jw_str(b, "username", u->username);
    jw_str(b, "name", u->gecos);
    jw_str(b, "email", u->email);
    char *gn[32];
    int n = managed_split_groups(u->groups, gn, 32);
    jw_str_arr(b, "groups", gn, (size_t)(n > 0 ? n : 0));
    for (int i = 0; i < n; i++)
        free(gn[i]);
    jw_bool(b, "disabled", u->disabled);
    jw_long(b, "created", (long long)u->created);
    jw_obj_end(b);
}

/* ---------- handlers ---------- */

static int api_list(http_req *r)
{
    managed_user *list = malloc(256 * sizeof *list);
    sbuf b;
    if (!list || sbuf_init(&b, 1024) != 0) {
        free(list);
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    }
    int n = managed_list(list, 256);
    jw_obj_begin(&b, NULL);
    jw_arr_begin(&b, "users");
    for (int i = 0; i < n; i++)
        user_json(&b, &list[i]);
    jw_arr_end(&b);
    jw_long(&b, "count", n);
    jw_obj_end(&b);
    free(list);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

static int api_get(http_req *r, const char *name)
{
    managed_user u;
    if (managed_get(name, &u) != 0)
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);
    sbuf b;
    if (sbuf_init(&b, 256) != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    user_json(&b, &u);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

static int api_create(http_req *r)
{
    const char *u = req_form(r, "username");
    const char *pw = req_form(r, "password");
    const char *name = req_form(r, "name");
    const char *email = req_form(r, "email");
    const char *groups = req_form(r, "groups");
    if (!u || !*u || !pw || !*pw)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "username and password are required");
    if (!valid_username(u))
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request", "bad username");
    if (!valid_password(pw))
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "password must be 8-128 printable characters");
    if (!clean_field(name, 127) || !valid_email(email) || !valid_groups(groups))
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "bad name/email/groups");

    int rc = managed_create(u, pw, name ? name : "", email ? email : "",
                            groups ? groups : "");
    if (rc == 1)
        return res_error_json(r, MHD_HTTP_CONFLICT, "conflict",
                              "username already exists");
    if (rc != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    log_audit("admin-user", u, req_peer_ip(r), "created", NULL);

    sbuf b;
    if (sbuf_init(&b, 128) != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    jw_obj_begin(&b, NULL);
    jw_str(&b, "username", u);
    jw_bool(&b, "managed", 1);
    jw_obj_end(&b);
    int rr = res_json(r, MHD_HTTP_CREATED, &b);
    sbuf_free(&b);
    return rr;
}

static int api_update(http_req *r, const char *name)
{
    managed_update_req mu;
    memset(&mu, 0, sizeof mu);
    mu.disabled = -1;

    const char *pw = req_form(r, "password");
    const char *gname = req_form(r, "name");
    const char *email = req_form(r, "email");
    const char *groups = req_form(r, "groups");
    const char *dis = req_form(r, "disabled");

    if (pw && *pw && !valid_password(pw))
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request", "bad password");
    if (!clean_field(gname, 127) || !valid_email(email) || !valid_groups(groups))
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "bad name/email/groups");
    if (dis && *dis && strcmp(dis, "0") != 0 && strcmp(dis, "1") != 0)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "disabled must be 0 or 1");

    mu.password = (pw && *pw) ? pw : NULL;
    mu.gecos = gname;
    mu.email = email;
    mu.groups = groups;
    if (dis && *dis)
        mu.disabled = atoi(dis);

    int rc = managed_update(name, &mu);
    if (rc == 1)
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);
    if (rc != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    log_audit("admin-user", name, req_peer_ip(r), "updated", NULL);
    return api_get(r, name);
}

static int api_delete(http_req *r, const char *name)
{
    int rc = managed_delete(name);
    if (rc == 1)
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);
    if (rc != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    log_audit("admin-user", name, req_peer_ip(r), "deleted", NULL);
    sbuf b;
    if (sbuf_init(&b, 64) != 0)
        return res_error_json(r, MHD_HTTP_INTERNAL_SERVER_ERROR, "server_error", NULL);
    jw_obj_begin(&b, NULL);
    jw_str(&b, "username", name);
    jw_bool(&b, "deleted", 1);
    jw_obj_end(&b);
    int rr = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rr;
}

/* ---------- routing ---------- */

int handle_api(http_req *r, const char *path)
{
    /* mynetworks gate first: refuse before revealing anything */
    if (!admin_allowed(req_peer_ip(r)))
        return res_error_json(r, MHD_HTTP_FORBIDDEN, "forbidden",
                              "admin API is not allowed from this address");
    if (g_token[0]) {
        const char *h = req_header(r, "Authorization");
        if (!h || strncmp(h, "Bearer ", 7) != 0 || !secret_eq(g_token, h + 7))
            return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "unauthorized",
                                  "admin token required");
    }

    const char *rest = path + 4; /* skip "/api" */
    if (strncmp(rest, "/users", 6) != 0)
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);
    rest += 6;
    if (*rest == 0) {
        if (strcmp(req_method(r), "GET") == 0)
            return api_list(r);
        if (strcmp(req_method(r), "POST") == 0)
            return api_create(r);
        return res_error_json(r, MHD_HTTP_METHOD_NOT_ALLOWED, "method_not_allowed", NULL);
    }
    if (*rest != '/')
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);
    const char *name = rest + 1;
    if (!*name || strchr(name, '/') || !valid_username(name))
        return res_error_json(r, MHD_HTTP_NOT_FOUND, "not_found", NULL);

    if (strcmp(req_method(r), "GET") == 0)
        return api_get(r, name);
    if (strcmp(req_method(r), "PUT") == 0 || strcmp(req_method(r), "PATCH") == 0)
        return api_update(r, name);
    if (strcmp(req_method(r), "DELETE") == 0)
        return api_delete(r, name);
    return res_error_json(r, MHD_HTTP_METHOD_NOT_ALLOWED, "method_not_allowed", NULL);
}
