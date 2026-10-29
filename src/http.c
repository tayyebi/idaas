#include "http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include "admin.h"
#include "ctx.h"
#include "discovery.h"
#include "jsonw.h"
#include "login.h"
#include "log.h"
#include "oauth.h"
#include "pages.h"
#include "token.h"
#include "userinfo.h"

#define BODY_MAX (64 * 1024)
#define MAX_FORMS 64
#define MAX_EXTRA_HDRS 4
#define MAX_COOKIES 4

struct form_kv {
    char *k;
    char *v;
};

struct http_req {
    struct MHD_Connection *conn;
    const char *method;
    const char *path;
    char peer_ip[64];
    struct form_kv forms[MAX_FORMS];
    size_t nforms;
    char resp_hdrs[MAX_EXTRA_HDRS][2][256];
    size_t nhdrs;
    char cookies[MAX_COOKIES][512];
    size_t ncookies;
};

struct conn_state {
    sbuf body;
    int too_large;
    int done;
};

/* ---------- request accessors ---------- */

const char *req_query(http_req *r, const char *name)
{
    return MHD_lookup_connection_value(r->conn, MHD_GET_ARGUMENT_KIND, name);
}

const char *req_form(http_req *r, const char *name)
{
    for (size_t i = 0; i < r->nforms; i++)
        if (strcmp(r->forms[i].k, name) == 0)
            return r->forms[i].v;
    return NULL;
}

const char *req_param(http_req *r, const char *name)
{
    const char *v = req_query(r, name);
    return v ? v : req_form(r, name);
}

const char *req_header(http_req *r, const char *name)
{
    return MHD_lookup_connection_value(r->conn, MHD_HEADER_KIND, name);
}

const char *req_cookie(http_req *r, const char *name)
{
    return MHD_lookup_connection_value(r->conn, MHD_COOKIE_KIND, name);
}

const char *req_method(http_req *r)
{
    return r->method;
}

const char *req_peer_ip(http_req *r)
{
    return r->peer_ip;
}

/* ---------- response helpers ---------- */

void res_set_header(http_req *r, const char *name, const char *val)
{
    if (r->nhdrs >= MAX_EXTRA_HDRS)
        return;
    snprintf(r->resp_hdrs[r->nhdrs][0], sizeof r->resp_hdrs[0][0], "%s", name);
    snprintf(r->resp_hdrs[r->nhdrs][1], sizeof r->resp_hdrs[0][1], "%s", val);
    r->nhdrs++;
}

void res_set_cookie(http_req *r, const char *name, const char *val, long max_age,
                    int secure, int httponly, const char *samesite)
{
    if (r->ncookies >= MAX_COOKIES)
        return;
    char *c = r->cookies[r->ncookies++];
    size_t n = sizeof r->cookies[0];
    int used = snprintf(c, n, "%s=%s; Path=/; Max-Age=%ld", name, val, max_age);
    if (used < 0 || (size_t)used >= n)
        return;
    if (samesite && *samesite)
        used += snprintf(c + used, n - (size_t)used, "; SameSite=%s", samesite);
    if (used > 0 && (size_t)used < n && httponly)
        used += snprintf(c + used, n - (size_t)used, "; HttpOnly");
    if (used > 0 && (size_t)used < n && secure)
        snprintf(c + used, n - (size_t)used, "; Secure");
}

static int finish_response(http_req *r, int status, struct MHD_Response *resp,
                           const char *ctype, int public_cache)
{
    if (!resp)
        return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", ctype);
    MHD_add_response_header(resp, "Cache-Control",
                            public_cache ? "public, max-age=300" : "no-store");
    if (!public_cache)
        MHD_add_response_header(resp, "Pragma", "no-cache");
    for (size_t i = 0; i < r->ncookies; i++)
        MHD_add_response_header(resp, "Set-Cookie", r->cookies[i]);
    for (size_t i = 0; i < r->nhdrs; i++)
        MHD_add_response_header(resp, r->resp_hdrs[i][0], r->resp_hdrs[i][1]);
    int rc = MHD_queue_response(r->conn, (unsigned int)status, resp);
    MHD_destroy_response(resp);
    return rc;
}

static int send_heap(http_req *r, int status, const char *ctype, char *heap, int public_cache)
{
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(strlen(heap), heap, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(heap);
        return MHD_NO;
    }
    return finish_response(r, status, resp, ctype, public_cache);
}

static int send_sbuf(http_req *r, int status, const char *ctype, sbuf *b, int public_cache)
{
    char *body = b->s;
    size_t len = b->len;
    b->s = NULL;
    b->len = b->cap = 0;
    if (!body)
        return MHD_NO;
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(len, body, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(body);
        return MHD_NO;
    }
    return finish_response(r, status, resp, ctype, public_cache);
}

int res_text(http_req *r, int status, const char *txt)
{
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(strlen(txt), (void *)txt, MHD_RESPMEM_PERSISTENT);
    return finish_response(r, status, resp, "text/plain; charset=utf-8", 0);
}

int res_html(http_req *r, int status, char *heap_html)
{
    return send_heap(r, status, "text/html; charset=utf-8", heap_html, 0);
}

int res_json(http_req *r, int status, sbuf *body)
{
    return send_sbuf(r, status, "application/json", body, 0);
}

int res_json_public(http_req *r, int status, sbuf *body)
{
    return send_sbuf(r, status, "application/json", body, 1);
}

int res_redirect(http_req *r, const char *location)
{
    struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    if (!resp)
        return MHD_NO;
    MHD_add_response_header(resp, "Location", location);
    return finish_response(r, MHD_HTTP_FOUND, resp, "text/plain", 0);
}

int res_error_json(http_req *r, int status, const char *err, const char *desc)
{
    sbuf b;
    if (sbuf_init(&b, 128))
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "error", err);
    if (desc)
        jw_str(&b, "error_description", desc);
    jw_obj_end(&b);
    int rc = res_json(r, status, &b);
    sbuf_free(&b);
    return rc;
}

int res_error_page(http_req *r, int status, const char *title, const char *msg)
{
    char *html = strtpl(PAGE_ERROR, "TITLE", title, "MESSAGE", msg, NULL);
    if (!html)
        return MHD_NO;
    return res_html(r, status, html);
}

int res_oauth_error_redirect(http_req *r, const char *redirect_uri, const char *error,
                             const char *desc, const char *state)
{
    char *e = url_encode(error);
    char *d = (desc && *desc) ? url_encode(desc) : NULL;
    char *s = (state && *state) ? url_encode(state) : NULL;
    sbuf loc;
    int rc = MHD_NO;
    if (e && sbuf_init(&loc, 512) == 0) {
        sbuf_adds(&loc, redirect_uri);
        sbuf_addch(&loc, strchr(redirect_uri, '?') ? '&' : '?');
        sbuf_adds(&loc, "error=");
        sbuf_adds(&loc, e);
        if (d) {
            sbuf_adds(&loc, "&error_description=");
            sbuf_adds(&loc, d);
        }
        if (s) {
            sbuf_adds(&loc, "&state=");
            sbuf_adds(&loc, s);
        }
        rc = res_redirect(r, loc.s);
        sbuf_free(&loc);
    }
    free(e);
    free(d);
    free(s);
    return rc;
}

/* ---------- routing ---------- */

struct route {
    const char *path;
    const char *method;
    int (*fn)(http_req *r);
};

static const struct route ROUTES[] = {
    {"/", "GET", handle_root},
    {"/healthz", "GET", handle_healthz},
    {"/.well-known/openid-configuration", "GET", handle_discovery},
    {"/.well-known/webfinger", "GET", handle_webfinger},
    {"/authorize", "GET", handle_authorize},
    {"/authorize", "POST", handle_authorize},
    {"/login", "GET", handle_login_get},
    {"/login", "POST", handle_login_post},
    {"/logout", "GET", handle_logout},
    {"/logout", "POST", handle_logout},
    {"/token", "POST", handle_token},
    {"/userinfo", "GET", handle_userinfo},
    {"/userinfo", "POST", handle_userinfo},
    {"/jwks.json", "GET", handle_jwks},
};

static int dispatch(http_req *r)
{
    char path[512];
    snprintf(path, sizeof path, "%s", r->path);
    size_t l = strlen(path);
    if (l > 1 && path[l - 1] == '/')
        path[l - 1] = 0;
    /* everything under /api goes through the mynetworks-gated admin router */
    if (strncmp(path, "/api", 4) == 0 && (path[4] == 0 || path[4] == '/'))
        return handle_api(r, path);
    const char *method = strcmp(r->method, "HEAD") == 0 ? "GET" : r->method;
    for (size_t i = 0; i < sizeof ROUTES / sizeof ROUTES[0]; i++)
        if (strcmp(ROUTES[i].path, path) == 0 && strcmp(ROUTES[i].method, method) == 0)
            return ROUTES[i].fn(r);
    return res_error_page(r, MHD_HTTP_NOT_FOUND, "Not found", "No such endpoint.");
}

/* ---------- body handling ---------- */

static void add_form(http_req *r, const char *k, const char *v)
{
    if (r->nforms >= MAX_FORMS)
        return;
    char *kd = strdup(k), *vd = strdup(v);
    if (!kd || !vd) {
        free(kd);
        free(vd);
        return;
    }
    r->forms[r->nforms].k = kd;
    r->forms[r->nforms].v = vd;
    r->nforms++;
}

static void free_forms(http_req *r)
{
    for (size_t i = 0; i < r->nforms; i++) {
        free(r->forms[i].k);
        free(r->forms[i].v);
    }
    r->nforms = 0;
}

static void parse_form_body(http_req *r, char *body)
{
    const char *ct = MHD_lookup_connection_value(r->conn, MHD_HEADER_KIND, "Content-Type");
    if (ct && strncmp(ct, "application/x-www-form-urlencoded", 33) != 0)
        return;
    if (!body || !*body)
        return;
    char *pair = body;
    while (pair && *pair) {
        char *amp = strchr(pair, '&');
        if (amp)
            *amp = 0;
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = 0;
            char k[512], v[2048];
            if (*pair && url_decode(pair, strlen(pair), k, sizeof k) == 0 &&
                url_decode(eq + 1, strlen(eq + 1), v, sizeof v) == 0)
                add_form(r, k, v);
        }
        pair = amp ? amp + 1 : NULL;
    }
}

/* ---------- peer address ---------- */

static void fill_peer_ip(http_req *r)
{
    r->peer_ip[0] = 0;
    const union MHD_ConnectionInfo *ci =
        MHD_get_connection_info(r->conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci && ci->client_addr) {
        struct sockaddr *sa = ci->client_addr;
        char ip[INET6_ADDRSTRLEN] = "";
        if (sa->sa_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, ip, sizeof ip);
        else if (sa->sa_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, ip, sizeof ip);
        snprintf(r->peer_ip, sizeof r->peer_ip, "%s", ip);
    }
    if (g_cfg.trust_proxy) {
        const char *xff = MHD_lookup_connection_value(r->conn, MHD_HEADER_KIND,
                                                      "X-Forwarded-For");
        if (xff && *xff) {
            char first[64];
            size_t n = 0;
            while (xff[n] && xff[n] != ',' && n + 1 < sizeof first) {
                first[n] = xff[n];
                n++;
            }
            first[n] = 0;
            snprintf(r->peer_ip, sizeof r->peer_ip, "%s", str_trim(first));
        }
    }
}

/* ---------- MHD integration ---------- */

static enum MHD_Result ahc(void *cls, struct MHD_Connection *conn, const char *url,
                           const char *method, const char *version,
                           const char *upload_data, size_t *upload_data_size,
                           void **con_cls)
{
    (void)cls;
    (void)version;
    struct conn_state *st = *con_cls;

    if (!st) {
        st = calloc(1, sizeof *st);
        if (!st)
            return MHD_NO;
        *con_cls = st;
        return MHD_YES;
    }

    if (*upload_data_size != 0) {
        if (st->too_large) {
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (st->body.len + *upload_data_size > BODY_MAX) {
            st->too_large = 1;
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (sbuf_add(&st->body, upload_data, *upload_data_size))
            return MHD_NO;
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (st->done)
        return MHD_YES;

    http_req r;
    memset(&r, 0, sizeof r);
    r.conn = conn;
    r.method = method;
    r.path = url;

    int rc;
    if (st->too_large) {
        rc = res_error_page(&r, MHD_HTTP_CONTENT_TOO_LARGE, "Payload too large",
                            "Request body exceeds the limit.");
    } else {
        fill_peer_ip(&r);
        parse_form_body(&r, st->body.s ? st->body.s : "");
        rc = dispatch(&r);
        free_forms(&r);
    }
    st->done = 1;
    return rc;
}

static void req_completed(void *cls, struct MHD_Connection *conn, void **con_cls,
                          enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)conn;
    (void)toe;
    struct conn_state *st = *con_cls;
    if (st) {
        sbuf_free(&st->body);
        free(st);
        *con_cls = NULL;
    }
}

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

int http_serve(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    unsigned port = 0;
    struct sockaddr_in bindaddr;
    int have_bind = 0;
    memset(&bindaddr, 0, sizeof bindaddr);
    bindaddr.sin_family = AF_INET;

    const char *l = g_cfg.listen;
    const char *colon = strrchr(l, ':');
    if (!colon) {
        port = (unsigned)atoi(l);
    } else {
        char host[64];
        size_t hl = (size_t)(colon - l);
        port = (unsigned)atoi(colon + 1);
        if (hl > 0) {
            if (hl >= sizeof host) {
                LOG_ERROR("IDAAS_LISTEN: host part too long");
                return -1;
            }
            memcpy(host, l, hl);
            host[hl] = 0;
            if (inet_pton(AF_INET, host, &bindaddr.sin_addr) != 1) {
                LOG_ERROR("IDAAS_LISTEN: '%s' is not an IPv4 address (or ':port')", host);
                return -1;
            }
            have_bind = 1;
        }
    }
    if (port == 0 || port > 65535) {
        LOG_ERROR("IDAAS_LISTEN: bad port in '%s'", g_cfg.listen);
        return -1;
    }
    bindaddr.sin_port = htons((unsigned short)port);

    struct MHD_Daemon *d;
    if (have_bind)
        d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, (unsigned short)port,
                             NULL, NULL, &ahc, NULL,
                             MHD_OPTION_SOCK_ADDR, &bindaddr,
                             MHD_OPTION_CONNECTION_LIMIT, (unsigned int)100,
                             MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
                             MHD_OPTION_NOTIFY_COMPLETED, req_completed, NULL,
                             MHD_OPTION_END);
    else
        d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, (unsigned short)port,
                             NULL, NULL, &ahc, NULL,
                             MHD_OPTION_CONNECTION_LIMIT, (unsigned int)100,
                             MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
                             MHD_OPTION_NOTIFY_COMPLETED, req_completed, NULL,
                             MHD_OPTION_END);
    if (!d) {
        LOG_ERROR("failed to start HTTP server on %s", g_cfg.listen);
        return -1;
    }
    LOG_INFO("listening on %s", g_cfg.listen);

    while (!g_stop)
        pause();
    MHD_stop_daemon(d);
    LOG_INFO("http server stopped");
    return 0;
}
