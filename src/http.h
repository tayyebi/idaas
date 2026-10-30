#ifndef IDAAS_HTTP_H
#define IDAAS_HTTP_H

#include <microhttpd.h>

#include "util.h"

typedef struct http_req http_req;

/* Request accessors. Returned strings are valid only for the duration of
 * the request. Query params come from MHD (already decoded); form params
 * are parsed from an application/x-www-form-urlencoded body. */
const char *req_query(http_req *r, const char *name);
const char *req_form(http_req *r, const char *name);
const char *req_param(http_req *r, const char *name); /* query, then form */
const char *req_header(http_req *r, const char *name);
const char *req_cookie(http_req *r, const char *name);

/* One parsed request cookie (names/values copied, safe past the request). */
typedef struct req_cookie_kv {
    char name[64];
    char value[256];
} req_cookie_kv;

/* Copy up to max cookies whose name starts with prefix into out.
 * Returns how many were copied. */
size_t req_cookies_prefix(http_req *r, const char *prefix,
                          req_cookie_kv *out, size_t max);

const char *req_method(http_req *r);   /* "GET", "POST", ... */
const char *req_peer_ip(http_req *r);  /* peer (or X-Forwarded-For) address */

/* Response helpers. */
void res_set_cookie(http_req *r, const char *name, const char *val, long max_age,
                    int secure, int httponly, const char *samesite);
void res_set_header(http_req *r, const char *name, const char *val);
int res_text(http_req *r, int status, const char *txt);
int res_html(http_req *r, int status, char *heap_html); /* takes ownership */
int res_json(http_req *r, int status, sbuf *body);      /* takes ownership of body->s */
int res_json_public(http_req *r, int status, sbuf *body); /* cacheable */
int res_redirect(http_req *r, const char *location);
int res_error_json(http_req *r, int status, const char *err, const char *desc);
int res_error_page(http_req *r, int status, const char *title, const char *msg);
int res_oauth_error_redirect(http_req *r, const char *redirect_uri, const char *error,
                             const char *desc, const char *state);

/* Start the HTTP server; blocks until SIGINT/SIGTERM. 0 on clean shutdown. */
int http_serve(void);

#endif
