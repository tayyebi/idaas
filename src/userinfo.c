#include "userinfo.h"

#include <string.h>

#include "ctx.h"
#include "jsonw.h"
#include "jwt_verify.h"
#include "users.h"
#include "util.h"

static int unauthorized(http_req *r, const char *why)
{
    res_set_header(r, "WWW-Authenticate", "Bearer error=\"invalid_token\"");
    return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "invalid_token", why);
}

int handle_userinfo(http_req *r)
{
    const char *h = req_header(r, "Authorization");
    if (!h || strncmp(h, "Bearer ", 7) != 0)
        return res_error_json(r, MHD_HTTP_UNAUTHORIZED, "invalid_request",
                              "Bearer token required");
    const char *tok = h + 7;
    while (*tok == ' ')
        tok++;

    access_claims c;
    if (jwt_verify_access(&g_key, g_cfg.issuer, tok, &c) != 0)
        return unauthorized(r, "token rejected");

    sbuf b;
    if (sbuf_init(&b, 256) != 0)
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "sub", c.sub);
    users_add_claims(&b, &g_cfg, c.sub, c.scope);
    jw_obj_end(&b);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}
