#include "discovery.h"

#include <stdio.h>
#include <string.h>

#include "ctx.h"
#include "jsonw.h"
#include "util.h"

int handle_root(http_req *r)
{
    return res_text(r, MHD_HTTP_OK,
                    "idaas: an OIDC provider backed by Linux accounts\n"
                    "See /.well-known/openid-configuration\n");
}

int handle_healthz(http_req *r)
{
    sbuf b;
    if (sbuf_init(&b, 64) != 0)
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "status", "ok");
    jw_obj_end(&b);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

int handle_jwks(http_req *r)
{
    sbuf b;
    if (sbuf_init(&b, 640) != 0)
        return MHD_NO;
    jwks_json(&g_key, &b);
    int rc = res_json_public(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

int handle_discovery(http_req *r)
{
    static const char *const scopes[] = { "openid", "profile", "email", "groups" };
    static const char *const response_types[] = { "code" };
    static const char *const response_modes[] = { "query" };
    static const char *const grant_types[] = { "authorization_code", "refresh_token" };
    static const char *const subject_types[] = { "public" };
    static const char *const algs[] = { "RS256" };
    static const char *const client_auth[] = { "client_secret_basic", "client_secret_post", "none" };
    static const char *const ccms[] = { "S256" };
    static const char *const claims[] = {
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
        "sid", "name", "preferred_username", "email", "email_verified", "groups",
    };

    sbuf b;
    if (sbuf_init(&b, 1024) != 0)
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    char u[600];
#define EP(name, path)                                  \
    do {                                                \
        snprintf(u, sizeof u, "%s%s", g_cfg.issuer, path); \
        jw_str(&b, name, u);                            \
    } while (0)
    EP("issuer", "");
    EP("authorization_endpoint", "/authorize");
    EP("token_endpoint", "/token");
    EP("userinfo_endpoint", "/userinfo");
    EP("jwks_uri", "/jwks.json");
    EP("end_session_endpoint", "/logout");
#undef EP
    jw_str_arr(&b, "scopes_supported", (char *const *)scopes, 4);
    jw_str_arr(&b, "response_types_supported", (char *const *)response_types, 1);
    jw_str_arr(&b, "response_modes_supported", (char *const *)response_modes, 1);
    jw_str_arr(&b, "grant_types_supported", (char *const *)grant_types, 2);
    jw_str_arr(&b, "subject_types_supported", (char *const *)subject_types, 1);
    jw_str_arr(&b, "id_token_signing_alg_values_supported", (char *const *)algs, 1);
    jw_str_arr(&b, "token_endpoint_auth_methods_supported", (char *const *)client_auth, 3);
    jw_str_arr(&b, "code_challenge_methods_supported", (char *const *)ccms, 1);
    jw_str_arr(&b, "claims_supported", (char *const *)claims,
               sizeof claims / sizeof claims[0]);
    jw_bool(&b, "claims_parameter_supported", 0);
    jw_obj_end(&b);
    int rc = res_json_public(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}

int handle_webfinger(http_req *r)
{
    const char *rel = req_query(r, "rel");
    const char *resource = req_query(r, "resource");
    if (!rel || strcmp(rel, "http://openid.net/specs/connect/1.0/issuer") != 0)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "rel must be the OIDC issuer identifier");
    if (!resource || !*resource)
        return res_error_json(r, MHD_HTTP_BAD_REQUEST, "invalid_request",
                              "resource is required");

    sbuf b;
    if (sbuf_init(&b, 256) != 0)
        return MHD_NO;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "subject", resource);
    jw_arr_begin(&b, "links");
    jw_obj_begin(&b, NULL);
    jw_str(&b, "rel", "http://openid.net/specs/connect/1.0/issuer");
    jw_str(&b, "href", g_cfg.issuer);
    jw_obj_end(&b);
    jw_arr_end(&b);
    jw_obj_end(&b);
    int rc = res_json(r, MHD_HTTP_OK, &b);
    sbuf_free(&b);
    return rc;
}
