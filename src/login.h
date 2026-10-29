#ifndef IDAAS_LOGIN_H
#define IDAAS_LOGIN_H

#include "http.h"
#include "session.h"

/* Render the login page for this session (error may be NULL). */
int login_render_page(http_req *r, const session *s, const char *error);

int handle_login_get(http_req *r);
int handle_login_post(http_req *r);
int handle_logout(http_req *r);

#endif
