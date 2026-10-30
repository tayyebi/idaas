#ifndef IDAAS_CHOOSE_H
#define IDAAS_CHOOSE_H

#include "accounts.h"
#include "http.h"
#include "session.h"

/* The account-chooser interstitial rendered by /authorize. */
int choose_render_page(http_req *r, const session *s,
                       const account_entry *accts, int n, const char *error);

/* POST /choose: confirm the picked remembered account and mint the code. */
int handle_choose_post(http_req *r);

#endif
