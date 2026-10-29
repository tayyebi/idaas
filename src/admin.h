#ifndef IDAAS_ADMIN_H
#define IDAAS_ADMIN_H

#include "http.h"

/* Parse IDAAS_ADMIN_NETWORKS / IDAAS_ADMIN_TOKEN once at startup.
 * With no networks configured, every admin request is refused. */
int admin_init(void);

/* Entry point for /api/... paths (called from the HTTP dispatcher). Applies
 * the mynetworks CIDR gate and the optional bearer token, then routes. */
int handle_api(http_req *r, const char *path);

#endif
