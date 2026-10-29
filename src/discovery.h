#ifndef IDAAS_DISCOVERY_H
#define IDAAS_DISCOVERY_H

#include "http.h"

int handle_root(http_req *r);
int handle_healthz(http_req *r);
int handle_discovery(http_req *r);
int handle_webfinger(http_req *r);
int handle_jwks(http_req *r);

#endif
