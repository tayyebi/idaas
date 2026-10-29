#ifndef IDAAS_CTX_H
#define IDAAS_CTX_H

#include "config.h"
#include "jwt.h"
#include "store.h"

/* Process-wide state, owned by main(). Read-only after startup except the
 * stores, which are internally synchronized. */
extern config g_cfg;
extern signing_key g_key;
extern store *g_sessions; /* login sessions (cookie tokens, hashed keys) */
extern store *g_codes;    /* pending authorization codes (hashed keys) */
extern store *g_refresh;  /* refresh tokens (hashed keys) */
extern store *g_rl;       /* login rate-limit counters */

#endif
