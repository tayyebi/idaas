#ifndef IDAAS_JWT_VERIFY_H
#define IDAAS_JWT_VERIFY_H

#include "jwt.h"

/* Claims extracted from access tokens we issued. */
typedef struct access_claims {
    char sub[64];
    char aud[128];
    char scope[256];
    char jti[64];
    char sid[64];
    long iat, exp;
} access_claims;

/* Verify one of our own RS256 access tokens: signature, expiry and issuer.
 * Values are only ever ones we produced, so the tiny "find a key and read
 * until the quote" extraction below is sufficient (no string values in our
 * tokens contain quotes). Returns 0 on success. */
int jwt_verify_access(const signing_key *k, const char *issuer,
                      const char *token, access_claims *out);

#endif
