#ifndef IDAAS_JWT_H
#define IDAAS_JWT_H

#include <openssl/evp.h>

#include "util.h"

typedef struct signing_key {
    EVP_PKEY *pkey;
    char kid[17];     /* 16 hex chars */
    char n_b64[384];  /* public modulus, base64url */
    char e_b64[8];    /* public exponent, base64url */
} signing_key;

/* Load <data_dir>/keys/rsa.pem or generate + persist a new RSA-2048 key
 * (file mode 0600). Returns 0 on success. */
int keys_init(signing_key *k, const char *data_dir);

/* Sign a JSON payload as an RS256 JWS. *out is malloc'd; caller frees. */
int jwt_sign_rs256(const signing_key *k, const char *payload_json, char **out);

/* Append the JWKS document for this key to an sbuf. */
int jwks_json(const signing_key *k, sbuf *out);

#endif
