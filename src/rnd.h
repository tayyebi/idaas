#ifndef IDAAS_RND_H
#define IDAAS_RND_H

#include <stddef.h>

/* Fill buf with n cryptographically random bytes (OpenSSL RAND). */
int rnd_bytes(unsigned char *buf, size_t n);

/* Random URL-safe token: b64url of nbytes random bytes, NUL-terminated.
 * out must hold ((nbytes+2)/3)*4 + 1 bytes; nbytes <= 48. */
int rnd_token(char *out, size_t nbytes);

#endif
