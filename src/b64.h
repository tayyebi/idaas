#ifndef IDAAS_B64_H
#define IDAAS_B64_H

#include <stddef.h>

/* Base64url (RFC 4648 §5, unpadded) encode. out must hold
 * ((n+2)/3)*4 + 1 bytes. Returns the number of characters written. */
size_t b64url_encode(const unsigned char *in, size_t n, char *out);

/* Decode base64url and standard base64 (both alphabets accepted, padding
 * tolerated). Returns 0 on success, -1 on invalid input or undersized out. */
int b64url_decode(const char *in, size_t n, unsigned char *out, size_t outsz, size_t *outlen);

#endif
