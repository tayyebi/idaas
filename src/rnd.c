#include "rnd.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "b64.h"

int rnd_bytes(unsigned char *buf, size_t n)
{
    return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

int rnd_token(char *out, size_t nbytes)
{
    if (nbytes > 48)
        return -1;
    unsigned char raw[48];
    if (rnd_bytes(raw, nbytes))
        return -1;
    b64url_encode(raw, nbytes, out);
    OPENSSL_cleanse(raw, nbytes);
    return 0;
}
