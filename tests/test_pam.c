/* PAM integration test. Runs inside the docker test stage where the fixture
 * users below exist (created at image build time, never on the host):
 *   alice     uid>=1000, sha512crypt password
 *   bob       uid>=1000, yescrypt password (distro default)
 */
#include <stdio.h>

#include "pam_auth.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int main(void)
{
    CHECK(pam_login("alice", "alice-pass-1", NULL) == AUTH_OK);
    CHECK(pam_login("alice", "wrong-password", NULL) == AUTH_INVALID);
    CHECK(pam_login("bob", "bob-pass-2", NULL) == AUTH_OK);
    CHECK(pam_login("bob", "nope", NULL) == AUTH_INVALID);
    CHECK(pam_login("nosuchuser", "whatever", NULL) == AUTH_INVALID);

    if (fails) {
        printf("pamtest FAILED: %d check(s)\n", fails);
        return 1;
    }
    printf("pamtest passed\n");
    return 0;
}
