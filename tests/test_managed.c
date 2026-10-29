#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "managed.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_managed(void)
{
    char path[] = "/tmp/idaas-managed-test-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd);
    unlink(path); /* start with no store file at all */

    CHECK(managed_init(path) == 0);
    CHECK(managed_count() == 0);

    CHECK(managed_valid_username("dan") == 1);
    CHECK(managed_valid_username("a.b-c_9") == 1);
    CHECK(managed_valid_username("") == 0);
    CHECK(managed_valid_username("1bad:name") == 0);
    CHECK(managed_valid_username("has space") == 0);

    CHECK(managed_create("dan", "dan-pass-99", "Dan M", "dan@x.example", "dev,ops") == 0);
    CHECK(managed_create("dan", "other-pass-1", "", "", "") == 1); /* exists */
    CHECK(managed_count() == 1);

    CHECK(managed_authenticate("dan", "dan-pass-99") == 1);
    CHECK(managed_authenticate("dan", "wrong-pass-x") == 0);
    CHECK(managed_authenticate("ghost", "whatever-x") == 0);

    managed_user u;
    CHECK(managed_get("dan", &u) == 0);
    CHECK(strcmp(u.gecos, "Dan M") == 0);
    CHECK(strcmp(u.email, "dan@x.example") == 0);
    CHECK(u.disabled == 0);
    CHECK(u.uid >= 60001);
    CHECK(u.hash[0] == '$'); /* crypt(3) format */

    /* group splitting */
    char *gn[8];
    int n = managed_split_groups("dev,ops", gn, 8);
    CHECK(n == 2);
    if (n == 2) {
        CHECK(strcmp(gn[0], "dev") == 0);
        CHECK(strcmp(gn[1], "ops") == 0);
    }
    for (int i = 0; i < n; i++)
        free(gn[i]);
    CHECK(managed_split_groups("", gn, 8) == 0);

    /* persistence: reload from the file */
    CHECK(managed_init(path) == 0);
    CHECK(managed_count() == 1);
    CHECK(managed_authenticate("dan", "dan-pass-99") == 1);

    /* password update */
    managed_update_req up;
    memset(&up, 0, sizeof up);
    up.password = "new-pass-77";
    CHECK(managed_update("dan", &up) == 0);
    CHECK(managed_authenticate("dan", "dan-pass-99") == 0);
    CHECK(managed_authenticate("dan", "new-pass-77") == 1);
    CHECK(managed_update("ghost", &up) == 1); /* not found */

    /* disable */
    up.password = NULL;
    up.disabled = 1;
    CHECK(managed_update("dan", &up) == 0);
    CHECK(managed_authenticate("dan", "new-pass-77") == 0);
    managed_user u2;
    CHECK(managed_get("dan", &u2) == 0 && u2.disabled == 1);

    /* re-enable, then delete */
    up.disabled = 0;
    CHECK(managed_update("dan", &up) == 0);
    CHECK(managed_authenticate("dan", "new-pass-77") == 1);
    CHECK(managed_delete("dan") == 0);
    CHECK(managed_delete("dan") == 1);
    CHECK(managed_get("dan", &u2) == -1);

    unlink(path);
    return fails;
}
