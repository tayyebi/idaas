#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "store.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

struct foo {
    int a;
    char s[16];
};

int test_store(void)
{
    store *st = store_new();
    CHECK(st != NULL);
    CHECK(store_len(st) == 0);

    struct foo v = { 1, "x" };
    CHECK(store_put(st, "k1", &v, sizeof v, time(NULL) + 60) == 0);
    CHECK(store_len(st) == 1);

    struct foo g;
    CHECK(store_get_copy(st, "k1", &g, sizeof g) == 0);
    CHECK(g.a == 1 && strcmp(g.s, "x") == 0);

    /* upsert replaces */
    struct foo v2 = { 2, "y" };
    CHECK(store_put(st, "k1", &v2, sizeof v2, time(NULL) + 60) == 0);
    CHECK(store_len(st) == 1);
    CHECK(store_get_copy(st, "k1", &g, sizeof g) == 0);
    CHECK(g.a == 2);

    /* take removes */
    void *taken = store_take(st, "k1");
    CHECK(taken != NULL);
    free(taken);
    CHECK(store_take(st, "k1") == NULL);
    CHECK(store_len(st) == 0);

    /* expired entries are invisible and swept */
    CHECK(store_put(st, "exp", &v, sizeof v, time(NULL) - 1) == 0);
    CHECK(store_get_copy(st, "exp", &g, sizeof g) == -1);
    store_sweep(st);
    CHECK(store_len(st) == 0);

    /* oversize key rejected */
    char longkey[70];
    memset(longkey, 'a', sizeof longkey - 1);
    longkey[sizeof longkey - 1] = 0;
    CHECK(store_put(st, longkey, &v, sizeof v, time(NULL) + 60) == -1);

    store_free(st);
    return fails;
}
