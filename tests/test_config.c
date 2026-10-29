#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "util.h"

static int fails;
#define CHECK(c)                                                        \
    do {                                                                \
        if (!(c)) {                                                     \
            fails++;                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                               \
    } while (0)

int test_config(void)
{
    config c;

    unsetenv("IDAAS_ISSUER");
    CHECK(config_from_env(&c) == -1);

    setenv("IDAAS_ISSUER", "https://sso.example.com/", 1);
    CHECK(config_from_env(&c) == 0);
    CHECK(strcmp(c.issuer, "https://sso.example.com") == 0); /* trailing slash stripped */
    CHECK(c.cookie_secure == 1);
    CHECK(c.uid_min == 1000 && c.uid_max == 60000);

    setenv("IDAAS_ISSUER", "http://dev.local", 1);
    CHECK(config_from_env(&c) == 0);
    CHECK(c.cookie_secure == 0);

    /* clients file */
    char path[] = "/tmp/idaas-clients-test-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    dprintf(fd,
            "# comment\n"
            "[app]\n"
            "secret = s3cr3t-value\n"
            "redirect_uri = https://a.example/cb\n"
            "redirect_uri = https://a.example/cb2\n"
            "scope = openid email\n"
            "\n"
            "[pub]\n"
            "public\n"
            "redirect_uri = http://localhost:9/cb\n");
    close(fd);
    snprintf(c.clients_file, sizeof c.clients_file, "%s", path);

    CHECK(config_load_clients(&c) == 0);
    const oauth_client *app = config_find_client(&c, "app");
    CHECK(app != NULL);
    CHECK(client_is_public(app) == 0);
    CHECK(client_redirect_ok(app, "https://a.example/cb") == 1);
    CHECK(client_redirect_ok(app, "https://a.example/cb2") == 1);
    CHECK(client_redirect_ok(app, "https://evil.example/cb") == 0);
    CHECK(scope_subset("openid", app->scope) == 1);

    const oauth_client *pub = config_find_client(&c, "pub");
    CHECK(pub != NULL);
    CHECK(client_is_public(pub) == 1);

    CHECK(config_find_client(&c, "nope") == NULL);
    CHECK(config_redirect_registered(&c, "http://localhost:9/cb") == 1);
    CHECK(config_redirect_registered(&c, "https://evil.example/x") == 0);

    unlink(path);
    return fails;
}
