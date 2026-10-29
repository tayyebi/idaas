#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "admin.h"
#include "config.h"
#include "ctx.h"
#include "http.h"
#include "jwt.h"
#include "log.h"
#include "managed.h"
#include "store.h"

config g_cfg;
signing_key g_key;
store *g_sessions;
store *g_codes;
store *g_refresh;
store *g_rl;

static void *sweeper(void *arg)
{
    (void)arg;
    for (;;) {
        sleep(10);
        store_sweep(g_sessions);
        store_sweep(g_codes);
        store_sweep(g_refresh);
        store_sweep(g_rl);
    }
    return NULL;
}

int main(void)
{
    const char *lvl = getenv("IDAAS_LOG_LEVEL");
    if (lvl) {
        if (strcmp(lvl, "debug") == 0)
            log_set_level(LOG_LVL_DEBUG);
        else if (strcmp(lvl, "warn") == 0)
            log_set_level(LOG_LVL_WARN);
        else if (strcmp(lvl, "error") == 0)
            log_set_level(LOG_LVL_ERROR);
    }

    if (config_from_env(&g_cfg) != 0)
        return 1;
    if (config_load_clients(&g_cfg) != 0)
        return 1;
    if (keys_init(&g_key, g_cfg.data_dir) != 0) {
        LOG_ERROR("key initialization failed in %s", g_cfg.data_dir);
        return 1;
    }

    char managed_file[512];
    const char *menv = getenv("IDAAS_MANAGED_USERS_FILE");
    if (menv && *menv)
        snprintf(managed_file, sizeof managed_file, "%s", menv);
    else
        snprintf(managed_file, sizeof managed_file, "%s/managed-users", g_cfg.data_dir);
    if (managed_init(managed_file) != 0) {
        LOG_ERROR("managed users store failed at %s", managed_file);
        return 1;
    }
    if (admin_init() != 0)
        return 1;

    g_sessions = store_new();
    g_codes = store_new();
    g_refresh = store_new();
    g_rl = store_new();
    if (!g_sessions || !g_codes || !g_refresh || !g_rl) {
        LOG_ERROR("out of memory");
        return 1;
    }

    LOG_INFO("idaas starting: issuer=%s listen=%s clients=%zu uid_range=[%ld,%ld] "
             "managed_users=%zu",
             g_cfg.issuer, g_cfg.listen, g_cfg.n_clients, g_cfg.uid_min, g_cfg.uid_max,
             managed_count());

    pthread_t th;
    if (pthread_create(&th, NULL, sweeper, NULL) == 0)
        pthread_detach(th);

    int rc = http_serve();
    LOG_INFO("idaas exiting");
    return rc ? 1 : 0;
}
