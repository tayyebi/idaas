#define _GNU_SOURCE /* crypt_r */
#include "managed.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <crypt.h>
#include <openssl/crypto.h>

#include "log.h"
#include "rnd.h"
#include "util.h"

#define MAX_MANAGED 1024

/* file format, one line per user:
 * username:uid:flags:created:gecos:email:groups:hash
 */
static managed_user *g_users;
static size_t g_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_path[480];
static char g_prefix[8]; /* crypt setting prefix, e.g. "$6$" */
static long g_uid_base = 60001;

int managed_valid_username(const char *s)
{
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 1 || n > 32)
        return 0;
    char c0 = s[0];
    if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') ||
          (c0 >= '0' && c0 <= '9') || c0 == '_'))
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

/* ---------- persistence ---------- */

/* caller holds g_mu; returns 0 on success */
static int persist_locked(void)
{
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", g_path) >= (int)sizeof tmp)
        return -1;
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    for (size_t i = 0; i < g_n; i++) {
        managed_user *u = &g_users[i];
        if (fprintf(f, "%s:%ld:%c:%lld:%s:%s:%s:%s\n",
                    u->username, u->uid, u->disabled ? 'D' : 'A',
                    (long long)u->created, u->gecos, u->email, u->groups,
                    u->hash) < 0) {
            fclose(f);
            unlink(tmp);
            return -1;
        }
    }
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    fclose(f);
    chmod(tmp, 0600);
    if (rename(tmp, g_path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* bounded copy; -1 if src (plus NUL) does not fit */
static int set_field(char *dst, size_t n, const char *src)
{
    size_t l = strlen(src);
    if (l >= n)
        return -1;
    memcpy(dst, src, l + 1);
    return 0;
}

static int load_locked(void)
{
    FILE *f = fopen(g_path, "r");
    if (!f)
        return 0; /* missing file = empty store */
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl)
            *nl = 0;
        char *fld[8];
        int nf = 0;
        char *p = line;
        fld[nf++] = p;
        for (char *c = line; *c && nf < 8; c++) {
            if (*c == ':') {
                *c = 0;
                fld[nf++] = c + 1;
            }
        }
        if (nf != 8 || !*fld[0] || g_n >= MAX_MANAGED)
            continue; /* skip malformed */
        if (!managed_valid_username(fld[0]))
            continue;
        managed_user u;
        memset(&u, 0, sizeof u);
        if (set_field(u.username, sizeof u.username, fld[0]) ||
            set_field(u.gecos, sizeof u.gecos, fld[4]) ||
            set_field(u.email, sizeof u.email, fld[5]) ||
            set_field(u.groups, sizeof u.groups, fld[6]) ||
            set_field(u.hash, sizeof u.hash, fld[7]))
            continue;
        u.uid = strtol(fld[1], NULL, 10);
        u.disabled = (*fld[2] == 'D');
        u.created = (time_t)strtoll(fld[3], NULL, 10);
        g_users[g_n++] = u;
    }
    fclose(f);
    return 0;
}

int managed_init(const char *path)
{
    if (!path || !*path || strlen(path) >= sizeof g_path)
        return -1;
    const char *method = getenv("IDAAS_HASH_METHOD");
    if (method && strcmp(method, "SHA256") == 0)
        snprintf(g_prefix, sizeof g_prefix, "$5$");
    else
        snprintf(g_prefix, sizeof g_prefix, "$6$");
    const char *base = getenv("IDAAS_MANAGED_UID_BASE");
    if (base && *base) {
        long b = strtol(base, NULL, 10);
        if (b > 0)
            g_uid_base = b;
    }

    pthread_mutex_lock(&g_mu);
    snprintf(g_path, sizeof g_path, "%s", path);
    free(g_users);
    g_users = calloc(MAX_MANAGED, sizeof *g_users);
    g_n = 0;
    int rc = g_users ? load_locked() : -1;
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* ---------- reads ---------- */

size_t managed_count(void)
{
    pthread_mutex_lock(&g_mu);
    size_t n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int managed_list(managed_user *out, size_t maxn)
{
    pthread_mutex_lock(&g_mu);
    size_t n = g_n < maxn ? g_n : maxn;
    memcpy(out, g_users, n * sizeof *out);
    pthread_mutex_unlock(&g_mu);
    return (int)n;
}

int managed_get(const char *username, managed_user *out)
{
    if (!username)
        return -1;
    pthread_mutex_lock(&g_mu);
    int rc = -1;
    for (size_t i = 0; i < g_n; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            *out = g_users[i];
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* ---------- writes ---------- */

static int copy_field(char *dst, size_t dstn, const char *src)
{
    if (!src)
        return 0;
    if (strlen(src) >= dstn)
        return -1;
    snprintf(dst, dstn, "%s", src);
    return 0;
}

int managed_create(const char *username, const char *password,
                   const char *gecos, const char *email, const char *groups)
{
    if (!managed_valid_username(username) || !password || !*password)
        return -1;

    char hash[256];
    unsigned char rnd[16];
    static const char SA[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if (rnd_bytes(rnd, sizeof rnd) != 0)
        return -1;
    char salt[17];
    for (size_t i = 0; i < sizeof rnd; i++)
        salt[i] = SA[rnd[i] & 63];
    salt[16] = 0;
    char setting[32];
    snprintf(setting, sizeof setting, "%s%s", g_prefix, salt);

    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd)
        return -1;
    char *h = crypt_r(password, setting, cd);
    int ok = h && h[0] && strlen(h) < sizeof hash;
    if (ok)
        snprintf(hash, sizeof hash, "%s", h);
    OPENSSL_cleanse(cd, sizeof *cd);
    free(cd);
    if (!ok)
        return -1;

    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < g_n; i++)
        if (strcmp(g_users[i].username, username) == 0) {
            pthread_mutex_unlock(&g_mu);
            return 1;
        }
    if (g_n >= MAX_MANAGED) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    managed_user u;
    memset(&u, 0, sizeof u);
    snprintf(u.username, sizeof u.username, "%s", username);
    long maxuid = g_uid_base;
    for (size_t i = 0; i < g_n; i++)
        if (g_users[i].uid > maxuid)
            maxuid = g_users[i].uid;
    u.uid = maxuid + 1;
    u.created = time(NULL);
    if (copy_field(u.gecos, sizeof u.gecos, gecos) ||
        copy_field(u.email, sizeof u.email, email) ||
        copy_field(u.groups, sizeof u.groups, groups)) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    snprintf(u.hash, sizeof u.hash, "%s", hash);

    g_users[g_n++] = u;
    int rc = persist_locked();
    if (rc != 0) {
        g_n--; /* roll back */
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    pthread_mutex_unlock(&g_mu);
    return 0;
}

int managed_update(const char *username, const managed_update_req *u)
{
    if (!username || !u)
        return -1;
    pthread_mutex_lock(&g_mu);
    managed_user *found = NULL;
    for (size_t i = 0; i < g_n; i++)
        if (strcmp(g_users[i].username, username) == 0) {
            found = &g_users[i];
            break;
        }
    if (!found) {
        pthread_mutex_unlock(&g_mu);
        return 1;
    }
    managed_user backup = *found;

    if (u->password && *u->password) {
        unsigned char rnd[16];
        static const char SA[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        char salt[17], setting[32];
        struct crypt_data *cd = calloc(1, sizeof *cd);
        int ok = cd && rnd_bytes(rnd, sizeof rnd) == 0;
        if (ok) {
            for (size_t i = 0; i < sizeof rnd; i++)
                salt[i] = SA[rnd[i] & 63];
            salt[16] = 0;
            snprintf(setting, sizeof setting, "%s%s", g_prefix, salt);
            char *h = crypt_r(u->password, setting, cd);
            ok = h && h[0] && strlen(h) < sizeof found->hash;
            if (ok)
                snprintf(found->hash, sizeof found->hash, "%s", h);
        }
        OPENSSL_cleanse(cd, sizeof *cd);
        free(cd);
        if (!ok) {
            pthread_mutex_unlock(&g_mu);
            return -1;
        }
    }
    if (copy_field(found->gecos, sizeof found->gecos, u->gecos) ||
        copy_field(found->email, sizeof found->email, u->email) ||
        copy_field(found->groups, sizeof found->groups, u->groups)) {
        *found = backup;
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    if (u->disabled >= 0)
        found->disabled = u->disabled ? 1 : 0;

    int rc = persist_locked();
    if (rc != 0)
        *found = backup; /* roll back */
    pthread_mutex_unlock(&g_mu);
    return rc == 0 ? 0 : -1;
}

int managed_delete(const char *username)
{
    if (!username)
        return -1;
    pthread_mutex_lock(&g_mu);
    int rc = 1;
    for (size_t i = 0; i < g_n; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            size_t last_idx = g_n - 1;
            managed_user victim = g_users[i];
            if (i != last_idx)
                g_users[i] = g_users[last_idx];
            g_n--;
            rc = persist_locked();
            if (rc != 0) {
                if (i != last_idx)
                    g_users[last_idx] = g_users[i]; /* tail back to the end */
                g_users[i] = victim;
                g_n++;
                rc = -1;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* ---------- authentication ---------- */

int managed_authenticate(const char *username, const char *password)
{
    managed_user u;
    if (managed_get(username, &u) != 0)
        return 0;
    if (u.disabled || !u.hash[0] || !password || !*password)
        return 0;
    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd)
        return 0;
    char *h = crypt_r(password, u.hash, cd);
    int ok = h && h[0] && strlen(h) == strlen(u.hash) &&
             ct_eq(h, u.hash, strlen(u.hash));
    OPENSSL_cleanse(cd, sizeof *cd);
    free(cd);
    return ok;
}

/* ---------- helpers ---------- */

int managed_split_groups(const char *csv, char **out, size_t maxn)
{
    if (!csv || !*csv)
        return 0;
    size_t n = 0;
    const char *p = csv;
    while (*p && n < maxn) {
        const char *e = strchr(p, ',');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len) {
            char *tok = malloc(len + 1);
            if (tok) {
                memcpy(tok, p, len);
                tok[len] = 0;
                out[n++] = tok;
            }
        }
        p = e ? e + 1 : p + len;
    }
    return (int)n;
}
