#ifndef IDAAS_MANAGED_H
#define IDAAS_MANAGED_H

#include <stddef.h>
#include <time.h>

/* API-managed users: a small local store under the data dir (e.g.
 * /data/managed-users). These accounts exist only for idaas — never on the
 * host — and are verified locally with crypt_r() instead of PAM. On a name
 * collision with a snapshot (Linux) user, the managed entry wins. */

typedef struct managed_user {
    char username[33];
    char hash[256];   /* crypt(3) string; empty = password login disabled */
    char gecos[128];  /* display name */
    char email[192];  /* empty = synthesize from IDAAS_EMAIL_DOMAIN */
    char groups[512]; /* comma-separated group names */
    int disabled;
    long uid;         /* internal, virtual uid for uniqueness */
    time_t created;
} managed_user;

typedef struct managed_update_req {
    const char *password; /* NULL = unchanged */
    const char *gecos;    /* NULL = unchanged */
    const char *email;    /* NULL = unchanged, "" clears */
    const char *groups;   /* NULL = unchanged, "" clears */
    int disabled;         /* -1 unchanged, 0/1 set */
} managed_update_req;

/* Load (or start empty) the store at path. Safe to call again to reload.
 * Reads IDAAS_HASH_METHOD (SHA512|SHA256, default SHA512) and
 * IDAAS_MANAGED_UID_BASE (default 60001) from the environment. */
int managed_init(const char *path);

size_t managed_count(void);
int managed_list(managed_user *out, size_t maxn); /* returns count copied */
int managed_get(const char *username, managed_user *out); /* 0 / -1 */

/* 0 created, 1 already exists, -1 error. */
int managed_create(const char *username, const char *password,
                   const char *gecos, const char *email, const char *groups);
/* 0 updated, 1 not found, -1 error. */
int managed_update(const char *username, const managed_update_req *u);
/* 0 deleted, 1 not found, -1 error. */
int managed_delete(const char *username);

/* Verify password (and not disabled). Never calls PAM. */
int managed_authenticate(const char *username, const char *password);

/* Split the comma-separated groups field into strdup'd tokens. */
int managed_split_groups(const char *csv, char **out, size_t maxn);

/* Shared username policy: [A-Za-z0-9_.-]{1,32}, must start alnum or '_'. */
int managed_valid_username(const char *s);

#endif
