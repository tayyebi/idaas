#ifndef IDAAS_USERS_H
#define IDAAS_USERS_H

#include "config.h"
#include "util.h"

/* Lookups go through NSS, which reads the passwd/group snapshots mounted
 * into the container. */

typedef struct user_info {
    char username[64];
    char gecos[128];   /* first GECOS field: the display name */
    long uid;
    long gid;
} user_info;

/* 0 if the account exists. */
int user_lookup(const char *username, user_info *out);

/* 0 if the account exists and its uid is inside the configured login range. */
int user_login_allowed(const config *cfg, const char *username, user_info *out);

/* Group names the user belongs to (primary + supplementary), from the group
 * snapshot. Fills at most maxn entries; returns the number filled. Caller
 * frees each name. */
int user_groups(const char *username, long gid, char **names, size_t maxn);

char *user_email(const config *cfg, const char *username); /* caller frees */

/* Append profile/email/groups claims (per the granted scope) to an already
 * open JSON object in b. */
void users_add_claims(sbuf *b, const config *cfg, const char *username, const char *scope);

#endif
