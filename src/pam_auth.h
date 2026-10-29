#ifndef IDAAS_PAM_AUTH_H
#define IDAAS_PAM_AUTH_H

typedef enum {
    AUTH_OK = 0,
    AUTH_INVALID,   /* unknown user / wrong password (indistinguishable by design) */
    AUTH_ACCOUNT,   /* account expired / locked / password change required */
    AUTH_ERROR      /* internal failure */
} auth_result;

/* Authenticate username/password through PAM (service "idaas", pam_unix
 * against the mounted passwd/shadow snapshots) and run account management.
 * rhost may be NULL. Never logs the password. */
auth_result pam_login(const char *username, const char *password, const char *rhost);

#endif
