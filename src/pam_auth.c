#include "pam_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "log.h"

struct conv_data {
    const char *password;
    int answered;
};

static int idaas_conv(int n, const struct pam_message **msgv,
                      struct pam_response **respv, void *appdata)
{
    struct conv_data *cd = appdata;
    if (n <= 0 || !msgv || !respv)
        return PAM_CONV_ERR;
    *respv = calloc((size_t)n, sizeof **respv);
    if (!*respv)
        return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        switch (msgv[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            /* answer the password prompt exactly once */
            if (cd->answered || !cd->password) {
                free(*respv);
                *respv = NULL;
                return PAM_CONV_ERR;
            }
            respv[i]->resp = strdup(cd->password);
            if (!respv[i]->resp) {
                free(*respv);
                *respv = NULL;
                return PAM_BUF_ERR;
            }
            cd->answered = 1;
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            break; /* informational; libpam owns the messages */
        default:
            free(*respv);
            *respv = NULL;
            return PAM_CONV_ERR;
        }
    }
    return PAM_SUCCESS;
}

auth_result pam_login(const char *username, const char *password, const char *rhost)
{
    if (!username || !*username || !password)
        return AUTH_INVALID;

    struct conv_data cd = { password, 0 };
    struct pam_conv conv = { idaas_conv, &cd };
    pam_handle_t *h = NULL;

    if (pam_start("idaas", username, &conv, &h) != PAM_SUCCESS)
        return AUTH_ERROR;
    if (rhost && *rhost)
        pam_set_item(h, PAM_RHOST, rhost);

    int rc = pam_authenticate(h, 0);
    if (rc == PAM_SUCCESS)
        rc = pam_acct_mgmt(h, 0);

    if (rc != PAM_SUCCESS && rc != PAM_USER_UNKNOWN && rc != PAM_AUTH_ERR)
        /* log the precise reason at debug level; callers only see the class */
        LOG_DEBUG("pam %s: %s", username, pam_strerror(h, rc));

    pam_end(h, rc);

    switch (rc) {
    case PAM_SUCCESS:
        return AUTH_OK;
    case PAM_AUTH_ERR:
    case PAM_USER_UNKNOWN:
    case PAM_CRED_ERR:
    case PAM_CRED_INSUFFICIENT:
    case PAM_MAXTRIES:
        return AUTH_INVALID;
    case PAM_ACCT_EXPIRED:
    case PAM_PERM_DENIED:
    case PAM_NEW_AUTHTOK_REQD:
        return AUTH_ACCOUNT;
    default:
        return AUTH_ERROR;
    }
}
