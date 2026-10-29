#ifndef IDAAS_LOG_H
#define IDAAS_LOG_H

enum {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO  = 1,
    LOG_LVL_WARN  = 2,
    LOG_LVL_ERROR = 3,
};

void log_set_level(int lvl);

/* JSON-lines logging on stdout. Never pass secrets as arguments. */
void idaas_log(int lvl, const char *fmt, ...);
#define LOG_DEBUG(...) idaas_log(LOG_LVL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  idaas_log(LOG_LVL_INFO, __VA_ARGS__)
#define LOG_WARN(...)  idaas_log(LOG_LVL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) idaas_log(LOG_LVL_ERROR, __VA_ARGS__)

/* Audit events (login, authorize, ...): {"event":..,"user":..,"ip":..,"result":..,"detail":..} */
void log_audit(const char *event, const char *user, const char *ip,
               const char *result, const char *detail);

#endif
