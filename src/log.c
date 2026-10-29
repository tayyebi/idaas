#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "jsonw.h"
#include "util.h"

static int g_level = LOG_LVL_INFO;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void log_set_level(int lvl)
{
    if (lvl >= LOG_LVL_DEBUG && lvl <= LOG_LVL_ERROR)
        g_level = lvl;
}

static void ts_now(char *out, size_t n)
{
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    struct tm tm;
    gmtime_r(&tp.tv_sec, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static const char *lvl_name(int lvl)
{
    switch (lvl) {
    case LOG_LVL_DEBUG: return "debug";
    case LOG_LVL_INFO:  return "info";
    case LOG_LVL_WARN:  return "warn";
    default:             return "error";
    }
}

static void emit(sbuf *b)
{
    pthread_mutex_lock(&g_mu);
    fputs(b->s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    pthread_mutex_unlock(&g_mu);
}

void idaas_log(int lvl, const char *fmt, ...)
{
    if (lvl < g_level)
        return;
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    char ts[40];
    ts_now(ts, sizeof ts);

    sbuf b;
    if (sbuf_init(&b, 256))
        return;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "ts", ts);
    jw_str(&b, "lvl", lvl_name(lvl));
    jw_str(&b, "msg", msg);
    jw_obj_end(&b);
    emit(&b);
    sbuf_free(&b);
}

void log_audit(const char *event, const char *user, const char *ip,
               const char *result, const char *detail)
{
    char ts[40];
    ts_now(ts, sizeof ts);

    sbuf b;
    if (sbuf_init(&b, 256))
        return;
    jw_obj_begin(&b, NULL);
    jw_str(&b, "ts", ts);
    jw_str(&b, "event", event ? event : "");
    jw_str(&b, "user", user ? user : "");
    jw_str(&b, "ip", ip ? ip : "");
    jw_str(&b, "result", result ? result : "");
    jw_str(&b, "detail", detail ? detail : "");
    jw_obj_end(&b);
    emit(&b);
    sbuf_free(&b);
}
