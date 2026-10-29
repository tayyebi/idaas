#ifndef IDAAS_STORE_H
#define IDAAS_STORE_H

#include <stddef.h>
#include <time.h>

/* Generic thread-safe expiring hash table. Keys are short strings
 * (max 64 chars — sha256 hex of a token). Values are copied in and
 * must be plain structs (no pointers needing individual frees). */

typedef struct store store;

store *store_new(void);

/* Insert or replace. The value is copied (valsz bytes). */
int   store_put(store *s, const char *key, const void *val, size_t valsz, time_t expires_at);
/* Copy a value out. Returns -1 if missing or expired. */
int   store_get_copy(store *s, const char *key, void *out, size_t valsz);
/* Atomically remove and return the value (caller frees), or NULL. */
void *store_take(store *s, const char *key);
int   store_del(store *s, const char *key);
/* Drop expired entries. */
void  store_sweep(store *s);
size_t store_len(store *s);
void  store_free(store *s);

#endif
