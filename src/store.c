#include "store.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NBUCKETS 256
#define KEYMAX 64

struct node {
    char key[KEYMAX + 1];
    void *val;
    size_t valsz;
    time_t exp;
    struct node *next;
};

struct store {
    struct node *b[NBUCKETS];
    size_t n;
    pthread_mutex_t mu;
};

store *store_new(void)
{
    store *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    pthread_mutex_init(&s->mu, NULL);
    return s;
}

static unsigned bucket(const char *key)
{
    /* FNV-1a */
    unsigned h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h & (NBUCKETS - 1);
}

/* unlink helper: returns the unlinked node for key, or NULL */
static struct node *unlink_node(store *s, const char *key)
{
    unsigned i = bucket(key);
    for (struct node **pp = &s->b[i]; *pp; pp = &(*pp)->next) {
        if (strcmp((*pp)->key, key) == 0) {
            struct node *n = *pp;
            *pp = n->next;
            s->n--;
            return n;
        }
    }
    return NULL;
}

int store_put(store *s, const char *key, const void *val, size_t valsz, time_t expires_at)
{
    if (!s || !key || strlen(key) > KEYMAX || valsz == 0)
        return -1;
    struct node *n = malloc(sizeof *n + valsz);
    if (!n)
        return -1;
    snprintf(n->key, sizeof n->key, "%s", key);
    n->val = (char *)n + sizeof *n;
    memcpy(n->val, val, valsz);
    n->valsz = valsz;
    n->exp = expires_at;

    pthread_mutex_lock(&s->mu);
    struct node *old = unlink_node(s, key);
    unsigned i = bucket(key);
    n->next = s->b[i];
    s->b[i] = n;
    s->n++;
    pthread_mutex_unlock(&s->mu);
    free(old);
    return 0;
}

int store_get_copy(store *s, const char *key, void *out, size_t valsz)
{
    if (!s || !key)
        return -1;
    int rc = -1;
    time_t now = time(NULL);
    pthread_mutex_lock(&s->mu);
    for (struct node *n = s->b[bucket(key)]; n; n = n->next) {
        if (strcmp(n->key, key) == 0) {
            if (now >= n->exp) {
                /* expired: leave for sweep; caller sees missing */
            } else if (n->valsz == valsz) {
                memcpy(out, n->val, valsz);
                rc = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&s->mu);
    return rc;
}

void *store_take(store *s, const char *key)
{
    if (!s || !key)
        return NULL;
    time_t now = time(NULL);
    void *copy = NULL;
    pthread_mutex_lock(&s->mu);
    struct node *n = unlink_node(s, key);
    pthread_mutex_unlock(&s->mu);
    if (n) {
        if (now < n->exp) {
            copy = malloc(n->valsz);
            if (copy)
                memcpy(copy, n->val, n->valsz);
        }
        free(n);
    }
    return copy;
}

int store_del(store *s, const char *key)
{
    if (!s || !key)
        return -1;
    pthread_mutex_lock(&s->mu);
    struct node *n = unlink_node(s, key);
    pthread_mutex_unlock(&s->mu);
    if (!n)
        return -1;
    free(n);
    return 0;
}

void store_sweep(store *s)
{
    if (!s)
        return;
    time_t now = time(NULL);
    pthread_mutex_lock(&s->mu);
    for (unsigned i = 0; i < NBUCKETS; i++) {
        struct node **pp = &s->b[i];
        while (*pp) {
            struct node *n = *pp;
            if (now >= n->exp) {
                *pp = n->next;
                s->n--;
                free(n);
            } else {
                pp = &n->next;
            }
        }
    }
    pthread_mutex_unlock(&s->mu);
}

size_t store_len(store *s)
{
    if (!s)
        return 0;
    pthread_mutex_lock(&s->mu);
    size_t n = s->n;
    pthread_mutex_unlock(&s->mu);
    return n;
}

void store_free(store *s)
{
    if (!s)
        return;
    for (unsigned i = 0; i < NBUCKETS; i++) {
        struct node *n = s->b[i];
        while (n) {
            struct node *next = n->next;
            free(n);
            n = next;
        }
    }
    pthread_mutex_destroy(&s->mu);
    free(s);
}
