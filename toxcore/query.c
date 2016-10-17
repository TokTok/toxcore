/** query.c
 *
 * Makes requests for information using the DHT or Onion as approitate.
 *
 * This file should include a licence, but if you're reading this, it doesn't yet so everything in
 * this file is donated to both tox, toktok, and you under a BSD or MIT licence at any option.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "query.h"

#include "crypto_core.h"
#include "logger.h"
#include "Messenger.h"
#include "network.h"
#include "util.h"

// #include <assert.h>

/**
 * Will realloc *queries to double the size of the current count.
 */
static bool grow(PENDING_QUERIES *queries)
{
    size_t size  = queries->count * 2;
    P_QUERY *new = realloc(queries->query_list, size * sizeof(P_QUERY));
    if (!new) {
        return false;
    }
    queries->size  = size;
    queries->query_list = new;

    return true;

}

static bool shrink(PENDING_QUERIES *queries)
{

    return 0;
}

/** q_check
 *
 * checks for a response in the pending queries list.
 */
static bool q_check(PENDING_QUERIES *queries, P_QUERY pend) {
    unsigned i;
    for (i = 0; i < queries->count; ++i) {
        P_QUERY test = queries->query_list[i];
        if (memcmp(&test.ipp, &pend.ipp, sizeof(IP_Port)) != 0) { /* TODO(grayhatter) will this work? */
            continue;
        } else if (!id_equal(test.key, pend.key)) {
            continue;
        } else if (test.length != pend.length ) {
            continue;
        } else if (memcmp(test.name, pend.name, test.length) != 0) {
            continue;
        } else if (test.query_nonce != pend.query_nonce) {
            continue;
        }
        return true;
    }

    return false;
}

static bool q_add(PENDING_QUERIES *queries, P_QUERY pend)
{
    if (queries->count >= queries->size) {
        if (grow(queries) != true) {
            return false;
        }
    }

    queries->query_list[queries->count++] = pend;
    return true;
}

static bool q_drop(PENDING_QUERIES *queries, IP_Port ipp, const uint8_t key[TOX_PUBLIC_KEY_SIZE],
                   const uint8_t *name, size_t length)
{

    return 0;
}

/** q_check_and_drop
 *
 * checks for a response in the pending queries list, if it exists, it'll drop it from the list.
 */
static bool q_check_and_drop(PENDING_QUERIES *queries, IP_Port ipp,
                             const uint8_t key[TOX_PUBLIC_KEY_SIZE], const uint8_t *name,
                             size_t length)
{

    return 0;
}

static int q_send(P_QUERY send) {

    return true;
}

static P_QUERY make(IP_Port ipp, const uint8_t key[TOX_PUBLIC_KEY_SIZE], const uint8_t *name, size_t length)
{
    P_QUERY new;
    memset(&new, 0, sizeof(P_QUERY));

    new.ipp = ipp;
    id_copy(new.key, key);
    new.name = calloc(1, length);
    memcpy(new.name, name, length);
    new.length = length;

    new.query_nonce = random_64b();

    new.tries_remaining = 2;
    new.next_timeout = unix_time() + QUERY_TIMEOUT;
    return new;
}

/** query_send_request
 *
 *
 */
int query_send_request(Tox *tox, const uint8_t *address, uint16_t port, const uint8_t *key,
                       const char *name, size_t length)
{
    Messenger *m = tox;

    struct addrinfo *info, *root;
    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        return -1;
    }

    IP_Port ipp;
    ipp.port = htons(port);

    info = root;
    do {
        if (info->ai_socktype && info->ai_socktype != SOCK_DGRAM) {
            continue;
        }

        ipp.ip.family = info->ai_family;
        if (info->ai_family == AF_INET) {
            ipp.ip.ip4.in_addr = ((struct sockaddr_in *)info->ai_addr)->sin_addr;
            break;
        } else if (info->ai_family == AF_INET6) {
            ipp.ip.ip6.in6_addr = ((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;
            break;
        } else {
            continue;
        }

    } while ((info = info->ai_next));
    freeaddrinfo(root);

    if (info == NULL) {
        return -1; // No host found
    }

    P_QUERY new = make(ipp, key, name, length);

    // Verify name isn't currently pending response
    if (q_check(m->queries, new)) {
        return -2;
    }

    // Send request
    if (q_send(new) == 0) {
        if (q_add(m->queries, new)) {
            return 0;
        }
    }
    return -3;
}

PENDING_QUERIES* query_new(void)
{
    PENDING_QUERIES *new = calloc(1, sizeof(PENDING_QUERIES));
    if (!new) {
        return NULL;
    }

    new->query_list = calloc(1, sizeof(P_QUERY));
    return new;
}