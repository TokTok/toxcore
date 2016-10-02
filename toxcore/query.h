/** query.h
 *
 * Makes requests for information using the DHT or Onion as approitate.
 *
 * This file should include a licence, but if you're reading this, it doesn't yet so everything in
 * this file is donated to both tox, toktok, and you under a BSD or MIT licence at any option.
 */

#ifndef TOX_QUERY_H
#define TOX_QUERY_H

#include "network.h"
#include "tox.h"


#define QUERY_TIMEOUT 500

typedef struct {
    IP_Port  ipp;
    uint8_t  key[TOX_PUBLIC_KEY_SIZE];
    uint8_t *name;
    size_t   length;

    uint64_t query_nonce;

    uint8_t  tries_remaining;
    uint64_t next_timeout;
} P_QUERY;

typedef struct {
    size_t size;
    size_t count;
    P_QUERY *query_list;
} PENDING_QUERIES;

/** query_send_request
 *
 *
 */
int query_send_request(Tox *tox, const uint8_t *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length);

PENDING_QUERIES* query_new(void);

#endif