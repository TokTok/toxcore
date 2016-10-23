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
#include "DHT.h"
#include "Messenger.h"
#include "network.h"
#include "util.h"

// #include <assert.h>

#define QUERY_PKT_ENCRYPTED_SIZE(payload_size) ( 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + payload_size )

/**
 * Will realloc *queries to double the size of the current count.
 */
static bool grow(PENDING_QUERIES *queries)
{
    size_t size = queries->count + 2;
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

static bool q_verify_server(IP_Port existing, IP_Port pending)
{
    if (existing.port != pending.port) {
        return false;
    }

    if (existing.ip.family != pending.ip.family) {
        return false;
    }

    if (memcmp(existing.ip.ip6.uint8, pending.ip.ip6.uint8, 16) != 0) {
        return false;
    }

    return true;
}

/** q_check
 *
 * checks for a response in the pending queries list.
 */
static bool q_check(PENDING_QUERIES *queries, P_QUERY pend)
{
    unsigned i;

    for (i = 0; i < queries->count; ++i) {
        P_QUERY test = queries->query_list[i];

        if (!q_verify_server(test.ipp, pend.ipp)) { /* TODO(grayhatter) will this work? */
            continue;
        }

        if (!id_equal(test.key, pend.key)) {
            continue;
        }

        if (test.length != pend.length) {
            continue;
        }

        if (memcmp(test.name, pend.name, test.length) != 0) {
            continue;
        }

        // if (memcmp(test.nonce, pend.nonce, ) {
            // continue;
        // }

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


static size_t q_build_pkt(const uint8_t *their_public_key, const uint8_t *our_public_key, const uint8_t *our_secret_key,
                          uint8_t type, const uint8_t *data, size_t length, uint8_t *built)
{
    // Encrypt the outgoing data
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypted[length + 16];
    int status = encrypt_data(their_public_key, our_secret_key, nonce, data, length, encrypted);
    if (status == -1) {
        return -1;
    }

    // Build the packet
    size_t size = 0;
    built[0] = type;
    size += 1;

    memcpy(built + size, our_public_key, crypto_box_PUBLICKEYBYTES);
    size += crypto_box_PUBLICKEYBYTES;

    memcpy(built + size, nonce, crypto_box_NONCEBYTES);
    size += crypto_box_NONCEBYTES;

    memcpy(built + size, encrypted, status);

    return 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + status;
}

static int q_send(DHT *dht, P_QUERY send)
{
    uint8_t packet[QUERY_PKT_ENCRYPTED_SIZE(send.length)];

    size_t written_size = q_build_pkt(send.key, dht->self_public_key, dht->self_secret_key, NET_PACKET_DATA_REQUEST, send.name, send.length, packet);
    // TODO(grayhatter) add tox_assert(written_size == QUERY_PKT_ENCRYPTED_SIZE(send.length));

    if (written_size != -1) {
        return sendpacket(dht->net, send.ipp, packet, written_size) != written_size;
    }

    return -1;
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

    // new.query_nonce = random_64b(); // TODO(grayhatter) readd nonce

    new.tries_remaining = 2;
    new.next_timeout = unix_time() + QUERY_TIMEOUT;
    return new;
}

/** query_send_request
 *
 *
 */
int query_send_request(Tox *tox, const char *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length)
{
    Messenger *m = (Messenger *)tox;

    struct addrinfo *info, *root;

    if (getaddrinfo((char *)address, NULL, NULL, &root) != 0) {
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
    if (q_check(m->dht->queries, new)) {
        return -2;
    }

    // Send request
    if (q_send(m->dht, new) == 0) {
        if (q_add(m->dht->queries, new)) {
            return 0;
        }
        return -3;
    }

    return -4;
}

int query_handle_toxid_response(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata)
{
    DHT *dht = (DHT *)object;

    if (*pkt != NET_PACKET_DATA_RESPONSE) {
        return -1;
    }

    if (length <= QUERY_PKT_ENCRYPTED_SIZE(crypto_box_PUBLICKEYBYTES)) {
        return -1;
    }
    length -= 1;

    uint8_t sender_key[crypto_box_PUBLICKEYBYTES];
    memcpy(sender_key, pkt + 1, crypto_box_PUBLICKEYBYTES);
    length -= crypto_box_PUBLICKEYBYTES;

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, pkt + 1 + crypto_box_PUBLICKEYBYTES, crypto_box_NONCEBYTES);
    length -= crypto_box_NONCEBYTES;

    uint8_t clear[length];

    int res = decrypt_data(sender_key, dht->self_secret_key, nonce, pkt + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, length, clear);

    if (res == -1) {
        return -1;
    }

    // TODO(grayhatter) verify this response is in our list

    if (dht->queries->query_response) {
        dht->queries->query_response(dht->queries->query_response_object, (uint8_t *)"string", strlen("string") -1, pkt, userdata);
    }

    return 0;
}

PENDING_QUERIES *query_new(Networking_Core *net)
{
    PENDING_QUERIES *new = calloc(1, sizeof(PENDING_QUERIES));

    if (!new) {
        return NULL;
    }

    new->query_list = calloc(1, sizeof(P_QUERY));
    return new;
}

void query_iterate(void *object)
{
    DHT *dht = (DHT *)object;

    if (dht->queries->count) {
        unsigned int i;
        for(i = 0; i < dht->queries->count; ++i ) {
            q_send(dht, dht->queries->query_list[i]);
        }
    }
    return;
}