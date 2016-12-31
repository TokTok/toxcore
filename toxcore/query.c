/**
 * Makes requests for information using the DHT or Onion as appropriate.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "query.h"

#include "DHT.h"
#include "logger.h"
#include "Messenger.h"
#include "network.h"
#include "util.h"

// #include <assert.h>

#define QUERY_PKT_ENCRYPTED_SIZE(payload) (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + payload + CRYPTO_MAC_SIZE)

/**
 * Increases the size of the query_list to count + 2.
 */
static bool q_grow(Pending_Queries *queries)
{
    size_t size = queries->count + 2;
    Query *new = realloc(queries->query_list, size * sizeof(Query));

    if (!new) {
        return false;
    }

    queries->size  = size;
    queries->query_list = new;

    return true;
}

/** returns true if existing and pending resolve to the same server address and port. */
static bool q_verify_server(const IP_Port *existing, const IP_Port *pending)
{
    if (existing->port != pending->port) {
        return false;
    }

    if (existing->ip.family != pending->ip.family) {
        return false;
    }

    if (existing->ip.family == AF_INET) {
        if (memcmp(&existing->ip.ip4.in_addr, &pending->ip.ip4.in_addr, sizeof(struct in_addr)) != 0) {
            return false;
        }
    } else {
        if (memcmp(&existing->ip.ip6.in6_addr, &pending->ip.ip6.in6_addr, sizeof(struct in6_addr)) != 0) {
            return false;
        }
    }

    return true;
}

/**
 * Checks for an existing entry in the pending queries list. Returns the position of the Query on
 * success, and -1 if the given query isn't found.
 */
static int q_check(const Pending_Queries *queries, const Query *pend, bool outgoing)
{
    unsigned i;

    for (i = 0; i < queries->count; ++i) {
        Query *test = &queries->query_list[i];

        if (!q_verify_server(&test->ipp, &pend->ipp)) {
            continue;
        }

        if (!id_equal(test->key, pend->key)) {
            continue;
        }

        if (outgoing) {
            if (test->length != pend->length) {
                continue;
            }

            if (memcmp(&test->name, &pend->name, test->length) != 0) {
                continue;
            }
        }

        // if (memcmp(test.nonce, pend.nonce, ) {
        // continue;
        // }

        return i;
    }

    return -1;
}

/** Adds pend to the query_list. */
static bool q_add(Pending_Queries *queries, const Query *pend)
{
    if (queries->count >= queries->size) {
        if (!q_grow(queries)) {
            return false;
        }
    }

    memcpy(&queries->query_list[queries->count], pend, sizeof(Query));
    ++queries->count;

    return true;
}

/** Drops the query at position loc from the list. */
static void q_drop(Pending_Queries *queries, size_t loc)
{
    if (loc && queries->count > loc + 1) {
        memmove(&queries->query_list[loc], &queries->query_list[loc + 1], sizeof(Query));
    }

    --queries->count;
}

static size_t q_build_packet(const uint8_t *their_public_key, const uint8_t *our_public_key,
                             const uint8_t *our_secret_key,
                             const uint8_t type, const uint8_t *data, const size_t length, uint8_t *built)
{
    // Encrypt the outgoing data
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    uint8_t encrypted[length + CRYPTO_MAC_SIZE];
    int status = encrypt_data(their_public_key, our_secret_key, nonce, data, length, encrypted);

    if (status == -1) {
        return -1;
    }

    // Build the packet
    size_t size = 0;
    built[0] = type;
    size += 1;

    memcpy(built + size, our_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    size += CRYPTO_PUBLIC_KEY_SIZE;

    memcpy(built + size, nonce, CRYPTO_NONCE_SIZE);
    size += CRYPTO_NONCE_SIZE;

    memcpy(built + size, encrypted, status);

    return 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + status;
}

static int q_send(const DHT *dht, const Query *send)
{
    uint8_t packet[QUERY_PKT_ENCRYPTED_SIZE(send->length)];

    size_t written_size = q_build_packet(send->key, dht->self_public_key, dht->self_secret_key, NET_PACKET_DATA_NAME_REQUEST,
                                         send->name, send->length, packet);
    // TODO(grayhatter) add tox_assert(written_size == QUERY_PKT_ENCRYPTED_SIZE(send->length));

    if (written_size != -1) {
        return sendpacket(dht->net, send->ipp, packet, written_size) != written_size;
    }

    return -1;
}

static Query q_make(IP_Port *ipp, const uint8_t key[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t *name,
                    const size_t length)
{
    Query new_query = { *ipp };
    id_copy(new_query.key, key);
    memcpy(new_query.name, name, length < QUERY_MAX_NAME_SIZE ? length : QUERY_MAX_NAME_SIZE);
    new_query.length = length < QUERY_MAX_NAME_SIZE ? length : QUERY_MAX_NAME_SIZE;

    // new_query.query_nonce = random_64b(); // TODO(grayhatter) readd nonce

    new_query.tries_remaining = 2;
    new_query.next_timeout = unix_time() + QUERY_TIMEOUT;
    return new_query;
}


int query_send_request(void *tox, const char *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length)
{
    Messenger *m = (Messenger *)tox;

    struct addrinfo *root;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        return -1;
    }

    IP_Port ipp = { .port = htons(port) };

    struct addrinfo *info = root;

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

    Query new_query = q_make(&ipp, key, name, length);

    // Verify name isn't currently pending response
    if (q_check(m->dht->queries, &new_query, 1) != -1) {
        return -2; // A similar request is already pending
    }

    // Send request
    if (q_send(m->dht, &new_query) == 0) {
        if (q_add(m->dht->queries, &new_query)) {
            return 0;
        }

        return -3; // Network reports sending error.
    }

    return -4; // Unknown error.
}

int query_handle_toxid_response(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata)
{
    DHT *dht = (DHT *)object;

    if (pkt[0] != NET_PACKET_DATA_NAME_RESPONSE) {
        return -1;
    }

    if (length <= QUERY_PKT_ENCRYPTED_SIZE(CRYPTO_PUBLIC_KEY_SIZE)) {
        return -1;
    }

    length -= 1; // drop the packet type

    // We verify the sender is in our list before we even try to decrypt anything
    unsigned int i;

    for (i = 0; i < dht->queries->count; ++i) {
        if (q_verify_server(&source, &dht->queries->query_list[i].ipp)) {
            break;
        }
    }

    uint8_t sender_key[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(sender_key, pkt + 1, CRYPTO_PUBLIC_KEY_SIZE);
    length -= CRYPTO_PUBLIC_KEY_SIZE;

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, pkt + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
    length -= CRYPTO_NONCE_SIZE;

    uint8_t clear[length];

    int res = decrypt_data(sender_key, dht->self_secret_key, nonce,
                           pkt + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, length, clear);

    if (res == -1) {
        return -1;
    }

    Query test = q_make(&source, sender_key, clear, length - CRYPTO_MAC_SIZE);

    int loc = q_check(dht->queries, &test, 0);

    if (loc == -1) {
        return -1;
    }

    if (dht->queries->query_response) {
        dht->queries->query_response(dht->queries->query_response_object, dht->queries->query_list[loc].name,
                                     dht->queries->query_list[loc].length, clear, userdata);
    }

    q_drop(dht->queries, loc);
    return 0;
}

Pending_Queries *query_new(Networking_Core *net)
{
    Pending_Queries *new = calloc(1, sizeof(Pending_Queries));

    if (!new) {
        return NULL;
    }

    new->query_list = calloc(1, sizeof(Query));

    if (new->query_list == NULL) {
        free(new);
        return NULL;
    }

    return new;
}

void query_iterate(void *object)
{
    DHT *dht = (DHT *)object;

    if (dht->queries->count) {
        unsigned int i;

        for (i = 0; i < dht->queries->count; ++i) {
            q_send(dht, &dht->queries->query_list[i]);
        }
    }

    return;
}
