/**
 * Makes requests for information using the DHT or Onion as appropriate.
 */

#ifndef QUERY_H
#define QUERY_H

#include "../toxcore/crypto_core.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/network.h"

// query timeout in milliseconds
#define QUERY_TIMEOUT 500
#define QUERY_MAX_NAME_SIZE 255

typedef struct {
    IP_Port  ipp;
    uint8_t  key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t  name[QUERY_MAX_NAME_SIZE];
    size_t   length;

    uint64_t query_nonce;

    uint8_t  tries_remaining;
    uint64_t next_timeout;
} Query;

typedef struct {
    size_t size;
    size_t count;
    Query *query_list;
} Pending_Queries;

struct Tox_QNL {
    Messenger *m;

    Pending_Queries *pending_list;

    void (*callback)(struct Tox_QNL *tqnl, const uint8_t *request, size_t length, const uint8_t *tox_id, void *user_data);
};

#ifndef TOX_QNL_DEFINED
#define TOX_QNL_DEFINED
typedef struct Tox_QNL Tox_QNL;
#endif /* TOX_QNL_DEFINED */

int query_send_request(Tox_QNL *tqnl, const char *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length);

int query_handle_toxid_response(void *obj, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata);

/**
 * Generate a new query object
 */
Pending_Queries *query_new(void);

/**
 * Process/iterate pending queries.
 *
 */
void query_iterate(Tox_QNL *tqnl);

#endif
