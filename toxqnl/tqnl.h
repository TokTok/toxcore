
#ifndef TOXQNL_H
#define TOXQNL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * External Tox type.
 */
#ifndef TOX_DEFINED
#define TOX_DEFINED
typedef struct Tox Tox;
#endif /* TOX_DEFINED */

/**
 * Tox_QNL.
 */
#ifndef TOX_QNL_DEFINED
#define TOX_QNL_DEFINED
typedef struct Tox_QNL Tox_QNL;
#endif /* TOX_QNL_DEFINED */

typedef enum TOX_QNL_ERR_NEW {

    /**
     * The function returned successfully.
     */
    TOX_QNL_ERR_NEW_OK,

    /**
     * The passed tox instance was NULL
     */
    TOX_QNL_ERR_NEW_TOX_NULL,

    /**
     * The passed tox instance was incompatible with Tox Quick Name Lookup (TQNL)
     */
    TOX_QNL_ERR_NEW_TOX_INVALID,

    /**
     * TQNL was unable to allocate the needed memory
     */
    TOX_QNL_ERR_NEW_MALLOC,

} TOX_QNL_ERR_NEW;


struct Tox_QNL *tox_qnl_new(Tox *tox, TOX_QNL_ERR_NEW *error);

void tox_qnl_kill(struct Tox_QNL *_qnl);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * tox_qnl_iteration_interval() milliseconds.
 */
void tox_qnl_iterate(struct Tox_QNL *_qnl);

typedef enum TOX_QNL_ERR_REQUEST_SEND {

    /**
     * The function returned successfully.
     */
    TOX_QNL_ERR_REQUEST_SEND_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_QNL_ERR_REQUEST_SEND_NULL,

    /**
     * The address could not be resolved to an IP address, or the IP address
     * passed was invalid.
     */
    TOX_QNL_ERR_REQUEST_SEND_BAD_HOST,

    /**
     * The port passed was invalid. The valid port range is (1, 65535).
     */
    TOX_QNL_ERR_REQUEST_SEND_BAD_PORT,

    /**
     * There is an existing request at this address with this name.
     */
    TOX_QNL_ERR_REQUEST_SEND_PENDING,

    /**
     * Unable to allocate the needed memory for this query.
     */
    TOX_QNL_ERR_REQUEST_SEND_MALLOC,

    /**
     * Unknown error of some kind; this indicates an error in toxcore. Please report this bug!
     */
    TOX_QNL_ERR_REQUEST_SEND_UNKNOWN,

} TOX_QNL_ERR_REQUEST_SEND;


/**
 * Queries the server at given address, port, public key, for the ToxID associated with supplied name.
 *
 * TODO(grayhatter) add a bool to send request from a one time use keypair. (Needs net_crypto/dht refactor)
 * NOTE(requires net_crypto.c support)
 *
 * @param address the IPv4 or IPv6 address for the server. Will attempt to resolve DNS addresses.
 * @param port the port the server is listening on.
 * @param public_key the long term public key for the name server.
 * @param name the string (name) you want to give to the server to request the associated ToxID.
 *
 * @return true on success.
 */
bool tox_qnl_request_send(struct Tox_QNL *_qnl, const char *address, uint16_t port, const uint8_t *public_key,
                          const uint8_t *name, size_t length, TOX_QNL_ERR_REQUEST_SEND *error);

/**
 * This callback will be invoked when a response from a pending query was received.
 * Once this callback is received, the query will have already been removed.
 */
typedef void tox_qnl_request_response_cb(struct Tox_QNL *_qnl, const uint8_t *request, size_t length,
        const uint8_t *tox_id, void *user_data);


/**
 * Set the callback for the `request_response` event. Pass NULL to unset.
 *
 */
void tox_qnl_callback_request_response(struct Tox_QNL *_qnl, tox_qnl_request_response_cb *callback);


#ifdef __cplusplus
}
#endif
#endif /* TOXQNL_H */
