#include "tqnl.h"

#include "query.h"

#include "../toxcore/DHT.h"

#define SET_ERROR(param, x) {if(param) {*param = x;}}

struct Tox_QNL *tox_qnl_new(Tox *tox, TOX_QNL_ERR_NEW *error)
{
    if (!tox) {
        SET_ERROR(error, TOX_QNL_ERR_NEW_NO_TOX);
    }

    Messenger *m = (Messenger *)tox;

    if (!m->net || !m->dht) {
        SET_ERROR(error, TOX_QNL_ERR_NEW_INVALID_TOX);
    }

    struct Tox_QNL *tqnl = (Tox_QNL *)calloc(1, sizeof(*tqnl));

    if (!tqnl) {
        SET_ERROR(error, TOX_QNL_ERR_NEW_MALLOC);
    }

    tqnl->m = (Messenger *)tox;

    tqnl->pending_list = query_new();

    if (!tqnl->pending_list) {
        free(tqnl);
        SET_ERROR(error, TOX_QNL_ERR_NEW_MALLOC);
    }

    networking_registerhandler(m->net, NET_PACKET_DATA_NAME_RESPONSE, &query_handle_toxid_response, tqnl);

    SET_ERROR(error, TOX_QNL_ERR_NEW_OK)
    return tqnl;
}

void tox_qnl_kill(struct Tox_QNL *tqnl)
{
    free(tqnl);
}

/**
 * Main loop for the session. This function needs to be called in intervals of
 * tox_qnl_iteration_interval() milliseconds.
 */
void tox_qnl_iterate(struct Tox_QNL *tqnl)
{
    if (!tqnl) {
        return;
    }

    // do stuff
}

bool tox_qnl_request_send(TOX_QNL *tqnl, const char *address, uint16_t port, const uint8_t *public_key,
                          const uint8_t *name,
                          size_t length, TOX_QNL_ERR_REQUEST_SEND *error)
{
    if (!address || !name || !length) {
        SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_NULL);
        return false;
    }

    if (port == 0) {
        SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_BAD_PORT);
        return false;
    }

    switch (query_send_request(tqnl, address, port, public_key, name, length)) {
        case 0: {
            SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_OK);
            return true;
        }

        case -1: {
            SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_BAD_HOST);
            return false;
        }

        case -2: {
            SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_PENDING);
            return false;
        }

        case -3: {
            SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_MALLOC);
            return false;
        }

        case -4: {
            SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_UNKNOWN);
            return false;
        }
    }

    SET_ERROR(error, TOX_QNL_ERR_REQUEST_SEND_UNKNOWN);
    return false;
}

/**
 * Set the callback for the `request_response` event. Pass NULL to unset.
 *
 */
void tox_qnl_callback_request_response(struct Tox_QNL *tqnl, tox_qnl_request_response_cb *callback)
{
    tqnl->callback = callback;
}
