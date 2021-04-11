/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "msi.h"
#include "toxav_hacks.h"

#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"
#include "../toxcore/net_crypto.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MSI_MAXMSG_SIZE 256

#ifndef TOXAV_DEFINED
#define TOXAV_DEFINED
typedef struct ToxAV ToxAV;
#endif /* TOXAV_DEFINED */

/**
 * Protocol:
 *
 * `|id [1 byte]| |size [1 byte]| |data [$size bytes]| |...{repeat}| |0 {end byte}|`
 */

typedef enum MSIHeaderID {
    ID_REQUEST = 1,
    ID_ERROR,
    ID_CAPABILITIES,
} MSIHeaderID;


typedef enum MSIRequest {
    REQU_INIT,
    REQU_PUSH,
    REQU_POP,
} MSIRequest;


typedef struct MSIHeaderRequest {
    MSIRequest value;
    bool exists;
} MSIHeaderRequest;

typedef struct MSIHeaderError {
    MSIError value;
    bool exists;
} MSIHeaderError;

typedef struct MSIHeaderCapabilities {
    uint8_t value;
    bool exists;
} MSIHeaderCapabilities;


typedef struct MSIMessage {
    MSIHeaderRequest      request;
    MSIHeaderError        error;
    MSIHeaderCapabilities capabilities;
} MSIMessage;


static void msg_init(MSIMessage *dest, MSIRequest request);
static int msg_parse_in(Tox *tox, MSIMessage *dest, const uint8_t *data, uint16_t length);
static uint8_t *msg_parse_header_out(MSIHeaderID id, uint8_t *dest, const void *value, uint8_t value_len,
                                     uint16_t *length);
static int send_message(Tox *tox, uint32_t friend_number, const MSIMessage *msg);
static int send_error(Tox *tox, uint32_t friend_number, MSIError error);
static MSICall *get_call(MSISession *session, uint32_t friend_number);
static MSICall *new_call(MSISession *session, uint32_t friend_number);
static void handle_init(MSICall *call, const MSIMessage *msg);
static void handle_push(MSICall *call, const MSIMessage *msg);
static void handle_pop(MSICall *call, const MSIMessage *msg);
static void handle_msi_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length2, void *object);


/**
 * Public functions
 */
void msi_register_callback(MSISession *session, msi_action_cb *callback, MSICallbackID id)
{
    if (!session) {
        return;
    }

    pthread_mutex_lock(session->mutex);
    session->callbacks[id] = callback;
    pthread_mutex_unlock(session->mutex);
}

MSISession *msi_new(Tox *tox)
{
    if (tox == nullptr) {
        return nullptr;
    }

    MSISession *retu = (MSISession *)calloc(sizeof(MSISession), 1);

    if (retu == nullptr) {
        LOGGER_API_ERROR(tox, "Allocation failed! Program might misbehave!");
        return nullptr;
    }

    if (create_recursive_mutex(retu->mutex) != 0) {
        LOGGER_API_ERROR(tox, "Failed to init mutex! Program might misbehave");
        free(retu);
        return nullptr;
    }

    retu->tox = tox;

    // register callback
    tox_callback_friend_lossless_packet_per_pktid(tox, handle_msi_packet, PACKET_ID_MSI);

    LOGGER_API_DEBUG(tox, "New msi session: %p ", (void *)retu);
    return retu;
}

int msi_kill(Tox *tox, MSISession *session)
{
    if (session == nullptr) {
        LOGGER_API_ERROR(tox, "Tried to terminate non-existing session");
        return -1;
    }

    // UN-register callback
    tox_callback_friend_lossless_packet_per_pktid(tox, nullptr, PACKET_ID_MSI);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_API_ERROR(tox, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (session->calls) {
        MSIMessage msg;
        msg_init(&msg, REQU_POP);

        MSICall *it = get_call(session, session->calls_head);

        while (it) {
            send_message(session->tox, it->friend_number, &msg);
            MSICall *temp_it = it;
            it = it->next;
            kill_call(temp_it); /* This will eventually free session->calls */
        }
    }

    pthread_mutex_unlock(session->mutex);
    pthread_mutex_destroy(session->mutex);

    LOGGER_API_DEBUG(tox, "Terminated session: %p", (void *)session);
    free(session);
    return 0;
}

/*
 * return true if friend was offline and the call was canceled
 */
bool check_peer_offline_status(Tox *tox, MSISession *session, uint32_t friend_number)
{
    if (!tox || !session) {
        return false;
    }

    Tox_Err_Friend_Query f_con_query_error;
    Tox_Connection f_con_status = tox_friend_get_connection_status(tox, friend_number, &f_con_query_error);

    if (f_con_status == TOX_CONNECTION_NONE) {
        /* Friend is now offline */
        LOGGER_API_DEBUG(tox, "Friend %d is now offline", friend_number);

        pthread_mutex_lock(session->mutex);
        MSICall *call = get_call(session, friend_number);

        if (call == nullptr) {
            pthread_mutex_unlock(session->mutex);
            return true;
        }

        invoke_callback(call, MSI_ON_PEERTIMEOUT); /* Failure is ignored */
        kill_call(call);
        pthread_mutex_unlock(session->mutex);
        return true;
    }

    return false;
}

int msi_invite(MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities)
{
    LOGGER_API_DEBUG(session->tox, "msi_invite:session:%p", (void *)session);

    if (!session) {
        return -1;
    }

    LOGGER_API_DEBUG(session->tox, "Session: %p Inviting friend: %u", (void *)session, friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_API_ERROR(session->tox, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (get_call(session, friend_number) != nullptr) {
        LOGGER_API_ERROR(session->tox, "Already in a call");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    MSICall *temp = new_call(session, friend_number);

    if (temp == nullptr) {
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    temp->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_INIT);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(temp->session->tox, temp->friend_number, &msg);

    temp->state = MSI_CALL_REQUESTING;

    *call = temp;

    LOGGER_API_DEBUG(session->tox, "Invite sent");
    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_hangup(MSICall *call)
{
    if (!call || !call->session) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_API_DEBUG(session->tox, "Session: %p Hanging up call with friend: %u", (void *)call->session,
                     call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_API_ERROR(session->tox, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state == MSI_CALL_INACTIVE) {
        LOGGER_API_ERROR(session->tox, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    MSIMessage msg;
    msg_init(&msg, REQU_POP);

    send_message(session->tox, call->friend_number, &msg);

    kill_call(call);
    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_answer(MSICall *call, uint8_t capabilities)
{
    if (!call || !call->session) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_API_DEBUG(session->tox, "Session: %p Answering call from: %u", (void *)call->session,
                     call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_API_ERROR(session->tox, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state != MSI_CALL_REQUESTED) {
        /* Though sending in invalid state will not cause anything weird
         * Its better to not do it like a maniac */
        LOGGER_API_ERROR(session->tox, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_PUSH);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(session->tox, call->friend_number, &msg);

    call->state = MSI_CALL_ACTIVE;
    pthread_mutex_unlock(session->mutex);

    return 0;
}

int msi_change_capabilities(MSICall *call, uint8_t capabilities)
{
    if (!call || !call->session) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_API_DEBUG(session->tox, "Session: %p Trying to change capabilities to friend %u", (void *)call->session,
                     call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_API_ERROR(session->tox, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state != MSI_CALL_ACTIVE) {
        LOGGER_API_ERROR(session->tox, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_PUSH);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(call->session->tox, call->friend_number, &msg);

    pthread_mutex_unlock(session->mutex);
    return 0;
}


/**
 * Private functions
 */
static void msg_init(MSIMessage *dest, MSIRequest request)
{
    memset(dest, 0, sizeof(*dest));
    dest->request.exists = true;
    dest->request.value = request;
}

static int msg_parse_in(Tox *tox, MSIMessage *dest, const uint8_t *data, uint16_t length)
{
    /* Parse raw data received from socket into MSIMessage struct */

#define CHECK_SIZE(bytes, constraint, size)          \
    do {                                             \
        constraint -= 2 + size;                      \
        if (constraint < 1) {                        \
            LOGGER_API_ERROR(tox, "Read over length!");  \
            return -1;                               \
        }                                            \
        if (bytes[1] != size) {                      \
            LOGGER_API_ERROR(tox, "Invalid data size!"); \
            return -1;                               \
        }                                            \
    } while (0)

    /* Assumes size == 1 */
#define CHECK_ENUM_HIGH(bytes, enum_high)                 \
    do {                                                  \
        if (bytes[2] > enum_high) {                       \
            LOGGER_API_ERROR(tox, "Failed enum high limit!"); \
            return -1;                                    \
        }                                                 \
    } while (0)

    assert(dest);

    if (length == 0 || data[length - 1]) { /* End byte must have value 0 */
        LOGGER_API_ERROR(tox, "Invalid end byte");
        return -1;
    }

    memset(dest, 0, sizeof(*dest));

    const uint8_t *it = data;
    int size_constraint = length;

    while (*it) {/* until end byte is hit */
        switch (*it) {
            case ID_REQUEST:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, REQU_POP);
                dest->request.value = (MSIRequest)it[2];
                dest->request.exists = true;
                it += 3;
                break;

            case ID_ERROR:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, MSI_E_UNDISCLOSED);
                dest->error.value = (MSIError)it[2];
                dest->error.exists = true;
                it += 3;
                break;

            case ID_CAPABILITIES:
                CHECK_SIZE(it, size_constraint, 1);
                dest->capabilities.value = it[2];
                dest->capabilities.exists = true;
                it += 3;
                break;

            default:
                LOGGER_API_ERROR(tox, "Invalid id byte");
                return -1;
        }
    }

    if (dest->request.exists == false) {
        LOGGER_API_ERROR(tox, "Invalid request field!");
        return -1;
    }

#undef CHECK_ENUM_HIGH
#undef CHECK_SIZE

    return 0;
}

static uint8_t *msg_parse_header_out(MSIHeaderID id, uint8_t *dest, const void *value, uint8_t value_len,
                                     uint16_t *length)
{
    /* Parse a single header for sending */
    assert(dest);
    assert(value);
    assert(value_len);

    *dest = id;
    ++dest;
    *dest = value_len;
    ++dest;

    memcpy(dest, value, value_len);

    *length += (2 + value_len);

    return dest + value_len; /* Set to next position ready to be written */
}

/* Send an msi packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
static int m_msi_packet(Tox *tox, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    // TODO(Zoff): make this better later! -------------------
    /* we need to prepend 1 byte (packet id) to data
     * do this without calloc, memcpy and free in the future
     */
    size_t length_new = length + 1;
    uint8_t *data_new = (uint8_t *)calloc(1, length_new);

    if (!data_new) {
        return 0;
    }

    data_new[0] = PACKET_ID_MSI;

    if (length != 0) {
        memcpy(data_new + 1, data, length);
    }

    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossless_packet(tox, friendnumber, data_new, length_new, &error);

    free(data_new);

    if (error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
        return 1;
    }

    return 0;
}

static int send_message(Tox *tox, uint32_t friend_number, const MSIMessage *msg)
{
    assert(tox);

    /* Parse and send message */

    uint8_t parsed [MSI_MAXMSG_SIZE];

    uint8_t *it = parsed;
    uint16_t size = 0;

    if (msg->request.exists) {
        uint8_t cast = msg->request.value;
        it = msg_parse_header_out(ID_REQUEST, it, &cast,
                                  sizeof(cast), &size);
    } else {
        LOGGER_API_DEBUG(tox, "Must have request field");
        return -1;
    }

    if (msg->error.exists) {
        uint8_t cast = msg->error.value;
        it = msg_parse_header_out(ID_ERROR, it, &cast,
                                  sizeof(cast), &size);
    }

    if (msg->capabilities.exists) {
        it = msg_parse_header_out(ID_CAPABILITIES, it, &msg->capabilities.value,
                                  sizeof(msg->capabilities.value), &size);
    }

    if (it == parsed) {
        LOGGER_API_WARNING(tox, "Parsing message failed; empty message");
        return -1;
    }

    *it = 0;
    ++size;

    if (m_msi_packet(tox, friend_number, parsed, size)) {
        LOGGER_API_DEBUG(tox, "Sent message");
        return 0;
    }

    return -1;
}

static int send_error(Tox *tox, uint32_t friend_number, MSIError error)
{
    assert(tox);

    /* Send error message */

    LOGGER_API_DEBUG(tox, "Sending error: %d to friend: %d", error, friend_number);

    MSIMessage msg;
    msg_init(&msg, REQU_POP);

    msg.error.exists = true;
    msg.error.value = error;

    send_message(tox, friend_number, &msg);
    return 0;
}

int invoke_callback(MSICall *call, MSICallbackID cb)
{
    assert(call);

    if (call->session->callbacks[cb]) {
        LOGGER_API_DEBUG(call->session->tox, "Invoking callback function: %d", cb);

        if (call->session->callbacks[cb](call->session->av, call) != 0) {
            LOGGER_API_WARNING(call->session->tox,
                               "Callback state handling failed, sending error");
            goto FAILURE;
        }

        return 0;
    }

FAILURE:
    /* If no callback present or error happened while handling,
     * an error message will be sent to friend
     */

    if (call->error == MSI_E_NONE) {
        call->error = MSI_E_HANDLE;
    }

    return -1;
}

static MSICall *get_call(MSISession *session, uint32_t friend_number)
{
    assert(session);

    if (session->calls == nullptr || session->calls_tail < friend_number) {
        return nullptr;
    }

    return session->calls[friend_number];
}

static MSICall *new_call(MSISession *session, uint32_t friend_number)
{
    assert(session);

    MSICall *rc = (MSICall *)calloc(sizeof(MSICall), 1);

    if (rc == nullptr) {
        return nullptr;
    }

    rc->session = session;
    rc->friend_number = friend_number;

    if (session->calls == nullptr) { /* Creating */
        session->calls = (MSICall **)calloc(sizeof(MSICall *), friend_number + 1);

        if (session->calls == nullptr) {
            free(rc);
            return nullptr;
        }

        session->calls_tail = friend_number;
        session->calls_head = friend_number;
    } else if (session->calls_tail < friend_number) { /* Appending */
        MSICall **tmp = (MSICall **)realloc(session->calls, sizeof(MSICall *) * (friend_number + 1));

        if (tmp == nullptr) {
            free(rc);
            return nullptr;
        }

        session->calls = tmp;

        /* Set fields in between to null */
        uint32_t i = session->calls_tail + 1;

        for (; i < friend_number; ++i) {
            session->calls[i] = nullptr;
        }

        rc->prev = session->calls[session->calls_tail];
        session->calls[session->calls_tail]->next = rc;

        session->calls_tail = friend_number;
    } else if (session->calls_head > friend_number) { /* Inserting at front */
        rc->next = session->calls[session->calls_head];
        session->calls[session->calls_head]->prev = rc;
        session->calls_head = friend_number;
    }

    session->calls[friend_number] = rc;
    return rc;
}

void kill_call(MSICall *call)
{
    /* Assume that session mutex is locked */
    if (call == nullptr) {
        return;
    }

    MSISession *session = call->session;

    LOGGER_API_DEBUG(session->tox, "Killing call: %p", (void *)call);

    MSICall *prev = call->prev;
    MSICall *next = call->next;

    if (prev) {
        prev->next = next;
    } else if (next) {
        session->calls_head = next->friend_number;
    } else {
        goto CLEAR_CONTAINER;
    }

    if (next) {
        next->prev = prev;
    } else if (prev) {
        session->calls_tail = prev->friend_number;
    } else {
        goto CLEAR_CONTAINER;
    }

    session->calls[call->friend_number] = nullptr;
    free(call);
    return;

CLEAR_CONTAINER:
    session->calls_head = 0;
    session->calls_tail = 0;
    free(session->calls);
    free(call);
    session->calls = nullptr;
}


static void handle_init(MSICall *call, const MSIMessage *msg)
{
    assert(call);
    LOGGER_API_DEBUG(call->session->tox,
                     "Session: %p Handling 'init' friend: %d", (void *)call->session, call->friend_number);

    if (!msg->capabilities.exists) {
        LOGGER_API_WARNING(call->session->tox, "Session: %p Invalid capabilities on 'init'", (void *)call->session);
        call->error = MSI_E_INVALID_MESSAGE;
        goto FAILURE;
    }

    switch (call->state) {
        case MSI_CALL_INACTIVE: {
            /* Call requested */
            call->peer_capabilities = msg->capabilities.value;
            call->state = MSI_CALL_REQUESTED;

            if (invoke_callback(call, MSI_ON_INVITE) == -1) {
                goto FAILURE;
            }
        }
        break;

        case MSI_CALL_ACTIVE: {
            /* If peer sent init while the call is already
             * active it's probable that he is trying to
             * re-call us while the call is not terminated
             * on our side. We can assume that in this case
             * we can automatically answer the re-call.
             */

            LOGGER_API_INFO(call->session->tox, "Friend is recalling us");

            MSIMessage out_msg;
            msg_init(&out_msg, REQU_PUSH);

            out_msg.capabilities.exists = true;
            out_msg.capabilities.value = call->self_capabilities;

            send_message(call->session->tox, call->friend_number, &out_msg);

            /* If peer changed capabilities during re-call they will
             * be handled accordingly during the next step
             */
        }
        break;

        case MSI_CALL_REQUESTED: // fall-through
        case MSI_CALL_REQUESTING: {
            LOGGER_API_WARNING(call->session->tox, "Session: %p Invalid state on 'init'", (void *)call->session);
            call->error = MSI_E_INVALID_STATE;
            goto FAILURE;
        }
    }

    return;
FAILURE:
    send_error(call->session->tox, call->friend_number, call->error);
    kill_call(call);
}

static void handle_push(MSICall *call, const MSIMessage *msg)
{
    assert(call);

    LOGGER_API_DEBUG(call->session->tox, "Session: %p Handling 'push' friend: %d", (void *)call->session,
                     call->friend_number);

    if (!msg->capabilities.exists) {
        LOGGER_API_WARNING(call->session->tox, "Session: %p Invalid capabilities on 'push'", (void *)call->session);
        call->error = MSI_E_INVALID_MESSAGE;
        goto FAILURE;
    }

    switch (call->state) {
        case MSI_CALL_ACTIVE: {
            /* Only act if capabilities changed */
            if (call->peer_capabilities != msg->capabilities.value) {
                LOGGER_API_INFO(call->session->tox, "Friend is changing capabilities to: %u", msg->capabilities.value);

                call->peer_capabilities = msg->capabilities.value;

                if (invoke_callback(call, MSI_ON_CAPABILITIES) == -1) {
                    goto FAILURE;
                }
            }
        }
        break;

        case MSI_CALL_REQUESTING: {
            LOGGER_API_INFO(call->session->tox, "Friend answered our call");

            /* Call started */
            call->peer_capabilities = msg->capabilities.value;
            call->state = MSI_CALL_ACTIVE;

            if (invoke_callback(call, MSI_ON_START) == -1) {
                goto FAILURE;
            }
        }
        break;

        /* Pushes during initialization state are ignored */
        case MSI_CALL_INACTIVE: // fall-through
        case MSI_CALL_REQUESTED: {
            LOGGER_API_WARNING(call->session->tox, "Ignoring invalid push");
        }
        break;
    }

    return;

FAILURE:
    send_error(call->session->tox, call->friend_number, call->error);
    kill_call(call);
}

static void handle_pop(MSICall *call, const MSIMessage *msg)
{
    assert(call);

    LOGGER_API_DEBUG(call->session->tox, "Session: %p Handling 'pop', friend id: %d", (void *)call->session,
                     call->friend_number);

    /* callback errors are ignored */

    if (msg->error.exists) {
        LOGGER_API_WARNING(call->session->tox, "Friend detected an error: %d", msg->error.value);
        call->error = msg->error.value;
        invoke_callback(call, MSI_ON_ERROR);
    } else {
        switch (call->state) {
            case MSI_CALL_INACTIVE: {
                LOGGER_API_ERROR(call->session->tox, "Handling what should be impossible case");
                abort();
            }

            case MSI_CALL_ACTIVE: {
                /* Hangup */
                LOGGER_API_INFO(call->session->tox, "Friend hung up on us");
                invoke_callback(call, MSI_ON_END);
            }
            break;

            case MSI_CALL_REQUESTING: {
                /* Reject */
                LOGGER_API_INFO(call->session->tox, "Friend rejected our call");
                invoke_callback(call, MSI_ON_END);
            }
            break;

            case MSI_CALL_REQUESTED: {
                /* Cancel */
                LOGGER_API_INFO(call->session->tox, "Friend canceled call invite");
                invoke_callback(call, MSI_ON_END);
            }
            break;
        }
    }

    kill_call(call);
}

static void handle_msi_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length2, void *object)
{
    if (length2 < 2) {
        LOGGER_API_ERROR(tox, "MSI packet is less than 2 bytes in size");
        // we need more than the ID byte for MSI messages
        return;
    }

    // Zoff: is this correct?
    uint16_t length = (uint16_t)(length2 - 1);

    // Zoff: do not show the first byte, its always "PACKET_ID_MSI"
    const uint8_t *data_strip_id_byte = (const uint8_t *)(data + 1);

    LOGGER_API_DEBUG(tox, "Got msi message");

    ToxAV *toxav = (ToxAV *)tox_get_av_object(tox);

    if (!toxav) {
        return;
    }

    MSISession *session = tox_av_msi_get(toxav);

    if (!session) {
        return;
    }

    MSIMessage msg;

    if (msg_parse_in(session->tox, &msg, data_strip_id_byte, length) == -1) {
        LOGGER_API_WARNING(tox, "Error parsing message");
        send_error(tox, friend_number, MSI_E_INVALID_MESSAGE);
        return;
    }

    LOGGER_API_DEBUG(tox, "Successfully parsed message");

    pthread_mutex_lock(session->mutex);
    MSICall *call = get_call(session, friend_number);

    if (call == nullptr) {
        if (msg.request.value != REQU_INIT) {
            send_error(tox, friend_number, MSI_E_STRAY_MESSAGE);
            pthread_mutex_unlock(session->mutex);
            return;
        }

        call = new_call(session, friend_number);

        if (call == nullptr) {
            send_error(tox, friend_number, MSI_E_SYSTEM);
            pthread_mutex_unlock(session->mutex);
            return;
        }
    }

    switch (msg.request.value) {
        case REQU_INIT:
            handle_init(call, &msg);
            break;

        case REQU_PUSH:
            handle_push(call, &msg);
            break;

        case REQU_POP:
            handle_pop(call, &msg); /* always kills the call */
            break;
    }

    pthread_mutex_unlock(session->mutex);
}
