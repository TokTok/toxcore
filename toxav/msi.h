/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_MSI_H
#define C_TOXCORE_TOXAV_MSI_H

#include "audio.h"
#include "video.h"

#include "../toxcore/logger.h"

#include <inttypes.h>
#include <pthread.h>

/**
 * Error codes.
 */
typedef enum MSIError {
    MSI_E_NONE,
    MSI_E_INVALID_MESSAGE,
    MSI_E_INVALID_PARAM,
    MSI_E_INVALID_STATE,
    MSI_E_STRAY_MESSAGE,
    MSI_E_SYSTEM,
    MSI_E_HANDLE,
    MSI_E_UNDISCLOSED, /* NOTE: must be last enum otherwise parsing will not work */
} MSIError;

/**
 * Supported capabilities
 */
typedef enum MSICapabilities {
    MSI_CAP_S_AUDIO = 4,  /* sending audio */
    MSI_CAP_S_VIDEO = 8,  /* sending video */
    MSI_CAP_R_AUDIO = 16, /* receiving audio */
    MSI_CAP_R_VIDEO = 32, /* receiving video */
} MSICapabilities;


/**
 * Call state identifiers.
 */
typedef enum MSICallState {
    MSI_CALL_INACTIVE = 0, /* Default */
    MSI_CALL_ACTIVE = 1,
    MSI_CALL_REQUESTING = 2, /* when sending call invite */
    MSI_CALL_REQUESTED = 3, /* when getting call invite */
} MSICallState;

/**
 * Callbacks ids that handle the states
 */
typedef enum MSICallbackID {
    MSI_ON_INVITE = 0, /* Incoming call */
    MSI_ON_START = 1, /* Call (RTP transmission) started */
    MSI_ON_END = 2, /* Call that was active ended */
    MSI_ON_ERROR = 3, /* On protocol error */
    MSI_ON_PEERTIMEOUT = 4, /* Peer timed out; stop the call */
    MSI_ON_CAPABILITIES = 5, /* Peer requested capabilities change */
} MSICallbackID;

/**
 * The call struct. Please do not modify outside msi.c
 */
typedef struct MSICall_s {
    struct MSISession_s *session;           /* Session pointer */

    MSICallState         state;
    uint8_t              peer_capabilities; /* Peer capabilities */
    uint8_t              self_capabilities; /* Self capabilities */
    uint16_t             peer_vfpsz;        /* Video frame piece size */
    uint32_t             friend_number;     /* Index of this call in MSISession */
    MSIError             error;             /* Last error */

    struct ToxAVCall    *av_call;           /* Pointer to av call handler */

    struct MSICall_s    *next;
    struct MSICall_s    *prev;
} MSICall;


/**
 * Expected return on success is 0, if any other number is
 * returned the call is considered errored and will be handled
 * as such which means it will be terminated without any notice.
 */
typedef int msi_action_cb(void *av, MSICall *call);

/**
 * Control session struct. Please do not modify outside msi.c
 */
typedef struct MSISession_s {
    /* Call handlers */
    MSICall       **calls;
    uint32_t        calls_tail;
    uint32_t        calls_head;

    void           *av;
    Tox            *tox;

    pthread_mutex_t mutex[1];
    msi_action_cb *callbacks[7];
} MSISession;

/**
 * Start the control session.
 */
MSISession *msi_new(Tox *tox);
/**
 * Terminate control session. NOTE: all calls will be freed
 */
int msi_kill(Tox *tox, MSISession *session);
/**
 * Callback setter.
 */
void msi_register_callback(MSISession *session, msi_action_cb *callback, MSICallbackID id);
/**
 * Send invite request to friend_number.
 */
int msi_invite(MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities);
/**
 * Hangup call. NOTE: `call` will be freed
 */
int msi_hangup(MSICall *call);
/**
 * Answer call request.
 */
int msi_answer(MSICall *call, uint8_t capabilities);
/**
 * Change capabilities of the call.
 */
int msi_change_capabilities(MSICall *call, uint8_t capabilities);

int invoke_callback(MSICall *call, MSICallbackID cb);
void kill_call(MSICall *call);
bool check_peer_offline_status(Tox *tox, MSISession *session, uint32_t friend_number);

#endif // C_TOXCORE_TOXAV_MSI_H
