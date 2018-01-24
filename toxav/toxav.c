/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxav.h"

#include "msi.h"
#include "rtp.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


// TODO: don't hardcode this, let the application choose it
// VPX Info: Time to spend encoding, in microseconds (it's a *soft* deadline)
#define WANTED_MAX_ENCODER_FPS (40)
#define MAX_ENCODE_TIME_US (1000000 / WANTED_MAX_ENCODER_FPS) // to allow x fps
/*
VPX_DL_REALTIME       (1)       deadline parameter analogous to VPx REALTIME mode.
VPX_DL_GOOD_QUALITY   (1000000) deadline parameter analogous to VPx GOOD QUALITY mode.
VPX_DL_BEST_QUALITY   (0)       deadline parameter analogous to VPx BEST QUALITY mode.
*/

#define VIDEO_ACCEPTABLE_LOSS (0.08f) /* if loss is less than this (8%), then don't do anything */
#define AUDIO_ITERATATIONS_WHILE_VIDEO (2)

#if defined(AUDIO_DEBUGGING_SKIP_FRAMES)
uint32_t _debug_count_sent_audio_frames = 0;
uint32_t _debug_skip_every_x_audio_frame = 10;
#endif


typedef struct ToxAVCall_s {
    ToxAV *av;

    pthread_mutex_t mutex_audio[1];
    PAIR(RTPSession *, ACSession *) audio;

    pthread_mutex_t mutex_video[1];
    PAIR(RTPSession *, VCSession *) video;

    BWController *bwc;

    uint8_t skip_video_flag;

    bool active;
    MSICall *msi_call;
    uint32_t friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    uint64_t last_incoming_video_frame_rtimestamp;
    uint64_t last_incoming_video_frame_ltimestamp;

    uint64_t last_incoming_audio_frame_rtimestamp;
    uint64_t last_incoming_audio_frame_ltimestamp;

    uint64_t reference_rtimestamp;
    uint64_t reference_ltimestamp;
    int64_t reference_diff_timestamp;
    uint8_t reference_diff_timestamp_set;

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    pthread_mutex_t mutex[1];

    struct ToxAVCall_s *prev;
    struct ToxAVCall_s *next;
} ToxAVCall;

struct ToxAV {
    Messenger *m;
    MSISession *msi;

    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall **calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t mutex[1];

    PAIR(toxav_call_cb *, void *) ccb; /* Call callback */
    PAIR(toxav_call_state_cb *, void *) scb; /* Call state callback */
    PAIR(toxav_audio_receive_frame_cb *, void *) acb; /* Audio frame receive callback */
    PAIR(toxav_video_receive_frame_cb *, void *) vcb; /* Video frame receive callback */
    PAIR(toxav_bit_rate_status_cb *, void *) bcb; /* Bit rate control callback */

    /** Decode time measures */
    int32_t dmssc; /** Measure count */
    int32_t dmsst; /** Last cycle total */
    int32_t dmssa; /** Average decoding time in ms */

    uint32_t interval; /** Calculated interval */
};


void callback_bwc(BWController *bwc, uint32_t friend_number, float loss, void *user_data);

int callback_invite(void *toxav_inst, MSICall *call);
int callback_start(void *toxav_inst, MSICall *call);
int callback_end(void *toxav_inst, MSICall *call);
int callback_error(void *toxav_inst, MSICall *call);
int callback_capabilites(void *toxav_inst, MSICall *call);

bool audio_bit_rate_invalid(uint32_t bit_rate);
bool video_bit_rate_invalid(uint32_t bit_rate);
bool invoke_call_state_callback(ToxAV *av, uint32_t friend_number, uint32_t state);
ToxAVCall *call_new(ToxAV *av, uint32_t friend_number, TOXAV_ERR_CALL *error);
ToxAVCall *call_get(ToxAV *av, uint32_t friend_number);
ToxAVCall *call_remove(ToxAVCall *call);
bool call_prepare_transmission(ToxAVCall *call);
void call_kill_transmission(ToxAVCall *call);

ToxAV *toxav_new(Tox *tox, TOXAV_ERR_NEW *error)
{
    TOXAV_ERR_NEW rc = TOXAV_ERR_NEW_OK;
    ToxAV *av = NULL;
    Messenger *m = (Messenger *)tox;

    if (tox == NULL) {
        rc = TOXAV_ERR_NEW_NULL;
        goto END;
    }

    if (m->msi_packet) {
        rc = TOXAV_ERR_NEW_MULTIPLE;
        goto END;
    }

    av = (ToxAV *)calloc(sizeof(ToxAV), 1);

    if (av == NULL) {
        LOGGER_WARNING(m->log, "Allocation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }

    if (create_recursive_mutex(av->mutex) != 0) {
        LOGGER_WARNING(m->log, "Mutex creation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }

    av->m = m;
    av->msi = msi_new(av->m);

    if (av->msi == NULL) {
        pthread_mutex_destroy(av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }

    av->interval = 200;
    av->msi->av = av;

    msi_register_callback(av->msi, callback_invite, msi_OnInvite);
    msi_register_callback(av->msi, callback_start, msi_OnStart);
    msi_register_callback(av->msi, callback_end, msi_OnEnd);
    msi_register_callback(av->msi, callback_error, msi_OnError);
    msi_register_callback(av->msi, callback_error, msi_OnPeerTimeout);
    msi_register_callback(av->msi, callback_capabilites, msi_OnCapabilities);

END:

    if (error) {
        *error = rc;
    }

    if (rc != TOXAV_ERR_NEW_OK) {
        free(av);
        av = NULL;
    }

    return av;
}
void toxav_kill(ToxAV *av)
{
    if (av == NULL) {
        return;
    }

    pthread_mutex_lock(av->mutex);

    /* To avoid possible deadlocks */
    while (av->msi && msi_kill(av->msi, av->m->log) != 0) {
        pthread_mutex_unlock(av->mutex);
        pthread_mutex_lock(av->mutex);
    }

    /* Msi kill will hang up all calls so just clean these calls */
    if (av->calls) {
        ToxAVCall *it = call_get(av, av->calls_head);

        while (it) {
            call_kill_transmission(it);
            it->msi_call = NULL; /* msi_kill() frees the call's msi_call handle; which causes #278 */
            it = call_remove(it); /* This will eventually free av->calls */
        }
    }

    pthread_mutex_unlock(av->mutex);
    pthread_mutex_destroy(av->mutex);

    free(av);
}

Tox *toxav_get_tox(const ToxAV *av)
{
    return (Tox *) av->m;
}

uint32_t toxav_iteration_interval(const ToxAV *av)
{
    /* If no call is active interval is 200 */
    return av->calls ? av->interval : 200;
}

static void *video_play_bg(void *data)
{
    if (data)
    {
        ToxAVCall *call = (ToxAVCall *)data;
        if (call)
        {
            VCSession *vc = (VCSession *)call->video.second;
            /*uint8_t got_video_frame =*/ vc_iterate(vc, call->skip_video_flag,
                    &(call->last_incoming_audio_frame_rtimestamp),
                    &(call->last_incoming_audio_frame_ltimestamp),
                    &(call->last_incoming_video_frame_rtimestamp),
                    &(call->last_incoming_video_frame_ltimestamp)
            );
        }
    }
    return (void *)NULL;
}


void toxav_iterate(ToxAV *av)
{
    pthread_mutex_lock(av->mutex);

    if (av->calls == NULL) {
        pthread_mutex_unlock(av->mutex);
        return;
    }

    uint64_t start = current_time_monotonic();
    int32_t rc = 500;
    uint32_t audio_iterations = 0;

    ToxAVCall *i = av->calls[av->calls_head];

    for (; i; i = i->next) {

        audio_iterations = 0;

        if (i->active) {
            pthread_mutex_lock(i->mutex);
            pthread_mutex_unlock(av->mutex);



#if !defined(_GNU_SOURCE)
            video_play_bg((void *)(i));
#else
            // ------- multithreaded av_iterate for video -------
	        pthread_t video_play_thread;
            LOGGER_TRACE(av->m->log, "video_play -----");

            if (pthread_create(&video_play_thread, NULL, video_play_bg, (void *)(i)))
            {
                LOGGER_WARNING(av->m->log, "error creating video play thread");
            }
            else
            {
                // TODO: set lower prio for video play thread ?
            }
            // ------- multithreaded av_iterate for video -------
#endif



            // ------- av_iterate for audio -------
            uint8_t res_ac = ac_iterate(i->audio.second,
            &(i->last_incoming_audio_frame_rtimestamp),
            &(i->last_incoming_audio_frame_ltimestamp),
            &(i->last_incoming_video_frame_rtimestamp),
            &(i->last_incoming_video_frame_ltimestamp)
            );
            if (res_ac == 2)
            {
                i->skip_video_flag = 1;
            }
            else
            {
                i->skip_video_flag = 0;
            }
            // ------- av_iterate for audio -------



/*
 * compile toxcore with "-D_GNU_SOURCE" to activate "pthread_tryjoin_np" solution!
 */
#if !defined(_GNU_SOURCE)
	        // pthread_join(video_play_thread, NULL);
#else
            while (pthread_tryjoin_np(video_play_thread, NULL) != 0)
            {
                if (audio_iterations < AUDIO_ITERATATIONS_WHILE_VIDEO)
                {
                    /* video thread still running, let's do some more audio */
                    if (ac_iterate(i->audio.second,
                    &(i->last_incoming_audio_frame_rtimestamp),
                    &(i->last_incoming_audio_frame_ltimestamp),
                    &(i->last_incoming_video_frame_rtimestamp),
                    &(i->last_incoming_video_frame_ltimestamp)
                    ) == 0)
                    {
                        // TODO: Zoff: not sure if this sleep is good, or bad??
                        usleep(100);
                    }
                    else
                    {
                        LOGGER_TRACE(av->m->log, "did some more audio iterate");
                    }
                }
                else
                {
                    break;
                }

                audio_iterations++;
            }

            pthread_join(video_play_thread, NULL);
#endif




            if (i->msi_call->self_capabilities & msi_CapRAudio &&
                    i->msi_call->peer_capabilities & msi_CapSAudio) {
                rc = MIN(i->audio.second->lp_frame_duration, rc);
            }

            if (i->msi_call->self_capabilities & msi_CapRVideo &&
                    i->msi_call->peer_capabilities & msi_CapSVideo) {
                rc = MIN(i->video.second->lcfd, (uint32_t) rc);
            }


            uint32_t fid = i->friend_number;

            pthread_mutex_unlock(i->mutex);
            pthread_mutex_lock(av->mutex);

            /* In case this call is popped from container stop iteration */
            if (call_get(av, fid) != i) {
                break;
            }

            if ((i->last_incoming_audio_frame_ltimestamp != 0)
            &&
            (i->last_incoming_video_frame_ltimestamp != 0))
            {
                if (i->reference_diff_timestamp_set == 0)
                {
                    i->reference_rtimestamp = i->last_incoming_audio_frame_rtimestamp;
                    i->reference_ltimestamp = i->last_incoming_audio_frame_ltimestamp;
                    // this is the difference between local and remote clocks in "ms"
                    i->reference_diff_timestamp = (int64_t)(i->reference_ltimestamp - i->reference_rtimestamp);
                    i->reference_diff_timestamp_set = 1;
                }
                else
                {
                    int64_t latency_ms = (int64_t)(
                    (i->last_incoming_video_frame_rtimestamp - i->last_incoming_audio_frame_rtimestamp) -
                    (i->last_incoming_video_frame_ltimestamp - i->last_incoming_audio_frame_ltimestamp)
                    );


                    LOGGER_DEBUG(av->m->log, "VIDEO:delay-to-audio-in-ms=%lld", (long long)latency_ms);
                    // LOGGER_INFO(av->m->log, "CLOCK:delay-to-rmote-in-ms=%lld", (long long)(i->reference_diff_timestamp));
                    LOGGER_DEBUG(av->m->log, "VIDEO:delay-to-refnc-in-ms=%lld", (long long)-((i->last_incoming_video_frame_ltimestamp - i->reference_diff_timestamp) - i->last_incoming_video_frame_rtimestamp));
                    LOGGER_DEBUG(av->m->log, "AUDIO:delay-to-refnc-in-ms=%lld", (long long)-((i->last_incoming_audio_frame_ltimestamp - i->reference_diff_timestamp) - i->last_incoming_audio_frame_rtimestamp));

                    // LOGGER_INFO(av->m->log, "VIDEO latency in ms=%lld", (long long)(i->last_incoming_video_frame_ltimestamp - i->last_incoming_video_frame_rtimestamp));
                    // LOGGER_INFO(av->m->log, "AUDIO latency in ms=%lld", (long long)(i->last_incoming_audio_frame_ltimestamp - i->last_incoming_audio_frame_rtimestamp));

                    // LOGGER_INFO(av->m->log, "VIDEO:3-latency-in-ms=%lld", (long long)(i->last_incoming_audio_frame_rtimestamp - i->last_incoming_video_frame_rtimestamp));

                    //LOGGER_INFO(av->m->log, "AUDIO (to video):latency in a=%lld b=%lld c=%lld d=%lld",
                    //(long long)i->last_incoming_video_frame_rtimestamp,
                    //(long long)i->last_incoming_audio_frame_rtimestamp,
                    //(long long)i->last_incoming_video_frame_ltimestamp,
                    //(long long)i->last_incoming_audio_frame_ltimestamp
                    //);
                }
            }
        }
    }

    pthread_mutex_unlock(av->mutex);

    av->interval = rc < av->dmssa ? 0 : (rc - av->dmssa);
    av->dmsst += current_time_monotonic() - start;

    if (++av->dmssc == 3) {
        av->dmssa = av->dmsst / 3 + 5 /* NOTE Magic Offset for precission */;
        av->dmssc = 0;
        av->dmsst = 0;
    }
}
bool toxav_call(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                TOXAV_ERR_CALL *error)
{
    TOXAV_ERR_CALL rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call;

    pthread_mutex_lock(av->mutex);

    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate && video_bit_rate_invalid(video_bit_rate))) {
        rc = TOXAV_ERR_CALL_INVALID_BIT_RATE;
        goto END;
    }

    call = call_new(av, friend_number, &rc);

    if (call == NULL) {
        goto END;
    }

    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;

    call->previous_self_capabilities = msi_CapRAudio | msi_CapRVideo;

    call->previous_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;

    if (msi_invite(av->msi, &call->msi_call, friend_number, call->previous_self_capabilities) != 0) {
        call_remove(call);
        rc = TOXAV_ERR_CALL_SYNC;
        goto END;
    }

    call->msi_call->av_call = call;

END:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_OK;
}
void toxav_callback_call(ToxAV *av, toxav_call_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->ccb.first = callback;
    av->ccb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_answer(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                  TOXAV_ERR_ANSWER *error)
{
    pthread_mutex_lock(av->mutex);

    TOXAV_ERR_ANSWER rc = TOXAV_ERR_ANSWER_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto END;
    }

    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate && video_bit_rate_invalid(video_bit_rate))
       ) {
        rc = TOXAV_ERR_ANSWER_INVALID_BIT_RATE;
        goto END;
    }

    call = call_get(av, friend_number);

    if (call == NULL) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;
        goto END;
    }

    if (!call_prepare_transmission(call)) {
        rc = TOXAV_ERR_ANSWER_CODEC_INITIALIZATION;
        goto END;
    }

    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;

    call->previous_self_capabilities = msi_CapRAudio | msi_CapRVideo;

    call->previous_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;

    if (msi_answer(call->msi_call, call->previous_self_capabilities) != 0) {
        rc = TOXAV_ERR_ANSWER_SYNC;
    }

END:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_ANSWER_OK;
}
void toxav_callback_call_state(ToxAV *av, toxav_call_state_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->scb.first = callback;
    av->scb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_call_control(ToxAV *av, uint32_t friend_number, TOXAV_CALL_CONTROL control, TOXAV_ERR_CALL_CONTROL *error)
{
    pthread_mutex_lock(av->mutex);
    TOXAV_ERR_CALL_CONTROL rc = TOXAV_ERR_CALL_CONTROL_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
        goto END;
    }

    call = call_get(av, friend_number);

    if (call == NULL || (!call->active && control != TOXAV_CALL_CONTROL_CANCEL)) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
        goto END;
    }

    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME: {
            /* Only act if paused and had media transfer active before */
            if (call->msi_call->self_capabilities == 0 &&
                    call->previous_self_capabilities) {

                if (msi_change_capabilities(call->msi_call,
                                            call->previous_self_capabilities) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_allow_receiving(call->audio.first);
                rtp_allow_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_PAUSE: {
            /* Only act if not already paused */
            if (call->msi_call->self_capabilities) {
                call->previous_self_capabilities = call->msi_call->self_capabilities;

                if (msi_change_capabilities(call->msi_call, 0) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_stop_receiving(call->audio.first);
                rtp_stop_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_CANCEL: {
            /* Hang up */
            pthread_mutex_lock(call->mutex);

            if (msi_hangup(call->msi_call) != 0) {
                rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                pthread_mutex_unlock(call->mutex);
                goto END;
            }

            call->msi_call = NULL;
            pthread_mutex_unlock(call->mutex);

            /* No mather the case, terminate the call */
            call_kill_transmission(call);
            call_remove(call);
        }
        break;

        case TOXAV_CALL_CONTROL_MUTE_AUDIO: {
            if (call->msi_call->self_capabilities & msi_CapRAudio) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities ^ msi_CapRAudio) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_stop_receiving(call->audio.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_UNMUTE_AUDIO: {
            if (call->msi_call->self_capabilities ^ msi_CapRAudio) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | msi_CapRAudio) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_allow_receiving(call->audio.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_HIDE_VIDEO: {
            if (call->msi_call->self_capabilities & msi_CapRVideo) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities ^ msi_CapRVideo) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_stop_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_SHOW_VIDEO: {
            if (call->msi_call->self_capabilities ^ msi_CapRVideo) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | msi_CapRVideo) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto END;
                }

                rtp_allow_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        }
        break;
    }

END:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}

bool toxav_option_set(ToxAV *av, uint32_t friend_number, TOXAV_OPTIONS_OPTION option, int32_t value,
                        TOXAV_ERR_OPTION_SET *error)
{
    TOXAV_ERR_OPTION_SET rc = TOXAV_ERR_OPTION_SET_OK;

    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_OPTION_SET_OTHER_ERROR;
        goto END;
    }

    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);

    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_OPTION_SET_OTHER_ERROR;
        goto END;
    }

    pthread_mutex_lock(call->mutex);

    if (option == TOXAV_ENCODER_CPU_USED)
    {
        VCSession *vc = (VCSession *)call->video.second;

        if (vc->video_encoder_cpu_used == (int32_t)value) {
            LOGGER_WARNING(av->m->log, "video encoder cpu_used already set to: %d", (int)value);
        }
        else
        {
            vc->video_encoder_cpu_used_prev = vc->video_encoder_cpu_used;
            vc->video_encoder_cpu_used = (int32_t)value;
            LOGGER_WARNING(av->m->log, "video encoder setting cpu_used to: %d", (int)value);
        }
    }
    else if (option == TOXAV_ENCODER_VP8_QUALITY)
    {
        VCSession *vc = (VCSession *)call->video.second;

        if (vc->video_encoder_vp8_quality == (int32_t)value) {
            LOGGER_WARNING(av->m->log, "video encoder vp8_quality already set to: %d", (int)value);
        }
        else
        {
            vc->video_encoder_vp8_quality_prev = vc->video_encoder_vp8_quality;
            vc->video_encoder_vp8_quality = (int32_t)value;
            LOGGER_WARNING(av->m->log, "video encoder setting vp8_quality to: %d", (int)value);
        }
    }

    pthread_mutex_unlock(call->mutex);
    pthread_mutex_unlock(av->mutex);
END:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_OPTION_SET_OK;
}

bool toxav_bit_rate_set(ToxAV *av, uint32_t friend_number, int32_t audio_bit_rate,
                        int32_t video_bit_rate, TOXAV_ERR_BIT_RATE_SET *error)
{
    TOXAV_ERR_BIT_RATE_SET rc = TOXAV_ERR_BIT_RATE_SET_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND;
        goto END;
    }

    if (audio_bit_rate > 0 && audio_bit_rate_invalid(audio_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_SET_INVALID_AUDIO_BIT_RATE;
        goto END;
    }

    if (video_bit_rate > 0 && video_bit_rate_invalid(video_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_SET_INVALID_VIDEO_BIT_RATE;
        goto END;
    }

    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);

    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL;
        goto END;
    }

    if (audio_bit_rate >= 0) {
        LOGGER_DEBUG(av->m->log, "Setting new audio bitrate to: %d", audio_bit_rate);

        if (call->audio_bit_rate == (uint32_t)audio_bit_rate) {
            LOGGER_DEBUG(av->m->log, "Audio bitrate already set to: %d", audio_bit_rate);
        } else if (audio_bit_rate == 0) {
            LOGGER_DEBUG(av->m->log, "Turned off audio sending");

            if (msi_change_capabilities(call->msi_call, call->msi_call->
                                        self_capabilities ^ msi_CapSAudio) != 0) {
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto END;
            }

            /* Audio sending is turned off; notify peer */
            call->audio_bit_rate = 0;
        } else {
            pthread_mutex_lock(call->mutex);

            if (call->audio_bit_rate == 0) {
                LOGGER_DEBUG(av->m->log, "Turned on audio sending");

                /* The audio has been turned off before this */
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | msi_CapSAudio) != 0) {
                    pthread_mutex_unlock(call->mutex);
                    pthread_mutex_unlock(av->mutex);
                    rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                    goto END;
                }
            } else {
                LOGGER_DEBUG(av->m->log, "Set new audio bit rate %d", audio_bit_rate);
            }

            call->audio_bit_rate = audio_bit_rate;
            pthread_mutex_unlock(call->mutex);
        }
    }

    if (video_bit_rate >= 0) {
        LOGGER_DEBUG(av->m->log, "Setting new video bitrate to: %d", video_bit_rate);

        if (call->video_bit_rate == (uint32_t)video_bit_rate) {
            LOGGER_DEBUG(av->m->log, "Video bitrate already set to: %d", video_bit_rate);
        } else if (video_bit_rate == 0) {
            LOGGER_DEBUG(av->m->log, "Turned off video sending");

            /* Video sending is turned off; notify peer */
            if (msi_change_capabilities(call->msi_call, call->msi_call->
                                        self_capabilities ^ msi_CapSVideo) != 0) {
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto END;
            }

            call->video_bit_rate = 0;
        } else {
            pthread_mutex_lock(call->mutex);

            if (call->video_bit_rate == 0) {
                LOGGER_DEBUG(av->m->log, "Turned on video sending");

                /* The video has been turned off before this */
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | msi_CapSVideo) != 0) {
                    pthread_mutex_unlock(call->mutex);
                    pthread_mutex_unlock(av->mutex);
                    rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                    goto END;
                }
            } else {
                LOGGER_DEBUG(av->m->log, "Set new video bit rate %d", video_bit_rate);
            }

            call->video_bit_rate = video_bit_rate;
            pthread_mutex_unlock(call->mutex);
        }
    }

    pthread_mutex_unlock(av->mutex);
END:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_BIT_RATE_SET_OK;
}

void toxav_callback_bit_rate_status(ToxAV *av, toxav_bit_rate_status_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->bcb.first = callback;
    av->bcb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_audio_send_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm, size_t sample_count,
                            uint8_t channels, uint32_t sampling_rate, TOXAV_ERR_SEND_FRAME *error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    uint64_t audio_frame_record_timestamp = current_time_monotonic();

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }

    if (pthread_mutex_trylock(av->mutex) != 0) {
        rc = TOXAV_ERR_SEND_FRAME_SYNC;
        goto END;
    }

    call = call_get(av, friend_number);

    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }

    if (call->audio_bit_rate == 0 ||
            !(call->msi_call->self_capabilities & msi_CapSAudio) ||
            !(call->msi_call->peer_capabilities & msi_CapRAudio)) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED;
        goto END;
    }

    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(av->mutex);

    if (pcm == NULL) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }

    if (channels > 2) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }

    { /* Encode and send */
        if (ac_reconfigure_encoder(call->audio.second, call->audio_bit_rate * 1000, sampling_rate, channels) != 0) {
            pthread_mutex_unlock(call->mutex_audio);
            LOGGER_WARNING(av->m->log, "Failed reconfigure audio encoder");
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }

        VLA(uint8_t, dest, sample_count + sizeof(sampling_rate)); /* This is more than enough always */

        sampling_rate = net_htonl(sampling_rate);
        memcpy(dest, &sampling_rate, sizeof(sampling_rate));
        int vrc = opus_encode(call->audio.second->encoder, pcm, sample_count,
                              dest + sizeof(sampling_rate), SIZEOF_VLA(dest) - sizeof(sampling_rate));

        if (vrc < 0) {
            LOGGER_WARNING(av->m->log, "Failed to encode audio frame %s", opus_strerror(vrc));
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }

#if defined(AUDIO_DEBUGGING_SIMULATE_SOME_DATA_LOSS)
        // set last part of audio frame to all zeros
        size_t ten_percent_size = ((size_t)vrc / 10);
        size_t start_offset = ((size_t)vrc - ten_percent_size - 1);
        memset((dest + 4 + start_offset), (int)0, ten_percent_size);
        LOGGER_WARNING(av->m->log, "* audio packet set some ZERO data at the end *");
#endif

#if defined(AUDIO_DEBUGGING_SKIP_FRAMES)
        // skip sending some audio frames
        _debug_count_sent_audio_frames++;
        if (_debug_count_sent_audio_frames > _debug_skip_every_x_audio_frame)
        {
            call->audio.first->sequnum++;
            LOGGER_WARNING(av->m->log, "* audio packet sending SKIPPED * %d", (int)call->audio.first->sequnum);
            _debug_count_sent_audio_frames = 0;
        }
        else
        {
#endif
            // LOGGER_DEBUG(av->m->log, "audio packet record time: %llu", audio_frame_record_timestamp);


            if (rtp_send_data(call->audio.first, dest,
                vrc + sizeof(sampling_rate),
                audio_frame_record_timestamp,
                VIDEO_FRAGMENT_NUM_NO_FRAG,
                av->m->log) != 0)
            {
                LOGGER_WARNING(av->m->log, "Failed to send audio packet");
                rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            }
            //else
            //{
            //    LOGGER_WARNING(av->m->log, "audio packet sent OK");
            //}

#if defined(AUDIO_DEBUGGING_SKIP_FRAMES)
        }
#endif

    }


    pthread_mutex_unlock(call->mutex_audio);

END:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}


bool toxav_video_send_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t *y,
                            const uint8_t *u, const uint8_t *v, TOXAV_ERR_SEND_FRAME *error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    uint64_t video_frame_record_timestamp = current_time_monotonic();

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }

    if (pthread_mutex_trylock(av->mutex) != 0) {
        rc = TOXAV_ERR_SEND_FRAME_SYNC;
        goto END;
    }

    call = call_get(av, friend_number);

    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }

    if (call->video_bit_rate == 0 ||
            !(call->msi_call->self_capabilities & msi_CapSVideo) ||
            !(call->msi_call->peer_capabilities & msi_CapRVideo)) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED;
        goto END;
    }

    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(av->mutex);

    if (y == NULL || u == NULL || v == NULL) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }

    if (vc_reconfigure_encoder(call->video.second, call->video_bit_rate * 1000,
           width, height, -1) != 0) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }

    int vpx_encode_flags = 0;
    unsigned long max_encode_time_in_us = MAX_ENCODE_TIME_US;


    if (call->video.first->ssrc < VIDEO_SEND_X_KEYFRAMES_FIRST) {
        //if (call->video.first->ssrc == 0)
        //{
        if (VPX_ENCODER_USED == VPX_VP8_CODEC) {
            // Key frame flag for first frames
            vpx_encode_flags = VPX_EFLAG_FORCE_KF;
            max_encode_time_in_us = VPX_DL_REALTIME;
            uint32_t lowered_bitrate = (800 * 1000);
            vc_reconfigure_encoder_bitrate_only(call->video.second, lowered_bitrate);
            // HINT: Zoff: this does not seem to work
            // vpx_codec_control(call->video.second->encoder, VP8E_SET_FRAME_FLAGS, vpx_encode_flags);
            LOGGER_INFO(av->m->log, "I_FRAME_FLAG:%d only-i-frame mode", call->video.first->ssrc);
        }

        //}
        call->video.first->ssrc++;
    } else if (call->video.first->ssrc == VIDEO_SEND_X_KEYFRAMES_FIRST) {
        if (VPX_ENCODER_USED == VPX_VP8_CODEC) {
            // normal keyframe placement
            vpx_encode_flags = 0;
            max_encode_time_in_us = MAX_ENCODE_TIME_US;
            vc_reconfigure_encoder_bitrate_only(call->video.second, call->video_bit_rate * 1000);
            // HINT: Zoff: this does not seem to work
            // vpx_codec_control(call->video.second->encoder, VP8E_SET_FRAME_FLAGS, vpx_encode_flags);
            LOGGER_INFO(av->m->log, "I_FRAME_FLAG:%d normal mode", call->video.first->ssrc);
        }

        call->video.first->ssrc++;
    }
    else
    {
#ifdef VIDEO_ENCODER_SOFT_DEADLINE_AUTOTUNE
        long encode_time_auto_tune = MAX_ENCODE_TIME_US;

        if (call->video.second->last_encoded_frame_ts > 0)
        {
            encode_time_auto_tune = (current_time_monotonic() - call->video.second->last_encoded_frame_ts) * 1000;
#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
            encode_time_auto_tune = encode_time_auto_tune * VIDEO_CODEC_FRAGMENT_NUMS;
#endif

            call->video.second->encoder_soft_deadline[call->video.second->encoder_soft_deadline_index] = encode_time_auto_tune;
            call->video.second->encoder_soft_deadline_index = (call->video.second->encoder_soft_deadline_index + 1) % 3;

            // calc mean value
            encode_time_auto_tune = (
                (
                call->video.second->encoder_soft_deadline[0] +
                call->video.second->encoder_soft_deadline[1] +
                call->video.second->encoder_soft_deadline[2]
                )
                / 3
            );

            if (encode_time_auto_tune > (1000000 / VIDEO_ENCODER_MINFPS_AUTOTUNE))
            {
                encode_time_auto_tune = (1000000 / VIDEO_ENCODER_MINFPS_AUTOTUNE);
            }

            if (encode_time_auto_tune > (VIDEO_ENCODER_LEEWAY_IN_MS_AUTOTUNE * 1000))
            {
                encode_time_auto_tune = encode_time_auto_tune - (VIDEO_ENCODER_LEEWAY_IN_MS_AUTOTUNE * 1000); // give x ms more room
            }
        }

        max_encode_time_in_us = encode_time_auto_tune;
        LOGGER_DEBUG(av->m->log, "AUTOTUNE:MAX_ENCODE_TIME_US=%ld us = %.1f fps", (long)encode_time_auto_tune, (float)(1000000.0f / encode_time_auto_tune));

#endif
    }
    // we start with I-frames (full frames) and then switch to normal mode later


#ifdef VIDEO_ENCODER_SOFT_DEADLINE_AUTOTUNE
		call->video.second->last_encoded_frame_ts = current_time_monotonic();
#endif

    { /* Encode */
        vpx_image_t img;
        img.w = img.h = img.d_w = img.d_h = 0;
        vpx_img_alloc(&img, VPX_IMG_FMT_I420, width, height, 0);

        /* I420 "It comprises an NxM Y plane followed by (N/2)x(M/2) V and U planes."
         * http://fourcc.org/yuv.php#IYUV
         */
        memcpy(img.planes[VPX_PLANE_Y], y, width * height);
        memcpy(img.planes[VPX_PLANE_U], u, (width / 2) * (height / 2));
        memcpy(img.planes[VPX_PLANE_V], v, (width / 2) * (height / 2));

        vpx_codec_err_t vrc = vpx_codec_encode(call->video.second->encoder, &img,
            (int64_t)video_frame_record_timestamp, 1, vpx_encode_flags, max_encode_time_in_us);

        vpx_img_free(&img);

        if (vrc != VPX_CODEC_OK) {
            pthread_mutex_unlock(call->mutex_video);
            LOGGER_ERROR(av->m->log, "Could not encode video frame: %s\n", vpx_codec_err_to_string(vrc));
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
    }

    ++call->video.second->frame_counter;

    LOGGER_DEBUG(av->m->log, "VPXENC:======================\n");
    LOGGER_DEBUG(av->m->log, "VPXENC:frame num=%ld\n", (long)call->video.second->frame_counter);


    { /* Send frames */
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t *pkt;

        while ((pkt = vpx_codec_get_cx_data(call->video.second->encoder, &iter)) != NULL) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                const int keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0;
                if ((pkt->data.frame.flags & VPX_FRAME_IS_FRAGMENT) != 0)
                {
                    LOGGER_DEBUG(av->m->log, "VPXENC:VPX_FRAME_IS_FRAGMENT:*yes* size=%lld pid=%d\n",
                     (long long)pkt->data.frame.sz, (int)pkt->data.frame.partition_id);
                }
                else
                {
                    LOGGER_DEBUG(av->m->log, "VPXENC:VPX_FRAME_IS_FRAGMENT:-no- size=%lld pid=%d\n",
                     (long long)pkt->data.frame.sz, (int)pkt->data.frame.partition_id);
                }

                // use the record timestamp that was actually used for this frame
                video_frame_record_timestamp = pkt->data.frame.pts;

                // TOX RTP V3 --- hack to give frame type to function ---
                //
                // use the highest bit (bit 31) to spec. keyframe = 1 / no keyframe = 0
                // if length(31 bits) > 1FFFFFFF then use all bits for length
                // and assume its a keyframe (most likely is anyway)

                // https://www.webmproject.org/docs/webm-sdk/structvpx__codec__cx__pkt.html
                // pkt->data.frame.sz -> size_t
                uint32_t frame_length_in_bytes = (uint64_t)pkt->data.frame.sz;

                if (LOWER_31_BITS(frame_length_in_bytes) > 0x1FFFFFFF) {
                } else {
                    if (keyframe == 1) {
                        frame_length_in_bytes = (uint32_t)(1L << 31) | LOWER_31_BITS(frame_length_in_bytes);
                    }
                }

                // TOX RTP V3 --- hack to give frame type to function ---

                // LOGGER_DEBUG(av->m->log, "video packet record time: %llu", video_frame_record_timestamp);

                int res = rtp_send_data
                          (
                              call->video.first,
                              (const uint8_t *)pkt->data.frame.buf,
                              frame_length_in_bytes,
                              video_frame_record_timestamp,
                              (int32_t)pkt->data.frame.partition_id,
                              av->m->log
                          );

                LOGGER_DEBUG(av->m->log, "+ _sending_FRAME_TYPE_==%s bytes=%d frame_len=%d", keyframe ? "K" : ".",
                             (int)pkt->data.frame.sz, (int)frame_length_in_bytes);
                LOGGER_DEBUG(av->m->log, "+ _sending_FRAME_ b0=%d b1=%d", ((const uint8_t *)pkt->data.frame.buf)[0] ,
                             ((const uint8_t *)pkt->data.frame.buf)[1]);

                video_frame_record_timestamp++;

                if (res < 0) {
                    pthread_mutex_unlock(call->mutex_video);
                    LOGGER_WARNING(av->m->log, "Could not send video frame: %s", strerror(errno));
                    rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                    goto END;
                } else {
                }
            }
        }
    }



    pthread_mutex_unlock(call->mutex_video);

END:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}



void toxav_callback_audio_receive_frame(ToxAV *av, toxav_audio_receive_frame_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->acb.first = callback;
    av->acb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}
void toxav_callback_video_receive_frame(ToxAV *av, toxav_video_receive_frame_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vcb.first = callback;
    av->vcb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}


/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
void callback_bwc(BWController *bwc, uint32_t friend_number, float loss, void *user_data)
{
    /* Callback which is called when the internal measure mechanism reported packet loss.
     * We report suggested lowered bitrate to an app. If app is sending both audio and video,
     * we will report lowered bitrate for video only because in that case video probably
     * takes more than 90% bandwidth. Otherwise, we report lowered bitrate on audio.
     * The application may choose to disable video totally if the stream is too bad.
     */

    ToxAVCall *call = (ToxAVCall *)user_data;
    assert(call);

    LOGGER_DEBUG(call->av->m->log, "Reported loss of %f%%", (double)loss * 100);

    /* if less than x% data loss we do nothing! */
    if (loss < VIDEO_ACCEPTABLE_LOSS) {
        return;
    }

    pthread_mutex_lock(call->av->mutex);

    if (!call->av->bcb.first) {
        pthread_mutex_unlock(call->av->mutex);
        LOGGER_DEBUG(call->av->m->log, "No callback to report loss on");
        return;
    }

    if (call->video_bit_rate) {
        (*call->av->bcb.first)(call->av, friend_number, call->audio_bit_rate,
                               call->video_bit_rate - (call->video_bit_rate * loss),
                               call->av->bcb.second);
    } else if (call->audio_bit_rate) {
        (*call->av->bcb.first)(call->av, friend_number,
                               call->audio_bit_rate - (call->audio_bit_rate * loss),
                               0, call->av->bcb.second);
    }

    pthread_mutex_unlock(call->av->mutex);
}
int callback_invite(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_new(toxav, call->friend_number, NULL);

    if (av_call == NULL) {
        LOGGER_WARNING(toxav->m->log, "Failed to initialize call...");
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    call->av_call = av_call;
    av_call->msi_call = call;

    if (toxav->ccb.first) {
        toxav->ccb.first(toxav, call->friend_number, call->peer_capabilities & msi_CapSAudio,
                         call->peer_capabilities & msi_CapSVideo, toxav->ccb.second);
    } else {
        /* No handler to capture the call request, send failure */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
int callback_start(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_get(toxav, call->friend_number);

    if (av_call == NULL) {
        /* Should this ever happen? */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!call_prepare_transmission(av_call)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!invoke_call_state_callback(toxav, call->friend_number, call->peer_capabilities)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
int callback_end(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_FINISHED);

    if (call->av_call) {
        call_kill_transmission((ToxAVCall *)call->av_call);
        call_remove((ToxAVCall *)call->av_call);
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
int callback_error(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_ERROR);

    if (call->av_call) {
        call_kill_transmission((ToxAVCall *)call->av_call);
        call_remove((ToxAVCall *)call->av_call);
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
int callback_capabilites(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    if (call->peer_capabilities & msi_CapSAudio) {
        rtp_allow_receiving(((ToxAVCall *)call->av_call)->audio.first);
    } else {
        rtp_stop_receiving(((ToxAVCall *)call->av_call)->audio.first);
    }

    if (call->peer_capabilities & msi_CapSVideo) {
        rtp_allow_receiving(((ToxAVCall *)call->av_call)->video.first);
    } else {
        rtp_stop_receiving(((ToxAVCall *)call->av_call)->video.first);
    }

    invoke_call_state_callback(toxav, call->friend_number, call->peer_capabilities);

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
bool audio_bit_rate_invalid(uint32_t bit_rate)
{
    /* Opus RFC 6716 section-2.1.1 dictates the following:
     * Opus supports all bit rates from 6 kbit/s to 510 kbit/s.
     */
    return bit_rate < 6 || bit_rate > 510;
}
bool video_bit_rate_invalid(uint32_t bit_rate)
{
    (void) bit_rate;
    /* TODO(mannol): If anyone knows the answer to this one please fill it up */
    return false;
}
bool invoke_call_state_callback(ToxAV *av, uint32_t friend_number, uint32_t state)
{
    if (av->scb.first) {
        av->scb.first(av, friend_number, state, av->scb.second);
    } else {
        return false;
    }

    return true;
}


ToxAVCall *call_new(ToxAV *av, uint32_t friend_number, TOXAV_ERR_CALL *error)
{
    /* Assumes mutex locked */
    TOXAV_ERR_CALL rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call = NULL;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_FOUND;
        goto END;
    }

    if (m_get_friend_connectionstatus(av->m, friend_number) < 1) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;
        goto END;
    }

    if (call_get(av, friend_number) != NULL) {
        rc = TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;
        goto END;
    }


    call = (ToxAVCall *)calloc(sizeof(ToxAVCall), 1);

    call->last_incoming_video_frame_rtimestamp = 0;
    call->last_incoming_video_frame_ltimestamp = 0;

    call->last_incoming_audio_frame_rtimestamp = 0;
    call->last_incoming_audio_frame_ltimestamp = 0;

    call->reference_rtimestamp = 0;
    call->reference_ltimestamp = 0;
    call->reference_diff_timestamp = 0;
    call->reference_diff_timestamp_set = 0;

    if (call == NULL) {
        rc = TOXAV_ERR_CALL_MALLOC;
        goto END;
    }

    call->av = av;
    call->friend_number = friend_number;

    if (av->calls == NULL) { /* Creating */
        av->calls = (ToxAVCall **)calloc(sizeof(ToxAVCall *), friend_number + 1);

        if (av->calls == NULL) {
            free(call);
            call = NULL;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto END;
        }

        av->calls_tail = av->calls_head = friend_number;
    } else if (av->calls_tail < friend_number) { /* Appending */
        ToxAVCall **tmp = (ToxAVCall **)realloc(av->calls, sizeof(ToxAVCall *) * (friend_number + 1));

        if (tmp == NULL) {
            free(call);
            call = NULL;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto END;
        }

        av->calls = tmp;

        /* Set fields in between to null */
        uint32_t i = av->calls_tail + 1;

        for (; i < friend_number; i ++) {
            av->calls[i] = NULL;
        }

        call->prev = av->calls[av->calls_tail];
        av->calls[av->calls_tail]->next = call;

        av->calls_tail = friend_number;
    } else if (av->calls_head > friend_number) { /* Inserting at front */
        call->next = av->calls[av->calls_head];
        av->calls[av->calls_head]->prev = call;
        av->calls_head = friend_number;
    }

    av->calls[friend_number] = call;

END:

    if (error) {
        *error = rc;
    }

    return call;
}


ToxAVCall *call_get(ToxAV *av, uint32_t friend_number)
{
    /* Assumes mutex locked */
    if (av->calls == NULL || av->calls_tail < friend_number) {
        return NULL;
    }

    return av->calls[friend_number];
}


ToxAVCall *call_remove(ToxAVCall *call)
{
    if (call == NULL) {
        return NULL;
    }

    uint32_t friend_number = call->friend_number;
    ToxAV *av = call->av;

    ToxAVCall *prev = call->prev;
    ToxAVCall *next = call->next;

    /* Set av call in msi to NULL in order to know if call if ToxAVCall is
     * removed from the msi call.
     */
    if (call->msi_call) {
        call->msi_call->av_call = NULL;
    }

    free(call);

    if (prev) {
        prev->next = next;
    } else if (next) {
        av->calls_head = next->friend_number;
    } else {
        goto CLEAR;
    }

    if (next) {
        next->prev = prev;
    } else if (prev) {
        av->calls_tail = prev->friend_number;
    } else {
        goto CLEAR;
    }

    av->calls[friend_number] = NULL;
    return next;

CLEAR:
    av->calls_head = av->calls_tail = 0;
    free(av->calls);
    av->calls = NULL;

    return NULL;
}


bool call_prepare_transmission(ToxAVCall *call)
{
    /* Assumes mutex locked */

    if (call == NULL) {
        return false;
    }

    ToxAV *av = call->av;

    if (!av->acb.first && !av->vcb.first) {
        /* It makes no sense to have CSession without callbacks */
        return false;
    }

    if (call->active) {
        LOGGER_WARNING(av->m->log, "Call already active!\n");
        return true;
    }

    if (create_recursive_mutex(call->mutex_audio) != 0) {
        return false;
    }

    if (create_recursive_mutex(call->mutex_video) != 0) {
        goto FAILURE_3;
    }

    if (create_recursive_mutex(call->mutex) != 0) {
        goto FAILURE_2;
    }

    /* Prepare bwc */
    call->bwc = bwc_new(av->m, call->friend_number, callback_bwc, call);

    { /* Prepare audio */
        call->audio.second = ac_new(av->m->log, av, call->friend_number, av->acb.first, av->acb.second);

        if (!call->audio.second) {
            LOGGER_ERROR(av->m->log, "Failed to create audio codec session");
            goto FAILURE;
        }

        call->audio.first = rtp_new(rtp_TypeAudio, av->m, call->friend_number, call->bwc,
                                    call->audio.second, ac_queue_message);

        if (!call->audio.first) {
            LOGGER_ERROR(av->m->log, "Failed to create audio rtp session");;
            goto FAILURE;
        }
    }
    { /* Prepare video */
        call->video.second = vc_new(av->m->log, av, call->friend_number, av->vcb.first, av->vcb.second);

        if (!call->video.second) {
            LOGGER_ERROR(av->m->log, "Failed to create video codec session");
            goto FAILURE;
        }

        call->video.first = rtp_new(rtp_TypeVideo, av->m, call->friend_number, call->bwc,
                                    call->video.second, vc_queue_message);

        if (!call->video.first) {
            LOGGER_ERROR(av->m->log, "Failed to create video rtp session");
            goto FAILURE;
        }
    }

    call->active = 1;
    return true;

FAILURE:
    bwc_kill(call->bwc);
    rtp_kill(call->audio.first);
    ac_kill(call->audio.second);
    call->audio.first = NULL;
    call->audio.second = NULL;
    rtp_kill(call->video.first);
    vc_kill(call->video.second);
    call->video.first = NULL;
    call->video.second = NULL;
    pthread_mutex_destroy(call->mutex);
FAILURE_2:
    pthread_mutex_destroy(call->mutex_video);
FAILURE_3:
    pthread_mutex_destroy(call->mutex_audio);
    return false;
}


void call_kill_transmission(ToxAVCall *call)
{
    if (call == NULL || call->active == 0) {
        return;
    }

    call->active = 0;

    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(call->mutex_audio);
    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(call->mutex_video);
    pthread_mutex_lock(call->mutex);
    pthread_mutex_unlock(call->mutex);

    bwc_kill(call->bwc);

    rtp_kill(call->audio.first);
    ac_kill(call->audio.second);
    call->audio.first = NULL;
    call->audio.second = NULL;

    rtp_kill(call->video.first);
    vc_kill(call->video.second);
    call->video.first = NULL;
    call->video.second = NULL;

    pthread_mutex_destroy(call->mutex_audio);
    pthread_mutex_destroy(call->mutex_video);
    pthread_mutex_destroy(call->mutex);
}


