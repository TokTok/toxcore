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
#ifndef AUDIO_H
#define AUDIO_H

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <opus.h>
#include <pthread.h>


#define AUDIO_JITTERBUFFER_COUNT (40) // ORIG = 3
#define AUDIO_JITTERBUFFER_FILL_THRESHOLD (8) // this must be lower than the above value!
#define AUDIO_JITTERBUFFER_SKIP_THRESHOLD (14)

#define AUDIO_JITTERBUFFER_MIN_FILLED (0)

#define AUDIO_MAX_SAMPLING_RATE (48000)
#define AUDIO_MAX_CHANNEL_COUNT (2)

#define AUDIO_START_SAMPLING_RATE (48000)
#define AUDIO_START_BITRATE_RATE (48000)
#define AUDIO_START_CHANNEL_COUNT (2)
#define AUDIO_OPUS_PACKET_LOSS_PERC (20) // allow upto 20% loss of audio packets
#define AUDIO_OPUS_COMPLEXITY (10)

#define AUDIO_DECODER__START_SAMPLING_RATE (48000)
#define AUDIO_DECODER__START_CHANNEL_COUNT (2)

#define AUDIO_MAX_FRAME_DURATION_MS (120)

#define AUDIO_LOST_FRAME_INDICATOR (4)

// ((sampling_rate_in_hz * frame_duration_in_ms) / 1000) * 2 // because PCM16 needs 2 bytes for 1 sample
#define AUDIO_MAX_BUFFER_SIZE_PCM16_FOR_FRAME_PER_CHANNEL ((AUDIO_MAX_SAMPLING_RATE * AUDIO_MAX_FRAME_DURATION_MS) / 1000)
#define AUDIO_MAX_BUFFER_SIZE_BYTES_FOR_FRAME_PER_CHANNEL (AUDIO_MAX_BUFFER_SIZE_PCM16_FOR_FRAME_PER_CHANNEL * 2)

/* debugging */
// #define AUDIO_DEBUGGING_SKIP_FRAMES 1
// #define AUDIO_DEBUGGING_SIMULATE_SOME_DATA_LOSS 1
/* debugging */

struct RTPMessage;

typedef struct ACSession_s {
    Logger *log;

    /* encoding */
    OpusEncoder *encoder;
    int32_t le_sample_rate; /* Last encoder sample rate */
    int32_t le_channel_count; /* Last encoder channel count */
    int32_t le_bit_rate; /* Last encoder bit rate */

    /* decoding */
    OpusDecoder *decoder;
    int32_t lp_channel_count; /* Last packet channel count */
    int32_t lp_sampling_rate; /* Last packet sample rate */
    int32_t lp_frame_duration; /* Last packet frame duration */
    int32_t ld_sample_rate; /* Last decoder sample rate */
    int32_t ld_channel_count; /* Last decoder channel count */
    uint64_t ldrts; /* Last decoder reconfiguration time stamp */
    int32_t lp_seqnum; /* last incoming packet sequence number */
    void *j_buf; /* it's a Ringbuffer now */

    pthread_mutex_t queue_mutex[1];

    ToxAV *av;
    uint32_t friend_number;
    PAIR(toxav_audio_receive_frame_cb *, void *) acb; /* Audio frame receive callback */
} ACSession;

ACSession *ac_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_audio_receive_frame_cb *cb, void *cb_data);
void ac_kill(ACSession *ac);
uint8_t ac_iterate(ACSession *ac, uint64_t *a_r_timestamp, uint64_t *a_l_timestamp, uint64_t *v_r_timestamp, uint64_t *v_l_timestamp);
int ac_queue_message(void *acp, struct RTPMessage *msg);
int ac_reconfigure_encoder(ACSession *ac, int32_t bit_rate, int32_t sampling_rate, uint8_t channels);

#endif /* AUDIO_H */
