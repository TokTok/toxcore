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
#ifndef VIDEO_H
#define VIDEO_H

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vpx_image.h>

#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>


// Zoff --
// -- VP8 codec ----------------
#define VIDEO_CODEC_DECODER_INTERFACE_VP8 (vpx_codec_vp8_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE_VP8 (vpx_codec_vp8_cx())
// -- VP9 codec ----------------
#define VIDEO_CODEC_DECODER_INTERFACE_VP9 (vpx_codec_vp9_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE_VP9 (vpx_codec_vp9_cx())
// Zoff --

#define VIDEO_CODEC_DECODER_MAX_WIDTH  (800) // (16384) // thats just some initial dummy value
#define VIDEO_CODEC_DECODER_MAX_HEIGHT (600) // (16384) // so don't worry

#define VPX_MAX_ENCODER_THREADS (8)
#define VPX_MAX_DECODER_THREADS (8)
#define VIDEO__VP9E_SET_TILE_COLUMNS (2)
#define VIDEO__VP9E_SET_TILE_ROWS (2)
#define VIDEO__VP9_KF_MAX_DIST (40)
#define VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED (0) // 0, 1, 2, 3 # 0->none, 3->maximum
// #define VIDEO_CODEC_ENCODER_USE_FRAGMENTS 1
#define VIDEO_CODEC_FRAGMENT_NUMS (5)
// #define VIDEO_CODEC_FRAGMENT_VPX_NUMS VP8_ONE_TOKENPARTITION
#define VIDEO_CODEC_FRAGMENT_VPX_NUMS VP8_FOUR_TOKENPARTITION
// #define VIDEO_CODEC_FRAGMENT_VPX_NUMS VP8_EIGHT_TOKENPARTITION
#define VIDEO_MAX_FRAGMENT_BUFFER_COUNT (100)


#define VIDEO_SEND_X_KEYFRAMES_FIRST (10) // force the first n frames to be keyframes!
#define VPX_MAX_DIST_NORMAL (30)
#define VPX_MAX_DIST_START (30)


#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
#define VIDEO_RINGBUFFER_BUFFER_ELEMENTS (8 * VIDEO_CODEC_FRAGMENT_NUMS) // this buffer has normally max. 1 entry
#define VIDEO_RINGBUFFER_FILL_THRESHOLD (2 * VIDEO_CODEC_FRAGMENT_NUMS) // start decoding at lower quality
#define VIDEO_RINGBUFFER_DROP_THRESHOLD (5 * VIDEO_CODEC_FRAGMENT_NUMS) // start dropping incoming frames (except index frames)
#else
#define VIDEO_RINGBUFFER_BUFFER_ELEMENTS (8) // this buffer has normally max. 1 entry
#define VIDEO_RINGBUFFER_FILL_THRESHOLD (2) // start decoding at lower quality
#define VIDEO_RINGBUFFER_DROP_THRESHOLD (5) // start dropping incoming frames (except index frames)
#endif

#define VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE 1
// #define VIDEO_DECODER_AUTOSWITCH_CODEC 1
#define VIDEO_DECODER_MINFPS_AUTOTUNE (8)
#define VIDEO_DECODER_LEEWAY_IN_MS_AUTOTUNE (10)

#define VIDEO_ENCODER_SOFT_DEADLINE_AUTOTUNE 1
#define VIDEO_ENCODER_MINFPS_AUTOTUNE (20)
#define VIDEO_ENCODER_LEEWAY_IN_MS_AUTOTUNE (10)


#define VPX_VP8_CODEC (0)
#define VPX_VP9_CODEC (1)

#define VPX_ENCODER_USED VPX_VP8_CODEC
#define VPX_DECODER_USED VPX_VP8_CODEC // this will switch automatically


#include <pthread.h>

struct RTPMessage;
struct RingBuffer;

typedef struct VCSession_s {
    /* encoding */
    vpx_codec_ctx_t encoder[1];
    uint32_t frame_counter;

    /* decoding */
    vpx_codec_ctx_t decoder[1];
    int8_t is_using_vp9;
    struct RingBuffer *vbuf_raw; /* Un-decoded data */

    uint64_t linfts; /* Last received frame time stamp */
    uint32_t lcfd; /* Last calculated frame duration for incoming video payload */
    
    uint64_t last_decoded_frame_ts;
    uint64_t last_encoded_frame_ts;
    uint8_t  flag_end_video_fragment;
    int32_t  last_seen_fragment_num;
    int32_t  last_seen_fragment_seqnum;
    uint32_t decoder_soft_deadline[3];
    uint8_t  decoder_soft_deadline_index;
    uint32_t encoder_soft_deadline[3];
    uint8_t  encoder_soft_deadline_index;

	// options ---
	int32_t video_encoder_cpu_used;
	int32_t video_encoder_cpu_used_prev;
	int32_t video_encoder_vp8_quality;
	int32_t video_encoder_vp8_quality_prev;
	// options ---

    void *vpx_frames_buf_list[VIDEO_MAX_FRAGMENT_BUFFER_COUNT];
    uint16_t fragment_buf_counter;

    Logger *log;
    ToxAV *av;
    uint32_t friend_number;

    PAIR(toxav_video_receive_frame_cb *, void *) vcb; /* Video frame receive callback */

    pthread_mutex_t queue_mutex[1];
} VCSession;

VCSession *vc_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data);
void vc_kill(VCSession *vc);
uint8_t vc_iterate(VCSession *vc, uint8_t skip_video_flag, uint64_t *a_r_timestamp, uint64_t *a_l_timestamp, uint64_t *v_r_timestamp, uint64_t *v_l_timestamp);
int vc_queue_message(void *vcp, struct RTPMessage *msg);
int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist);
int vc_reconfigure_encoder_bitrate_only(VCSession *vc, uint32_t bit_rate);

#endif /* VIDEO_H */
