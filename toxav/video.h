/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_VIDEO_H
#define C_TOXCORE_TOXAV_VIDEO_H

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

#define VIDEO_CODEC_DECODER_MAX_WIDTH  (800) // (16384)
#define VIDEO_CODEC_DECODER_MAX_HEIGHT (600) // (16384)


#define VIDEO_SEND_X_KEYFRAMES_FIRST (7) // force the first n frames to be keyframes!
#define VPX_MAX_DIST_NORMAL (40)
#define VPX_MAX_DIST_START (40)

#define VPX_MAX_ENCODER_THREADS (4)
#define VPX_MAX_DECODER_THREADS (4)
#define VIDEO__VP9E_SET_TILE_COLUMNS (0)
#define VIDEO__VP9_KF_MAX_DIST (999)
#define VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED (0)

#define VPX_VP8_CODEC (0)
#define VPX_VP9_CODEC (1)

#define VPX_ENCODER_USED VPX_VP8_CODEC
#define VPX_DECODER_USED VPX_VP8_CODEC // this will switch automatically


#include <pthread.h>

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

    Logger *log;
    ToxAV *av;
    uint32_t friend_number;

    /* Video frame receive callback */
    toxav_video_receive_frame_cb *vcb;
    void *vcb_user_data;

    pthread_mutex_t queue_mutex[1];
} VCSession;

VCSession *vc_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data);
void vc_kill(VCSession *vc);
void vc_iterate(VCSession *vc);
int vc_queue_message(Mono_Time *mono_time, void *vcp, struct RTPMessage *msg);
int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist);

#endif // C_TOXCORE_TOXAV_VIDEO_H
