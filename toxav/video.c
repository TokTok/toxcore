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

#include "video.h"

#include "msi.h"
#include "ring_buffer.h"
#include "rtp.h"

#include "../toxcore/logger.h"
#include "../toxcore/network.h"

#include <assert.h>
#include <stdlib.h>

/*
  Soft deadline the decoder should attempt to meet, in "us" (microseconds). Set to zero for unlimited.
  By convention, the value 1 is used to mean "return as fast as possible."
*/
// TODO: don't hardcode this, let the application choose it
#define WANTED_MAX_DECODER_FPS (20)
#define MAX_DECODE_TIME_US (1000000 / WANTED_MAX_DECODER_FPS) // to allow x fps
/*
VPX_DL_REALTIME       (1)
deadline parameter analogous to VPx REALTIME mode.

VPX_DL_GOOD_QUALITY   (1000000)
deadline parameter analogous to VPx GOOD QUALITY mode.

VPX_DL_BEST_QUALITY   (0)
deadline parameter analogous to VPx BEST QUALITY mode.
*/


// initialize encoder with this value. Target bandwidth to use for this stream, in kilobits per second.
#define VIDEO_BITRATE_INITIAL_VALUE 400
#define VIDEO_BITRATE_INITIAL_VALUE_VP9 400

struct vpx_frame_user_data {
    uint64_t record_timestamp;
};


uint32_t MaxIntraTarget(uint32_t optimalBuffersize)
{
    // Set max to the optimal buffer level (normalized by target BR),
    // and scaled by a scalePar.
    // Max target size = scalePar * optimalBufferSize * targetBR[Kbps].
    // This values is presented in percentage of perFrameBw:
    // perFrameBw = targetBR[Kbps] * 1000 / frameRate.
    // The target in % is as follows:
    float scalePar = 0.5;
    float codec_maxFramerate = 30;
    uint32_t targetPct = optimalBuffersize * scalePar * codec_maxFramerate / 10;

    // Don't go below 3 times the per frame bandwidth.
    const uint32_t minIntraTh = 300;
    return (targetPct < minIntraTh) ? minIntraTh : targetPct;
}


void vc__init_encoder_cfg(Logger *log, vpx_codec_enc_cfg_t *cfg, int16_t kf_max_dist, int32_t quality,
                          int32_t rc_max_quantizer, int32_t rc_min_quantizer, int32_t encoder_codec,
                          int32_t video_keyframe_method)
{

    vpx_codec_err_t rc;

    if (encoder_codec == TOXAV_ENCODER_CODEC_USED_VP8) {
        LOGGER_WARNING(log, "Using VP8 codec for encoder (1)");
        rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE_VP8, cfg, 0);
    } else {
        LOGGER_WARNING(log, "Using VP9 codec for encoder (1)");
        rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE_VP9, cfg, 0);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "vc__init_encoder_cfg:Failed to get config: %s", vpx_codec_err_to_string(rc));
    }

    if (encoder_codec == TOXAV_ENCODER_CODEC_USED_VP9) {
        cfg->rc_target_bitrate = VIDEO_BITRATE_INITIAL_VALUE_VP9;
    } else {
        cfg->rc_target_bitrate =
            VIDEO_BITRATE_INITIAL_VALUE; /* Target bandwidth to use for this stream, in kilobits per second */
    }

    cfg->g_w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    cfg->g_h = VIDEO_CODEC_DECODER_MAX_HEIGHT;
    cfg->g_pass = VPX_RC_ONE_PASS;



    /* zoff (in 2017) */
    cfg->g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT; // | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg->g_lag_in_frames = 0;
    /* Allow lagged encoding
     *
     * If set, this value allows the encoder to consume a number of input
     * frames before producing output frames. This allows the encoder to
     * base decisions for the current frame on future frames. This does
     * increase the latency of the encoding pipeline, so it is not appropriate
     * in all situations (ex: realtime encoding).
     *
     * Note that this is a maximum value -- the encoder may produce frames
     * sooner than the given limit. Set this value to 0 to disable this
     * feature.
     */

    if (video_keyframe_method == TOXAV_ENCODER_KF_METHOD_PATTERN) {
        cfg->kf_min_dist = 0;
        cfg->kf_mode = VPX_KF_DISABLED;
    } else {
        cfg->kf_min_dist = 0;
        cfg->kf_mode = VPX_KF_AUTO; // Encoder determines optimal placement automatically
    }

    cfg->rc_end_usage = VPX_VBR; // what quality mode?
    /*
     VPX_VBR    Variable Bit Rate (VBR) mode
     VPX_CBR    Constant Bit Rate (CBR) mode
     VPX_CQ     Constrained Quality (CQ) mode -> give codec a hint that we may be on low bandwidth connection
     VPX_Q      Constant Quality (Q) mode
     */

    if (kf_max_dist > 1) {
        cfg->kf_max_dist = kf_max_dist; // a full frame every x frames minimum (can be more often, codec decides automatically)
        LOGGER_WARNING(log, "kf_max_dist=%d (1)", cfg->kf_max_dist);
    } else {
        cfg->kf_max_dist = VPX_MAX_DIST_START;
        LOGGER_WARNING(log, "kf_max_dist=%d (2)", cfg->kf_max_dist);
    }

    if (encoder_codec == TOXAV_ENCODER_CODEC_USED_VP9) {
        cfg->kf_max_dist = VIDEO__VP9_KF_MAX_DIST;
        LOGGER_WARNING(log, "kf_max_dist=%d (3)", cfg->kf_max_dist);
    }

    cfg->g_threads = VPX_MAX_ENCODER_THREADS; // Maximum number of threads to use

    cfg->g_timebase.num = 1; // 0.1 ms = timebase units = (1/10000)s
    cfg->g_timebase.den = 10000; // 0.1 ms = timebase units = (1/10000)s

    if (encoder_codec == TOXAV_ENCODER_CODEC_USED_VP9) {
        cfg->rc_dropframe_thresh = 0;
        cfg->rc_resize_allowed = 0;
    } else {
        if (quality == TOXAV_ENCODER_VP8_QUALITY_HIGH) {
            /* Highest-resolution encoder settings */
            cfg->rc_dropframe_thresh = 0; // 0
            cfg->rc_resize_allowed = 0; // 0
            cfg->rc_min_quantizer = rc_min_quantizer; // 0
            cfg->rc_max_quantizer = rc_max_quantizer; // 40
            cfg->rc_resize_up_thresh = 29;
            cfg->rc_resize_down_thresh = 5;
            cfg->rc_undershoot_pct = 100; // 100
            cfg->rc_overshoot_pct = 15; // 15
            cfg->rc_buf_initial_sz = 500; // 500 in ms
            cfg->rc_buf_optimal_sz = 600; // 600 in ms
            cfg->rc_buf_sz = 1000; // 1000 in ms
        } else { // TOXAV_ENCODER_VP8_QUALITY_NORMAL
            cfg->rc_dropframe_thresh = 0;
            cfg->rc_resize_allowed = 0; // allow encoder to resize to smaller resolution
            cfg->rc_min_quantizer = rc_min_quantizer; // 2
            cfg->rc_max_quantizer = rc_max_quantizer; // 63
            cfg->rc_resize_up_thresh = TOXAV_ENCODER_VP_RC_RESIZE_UP_THRESH;
            cfg->rc_resize_down_thresh = TOXAV_ENCODER_VP_RC_RESIZE_DOWN_THRESH;
            cfg->rc_undershoot_pct = 100; // 100
            cfg->rc_overshoot_pct = 15; // 15
            cfg->rc_buf_initial_sz = 500; // 500 in ms
            cfg->rc_buf_optimal_sz = 600; // 600 in ms
            cfg->rc_buf_sz = 1000; // 1000 in ms
        }

    }
}



VCSession *vc_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data)
{
    VCSession *vc = (VCSession *)calloc(sizeof(VCSession), 1);
    vpx_codec_err_t rc;

    if (!vc) {
        LOGGER_WARNING(log, "Allocation failed! Application might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(vc->queue_mutex) != 0) {
        LOGGER_WARNING(log, "Failed to create recursive mutex!");
        free(vc);
        return NULL;
    }

    if (!(vc->vbuf_raw = rb_new(VIDEO_RINGBUFFER_BUFFER_ELEMENTS))) {
        goto BASE_CLEANUP;
    }



    // options ---
    vc->video_encoder_cpu_used = VP8E_SET_CPUUSED_VALUE;
    vc->video_encoder_cpu_used_prev = vc->video_encoder_cpu_used;
    vc->video_encoder_vp8_quality = TOXAV_ENCODER_VP8_QUALITY_NORMAL;
    vc->video_encoder_vp8_quality_prev = vc->video_encoder_vp8_quality;
    vc->video_rc_max_quantizer = TOXAV_ENCODER_VP8_RC_MAX_QUANTIZER_NORMAL;
    vc->video_rc_max_quantizer_prev = vc->video_rc_max_quantizer;
    vc->video_rc_min_quantizer = TOXAV_ENCODER_VP8_RC_MIN_QUANTIZER_NORMAL;
    vc->video_rc_min_quantizer_prev = vc->video_rc_min_quantizer;
    vc->video_encoder_coded_used = TOXAV_ENCODER_CODEC_USED_VP8;
    vc->video_encoder_coded_used_prev = vc->video_encoder_coded_used;
    vc->video_keyframe_method = TOXAV_ENCODER_KF_METHOD_NORMAL;
    vc->video_keyframe_method_prev = vc->video_keyframe_method;
    vc->video_decoder_error_concealment = VIDEO__VP8_DECODER_ERROR_CONCEALMENT;
    vc->video_decoder_error_concealment_prev = vc->video_decoder_error_concealment;
    vc->video_decoder_codec_used = TOXAV_ENCODER_CODEC_USED_VP8;
    // options ---

    vc->send_keyframe_request_received = 0;

    /*
    VPX_CODEC_USE_FRAME_THREADING
       Enable frame-based multi-threading

    VPX_CODEC_USE_ERROR_CONCEALMENT
       Conceal errors in decoded frames
    */
    vpx_codec_dec_cfg_t  dec_cfg;
    dec_cfg.threads = VPX_MAX_DECODER_THREADS; // Maximum number of threads to use
    dec_cfg.w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    dec_cfg.h = VIDEO_CODEC_DECODER_MAX_HEIGHT;

    if (VPX_DECODER_USED == TOXAV_ENCODER_CODEC_USED_VP8) {
        LOGGER_WARNING(log, "Using VP8 codec for decoder (0)");

        vpx_codec_flags_t dec_flags_ = 0;

        if (vc->video_decoder_error_concealment == 1) {
            vpx_codec_caps_t decoder_caps = vpx_codec_get_caps(VIDEO_CODEC_DECODER_INTERFACE_VP8);

            if (decoder_caps & VPX_CODEC_CAP_ERROR_CONCEALMENT) {
                dec_flags_ = VPX_CODEC_USE_ERROR_CONCEALMENT;
                LOGGER_WARNING(log, "Using VP8 VPX_CODEC_USE_ERROR_CONCEALMENT (0)");
            }
        }

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
        rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                dec_flags_ | VPX_CODEC_USE_FRAME_THREADING
                                | VPX_CODEC_USE_POSTPROC | VPX_CODEC_USE_INPUT_FRAGMENTS);
        LOGGER_WARNING(log, "Using VP8 using input fragments (0) rc=%d", (int)rc);
#else
        rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                dec_flags_ | VPX_CODEC_USE_FRAME_THREADING
                                | VPX_CODEC_USE_POSTPROC);
#endif

        if (rc == VPX_CODEC_INCAPABLE) {
            LOGGER_WARNING(log, "Postproc not supported by this decoder (0)");
            rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                    dec_flags_ | VPX_CODEC_USE_FRAME_THREADING);
        }

    } else {
        LOGGER_WARNING(log, "Using VP9 codec for decoder (0)");
        rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP9, &dec_cfg,
                                VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP;
    }


    if (VPX_DECODER_USED == TOXAV_ENCODER_CODEC_USED_VP8) {
        if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 1) {
            LOGGER_WARNING(log, "turn on postproc: OK");
        } else if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 2) {
            vp8_postproc_cfg_t pp = {VP8_MFQE, 1, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(log, "Failed to turn on postproc");
            } else {
                LOGGER_WARNING(log, "turn on postproc: OK");
            }
        } else if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 3) {
            vp8_postproc_cfg_t pp = {VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_MFQE, 1, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(log, "Failed to turn on postproc");
            } else {
                LOGGER_WARNING(log, "turn on postproc: OK");
            }
        } else {
            vp8_postproc_cfg_t pp = {0, 0, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(log, "Failed to turn OFF postproc");
            } else {
                LOGGER_WARNING(log, "Disable postproc: OK");
            }
        }
    }










    /* Set encoder to some initial values
     */
    vpx_codec_enc_cfg_t  cfg;
    vc__init_encoder_cfg(log, &cfg, 1,
                         vc->video_encoder_vp8_quality,
                         vc->video_rc_max_quantizer,
                         vc->video_rc_min_quantizer,
                         vc->video_encoder_coded_used,
                         vc->video_keyframe_method);

    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP8) {
        LOGGER_WARNING(log, "Using VP8 codec for encoder (0.1)");

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
        rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg,
                                VPX_CODEC_USE_FRAME_THREADING | VPX_CODEC_USE_OUTPUT_PARTITION);
#else
        rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg,
                                VPX_CODEC_USE_FRAME_THREADING);
#endif

    } else {
        LOGGER_WARNING(log, "Using VP9 codec for encoder (0.1)");
        rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE_VP9, &cfg, VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }


#if 1
    rc = vpx_codec_control(vc->encoder, VP8E_SET_ENABLEAUTOALTREF, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder VP8E_SET_ENABLEAUTOALTREF setting: %s value=%d", vpx_codec_err_to_string(rc),
                     (int)0);
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    } else {
        LOGGER_WARNING(log, "set encoder VP8E_SET_ENABLEAUTOALTREF setting: %s value=%d", vpx_codec_err_to_string(rc),
                       (int)0);
    }

#endif


#if 1
    uint32_t rc_max_intra_target = MaxIntraTarget(600);
    rc_max_intra_target = 102;
    rc = vpx_codec_control(vc->encoder, VP8E_SET_MAX_INTRA_BITRATE_PCT, rc_max_intra_target);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder VP8E_SET_MAX_INTRA_BITRATE_PCT setting: %s value=%d",
                     vpx_codec_err_to_string(rc),
                     (int)rc_max_intra_target);
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    } else {
        LOGGER_WARNING(log, "set encoder VP8E_SET_MAX_INTRA_BITRATE_PCT setting: %s value=%d", vpx_codec_err_to_string(rc),
                       (int)rc_max_intra_target);
    }

#endif



    /*
    Codec control function to set encoder internal speed settings.
    Changes in this value influences, among others, the encoder's selection of motion estimation methods.
    Values greater than 0 will increase encoder speed at the expense of quality.

    Note:
      Valid range for VP8: -16..16
      Valid range for VP9: -8..8
    */

    int cpu_used_value = vc->video_encoder_cpu_used;

    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
        if (cpu_used_value < -8) {
            cpu_used_value = -8;
        } else if (cpu_used_value > 8) {
            cpu_used_value = 8; // set to default (fastest) value
        }
    }

    rc = vpx_codec_control(vc->encoder, VP8E_SET_CPUUSED, cpu_used_value);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder VP8E_SET_CPUUSED setting: %s value=%d", vpx_codec_err_to_string(rc),
                     (int)cpu_used_value);
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    } else {
        LOGGER_WARNING(log, "set encoder VP8E_SET_CPUUSED setting: %s value=%d", vpx_codec_err_to_string(rc),
                       (int)cpu_used_value);
    }

    vc->video_encoder_cpu_used = cpu_used_value;
    vc->video_encoder_cpu_used_prev = cpu_used_value;

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS

    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP8) {
        rc = vpx_codec_control(vc->encoder, VP8E_SET_TOKEN_PARTITIONS, VIDEO_CODEC_FRAGMENT_VPX_NUMS);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(log, "Failed to set encoder token partitions: %s", vpx_codec_err_to_string(rc));
        }
    }

#endif

    /*
    VP9E_SET_TILE_COLUMNS

    Codec control function to set number of tile columns.

    In encoding and decoding, VP9 allows an input image frame be partitioned
    into separated vertical tile columns, which can be encoded or decoded independently.
    This enables easy implementation of parallel encoding and decoding. This control requests
    the encoder to use column tiles in encoding an input frame, with number of tile columns
    (in Log2 unit) as the parameter: 0 = 1 tile column 1 = 2 tile columns
    2 = 4 tile columns ..... n = 2**n tile columns The requested tile columns will
    be capped by encoder based on image size limitation (The minimum width of a
    tile column is 256 pixel, the maximum is 4096).

    By default, the value is 0, i.e. one single column tile for entire image.

    Supported in codecs: VP9
     */

    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
        rc = vpx_codec_control(vc->encoder, VP9E_SET_TILE_COLUMNS, VIDEO__VP9E_SET_TILE_COLUMNS);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(vc->encoder);
            goto BASE_CLEANUP_1;
        }

        rc = vpx_codec_control(vc->encoder, VP9E_SET_TILE_ROWS, VIDEO__VP9E_SET_TILE_ROWS);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(vc->encoder);
            goto BASE_CLEANUP_1;
        }
    }


#if 0

    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
        if (1 == 2) {
            rc = vpx_codec_control(vc->encoder, VP9E_SET_LOSSLESS, 1);

            LOGGER_WARNING(vc->log, "setting VP9 lossless video quality(2): ON");

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(vc->encoder);
                goto BASE_CLEANUP_1;
            }
        } else {
            rc = vpx_codec_control(vc->encoder, VP9E_SET_LOSSLESS, 0);

            LOGGER_WARNING(vc->log, "setting VP9 lossless video quality(2): OFF");

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(vc->encoder);
                goto BASE_CLEANUP_1;
            }
        }
    }

#endif


    /*
    VPX_CTRL_USE_TYPE(VP8E_SET_NOISE_SENSITIVITY,  unsigned int)
    control function to set noise sensitivity
      0: off, 1: OnYOnly, 2: OnYUV, 3: OnYUVAggressive, 4: Adaptive
    */
    /*
      rc = vpx_codec_control(vc->encoder, VP8E_SET_NOISE_SENSITIVITY, 2);

      if (rc != VPX_CODEC_OK) {
          LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
          vpx_codec_destroy(vc->encoder);
          goto BASE_CLEANUP_1;
      }
     */

    // VP8E_SET_STATIC_THRESHOLD


    vc->linfts = current_time_monotonic();
    vc->lcfd = 10; // initial value in ms for av_iterate sleep
    vc->vcb.first = cb;
    vc->vcb.second = cb_data;
    vc->friend_number = friend_number;
    vc->av = av;
    vc->log = log;
    vc->last_decoded_frame_ts = 0;
    vc->last_encoded_frame_ts = 0;
    vc->flag_end_video_fragment = 0;
    vc->last_seen_fragment_num = 0;
    vc->count_old_video_frames_seen = 0;
    vc->last_seen_fragment_seqnum = -1;
    vc->fragment_buf_counter = 0;

    for (int k = 0; k < VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE_ENTRIES; k++) {
        vc->decoder_soft_deadline[k] = MAX_DECODE_TIME_US;
    }

    vc->decoder_soft_deadline_index = 0;

    for (int k = 0; k < VIDEO_ENCODER_SOFT_DEADLINE_AUTOTUNE_ENTRIES; k++) {
        vc->encoder_soft_deadline[k] = MAX_ENCODE_TIME_US;
    }

    vc->encoder_soft_deadline_index = 0;

    uint16_t jk = 0;

    for (jk = 0; jk < (uint16_t)VIDEO_MAX_FRAGMENT_BUFFER_COUNT; jk++) {
        vc->vpx_frames_buf_list[jk] = NULL;
    }

    return vc;

BASE_CLEANUP_1:
    vpx_codec_destroy(vc->decoder);
BASE_CLEANUP:
    pthread_mutex_destroy(vc->queue_mutex);
    rb_kill((RingBuffer *)vc->vbuf_raw);
    free(vc);
    return NULL;
}

void vc_kill(VCSession *vc)
{
    if (!vc) {
        return;
    }

    int jk;

    for (jk = 0; jk < vc->fragment_buf_counter; jk++) {
        free(vc->vpx_frames_buf_list[jk]);
        vc->vpx_frames_buf_list[jk] = NULL;
    }

    vc->fragment_buf_counter = 0;


    vpx_codec_destroy(vc->encoder);
    vpx_codec_destroy(vc->decoder);

    void *p;
    uint8_t dummy;

    while (rb_read((RingBuffer *)vc->vbuf_raw, &p, &dummy)) {
        free(p);
    }

    rb_kill((RingBuffer *)vc->vbuf_raw);

    pthread_mutex_destroy(vc->queue_mutex);

    LOGGER_DEBUG(vc->log, "Terminated video handler: %p", vc);
    free(vc);
}



void video_switch_decoder(VCSession *vc)
{


    /*
    vpx_codec_err_t vpx_codec_peek_stream_info  (   vpx_codec_iface_t *     iface,
            const uint8_t *     data,
            unsigned int    data_sz,
            vpx_codec_stream_info_t *   si
        )

    Parse stream info from a buffer.
    Performs high level parsing of the bitstream. Construction of a decoder context is not necessary.
    Can be used to determine if the bitstream is of the proper format, and to extract information from the stream.
    */


    // toggle decoder codec between VP8 and VP9
    // TODO: put codec into header flags at encoder side, then use this at decoder side!
    if (vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_VP8) {
        vc->video_decoder_codec_used = TOXAV_ENCODER_CODEC_USED_VP9;
    } else {
        vc->video_decoder_codec_used = TOXAV_ENCODER_CODEC_USED_VP8;
    }

    vpx_codec_err_t rc;
    vpx_codec_ctx_t new_d;

    LOGGER_WARNING(vc->log, "Switch:Re-initializing DEcoder to: %d", (int)vc->video_decoder_codec_used);

    vpx_codec_dec_cfg_t dec_cfg;
    dec_cfg.threads = VPX_MAX_DECODER_THREADS; // Maximum number of threads to use
    dec_cfg.w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    dec_cfg.h = VIDEO_CODEC_DECODER_MAX_HEIGHT;

    if (vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_VP8) {

        vpx_codec_flags_t dec_flags_ = 0;

        if (vc->video_decoder_error_concealment == 1) {
            vpx_codec_caps_t decoder_caps = vpx_codec_get_caps(VIDEO_CODEC_DECODER_INTERFACE_VP8);

            if (decoder_caps & VPX_CODEC_CAP_ERROR_CONCEALMENT) {
                dec_flags_ = VPX_CODEC_USE_ERROR_CONCEALMENT;
                LOGGER_WARNING(vc->log, "Using VP8 VPX_CODEC_USE_ERROR_CONCEALMENT (1)");
            }
        }

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
        rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                dec_flags_ | VPX_CODEC_USE_FRAME_THREADING
                                | VPX_CODEC_USE_POSTPROC | VPX_CODEC_USE_INPUT_FRAGMENTS);
        LOGGER_WARNING(vc->log, "Using VP8 using input fragments (1) rc=%d", (int)rc);
#else
        rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                dec_flags_ | VPX_CODEC_USE_FRAME_THREADING
                                | VPX_CODEC_USE_POSTPROC);
#endif

        if (rc == VPX_CODEC_INCAPABLE) {
            LOGGER_WARNING(vc->log, "Postproc not supported by this decoder");
            rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                    dec_flags_ | VPX_CODEC_USE_FRAME_THREADING);
        }

    } else {
        rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP9, &dec_cfg,
                                VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(vc->log, "Failed to Re-initialize decoder: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(&new_d);
        return;
    }


    if (vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_VP8) {
        if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 1) {
            LOGGER_WARNING(vc->log, "turn on postproc: OK");
        } else if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 2) {
            vp8_postproc_cfg_t pp = {VP8_DEBLOCK, 1, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(&new_d, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(vc->log, "Failed to turn on postproc");
            } else {
                LOGGER_WARNING(vc->log, "turn on postproc: OK");
            }
        } else if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 3) {
            vp8_postproc_cfg_t pp = {VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_MFQE, 1, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(&new_d, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(vc->log, "Failed to turn on postproc");
            } else {
                LOGGER_WARNING(vc->log, "turn on postproc: OK");
            }
        } else {
            vp8_postproc_cfg_t pp = {0, 0, 0};
            vpx_codec_err_t cc_res = vpx_codec_control(&new_d, VP8_SET_POSTPROC, &pp);

            if (cc_res != VPX_CODEC_OK) {
                LOGGER_WARNING(vc->log, "Failed to turn OFF postproc");
            } else {
                LOGGER_WARNING(vc->log, "Disable postproc: OK");
            }
        }
    }

    // now replace the current decoder
    vpx_codec_destroy(vc->decoder);
    memcpy(vc->decoder, &new_d, sizeof(new_d));

    LOGGER_ERROR(vc->log, "Re-initialize decoder OK: %s", vpx_codec_err_to_string(rc));

}


uint8_t vc_iterate(VCSession *vc, Messenger *m, uint8_t skip_video_flag, uint64_t *a_r_timestamp,
                   uint64_t *a_l_timestamp,
                   uint64_t *v_r_timestamp, uint64_t *v_l_timestamp)
{
    if (!vc) {
        return 0;
    }

    uint8_t ret_value = 0;
    struct RTPMessage *p;
    bool have_requested_index_frame = false;

    vpx_codec_err_t rc;

    pthread_mutex_lock(vc->queue_mutex);

    uint8_t data_type;

    uint32_t full_data_len;


    if (rb_read((RingBuffer *)vc->vbuf_raw, (void **)&p, &data_type)) {
        const struct RTPHeader *header_v3_0 = (void *) & (p->header);

        if ((int32_t)header_v3_0->sequnum < (int32_t)vc->last_seen_fragment_seqnum) {
            // drop frame with too old sequence number
            LOGGER_WARNING(vc->log, "skipping incoming video frame (0) with sn=%d lastseen=%d old_frames_count=%d",
                           (int)header_v3_0->sequnum,
                           (int)vc->last_seen_fragment_seqnum,
                           (int)vc->count_old_video_frames_seen);

            vc->count_old_video_frames_seen++;

            if (vc->count_old_video_frames_seen > 6) {
                // if we see more than 6 old video frames in a row, then either there was
                // a seqnum rollover or something else. just play those frames then
                vc->last_seen_fragment_seqnum = (int32_t)header_v3_0->sequnum;
                vc->count_old_video_frames_seen = 0;
            }

            // rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);

            free(p);
            pthread_mutex_unlock(vc->queue_mutex);
            return 0;
        }

        if ((int32_t)header_v3_0->sequnum != (int32_t)(vc->last_seen_fragment_seqnum + 1)) {
            int32_t missing_frames_count = (int32_t)header_v3_0->sequnum -
                                           (int32_t)(vc->last_seen_fragment_seqnum + 1);
            LOGGER_DEBUG(vc->log, "missing %d video frames (m1)", (int)missing_frames_count);
            rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);

            if (missing_frames_count > 5) {
                if ((vc->last_requested_keyframe_ts + VIDEO_MIN_REQUEST_KEYFRAME_INTERVAL_MS_FOR_NF)
                        < current_time_monotonic()) {
                    uint32_t pkg_buf_len = 2;
                    uint8_t pkg_buf[pkg_buf_len];
                    pkg_buf[0] = PACKET_REQUEST_KEYFRAME;
                    pkg_buf[1] = 0;

                    if (-1 == send_custom_lossless_packet(m, vc->friend_number, pkg_buf, pkg_buf_len)) {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_REQUEST_KEYFRAME:RTP send failed (2)");
                    } else {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_REQUEST_KEYFRAME:RTP Sent. (2)");
                        have_requested_index_frame = true;
                        vc->last_requested_keyframe_ts = current_time_monotonic();
                    }
                }
            }
        }


        // TODO: check for seqnum rollover!!
        vc->count_old_video_frames_seen = 0;
        vc->last_seen_fragment_seqnum = header_v3_0->sequnum;

        if (skip_video_flag == 1) {
#if 1

            if ((int)data_type != (int)video_frame_type_KEYFRAME) {
                free(p);
                LOGGER_DEBUG(vc->log, "skipping incoming video frame (1)");

                rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);

                //if (rb_read((RingBuffer *)vc->vbuf_raw, (void **)&p, &data_type)) {
                //} else {
                pthread_mutex_unlock(vc->queue_mutex);
                return 0;
                //}
            }

#endif
        } else {
#if 0

            if ((int)rb_size((RingBuffer *)vc->vbuf_raw) > (int)VIDEO_RINGBUFFER_DROP_THRESHOLD) {
                // LOGGER_WARNING(vc->log, "skipping:002 data_type=%d", (int)data_type);
                if ((int)data_type != (int)video_frame_type_KEYFRAME) {
                    // LOGGER_WARNING(vc->log, "skipping:003");
                    free(p);
                    LOGGER_WARNING(vc->log, "skipping all incoming video frames (2)");
                    //void *p2;
                    //uint8_t dummy;
                    //while (rb_read((RingBuffer *)vc->vbuf_raw, &p2, &dummy)) {
                    //    free(p2);
                    //}

                    rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);

                    pthread_mutex_unlock(vc->queue_mutex);
                    return 0;
                }
            }

#endif
        }

        pthread_mutex_unlock(vc->queue_mutex);

        const struct RTPHeader *header_v3 = (void *) & (p->header);

        if (header_v3->flags & RTP_LARGE_FRAME) {
            full_data_len = header_v3->data_length_full;
            LOGGER_DEBUG(vc->log, "vc_iterate:001:full_data_len=%d", (int)full_data_len);
        } else {
            full_data_len = p->len;
            LOGGER_DEBUG(vc->log, "vc_iterate:002");
        }

        LOGGER_DEBUG(vc->log, "vc_iterate: rb_read p->len=%d data_type=%d", (int)full_data_len, (int)data_type);
        LOGGER_DEBUG(vc->log, "vc_iterate: rb_read rb size=%d", (int)rb_size((RingBuffer *)vc->vbuf_raw));

#if 1

        if ((int)data_type == (int)video_frame_type_KEYFRAME) {
            int percent_recvd = (int)(((float)header_v3->received_length_full / (float)full_data_len) * 100.0f);

            if (percent_recvd < 100) {
                LOGGER_WARNING(vc->log, "RTP_RECV:sn=%ld fn=%ld pct=%d%% *I* len=%ld recv_len=%ld",
                               (long)header_v3->sequnum,
                               (long)header_v3->fragment_num,
                               percent_recvd,
                               (long)full_data_len,
                               (long)header_v3->received_length_full);
            } else {
                LOGGER_DEBUG(vc->log, "RTP_RECV:sn=%ld fn=%ld pct=%d%% *I* len=%ld recv_len=%ld",
                             (long)header_v3->sequnum,
                             (long)header_v3->fragment_num,
                             percent_recvd,
                             (long)full_data_len,
                             (long)header_v3->received_length_full);
            }

            if ((percent_recvd < 100) && (have_requested_index_frame == false)) {
                if ((vc->last_requested_keyframe_ts + VIDEO_MIN_REQUEST_KEYFRAME_INTERVAL_MS_FOR_KF)
                        < current_time_monotonic()) {
                    // if keyframe received has less than 100% of the data, request a new keyframe
                    // from the sender
                    uint32_t pkg_buf_len = 2;
                    uint8_t pkg_buf[pkg_buf_len];
                    pkg_buf[0] = PACKET_REQUEST_KEYFRAME;
                    pkg_buf[1] = 0;

                    if (-1 == send_custom_lossless_packet(m, vc->friend_number, pkg_buf, pkg_buf_len)) {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_REQUEST_KEYFRAME:RTP send failed");
                    } else {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_REQUEST_KEYFRAME:RTP Sent.");
                        vc->last_requested_keyframe_ts = current_time_monotonic();
                    }
                }
            }
        } else {
            LOGGER_DEBUG(vc->log, "RTP_RECV:sn=%ld fn=%ld pct=%d%% len=%ld recv_len=%ld",
                         (long)header_v3->sequnum,
                         (long)header_v3->fragment_num,
                         (int)(((float)header_v3->received_length_full / (float)full_data_len) * 100.0f),
                         (long)full_data_len,
                         (long)header_v3->received_length_full);
        }

#endif

        long decoder_soft_dealine_value_used = VPX_DL_REALTIME;
        void *user_priv = NULL;

        if (header_v3->frame_record_timestamp > 0) {
#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
            // --- //
#else

#ifdef VIDEO_PTS_TIMESTAMPS
            struct vpx_frame_user_data *vpx_u_data = calloc(1, sizeof(struct vpx_frame_user_data));
            vpx_u_data->record_timestamp = header_v3->frame_record_timestamp;
            user_priv = vpx_u_data;
#endif

#endif
        }

        if ((int)rb_size((RingBuffer *)vc->vbuf_raw) > (int)VIDEO_RINGBUFFER_FILL_THRESHOLD) {
            rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, user_priv, VPX_DL_REALTIME);
            LOGGER_DEBUG(vc->log, "skipping:REALTIME");
        }

#ifdef VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE
        else {
            long decode_time_auto_tune = MAX_DECODE_TIME_US;

            if (vc->last_decoded_frame_ts > 0) {

                // calc mean value
                decode_time_auto_tune = 0;

                for (int k = 0; k < VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE_ENTRIES; k++) {
                    decode_time_auto_tune = decode_time_auto_tune + vc->decoder_soft_deadline[k];
                }

                decode_time_auto_tune = decode_time_auto_tune / VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE_ENTRIES;

                if (decode_time_auto_tune > (1000000 / VIDEO_DECODER_MINFPS_AUTOTUNE)) {
                    decode_time_auto_tune = (1000000 / VIDEO_DECODER_MINFPS_AUTOTUNE);
                }

                if (decode_time_auto_tune > (VIDEO_DECODER_LEEWAY_IN_MS_AUTOTUNE * 1000)) {
                    decode_time_auto_tune = decode_time_auto_tune - (VIDEO_DECODER_LEEWAY_IN_MS_AUTOTUNE * 1000); // give x ms more room
                }
            }

            decoder_soft_dealine_value_used = decode_time_auto_tune;
            rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, user_priv, (long)decode_time_auto_tune);

            LOGGER_DEBUG(vc->log, "AUTOTUNE:MAX_DECODE_TIME_US=%ld us = %.1f fps", (long)decode_time_auto_tune,
                         (float)(1000000.0f / decode_time_auto_tune));
        }

#else
        else {
            decoder_soft_dealine_value_used = MAX_DECODE_TIME_US;
            rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, user_priv, MAX_DECODE_TIME_US);
            // LOGGER_WARNING(vc->log, "NORMAL:MAX_DECODE_TIME_US=%d", (int)MAX_DECODE_TIME_US);
        }

#endif



#ifdef VIDEO_DECODER_AUTOSWITCH_CODEC

        if (rc != VPX_CODEC_OK) {
            if ((rc == VPX_CODEC_CORRUPT_FRAME) || (rc == VPX_CODEC_UNSUP_BITSTREAM)) {
                LOGGER_WARNING(vc->log, "Switching VPX Decoder");
                video_switch_decoder(vc);

                rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, user_priv, VPX_DL_REALTIME);

                if (rc != VPX_CODEC_OK) {
                    LOGGER_ERROR(vc->log, "There is still an error decoding video: err-num=%d err-str=%s", (int)rc,
                                 vpx_codec_err_to_string(rc));

                    if (user_priv != NULL) {
                        free(user_priv);
                    }
                }
            } else {
                // LOGGER_ERROR(vc->log, "Error decoding video: err-num=%d err-str=%s", (int)rc, vpx_codec_err_to_string(rc));
            }
        }

#else

        if (rc != VPX_CODEC_OK) {
            if (rc == VPX_CODEC_CORRUPT_FRAME) {
                LOGGER_WARNING(vc->log, "Corrupt frame detected: data size=%d start byte=%d end byte=%d",
                               (int)full_data_len, (int)p->data[0], (int)p->data[full_data_len - 1]);
            } else {
                // LOGGER_ERROR(vc->log, "Error decoding video: err-num=%d err-str=%s", (int)rc, vpx_codec_err_to_string(rc));
            }
        }

#endif

        if (rc == VPX_CODEC_OK) {

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS

            int save_current_buf = 0;

            if (header_v3->fragment_num < vc->last_seen_fragment_num) {
                if (vc->flag_end_video_fragment == 0) {
                    //LOGGER_WARNING(vc->log, "endframe:x:%d", (int)header_v3->fragment_num);
                    vc->flag_end_video_fragment = 1;
                    save_current_buf = 1;
                    vpx_codec_decode(vc->decoder, NULL, 0, user_priv, decoder_soft_dealine_value_used);
                } else {
                    vc->flag_end_video_fragment = 0;
                    //LOGGER_WARNING(vc->log, "reset:flag:%d", (int)header_v3->fragment_num);
                }
            } else {
                if ((long)header_v3->fragment_num == (long)(VIDEO_CODEC_FRAGMENT_NUMS - 1)) {
                    //LOGGER_WARNING(vc->log, "endframe:N:%d", (int)(VIDEO_CODEC_FRAGMENT_NUMS - 1));
                    vc->flag_end_video_fragment = 1;
                    vpx_codec_decode(vc->decoder, NULL, 0, user_priv, decoder_soft_dealine_value_used);
                }
            }

            // push buffer to list
            if (vc->fragment_buf_counter < (uint16_t)(VIDEO_MAX_FRAGMENT_BUFFER_COUNT - 1)) {
                vc->vpx_frames_buf_list[vc->fragment_buf_counter] = p;
                vc->fragment_buf_counter++;
            } else {
                LOGGER_WARNING(vc->log, "mem leak: VIDEO_MAX_FRAGMENT_BUFFER_COUNT");
            }

            vc->last_seen_fragment_num = header_v3->fragment_num;
#endif

            /* Play decoded images */
            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = NULL;

            while ((dest = vpx_codec_get_frame(vc->decoder, &iter)) != NULL) {
                // we have a frame, set return code
                ret_value = 1;

                if (vc->vcb.first) {

                    // what is the audio to video latency?
                    //
                    if (dest->user_priv != NULL) {
                        uint64_t frame_record_timestamp_vpx = ((struct vpx_frame_user_data *)(dest->user_priv))->record_timestamp;

                        //LOGGER_ERROR(vc->log, "VIDEO:TTx: %llu now=%llu", frame_record_timestamp_vpx, current_time_monotonic());
                        if (frame_record_timestamp_vpx > 0) {
                            ret_value = 1;

                            if (*v_r_timestamp < frame_record_timestamp_vpx) {
                                // LOGGER_ERROR(vc->log, "VIDEO:TTx:2: %llu", frame_record_timestamp_vpx);
                                *v_r_timestamp = frame_record_timestamp_vpx;
                                *v_l_timestamp = current_time_monotonic();
                            } else {
                                // TODO: this should not happen here!
                                LOGGER_DEBUG(vc->log, "VIDEO: remote timestamp older");
                            }
                        }

                        //
                        // what is the audio to video latency?
                        free(dest->user_priv);
                    }

                    LOGGER_DEBUG(vc->log, "VIDEO: -FRAME OUT- %p %p %p",
                                 (const uint8_t *)dest->planes[0],
                                 (const uint8_t *)dest->planes[1],
                                 (const uint8_t *)dest->planes[2]);

                    vc->vcb.first(vc->av, vc->friend_number, dest->d_w, dest->d_h,
                                  (const uint8_t *)dest->planes[0],
                                  (const uint8_t *)dest->planes[1],
                                  (const uint8_t *)dest->planes[2],
                                  dest->stride[0], dest->stride[1], dest->stride[2], vc->vcb.second);
                }

                vpx_img_free(dest); // is this needed? none of the VPx examples show that
            }

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS

            if (vc->flag_end_video_fragment == 1) {
                //LOGGER_ERROR(vc->log, "free vpx_frames_buf_list:count=%d", (int)vc->fragment_buf_counter);
                uint16_t jk = 0;

                if (save_current_buf == 1) {
                    for (jk = 0; jk < (vc->fragment_buf_counter - 1); jk++) {
                        free(vc->vpx_frames_buf_list[jk]);
                        vc->vpx_frames_buf_list[jk] = NULL;
                    }

                    vc->vpx_frames_buf_list[0] = vc->vpx_frames_buf_list[vc->fragment_buf_counter];
                    vc->vpx_frames_buf_list[vc->fragment_buf_counter] = NULL;
                    vc->fragment_buf_counter = 1;
                } else {
                    for (jk = 0; jk < vc->fragment_buf_counter; jk++) {
                        free(vc->vpx_frames_buf_list[jk]);
                        vc->vpx_frames_buf_list[jk] = NULL;
                    }

                    vc->fragment_buf_counter = 0;
                }
            }

#else
            free(p);
#endif

        } else {
            free(p);
        }

        return ret_value;
    } else {
        // no frame data available
        // LOGGER_WARNING(vc->log, "Error decoding video: rb_read");
    }

    pthread_mutex_unlock(vc->queue_mutex);

    return ret_value;
}


int vc_queue_message(void *vcp, struct RTPMessage *msg)
{
    /* This function is called with complete messages
     * they have already been assembled.
     * this function gets called from handle_rtp_packet() and handle_rtp_packet_v3()
     */
    if (!vcp || !msg) {
        return -1;
    }

    VCSession *vc = (VCSession *)vcp;

    const struct RTPHeader *header_v3 = (void *) & (msg->header);
    const struct RTPHeader *const header = &msg->header;

    if (msg->header.pt == (rtp_TypeVideo + 2) % 128) {
        LOGGER_WARNING(vc->log, "Got dummy!");
        free(msg);
        return 0;
    }

    if (msg->header.pt != rtp_TypeVideo % 128) {
        LOGGER_WARNING(vc->log, "Invalid payload type! pt=%d", (int)msg->header.pt);
        free(msg);
        return -1;
    }

    pthread_mutex_lock(vc->queue_mutex);

    LOGGER_DEBUG(vc->log, "TT:queue:V:fragnum=%ld", (long)header_v3->fragment_num);


    if ((header->flags & RTP_LARGE_FRAME) && header->pt == rtp_TypeVideo % 128) {
        // LOGGER_WARNING(vc->log, "rb_write msg->len=%d b0=%d b1=%d rb_size=%d", (int)msg->len, (int)msg->data[0], (int)msg->data[1], (int)rb_size((RingBuffer *)vc->vbuf_raw));
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, (uint8_t)((header->flags & RTP_KEY_FRAME) != 0)));
    } else {
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, 0));
    }


    /* Calculate time since we received the last video frame */
    // use 5ms less than the actual time, to give some free room
    uint32_t t_lcfd = (current_time_monotonic() - vc->linfts) - 5;
    vc->lcfd = t_lcfd > 100 ? vc->lcfd : t_lcfd;

#ifdef VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE

    // Autotune decoder softdeadline here ----------
    if (vc->last_decoded_frame_ts > 0) {
        long decode_time_auto_tune = (current_time_monotonic() - vc->last_decoded_frame_ts) * 1000;

        if (decode_time_auto_tune == 0) {
            decode_time_auto_tune = 1; // 0 means infinite long softdeadline!
        }

        vc->decoder_soft_deadline[vc->decoder_soft_deadline_index] = decode_time_auto_tune;
        vc->decoder_soft_deadline_index = (vc->decoder_soft_deadline_index + 1) % VIDEO_DECODER_SOFT_DEADLINE_AUTOTUNE_ENTRIES;

        LOGGER_DEBUG(vc->log, "AUTOTUNE:INCOMING=%ld us = %.1f fps", (long)decode_time_auto_tune,
                     (float)(1000000.0f / decode_time_auto_tune));

    }

    vc->last_decoded_frame_ts = current_time_monotonic();
    // Autotune decoder softdeadline here ----------
#endif

    vc->linfts = current_time_monotonic();

    pthread_mutex_unlock(vc->queue_mutex);

    return 0;
}

int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height,
                           int16_t kf_max_dist)
{
    if (!vc) {
        return -1;
    }

    vpx_codec_enc_cfg_t cfg2 = *vc->encoder->config.enc;
    vpx_codec_err_t rc;

    if (cfg2.rc_target_bitrate == bit_rate && cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1
            && vc->video_encoder_cpu_used == vc->video_encoder_cpu_used_prev
            && vc->video_encoder_vp8_quality == vc->video_encoder_vp8_quality_prev
            && vc->video_rc_max_quantizer == vc->video_rc_max_quantizer_prev
            && vc->video_rc_min_quantizer == vc->video_rc_min_quantizer_prev
            && vc->video_encoder_coded_used == vc->video_encoder_coded_used_prev
            && vc->video_keyframe_method == vc->video_keyframe_method_prev
       ) {
        return 0; /* Nothing changed */
    }

    if (cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1
            && vc->video_encoder_cpu_used == vc->video_encoder_cpu_used_prev
            && vc->video_encoder_vp8_quality == vc->video_encoder_vp8_quality_prev
            && vc->video_rc_max_quantizer == vc->video_rc_max_quantizer_prev
            && vc->video_rc_min_quantizer == vc->video_rc_min_quantizer_prev
            && vc->video_encoder_coded_used == vc->video_encoder_coded_used_prev
            && vc->video_keyframe_method == vc->video_keyframe_method_prev
       ) {
        /* Only bit rate changed */

        LOGGER_INFO(vc->log, "bitrate change from: %u to: %u", (uint32_t)(cfg2.rc_target_bitrate / 1000),
                    (uint32_t)(bit_rate / 1000));

        cfg2.rc_target_bitrate = bit_rate;

        rc = vpx_codec_enc_config_set(vc->encoder, &cfg2);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            return -1;
        }
    } else {
        /* Resolution is changed, must reinitialize encoder since libvpx v1.4 doesn't support
         * reconfiguring encoder to use resolutions greater than initially set.
         */
        /*
         * TODO: Zoff in 2018: i wonder if this is still the case with libvpx 1.7.x ?
         */

        LOGGER_DEBUG(vc->log, "Have to reinitialize vpx encoder on session %p", vc);


        vpx_codec_ctx_t new_c;
        vpx_codec_enc_cfg_t  cfg;
        vc__init_encoder_cfg(vc->log, &cfg, kf_max_dist,
                             vc->video_encoder_vp8_quality,
                             vc->video_rc_max_quantizer,
                             vc->video_rc_min_quantizer,
                             vc->video_encoder_coded_used,
                             vc->video_keyframe_method);

        vc->video_encoder_coded_used_prev = vc->video_encoder_coded_used;
        vc->video_encoder_vp8_quality_prev = vc->video_encoder_vp8_quality;
        vc->video_rc_max_quantizer_prev = vc->video_rc_max_quantizer;
        vc->video_rc_min_quantizer_prev = vc->video_rc_min_quantizer;
        vc->video_keyframe_method_prev = vc->video_keyframe_method;

        cfg.rc_target_bitrate = bit_rate;
        cfg.g_w = width;
        cfg.g_h = height;


        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP8) {
            LOGGER_WARNING(vc->log, "Using VP8 codec for encoder");

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS
            rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg,
                                    VPX_CODEC_USE_FRAME_THREADING | VPX_CODEC_USE_OUTPUT_PARTITION);
#else
            rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg,
                                    VPX_CODEC_USE_FRAME_THREADING);
#endif
        } else {
            LOGGER_WARNING(vc->log, "Using VP9 codec for encoder");
            rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE_VP9, &cfg, VPX_CODEC_USE_FRAME_THREADING);
        }

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
            return -1;
        }


#if 0
        rc = vpx_codec_control(&new_c, VP8E_SET_ENABLEAUTOALTREF, 0);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "(b)Failed to set encoder VP8E_SET_ENABLEAUTOALTREF setting: %s value=%d",
                         vpx_codec_err_to_string(rc),
                         (int)1);
            vpx_codec_destroy(&new_c);
            return -1;
        } else {
            LOGGER_WARNING(vc->log, "(b)set encoder VP8E_SET_ENABLEAUTOALTREF setting: %s value=%d", vpx_codec_err_to_string(rc),
                           (int)1);
        }

#endif

        /*
        encoder->Control(VP8E_SET_ARNR_MAXFRAMES, 7);
        encoder->Control(VP8E_SET_ARNR_STRENGTH, 5);
        encoder->Control(VP8E_SET_ARNR_TYPE, 3);
        */

#if 1
        /*
        Codec control function to set Max data rate for Intra frames.
        This value controls additional clamping on the maximum size of a keyframe. It is expressed as a percentage of the average per-frame bitrate, with the special (and default) value 0 meaning unlimited, or no additional clamping beyond the codec's built-in algorithm.
        For example, to allocate no more than 4.5 frames worth of bitrate to a keyframe, set this to 450.
        Supported in codecs: VP8, VP9
        */
        uint32_t rc_max_intra_target = MaxIntraTarget(600);
        rc_max_intra_target = 102;
        rc = vpx_codec_control(&new_c, VP8E_SET_MAX_INTRA_BITRATE_PCT, rc_max_intra_target);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "(b)Failed to set encoder VP8E_SET_MAX_INTRA_BITRATE_PCT setting: %s value=%d",
                         vpx_codec_err_to_string(rc),
                         (int)rc_max_intra_target);
            vpx_codec_destroy(&new_c);
            return -1;
        } else {
            LOGGER_WARNING(vc->log, "(b)set encoder VP8E_SET_MAX_INTRA_BITRATE_PCT setting: %s value=%d",
                           vpx_codec_err_to_string(rc),
                           (int)rc_max_intra_target);
        }

#endif

        /*
        Codec control function to set max data rate for Inter frames.
        This value controls additional clamping on the maximum size of an inter frame. It is expressed as a percentage of the average per-frame bitrate, with the special (and default) value 0 meaning unlimited, or no additional clamping beyond the codec's built-in algorithm.
        For example, to allow no more than 4.5 frames worth of bitrate to an inter frame, set this to 450.
        Supported in codecs: VP9

        VP9E_SET_MAX_INTER_BITRATE_PCT
        */


        int cpu_used_value = vc->video_encoder_cpu_used;

        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
            if (cpu_used_value < -8) {
                cpu_used_value = -8;
            } else if (cpu_used_value > 8) {
                cpu_used_value = 8; // set to default (fastest) value
            }
        }

        rc = vpx_codec_control(&new_c, VP8E_SET_CPUUSED, cpu_used_value);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "(b)Failed to set encoder VP8E_SET_CPUUSED setting: %s value=%d", vpx_codec_err_to_string(rc),
                         (int)cpu_used_value);
            vpx_codec_destroy(&new_c);
            return -1;
        } else {
            LOGGER_WARNING(vc->log, "(b)set encoder VP8E_SET_CPUUSED setting: %s value=%d", vpx_codec_err_to_string(rc),
                           (int)cpu_used_value);
        }

        vc->video_encoder_cpu_used = cpu_used_value;
        vc->video_encoder_cpu_used_prev = cpu_used_value;

#ifdef VIDEO_CODEC_ENCODER_USE_FRAGMENTS

        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP8) {
            rc = vpx_codec_control(&new_c, VP8E_SET_TOKEN_PARTITIONS, VIDEO_CODEC_FRAGMENT_VPX_NUMS);

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(vc->log, "Failed to set encoder token partitions: %s", vpx_codec_err_to_string(rc));
            }
        }

#endif

        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
            rc = vpx_codec_control(&new_c, VP9E_SET_TILE_COLUMNS, VIDEO__VP9E_SET_TILE_COLUMNS);

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(&new_c);
                return -1;
            }

            rc = vpx_codec_control(&new_c, VP9E_SET_TILE_ROWS, VIDEO__VP9E_SET_TILE_ROWS);

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(&new_c);
                return -1;
            }
        }

#if 0

        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP9) {
            if (1 == 2) {
                LOGGER_WARNING(vc->log, "setting VP9 lossless video quality: ON");

                rc = vpx_codec_control(&new_c, VP9E_SET_LOSSLESS, 1);

                if (rc != VPX_CODEC_OK) {
                    LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                    vpx_codec_destroy(&new_c);
                    return -1;
                }
            } else {
                LOGGER_WARNING(vc->log, "setting VP9 lossless video quality: OFF");

                rc = vpx_codec_control(&new_c, VP9E_SET_LOSSLESS, 0);

                if (rc != VPX_CODEC_OK) {
                    LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                    vpx_codec_destroy(&new_c);
                    return -1;
                }
            }
        }

#endif


        vpx_codec_destroy(vc->encoder);
        memcpy(vc->encoder, &new_c, sizeof(new_c));
    }

    return 0;
}


int vc_reconfigure_encoder_bitrate_only(VCSession *vc, uint32_t bit_rate)
{
    if (!vc) {
        return -1;
    }

    vpx_codec_enc_cfg_t cfg2 = *vc->encoder->config.enc;
    vpx_codec_err_t rc;

    if (cfg2.rc_target_bitrate == bit_rate) {
        return 0; /* Nothing changed */
    }

    /* bit rate changed */
    LOGGER_WARNING(vc->log, "bitrate change (2) from: %u to: %u", (uint32_t)(cfg2.rc_target_bitrate / 1000),
                   (uint32_t)(bit_rate / 1000));

    cfg2.rc_target_bitrate = bit_rate;
    rc = vpx_codec_enc_config_set(vc->encoder, &cfg2);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(vc->log, "Failed to set (2) encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}


