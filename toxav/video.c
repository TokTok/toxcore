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

#include "tox_generic.h"

#include "codecs/toxav_codecs.h"

#include <assert.h>
#include <stdlib.h>


VCSession *vc_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data)
{
    VCSession *vc = (VCSession *)calloc(sizeof(VCSession), 1);

    if (!vc) {
        LOGGER_WARNING(log, "Allocation failed! Application might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(vc->queue_mutex) != 0) {
        LOGGER_WARNING(log, "Failed to create recursive mutex!");
        free(vc);
        return NULL;
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
    vc->video_encoder_coded_used = TOXAV_ENCODER_CODEC_USED_VP8; // DEBUG: H264 !!
    vc->video_encoder_coded_used_prev = vc->video_encoder_coded_used;
    vc->video_keyframe_method = TOXAV_ENCODER_KF_METHOD_NORMAL;
    vc->video_keyframe_method_prev = vc->video_keyframe_method;
    vc->video_decoder_error_concealment = VIDEO__VP8_DECODER_ERROR_CONCEALMENT;
    vc->video_decoder_error_concealment_prev = vc->video_decoder_error_concealment;
    vc->video_decoder_codec_used = TOXAV_ENCODER_CODEC_USED_VP8; // DEBUG: H264 !!
    // options ---


    if (!(vc->vbuf_raw = rb_new(VIDEO_RINGBUFFER_BUFFER_ELEMENTS))) {
        goto BASE_CLEANUP;
    }

    // HINT: tell client what encoder and decoder are in use now -----------
    if (av->call_comm_cb.first) {

        TOXAV_CALL_COMM_INFO cmi;
        cmi = TOXAV_CALL_COMM_DECODER_IN_USE_VP8;

        if (vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_H264) {
            cmi = TOXAV_CALL_COMM_DECODER_IN_USE_H264;
        }

        av->call_comm_cb.first(av, friend_number, cmi, 0, av->call_comm_cb.second);


        cmi = TOXAV_CALL_COMM_ENCODER_IN_USE_VP8;

        if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_H264) {
            cmi = TOXAV_CALL_COMM_ENCODER_IN_USE_H264;
        }

        av->call_comm_cb.first(av, friend_number, cmi, 0, av->call_comm_cb.second);
    }

    // HINT: tell client what encoder and decoder are in use now -----------

    // HINT: initialize the H264 encoder
    vc = vc_new_h264(log, av, friend_number, cb, cb_data, vc);

    // HINT: initialize VP8 encoder
    return vc_new_vpx(log, av, friend_number, cb, cb_data, vc);

BASE_CLEANUP:
    pthread_mutex_destroy(vc->queue_mutex);
    rb_kill((RingBuffer *)vc->vbuf_raw);
    free(vc);
    return NULL;
}


void vc_kill_vpx(VCSession *vc)
{
    int jk;

    for (jk = 0; jk < vc->fragment_buf_counter; jk++) {
        free(vc->vpx_frames_buf_list[jk]);
        vc->vpx_frames_buf_list[jk] = NULL;
    }

    vc->fragment_buf_counter = 0;

    vpx_codec_destroy(vc->encoder);
    vpx_codec_destroy(vc->decoder);
}


void vc_kill_h264(VCSession *vc)
{
    x264_encoder_close(vc->h264_encoder);
    x264_picture_clean(&(vc->h264_in_pic));
    avcodec_free_context(&vc->h264_decoder);
}

void vc_kill(VCSession *vc)
{
    if (!vc) {
        return;
    }

    vc_kill_h264(vc);
    vc_kill_vpx(vc);

    void *p;
    uint64_t dummy;

    while (rb_read((RingBuffer *)vc->vbuf_raw, &p, &dummy)) {
        free(p);
    }

    rb_kill((RingBuffer *)vc->vbuf_raw);

    pthread_mutex_destroy(vc->queue_mutex);

    LOGGER_DEBUG(vc->log, "Terminated video handler: %p", vc);
    free(vc);
}

void video_switch_decoder_vpx(VCSession *vc, TOXAV_ENCODER_CODEC_USED_VALUE decoder_to_use)
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

    if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_VP9) {

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


    if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_VP9) {
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

void video_switch_decoder(VCSession *vc, TOXAV_ENCODER_CODEC_USED_VALUE decoder_to_use)
{
    if (vc->video_decoder_codec_used != (int32_t)decoder_to_use) {
        if ((decoder_to_use == TOXAV_ENCODER_CODEC_USED_VP8)
                || (decoder_to_use == TOXAV_ENCODER_CODEC_USED_VP9)
                || (decoder_to_use == TOXAV_ENCODER_CODEC_USED_H264)) {

            // ** DISABLED ** // video_switch_decoder_vpx(vc, decoder_to_use);
            vc->video_decoder_codec_used = decoder_to_use;
            LOGGER_ERROR(vc->log, "**switching DECODER to **:%d",
                         (int)vc->video_decoder_codec_used);


            if (vc->av) {
                if (vc->av->call_comm_cb.first) {

                    TOXAV_CALL_COMM_INFO cmi;
                    cmi = TOXAV_CALL_COMM_DECODER_IN_USE_VP8;

                    if (vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_H264) {
                        cmi = TOXAV_CALL_COMM_DECODER_IN_USE_H264;
                    }

                    vc->av->call_comm_cb.first(vc->av, vc->friend_number,
                                               cmi, 0, vc->av->call_comm_cb.second);

                }
            }


        }
    }
}


/* --- VIDEO DECODING happens here --- */
/* --- VIDEO DECODING happens here --- */
/* --- VIDEO DECODING happens here --- */
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

    uint64_t frame_flags;
    uint8_t data_type;
    uint8_t h264_encoded_video_frame;

    uint32_t full_data_len;


    if (rb_read((RingBuffer *)vc->vbuf_raw, (void **)&p, &frame_flags)) {
        const struct RTPHeader *header_v3_0 = (void *) & (p->header);

        data_type = (uint8_t)((frame_flags & RTP_KEY_FRAME) != 0);
        h264_encoded_video_frame = (uint8_t)((frame_flags & RTP_ENCODER_IS_H264) != 0);


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

            // if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264) {
            // rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);
            // }

            free(p);
            pthread_mutex_unlock(vc->queue_mutex);
            return 0;
        }

        if ((int32_t)header_v3_0->sequnum != (int32_t)(vc->last_seen_fragment_seqnum + 1)) {
            int32_t missing_frames_count = (int32_t)header_v3_0->sequnum -
                                           (int32_t)(vc->last_seen_fragment_seqnum + 1);
            LOGGER_DEBUG(vc->log, "missing %d video frames (m1)", (int)missing_frames_count);

            if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264) {
                rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);
            }

            if (missing_frames_count > 5) {
                if ((vc->last_requested_keyframe_ts + VIDEO_MIN_REQUEST_KEYFRAME_INTERVAL_MS_FOR_NF)
                        < current_time_monotonic()) {
                    uint32_t pkg_buf_len = 2;
                    uint8_t pkg_buf[pkg_buf_len];
                    pkg_buf[0] = PACKET_TOXAV_COMM_CHANNEL;
                    pkg_buf[1] = PACKET_TOXAV_COMM_CHANNEL_REQUEST_KEYFRAME;

                    if (-1 == send_custom_lossless_packet(m, vc->friend_number, pkg_buf, pkg_buf_len)) {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_TOXAV_COMM_CHANNEL:RTP send failed (2)");
                    } else {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_TOXAV_COMM_CHANNEL:RTP Sent. (2)");
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

                if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264) {
                    rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);
                }

                pthread_mutex_unlock(vc->queue_mutex);
                return 0;
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

                    if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264) {
                        rc = vpx_codec_decode(vc->decoder, NULL, 0, NULL, VPX_DL_REALTIME);
                    }

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

        // LOGGER_DEBUG(vc->log, "vc_iterate: rb_read p->len=%d data_type=%d", (int)full_data_len, (int)data_type);
        // LOGGER_DEBUG(vc->log, "vc_iterate: rb_read rb size=%d", (int)rb_size((RingBuffer *)vc->vbuf_raw));

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
                    pkg_buf[0] = PACKET_TOXAV_COMM_CHANNEL;
                    pkg_buf[1] = PACKET_TOXAV_COMM_CHANNEL_REQUEST_KEYFRAME;

                    if (-1 == send_custom_lossless_packet(m, vc->friend_number, pkg_buf, pkg_buf_len)) {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_TOXAV_COMM_CHANNEL:RTP send failed");
                    } else {
                        LOGGER_WARNING(vc->log,
                                       "PACKET_TOXAV_COMM_CHANNEL:RTP Sent.");
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




        LOGGER_DEBUG(vc->log, "h264_encoded_video_frame=%d", (int)h264_encoded_video_frame);

        if ((vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264)
                && (h264_encoded_video_frame == 1)) {
            LOGGER_DEBUG(vc->log, "h264_encoded_video_frame:AA");
            video_switch_decoder(vc, TOXAV_ENCODER_CODEC_USED_H264);
        } else if ((vc->video_decoder_codec_used == TOXAV_ENCODER_CODEC_USED_H264)
                   && (h264_encoded_video_frame == 0)) {
            LOGGER_DEBUG(vc->log, "h264_encoded_video_frame:BB");
            video_switch_decoder(vc, TOXAV_ENCODER_CODEC_USED_VP8);
        }






        if (vc->video_decoder_codec_used != TOXAV_ENCODER_CODEC_USED_H264) {



            // LOGGER_ERROR(vc->log, "DEC:VP8------------");




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
                    // LOGGER_ERROR(vc->log, "Error decoding video: VPX_CODEC_CORRUPT_FRAME or VPX_CODEC_UNSUP_BITSTREAM");
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








        } else {

            // HINT: H264 decode ----------------


            // LOGGER_ERROR(vc->log, "DEC:H264------------");


            /*
             For decoding, call avcodec_send_packet() to give the decoder raw
                  compressed data in an AVPacket.


                  For decoding, call avcodec_receive_frame(). On success, it will return
                  an AVFrame containing uncompressed audio or video data.


             *   Repeat this call until it returns AVERROR(EAGAIN) or an error. The
             *   AVERROR(EAGAIN) return value means that new input data is required to
             *   return new output. In this case, continue with sending input. For each
             *   input frame/packet, the codec will typically return 1 output frame/packet,
             *   but it can also be 0 or more than 1.

             */

            AVPacket *compr_data;
            compr_data = av_packet_alloc();

#if 0
            compr_data->pts = AV_NOPTS_VALUE;
            compr_data->dts = AV_NOPTS_VALUE;

            compr_data->duration = 0;
            compr_data->post = -1;
#endif

            // HINT: dirty hack to add FF_INPUT_BUFFER_PADDING_SIZE bytes!! ----------
            uint8_t *tmp_buf = calloc(1, full_data_len + FF_INPUT_BUFFER_PADDING_SIZE);
            memcpy(tmp_buf, p->data, full_data_len);
            // HINT: dirty hack to add FF_INPUT_BUFFER_PADDING_SIZE bytes!! ----------

            compr_data->data = tmp_buf; // p->data;
            compr_data->size = (int)full_data_len; // hmm, "int" again

            avcodec_send_packet(vc->h264_decoder, compr_data);


            int ret_ = 0;

            while (ret_ >= 0) {

                AVFrame *frame = av_frame_alloc();
                ret_ = avcodec_receive_frame(vc->h264_decoder, frame);

                // LOGGER_ERROR(vc->log, "H264:decoder:ret_=%d\n", (int)ret_);


                if (ret_ == AVERROR(EAGAIN) || ret_ == AVERROR_EOF) {
                    // error
                    break;
                } else if (ret_ < 0) {
                    // Error during decoding
                    break;
                } else if (ret_ == 0) {

                    // LOGGER_ERROR(vc->log, "H264:decoder:fnum=%d\n", (int)vc->h264_decoder->frame_number);
                    // LOGGER_ERROR(vc->log, "H264:decoder:linesize=%d\n", (int)frame->linesize[0]);
                    // LOGGER_ERROR(vc->log, "H264:decoder:w=%d\n", (int)frame->width);
                    // LOGGER_ERROR(vc->log, "H264:decoder:h=%d\n", (int)frame->height);

                    vc->vcb.first(vc->av, vc->friend_number, frame->width, frame->height,
                                  (const uint8_t *)frame->data[0],
                                  (const uint8_t *)frame->data[1],
                                  (const uint8_t *)frame->data[2],
                                  frame->linesize[0], frame->linesize[1],
                                  frame->linesize[2], vc->vcb.second);

                } else {
                    // some other error
                }

                av_frame_free(&frame);
            }

            av_packet_free(&compr_data);

            // HINT: dirty hack to add FF_INPUT_BUFFER_PADDING_SIZE bytes!! ----------
            free(tmp_buf);
            // HINT: dirty hack to add FF_INPUT_BUFFER_PADDING_SIZE bytes!! ----------

            free(p);

            // HINT: H264 decode ----------------

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

        LOGGER_DEBUG(vc->log, "VIDEO_incoming_bitrate=%d", (int)header->encoder_bit_rate_used);

        if (vc->incoming_video_bitrate_last_changed != header->encoder_bit_rate_used) {
            if (vc->av) {
                if (vc->av->call_comm_cb.first) {
                    vc->av->call_comm_cb.first(vc->av, vc->friend_number,
                                               TOXAV_CALL_COMM_DECODER_CURRENT_BITRATE,
                                               (int64_t)header->encoder_bit_rate_used,
                                               vc->av->call_comm_cb.second);
                }

            }

            vc->incoming_video_bitrate_last_changed = header->encoder_bit_rate_used;
        }

        // LOGGER_WARNING(vc->log, "rb_write msg->len=%d b0=%d b1=%d rb_size=%d", (int)msg->len, (int)msg->data[0], (int)msg->data[1], (int)rb_size((RingBuffer *)vc->vbuf_raw));
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, (uint64_t)header->flags));
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



int vc_reconfigure_encoder(Logger *log, VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height,
                           int16_t kf_max_dist)
{
    if (vc->video_encoder_coded_used == TOXAV_ENCODER_CODEC_USED_VP8) {
        return vc_reconfigure_encoder_vpx(log, vc, bit_rate, width, height, kf_max_dist);
    } else {
        return vc_reconfigure_encoder_h264(log, vc, bit_rate, width, height, kf_max_dist);
    }
}

