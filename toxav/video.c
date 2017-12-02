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

#define MAX_DECODE_TIME_US 0 /* Good quality encode. */
#define VIDEO_DECODE_BUFFER_SIZE 20

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

    if (!(vc->vbuf_raw = rb_new(VIDEO_DECODE_BUFFER_SIZE))) {
        goto BASE_CLEANUP;
    }

    rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE, NULL, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP;
    }

    /* Set encoder to some initial values
     */
    vpx_codec_enc_cfg_t  cfg;
    rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to get config: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }

    cfg.rc_target_bitrate = 500000;
    cfg.g_w = 800;
    cfg.g_h = 600;
    cfg.g_pass = VPX_RC_ONE_PASS;
    /* TODO(mannol): If we set error resilience the app will crash due to bug in vp8.
       Perhaps vp9 has solved it?*/
#if 0
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
#endif
    cfg.g_lag_in_frames = 0;
    cfg.kf_min_dist = 0;
    cfg.kf_max_dist = 48;
    cfg.kf_mode = VPX_KF_AUTO;

    rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }

    rc = vpx_codec_control(vc->encoder, VP8E_SET_CPUUSED, 8);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    }

    vc->linfts = current_time_monotonic();
    vc->lcfd = 60;
    vc->vcb.first = cb;
    vc->vcb.second = cb_data;
    vc->friend_number = friend_number;
    vc->av = av;
    vc->log = log;

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


void vc_iterate(VCSession *vc)
{
    if (!vc)
    {
        return;
    }

    struct RTPMessage *p;

    vpx_codec_err_t rc;

    pthread_mutex_lock(vc->queue_mutex);
    uint8_t data_type;

    uint32_t full_data_len;

    if (rb_read((RingBuffer *)vc->vbuf_raw, (void **)&p, &data_type))
    {
        pthread_mutex_unlock(vc->queue_mutex);

        const struct RTPHeaderV3 *header_v3 = (void *)&(p->header);
        LOGGER_WARNING(vc->log, "vc_iterate:00:pv=%d", (uint8_t)header_v3->protocol_version);
        if ( ((uint8_t)header_v3->protocol_version) == 3)
        {
            LOGGER_WARNING(vc->log, "vc_iterate:001:full_data_len=%d", (int)full_data_len);
            full_data_len = header_v3->data_length_full;
        }
        else
        {
            LOGGER_WARNING(vc->log, "vc_iterate:002");
            full_data_len = p->len;
        }

        LOGGER_WARNING(vc->log, "vc_iterate: rb_read p->len=%d data_type=%d", (int)full_data_len, (int)data_type);
        LOGGER_WARNING(vc->log, "vc_iterate: rb_read rb size=%d", (int)rb_size((RingBuffer *)vc->vbuf_raw));

        rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, NULL, MAX_DECODE_TIME_US);
        if (rc != VPX_CODEC_OK)
        {
            if (rc == 5) // Bitstream not supported by this decoder
            {
                LOGGER_WARNING(vc->log, "Switching VPX Decoder");
                // video_switch_decoder(vc);
            }
            else if (rc == 7)
            {
                LOGGER_WARNING(vc->log, "Corrupt frame detected: data size=%d start byte=%d end byte=%d",
                    (int)full_data_len, (int)p->data[0], (int)p->data[full_data_len - 1]);
            }
            else
            {
                LOGGER_ERROR(vc->log, "Error decoding video: %d %s", (int)rc, vpx_codec_err_to_string(rc));
            }

            rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, NULL, MAX_DECODE_TIME_US);
			if (rc != 5)
			{
				LOGGER_ERROR(vc->log, "There is still an error decoding video: %d %s", (int)rc, vpx_codec_err_to_string(rc));
			}
        }

        if (rc == VPX_CODEC_OK)
        {
            free(p);

            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = vpx_codec_get_frame(vc->decoder, &iter);
            LOGGER_WARNING(vc->log, "vpx_codec_get_frame=%p", dest);


            if (dest != NULL)
	        {
                if (vc->vcb.first) {
                    vc->vcb.first(vc->av, vc->friend_number, dest->d_w, dest->d_h,
                                  (const uint8_t *)dest->planes[0], (const uint8_t *)dest->planes[1], (const uint8_t *)dest->planes[2],
                                  dest->stride[0], dest->stride[1], dest->stride[2], vc->vcb.second);
                }
				// vpx_img_free(dest);
	        }

            /* Play decoded images */
            for (; dest; dest = vpx_codec_get_frame(vc->decoder, &iter))
			{
                if (vc->vcb.first)
				{
                    vc->vcb.first(vc->av, vc->friend_number, dest->d_w, dest->d_h,
                                  (const uint8_t *)dest->planes[0], (const uint8_t *)dest->planes[1], (const uint8_t *)dest->planes[2],
                                  dest->stride[0], dest->stride[1], dest->stride[2], vc->vcb.second);
                }
                // vpx_img_free(dest);
            }
        }
        else
        {
            free(p);
        }

        return;
    }
    else
    {
        // no frame data available
        // LOGGER_WARNING(vc->log, "Error decoding video: rb_read");
    }

    pthread_mutex_unlock(vc->queue_mutex);
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

    // const struct RTPHeader *header = (void *)&(msg->header);
    const struct RTPHeaderV3 *header_v3 = (void *)&(msg->header);

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

    if (( ((uint8_t)header_v3->protocol_version) == 3) &&
        ( ((uint8_t)header_v3->pt) == (rtp_TypeVideo % 128))
        )
    {
        LOGGER_WARNING(vc->log, "rb_write msg->len=%d b0=%d b1=%d", (int)msg->len, (int)msg->data[0], (int)msg->data[1]);
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, (uint8_t)header_v3->is_keyframe));
    }
    else
    {
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, 0));
    }


    /* Calculate time it took for peer to send us this frame */
    uint32_t t_lcfd = current_time_monotonic() - vc->linfts;
    vc->lcfd = t_lcfd > 100 ? vc->lcfd : t_lcfd;
    vc->linfts = current_time_monotonic();

    pthread_mutex_unlock(vc->queue_mutex);

    return 0;
}

int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height)
{
    if (!vc) {
        return -1;
    }

    vpx_codec_enc_cfg_t cfg = *vc->encoder->config.enc;
    vpx_codec_err_t rc;

    if (cfg.rc_target_bitrate == bit_rate && cfg.g_w == width && cfg.g_h == height) {
        return 0; /* Nothing changed */
    }

    if (cfg.g_w == width && cfg.g_h == height) {
        /* Only bit rate changed */
        cfg.rc_target_bitrate = bit_rate;

        rc = vpx_codec_enc_config_set(vc->encoder, &cfg);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            return -1;
        }
    } else {
        /* Resolution is changed, must reinitialize encoder since libvpx v1.4 doesn't support
         * reconfiguring encoder to use resolutions greater than initially set.
         */

        LOGGER_DEBUG(vc->log, "Have to reinitialize vpx encoder on session %p", vc);

        cfg.rc_target_bitrate = bit_rate;
        cfg.g_w = width;
        cfg.g_h = height;

        vpx_codec_ctx_t new_c;

        rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
            return -1;
        }

        rc = vpx_codec_control(&new_c, VP8E_SET_CPUUSED, 8);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(&new_c);
            return -1;
        }

        vpx_codec_destroy(vc->encoder);
        memcpy(vc->encoder, &new_c, sizeof(new_c));
    }

    return 0;
}
