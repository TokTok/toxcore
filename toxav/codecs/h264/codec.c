/*
 * Copyright © 2018 zoff@zoff.cc and mail@strfry.org
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

#include "audio.h"
#include "video.h"
#include "msi.h"
#include "ring_buffer.h"
#include "rtp.h"
#include "tox_generic.h"
#include "codecs/toxav_codecs.h"


VCSession *vc_new_h264(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data,
                       VCSession *vc)
{

    // ENCODER -------
    x264_param_t param;

    if (x264_param_default_preset(&param, "ultrafast", "zerolatency") < 0) {
        // goto fail;
    }

    /* Configure non-default params */
    // param.i_bitdepth = 8;
    param.i_csp = X264_CSP_I420;
    param.i_width  = 1920;
    param.i_height = 1080;
    vc->h264_enc_width = param.i_width;
    vc->h264_enc_height = param.i_height;
    param.i_threads = 3;
    param.b_deterministic = 0;
    param.b_intra_refresh = 1;
    // param.b_open_gop = 20;
    param.i_keyint_max = VIDEO_MAX_KF_H264;
    // param.rc.i_rc_method = X264_RC_CRF; // X264_RC_ABR;
    // param.i_nal_hrd = X264_NAL_HRD_CBR;

    param.b_vfr_input = 1; /* VFR input.  If 1, use timebase and timestamps for ratecontrol purposes.
                            * If 0, use fps only. */
    param.i_timebase_num = 1;       // 1 ms = timebase units = (1/1000)s
    param.i_timebase_den = 1000;   // 1 ms = timebase units = (1/1000)s
    param.b_repeat_headers = 1;
    param.b_annexb = 1;

    param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
    param.rc.i_vbv_buffer_size = VIDEO_BITRATE_INITIAL_VALUE_H264 * VIDEO_BUF_FACTOR_H264;
    param.rc.i_vbv_max_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1;
    // param.rc.i_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * VIDEO_BITRATE_FACTOR_H264;

    vc->h264_enc_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000;

    param.rc.b_stat_read = 0;
    param.rc.b_stat_write = 1;
    x264_param_apply_fastfirstpass(&param);

    /* Apply profile restrictions. */
    if (x264_param_apply_profile(&param,
                                 x264_param_profile_str) < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
        // goto fail;
    }

    if (x264_picture_alloc(&(vc->h264_in_pic), param.i_csp, param.i_width, param.i_height) < 0) {
        // goto fail;
    }

    // vc->h264_in_pic.img.plane[0] --> Y
    // vc->h264_in_pic.img.plane[1] --> U
    // vc->h264_in_pic.img.plane[2] --> V

    vc->h264_encoder = x264_encoder_open(&param);

//    goto good;

//fail:
//    vc->h264_encoder = NULL;

//good:

    // ENCODER -------


    // DECODER -------
    AVCodec *codec;
    vc->h264_decoder = NULL;

    avcodec_register_all();

    codec = avcodec_find_decoder(AV_CODEC_ID_H264);


    if (!codec) {
        LOGGER_WARNING(log, "codec not found H264 on decoder");
    }

    vc->h264_decoder = avcodec_alloc_context3(codec);

    if (codec->capabilities & CODEC_CAP_TRUNCATED) {
        vc->h264_decoder->flags |= CODEC_FLAG_TRUNCATED; /* we do not send complete frames */
    }

    vc->h264_decoder->refcounted_frames = 0;
    /*   When AVCodecContext.refcounted_frames is set to 0, the returned
    *             reference belongs to the decoder and is valid only until the
    *             next call to this function or until closing or flushing the
    *             decoder. The caller may not write to it.
    */

    if (avcodec_open2(vc->h264_decoder, codec, NULL) < 0) {
        LOGGER_WARNING(log, "could not open codec H264 on decoder");
    }

    vc->h264_decoder->refcounted_frames = 0;
    /*   When AVCodecContext.refcounted_frames is set to 0, the returned
    *             reference belongs to the decoder and is valid only until the
    *             next call to this function or until closing or flushing the
    *             decoder. The caller may not write to it.
    */

    // DECODER -------

    return vc;
}

int vc_reconfigure_encoder_h264(Logger *log, VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height,
                                int16_t kf_max_dist)
{
    if (!vc) {
        return -1;
    }

    if ((vc->h264_enc_width == width) ||
            (vc->h264_enc_height == height) ||
            (vc->h264_enc_bitrate != bit_rate) ||
            (kf_max_dist != -2)
       ) {
        // only bit rate changed
        if (vc->h264_encoder) {
            x264_param_t param;

            x264_encoder_parameters(vc->h264_encoder, &param);

            LOGGER_ERROR(log, "vc_reconfigure_encoder_h264:vb=%d [bitrate only]", (int)(bit_rate / 1000));

            param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
            param.rc.i_vbv_buffer_size = (bit_rate / 1000) * VIDEO_BUF_FACTOR_H264;
            param.rc.i_vbv_max_bitrate = (bit_rate / 1000) * 1;

            // param.rc.i_bitrate = (bit_rate / 1000) * VIDEO_BITRATE_FACTOR_H264;
            vc->h264_enc_bitrate = bit_rate;

            int  res =   x264_encoder_reconfig(vc->h264_encoder, &param);
        }
    } else {
        if ((vc->h264_enc_width != width) ||
                (vc->h264_enc_height != height) ||
                (vc->h264_enc_bitrate != bit_rate) ||
                (kf_max_dist == -2)
           ) {
            // input image size changed

            x264_param_t param;

            if (x264_param_default_preset(&param, "ultrafast", "zerolatency") < 0) {
                // goto fail;
            }


            /* Configure non-default params */
            // param.i_bitdepth = 8;
            param.i_csp = X264_CSP_I420;
            param.i_width  = width;
            param.i_height = height;
            vc->h264_enc_width = param.i_width;
            vc->h264_enc_height = param.i_height;
            param.i_threads = 3;
            param.b_deterministic = 0;
            param.b_intra_refresh = 1;
            // param.b_open_gop = 20;
            param.i_keyint_max = VIDEO_MAX_KF_H264;
            // param.rc.i_rc_method = X264_RC_ABR;

            param.b_vfr_input = 1; /* VFR input.  If 1, use timebase and timestamps for ratecontrol purposes.
                            * If 0, use fps only. */
            param.i_timebase_num = 1;       // 1 ms = timebase units = (1/1000)s
            param.i_timebase_den = 1000;   // 1 ms = timebase units = (1/1000)s
            param.b_repeat_headers = 1;
            param.b_annexb = 1;

            LOGGER_ERROR(log, "vc_reconfigure_encoder_h264:vb=%d", (int)(bit_rate / 1000));

            param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
            param.rc.i_vbv_buffer_size = (bit_rate / 1000) * VIDEO_BUF_FACTOR_H264;
            param.rc.i_vbv_max_bitrate = (bit_rate / 1000) * 1;

            // param.rc.i_bitrate = (bit_rate / 1000) * VIDEO_BITRATE_FACTOR_H264;
            vc->h264_enc_bitrate = bit_rate;

            param.rc.b_stat_read = 0;
            param.rc.b_stat_write = 1;
            x264_param_apply_fastfirstpass(&param);

            /* Apply profile restrictions. */
            if (x264_param_apply_profile(&param,
                                         x264_param_profile_str) < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
                // goto fail;
            }

            LOGGER_DEBUG(log, "H264: reconfigure encoder:001: w:%d h:%d w_new:%d h_new:%d BR:%d\n",
                         vc->h264_enc_width,
                         vc->h264_enc_height,
                         width,
                         height,
                         (int)bit_rate);

            // free old stuff ---------
            x264_encoder_close(vc->h264_encoder);
            x264_picture_clean(&(vc->h264_in_pic));
            // free old stuff ---------

            LOGGER_DEBUG(log, "H264: reconfigure encoder:002\n");

            // alloc with new values -------
            if (x264_picture_alloc(&(vc->h264_in_pic), param.i_csp, param.i_width, param.i_height) < 0) {
                // goto fail;
            }

            LOGGER_DEBUG(log, "H264: reconfigure encoder:003\n");

            vc->h264_encoder = x264_encoder_open(&param);
            // alloc with new values -------


            LOGGER_DEBUG(log, "H264: reconfigure encoder:004\n");

        }
    }

    return 0;
}

void vc_kill_h264(VCSession *vc)
{
    x264_encoder_close(vc->h264_encoder);
    x264_picture_clean(&(vc->h264_in_pic));
    avcodec_free_context(&vc->h264_decoder);
}


