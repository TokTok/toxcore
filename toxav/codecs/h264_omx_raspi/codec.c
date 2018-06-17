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

/*
 * Copyright © 2013 Tuomas Jormola <tj@solitudo.net> <http://solitudo.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <http://www.apache.org/licenses/LICENSE-2.0>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Short intro about this program:
 *
 * `rpi-encode-yuv` reads raw YUV frame data from `stdin`, encodes the stream
 * using the VideoCore hardware encoder using H.264 codec and emits the H.264
 * stream to `stdout`.
 *
 *     $ ./rpi-encode-yuv <test.yuv >test.h264
 *
 * `rpi-encode-yuv` uses the `video_encode` component. Uncompressed raw YUV frame
 * data is read from `stdin` and passed to the buffer of input port of
 * `video_encode`. H.264 encoded video is read from the buffer of `video_encode`
 * output port and dumped to `stdout`.
 *
 * Please see README.mdwn for more detailed description of this
 * OpenMAX IL demos for Raspberry Pi bundle.
 *
 */

#include "audio.h"
#include "video.h"
#include "msi.h"
#include "ring_buffer.h"
#include "rtp.h"
#include "tox_generic.h"
#include "codecs/toxav_codecs.h"




// ---------------------------------
// ---------------------------------
// ---------------------------------



#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <bcm_host.h>

#include <interface/vcos/vcos_semaphore.h>
#include <interface/vmcs_host/vchost.h>

#include <IL/OMX_Core.h>
#include <IL/OMX_Component.h>
#include <IL/OMX_Video.h>
#include <IL/OMX_Broadcom.h>

static int frame_in = 0;
static int frame_out = 0;

static uint16_t fake_sequnum = 0;

static void shutdown_h264_omx_raspi_encoder(VCSession *vc);
static void startup_h264_omx_raspi_encoder(VCSession *vc, uint16_t width, uint16_t height,
        uint32_t bit_rate);

// Hard coded parameters
#define VIDEO_WIDTH                     640
#define VIDEO_HEIGHT                    480
#define VIDEO_FRAMERATE                 25
#define VIDEO_BITRATE                   1500000 // 1500kbit initial value

// Dunno where this is originally stolen from...
#define OMX_INIT_STRUCTURE(a) \
    memset(&(a), 0, sizeof(a)); \
    (a).nSize = sizeof(a); \
    (a).nVersion.nVersion = OMX_VERSION; \
    (a).nVersion.s.nVersionMajor = OMX_VERSION_MAJOR; \
    (a).nVersion.s.nVersionMinor = OMX_VERSION_MINOR; \
    (a).nVersion.s.nRevision = OMX_VERSION_REVISION; \
    (a).nVersion.s.nStep = OMX_VERSION_STEP

// Global variable used by the signal handler and encoding loop
static int want_quit = 0;

// Our application context passed around
// the main routine and callback handlers
struct OMXContext {
    OMX_HANDLETYPE encoder;
    OMX_BUFFERHEADERTYPE *encoder_ppBuffer_in;
    OMX_BUFFERHEADERTYPE *encoder_ppBuffer_out;
    int encoder_input_buffer_needed;
    int encoder_output_buffer_available;
    int flushed;
    VCOS_SEMAPHORE_T handler_lock;
};

// I420 frame stuff
typedef struct {
    int width;
    int height;
    size_t size;
    int buf_stride;
    int buf_slice_height;
    int buf_extra_padding;
    int p_offset[3];
    int p_stride[3];
} i420_frame_info;

// Stolen from video-info.c of gstreamer-plugins-base
#define ROUND_UP_2(num) (((num)+1)&~1)
#define ROUND_UP_4(num) (((num)+3)&~3)
static void get_i420_frame_info(int width, int height, int buf_stride, int buf_slice_height, i420_frame_info *info)
{
    info->p_stride[0] = ROUND_UP_4(width);
    info->p_stride[1] = ROUND_UP_4(ROUND_UP_2(width) / 2);
    info->p_stride[2] = info->p_stride[1];
    info->p_offset[0] = 0;
    info->p_offset[1] = info->p_stride[0] * ROUND_UP_2(height);
    info->p_offset[2] = info->p_offset[1] + info->p_stride[1] * (ROUND_UP_2(height) / 2);
    info->size = info->p_offset[2] + info->p_stride[2] * (ROUND_UP_2(height) / 2);
    info->width = width;
    info->height = height;
    info->buf_stride = buf_stride;
    info->buf_slice_height = buf_slice_height;
    info->buf_extra_padding =
        buf_slice_height >= 0
        ? ((buf_slice_height && (height % buf_slice_height))
           ? (buf_slice_height - (height % buf_slice_height))
           : 0)
        : -1;
}


static void die(const char *message, ...)
{
#if 0
    va_list args;
    char str[1024];
    memset(str, 0, sizeof(str));
    va_start(args, message);
    vsnprintf(str, sizeof(str), message, args);
    va_end(args);
    // say(str);
    exit(1);
#endif
}

static void omx_die(OMX_ERRORTYPE error, const char *message, ...)
{
#if 0
    va_list args;
    char str[1024];
    char *e;
    memset(str, 0, sizeof(str));
    va_start(args, message);
    vsnprintf(str, sizeof(str), message, args);
    va_end(args);

    switch (error) {
        case OMX_ErrorNone:
            e = "no error";
            break;

        case OMX_ErrorBadParameter:
            e = "bad parameter";
            break;

        case OMX_ErrorIncorrectStateOperation:
            e = "invalid state while trying to perform command";
            break;

        case OMX_ErrorIncorrectStateTransition:
            e = "unallowed state transition";
            break;

        case OMX_ErrorInsufficientResources:
            e = "insufficient resource";
            break;

        case OMX_ErrorBadPortIndex:
            e = "bad port index, i.e. incorrect port";
            break;

        case OMX_ErrorHardware:
            e = "hardware error";
            break;

        /* That's all I've encountered during hacking so let's not bother with the rest... */
        default:
            e = "(no description)";
    }

    die("OMX error: %s: 0x%08x %s", str, error, e);
#endif
}

static void dump_frame_info(const char *message, const i420_frame_info *info)
{
}

static void dump_event(OMX_HANDLETYPE hComponent, OMX_EVENTTYPE eEvent, OMX_U32 nData1, OMX_U32 nData2)
{
}

static const char *dump_compression_format(OMX_VIDEO_CODINGTYPE c)
{
}

static const char *dump_color_format(OMX_COLOR_FORMATTYPE c)
{
}

static void dump_portdef(OMX_PARAM_PORTDEFINITIONTYPE *portdef)
{
}

static void dump_port(OMX_HANDLETYPE hComponent, OMX_U32 nPortIndex, OMX_BOOL dumpformats)
{
}

// Some busy loops to verify we're running in order
static void block_until_state_changed(OMX_HANDLETYPE hComponent, OMX_STATETYPE wanted_eState)
{
    OMX_STATETYPE eState;
    int i = 0;

    while (i++ == 0 || eState != wanted_eState) {
        OMX_GetState(hComponent, &eState);

        if (eState != wanted_eState) {
            usleep(10000);
        }
    }
}

static void block_until_port_changed(OMX_HANDLETYPE hComponent, OMX_U32 nPortIndex, OMX_BOOL bEnabled)
{
    OMX_ERRORTYPE r;
    OMX_PARAM_PORTDEFINITIONTYPE portdef;
    OMX_INIT_STRUCTURE(portdef);
    portdef.nPortIndex = nPortIndex;
    OMX_U32 i = 0;

    while (i++ == 0 || portdef.bEnabled != bEnabled) {
        if ((r = OMX_GetParameter(hComponent, OMX_IndexParamPortDefinition, &portdef)) != OMX_ErrorNone) {
            omx_die(r, "Failed to get port definition");
        }

        if (portdef.bEnabled != bEnabled) {
            usleep(10000);
        }
    }
}

static void block_until_flushed(struct OMXContext *ctx)
{
    int quit;

    while (!quit) {
        vcos_semaphore_wait(&ctx->handler_lock);

        if (ctx->flushed) {
            ctx->flushed = 0;
            quit = 1;
        }

        vcos_semaphore_post(&ctx->handler_lock);

        if (!quit) {
            usleep(10000);
        }
    }
}

static void init_component_handle(
    const char *name,
    OMX_HANDLETYPE *hComponent,
    OMX_PTR pAppData,
    OMX_CALLBACKTYPE *callbacks)
{
    OMX_ERRORTYPE r;
    char fullname[32];

    // Get handle
    memset(fullname, 0, sizeof(fullname));
    strcat(fullname, "OMX.broadcom.");
    strncat(fullname, name, strlen(fullname) - 1);
    // say("Initializing component %s", fullname);

    if ((r = OMX_GetHandle(hComponent, fullname, pAppData, callbacks)) != OMX_ErrorNone) {
        omx_die(r, "Failed to get handle for component %s", fullname);
    }

    // Disable ports
    OMX_INDEXTYPE types[] = {
        OMX_IndexParamAudioInit,
        OMX_IndexParamVideoInit,
        OMX_IndexParamImageInit,
        OMX_IndexParamOtherInit
    };
    OMX_PORT_PARAM_TYPE ports;
    OMX_INIT_STRUCTURE(ports);
    OMX_GetParameter(*hComponent, OMX_IndexParamVideoInit, &ports);

    int i;

    for (i = 0; i < 4; i++) {
        if (OMX_GetParameter(*hComponent, types[i], &ports) == OMX_ErrorNone) {
            OMX_U32 nPortIndex;

            for (nPortIndex = ports.nStartPortNumber; nPortIndex < ports.nStartPortNumber + ports.nPorts; nPortIndex++) {
                // say("Disabling port %d of component %s", nPortIndex, fullname);

                if ((r = OMX_SendCommand(*hComponent, OMX_CommandPortDisable, nPortIndex, NULL)) != OMX_ErrorNone) {
                    omx_die(r, "Failed to disable port %d of component %s", nPortIndex, fullname);
                }

                block_until_port_changed(*hComponent, nPortIndex, OMX_FALSE);
            }
        }
    }
}

// OMX calls this handler for all the events it emits
static OMX_ERRORTYPE event_handler(
    OMX_HANDLETYPE hComponent,
    OMX_PTR pAppData,
    OMX_EVENTTYPE eEvent,
    OMX_U32 nData1,
    OMX_U32 nData2,
    OMX_PTR pEventData)
{

    dump_event(hComponent, eEvent, nData1, nData2);

    struct OMXContext *ctx = (struct OMXContext *)pAppData;

    switch (eEvent) {
        case OMX_EventCmdComplete:
            vcos_semaphore_wait(&ctx->handler_lock);

            if (nData1 == OMX_CommandFlush) {
                ctx->flushed = 1;
            }

            vcos_semaphore_post(&ctx->handler_lock);
            break;

        case OMX_EventError:
            omx_die(nData1, "error event received");
            break;

        default:
            break;
    }

    return OMX_ErrorNone;
}

// Called by OMX when the encoder component requires
// the input buffer to be filled with YUV video data
static OMX_ERRORTYPE empty_input_buffer_done_handler(
    OMX_HANDLETYPE hComponent,
    OMX_PTR pAppData,
    OMX_BUFFERHEADERTYPE *pBuffer)
{
    struct OMXContext *ctx = ((struct OMXContext *)pAppData);
    vcos_semaphore_wait(&ctx->handler_lock);
    // say("?!? empty_input_buffer_done\n");
    // The main loop can now fill the buffer from input file
    ctx->encoder_input_buffer_needed = 1;
    vcos_semaphore_post(&ctx->handler_lock);
    return OMX_ErrorNone;
}

// Called by OMX when the encoder component has filled
// the output buffer with H.264 encoded video data
static OMX_ERRORTYPE fill_output_buffer_done_handler(
    OMX_HANDLETYPE hComponent,
    OMX_PTR pAppData,
    OMX_BUFFERHEADERTYPE *pBuffer)
{

    struct OMXContext *ctx = ((struct OMXContext *)pAppData);
    vcos_semaphore_wait(&ctx->handler_lock);
    // The main loop can now flush the buffer to output file
    ctx->encoder_output_buffer_available = 1;
    vcos_semaphore_post(&ctx->handler_lock);
    return OMX_ErrorNone;
}



static void
print_def(OMX_PARAM_PORTDEFINITIONTYPE def)
{
    printf("Port %u: %s %u/%u %u %u %s,%s,%s %ux%u %ux%u @%u %u\n",
           def.nPortIndex,
           def.eDir == OMX_DirInput ? "in" : "out",
           def.nBufferCountActual,
           def.nBufferCountMin,
           def.nBufferSize,
           def.nBufferAlignment,
           def.bEnabled ? "enabled" : "disabled",
           def.bPopulated ? "populated" : "not pop.",
           def.bBuffersContiguous ? "contig." : "not cont.",
           def.format.video.nFrameWidth,
           def.format.video.nFrameHeight,
           def.format.video.nStride,
           def.format.video.nSliceHeight,
           def.format.video.xFramerate, def.format.video.eColorFormat);
}

// ---------------------------------
// ---------------------------------
// ---------------------------------
// ---------------------------------


static i420_frame_info frame_info;
static i420_frame_info buf_info;



static void h264_omx_set_bool(VCSession *vc, OMX_INDEXTYPE i, bool value)
{
    OMX_CONFIG_PORTBOOLEANTYPE bool_type;
    bool_type.nSize = sizeof(bool_type);
    bool_type.nVersion.nVersion = OMX_VERSION;
    bool_type.nPortIndex = 201;

    if (value == true) {
        bool_type.bEnabled = OMX_TRUE;
    } else {
        bool_type.bEnabled = OMX_FALSE;
    }

    LOGGER_ERROR(vc->log, "OMX: setting bool param to: %d", (int)value);

    if (OMX_SetParameter(vc->omx_ctx->encoder, i, &bool_type) != OMX_ErrorNone) {
        LOGGER_ERROR(vc->log, "OMX: failed to param!");
    }
}


static void h264_omx_set_u32(VCSession *vc, OMX_INDEXTYPE i, uint32_t value)
{

    OMX_PARAM_U32TYPE p;
    OMX_INIT_STRUCTURE(p);
    p.nPortIndex = 201;
    p.nU32 = value;

    LOGGER_ERROR(vc->log, "OMX: setting uint32 param to: %d", (int)value);

    if (OMX_SetParameter(vc->omx_ctx->encoder, i, &p) != OMX_ErrorNone) {
        LOGGER_ERROR(vc->log, "OMX: failed to param!");
    }
}

void h264_omx_raspi_force_i_frame(Logger *log, VCSession *vc)
{

#if 0
    OMX_CONFIG_PORTBOOLEANTYPE bool_type;
    bool_type.nSize = sizeof(bool_type);
    bool_type.nVersion.nVersion = OMX_VERSION;
    bool_type.nPortIndex = 201;
    bool_type.bEnabled = OMX_TRUE;

    int r;

    if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexConfigBrcmVideoRequestIFrame, &bool_type)) != OMX_ErrorNone) {
        LOGGER_ERROR(log, "Failed to request I-FRAME output port 201");
    }

#endif

    h264_omx_set_bool(vc, OMX_IndexConfigBrcmVideoRequestIFrame, true);
}

static void startup_h264_omx_raspi_encoder(VCSession *vc, uint16_t width, uint16_t height,
        uint32_t bit_rate)
{
    LOGGER_WARNING(vc->log, "H264_OMX_PI:new");

    bcm_host_init();

    OMX_ERRORTYPE r;

    if ((r = OMX_Init()) != OMX_ErrorNone) {
        omx_die(r, "OMX initalization failed");
    }


    // Init context

    vc->omx_ctx = calloc(1, sizeof(struct OMXContext));

    if (vcos_semaphore_create(&vc->omx_ctx->handler_lock, "handler_lock", 1) != VCOS_SUCCESS) {
        die("Failed to create handler lock semaphore");
    }


    // Init component handles
    OMX_CALLBACKTYPE callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.EventHandler    = event_handler;
    callbacks.EmptyBufferDone = empty_input_buffer_done_handler;
    callbacks.FillBufferDone  = fill_output_buffer_done_handler;

    init_component_handle("video_encode", &vc->omx_ctx->encoder, vc->omx_ctx, &callbacks);

    LOGGER_ERROR(vc->log, "H264_OMX_PI:Configuring encoder...");

    // say("Configuring encoder...");

    // say("Default port definition for encoder input port 200");
    dump_port(vc->omx_ctx->encoder, 200, OMX_TRUE);
    // say("Default port definition for encoder output port 201");
    dump_port(vc->omx_ctx->encoder, 201, OMX_TRUE);

    OMX_PARAM_PORTDEFINITIONTYPE encoder_portdef;
    OMX_INIT_STRUCTURE(encoder_portdef);
    encoder_portdef.nPortIndex = 200;

    if ((r = OMX_GetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to get port definition for encoder input port 200");
    }

    encoder_portdef.format.video.nFrameWidth  = width;
    encoder_portdef.format.video.nFrameHeight = height;
    encoder_portdef.format.video.xFramerate   = VIDEO_FRAMERATE << 16;
    // Stolen from gstomxvideodec.c of gst-omx
    encoder_portdef.format.video.nStride      = (encoder_portdef.format.video.nFrameWidth + encoder_portdef.nBufferAlignment
            - 1) & (~(encoder_portdef.nBufferAlignment - 1));
    encoder_portdef.format.video.eColorFormat = OMX_COLOR_FormatYUV420PackedPlanar;

    if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to set port definition for encoder input port 200");
    }

    // Copy encoder input port definition as basis encoder output port definition
    OMX_INIT_STRUCTURE(encoder_portdef);
    encoder_portdef.nPortIndex = 200;

    if ((r = OMX_GetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to get port definition for encoder input port 200");
    }

    encoder_portdef.nPortIndex = 201;
    encoder_portdef.format.video.eColorFormat = OMX_COLOR_FormatUnused;
    encoder_portdef.format.video.eCompressionFormat = OMX_VIDEO_CodingAVC;
    // Which one is effective, this or the configuration just below?
    encoder_portdef.format.video.nBitrate     = bit_rate;

    if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to set port definition for encoder output port 201");
    }

    // Configure bitrate
    OMX_VIDEO_PARAM_BITRATETYPE bitrate;
    OMX_INIT_STRUCTURE(bitrate);
    bitrate.eControlRate = OMX_Video_ControlRateVariable;
    bitrate.nTargetBitrate = encoder_portdef.format.video.nBitrate;
    bitrate.nPortIndex = 201;

    if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexParamVideoBitrate, &bitrate)) != OMX_ErrorNone) {
        omx_die(r, "Failed to set bitrate for encoder output port 201");
    }

    // Configure format
    OMX_VIDEO_PARAM_PORTFORMATTYPE format;
    OMX_INIT_STRUCTURE(format);
    format.nPortIndex = 201;
    format.eCompressionFormat = OMX_VIDEO_CodingAVC;

    if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexParamVideoPortFormat, &format)) != OMX_ErrorNone) {
        omx_die(r, "Failed to set video format for encoder output port 201");
    }


    h264_omx_set_u32(vc, OMX_IndexConfigBrcmVideoIntraPeriod, 50);
    h264_omx_set_bool(vc, OMX_IndexParamBrcmVideoAVCInlineHeaderEnable, true);
    h264_omx_set_u32(vc, OMX_IndexParamBrcmVideoEncodeMaxQuant, 48); // max. 48
    h264_omx_set_u32(vc, OMX_IndexParamBrcmVideoEncodeMinQuant, 15); // min. 10


    // Switch components to idle state
    // say("Switching state of the encoder component to idle...");

    if ((r = OMX_SendCommand(vc->omx_ctx->encoder, OMX_CommandStateSet, OMX_StateIdle, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to switch state of the encoder component to idle");
    }

    block_until_state_changed(vc->omx_ctx->encoder, OMX_StateIdle);

    // Enable ports
    // say("Enabling ports...");

    if ((r = OMX_SendCommand(vc->omx_ctx->encoder, OMX_CommandPortEnable, 200, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to enable encoder input port 200");
    }

    block_until_port_changed(vc->omx_ctx->encoder, 200, OMX_TRUE);

    if ((r = OMX_SendCommand(vc->omx_ctx->encoder, OMX_CommandPortEnable, 201, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to enable encoder output port 201");
    }

    block_until_port_changed(vc->omx_ctx->encoder, 201, OMX_TRUE);

    // Allocate encoder input and output buffers
    // say("Allocating buffers...");
    OMX_INIT_STRUCTURE(encoder_portdef);
    encoder_portdef.nPortIndex = 200;

    if ((r = OMX_GetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to get port definition for encoder input port 200");
    }

    if ((r = OMX_AllocateBuffer(vc->omx_ctx->encoder, &vc->omx_ctx->encoder_ppBuffer_in, 200, NULL,
                                encoder_portdef.nBufferSize)) != OMX_ErrorNone) {
        omx_die(r, "Failed to allocate buffer for encoder input port 200");
    }

    OMX_INIT_STRUCTURE(encoder_portdef);
    encoder_portdef.nPortIndex = 201;

    if ((r = OMX_GetParameter(vc->omx_ctx->encoder, OMX_IndexParamPortDefinition, &encoder_portdef)) != OMX_ErrorNone) {
        omx_die(r, "Failed to get port definition for encoder output port 201");
    }

    if ((r = OMX_AllocateBuffer(vc->omx_ctx->encoder, &vc->omx_ctx->encoder_ppBuffer_out, 201, NULL,
                                encoder_portdef.nBufferSize)) != OMX_ErrorNone) {
        omx_die(r, "Failed to allocate buffer for encoder output port 201");
    }

    // Switch state of the components prior to starting
    // the video capture and encoding loop
    // say("Switching state of the encoder component to executing...");

    if ((r = OMX_SendCommand(vc->omx_ctx->encoder, OMX_CommandStateSet, OMX_StateExecuting, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to switch state of the encoder component to executing");
    }

    block_until_state_changed(vc->omx_ctx->encoder, OMX_StateExecuting);

    // say("Configured port definition for encoder input port 200");
    dump_port(vc->omx_ctx->encoder, 200, OMX_FALSE);
    // say("Configured port definition for encoder output port 201");
    dump_port(vc->omx_ctx->encoder, 201, OMX_FALSE);

    get_i420_frame_info(encoder_portdef.format.image.nFrameWidth, encoder_portdef.format.image.nFrameHeight,
                        encoder_portdef.format.image.nStride, encoder_portdef.format.video.nSliceHeight, &frame_info);
    get_i420_frame_info(frame_info.buf_stride, frame_info.buf_slice_height, -1, -1, &buf_info);

    // dump_frame_info("Destination frame", &frame_info);
    // dump_frame_info("Source buffer", &buf_info);

    if (vc->omx_ctx->encoder_ppBuffer_in->nAllocLen != buf_info.size) {
        die("Allocated encoder input port 200 buffer size %d doesn't equal to the expected buffer size %d",
            vc->omx_ctx->encoder_ppBuffer_in->nAllocLen, buf_info.size);
    }

    vc->omx_ctx->encoder_input_buffer_needed = 1;

    // say("vc_new_h264_omx finished!");

}

VCSession *vc_new_h264_omx_raspi(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb,
                                 void *cb_data,
                                 VCSession *vc)
{
    startup_h264_omx_raspi_encoder(vc, VIDEO_WIDTH, VIDEO_HEIGHT, VIDEO_BITRATE);
    // ---------



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

int vc_reconfigure_encoder_h264_omx_raspi(Logger *log, VCSession *vc, uint32_t bit_rate,
        uint16_t width, uint16_t height,
        int16_t kf_max_dist)
{

    if (!vc) {
        return -1;
    }

    if ((vc->h264_enc_width == width) &&
            (vc->h264_enc_height == height) &&
            (vc->h264_enc_bitrate != bit_rate) &&
            (kf_max_dist != -2)) {
        // only bit rate changed

        // LOGGER_ERROR(log, "OMX set bitrate to %d", (int)(bit_rate / 1000));

        // Configure bitrate
        OMX_VIDEO_CONFIG_BITRATETYPE bitrate;
        OMX_INIT_STRUCTURE(bitrate);
        bitrate.nPortIndex = 201;
        bitrate.nEncodeBitrate = bit_rate;

        int r;

        if ((r = OMX_SetParameter(vc->omx_ctx->encoder, OMX_IndexConfigVideoBitrate, &bitrate)) != OMX_ErrorNone) {
            // omx_die(r, "Failed to set bitrate for encoder output port 201");
            LOGGER_ERROR(log, "Failed to set bitrate for encoder output port 201");
        }

        vc->h264_enc_bitrate = bit_rate;

    } else {
        if ((vc->h264_enc_width != width) ||
                (vc->h264_enc_height != height) ||
                (vc->h264_enc_bitrate != bit_rate) ||
                (kf_max_dist == -2)
           ) {
            // input image size changed

            vc->h264_enc_width = width;
            vc->h264_enc_height = height;
            vc->h264_enc_bitrate = bit_rate;


            // full shutdown
            shutdown_h264_omx_raspi_encoder(vc);
            // startup again
            startup_h264_omx_raspi_encoder(vc, width, height, bit_rate);
        }
    }

    return 0;
}

void decode_frame_h264_omx_raspi(VCSession *vc, Messenger *m, uint8_t skip_video_flag, uint64_t *a_r_timestamp,
                                 uint64_t *a_l_timestamp,
                                 uint64_t *v_r_timestamp, uint64_t *v_l_timestamp,
                                 const struct RTPHeader *header_v3,
                                 struct RTPMessage *p, vpx_codec_err_t rc,
                                 uint32_t full_data_len,
                                 uint8_t *ret_value)
{


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

    LOGGER_DEBUG(vc->log, "H264:decoder:full_data_len=%d p->data=%p\n", (int)full_data_len, p->data);

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

}

uint32_t encode_frame_h264_omx_raspi(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                                     const uint8_t *y,
                                     const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                                     uint64_t *video_frame_record_timestamp,
                                     int vpx_encode_flags,
                                     x264_nal_t **nal,
                                     int *i_frame_size)
{
    // LOGGER_WARNING(av->m->log, "H264_OMX_PI:encode frame");

    // get sessions object ---
    VCSession *vc = call->video.second;
    // get sessions object ---

    OMX_ERRORTYPE r = 0;
    struct OMXContext *ctx = vc->omx_ctx;

    // LOGGER_WARNING(av->m->log, "!!! vc_encode_frame_h264_omx ctx=%p", ctx);

    // input buffer should be available with our synchronous scheme
    assert(ctx->encoder_input_buffer_needed);
    // output buffer should be empty
    assert(!ctx->encoder_output_buffer_available);

    // Dump new YUV frame into OMX
    {
        // LOGGER_WARNING(av->m->log, "!!! sending new frame to omx\n");
        //memset(ctx.encoder_ppBuffer_in->pBuffer, 0, ctx.encoder_ppBuffer_in->nAllocLen);

        size_t input_total_read = 0;

        // Pack Y, U, and V plane spans read from input file to the buffer
        const void *yuv[3] = {y, u, v};
        int i;

        for (i = 0; i < 3; i++) {

            int plane_span_y = ROUND_UP_2(height);
            int plane_span_uv = plane_span_y / 2;
            int want_read = frame_info.p_stride[i] * (i == 0 ? plane_span_y : plane_span_uv);

            memcpy(
                ctx->encoder_ppBuffer_in->pBuffer + buf_info.p_offset[i],
                yuv[i],
                want_read);

            input_total_read += want_read;
        }

        ctx->encoder_ppBuffer_in->nOffset = 0;
        ctx->encoder_ppBuffer_in->nFilledLen = (buf_info.size - frame_info.size) + input_total_read;

        ctx->encoder_input_buffer_needed = 0;

        if ((r = OMX_EmptyThisBuffer(ctx->encoder, ctx->encoder_ppBuffer_in)) != OMX_ErrorNone) {
            omx_die(r, "Failed to request emptying of the input buffer on encoder input port 200");
        }
    }

    return 0;

}

uint32_t send_frames_h264_omx_raspi(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                                    const uint8_t *y,
                                    const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                                    uint64_t *video_frame_record_timestamp,
                                    int vpx_encode_flags,
                                    x264_nal_t **nal,
                                    int *i_frame_size,
                                    TOXAV_ERR_SEND_FRAME *rc)
{
    // LOGGER_WARNING(av->m->log, "H264_OMX_PI:send frames");

    // get sessions object ---
    VCSession *vc = call->video.second;
    // get sessions object ---

    OMX_ERRORTYPE r = 0;
    struct OMXContext *ctx = vc->omx_ctx;

    bool wait_for_eof = true;

    while (wait_for_eof) {
        // Request a new buffer form the encoder
        if ((r = OMX_FillThisBuffer(ctx->encoder, ctx->encoder_ppBuffer_out)) != OMX_ErrorNone) {
            omx_die(r, "Failed to request filling of the output buffer on encoder output port 201");
        }

        bool wait_for_buffer = true;

        while (wait_for_buffer) {
            vcos_semaphore_wait(&ctx->handler_lock);
            wait_for_buffer = !ctx->encoder_output_buffer_available;
            vcos_semaphore_post(&ctx->handler_lock);

            if (wait_for_buffer) {
                usleep(10);
            } else {
                ctx->encoder_output_buffer_available = 0;
            }
        }

        if (ctx->encoder_ppBuffer_out->nFlags & OMX_BUFFERFLAG_ENDOFFRAME) {
            wait_for_eof = false;
        }

        // TODO: use the record timestamp that was actually used for this frame
        *video_frame_record_timestamp = current_time_monotonic();

        const int keyframe = ctx->encoder_ppBuffer_out->nFlags & OMX_BUFFERFLAG_SYNCFRAME;
        const int spspps = ctx->encoder_ppBuffer_out->nFlags & OMX_BUFFERFLAG_CODECCONFIG;
        const int eof  = ctx->encoder_ppBuffer_out->nFlags & OMX_BUFFERFLAG_ENDOFFRAME;
        size_t frame_bytes = ctx->encoder_ppBuffer_out->nFilledLen;

        //LOGGER_WARNING(av->m->log, "!   omx h264 packet: keyframe=%d sps/pps=%d eof=%d size=%d\n", keyframe, spspps, eof,
        //               frame_bytes);
        // LOGGER_WARNING(av->m->log, "H264_OMX_PI:packet");


        // prepend a faked Annex-B header
        uint8_t *buf = calloc(1, (size_t)(frame_bytes + 4));
        memcpy((buf + 4), ctx->encoder_ppBuffer_out->pBuffer + ctx->encoder_ppBuffer_out->nOffset, frame_bytes);

        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 1;

        int res = rtp_send_data
                  (
                      call->video.first,
                      (const uint8_t *)buf,
                      (uint32_t)(frame_bytes + 4),
                      keyframe,
                      *video_frame_record_timestamp,
                      (int32_t)0,
                      TOXAV_ENCODER_CODEC_USED_H264,
                      call->video_bit_rate,
                      av->m->log
                  );

        if (vc->show_own_video == 0) {
            free(buf);
        } else {

            if (buf) {

                // push outgoing video frame into incoming video frame queue
                // dirty hack to construct an RTPMessage struct

                LOGGER_DEBUG(av->m->log, "OMX:own_video:malloc size=%d", (int)sizeof(uint16_t)
                             + sizeof(struct RTPHeader)
                             + (frame_bytes + 4));

                struct RTPMessage *msg2 = (struct RTPMessage *)calloc(1, sizeof(uint16_t)
                                          + sizeof(struct RTPHeader)
                                          + (frame_bytes + 4) + 200000); // HINT: +200000 is for safety reason, otherwise something crashes. fix me!!!

                if (msg2) {

                    memcpy(msg2->data, (const uint8_t *)buf, (frame_bytes + 4));

                    msg2->len = (frame_bytes + 4);

                    struct RTPHeader *header = & (msg2->header);
                    header->ve = 2;  // this is unused in toxav
                    header->pe = 0;
                    header->xe = 0;
                    header->cc = 0;
                    header->ma = 0;
                    header->pt = rtp_TypeVideo % 128;
                    header->sequnum = fake_sequnum;
                    header->timestamp = current_time_monotonic();
                    header->ssrc = 0;
                    header->offset_lower = 0;
                    header->data_length_lower = (frame_bytes + 4);
                    header->flags = RTP_LARGE_FRAME | RTP_ENCODER_IS_H264;
                    header->frame_record_timestamp = (*video_frame_record_timestamp);
                    header->fragment_num = 0;
                    header->real_frame_num = fake_sequnum; // not yet used
                    header->encoder_bit_rate_used = call->video_bit_rate;
                    uint16_t length_safe = (uint16_t)(frame_bytes + 4);

                    if ((frame_bytes + 4) > UINT16_MAX) {
                        length_safe = UINT16_MAX;
                    }

                    header->data_length_lower = length_safe;
                    header->data_length_full = (frame_bytes + 4); // without header
                    header->received_length_full = header->data_length_full;
                    header->offset_lower = 0;
                    header->offset_full = 0;

                    fake_sequnum++;

                    LOGGER_DEBUG(av->m->log, "OMX:own_video:video frame:1len=%d", (int)header->data_length_full);
                    LOGGER_DEBUG(av->m->log, "OMX:own_video:video frame:2len=%d", (int)msg2->header.data_length_full);


                    if ((vc) && (vc->vbuf_raw)) {
                        free(rb_write((RingBuffer *)vc->vbuf_raw, msg2,
                                      (uint64_t)header->flags));
                    } else {
                        free(msg2);
                    }

                }

                free(buf);
            }
        }


        if (res < 0) {
            LOGGER_WARNING(av->m->log, "Could not send video frame: %s", strerror(errno));
            *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            return 1;
        }
    }

    return 0;
}

static void shutdown_h264_omx_raspi_encoder(VCSession *vc)
{
    //**// vc->omx_ctx->encoder_input_buffer_needed = 0;

    struct OMXContext ctx;
    memcpy(&ctx, vc->omx_ctx, sizeof(struct OMXContext));

    OMX_ERRORTYPE r;

    LOGGER_WARNING(vc->log, "H264_OMX_PI:kill");

    // Flush the buffers on each component
    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandFlush, 200, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to flush buffers of encoder input port 200");
    }

    block_until_flushed(&ctx);

    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandFlush, 201, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to flush buffers of encoder output port 201");
    }

    block_until_flushed(&ctx);

    // Disable all the ports
    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandPortDisable, 200, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to disable encoder input port 200");
    }

    block_until_port_changed(ctx.encoder, 200, OMX_FALSE);

    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandPortDisable, 201, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to disable encoder output port 201");
    }

    block_until_port_changed(ctx.encoder, 201, OMX_FALSE);

    // Free all the buffers
    if ((r = OMX_FreeBuffer(ctx.encoder, 200, ctx.encoder_ppBuffer_in)) != OMX_ErrorNone) {
        omx_die(r, "Failed to free buffer for encoder input port 200");
    }

    if ((r = OMX_FreeBuffer(ctx.encoder, 201, ctx.encoder_ppBuffer_out)) != OMX_ErrorNone) {
        omx_die(r, "Failed to free buffer for encoder output port 201");
    }

    // Transition all the components to idle and then to loaded states
    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandStateSet, OMX_StateIdle, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to switch state of the encoder component to idle");
    }

    block_until_state_changed(ctx.encoder, OMX_StateIdle);

    if ((r = OMX_SendCommand(ctx.encoder, OMX_CommandStateSet, OMX_StateLoaded, NULL)) != OMX_ErrorNone) {
        omx_die(r, "Failed to switch state of the encoder component to loaded");
    }

    block_until_state_changed(ctx.encoder, OMX_StateLoaded);

    // Free the component handles
    if ((r = OMX_FreeHandle(ctx.encoder)) != OMX_ErrorNone) {
        omx_die(r, "Failed to free encoder component handle");
    }

    vcos_semaphore_delete(&ctx.handler_lock);

    if ((r = OMX_Deinit()) != OMX_ErrorNone) {
        omx_die(r, "OMX de-initalization failed");
    }
}


void vc_kill_h264_omx_raspi(VCSession *vc)
{
    shutdown_h264_omx_raspi_encoder(vc);

    // -- DECODER --
    avcodec_free_context(&vc->h264_decoder);

}


/*  --- DO NOT USE --- */
void vc_restart_h264_decoder(VCSession *vc, Logger *log)
{
    // -- SHUTDOWN --
    avcodec_free_context(&vc->h264_decoder);

    // -- STARTUP --

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

    if (avcodec_open2(vc->h264_decoder, codec, NULL) < 0) {
        LOGGER_WARNING(log, "could not open codec H264 on decoder");
    }

    vc->h264_decoder->refcounted_frames = 0;

}

