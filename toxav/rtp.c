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

#include "rtp.h"

#include "bwcontroller.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>


int handle_rtp_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object);


RTPSession *rtp_new(int payload_type, Messenger *m, uint32_t friendnumber,
                    BWController *bwc, void *cs,
                    int (*mcb)(void *, struct RTPMessage *))
{
    assert(mcb);
    assert(cs);
    assert(m);

    RTPSession *retu = (RTPSession *)calloc(1, sizeof(RTPSession));

    if (!retu) {
        LOGGER_WARNING(m->log, "Alloc failed! Program might misbehave!");
        return NULL;
    }

    if (payload_type == rtp_TypeVideo) {
        retu->ssrc = 0;
    } else {
        retu->ssrc = random_u32();
    }

    retu->payload_type = payload_type;

    retu->m = m;
    retu->friend_number = friendnumber;

    // set NULL just in case
    retu->mp = NULL;
    retu->first_packets_counter = 1;

    /* Also set payload type as prefix */

    retu->bwc = bwc;
    retu->cs = cs;
    retu->mcb = mcb;

    if (-1 == rtp_allow_receiving(retu)) {
        LOGGER_WARNING(m->log, "Failed to start rtp receiving mode");
        free(retu);
        return NULL;
    }

    return retu;
}

void rtp_kill(RTPSession *session)
{
    if (!session) {
        return;
    }

    LOGGER_DEBUG(session->m->log, "Terminated RTP session: %p", session);

    rtp_stop_receiving(session);

    RTPSessionV3 *session_v3 = (RTPSessionV3 *)session;

    LOGGER_DEBUG(session->m->log, "Terminated RTP session V3 work_buffer_list: %p", session_v3->work_buffer_list);

    if (session_v3->work_buffer_list) {
        LOGGER_DEBUG(session->m->log, "Terminated RTP session V3 next_free_entry: %d",
                     (int)session_v3->work_buffer_list->next_free_entry);

        if (session_v3->work_buffer_list->next_free_entry > 0) {
        }

        free(session_v3->work_buffer_list);
        session_v3->work_buffer_list = NULL;
    }

    free(session);
}

int rtp_allow_receiving(RTPSession *session)
{
    if (session == NULL) {
        return -1;
    }

    if (m_callback_rtp_packet(session->m, session->friend_number, session->payload_type,
                              handle_rtp_packet, session) == -1) {
        LOGGER_WARNING(session->m->log, "Failed to register rtp receive handler");
        return -1;
    }

    LOGGER_DEBUG(session->m->log, "Started receiving on session: %p", session);
    return 0;
}

int rtp_stop_receiving(RTPSession *session)
{
    if (session == NULL) {
        return -1;
    }

    m_callback_rtp_packet(session->m, session->friend_number, session->payload_type, NULL, NULL);

    LOGGER_DEBUG(session->m->log, "Stopped receiving on session: %p", session);
    return 0;
}


/*
 * input is raw vpx data. length_v3 is the length of the raw data
 * HINT: this function must be thread safe!
 */
int rtp_send_data(RTPSession *session, const uint8_t *data, uint32_t length_v3,
	uint64_t frame_record_timestamp, int32_t fragment_num, Logger *log)
{
    if (!session) {
        LOGGER_ERROR(log, "No session!");
        return -1;
    }

    // here the highest bits gets stripped anyway, no need to do keyframe bit magic here!
    uint16_t length = (uint16_t)length_v3;

    uint8_t is_keyframe = 0;
    uint8_t is_video_payload = 0;

    if (session->payload_type == rtp_TypeVideo) {
        is_video_payload = 1;
    }

    if (is_video_payload == 1) {
        // TOX RTP V3 --- hack to get frame type ---
        //
        // use the highest bit (bit 31) to spec. keyframe = 1 / no keyframe = 0
        // if length(31 bits) > 1FFFFFFF then use all bits for length
        // and assume its a keyframe (most likely is anyway)

        if (LOWER_31_BITS(length_v3) > 0x1FFFFFFF) {
            is_keyframe = 1;
        } else {
            is_keyframe = (length_v3 & (uint32_t)(1L << 31)) != 0; // 1-> is keyframe, 0-> no keyframe
            length_v3 = LOWER_31_BITS(length_v3);
        }

        // TOX RTP V3 --- hack to get frame type ---
    }

    VLA(uint8_t, rdata, length_v3 + sizeof(struct RTPHeader) + 1);
    memset(rdata, 0, SIZEOF_VLA(rdata));

    rdata[0] = session->payload_type;

    struct RTPHeader *header = (struct RTPHeader *)(rdata + 1);

    header->ve = 2; // protocol version
    header->pe = 0;
    header->xe = 0;
    header->cc = 0;

    header->ma = 0;
    header->pt = session->payload_type % 128;

    header->sequnum = net_htons(session->sequnum);

	if (is_video_payload == 1) {
		LOGGER_DEBUG(session->m->log, "RTP_SEND:seqnum=%ld length=%lld",
				(long)session->sequnum, (long long)length_v3);
	}

    // this can not work! putting a uint64_t into a uint32_t field in the header!
    header->timestamp = net_htonl(current_time_monotonic());
    // LOGGER_WARNING(session->m->log, "TT:1:%llu", current_time_monotonic());
    // LOGGER_WARNING(session->m->log, "TT:2:%llu", header->timestamp);
    // LOGGER_WARNING(session->m->log, "TT:2b:%llu", net_ntohl(header->timestamp));

    header->ssrc = net_htonl(session->ssrc);

    header->cpart = 0;
    header->tlen = net_htons(length);


// Zoff -- new stuff --

    struct RTPHeaderV3 *header_v3 = (struct RTPHeaderV3 *)header;

    header_v3->protocol_version = 3; // TOX RTP V3

    uint16_t length_safe = (uint16_t)(length_v3);

    if (length_v3 > UINT16_MAX) {
        length_safe = UINT16_MAX;
    }

    header_v3->data_length_lower = net_htons(length_safe);
    header_v3->data_length_full = net_htonl(length_v3); // without header
    header_v3->fragment_num = net_htonl(fragment_num);

    header_v3->offset_lower = net_htons((uint16_t)(0));
    header_v3->offset_full = net_htonl(0);

	header_v3->frame_record_timestamp = htonll(frame_record_timestamp);
    LOGGER_DEBUG(session->m->log, "TT:3:%llu", frame_record_timestamp);
    LOGGER_DEBUG(session->m->log, "TT:4:%llu", header_v3->frame_record_timestamp);
    LOGGER_DEBUG(session->m->log, "TT:4b:%llu", ntohll(header_v3->frame_record_timestamp));


    header_v3->is_keyframe = is_keyframe;
    // TODO: bigendian ??

// Zoff -- new stuff --



    if (MAX_CRYPTO_DATA_SIZE > (length_v3 + sizeof(struct RTPHeader) + 1)) {

        /**
         * The length is lesser than the maximum allowed length (including header)
         * Send the packet in single piece.
         */

        memcpy(rdata + 1 + sizeof(struct RTPHeader), data, length_v3);

        if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number, rdata, SIZEOF_VLA(rdata))) {
            LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s", SIZEOF_VLA(rdata), strerror(errno));
        }
    } else {

        /**
         * The length is greater than the maximum allowed length (including header)
         * Send the packet in multiple pieces.
         */

        uint32_t sent = 0;
        uint16_t piece = MAX_CRYPTO_DATA_SIZE - (sizeof(struct RTPHeader) + 1);

        while ((length_v3 - sent) + sizeof(struct RTPHeader) + 1 > MAX_CRYPTO_DATA_SIZE) {
            memcpy(rdata + 1 + sizeof(struct RTPHeader), data + sent, piece);

            if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number,
                                                 rdata, piece + sizeof(struct RTPHeader) + 1)) {
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s",
                               piece + sizeof(struct RTPHeader) + 1, strerror(errno));
            }

            sent += piece;
            header->cpart = net_htons((uint16_t)sent);

// Zoff -- new stuff --

            header_v3->offset_full = net_htonl(sent); // raw data offset, without any header
            // TODO: bigendian ??

// Zoff -- new stuff --

        }

        /* Send remaining */
        piece = length - sent;

        if (piece) {
            memcpy(rdata + 1 + sizeof(struct RTPHeader), data + sent, piece);

            if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number, rdata,
                                                 piece + sizeof(struct RTPHeader) + 1)) {
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s",
                               piece + sizeof(struct RTPHeader) + 1, strerror(errno));
            }
        }
    }

    session->sequnum++;
    return 0;
}


static bool chloss(const RTPSession *session, const struct RTPHeader *header)
{
    if (net_ntohl(header->timestamp) < session->rtimestamp) {
        uint16_t hosq, lost = 0;

        hosq = net_ntohs(header->sequnum);

        lost = (hosq > session->rsequnum) ?
               (session->rsequnum + 65535) - hosq :
               session->rsequnum - hosq;

        LOGGER_WARNING(session->m->log, "Lost packet");

        while (lost --) {
            bwc_add_lost(session->bwc , 0);
        }

        return true;
    }

    return false;
}

// allocate_len is including header!
static struct RTPMessage *new_message(size_t allocate_len, const uint8_t *data, uint16_t data_length)
{
    assert(allocate_len >= data_length);

    struct RTPMessage *msg = (struct RTPMessage *)calloc(sizeof(struct RTPMessage) + (allocate_len - sizeof(
                                 struct RTPHeader)), 1);

    msg->len = data_length - sizeof(struct RTPHeader); // result without header
    memcpy(&msg->header, data, data_length);

    // printf("XT:1v:%llu\n", (long long unsigned int)msg->header.sequnum);
    msg->header.sequnum = net_ntohs(msg->header.sequnum);
    // printf("XT:2v:%llu\n", (long long unsigned int)msg->header.sequnum);

    // printf("XT:1:%llu\n", (long long unsigned int)msg->header.timestamp);
    msg->header.timestamp = net_ntohl(msg->header.timestamp);
    // printf("XT:2:%llu\n", (long long unsigned int)msg->header.timestamp);
    msg->header.ssrc = net_ntohl(msg->header.ssrc);

    struct RTPHeaderV3 *header_v3 = (struct RTPHeaderV3 *) & (msg->header);
    // printf("XTB:1:%llu\n", (long long unsigned int)header_v3->frame_record_timestamp);
    header_v3->frame_record_timestamp = ntohll(header_v3->frame_record_timestamp);
    // printf("XTB:2:%llu\n", (long long unsigned int)header_v3->frame_record_timestamp);

    msg->header.cpart = net_ntohs(msg->header.cpart);
    msg->header.tlen = net_ntohs(msg->header.tlen); // result without header

    return msg;
}

//
// full message len incl. header, data pointer, length of this part without header
//
static struct RTPMessage *new_message_v3(size_t allocate_len, const uint8_t *data, uint16_t data_length,
        uint32_t offset, uint32_t full_data_length, uint8_t is_keyframe)
{
    // assert(allocate_len >= data_length);

    struct RTPMessage *msg = (
                                 struct RTPMessage *)calloc(1,
                                         sizeof(struct RTPMessage) + (allocate_len)
                                                           );

    msg->len = data_length - sizeof(struct RTPHeader); // without header
    memcpy(&msg->header, data, data_length);

    msg->header.sequnum = net_ntohs(msg->header.sequnum);
    msg->header.timestamp = net_ntohl(msg->header.timestamp);

    msg->header.ssrc = net_ntohl(msg->header.ssrc);

    msg->header.cpart = net_ntohs(msg->header.cpart);
    msg->header.tlen = net_ntohs(msg->header.tlen); // without header

    msg->header.pt = (rtp_TypeVideo % 128);

    struct RTPHeaderV3 *header_v3 = (struct RTPHeaderV3 *) & (msg->header);
    header_v3->data_length_full = full_data_length; // without header
    header_v3->offset_full = offset;
    header_v3->is_keyframe = is_keyframe;
    header_v3->protocol_version = 3;

    // printf("XTB:1:%llu\n", header_v3->frame_record_timestamp);
    header_v3->frame_record_timestamp = ntohll(header_v3->frame_record_timestamp);
    // printf("XTB:2:%llu\n", header_v3->frame_record_timestamp);

    // printf("XTB:1:%ld\n", (long)header_v3->fragment_num);
    header_v3->fragment_num = ntohl(header_v3->fragment_num);
    // printf("XTB:2:%ld\n", (long)header_v3->fragment_num);

    return msg;
}


static void move_slot(struct RTPWorkBufferList *wkbl, int8_t dst_slot, int8_t src_slot)
{
    memcpy(&(wkbl->work_buffer[dst_slot]), &(wkbl->work_buffer[src_slot]), sizeof(struct RTPWorkBuffer));
    wkbl->work_buffer[dst_slot].buf = wkbl->work_buffer[src_slot].buf;
    memset(&(wkbl->work_buffer[src_slot]), 0, sizeof(struct RTPWorkBuffer));
}


static int8_t get_slot(Logger *log, struct RTPWorkBufferList *wkbl, uint8_t is_keyframe,
                       const struct RTPHeaderV3 *header_v3, uint8_t is_multipart)
{
    int8_t result_slot = -1;    // -1 -> means drop oldest message
    // -2 -> means drop this frame

    if (is_multipart == 1) {
        int i;

        for (i = 0; i < wkbl->next_free_entry; i++) {
            if ((wkbl->work_buffer[i].sequnum == net_ntohs(header_v3->sequnum))
                    &&
                    (wkbl->work_buffer[i].timestamp == net_ntohl(header_v3->timestamp))) {
                return i;
            }
        }

        if (wkbl->next_free_entry < USED_RTP_WORKBUFFER_COUNT) {
            if ((wkbl->next_free_entry > 0)
                    && (wkbl->work_buffer[wkbl->next_free_entry - 1].timestamp > net_ntohl(header_v3->timestamp))) {
                LOGGER_DEBUG(log, "workbuffer:1a:timestamp too old");
                return -2;
            } else {
                // LOGGER_WARNING(log, "workbuffer:1b:timestamp prev=%d cur=%d", (int)wkbl->work_buffer[wkbl->next_free_entry - 1].timestamp , (int)net_ntohl(header_v3->timestamp));
                return wkbl->next_free_entry;
            }
        }
    } else {
        if (wkbl->next_free_entry < USED_RTP_WORKBUFFER_COUNT) {
            if ((wkbl->next_free_entry > 0)
                    && (wkbl->work_buffer[wkbl->next_free_entry - 1].timestamp > net_ntohl(header_v3->timestamp))) {
                LOGGER_DEBUG(log, "workbuffer:2:timestamp too old");
                return -2;
            } else {
                // LOGGER_WARNING(log, "workbuffer:2b:timestamp prev=%d cur=%d", (int)wkbl->work_buffer[wkbl->next_free_entry - 1].timestamp , (int)net_ntohl(header_v3->timestamp));
                return wkbl->next_free_entry;
            }
        }
    }

    if (wkbl->work_buffer[0].frame_type == video_frame_type_KEYFRAME) {
        if (is_keyframe == video_frame_type_NORMALFRAME) {
            if (wkbl->work_buffer[0].received_len < wkbl->work_buffer[0].data_len) {
                if ((wkbl->work_buffer[0].timestamp + VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS) > net_ntohl(header_v3->timestamp)) {
                    // if we are processing a keyframe and the current part does not belong to a keyframe
                    // keep the keyframe and drop the current data
                    LOGGER_DEBUG(log, "keep KEYFRAME in workbuffer");
                    result_slot = -2;
                }
            }
        }
    }

    return result_slot;
}


static struct RTPMessage *process_oldest_frame(Logger *log, struct RTPWorkBufferList *wkbl)
{
    if (wkbl->next_free_entry > 0) {
        // remove entry 0, and make RTPMessageV3 from it
        struct RTPMessage *m_new = (struct RTPMessage *)wkbl->work_buffer[0].buf;
        wkbl->work_buffer[0].buf = NULL;

        LOGGER_DEBUG(log, "process_oldest_frame:m_new->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0],
                     (int)m_new->data[1]);


        LOGGER_DEBUG(log, "process_oldest_frame:001a next_free_entry=%d", wkbl->next_free_entry);

        int i;

        for (i = 0; i < (wkbl->next_free_entry - 1); i++) {
            // move entry (i+1) into entry (i)
            move_slot(wkbl, i, i + 1);
        }

        wkbl->next_free_entry--;

        LOGGER_DEBUG(log, "process_oldest_frame:m_newX->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0],
                     (int)m_new->data[1]);
        LOGGER_DEBUG(log, "process_oldest_frame:001b next_free_entry=%d", wkbl->next_free_entry);

        return m_new;
    } else {
        return NULL;
    }
}

static struct RTPMessage *process_frame(Logger *log, struct RTPWorkBufferList *wkbl, int8_t slot)
{
    if ((wkbl->work_buffer[0].frame_type == video_frame_type_KEYFRAME) && (slot != 0)) {
        LOGGER_DEBUG(log, "process_frame:KEYFRAME waiting in slot 0");
        // there is a keyframe waiting in slot 0, dont use the current frame yet
        return NULL;
    }

    // remove entry, and make RTPMessageV3 from it
    struct RTPMessage *m_new = (struct RTPMessage *)wkbl->work_buffer[slot].buf;
    wkbl->work_buffer[slot].buf = NULL;

    LOGGER_DEBUG(log, "process_frame:m_new->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0], (int)m_new->data[1]);


    LOGGER_DEBUG(log, "process_frame:001a next_free_entry=%d", wkbl->next_free_entry);

    if (slot == (wkbl->next_free_entry - 1)) {
        memset(&(wkbl->work_buffer[slot]), 0, sizeof(struct RTPWorkBuffer));
        wkbl->next_free_entry--;
    } else {
        // move entries to fill the gap
        int i;

        for (i = slot; i < (wkbl->next_free_entry - 1); i++) {
            // move entry (i+1) into entry (i)
            move_slot(wkbl, i, i + 1);
        }

        wkbl->next_free_entry--;
    }

    LOGGER_DEBUG(log, "process_frame:m_newX->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0], (int)m_new->data[1]);
    LOGGER_DEBUG(log, "process_frame:001b next_free_entry=%d", wkbl->next_free_entry);

    return m_new;
}

static uint8_t fill_data_into_slot(Logger *log, struct RTPWorkBufferList *wkbl, int8_t slot, uint8_t is_keyframe,
                                   const struct RTPHeaderV3 *header_v3, uint32_t length_v3, uint32_t offset_v3, const uint8_t *data, uint16_t length)
{
    uint8_t frame_complete = 0;


    if (slot > -1) {
        if (wkbl->work_buffer[slot].received_len == 0) {
            // this is the first time this slot is used. initialize it
            wkbl->work_buffer[slot].buf = (void *)new_message_v3(
                                              length_v3, data, length,
                                              offset_v3, length_v3, is_keyframe);

            LOGGER_DEBUG(log, "new message v3 001 is_keyframe=%d len=%d offset=%d", is_keyframe, (int)length_v3, (int)offset_v3);

            wkbl->work_buffer[slot].frame_type = is_keyframe;
            wkbl->work_buffer[slot].data_len = length_v3;
            // LOGGER_INFO(log, "new message v3 TT1 ts=%llu", header_v3->timestamp);
            wkbl->work_buffer[slot].timestamp = net_ntohl(header_v3->timestamp);
            // frame_record_timestamp
            // LOGGER_INFO(log, "new message v3 TT2 ts=%llu", net_ntohl(header_v3->timestamp));
            wkbl->work_buffer[slot].sequnum = net_ntohs(header_v3->sequnum);
            wkbl->work_buffer[slot].fragment_num = net_ntohl(header_v3->fragment_num);
            LOGGER_DEBUG(log, "fragnum=%ld", (long)wkbl->work_buffer[slot].fragment_num);

            wkbl->next_free_entry++;
            LOGGER_DEBUG(log, "wkbl->next_free_entry:001=%d", wkbl->next_free_entry);
            struct RTPMessage *mm = (struct RTPMessage *)wkbl->work_buffer[slot].buf;
            LOGGER_DEBUG(log, "wkbl->next_free_entry:001:b0=%d b1=%d", mm->data[0], mm->data[1]);
        }

        if (offset_v3 > length_v3) {
            LOGGER_ERROR(log, "memory size too small!");
        }

        struct RTPMessage *mm2 = (struct RTPMessage *)wkbl->work_buffer[slot].buf;


        memcpy(
            (mm2->data + offset_v3),
            data + sizeof(struct RTPHeader),
            (size_t)(length - sizeof(struct RTPHeader))
        );

        wkbl->work_buffer[slot].received_len = wkbl->work_buffer[slot].received_len + (length - sizeof(struct RTPHeader));

        // update received length also in the Header of the Message, for later use
        struct RTPHeaderV3 *header_v3 = (struct RTPHeaderV3 *) & (mm2->header);

        header_v3->received_length_full = wkbl->work_buffer[slot].received_len;

        if (wkbl->work_buffer[slot].received_len == length_v3) {
            frame_complete = 1;
        }

        LOGGER_DEBUG(log, "wkbl->next_free_entry:002=%d", wkbl->next_free_entry);
        LOGGER_DEBUG(log, "fill data into slot=%d rec_len=%d", slot, (int)wkbl->work_buffer[slot].received_len);
    }

    return frame_complete;
}

static void update_bwc_values(Logger *log, RTPSession *session, struct RTPMessage *msg)
{
    if (session->first_packets_counter < DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT) {
        session->first_packets_counter++;
    } else {
        struct RTPHeaderV3 *header_v3 = (struct RTPHeaderV3 *) & (msg->header);
        uint32_t data_length_full = header_v3->data_length_full; // without header
        uint32_t received_length_full = header_v3->received_length_full; // without header

        bwc_add_recv(session->bwc, data_length_full);

        if (received_length_full < data_length_full) {
            // LOGGER_WARNING(log, "BWC: full length=%u received length=%d", data_length_full, received_length_full);
            bwc_add_lost_v3(session->bwc, (data_length_full - received_length_full));
        }
    }
}

int handle_rtp_packet_v3(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
{
    (void) m;
    (void) friendnumber;

    RTPSession *session = (RTPSession *)object;
    RTPSessionV3 *session_v3 = (RTPSessionV3 *)object;
    struct RTPWorkBufferList *work_buffer_list = (struct RTPWorkBufferList *)session_v3->work_buffer_list;

    if (session_v3->work_buffer_list == NULL) {
        session_v3->work_buffer_list = (struct RTPWorkBufferList *)calloc(1, sizeof(struct RTPWorkBufferList));
        session_v3->work_buffer_list->next_free_entry = 0;
        work_buffer_list = (struct RTPWorkBufferList *)session_v3->work_buffer_list;
    }

    /*
     *
     * session->mcb == vc_queue_message() // this function is called from here! arrgh **
     * session->mp == struct *RTPMessage
     * session->cs == call->video.second // == VCSession created by vc_new() call!
     *
     *
     */

    // here the packet ID byte gets stripped, why? -----------
    data++;
    length--; // this is the length of only this part of the message (brutto)
    // here the packet ID byte gets stripped, why? -----------


    const struct RTPHeaderV3 *header_v3 = (const struct RTPHeaderV3 *)data;

    uint32_t length_v3 = net_htonl(header_v3->data_length_full); // without header
    uint32_t offset_v3 = net_htonl(header_v3->offset_full); // without header
    uint8_t is_keyframe = (int)header_v3->is_keyframe;
    int32_t fragment_num = net_htonl(header_v3->fragment_num);

    LOGGER_DEBUG(m->log, "handle_rtp_packet_v3: fragment_num=%ld", (long)fragment_num);

    // LOGGER_WARNING(m->log, "frame timestamp TT2 %llu", ntohll(header_v3->frame_record_timestamp));

    LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- full lens=%d len=%d offset=%d is_keyframe=%s", (int)length,
                 (int)length_v3, (int)offset_v3, ((int)header_v3->is_keyframe) ? "K" : ".");
    LOGGER_DEBUG(m->log, "wkbl->next_free_entry:003=%d", work_buffer_list->next_free_entry);

    if (offset_v3 >= length_v3) {
        /* Never allow this case to happen */
        LOGGER_ERROR(m->log, "Never allow this case to happen");
        return -1;
    }


    // length -> includes header
    // length_v3 -> does not include header

    if (length_v3 == (length - sizeof(struct RTPHeader))) {
        /* The message was sent in single part */

        LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- single part message");

        int8_t slot = get_slot(m->log, work_buffer_list, is_keyframe, header_v3, 0);
        LOGGER_DEBUG(m->log, "slot num=%d", (int)slot);

        if (slot == -2) {
            // drop data
            return -1;
        }

        if (slot == -1) {
            LOGGER_DEBUG(m->log, "process_oldest_frame");
            struct RTPMessage *m_new = process_oldest_frame(m->log, work_buffer_list);

            if (m_new) {
                if (session->mcb) {
                    LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- CALLBACK-001a b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
                    update_bwc_values(m->log, session, m_new);
                    session->mcb(session->cs, m_new);
                } else {
                    free(m_new);
                }

                m_new = NULL;
            }

            slot = get_slot(m->log, work_buffer_list, is_keyframe, header_v3, 0);

            if (slot == -2) {
                if (m_new) {
                    free(m_new);
                }

                // drop data
                return -1;
            }

        }

        if (slot > -1) {
            LOGGER_DEBUG(m->log, "fill_data_into_slot.1");

            // fill in this part into the slot buffer at the correct offset
            uint8_t frame_complete = fill_data_into_slot(m->log, work_buffer_list, slot, is_keyframe, header_v3, length_v3,
                                     offset_v3, data, length);

            //if ((frame_complete == 1) && (is_keyframe == 1))
            if (frame_complete == 1)
                //if (1 == 2)
            {
                struct RTPMessage *m_new = process_frame(m->log, work_buffer_list, slot);

                if (m_new) {
                    if (session->mcb) {
                        LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- CALLBACK-003a b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
                        update_bwc_values(m->log, session, m_new);
                        session->mcb(session->cs, m_new);
                    } else {
                        free(m_new);
                    }

                    m_new = NULL;
                }
            }
        }


#if 0

        struct RTPMessage *m_new = new_message_v3(length_v3, data, length, 0,
			length_v3, (uint8_t)header_v3->is_keyframe);
        // memcpy(&m_new->header, data, length);

        if (session->mcb) {
            LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- CALLBACK-001");
            update_bwc_values(m->log, session, m_new);
            session->mcb(session->cs, m_new);
        } else {
            free(m_new);
        }

        m_new = NULL;
#endif

    } else {
        /* Multipart-message */

        // check which slot to use
        int8_t slot = get_slot(m->log, work_buffer_list, is_keyframe, header_v3, 1);
        LOGGER_DEBUG(m->log, "slot num=%d", (int)slot);

        if (slot == -2) {
            // drop data
            return -1;
        }

        if (slot == -1) {
            LOGGER_DEBUG(m->log, "process_oldest_frame");
            struct RTPMessage *m_new = process_oldest_frame(m->log, work_buffer_list);

            if (m_new) {
                if (session->mcb) {
                    LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- CALLBACK-002 b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
                    update_bwc_values(m->log, session, m_new);
                    session->mcb(session->cs, m_new);
                } else {
                    free(m_new);
                }

                m_new = NULL;
            }

            slot = get_slot(m->log, work_buffer_list, is_keyframe, header_v3, 1);

            if (slot == -2) {
                if (m_new) {
                    free(m_new);
                }

                // drop data
                return -1;
            }
        }

        if (slot > -1) {
            LOGGER_DEBUG(m->log, "fill_data_into_slot");

            // fill in this part into the solt buffer at the correct offset
            uint8_t frame_complete = fill_data_into_slot(m->log, work_buffer_list, slot, is_keyframe, header_v3, length_v3,
                                     offset_v3, data, length);

            // if ((frame_complete == 1) && (is_keyframe == 1))
            if (frame_complete == 1)
                // if (1 == 2)
            {
                struct RTPMessage *m_new = process_frame(m->log, work_buffer_list, slot);

                if (m_new) {
                    if (session->mcb) {
                        LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- CALLBACK-003 b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
                        update_bwc_values(m->log, session, m_new);
                        session->mcb(session->cs, m_new);
                    } else {
                        free(m_new);
                    }

                    m_new = NULL;
                }
            }
        }
    }


    return 0;
}


int handle_rtp_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
{
    (void) m;
    (void) friendnumber;

    RTPSession *session = (RTPSession *)object;

    // here the packet ID byte gets stripped, why? -----------
    const uint8_t *data_orig = data;
    const uint32_t length_orig = length;
    data++;
    length--;
    // here the packet ID byte gets stripped, why? -----------

    if (!session || length < sizeof(struct RTPHeader)) {
        LOGGER_WARNING(m->log, "No session or invalid length of received buffer!");
        return -1;
    }


// Zoff -- new stuff --

    const struct RTPHeaderV3 *header_v3 = (const struct RTPHeaderV3 *)data;

    LOGGER_DEBUG(m->log, "header->pt %d, video %d", (uint8_t)header_v3->pt, (rtp_TypeVideo % 128));

    if ((((uint8_t)header_v3->protocol_version) == 3) &&
            (((uint8_t)header_v3->pt) == (rtp_TypeVideo % 128))
       ) {
        // use V3 only for Video payload (at the moment)
        return handle_rtp_packet_v3(m, friendnumber, data_orig, length_orig, object);
    }

// Zoff -- new stuff --


    // everything below here is protocol version 2 ------------------
    // everything below here is protocol version 2 ------------------
    // everything below here is protocol version 2 ------------------

    const struct RTPHeader *header = (const struct RTPHeader *) data;

    if (header->pt != session->payload_type % 128) {
        LOGGER_WARNING(m->log, "Invalid payload type with the session");
        return -1;
    }

    if (net_ntohs(header->cpart) >= net_ntohs(header->tlen)) {
        /* Never allow this case to happen */
        return -1;
    }


	//if ((uint8_t)header->pt == (rtp_TypeAudio % 128))
	//{
    //    LOGGER_TRACE(m->log, "incoming audio data packet");
	//}


    bwc_feed_avg(session->bwc, length);

    if (net_ntohs(header->tlen) == length - sizeof(struct RTPHeader)) {
        /* The message is sent in single part */

        /* Only allow messages which have arrived in order;
         * drop late messages
         */
        if (chloss(session, header)) {
			if ((uint8_t)header->pt == (rtp_TypeAudio % 128))
			{
					LOGGER_DEBUG(m->log, "drop late audio messages (1)");
			}

            return 0;
        }

        /* Message is not late; pick up the latest parameters */
        session->rsequnum = net_ntohs(header->sequnum);
        session->rtimestamp = net_ntohl(header->timestamp);

        bwc_add_recv(session->bwc, length);

        /* Invoke processing of active multiparted message */
        if (session->mp) {
            if (session->mcb) {
                session->mcb(session->cs, session->mp);
            } else {
                free(session->mp);
            }

            session->mp = NULL;
        }

        /* The message came in the allowed time;
         * process it only if handler for the session is present.
         */

        if (!session->mcb) {
            return 0;
        }

        return session->mcb(session->cs, new_message(length, data, length));
    }

    /* The message is sent in multiple parts */

    if (session->mp) {
        /* There are 2 possible situations in this case:
         *      1) being that we got the part of already processing message.
         *      2) being that we got the part of a new/old message.
         *
         * We handle them differently as we only allow a single multiparted
         * processing message
         */

        if (session->mp->header.sequnum == net_ntohs(header->sequnum) &&
                session->mp->header.timestamp == net_ntohl(header->timestamp)) {
            /* First case */

            /* Make sure we have enough allocated memory */
            if ((
				(int32_t)(session->mp->header.tlen - session->mp->len)
				<
				(int32_t)(length - sizeof(struct RTPHeader))
               )
               ||
               (
               ((int32_t)session->mp->header.tlen <= (int32_t)net_ntohs(header->cpart))
               )) {
                /* There happened to be some corruption on the stream;
                 * continue wihtout this part
                 */

				if ((uint8_t)header->pt == (rtp_TypeAudio % 128))
				{
						LOGGER_DEBUG(m->log, "drop audio message (2)");
				}

                return 0;
            }

            memcpy(session->mp->data + net_ntohs(header->cpart), data + sizeof(struct RTPHeader),
                   length - sizeof(struct RTPHeader));

            session->mp->len += length - sizeof(struct RTPHeader);

            bwc_add_recv(session->bwc, length);

            if (session->mp->len == session->mp->header.tlen) {
                /* Received a full message; now push it for the further
                 * processing.
                 */
                if (session->mcb) {
                    session->mcb(session->cs, session->mp);
                } else {
                    free(session->mp);
                }

                session->mp = NULL;
            }
        } else {
            /* Second case */

            if (session->mp->header.timestamp > net_ntohl(header->timestamp)) {
                /* The received message part is from the old message;
                 * discard it.
                 */
				if ((uint8_t)header->pt == (rtp_TypeAudio % 128))
				{
						LOGGER_DEBUG(m->log, "drop old audio message (3)");
				}

                return 0;
            }

            /* Measure missing parts of the old message */
            bwc_add_lost(session->bwc,
                         (session->mp->header.tlen - session->mp->len) +

                         /* Must account sizes of rtp headers too */
                         ((session->mp->header.tlen - session->mp->len) /
                          MAX_CRYPTO_DATA_SIZE) * sizeof(struct RTPHeader));

            /* Push the previous message for processing */
            if (session->mcb) {
                session->mcb(session->cs, session->mp);
            } else {
                free(session->mp);
            }

            session->mp = NULL;
            goto NEW_MULTIPARTED;
        }
    } else {
        /* In this case threat the message as if it was received in order
         */

        /* This is also a point for new multiparted messages */
NEW_MULTIPARTED:

        /* Only allow messages which have arrived in order;
         * drop late messages
         */
        if (chloss(session, header)) {
			if ((uint8_t)header->pt == (rtp_TypeAudio % 128))
			{
					LOGGER_DEBUG(m->log, "drop out of order audio message (4)");
			}

            return 0;
        }

        /* Message is not late; pick up the latest parameters */
        session->rsequnum = net_ntohs(header->sequnum);
        session->rtimestamp = net_ntohl(header->timestamp);

        bwc_add_recv(session->bwc, length);

        /* Again, only store message if handler is present
         */
        if (session->mcb) {
            session->mp = new_message(net_ntohs(header->tlen) + sizeof(struct RTPHeader), data, length);

            /* Reposition data if necessary */
            if (net_ntohs(header->cpart)) {
                ;
            }

            memmove(session->mp->data + net_ntohs(header->cpart), session->mp->data, session->mp->len);
        }
    }

    return 0;
}


