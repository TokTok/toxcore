/*
 * Copyright © 2016-2018 The TokTok team.
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


size_t rtp_header_pack(uint8_t *const rdata, const struct RTPHeader *header)
{
    uint8_t *p = rdata;
    *p++ = (header->ve & 3) << 6
           | (header->pe & 1) << 5
           | (header->xe & 1) << 4
           | (header->cc & 0xf);
    *p++ = (header->ma & 1) << 7
           | (header->pt & 0x7f);

    p += net_pack_u16(p, header->sequnum);
    p += net_pack_u32(p, header->timestamp);
    p += net_pack_u32(p, header->ssrc);
    p += net_pack_u64(p, header->flags);
    p += net_pack_u32(p, header->offset_full);
    p += net_pack_u32(p, header->data_length_full);
    p += net_pack_u32(p, header->received_length_full);

    for (size_t i = 0; i < sizeof header->csrc / sizeof header->csrc[0]; i++) {
        p += net_pack_u32(p, header->csrc[i]);
    }

    p += net_pack_u16(p, header->offset_lower);
    p += net_pack_u16(p, header->data_length_lower);
    assert(p == rdata + RTP_HEADER_SIZE);
    return p - rdata;
}

size_t rtp_header_unpack(const uint8_t *data, struct RTPHeader *header)
{
    const uint8_t *p = data;
    header->ve = (*p >> 6) & 3;
    header->pe = (*p >> 5) & 1;
    header->xe = (*p >> 4) & 1;
    header->cc = *p & 0xf;
    ++p;

    header->ma = (*p >> 7) & 1;
    header->pt = *p & 0x7f;
    ++p;

    p += net_unpack_u16(p, &header->sequnum);
    p += net_unpack_u32(p, &header->timestamp);
    p += net_unpack_u32(p, &header->ssrc);
    p += net_unpack_u64(p, &header->flags);
    p += net_unpack_u32(p, &header->offset_full);
    p += net_unpack_u32(p, &header->data_length_full);
    p += net_unpack_u32(p, &header->received_length_full);

    for (size_t i = 0; i < sizeof header->csrc / sizeof header->csrc[0]; i++) {
        p += net_unpack_u32(p, &header->csrc[i]);
    }

    p += net_unpack_u16(p, &header->offset_lower);
    p += net_unpack_u16(p, &header->data_length_lower);
    assert(p == data + RTP_HEADER_SIZE);
    return p - data;
}

static int handle_rtp_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object);


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
        return nullptr;
    }

    retu->ssrc = payload_type == rtp_TypeVideo ? 0 : random_u32();
    retu->payload_type = payload_type;
    retu->m = m;
    retu->friend_number = friendnumber;

    // set NULL just in case
    retu->mp = nullptr;
    retu->first_packets_counter = 1;

    /* Also set payload type as prefix */
    retu->bwc = bwc;
    retu->cs = cs;
    retu->mcb = mcb;

    if (-1 == rtp_allow_receiving(retu)) {
        LOGGER_WARNING(m->log, "Failed to start rtp receiving mode");
        free(retu);
        return nullptr;
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
        free(session_v3->work_buffer_list);
        session_v3->work_buffer_list = nullptr;
    }

    free(session);
}

int rtp_allow_receiving(RTPSession *session)
{
    if (session == nullptr) {
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
    if (session == nullptr) {
        return -1;
    }

    m_callback_rtp_packet(session->m, session->friend_number, session->payload_type, nullptr, nullptr);

    LOGGER_DEBUG(session->m->log, "Stopped receiving on session: %p", session);
    return 0;
}

/*
 * input is raw vpx data. length_v3 is the length of the raw data
 */
int rtp_send_data(RTPSession *session, const uint8_t *data, uint32_t length_v3,
                  bool is_keyframe, Logger *log)
{
    if (!session) {
        LOGGER_ERROR(log, "No session!");
        return -1;
    }

    // here the highest bits gets stripped anyway, no need to do keyframe bit magic here!
    const uint16_t length = (uint16_t)length_v3;
    uint8_t is_video_payload = 0;

    if (session->payload_type == rtp_TypeVideo) {
        is_video_payload = 1;
    }

    VLA(uint8_t, rdata, length_v3 + RTP_HEADER_SIZE + 1);
    memset(rdata, 0, SIZEOF_VLA(rdata));
    rdata[0] = session->payload_type;

    struct RTPHeader header = {0};

    header.ve = 2;  // this is unused in toxav
    header.pe = 0;
    header.xe = 0;
    header.cc = 0;

    header.ma = 0;
    header.pt = session->payload_type % 128;

    header.sequnum = session->sequnum;
    header.timestamp = current_time_monotonic();
    header.ssrc = session->ssrc;

    header.offset_lower = 0;
    header.data_length_lower = length;
    header.flags = RTP_LARGE_FRAME;

    uint16_t length_safe = (uint16_t)length_v3;

    if (length_v3 > UINT16_MAX) {
        length_safe = UINT16_MAX;
    }

    header.data_length_lower = length_safe;
    header.data_length_full = length_v3; // without header
    header.offset_lower = 0;
    header.offset_full = 0;

    if (is_keyframe) {
        header.flags |= RTP_KEY_FRAME;
    }

    if (MAX_CRYPTO_DATA_SIZE > (length_v3 + RTP_HEADER_SIZE + 1)) {
        /**
         * The length is lesser than the maximum allowed length (including header)
         * Send the packet in single piece.
         */
        rtp_header_pack(rdata + 1, &header);
        memcpy(rdata + 1 + RTP_HEADER_SIZE, data, length_v3);

        if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number, rdata, SIZEOF_VLA(rdata))) {
            LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s", SIZEOF_VLA(rdata), strerror(errno));
        }
    } else {
        /**
         * The length is greater than the maximum allowed length (including header)
         * Send the packet in multiple pieces.
         */
        uint32_t sent = 0;
        uint16_t piece = MAX_CRYPTO_DATA_SIZE - (RTP_HEADER_SIZE + 1);

        while ((length_v3 - sent) + RTP_HEADER_SIZE + 1 > MAX_CRYPTO_DATA_SIZE) {
            rtp_header_pack(rdata + 1, &header);
            memcpy(rdata + 1 + RTP_HEADER_SIZE, data + sent, piece);

            if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number,
                                                 rdata, piece + RTP_HEADER_SIZE + 1)) {
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s",
                               piece + RTP_HEADER_SIZE + 1, strerror(errno));
            }

            sent += piece;
            header.offset_lower = sent;
            header.offset_full = sent; // raw data offset, without any header
        }

        /* Send remaining */
        piece = length - sent;

        if (piece) {
            rtp_header_pack(rdata + 1, &header);
            memcpy(rdata + 1 + RTP_HEADER_SIZE, data + sent, piece);

            if (-1 == m_send_custom_lossy_packet(session->m, session->friend_number, rdata,
                                                 piece + RTP_HEADER_SIZE + 1)) {
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! std error: %s",
                               piece + RTP_HEADER_SIZE + 1, strerror(errno));
            }
        }
    }

    session->sequnum ++;
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

        return true;
    }

    return false;
}

// allocate_len is including header!
static struct RTPMessage *new_message(size_t allocate_len, const uint8_t *data, uint16_t data_length)
{
    assert(allocate_len >= data_length);
    struct RTPMessage *msg = (struct RTPMessage *)calloc(sizeof(struct RTPMessage) +
                             (allocate_len - sizeof(struct RTPHeader)), 1);

    if (msg == nullptr) {
        return nullptr;
    }

    msg->len = data_length - RTP_HEADER_SIZE; // result without header
    memcpy(&msg->header, data, data_length);
    msg->header.sequnum = net_ntohs(msg->header.sequnum);
    msg->header.timestamp = net_ntohl(msg->header.timestamp);
    msg->header.ssrc = net_ntohl(msg->header.ssrc);
    msg->header.offset_lower = net_ntohs(msg->header.offset_lower);
    msg->header.data_length_lower = net_ntohs(msg->header.data_length_lower); // result without header
    return msg;
}

//
// full message len incl. header, data pointer, length of this part without header
//
static struct RTPMessage *new_message_v3(size_t allocate_len, const uint8_t *data, uint16_t data_length,
        uint32_t offset, uint32_t full_data_length, bool is_keyframe)
{
    struct RTPMessage *msg = (struct RTPMessage *)calloc(1, sizeof(struct RTPMessage) + allocate_len);

    if (msg == nullptr) {
        return nullptr;
    }

    msg->len = data_length - RTP_HEADER_SIZE;  // without header
    rtp_header_unpack(data, &msg->header);
    memcpy(msg->data, data + RTP_HEADER_SIZE, allocate_len - RTP_HEADER_SIZE);
    msg->header.pt = rtp_TypeVideo % 128;
    msg->header.data_length_full = full_data_length;  // without header
    msg->header.offset_full = offset;

    if (is_keyframe) {
        msg->header.flags |= RTP_KEY_FRAME;
    }

    return msg;
}

/*
 * move data pointers in work_buffer from slot src_slot to dst_slot
 */
static void move_slot(struct RTPWorkBufferList *wkbl, int8_t dst_slot, int8_t src_slot)
{
    assert(0 <= dst_slot && dst_slot < USED_RTP_WORKBUFFER_COUNT);
    assert(0 <= src_slot && src_slot < USED_RTP_WORKBUFFER_COUNT);
    memcpy(&wkbl->work_buffer[dst_slot], &wkbl->work_buffer[src_slot], sizeof(struct RTPWorkBuffer));
    wkbl->work_buffer[dst_slot].buf = wkbl->work_buffer[src_slot].buf;
    memset(&wkbl->work_buffer[src_slot], 0, sizeof(struct RTPWorkBuffer));
}

/*
 * find the next free slot in work_buffer for the incoming data packet
 * if the data packet belongs to a frame thats already in the work_buffer
 * then use that slot
 * if there is no free slot return -1
 * if the data packet is too old return -2
 * if there is a keyframe beeing assembled in slot 0, keep it a bit longer
 * and do not kick it out right away if all slots are full
 * instead kick out the new incoming interframe
 */
static int8_t get_slot(Logger *log, struct RTPWorkBufferList *wkbl, bool is_keyframe,
                       const struct RTPHeader *header, uint8_t is_multipart)
{
    int8_t result_slot = -1;    // -1 -> means drop oldest message
    // -2 -> means drop this frame

    if (is_multipart == 1) {
        for (int i = 0; i < wkbl->next_free_entry; i++) {
            if ((wkbl->work_buffer[i].sequnum == net_ntohs(header->sequnum))
                    &&
                    (wkbl->work_buffer[i].timestamp == net_ntohl(header->timestamp))) {
                return i;
            }
        }
    }

    if (wkbl->next_free_entry < USED_RTP_WORKBUFFER_COUNT) {
        if ((wkbl->next_free_entry > 0)
                && (wkbl->work_buffer[wkbl->next_free_entry - 1].timestamp > net_ntohl(header->timestamp))) {
            LOGGER_DEBUG(log, "workbuffer:2:timestamp too old");
            return -2;
        } else {
            return wkbl->next_free_entry;
        }
    }

    if (wkbl->work_buffer[0].is_keyframe && !is_keyframe
            && wkbl->work_buffer[0].received_len < wkbl->work_buffer[0].data_len
            && wkbl->work_buffer[0].timestamp + VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS > net_ntohl(header->timestamp)) {
        // if we are processing a keyframe and the current part does not belong to a keyframe
        // keep the keyframe and drop the current data
        LOGGER_WARNING(log, "keep KEYFRAME in workbuffer");
        result_slot = -2;
    }

    return result_slot;
}

static struct RTPMessage *process_oldest_frame(Logger *log, struct RTPWorkBufferList *wkbl)
{
    if (wkbl->next_free_entry <= 0) {
        return nullptr;
    }

    // remove entry 0, and make RTPMessageV3 from it
    struct RTPMessage *m_new = (struct RTPMessage *)wkbl->work_buffer[0].buf;
    wkbl->work_buffer[0].buf = nullptr;
    LOGGER_DEBUG(log, "process_oldest_frame:m_new->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0],
                 (int)m_new->data[1]);
    LOGGER_DEBUG(log, "process_oldest_frame:001a next_free_entry=%d", wkbl->next_free_entry);

    for (int i = 0; i < (wkbl->next_free_entry - 1); i++) {
        // move entry (i+1) into entry (i)
        move_slot(wkbl, i, i + 1);
    }

    wkbl->next_free_entry--;
    LOGGER_DEBUG(log, "process_oldest_frame:m_newX->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0],
                 (int)m_new->data[1]);
    LOGGER_DEBUG(log, "process_oldest_frame:001b next_free_entry=%d", wkbl->next_free_entry);
    return m_new;
}

static struct RTPMessage *process_frame(Logger *log, struct RTPWorkBufferList *wkbl, int8_t slot)
{
    if (wkbl->work_buffer[0].is_keyframe && slot != 0) {
        LOGGER_DEBUG(log, "process_frame:KEYFRAME waiting in slot 0");
        // there is a keyframe waiting in slot 0, dont use the current frame yet
        return nullptr;
    }

    // remove entry, and make RTPMessageV3 from it
    struct RTPMessage *m_new = (struct RTPMessage *)wkbl->work_buffer[slot].buf;
    wkbl->work_buffer[slot].buf = nullptr;
    LOGGER_DEBUG(log, "process_frame:m_new->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0], (int)m_new->data[1]);
    LOGGER_DEBUG(log, "process_frame:001a next_free_entry=%d", wkbl->next_free_entry);

    if (slot == (wkbl->next_free_entry - 1)) {
        memset(&(wkbl->work_buffer[slot]), 0, sizeof(struct RTPWorkBuffer));
    } else {
        // move entries to fill the gap
        for (int i = slot; i < (wkbl->next_free_entry - 1); i++) {
            // move entry (i+1) into entry (i)
            move_slot(wkbl, i, i + 1);
        }
    }

    wkbl->next_free_entry--;

    LOGGER_DEBUG(log, "process_frame:m_newX->len=%d b0=%d b1=%d", m_new->len, (int)m_new->data[0], (int)m_new->data[1]);
    LOGGER_DEBUG(log, "process_frame:001b next_free_entry=%d", wkbl->next_free_entry);
    return m_new;
}

static uint8_t fill_data_into_slot(Logger *log, struct RTPWorkBufferList *wkbl, int8_t slot, bool is_keyframe,
                                   const struct RTPHeader *header, uint32_t length_v3, uint32_t offset_v3,
                                   const uint8_t *data, uint16_t length)
{
    uint8_t frame_complete = 0;

    if (slot < 0) {
        return frame_complete;
    }

    if (wkbl->work_buffer[slot].received_len == 0) {
        // this is the first time this slot is used. initialize it
        wkbl->work_buffer[slot].buf = (uint8_t *)new_message_v3(
                                          length_v3, data, length,
                                          offset_v3, length_v3, is_keyframe);
        LOGGER_DEBUG(log, "new message v3 001 is_keyframe=%d len=%d offset=%d", is_keyframe, (int)length_v3, (int)offset_v3);
        wkbl->work_buffer[slot].is_keyframe = is_keyframe;
        wkbl->work_buffer[slot].data_len = length_v3;
        wkbl->work_buffer[slot].timestamp = net_ntohl(header->timestamp);
        wkbl->work_buffer[slot].sequnum = net_ntohs(header->sequnum);
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
        data + RTP_HEADER_SIZE,
        (size_t)(length - RTP_HEADER_SIZE)
    );

    wkbl->work_buffer[slot].received_len = wkbl->work_buffer[slot].received_len + (length - RTP_HEADER_SIZE);

    // update received length also in the Header of the Message, for later use
    struct RTPHeader *header_v3_new = &mm2->header;

    header_v3_new->received_length_full = wkbl->work_buffer[slot].received_len;

    if (wkbl->work_buffer[slot].received_len == length_v3) {
        frame_complete = 1;
    }

    LOGGER_DEBUG(log, "wkbl->next_free_entry:002=%d", wkbl->next_free_entry);
    LOGGER_DEBUG(log, "fill data into slot=%d rec_len=%d", slot, (int)wkbl->work_buffer[slot].received_len);
    return frame_complete;
}

static void update_bwc_values(Logger *log, RTPSession *session, struct RTPMessage *msg)
{
    if (session->first_packets_counter < DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT) {
        session->first_packets_counter++;
    } else {
        uint32_t data_length_full = msg->header.data_length_full; // without header
        uint32_t received_length_full = msg->header.received_length_full; // without header
        bwc_add_recv(session->bwc, data_length_full);

        if (received_length_full < data_length_full) {
            LOGGER_DEBUG(log, "BWC: full length=%u received length=%d", data_length_full, received_length_full);
            bwc_add_lost(session->bwc, (data_length_full - received_length_full));
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

    if (session_v3->work_buffer_list == nullptr) {
        session_v3->work_buffer_list = (struct RTPWorkBufferList *)calloc(1, sizeof(struct RTPWorkBufferList));

        if (session_v3->work_buffer_list == nullptr) {
            LOGGER_ERROR(m->log, "out of memory while allocating work buffer list");
            return -1;
        }

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
    const struct RTPHeader *header = (const struct RTPHeader *)data;
    uint32_t length_v3 = net_htonl(header->data_length_full); // without header
    uint32_t offset_v3 = net_htonl(header->offset_full); // without header
    bool is_keyframe = (header->flags & RTP_KEY_FRAME) != 0;
    LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- full lens=%d len=%d offset=%d is_keyframe=%s", (int)length,
                 (int)length_v3, (int)offset_v3, is_keyframe ? "K" : ".");
    LOGGER_DEBUG(m->log, "wkbl->next_free_entry:003=%d", work_buffer_list->next_free_entry);

    if (offset_v3 >= length_v3) {
        /* Never allow this case to happen */
        LOGGER_ERROR(m->log, "Never allow this case to happen");
        return -1;
    }

    // length -> includes header
    // length_v3 -> does not include header
    uint8_t is_multipart = length_v3 != (length - RTP_HEADER_SIZE);

    /* The message was sent in single part */
    LOGGER_DEBUG(m->log, "-- handle_rtp_packet_v3 -- single part message");
    int8_t slot = get_slot(m->log, work_buffer_list, is_keyframe, header, is_multipart);
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

            m_new = nullptr;
        }

        slot = get_slot(m->log, work_buffer_list, is_keyframe, header, 0);

        if (slot == -2) {
            free(m_new);
            // drop data
            return -1;
        }
    }

    if (slot > -1) {
        LOGGER_DEBUG(m->log, "fill_data_into_slot.1");
        // fill in this part into the slot buffer at the correct offset
        uint8_t frame_complete = fill_data_into_slot(m->log, work_buffer_list, slot, is_keyframe, header, length_v3,
                                 offset_v3, data, length);

        //if ((frame_complete == 1) && is_keyframe)
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

                m_new = nullptr;
            }
        }
    }

    return 0;
}

static int handle_rtp_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
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

    if (!session || length < RTP_HEADER_SIZE) {
        LOGGER_WARNING(m->log, "No session or invalid length of received buffer!");
        return -1;
    }

    const struct RTPHeader *header = (const struct RTPHeader *)data;
    LOGGER_DEBUG(m->log, "header->pt %d, video %d", (uint8_t)header->pt, (rtp_TypeVideo % 128));

    if ((uint8_t)((header->flags & RTP_LARGE_FRAME) != 0) &&
            (uint8_t)header->pt == (rtp_TypeVideo % 128)) {
        // use V3 only for Video payload (at the moment)
        return handle_rtp_packet_v3(m, friendnumber, data_orig, length_orig, object);
    }

    // everything below here is protocol version V2 ------------------

    if (header->pt != session->payload_type % 128) {
        LOGGER_WARNING(m->log, "Invalid payload type with the session");
        return -1;
    }

    if (net_ntohs(header->offset_lower) >= net_ntohs(header->data_length_lower)) {
        /* Never allow this case to happen */
        return -1;
    }

    if (net_ntohs(header->data_length_lower) == length - RTP_HEADER_SIZE) {
        /* The message is sent in single part */

        /* Only allow messages which have arrived in order;
         * drop late messages
         */
        if (chloss(session, header)) {
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

            session->mp = nullptr;
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
            if (session->mp->header.data_length_lower - session->mp->len < length - RTP_HEADER_SIZE ||
                    session->mp->header.data_length_lower <= net_ntohs(header->offset_lower)) {
                /* There happened to be some corruption on the stream;
                 * continue wihtout this part
                 */
                return 0;
            }

            memcpy(session->mp->data + net_ntohs(header->offset_lower), data + RTP_HEADER_SIZE,
                   length - RTP_HEADER_SIZE);
            session->mp->len += length - RTP_HEADER_SIZE;
            bwc_add_recv(session->bwc, length);

            if (session->mp->len == session->mp->header.data_length_lower) {
                /* Received a full message; now push it for the further
                 * processing.
                 */
                if (session->mcb) {
                    session->mcb(session->cs, session->mp);
                } else {
                    free(session->mp);
                }

                session->mp = nullptr;
            }
        } else {
            /* Second case */
            if (session->mp->header.timestamp > net_ntohl(header->timestamp)) {
                /* The received message part is from the old message;
                 * discard it.
                 */
                return 0;
            }

            /* Push the previous message for processing */
            if (session->mcb) {
                session->mcb(session->cs, session->mp);
            } else {
                free(session->mp);
            }

            session->mp = nullptr;
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
            return 0;
        }

        /* Message is not late; pick up the latest parameters */
        session->rsequnum = net_ntohs(header->sequnum);
        session->rtimestamp = net_ntohl(header->timestamp);
        bwc_add_recv(session->bwc, length);

        /* Again, only store message if handler is present
         */
        if (session->mcb) {
            session->mp = new_message(net_ntohs(header->data_length_lower) + RTP_HEADER_SIZE, data, length);
            memmove(session->mp->data + net_ntohs(header->offset_lower), session->mp->data, session->mp->len);
        }
    }

    return 0;
}
