/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "group_connection.h"
#include "group_chats.h"
#include "Messenger.h"
#include "util.h"

#ifndef VANILLA_NACL

/* Returns group connection object for peer_number.
 * Returns NULL if peer_number is invalid.
 */
GC_Connection *gcc_get_connection(const GC_Chat *chat, int peer_number)
{
    if (!peer_number_valid(chat, peer_number)) {
        return nullptr;
    }

    return &chat->gcc[peer_number];
}

/* Returns true if ary entry does not contain an active packet. */
static bool array_entry_is_empty(struct GC_Message_Array_Entry *array_entry)
{
    return array_entry->time_added == 0;
}

/* Clears an ary entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static void clear_array_entry(struct GC_Message_Array_Entry *array_entry)
{
    if (array_entry->data) {
        free(array_entry->data);
    }

    memset(array_entry, 0, sizeof(struct GC_Message_Array_Entry));
}

/* Returns ary index for message_id */
uint16_t get_array_index(uint64_t message_id)
{
    return message_id % GCC_BUFFER_SIZE;
}

/* Puts packet data in ary_entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int create_array_entry(const Mono_Time *mono_time, struct GC_Message_Array_Entry *array_entry,
                              const uint8_t *data, uint32_t length,
                              uint8_t packet_type, uint64_t message_id)
{
    if (length) {
        array_entry->data = (uint8_t *)malloc(sizeof(uint8_t) * length);

        if (array_entry->data == nullptr) {
            return -1;
        }

        memcpy(array_entry->data, data, length);
    }

    array_entry->data_length = length;
    array_entry->packet_type = packet_type;
    array_entry->message_id = message_id;
    array_entry->time_added = mono_time_get(mono_time);
    array_entry->last_send_try = mono_time_get(mono_time);

    return 0;
}

/* Adds data of length to gconn's send_array.
 *
 * Returns 0 on success and increments gconn's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_to_send_array(const Mono_Time *mono_time, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                          uint8_t packet_type)
{
    /* check if send_array is full */
    if ((gconn->send_message_id % GCC_BUFFER_SIZE) == (uint16_t)(gconn->send_array_start - 1)) {
        return -1;
    }

    uint16_t idx = get_array_index(gconn->send_message_id);
    struct GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (!array_entry_is_empty(array_entry)) {
        return -1;
    }

    if (create_array_entry(mono_time, array_entry, data, length, packet_type, gconn->send_message_id) == -1) {
        return -1;
    }

    ++gconn->send_message_id;

    return 0;
}

/* Removes send_array item with message_id.
 *
 * Returns 0 if success.
 * Returns -1 on failure.
 */
int gcc_handle_ack(GC_Connection *gconn, uint64_t message_id)
{
    uint16_t idx = get_array_index(message_id);
    struct GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (array_entry_is_empty(array_entry)) {
        return -1;
    }

    if (array_entry->message_id != message_id) {  // wrap-around indicates a connection problem
        return -1;
    }

    clear_array_entry(array_entry);

    /* Put send_array_start in proper position */
    if (idx == gconn->send_array_start) {
        uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

        while (array_entry_is_empty(array_entry) && gconn->send_array_start != end) {
            gconn->send_array_start = (gconn->send_array_start + 1) % GCC_BUFFER_SIZE;
            idx = (idx + 1) % GCC_BUFFER_SIZE;
        }
    }

    return 0;
}

bool gcc_is_ip_set(GC_Connection *gconn)
{
    return gconn->addr.ip_port.ip.family.value != 0;
}

/* Decides if message need to be put in received_array or immediately handled.
 *
 * Return 2 if message is in correct sequence and may be handled immediately.
 * Return 1 if packet is out of sequence and added to received_array.
 * Return 0 if message is a duplicate.
 * Return -1 on failure
 */
int gcc_handle_received_message(GC_Chat *chat, uint32_t peer_number, const uint8_t *data, uint32_t length,
                                uint8_t packet_type, uint64_t message_id)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (!gconn) {
        return -1;
    }

    /* Appears to be a duplicate packet so we discard it */
    if (message_id < gconn->received_message_id + 1) {
        return 0;
    }

    /* we're missing an older message from this peer so we store it in received_array */
    if (message_id > gconn->received_message_id + 1) {
        uint16_t idx = get_array_index(message_id);
        struct GC_Message_Array_Entry *ary_entry = &gconn->received_array[idx];

        if (!array_entry_is_empty(ary_entry)) {
            return -1;
        }

        if (create_array_entry(chat->mono_time, ary_entry, data, length, packet_type, message_id) == -1) {
            return -1;
        }

        return 1;
    }

    ++gconn->received_message_id;

    return 2;
}

/* Handles peer_number's array entry with appropriate handler and clears it from array.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int process_received_array_entry(GC_Chat *chat, Messenger *m, int group_number, uint32_t peer_number,
                                        struct GC_Message_Array_Entry *array_entry)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    int ret = handle_gc_lossless_helper(m, group_number, peer_number, array_entry->data, array_entry->data_length,
                                        array_entry->message_id, array_entry->packet_type);
    clear_array_entry(array_entry);

    if (ret == -1) {
        gc_send_message_ack(chat, gconn, 0, array_entry->message_id);
        return -1;
    }

    gc_send_message_ack(chat, gconn, array_entry->message_id, 0);
    ++gconn->received_message_id;

    return 0;
}

/* Checks for and handles messages that are in proper sequence in gconn's received_array.
 * This should always be called after a new packet is handled in correct sequence.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_received_array(Messenger *m, int group_number, uint32_t peer_number)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (!chat) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    uint16_t idx = (gconn->received_message_id + 1) % GCC_BUFFER_SIZE;
    struct GC_Message_Array_Entry *array_entry = &gconn->received_array[idx];

    while (!array_entry_is_empty(array_entry)) {
        if (process_received_array_entry(chat, m, group_number, peer_number, array_entry) == -1) {
            return -1;
        }

        idx = (gconn->received_message_id + 1) % GCC_BUFFER_SIZE;
        array_entry = &gconn->received_array[idx];
    }

    return 0;
}

void gcc_resend_packets(Messenger *m, GC_Chat *chat, uint32_t peer_number)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return;
    }

    uint64_t tm = mono_time_get(m->mono_time);
    uint16_t i, start = gconn->send_array_start, end = gconn->send_message_id % GCC_BUFFER_SIZE;

    for (i = start; i != end; i = (i + 1) % GCC_BUFFER_SIZE) {
        struct GC_Message_Array_Entry *array_entry = &gconn->send_array[i];

        if (array_entry_is_empty(array_entry)) {
            continue;
        }

        if (tm == array_entry->last_send_try) {
            continue;
        }

        uint64_t delta = array_entry->last_send_try - array_entry->time_added;
        array_entry->last_send_try = tm;

        /* if this occurrs less than once per second this won't be reliable */
        if (delta > 1 && is_power_of_2(delta)) {
            gcc_send_group_packet(chat, gconn, array_entry->data, array_entry->data_length, array_entry->packet_type);
            continue;
        }

        if (mono_time_is_timeout(m->mono_time, array_entry->time_added, GC_CONFIRMED_PEER_TIMEOUT)) {
            gc_peer_delete(m, chat->group_number, peer_number, (const uint8_t *)"Peer timed out", 14, false);
            return;
        }
    }
}

/* Sends a packet to the peer associated with gconn.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int gcc_send_group_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet,
                          uint16_t length, uint8_t packet_type)
{
    if (!packet || length == 0) {
        return -1;
    }

    bool direct_send_attempt = false;

    if (!net_family_is_unspec(gconn->addr.ip_port.ip.family)) {
        if (gcc_connection_is_direct(chat->mono_time, gconn)) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length) {
                return 0;
            }

            return -1;
        }

        if (packet_type != GP_BROADCAST && packet_type != GP_MESSAGE_ACK) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length) {
                direct_send_attempt = true;
            }
        }
    }

    int ret = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret == 0 || direct_send_attempt) {
        return 0;
    }

    return -1;
}

/* Returns true if we have a direct connection with this group connection */
bool gcc_connection_is_direct(const Mono_Time *mono_time, const GC_Connection *gconn)
{
    return ((GCC_UDP_DIRECT_TIMEOUT + gconn->last_received_direct_time) > mono_time_get(mono_time));
}

/* called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn)
{
    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_array[i].data) {
            free(gconn->send_array[i].data);
        }

        if (gconn->received_array[i].data) {
            free(gconn->received_array[i].data);
        }
    }

    memset(gconn, 0, sizeof(GC_Connection));
}

/* called on group exit */
void gcc_cleanup(GC_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (&chat->gcc[i]) {
            gcc_peer_cleanup(&chat->gcc[i]);
        }
    }

    free(chat->gcc);
    chat->gcc = nullptr;
}

#endif /* VANILLA_NACL */
