/*
 * Copyright © 2019 The TokTok team.
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
#endif

#include "forwarders.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "forwarding.h"
#include "mono_time.h"

#define FORWARDER_RESPONSE_TIMEOUT 10
#define MAX_FORWARD_USE_NO_RESPONSE 2

#define NUM_FORWARDERS 8


typedef struct Forwarder_Info {
    IP_Port ip_port;
    bool set;
    uint16_t no_response_times;
    uint64_t no_response_last_used;
} Forwarder_Info;

struct Forwarders {
    Mono_Time *mono_time;
    DHT *dht;
    Networking_Core *net;
    Net_Crypto *c;

    Forwarder_Info forwarder_infos[NUM_FORWARDERS];

    forwarded_cb *forwarded_cb;
    void *forwarded_callback_object;
};

/* Put random forwarder in forwarder.
 * Uses either a known good forwarder, or a random DHT node or TCP connection.
 *
 * return true on success, false otherwise.
 */
static bool get_forwarder(Forwarders *forwarders, IP_Port *forwarder)
{
    Forwarder_Info *forwarder_info = &forwarders->forwarder_infos[random_u32() % NUM_FORWARDERS];

    if (forwarder_info->set &&
            (forwarder_info->no_response_times < MAX_FORWARD_USE_NO_RESPONSE ||
             !mono_time_is_timeout(forwarders->mono_time,
                                   forwarder_info->no_response_last_used, FORWARDER_RESPONSE_TIMEOUT))) {
        *forwarder = forwarder_info->ip_port;

        if (forwarder_info->no_response_times < MAX_FORWARD_USE_NO_RESPONSE) {
            forwarder_info->no_response_last_used = mono_time_get(forwarders->mono_time);
        }

        ++forwarder_info->no_response_times;
        return true;
    }

    if (dht_isconnected(forwarders->dht)) {
        if (random_dht_node_ip_port(forwarders->dht, forwarder)) {
            return true;
        }
    }

    /* TODO(zugz): need to tell TCP_connection that we want connections
     * available if we can't connect to the DHT. Currently this is done by the
     * onion, using set_tcp_onion_status, but when we disable the onion we
     * will need to replicate this.
     */
    int random_tcp = get_random_tcp_con_number(forwarders->c);

    if (random_tcp == -1) {
        return false;
    }

    *forwarder = tcp_connections_number_to_ip_port(random_tcp);
    return true;
}

/* Add new forwarder, or note that existing forwarder has responded.
 */
static void add_forwarder(Forwarders *forwarders, IP_Port forwarder)
{
    Forwarder_Info *update = &forwarders->forwarder_infos[random_u08() % NUM_FORWARDERS];

    for (unsigned i = 0; i < NUM_FORWARDERS; ++i) {
        Forwarder_Info *forwarder_info = &forwarders->forwarder_infos[i];

        if (forwarder_info->set && ipport_equal(&forwarder_info->ip_port, &forwarder)) {
            forwarder_info->no_response_times = 0;
            return;
        }

        if (!forwarder_info->set ||
                (forwarder_info->no_response_times > 0 &&
                 (update->no_response_times == 0 ||
                  forwarder_info->no_response_last_used < update->no_response_last_used))) {
            update = forwarder_info;
        }
    }

    update->set = true;
    update->ip_port = forwarder;
    update->no_response_times = 0;
}


static int handle_plain_forwarding(Forwarders *forwarders, const uint8_t *data, uint16_t length, IP_Port forwarder,
                                   void *userdata)
{
    IP_Port sender;
    int ipport_length = unpack_ip_port(&sender, data, length, true, true);

    if (ipport_length == -1) {
        return 1;
    }

    if (!forwarders->forwarded_cb) {
        return 1;
    }

    if (forwarders->forwarded_cb(forwarders->forwarded_callback_object, sender, forwarder, data + ipport_length,
                                 length - ipport_length, userdata)) {
        add_forwarder(forwarders, forwarder);
    }

    return 0;
}

static int handle_plain_forwarding_cb(void *object, const uint8_t *data, uint16_t length, IP_Port forwarder,
                                      void *userdata)
{
    return handle_plain_forwarding((Forwarders *)object, data, length, forwarder, userdata);
}

static int handle_forwarding(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Forwarders *forwarders = (Forwarders *)object;

    if (length > FORWARDING_MAX_PACKET_SIZE || length < 1 + CRYPTO_SYMMETRIC_KEY_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    const uint8_t zero_nonce[CRYPTO_NONCE_SIZE] = {0};

    const uint16_t plain_length = length - 1 - CRYPTO_SYMMETRIC_KEY_SIZE - CRYPTO_MAC_SIZE;
    VLA(uint8_t, plain, plain_length);

    int len = decrypt_data_symmetric(packet + 1, zero_nonce, packet + 1 + CRYPTO_SYMMETRIC_KEY_SIZE,
                                     length - 1 - CRYPTO_SYMMETRIC_KEY_SIZE, plain);

    if (len != plain_length) {
        return 1;
    }

    return handle_plain_forwarding(forwarders, plain, len, source, userdata);
}

static bool send_forward_request_packet(Networking_Core *net, IP_Port forwarder, const uint8_t *data, uint16_t length)
{
    const uint16_t len = 1 + length;

    if (len > FORWARD_REQUEST_MAX_PACKET_SIZE) {
        return false;
    }

    VLA(uint8_t, packet, len);
    packet[0] = NET_PACKET_FORWARD_REQUEST;
    memcpy(packet + 1, data, length);
    return (sendpacket(net, forwarder, packet, len) == len);
}

bool send_forward_request_to(const Forwarders *forwarders, IP_Port forwarder, IP_Port dest, const uint8_t *data,
                             uint16_t length)
{
    VLA(uint8_t, request, length + MAX_PACKED_IPPORT_SIZE);

    int request_length = prepend_ip_port(request, SIZEOF_VLA(request), dest, data, length);

    unsigned int tcp_connection_number;

    if (ip_port_to_tcp_connections_number(forwarder, &tcp_connection_number)) {
        return (tcp_send_forward_request(nc_get_tcp_c(forwarders->c), tcp_connection_number, request,
                                         request_length) == 0);
    }

    return send_forward_request_packet(forwarders->net, forwarder, request, request_length);
}

bool send_forward_request(Forwarders *forwarders, IP_Port dest, const uint8_t *data, uint16_t length)
{
    IP_Port forwarder;

    if (!get_forwarder(forwarders, &forwarder)) {
        return false;
    }

    return send_forward_request_to(forwarders, forwarder, dest, data, length);
}

void set_callback_forwarded(Forwarders *forwarders, forwarded_cb *function, void *object)
{
    forwarders->forwarded_cb = function;
    forwarders->forwarded_callback_object = object;
}

Forwarders *new_forwarders(Mono_Time *mono_time, DHT *dht, Net_Crypto *c)
{
    if (mono_time == nullptr || dht == nullptr || c == nullptr) {
        return nullptr;
    }

    Forwarders *forwarders = (Forwarders *)calloc(1, sizeof(Forwarders));

    if (forwarders == nullptr) {
        return nullptr;
    }

    forwarders->mono_time = mono_time;
    forwarders->dht = dht;
    forwarders->c = c;
    forwarders->net = dht_get_net(dht);

    networking_registerhandler(forwarders->net, NET_PACKET_FORWARDING, &handle_forwarding, forwarders);

    set_forwarding_packet_tcp_connection_callback(nc_get_tcp_c(forwarders->c), &handle_plain_forwarding_cb, forwarders);

    return forwarders;
}

void kill_forwarders(Forwarders *forwarders)
{
    if (forwarders == nullptr) {
        return;
    }

    networking_registerhandler(forwarders->net, NET_PACKET_FORWARDING, nullptr, nullptr);

    set_forwarding_packet_tcp_connection_callback(nc_get_tcp_c(forwarders->c), nullptr, nullptr);

    free(forwarders);
}

// TODO(zugz): saving?
