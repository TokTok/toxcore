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

#include "forwarding.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "DHT.h"

struct Forwarding {
    Networking_Core *net;

    forward_request_cb *forward_request_cb;
    void *forward_request_callback_object;
};

int prepend_ip_port(uint8_t *out, uint16_t out_length, IP_Port ip_port, const uint8_t *data, uint16_t length)
{
    if (out_length < MAX_PACKED_IPPORT_SIZE) {
        return -1;
    }

    int ipport_length = pack_ip_port(out, MAX_PACKED_IPPORT_SIZE, &ip_port, true);

    if (ipport_length == -1) {
        return -1;
    }

    if (out_length < ipport_length + length) {
        return -1;
    }

    memcpy(out + ipport_length, data, length);

    return ipport_length + length;
}

/* Encrypt and send unencrypted forwarding packet.
 * Encryption is with a fresh random symmetric key and the zero nonce.
 *
 * return true on success, false otherwise.
 */
static bool send_forwarding_packet(Networking_Core *net, IP_Port dest, const uint8_t *plain,
                                   uint16_t length)
{
    const uint16_t len = 1 + CRYPTO_SYMMETRIC_KEY_SIZE + length + CRYPTO_MAC_SIZE;

    if (len > FORWARDING_MAX_PACKET_SIZE) {
        return false;
    }

    VLA(uint8_t, packet, len);
    const uint8_t zero_nonce[CRYPTO_NONCE_SIZE] = {0};

    packet[0] = NET_PACKET_FORWARDING;
    new_symmetric_key(packet + 1);

    if (encrypt_data_symmetric(packet + 1, zero_nonce, plain, length,
                               packet + 1 + CRYPTO_SYMMETRIC_KEY_SIZE) !=
            length + CRYPTO_MAC_SIZE) {
        return false;
    }

    return (sendpacket(net, dest, packet, len) == len);
}

bool handle_forward_request(const Forwarding *forwarding, IP_Port source, const uint8_t *packet, uint16_t length)
{
    if (length > FORWARD_REQUEST_MAX_PACKET_SIZE) {
        return false;
    }

    IP_Port dest;
    int ipport_length = unpack_ip_port(&dest, packet, length, true, true);

    if (ipport_length == -1) {
        return false;
    }

    VLA(uint8_t, plain, length - ipport_length + MAX_PACKED_IPPORT_SIZE);

    int plain_length = prepend_ip_port(plain, SIZEOF_VLA(plain), source, packet + ipport_length, length - ipport_length);

    if (plain_length == -1) {
        return false;
    }

    if (!net_family_is_ipv4(dest.ip.family) && !net_family_is_ipv6(dest.ip.family)) {
        return (forwarding->forward_request_cb &&
                forwarding->forward_request_cb(forwarding->forward_request_callback_object, dest, plain, plain_length));
    }

    return send_forwarding_packet(forwarding->net, dest, plain, plain_length);
}

static int handle_forward_request_direct(void *object, IP_Port source, const uint8_t *packet, uint16_t length,
        void *userdata)
{
    if (!handle_forward_request((Forwarding *)object, source, packet + 1, length - 1)) {
        return 1;
    }

    return 0;
}

void set_callback_forward_request_not_inet(Forwarding *forwarding, forward_request_cb *function, void *object)
{
    forwarding->forward_request_cb = function;
    forwarding->forward_request_callback_object = object;
}

Forwarding *new_forwarding(Networking_Core *net)
{
    if (net == nullptr) {
        return nullptr;
    }

    Forwarding *forwarding = (Forwarding *)calloc(1, sizeof(Forwarding));

    if (forwarding == nullptr) {
        return nullptr;
    }

    forwarding->net = net;

    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REQUEST, &handle_forward_request_direct, forwarding);

    return forwarding;
}

void kill_forwarding(Forwarding *forwarding)
{
    if (forwarding == nullptr) {
        return;
    }

    networking_registerhandler(forwarding->net, NET_PACKET_FORWARD_REQUEST, nullptr, nullptr);

    free(forwarding);
}
