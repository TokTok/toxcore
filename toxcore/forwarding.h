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
#ifndef C_TOXCORE_TOXCORE_FORWARDING_H
#define C_TOXCORE_TOXCORE_FORWARDING_H

#include "crypto_core.h"
#include "network.h"

#define MAX_PACKED_IPPORT_SIZE (1 + SIZE_IP6 + sizeof(uint16_t))

#define MAX_FORWARD_DATA_SIZE 4096

#define FORWARD_REQUEST_MAX_PACKET_SIZE (1 + MAX_PACKED_IPPORT_SIZE + MAX_FORWARD_DATA_SIZE)
#define FORWARDING_MAX_PACKET_SIZE (1 + CRYPTO_SHARED_KEY_SIZE + MAX_PACKED_IPPORT_SIZE + MAX_FORWARD_DATA_SIZE + CRYPTO_MAC_SIZE)

typedef struct Forwarding Forwarding;

/* Write packed ip_port followed by data to out.
 * Fail if the total length is more than out_length.
 *
 * return output length, or -1 on failure.
 */
int prepend_ip_port(uint8_t *out, uint16_t out_length, IP_Port ip_port, const uint8_t *data, uint16_t length);

/* Handle forward request packet.
 * Intended for use by TCP server when handling forward requests.
 *
 * return true on success, false otherwise.
 */
bool handle_forward_request(const Forwarding *forwarding, IP_Port source, const uint8_t *packet, uint16_t length);

/* Set callback to handle a forward request when the dest ip_port doesn't have
 * TOX_AF_INET6 or TOX_AF_INET as the family.
 */
typedef bool forward_request_cb(void *object, IP_Port dest, const uint8_t *data, uint16_t length);
void set_callback_forward_request_not_inet(Forwarding *forwarding, forward_request_cb *function, void *object);

Forwarding *new_forwarding(Networking_Core *net);

void kill_forwarding();

#endif
