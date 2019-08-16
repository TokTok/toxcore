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
#ifndef C_TOXCORE_TOXCORE_FORWARDERS_H
#define C_TOXCORE_TOXCORE_FORWARDERS_H

#include "DHT.h"
#include "net_crypto.h"
#include "mono_time.h"

typedef struct Forwarders Forwarders;

/* Send data of length to a random forwarder for forwarding to dest.
 * Maximum length of data is MAX_FORWARD_DATA_SIZE.
 *
 * return true on success, false otherwise.
 */
bool send_forward_request(Forwarders *forwarders, IP_Port dest, const uint8_t *data, uint16_t length);

/* Send data of length to forwarder for forwarding to dest.
 * Maximum length of data is MAX_FORWARD_DATA_SIZE.
 *
 * return true on success, false otherwise.
 */
bool send_forward_request_to(const Forwarders *forwarders, IP_Port forwarder, IP_Port dest, const uint8_t *data,
                             uint16_t length);

/* Set callback to handle a forwarded packet.
 *
 * Callback should return true if the forwarded packet is a reply to a
 * previously sent packet (indicating that the forwarder is functional), false
 * otherwise.
 *
 * To reply to the packet, callback should use send_forward_request_to() to send a reply
 * forwarded via forwarder.
 */
typedef bool forwarded_cb(void *object, IP_Port sender, IP_Port forwarder, const uint8_t *data, uint16_t length,
                          void *userdata);
void set_callback_forwarded(Forwarders *forwarders, forwarded_cb *function, void *object);

Forwarders *new_forwarders(Mono_Time *mono_time, DHT *dht, Net_Crypto *c);

void kill_forwarders(Forwarders *forwarders);

#endif
