/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include "DHT.h"
#include "stdbool.h"

#define MAX_GCA_SAVED_ANNOUNCES_PER_GC 100
#define GC_ANNOUNCE_SAVING_TIMEOUT 30
#define MAX_ANNOUNCED_TCP_RELAYS 1
#define MAX_SENT_ANNOUNCES 4
#define GC_ANNOUNCE_MIN_SIZE (ENC_PUBLIC_KEY + 2)
#define GC_ANNOUNCE_MAX_SIZE (sizeof(GC_Announce))
#define GC_PUBLIC_ANNOUNCE_MAX_SIZE (sizeof(GC_Public_Announce))


typedef struct GC_Announce GC_Announce;
typedef struct GC_Peer_Announce GC_Peer_Announce;
typedef struct GC_Announces GC_Announces;
typedef struct GC_Announces_List GC_Announces_List;
typedef struct GC_Public_Announce GC_Public_Announce;

// Base announce
struct GC_Announce {
    Node_format tcp_relays[MAX_ANNOUNCED_TCP_RELAYS];
    uint8_t tcp_relays_count;
    uint8_t ip_port_is_set;
    IP_Port ip_port;
    uint8_t peer_public_key[ENC_PUBLIC_KEY];
};

// Peer announce for specific group
struct GC_Peer_Announce {
    GC_Announce base_announce;

    uint64_t timestamp;
};

// Used for announces in public groups
struct GC_Public_Announce {
    GC_Announce base_announce;

    uint8_t chat_public_key[ENC_PUBLIC_KEY];
};

struct GC_Announces {
    uint8_t chat_id[CHAT_ID_SIZE];
    uint64_t index;
    uint64_t last_announce_received_timestamp;

    GC_Peer_Announce announces[MAX_GCA_SAVED_ANNOUNCES_PER_GC];

    GC_Announces *next_announce;
    GC_Announces *prev_announce;
};

struct GC_Announces_List {
    GC_Announces *announces;
    int announces_count;
};


GC_Announces_List *new_gca_list();

void kill_gca(GC_Announces_List *announces_list);

void do_gca(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list);

bool cleanup_gca(GC_Announces_List *announces_list, const uint8_t *chat_id);


int get_gc_announces(GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                     const uint8_t *chat_id, const uint8_t *except_public_key);

GC_Peer_Announce* add_gc_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list, const GC_Public_Announce *announce);

int pack_announce(uint8_t *data, uint16_t length, GC_Announce *announce);

int unpack_announce(uint8_t *data, uint16_t length, GC_Announce *announce);

int pack_announces_list(uint8_t *data, uint16_t length, GC_Announce *announces, uint8_t announces_count,
                        size_t *processed);

int unpack_announces_list(uint8_t *data, uint16_t length, GC_Announce *announces, uint8_t max_announces_count,
                          size_t *processed);

int pack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce);

int unpack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce);

bool is_valid_announce(const GC_Announce *announce);

#endif /* GROUP_ANNOUNCE_H */
