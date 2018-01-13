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

#define MAX_GCA_SELF_REQUESTS 30
#define MAX_GCA_SAVED_ANNOUNCES_PER_GC 100
#define GC_ANNOUNCE_PACKED_SIZE (sizeof(Node_format) + ENC_PUBLIC_KEY)

typedef struct {
    uint8_t public_key[ENC_PUBLIC_KEY];
    IP_Port ip_port;
} GC_Announce_Node;

typedef struct GC_Announce GC_Announce;
typedef struct GC_Announces GC_Announces;
typedef struct GC_Announces_List GC_Announces_List;

struct GC_Announce {
    uint64_t timestamp;
    Node_format node;
    uint8_t gc_public_key[ENC_PUBLIC_KEY];
    uint8_t peer_public_key[ENC_PUBLIC_KEY];
};

struct GC_Announces {
    uint8_t chat_id[CHAT_ID_SIZE];
    uint64_t index;

    GC_Announce announces[MAX_GCA_SAVED_ANNOUNCES_PER_GC];
};

struct GC_Announces_List {
    GC_Announces *announces;
    int announces_count;
};


GC_Announces_List *new_gca_list();

void kill_gca(GC_Announces_List *announces_list);

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_gca_nodes(uint8_t *data, uint16_t length, const GC_Announce_Node *nodes, uint32_t number);

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_gca_nodes(GC_Announce_Node *nodes, uint32_t max_num_nodes, uint16_t *processed_data_len,
                     const uint8_t *data, uint16_t length, uint8_t tcp_enabled);

/* Creates a GC_Announce_Node using client_id and your own IP_Port struct
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int make_self_gca_node(const DHT *dht, GC_Announce_Node *node, const uint8_t *client_id);


int get_gc_announces(GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                     const uint8_t *chat_id, const uint8_t *except_public_key);

GC_Announce* add_gc_announce(GC_Announces_List *gc_announces_list, const uint8_t *node, const uint8_t *node_pk,
                             const uint8_t *chat_id, const uint8_t *peer_id);


//TODO: pack && unpack announces?

#endif /* GROUP_ANNOUNCE_H */
