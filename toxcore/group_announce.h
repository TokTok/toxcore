/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Similar to ping.h, but designed for group chat purposes
 */
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include "DHT.h"
#include "stdbool.h"

#define MAX_GCA_SAVED_ANNOUNCES_PER_GC 100
#define GC_ANNOUNCE_PACKED_SIZE (sizeof(GC_Peer_Announce))
#define GC_ANNOUNCE_SAVING_TIMEOUT 30
#define MAX_ANNOUNCED_TCP_RELAYS 1

typedef struct GC_Announce_Node {
    uint8_t public_key[ENC_PUBLIC_KEY];
    IP_Port ip_port;
} GC_Announce_Node;

typedef struct GC_Peer_Announce GC_Peer_Announce;
typedef struct GC_Announces GC_Announces;
typedef struct GC_Announces_List GC_Announces_List;
typedef struct GC_Public_Announce GC_Public_Announce;

struct GC_Peer_Announce {
    uint64_t timestamp;
    Node_format node; // TODO: array?
    IP_Port peer_ip_port;
    uint8_t peer_public_key[ENC_PUBLIC_KEY];
};

// Used for announces in public groups
struct GC_Public_Announce {
    Node_format tcp_relays[MAX_ANNOUNCED_TCP_RELAYS];
    uint8_t tcp_relays_count;
    uint8_t chat_public_key[ENC_PUBLIC_KEY];
    uint8_t peer_public_key[ENC_PUBLIC_KEY];
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


int get_gc_announces(GC_Announces_List *gc_announces_list, GC_Peer_Announce *gc_announces, uint8_t max_nodes,
                     const uint8_t *chat_id, const uint8_t *except_public_key);

GC_Peer_Announce* add_gc_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list, const GC_Public_Announce *announce);

int pack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce);

bool unpack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce);

#endif /* GROUP_ANNOUNCE_H */
