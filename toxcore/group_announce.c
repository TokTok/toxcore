#include <wchar.h>
#include "group_announce.h"

#ifndef VANILLA_NACL

GC_Announces_List *new_gca_list()
{
    GC_Announces_List *announces_list = (GC_Announces_List *)calloc(0, sizeof(GC_Announce));

    if (announces_list) {
        // TODO: process?
    }

    return announces_list;
}

void kill_gca(GC_Announces_List *announces_list)
{
    free(announces_list->announces);
    free(announces_list);
    announces_list = NULL;
}

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_gca_nodes(uint8_t *data, uint16_t length, const GC_Announce_Node *nodes, uint32_t number)
{
    uint32_t i;
    int packed_length = 0;

    for (i = 0; i < number; ++i) {
        int ipp_size = pack_ip_port(data + packed_length, length - packed_length, &nodes[i].ip_port);

        if (ipp_size == -1) {
            return -1;
        }

        packed_length += ipp_size;

        if (packed_length + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(data + packed_length, nodes[i].public_key, ENC_PUBLIC_KEY);
        packed_length += ENC_PUBLIC_KEY;
    }

    return packed_length;
}

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_gca_nodes(GC_Announce_Node *nodes, uint32_t max_num_nodes, uint16_t *processed_data_len,
                     const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_nodes && len_processed < length) {
        int ipp_size = unpack_ip_port(&nodes[num].ip_port, data + len_processed, length - len_processed, tcp_enabled);

        if (ipp_size == -1) {
            return -1;
        }

        len_processed += ipp_size;

        if (len_processed + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(nodes[num].public_key, data + len_processed, ENC_PUBLIC_KEY);
        len_processed += ENC_PUBLIC_KEY;
        ++num;
    }

    if (processed_data_len) {
        *processed_data_len = len_processed;
    }

    return num;
}

/* Creates a GC_Announce_Node using public_key and your own IP_Port struct
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int make_self_gca_node(const DHT *dht, GC_Announce_Node *node, const uint8_t *public_key)
{
    if (ipport_self_copy(dht, &node->ip_port) == -1) {
        return -1;
    }

    memcpy(node->public_key, public_key, ENC_PUBLIC_KEY);
    return 0;
}

static GC_Announces* get_announces_by_chat_id(GC_Announces_List *gc_announces_list,  const uint8_t *chat_id)
{
    int i;
    for (i = 0; i < gc_announces_list->announces_count; i++) {
        if (!memcmp(gc_announces_list->announces[i].chat_id, chat_id, ENC_PUBLIC_KEY)) {
            return &gc_announces_list->announces[i];
        }
    }

    return NULL;
}

int get_gc_announces(GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                         const uint8_t *chat_id)
{
    if (!gc_announces || !gc_announces_list || !chat_id || !max_nodes) {
        return -1;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, chat_id);
    if (!announces) {
        return 0;
    }

    // TODO: add proper selection
    int gc_announces_count = 0, announce_size = sizeof(GC_Announce), i;
    GC_Announce *curr_announce = gc_announces;
    for (i = 0; i < announces->index && i < max_nodes; i++) {
        memcpy(curr_announce, &announces->announces[i], announce_size);
        curr_announce += announce_size;
        gc_announces_count++;
    }

    return gc_announces_count;
}

#endif /* VANILLA_NACL */
