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

#endif /* VANILLA_NACL */
