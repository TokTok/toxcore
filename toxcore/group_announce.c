#include "group_announce.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>

#include "util.h"


static void remove_announces(GC_Announces_List *gc_announces_list, GC_Announces *announces) {
    if (announces->prev_announce) {
        announces->prev_announce->next_announce = announces->next_announce;
    } else {
        gc_announces_list->announces = announces->next_announce;
    }

    if (announces->next_announce) {
        announces->next_announce->prev_announce = announces->prev_announce;
    }

    free(announces);
    gc_announces_list->announces_count--;
}

GC_Announces_List *new_gca_list()
{
    GC_Announces_List *announces_list = (GC_Announces_List*)calloc(1, sizeof(GC_Announces_List));

    return announces_list;
}

void kill_gca(GC_Announces_List *announces_list)
{
    while (announces_list->announces) {
        remove_announces(announces_list, announces_list->announces);
    }

    free(announces_list);
}

void do_gca(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list) {
    if (!gc_announces_list) {
        return;
    }

    GC_Announces *announces = gc_announces_list->announces;
    while (announces) {
        if (announces->last_announce_received_timestamp <= mono_time_get(mono_time) - GC_ANNOUNCE_SAVING_TIMEOUT) {
            GC_Announces *announces_to_delete = announces;
            announces = announces->next_announce;
            remove_announces(gc_announces_list, announces_to_delete);

            continue;
        }

        announces = announces->next_announce;
    }
}

static GC_Announces* get_announces_by_chat_id(const GC_Announces_List *gc_announces_list,  const uint8_t *chat_id)
{
    GC_Announces *announces = gc_announces_list->announces;
    while (announces) {
        if (!memcmp(announces->chat_id, chat_id, CHAT_ID_SIZE)) {
            return announces;
        }

        announces = announces->next_announce;
    }

    return nullptr;
}

bool cleanup_gca(GC_Announces_List *gc_announces_list, const uint8_t *chat_id) {
    if (!gc_announces_list || !chat_id) {
        return false;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, chat_id);
    if (announces) {
        remove_announces(gc_announces_list, announces);

        return true;
    }

    return false;
}

int get_gc_announces(GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                     const uint8_t *chat_id, const uint8_t *except_public_key)
{
    if (!gc_announces || !gc_announces_list || !chat_id || !max_nodes || !except_public_key) {
        return -1;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, chat_id);
    if (!announces) {
        return 0;
    }

    // TODO: add proper selection
    int gc_announces_count = 0, i, j;
    for (i = 0; i < announces->index && i < MAX_GCA_SAVED_ANNOUNCES_PER_GC && gc_announces_count < max_nodes; i++) {
        int index = i % MAX_GCA_SAVED_ANNOUNCES_PER_GC;
        if (!memcmp(except_public_key, &announces->announces[index].base_announce.peer_public_key, ENC_PUBLIC_KEY)) {
            continue;
        }

        bool already_added = false;
        for (j = 0; j < gc_announces_count; j++) {
            if (!memcmp(&gc_announces[j].peer_public_key,
                        &announces->announces[index].base_announce.peer_public_key,
                        ENC_PUBLIC_KEY)) {
                already_added = true;
                break;
            }
        }

        if (!already_added) {
            memcpy(&gc_announces[gc_announces_count], &announces->announces[index], sizeof(GC_Announce));
            gc_announces_count++;
        }
    }

    return gc_announces_count;
}

int pack_announce(uint8_t *data, uint16_t length, GC_Announce *announce)
{
    if (!data || !announce || length < GC_ANNOUNCE_MAX_SIZE) {
        return -1;
    }

    uint16_t offset = 0;
    memcpy(data + offset, announce->peer_public_key, ENC_PUBLIC_KEY);
    offset += ENC_PUBLIC_KEY;

    data[offset] = announce->ip_port_is_set;
    offset++;

    data[offset] = announce->tcp_relays_count;
    offset++;

    if (announce->ip_port_is_set) {
        int ip_port_length = pack_ip_port(data + offset, length - offset, &announce->ip_port);
        if (ip_port_length == -1) {
            return -1;
        }

        offset += ip_port_length;
    }

    int nodes_length = pack_nodes(data + offset, length - offset, announce->tcp_relays, announce->tcp_relays_count);
    if (nodes_length == -1) {
        return -1;
    }

    return nodes_length + offset;
}

int unpack_announce(uint8_t *data, uint16_t length, GC_Announce *announce)
{
    if (!data || !announce || length < GC_ANNOUNCE_MIN_SIZE) {
        return -1;
    }

    uint16_t offset = 0;
    memcpy(announce->peer_public_key, data + offset, ENC_PUBLIC_KEY);
    offset += ENC_PUBLIC_KEY;

    announce->ip_port_is_set = data[offset];
    offset++;

    announce->tcp_relays_count = data[offset];
    offset++;

    if (announce->tcp_relays_count > MAX_ANNOUNCED_TCP_RELAYS) {
        return -1;
    }

    if (announce->ip_port_is_set) {
        int ip_port_length = unpack_ip_port(&announce->ip_port, data + offset, length - offset, 0);
        if (ip_port_length == -1) {
            return -1;
        }

        offset += ip_port_length;
    }

    uint16_t nodes_length;
    int nodes_count = unpack_nodes(announce->tcp_relays,announce->tcp_relays_count, &nodes_length,
                                   data + offset, length - offset, 1);
    if (nodes_count != announce->tcp_relays_count) {
        return -1;
    }

    return offset + nodes_length;
}

int pack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce)
{
    if (!announce || !data || length < CHAT_ID_SIZE) {
        return -1;
    }

    memcpy(data, announce->chat_public_key, CHAT_ID_SIZE);

    int packed_size = pack_announce(data + CHAT_ID_SIZE, length - CHAT_ID_SIZE, &announce->base_announce);
    if (packed_size < 0) {
        return -1;
    }

    return packed_size + CHAT_ID_SIZE;
}

int unpack_public_announce(uint8_t *data, uint16_t length, GC_Public_Announce *announce)
{
    if (length < CHAT_ID_SIZE || !announce || !data) {
        return -1;
    }

    memcpy(announce->chat_public_key, data, CHAT_ID_SIZE);

    int base_announce_size = unpack_announce(data + ENC_PUBLIC_KEY, length - ENC_PUBLIC_KEY, &announce->base_announce);
    if (base_announce_size == -1) {
        return -1;
    }

    return base_announce_size + CHAT_ID_SIZE;
}

int pack_announces_list(uint8_t *data, uint16_t length, GC_Announce *announces, uint8_t announces_count,
                        size_t *processed)
{
    if (!data || !announces) {
        return -1;
    }

    uint16_t offset = 0;
    int i;

    for (i = 0; i < announces_count; i++) {
        int packed_length = pack_announce(data + offset, length - offset, &announces[i]);
        if (packed_length == -1) {
            return -1;
        }

        offset += packed_length;
    }

    if (processed) {
        *processed = offset;
    }

    return announces_count;
}

int unpack_announces_list(uint8_t *data, uint16_t length, GC_Announce *announces, uint8_t max_announces_count,
                          size_t *processed)
{
    if (!data || !announces) {
        return -1;
    }

    uint16_t offset = 0;
    int i, announces_count = 0;

    for (i = 0; i < max_announces_count && length > offset; i++) {
        int unpacked_length = unpack_announce(data + offset, length - offset, &announces[i]);
        if (unpacked_length == -1) {
            fprintf(stderr, "unpack error: %d %d\n", length, offset);
            return -1;
        }

        offset += unpacked_length;
        announces_count++;
    }

    if (processed) {
        *processed = offset;
    }

    return announces_count;
}

GC_Peer_Announce* add_gc_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list, const GC_Public_Announce *announce)
{
    if (!gc_announces_list || !announce) {
        return nullptr;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, announce->chat_public_key);
    if (!announces) {
        gc_announces_list->announces_count++;
        announces = (GC_Announces*)malloc(sizeof(GC_Announces));
        announces->index = 0;
        announces->prev_announce = nullptr;
        if (gc_announces_list->announces) {
            gc_announces_list->announces->prev_announce = announces;
        }
        announces->next_announce = gc_announces_list->announces;
        gc_announces_list->announces = announces;
        memcpy(announces->chat_id, announce->chat_public_key, CHAT_ID_SIZE);
    }
    uint64_t index = announces->index % MAX_GCA_SAVED_ANNOUNCES_PER_GC;
    announces->last_announce_received_timestamp = mono_time_get(mono_time);
    GC_Peer_Announce *gc_peer_announce = &announces->announces[index];
    memcpy(&gc_peer_announce->base_announce, &announce->base_announce, sizeof(GC_Announce));
    gc_peer_announce->timestamp = mono_time_get(mono_time);
    announces->index++;
    // TODO; lock
    return gc_peer_announce;
}

bool is_valid_announce(const GC_Announce *announce)
{
    if (!announce) {
        return false;
    }

    return announce->tcp_relays_count || announce->ip_port_is_set;
}
