/* group_chats.c
 *
 * An implementation of massive text only group chats.
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "TCP_connection.h"
#include "group_chats.h"
#include "group_announce.h"
#include "group_connection.h"
#include "group_moderation.h"
#include "LAN_discovery.h"
#include "util.h"
#include "Messenger.h"
#include "friend_connection.h"

#include <sodium.h>

enum {
    GC_MAX_PACKET_PADDING = 8,
#define GC_PACKET_PADDING_LENGTH(length) (((MAX_GC_PACKET_SIZE - (length)) % GC_MAX_PACKET_PADDING))

    GC_PLAIN_HS_PACKET_SIZE = sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + SIG_PUBLIC_KEY\
                                  + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t),

    GC_ENCRYPTED_HS_PACKET_SIZE = sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE
                                  + GC_PLAIN_HS_PACKET_SIZE + CRYPTO_MAC_SIZE,

    GC_PACKED_SHARED_STATE_SIZE = EXT_PUBLIC_KEY + sizeof(uint32_t) + MAX_GC_GROUP_NAME_SIZE + sizeof(uint16_t)
                                  + sizeof(uint8_t) + sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE
                                  + GC_MODERATION_HASH_SIZE + sizeof(uint32_t),

    /* Minimum size of a topic packet; includes topic length, public signature key, and the topic version */
    GC_MIN_PACKED_TOPIC_INFO_SIZE = sizeof(uint16_t) + SIG_PUBLIC_KEY + sizeof(uint32_t),

    GC_SHARED_STATE_ENC_PACKET_SIZE = HASH_ID_BYTES + SIGNATURE_SIZE + GC_PACKED_SHARED_STATE_SIZE,

    /* Header information attached to all broadcast messages. broadcast_type, public key hash, timestamp */
    GC_BROADCAST_ENC_HEADER_SIZE = 1 + HASH_ID_BYTES + TIME_STAMP_SIZE,

    MESSAGE_ID_BYTES = sizeof(uint64_t),

    MIN_GC_LOSSLESS_PACKET_SIZE = sizeof(uint8_t) + MESSAGE_ID_BYTES + HASH_ID_BYTES + ENC_PUBLIC_KEY
                                  + CRYPTO_NONCE_SIZE + sizeof(uint8_t) + CRYPTO_MAC_SIZE,

    MIN_GC_LOSSY_PACKET_SIZE = MIN_GC_LOSSLESS_PACKET_SIZE - MESSAGE_ID_BYTES,

    MAX_GC_PACKET_SIZE = 65507,

    /* approximation of the sync response packet size limit */
    MAX_GC_NUM_PEERS = MAX_GC_PACKET_SIZE / (ENC_PUBLIC_KEY + sizeof(IP_Port)),

    /* Size of a ping packet which contains a peer count, the shared state version,
     * the sanctions list version and the topic version
     */
    GC_PING_PACKET_DATA_SIZE = sizeof(uint32_t) * 4,
};

static bool group_number_valid(const GC_Session *c, int group_number);
static int peer_add(Messenger *m, int group_number, IP_Port *ipp, const uint8_t *public_key);
static int peer_update(Messenger *m, int group_number, GC_GroupPeer *peer, uint32_t peer_number);
static int group_delete(GC_Session *c, GC_Chat *chat);
static void group_cleanup(GC_Session *c, GC_Chat *chat);
static int get_nick_peer_number(const GC_Chat *chat, const uint8_t *nick, uint16_t length);
static bool group_exists(const GC_Session *c, const uint8_t *chat_id);
static int save_tcp_relay(GC_Connection *gconn, Node_format *node);
int gcc_copy_tcp_relay(GC_Connection *gconn, Node_format *node);
static void add_tcp_relays_to_chat(Messenger *m, GC_Chat *chat);


typedef enum {
    GH_REQUEST,
    GH_RESPONSE
} GROUP_HANDSHAKE_PACKET_TYPE;

typedef enum {
    HS_INVITE_REQUEST,
    HS_PEER_INFO_EXCHANGE
} GROUP_HANDSHAKE_REQUEST_TYPE;


void pack_group_info(GC_Chat *chat, Saved_Group *temp, bool can_use_cached_value)
{
    // copy info from cached save struct if possible (for disconnected groups only)
    if (can_use_cached_value && chat->save) {
        memcpy(temp, chat->save, sizeof(Saved_Group));

        return;
    }

    memset(temp, 0, sizeof(Saved_Group));

    memcpy(temp->founder_public_key, chat->shared_state.founder_public_key, EXT_PUBLIC_KEY);
    temp->group_name_length = net_htons(chat->shared_state.group_name_len);
    memcpy(temp->group_name, chat->shared_state.group_name, MAX_GC_GROUP_NAME_SIZE);
    temp->privacy_state = chat->shared_state.privacy_state;
    temp->maxpeers = net_htons(chat->shared_state.maxpeers);
    temp->password_length = net_htons(chat->shared_state.password_length);
    memcpy(temp->password, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    memcpy(temp->mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE);
    temp->shared_state_version = net_htonl(chat->shared_state.version);
    memcpy(temp->shared_state_signature, chat->shared_state_sig, SIGNATURE_SIZE);

    temp->topic_length = net_htons(chat->topic_info.length);
    memcpy(temp->topic, chat->topic_info.topic, MAX_GC_TOPIC_SIZE);
    memcpy(temp->topic_public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY);
    temp->topic_version = net_htonl(chat->topic_info.version);
    memcpy(temp->topic_signature, chat->topic_sig, SIGNATURE_SIZE);

    memcpy(temp->chat_public_key, chat->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(temp->chat_secret_key, chat->chat_secret_key, EXT_SECRET_KEY);  /* empty for non-founders */

    uint16_t num_addrs = gc_copy_peer_addrs(chat, temp->addrs, GROUP_SAVE_MAX_PEERS);
    temp->num_addrs = net_htons(num_addrs);

    temp->num_mods = net_htons(chat->moderation.num_mods);
    mod_list_pack(chat, temp->mod_list);

    bool is_manually_disconnected = chat->connection_state == CS_MANUALLY_DISCONNECTED;
    temp->group_connection_state = is_manually_disconnected ? SGCS_DISCONNECTED : SGCS_CONNECTED;

    memcpy(temp->self_public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(temp->self_secret_key, chat->self_secret_key, EXT_SECRET_KEY);
    memcpy(temp->self_nick, chat->group[0].nick, MAX_GC_NICK_SIZE);
    temp->self_nick_length = net_htons(chat->group[0].nick_length);
    temp->self_role = chat->group[0].role;
    temp->self_status = chat->group[0].status;
}

static bool is_peer_confirmed(const GC_Chat *chat, const uint8_t *peer_pk)
{
    int i;
    for (i = 0; i < MAX_GC_CONFIRMED_PEERS; i++) {
        if (!memcmp(chat->confirmed_peers[i], peer_pk, ENC_PUBLIC_KEY)) { // peer in our list
            return true;
        }
    }

    return false;
}

static bool is_self_peer_info_valid(const GC_SelfPeerInfo *peer_info)
{
    return peer_info && peer_info->nick_length && peer_info->nick_length <= MAX_GC_NICK_SIZE && peer_info->nick && peer_info->user_status < GS_INVALID;
}

bool is_public_chat(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state == GI_PUBLIC;
}

static GC_Chat *get_chat_by_hash(GC_Session *c, uint32_t hash)
{
    if (!c) {
        return nullptr;
    }

    uint32_t i;

    for (i = 0; i < c->num_chats; i ++) {
        if (c->chats[i].chat_id_hash == hash) {
            return &c->chats[i];
        }
    }

    return nullptr;
}

/* Returns the jenkins hash of a 32 byte public encryption key */
static uint32_t get_peer_key_hash(const uint8_t *public_key)
{
    return jenkins_one_at_a_time_hash(public_key, ENC_PUBLIC_KEY);
}

/* Returns the jenkins hash of a 32 byte chat_id. */
static uint32_t get_chat_id_hash(const uint8_t *chat_id)
{
    return jenkins_one_at_a_time_hash(chat_id, CHAT_ID_SIZE);
}

/* Check if peer with the public encryption key is in peer list.
 *
 * return peer_number if peer is in chat.
 * return -1 if peer is not in chat.
 */
static int get_peernum_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(chat->gcc[i].addr.public_key, public_enc_key, ENC_PUBLIC_KEY) == 0) {
            return i;
        }
    }

    return -1;
}

/* Check if peer with the public signature key is in peer list.
 *
 * return peer_number if peer is in chat.
 * return -1 if peer is not in chat.
 */
static int get_peernum_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(get_sig_pk(chat->gcc[i].addr.public_key), public_sig_key, SIG_PUBLIC_KEY) == 0) {
            return i;
        }
    }

    return -1;
}

/* Validates peer's group role.
 *
 * Returns 0 if role is valid.
 * Returns -1 if role is invalid.
 */
static int validate_gc_peer_role(const GC_Chat *chat, uint32_t peer_number)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].role >= GR_INVALID) {
        return -1;
    }

    switch (chat->group[peer_number].role) {
        case GR_FOUNDER: {
            if (memcmp(chat->shared_state.founder_public_key, gconn->addr.public_key, ENC_PUBLIC_KEY) != 0) {
                return -1;
            }

            break;
        }

        case GR_MODERATOR: {
            if (mod_list_index_of_sig_pk(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
                return -1;
            }

            break;
        }

        case GR_USER: {
            if (sanctions_list_is_observer(chat, gconn->addr.public_key)) {
                return -1;
            }

            break;
        }

        case GR_OBSERVER: {
            /* Don't validate self as this is called when we don't have the sanctions list yet */
            if (!sanctions_list_is_observer(chat, gconn->addr.public_key) && peer_number != 0) {
                return -1;
            }

            break;
        }

        default: {
            return -1;
        }
    }

    return 0;
}

/* Returns true if peer_number exists */
bool peer_number_valid(const GC_Chat *chat, int peer_number)
{
    return peer_number >= 0 && peer_number < chat->numpeers;
}


/* Returns the peer_number of the peer with peer_id.
 * Returns -1 if peer_id is invalid. */
static int get_peer_number_of_peer_id(const GC_Chat *chat, uint32_t peer_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].peer_id == peer_id) {
            return i;
        }
    }

    return -1;
}

/* Returns a new peer ID.
 *
 * These ID's are permanently assigned to a peer when they join the group and should be
 * considered arbitrary values. TODO: This could probably be done a better way.
 */
static uint32_t get_new_peer_id(const GC_Chat *chat)
{
    uint32_t new_id = random_u32();

    while (get_peer_number_of_peer_id(chat, new_id) != -1) {
        new_id = random_u32();
    }

    return new_id;
}

/* Returns true if sender_pk_hash is equal to peers's public key hash */
static bool peer_pk_hash_match(GC_Connection *gconn, uint32_t sender_pk_hash)
{
    return sender_pk_hash == gconn->public_key_hash;
}

static void self_gc_connected(const Mono_Time *mono_time, GC_Chat *chat)
{
    chat->connection_state = CS_CONNECTED;
}

/* Sets the password for the group (locally only).
 *
 * Returns 0 on success.
 * Returns -1 if the password is too long.
 */
static int set_gc_password_local(GC_Chat *chat, const uint8_t *passwd, uint16_t length)
{
    if (length > MAX_GC_PASSWORD_SIZE) {
        return -1;
    }

    if (!passwd || length == 0) {
        chat->shared_state.password_length = 0;
        memset(chat->shared_state.password, 0, MAX_GC_PASSWORD_SIZE);
    } else {
        chat->shared_state.password_length = length;
        memcpy(chat->shared_state.password, passwd, length);
    }

    return 0;
}

/* Expands the chat_id into the extended chat public key (encryption key + signature key)
 * dest must have room for EXT_PUBLIC_KEY bytes.
 */
static int expand_chat_id(uint8_t *dest, const uint8_t *chat_id)
{
    int result = crypto_sign_ed25519_pk_to_curve25519(dest, chat_id);
    memcpy(dest + ENC_PUBLIC_KEY, chat_id, SIG_PUBLIC_KEY);
    return result;
}


/* Copies up to max_addrs peer addresses from chat to addrs.
 *
 * Returns number of addresses copied.
 */
uint16_t gc_copy_peer_addrs(const GC_Chat *chat, GC_SavedPeerInfo *addrs, size_t max_addrs)
{
    uint32_t i;
    uint16_t num = 0;

    for (i = 1; i < chat->numpeers && i < max_addrs; ++i) {
        GC_Connection *gconn = &chat->gcc[i];
        if (gconn->confirmed || chat->connection_state != CS_CONNECTED) {
            gcc_copy_tcp_relay(gconn, &addrs[num].tcp_relay);
            memcpy(&addrs[num].ip_port, &gconn->addr.ip_port, sizeof(IP_Port));
            memcpy(addrs[num].public_key, gconn->addr.public_key, ENC_PUBLIC_KEY);
            num++;
        }
    }

    return num;
}

/* Returns the number of confirmed peers in peerlist */
static uint32_t get_gc_confirmed_numpeers(const GC_Chat *chat)
{
    uint32_t i, count = 0;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            ++count;
        }
    }

    return count;
}

static int sign_gc_shared_state(GC_Chat *chat);
static int broadcast_gc_mod_list(GC_Chat *chat);
static int broadcast_gc_shared_state(GC_Chat *chat);
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key);
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key);

/* Removes the first found offline mod from the mod list.
 * Re-broadcasts the shared state and moderator list on success, as well
 * as the updated sanctions list if necessary.
 *
 * TODO: Make this smarter in who to remove (e.g. the mod who hasn't been seen online in the longest time)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if no mods were removed.
 */
static int prune_gc_mod_list(GC_Chat *chat)
{
    if (chat->moderation.num_mods == 0) {
        return 0;
    }

    const uint8_t *public_sig_key = nullptr;
    size_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (get_peernum_of_sig_pk(chat, chat->moderation.mod_list[i]) == -1) {
            public_sig_key = chat->moderation.mod_list[i];

            if (mod_list_remove_index(chat, i) == -1) {
                public_sig_key = nullptr;
                continue;
            }

            break;
        }
    }

    if (public_sig_key == nullptr) {
        return -1;
    }

    mod_list_make_hash(chat, chat->shared_state.mod_list_hash);

    if (sign_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_mod_list(chat) == -1) {
        return -1;
    }

    if (update_gc_sanctions_list(chat,  public_sig_key) == -1) {
        return -1;
    }

    if (update_gc_topic(chat, public_sig_key) == -1) {
        return -1;
    }

    return 0;
}

/* Size of peer data that we pack for transfer (nick length must be accounted for separately).
 * packed data includes: nick, nick length, status, role
 */
#define PACKED_GC_PEER_SIZE (MAX_GC_NICK_SIZE + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t))

/* Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_GroupPeer *peer)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t packed_len = 0;

    net_pack_u16(data + packed_len, peer->nick_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, peer->nick, MAX_GC_NICK_SIZE);
    packed_len += MAX_GC_NICK_SIZE;
    memcpy(data + packed_len, &peer->status, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    memcpy(data + packed_len, &peer->role, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);

    return packed_len;
}

/* Unpacks peer info of size length into peer.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
static int unpack_gc_peer(GC_GroupPeer *peer, const uint8_t *data, uint16_t length)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t len_processed = 0;

    net_unpack_u16(data + len_processed, &peer->nick_length);
    len_processed += sizeof(uint16_t);
    peer->nick_length = min_u16(MAX_GC_NICK_SIZE, peer->nick_length);
    memcpy(peer->nick, data + len_processed, MAX_GC_NICK_SIZE);
    len_processed += MAX_GC_NICK_SIZE;
    memcpy(&peer->status, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    memcpy(&peer->role, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    return len_processed;
}

/* Packs shared_state into data. data must have room for at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint16_t pack_gc_shared_state(uint8_t *data, uint16_t length, const GC_SharedState *shared_state)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    memcpy(data + packed_len, shared_state->founder_public_key, EXT_PUBLIC_KEY);
    packed_len += EXT_PUBLIC_KEY;
    net_pack_u32(data + packed_len, shared_state->maxpeers);
    packed_len += sizeof(uint32_t);
    net_pack_u16(data + packed_len, shared_state->group_name_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->group_name, MAX_GC_GROUP_NAME_SIZE);
    packed_len += MAX_GC_GROUP_NAME_SIZE;
    memcpy(data + packed_len, &shared_state->privacy_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    net_pack_u16(data + packed_len, shared_state->password_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->password, MAX_GC_PASSWORD_SIZE);
    packed_len += MAX_GC_PASSWORD_SIZE;
    memcpy(data + packed_len, shared_state->mod_list_hash, GC_MODERATION_HASH_SIZE);
    packed_len += GC_MODERATION_HASH_SIZE;
    net_pack_u32(data + packed_len, shared_state->version);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks shared state data into shared_state. data must contain at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns the length of processed data.
 */
static uint16_t unpack_gc_shared_state(GC_SharedState *shared_state, const uint8_t *data, uint16_t length)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t len_processed = 0;

    memcpy(shared_state->founder_public_key, data + len_processed, EXT_PUBLIC_KEY);
    len_processed += EXT_PUBLIC_KEY;
    net_unpack_u32(data + len_processed, &shared_state->maxpeers);
    len_processed += sizeof(uint32_t);
    net_unpack_u16(data + len_processed, &shared_state->group_name_len);
    shared_state->group_name_len = min_u16(shared_state->group_name_len, MAX_GC_GROUP_NAME_SIZE);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->group_name, data + len_processed, MAX_GC_GROUP_NAME_SIZE);
    len_processed += MAX_GC_GROUP_NAME_SIZE;
    memcpy(&shared_state->privacy_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    net_unpack_u16(data + len_processed, &shared_state->password_length);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->password, data + len_processed, MAX_GC_PASSWORD_SIZE);
    len_processed += MAX_GC_PASSWORD_SIZE;
    memcpy(shared_state->mod_list_hash, data + len_processed, GC_MODERATION_HASH_SIZE);
    len_processed += GC_MODERATION_HASH_SIZE;
    net_unpack_u32(data + len_processed, &shared_state->version);
    len_processed += sizeof(uint32_t);

    return len_processed;
}

/* Packs topic info into data. data must have room for at least
 * topic length + GC_MIN_PACKED_TOPIC_INFO_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint16_t pack_gc_topic_info(uint8_t *data, uint16_t length, const GC_TopicInfo *topic_info)
{
    if (length < topic_info->length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u16(data + packed_len, topic_info->length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, topic_info->topic, topic_info->length);
    packed_len += topic_info->length;
    memcpy(data + packed_len, topic_info->public_sig_key, SIG_PUBLIC_KEY);
    packed_len += SIG_PUBLIC_KEY;
    net_pack_u32(data + packed_len, topic_info->version);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks topic info into topic_info.
 *
 * Returns -1 on failure.
 * Returns the length of the processed data.
 */
static int unpack_gc_topic_info(GC_TopicInfo *topic_info, const uint8_t *data, uint16_t length)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    uint16_t len_processed = 0;

    net_unpack_u16(data + len_processed, &topic_info->length);
    len_processed += sizeof(uint16_t);
    topic_info->length = min_u16(topic_info->length, MAX_GC_TOPIC_SIZE);

    if (length - sizeof(uint16_t) < topic_info->length + SIG_PUBLIC_KEY + sizeof(uint32_t)) {
        return -1;
    }

    memcpy(topic_info->topic, data + len_processed, topic_info->length);
    len_processed += topic_info->length;
    memcpy(topic_info->public_sig_key, data + len_processed, SIG_PUBLIC_KEY);
    len_processed += SIG_PUBLIC_KEY;
    net_unpack_u32(data + len_processed, &topic_info->version);
    len_processed += sizeof(uint32_t);

    return len_processed;
}

/* Creates a shared state packet and puts it in data.
 * Packet includes self pk hash, shared state signature, and packed shared state info.
 * data must have room for at least GC_SHARED_STATE_ENC_PACKET_SIZE bytes.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_shared_state_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, chat->shared_state_sig, SIGNATURE_SIZE);
    uint16_t packed_len = pack_gc_shared_state(data + HASH_ID_BYTES + SIGNATURE_SIZE,
                          length - HASH_ID_BYTES - SIGNATURE_SIZE,
                          &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        return -1;
    }

    return HASH_ID_BYTES + SIGNATURE_SIZE + packed_len;
}

/* Creates a signature for the group's shared state in packed form and increments the version.
 * This should only be called by the founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sign_gc_shared_state(GC_Chat *chat)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    if (chat->shared_state.version != UINT32_MAX) { /* improbable, but an overflow would break everything */
        ++chat->shared_state.version;
    }

    uint8_t shared_state[GC_PACKED_SHARED_STATE_SIZE];
    uint16_t packed_len = pack_gc_shared_state(shared_state, sizeof(shared_state), &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        --chat->shared_state.version;
        return -1;
    }

    int ret = crypto_sign_detached(chat->shared_state_sig, nullptr, shared_state, packed_len,
                                   get_sig_sk(chat->chat_secret_key));

    if (ret != 0) {
        --chat->shared_state.version;
    }

    return ret;
}

/* Decrypts data using the peer's shared key and a nonce.
 * message_id should be set to NULL for lossy packets.
 *
 * Returns length of the plaintext data on success.
 * Returns -1 on failure.
 */
static int unwrap_group_packet(const uint8_t *shared_key, uint8_t *data, uint64_t *message_id,
                               uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    uint8_t plain[MAX_GC_PACKET_SIZE];
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);

    int plain_len = decrypt_data_symmetric(shared_key, nonce,
                                           packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE,
                                           length - (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE),
                                           plain);

    if (plain_len <= 0) {
        fprintf(stderr, "decrypt failed: len %d\n", plain_len);
        return -1;
    }

    int min_plain_len = message_id != nullptr ? 1 + MESSAGE_ID_BYTES : 1;

    /* remove padding */
    uint8_t *real_plain = plain;

    while (real_plain[0] == 0) {
        ++real_plain;
        --plain_len;

        if (plain_len < min_plain_len) {
            return -1;
        }
    }

    uint32_t header_len = sizeof(uint8_t);
    *packet_type = real_plain[0];
    plain_len -= sizeof(uint8_t);

    if (message_id != nullptr) {
        net_unpack_u64(real_plain + sizeof(uint8_t), message_id);
        plain_len -= MESSAGE_ID_BYTES;
        header_len += MESSAGE_ID_BYTES;
    }

    memcpy(data, real_plain + header_len, plain_len);

    return plain_len;
}

/* Encrypts data of length using the peer's shared key and a new nonce.
 *
 * Adds encrypted header consisting of: packet type, message_id (only for lossless packets)
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public encryption key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_packet(const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
                             uint32_t packet_size, const uint8_t *data, uint32_t length, uint64_t message_id,
                             uint8_t packet_type, uint32_t chat_id_hash, uint8_t packet_id)
{
    uint16_t padding_len = GC_PACKET_PADDING_LENGTH(length);

    if (length + padding_len + CRYPTO_MAC_SIZE + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY
            + CRYPTO_NONCE_SIZE > packet_size) {
        return -1;
    }

    uint8_t plain[MAX_GC_PACKET_SIZE];
    memset(plain, 0, padding_len);

    uint32_t enc_header_len = sizeof(uint8_t);
    plain[padding_len] = packet_type;

    if (packet_id == NET_PACKET_GC_LOSSLESS) {
        net_pack_u64(plain + padding_len + sizeof(uint8_t), message_id);
        enc_header_len += MESSAGE_ID_BYTES;
    }

    memcpy(plain + padding_len + enc_header_len, data, length);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    uint16_t plain_len = padding_len + enc_header_len + length;
    VLA(uint8_t, encrypt, plain_len + CRYPTO_MAC_SIZE);

    int enc_len = encrypt_data_symmetric(shared_key, nonce, plain, plain_len, encrypt);

    if (enc_len != SIZEOF_VLA(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, enc_len: %d\n", packet_type, enc_len);
        return -1;
    }

    packet[0] = packet_id;
    net_pack_u32(packet + sizeof(uint8_t), chat_id_hash);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    return 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE + enc_len;
}

/* Sends a lossy packet to peer_number in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossy_group_packet(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                                   uint8_t packet_type)
{
    if (!gconn->handshaked) {
        return -1;
    }

    if (!data || length == 0) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, gconn->shared_key, packet, sizeof(packet),
                                data, length, 0, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSY);

    if (len == -1) {
        fprintf(stderr, "wrap_group_packet failed (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    if (gcc_send_group_packet(chat, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a lossless packet to peer_number in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossless_group_packet(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                                      uint8_t packet_type)
{
    if (!gconn->handshaked) {
        return -1;
    }

    if (!data || length == 0) {
        return -1;
    }

    uint64_t message_id = gconn->send_message_id;
    fprintf(stderr, "send_lossless_group_packet (type: %u, id: %ld)\n", packet_type, message_id);
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, gconn->shared_key, packet, sizeof(packet), data, length,
                                message_id, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSLESS);

    if (len == -1) {
        fprintf(stderr, "wrap_group_packet failed (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    if (gcc_add_to_send_array(chat->mono_time, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    if (gcc_send_group_packet(chat, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a group sync request to peer.
 * num_peers should be set to 0 if this is our initial sync request on join.
 */
static int send_gc_sync_request(GC_Chat *chat, GC_Connection *gconn, uint32_t num_peers)
{
    fprintf(stderr, "send gc sync request\n");
    if (gconn->pending_sync_request) {
        fprintf(stderr, "send gc sync request: pending sync\n");
        return -1;
    }
    gconn->pending_sync_request = true;

    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t) + MAX_GC_PASSWORD_SIZE;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, num_peers);
    memcpy(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.password, MAX_GC_PASSWORD_SIZE);

    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_REQUEST);
}

static int send_gc_sync_response(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_RESPONSE);
}

static int send_new_peer_announcement(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_ANNOUNCE);
}

static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn);

static int send_gc_handshake_packet(GC_Chat *chat, uint32_t peer_number, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type);

static int send_gc_oob_handshake_packet(GC_Chat *chat, uint32_t peer_number, uint8_t handshake_type,
                                        uint8_t request_type, uint8_t join_type);

static int handle_gc_sync_response(Messenger *m, int group_number, int peer_number, GC_Connection *gconn,
                                   const uint8_t *data, uint32_t length)
{
    fprintf(stderr, "gc sync resp start\n");
    if (length < sizeof(uint32_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);
    if (!chat) {
        return -1;
    }

    if (!gconn->pending_sync_request) {
        fprintf(stderr, "pending sync\n");

        return 0;
    }

    gconn->pending_sync_request = false;

    uint32_t num_peers;
    net_unpack_u32(data, &num_peers);

    if (num_peers > chat->shared_state.maxpeers || num_peers > MAX_GC_NUM_PEERS) {
        fprintf(stderr, "peers overflow\n");

        return -1;
    }

    mono_time_update(m->mono_time);

    fprintf(stderr, "got peers in response: %d\n", num_peers);
    if (num_peers) {

        GC_Announce *announces = (GC_Announce *)malloc(sizeof(GC_Announce) * num_peers);
        uint8_t *announces_pointer = (uint8_t *)(data + sizeof(uint32_t));
        unpack_announces_list(announces_pointer, length - sizeof(uint32_t), announces, num_peers, nullptr);

        int i, j;
        for (i = 0; i < num_peers; i++) {
            GC_Announce *curr_announce = &announces[i];
            if (!memcmp(curr_announce->peer_public_key, chat->self_public_key, ENC_PUBLIC_KEY)) { // our own info
                continue;
            }

            if (!is_valid_announce(curr_announce)) {
                fprintf(stderr, "invalid ann\n");
                continue;
            }

            IP_Port *ip_port = curr_announce->ip_port_is_set ? &curr_announce->ip_port : nullptr;
            int new_peer_number = peer_add(c->messenger, group_number, ip_port, curr_announce->peer_public_key);
            if (new_peer_number < 0) {
                continue;
            }

            GC_Connection *peer_gconn = gcc_get_connection(chat, new_peer_number);
            if (!peer_gconn) {
                continue;
            }

            for (j = 0; j < announces->tcp_relays_count; j++) {
                add_tcp_relay_connection(chat->tcp_conn, peer_gconn->tcp_connection_num,
                                         curr_announce->tcp_relays[j].ip_port,
                                         curr_announce->tcp_relays[j].public_key);
                save_tcp_relay(peer_gconn, &curr_announce->tcp_relays[j]);
            }

            fprintf(stderr, "handle_gc_sync_response - added peer %s\n", id_toa(curr_announce->peer_public_key));

            if (curr_announce->ip_port_is_set && !curr_announce->tcp_relays_count) {
                send_gc_handshake_packet(chat, (uint32_t)new_peer_number, GH_REQUEST, HS_PEER_INFO_EXCHANGE,
                                         chat->join_type);
                peer_gconn->send_message_id++;
                fprintf(stderr, "handle_gc_sync_response - send_message_id %ld\n", peer_gconn->send_message_id);
            } else {
                peer_gconn->pending_handshake_type = HS_PEER_INFO_EXCHANGE;
                peer_gconn->is_pending_handshake_response = peer_gconn->is_oob_handshake = false;
                peer_gconn->pending_handshake = gconn->last_received_ping_time = mono_time_get(chat->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
            }
        }

        free(announces);
    }

    gconn = gcc_get_connection(chat, peer_number);
    self_gc_connected(c->messenger->mono_time, chat);
    send_gc_peer_exchange(c, chat, gconn);

    if (c->self_join) {
        (*c->self_join)(m, group_number, c->self_join_userdata);
    }
    fprintf(stderr, "gc sync resp success\n");
    return 0;
}

static int send_peer_shared_state(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_mod_list(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_sanctions_list(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_topic(GC_Chat *chat, GC_Connection *gconn);

int gcc_copy_tcp_relay(GC_Connection *gconn, Node_format *node)
{
    if (!gconn) {
        return 1;
    }

    if (!node) {
        return 2;
    }

    int index = (gconn->tcp_relays_index - 1 + MAX_FRIEND_TCP_CONNECTIONS) % MAX_FRIEND_TCP_CONNECTIONS;

    memcpy(node, &gconn->connected_tcp_relays[index], sizeof(Node_format));

    return 0;
}

bool create_announce_for_peer(GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number, GC_Announce *announce)
{
    if (!chat || !gconn || !announce) {
        return false;
    }

    // pack tcp relays
    if (gconn->any_tcp_connections) {
        gcc_copy_tcp_relay(gconn, &announce->tcp_relays[0]);
        announce->tcp_relays_count = 1;
    } else {
        announce->tcp_relays_count = 0;
    }

    // pack peer public key
    gc_get_peer_public_key(chat, peer_number, announce->peer_public_key);

    // pack peer ip and port
    if (gcc_is_ip_set(gconn)) {
        memcpy(&announce->ip_port, &gconn->addr.ip_port, sizeof(IP_Port));
        announce->ip_port_is_set = true;
    } else {
        announce->ip_port_is_set = false;
    }

    return true;
}

/* Handles a sync request packet and sends a response containing the peer list.
 * Additionally sends the group topic, shared state, mod list and sanctions list in respective packets.
 *
 * If the group is password protected the password in the request data must first be verified.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_sync_request(const Messenger *m, int group_number, int peer_number,
                                  GC_Connection *gconn, const uint8_t *data,
                                  uint32_t length)
{
    fprintf(stderr, "handle gc sync request\n");
    if (length != sizeof(uint32_t) + MAX_GC_PASSWORD_SIZE) {
        fprintf(stderr, "handle gc sync request1\n");
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);
    if (!chat) {
        fprintf(stderr, "handle gc sync request2\n");
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED || chat->shared_state.version == 0) {
        fprintf(stderr, "handle gc sync request3\n");
        return -1;
    }

    if (chat->shared_state.password_length > 0) {
        uint8_t password[MAX_GC_PASSWORD_SIZE];
        memcpy(password, data + sizeof(uint32_t), MAX_GC_PASSWORD_SIZE);

        if (memcmp(chat->shared_state.password, password, chat->shared_state.password_length) != 0) {
            fprintf(stderr, "handle gc sync request4\n");
            return -1;
        }
    }

    /* Do not change the order of these four calls or else */
    if (send_peer_shared_state(chat, gconn) == -1) {
        fprintf(stderr, "handle gc sync request5\n");
        return -1;
    }

    if (send_peer_mod_list(chat, gconn) == -1) {
        fprintf(stderr, "handle gc sync request6\n");
        return -1;
    }

    if (send_peer_sanctions_list(chat, gconn) == -1) {
        fprintf(stderr, "handle gc sync request7\n");
        return -1;
    }

    if (send_peer_topic(chat, gconn) == -1) {
        fprintf(stderr, "handle gc sync request8\n");
        return -1;
    }

    uint8_t response[MAX_GC_PACKET_SIZE];
    net_pack_u32(response, chat->self_public_key_hash);
    uint32_t len = HASH_ID_BYTES;

    uint32_t i, num = 0;
    GC_Announce *existing_peers_announces = (GC_Announce *)malloc(sizeof(GC_Announce) * (chat->numpeers - 1));

    if (!existing_peers_announces) {
        fprintf(stderr, "handle gc sync request11\n");
        return -1;
    }

    // pack info about new node
    GC_Announce new_peer_announce;
    if (!create_announce_for_peer(chat, gconn, (uint32_t)peer_number, &new_peer_announce)) {
        return -1;
    }

    uint8_t sender_relay_data[MAX_GC_PACKET_SIZE];
    net_pack_u32(sender_relay_data, chat->self_public_key_hash);
    int announce_length = pack_announce(sender_relay_data + HASH_ID_BYTES, sizeof(sender_relay_data) - HASH_ID_BYTES,
                                        &new_peer_announce);
    if (announce_length == -1) {
        return -1;
    }

    uint32_t sender_data_length = announce_length + HASH_ID_BYTES;

    for (i = 1; i < chat->numpeers; i++) {
        if (chat->gcc[i].public_key_hash != gconn->public_key_hash && chat->gcc[i].confirmed && i != peer_number) {

            GC_Connection *peer_gconn = gcc_get_connection(chat, i);
            if (!peer_gconn) {
                continue;
            }

            // creates existing peer announce. we will send it to new node later
            if (!create_announce_for_peer(chat, peer_gconn, i, &existing_peers_announces[num])) {
                continue;
            }

            // sends new peer announce to selected existing peer
            send_new_peer_announcement(chat, peer_gconn, sender_relay_data, sender_data_length);
            num++;
        }
    }

    net_pack_u32(response + len, num);
    len += sizeof(uint32_t);

    size_t packed_announces_length;
    int announces_count = pack_announces_list(response + len, sizeof(response) - len, existing_peers_announces,
                                              num, &packed_announces_length);
    if (announces_count != num) {
        return -1;
    }

    len += packed_announces_length;

    // TODO: split packet !important
    fprintf(stderr, "handle gc sync success\n");

    return send_gc_sync_response(chat, gconn, response, len);
}


static void self_to_peer(const GC_Chat *chat, GC_GroupPeer *peer);
static int send_gc_peer_info_request(GC_Chat *chat, GC_Connection *gconn);


static int save_tcp_relay(GC_Connection *gconn, Node_format *node)
{
    if (!gconn || !node) {
        return 1;
    }

    memcpy(&gconn->connected_tcp_relays[gconn->tcp_relays_index], node, sizeof(Node_format));
    gconn->tcp_relays_index = (gconn->tcp_relays_index + 1) % MAX_FRIEND_TCP_CONNECTIONS;
    gconn->any_tcp_connections = true;

    return 0;
}


/* Shares our TCP relays with peer and adds shared relays to our connection with them.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_tcp_relays(const Mono_Time *mono_time, GC_Chat *chat, GC_Connection *gconn)
{
    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    unsigned int i, num = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    if (num == 0) {
        return 0;
    }

    uint8_t data[HASH_ID_BYTES + sizeof(tcp_relays)];
    net_pack_u32(data, chat->self_public_key_hash);
    uint32_t length = HASH_ID_BYTES;

    for (i = 0; i < num; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
    }

    int nodes_len = pack_nodes(data + length, sizeof(data) - length, tcp_relays, num);
    if (nodes_len <= 0) {
        return -1;
    }

    length += nodes_len;

    if (send_lossy_group_packet(chat, gconn, data, length, GP_TCP_RELAYS) == -1) {
        return -1;
    }

    gconn->last_tcp_relays_shared = mono_time_get(mono_time);

    return 0;
}

/* Adds peer's shared TCP relays to our connection with them.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_tcp_relays(Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                                uint32_t length)
{
    if (length == 0) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];

    int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS, nullptr, data, length, 1);
    if (num_nodes <= 0) {
        return -1;
    }

    int i;

    for (i = 0; i < num_nodes; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
    }

    return 0;
}

/* Send invite request to peer_number. Invite packet contains your nick and the group password.
 * If no group password is necessary the password field will be ignored by the invitee.
 *
 * Return -1 if fail
 * Return 0 if success
 */
static int send_gc_invite_request(GC_Chat *chat, GC_Connection *gconn)
{
    fprintf(stderr, "send gc invite request\n");
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint32_t length = HASH_ID_BYTES;

    net_pack_u32(data, chat->self_public_key_hash);

    net_pack_u16(data + length, chat->group[0].nick_length);
    length += sizeof(uint16_t);

    memcpy(data + length, chat->group[0].nick, chat->group[0].nick_length);
    length += chat->group[0].nick_length;

    memcpy(data + length, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    length += MAX_GC_PASSWORD_SIZE;

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_REQUEST);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int send_gc_invite_response(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t,  data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int handle_gc_invite_response(Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                                     uint32_t length)
{
    fprintf(stderr, "handle gc invite resp\n");
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    return send_gc_sync_request(chat, gconn, 0);
}

static int handle_gc_invite_response_reject(Messenger *m, int group_number, const uint8_t *data, uint32_t length)
{
    fprintf(stderr, "handle gc invite rejected\n");
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    uint8_t type = data[0];

    if (type >= GJ_INVALID) {
        type = GJ_INVITE_FAILED;
    }

    chat->connection_state = CS_FAILED;

    if (c->rejected) {
        (*c->rejected)(m, group_number, type, c->rejected_userdata);
    }

    return 0;
}

static int send_gc_invite_response_reject(GC_Chat *chat, GC_Connection *gconn, uint8_t type)
{
    uint32_t length = HASH_ID_BYTES + 1;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, &type, sizeof(uint8_t));

    return send_lossy_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE_REJECT);
}

/* Handles an invite request.
 *
 * Verifies that the invitee's nick is not already taken, and that the correct password has
 * been supplied if the group is password protected.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
int handle_gc_invite_request(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                             uint32_t length)
{
    fprintf(stderr, "handle_gc_invite_request\n");
    if (length <= sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE) {
        fprintf(stderr, "invite fail1\n");
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);
    if (!chat) {
        fprintf(stderr, "invite fail chat\n");
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        fprintf(stderr, "!gconn\n");
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED || chat->shared_state.version == 0) {
        fprintf(stderr, "not connected - return\n");
        return -1;
    }

    uint8_t invite_error = GJ_INVITE_FAILED;
    uint8_t nick[MAX_GC_NICK_SIZE] = {0};
    uint16_t nick_len;
    int peer_number_by_nick;

    if (get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        fprintf(stderr, "invite full gc\n");
        invite_error = GJ_GROUP_FULL;
        goto failed_invite;
    }

    net_unpack_u16(data, &nick_len);

    if (nick_len > MAX_GC_NICK_SIZE) {
        fprintf(stderr, "invite nick\n");
        goto failed_invite;
    }

    if (length - sizeof(uint16_t) < nick_len) {
        fprintf(stderr, "invali len");
        goto failed_invite;
    }

    memcpy(nick, data + sizeof(uint16_t), nick_len);

    peer_number_by_nick = get_nick_peer_number(chat, nick, nick_len);
    if (peer_number_by_nick != -1 && peer_number_by_nick != peer_number) { // in case of duplicate invite
        fprintf(stderr, "nick taken\n");
        invite_error = GJ_NICK_TAKEN;
        goto failed_invite;
    }

    if (sanctions_list_nick_banned(chat, nick)) {
        invite_error = GJ_NICK_BANNED;
        goto failed_invite;
    }

    if (length - sizeof(uint16_t) - nick_len < MAX_GC_PASSWORD_SIZE) {
        fprintf(stderr, "invite pass error\n");
        goto failed_invite;
    }

    if (chat->shared_state.password_length > 0) {
        uint8_t password[MAX_GC_PASSWORD_SIZE];
        memcpy(password, data + sizeof(uint16_t) + nick_len, MAX_GC_PASSWORD_SIZE);

        if (memcmp(chat->shared_state.password, password, chat->shared_state.password_length) != 0) {
            invite_error = GJ_INVALID_PASSWORD;
            fprintf(stderr, "invite pass\n");
            goto failed_invite;
        }
    }

    return send_gc_invite_response(chat, gconn);

failed_invite:
    fprintf(stderr, "failed_invite\n");
    send_gc_invite_response_reject(chat, gconn, invite_error);
    gc_peer_delete(m, group_number, peer_number, nullptr, 0);

    return -1;
}

/* Sends a lossless packet of type and length to all confirmed peers. */
static void send_gc_lossless_packet_all_peers(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossless_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Sends a lossy packet of type and length to all confirmed peers. */
static void send_gc_lossy_packet_all_peers(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossy_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Creates packet with broadcast header info followed by data of length.
 * Returns length of packet including header.
 */
static uint32_t make_gc_broadcast_header(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t *packet,
        uint8_t bc_type)
{
    uint32_t header_len = 0;
    net_pack_u32(packet, chat->self_public_key_hash);
    header_len += HASH_ID_BYTES;
    packet[header_len] = bc_type;
    header_len += sizeof(uint8_t);
    net_pack_u64(packet + header_len, mono_time_get(chat->mono_time));
    header_len += TIME_STAMP_SIZE;

    if (length > 0) {
        memcpy(packet + header_len, data, length);
    }

    return length + header_len;
}

/* sends a group broadcast packet to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_broadcast_message(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t bc_type)
{
    if (length + GC_BROADCAST_ENC_HEADER_SIZE > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    VLA(uint8_t, packet, length + GC_BROADCAST_ENC_HEADER_SIZE);
    uint32_t packet_len = make_gc_broadcast_header(chat, data, length, packet, bc_type);

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_BROADCAST);

    return 0;
}

/* Compares a peer's group sync info that we received in a ping packet to our own.
 *
 * If their info appears to be more recent than ours we will first set a sync request flag.
 * If the flag is already set we send a sync request to this peer then set the flag back to false.
 *
 * This function should only be called from handle_gc_ping().
 */
static void do_gc_peer_state_sync(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sync_data, uint32_t length)
{
    if (length != GC_PING_PACKET_DATA_SIZE) {
        return;
    }

    uint32_t other_num_peers, sstate_version, screds_version, topic_version;
    net_unpack_u32(sync_data, &other_num_peers);
    net_unpack_u32(sync_data + sizeof(uint32_t), &sstate_version);
    net_unpack_u32(sync_data + (sizeof(uint32_t) * 2), &screds_version);
    net_unpack_u32(sync_data + (sizeof(uint32_t) * 3), &topic_version);

    if (other_num_peers > get_gc_confirmed_numpeers(chat)
            || sstate_version > chat->shared_state.version
            || screds_version > chat->moderation.sanctions_creds.version
            || topic_version > chat->topic_info.version) {

        if (gconn->pending_state_sync) {
            send_gc_sync_request(chat, gconn, 0);
            gconn->pending_state_sync = false;
            return;
        }

        gconn->pending_state_sync = true;
        return;
    }

    gconn->pending_state_sync = false;
}

/* Handles a ping packet.
 *
 * The packet contains sync information including peer's confirmed peer count,
 * shared state version and sanction credentials version.
 */
static int handle_gc_ping(Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length != GC_PING_PACKET_DATA_SIZE) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    do_gc_peer_state_sync(chat, gconn, data, length);
    gconn->last_received_ping_time = mono_time_get(m->mono_time);

    return 0;
}

/* Sets the caller's status
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the status type is invalid.
 * Returns -3 if the packet failed to send.
 */
int gc_set_self_status(Messenger *m, int group_number, uint8_t status)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (status >= GS_INVALID) {
        return -2;
    }

    if (c->status_change) {
        (*c->status_change)(m, group_number, chat->group[0].peer_id, status, c->status_change_userdata);
    }

    chat->group[0].status = status;
    uint8_t data[1];
    data[0] = chat->group[0].status;

    if (send_gc_broadcast_message(chat, data, 1, GM_STATUS) == -1) {
        return -3;
    }

    return 0;
}

static int handle_gc_status(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint32_t length)
{
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    uint8_t status = data[0];

    if (status >= GS_INVALID) {
        return -1;
    }

    if (c->status_change) {
        (*c->status_change)(m, group_number, chat->group[peer_number].peer_id, status, c->status_change_userdata);
    }

    chat->group[peer_number].status = status;

    return 0;
}

/* Returns peer_id's status.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!peer_number_valid(chat, peer_number)) {
        return -1;
    }

    return chat->group[peer_number].status;
}

/* Returns peer_id's group role.
 * Returns (uint8_t)-1 on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!peer_number_valid(chat, peer_number)) {
        return -1;
    }

    return chat->group[peer_number].role;
}

/* Copies the chat_id to dest. */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest)
{
    if (dest) {
        memcpy(dest, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);
    }
}

/* Sends self peer info to peer_number. If the group is password protected the request
 * will contain the group password, which the recipient will validate in the respective
 * group message handler.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_self_to_peer(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn)
{
    GC_GroupPeer self;
    self_to_peer(chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    uint32_t length = HASH_ID_BYTES + MAX_GC_PASSWORD_SIZE;

    int packed_len = pack_gc_peer(data + length, sizeof(data) - length, &self);
    length += packed_len;

    if (packed_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in handle_gc_peer_info_request_request %d\n", packed_len);
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_RESPONSE);
}

static int handle_gc_peer_info_request(Messenger *m, int group_number, GC_Connection *gconn)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -1;
    }

    return send_self_to_peer(c, chat, gconn);
}

static int send_gc_peer_info_request(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_REQUEST);
}

/* Do peer info exchange with peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn)
{
    int ret1 = send_self_to_peer(c, chat, gconn);
    int ret2 = send_gc_peer_info_request(chat, gconn);
    return (ret1 == -1 || ret2 == -1) ? -1 : 0;
}

static int handle_gc_peer_announcement(Messenger *m, int group_number, const uint8_t *data, uint32_t length)
{
    if (length <= ENC_PUBLIC_KEY) {
        return -1;
    }
    fprintf(stderr, "in handle_gc_peer_announcement\n");

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);
    if (!chat) {
        return -1;
    }

    GC_Announce new_peer_announce;
    int unpack_result = unpack_announce((uint8_t*)data, length, &new_peer_announce);
    if (unpack_result == -1) {
        fprintf(stderr, "in handle_gc_peer_announcement unpack error\n");
        return -1;
    }

    if (sanctions_list_pk_banned(chat, new_peer_announce.peer_public_key)) {
        fprintf(stderr, "in handle_gc_peer_announcement banned\n");
        return -1;
    }

    IP_Port *ip_port = new_peer_announce.ip_port_is_set ? &new_peer_announce.ip_port : nullptr;
    if (!ip_port && !new_peer_announce.tcp_relays_count) {
        fprintf(stderr, "in handle_gc_peer_announcement invalid info\n");
        return -1;
    }

    int peer_number = peer_add(m, group_number, ip_port, new_peer_announce.peer_public_key);
    if (peer_number == -2) {
        return 0;
    } else if (peer_number == -1) {
        fprintf(stderr, "peer add failed\n");
        return -1;
    }

    fprintf(stderr, "peer add %s\n", id_toa(new_peer_announce.peer_public_key));
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    if (new_peer_announce.tcp_relays_count == 0) {
        return 0;
    }

    int i;
    for (i = 0; i < new_peer_announce.tcp_relays_count; i++) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                 new_peer_announce.tcp_relays[i].ip_port,
                                 new_peer_announce.tcp_relays[i].public_key);
        save_tcp_relay(gconn, &new_peer_announce.tcp_relays[i]);
    }

    return 0;
}

/* Updates peer's info, validates their group role, and sets them as a confirmed peer.
 * If the group is password protected the password must first be validated.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_peer_info_response(Messenger *m, int group_number, uint32_t peer_number,
                                        const uint8_t *data, uint32_t length)
{
    if (length <= SIG_PUBLIC_KEY + MAX_GC_PASSWORD_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);
    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (gconn == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -1;
    }

    if (chat->shared_state.password_length > 0) {
        uint8_t password[MAX_GC_PASSWORD_SIZE];
        memcpy(password, data, sizeof(password));

        if (memcmp(chat->shared_state.password, password, chat->shared_state.password_length) != 0) {
            return -1;
        }
    }

    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    if (unpack_gc_peer(&peer, data + MAX_GC_PASSWORD_SIZE, length - MAX_GC_PASSWORD_SIZE) == -1) {
        fprintf(stderr, "unpack_gc_peer failed in handle_gc_peer_info_request\n");
        return -1;
    }

    if (chat->shared_state.version > 0
        && sanctions_list_nick_banned(chat, peer.nick)
        && !mod_list_verify_sig_pk(chat, get_sig_pk(gconn->addr.public_key))) {
        return -1;
    }

    if (peer_update(m, group_number, &peer, peer_number) == -1) {
        fprintf(stderr, "peer_update() failed in handle_gc_peer_info_request\n");
        return -1;
    }

    if (validate_gc_peer_role(chat, peer_number) == -1) {
        gc_peer_delete(m, group_number, peer_number, nullptr, 0);
        fprintf(stderr, "failed to validate peer role\n");
        return -1;
    }

    if (c->peer_join && !gconn->confirmed) {
        (*c->peer_join)(m, group_number, chat->group[peer_number].peer_id, c->peer_join_userdata);
    }

    gconn->confirmed = true;

    return 0;
}

/* Sends the group shared state and its signature to peer_number.
 *
 * Returns a non-negative integer on success.
 * Returns -1 on failure.
 */
static int send_peer_shared_state(GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->shared_state.version == 0) {
        return -1;
    }

    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int length = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, length, GP_SHARED_STATE);
}

/* Sends the group shared state and signature to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure
 */
static int broadcast_gc_shared_state(GC_Chat *chat)
{
    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int packet_len = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (packet_len != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SHARED_STATE);
    return 0;
}

/* Compares old_shared_state with the chat instance's current shared state and triggers the
 * appropriate callback depending on what piece of state information changed. Also
 * handles DHT announcement/removal if the privacy state changed.
 *
 * The initial retrieval of the shared state on group join will be ignored by this function.
 */
static void do_gc_shared_state_changes(GC_Session *c, GC_Chat *chat, const GC_SharedState *old_shared_state)
{
    /* Max peers changed */
    if (chat->shared_state.maxpeers != old_shared_state->maxpeers) {
        if (c->peer_limit) {
            (*c->peer_limit)(c->messenger, chat->group_number, chat->shared_state.maxpeers, c->peer_limit_userdata);
        }
    }

    /* privacy state changed */
    if (chat->shared_state.privacy_state != old_shared_state->privacy_state) {
        if (c->privacy_state) {
            (*c->privacy_state)(c->messenger, chat->group_number, chat->shared_state.privacy_state,
                                c->privacy_state_userdata);
        }

        if (is_public_chat(chat)) {
            m_add_friend_gc(c->messenger, chat);
        } else if (chat->shared_state.privacy_state == GI_PRIVATE) {
            m_remove_friend_gc(c->messenger, chat);
            cleanup_gca(c->announces_list, get_chat_id(chat->chat_public_key));
        }
    }

    /* password changed */
    if (chat->shared_state.password_length != old_shared_state->password_length
            || memcmp(chat->shared_state.password, old_shared_state->password, old_shared_state->password_length) != 0) {

        if (c->password) {
            (*c->password)(c->messenger, chat->group_number, chat->shared_state.password,
                           chat->shared_state.password_length, c->password_userdata);
        }
    }
}

/* Checks that all shared state values are legal.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int validate_gc_shared_state(const GC_SharedState *state)
{
    if (state->maxpeers > MAX_GC_NUM_PEERS) {
        return -1;
    }

    if (state->password_length > MAX_GC_PASSWORD_SIZE) {
        return -1;
    }

    if (state->group_name_len == 0 || state->group_name_len > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    return 0;
}

static int handle_gc_shared_state_error(Messenger *m, int group_number,
                                        uint32_t peer_number, GC_Chat *chat)
{
    /* If we don't already have a valid shared state we will automatically try to get another invite.
       Otherwise we attempt to ask a different peer for a sync. */
    gc_peer_delete(m, group_number, peer_number, (const uint8_t *)"BAD SHARED STATE", 10);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

/* Handles a shared state packet.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_shared_state(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                  uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE - HASH_ID_BYTES) {
        return handle_gc_shared_state_error(m, group_number, peer_number, chat);
    }

    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, data, SIGNATURE_SIZE);

    const uint8_t *ss_data = data + SIGNATURE_SIZE;
    uint16_t ss_length = length - SIGNATURE_SIZE;

    if (crypto_sign_verify_detached(signature, ss_data, GC_PACKED_SHARED_STATE_SIZE,
                                    get_sig_pk(chat->chat_public_key)) == -1) {
        return handle_gc_shared_state_error(m, group_number, peer_number, chat);
    }

    uint32_t version;
    net_unpack_u32(data + length - sizeof(uint32_t), &version);

    if (version < chat->shared_state.version) {
        return 0;
    }

    GC_SharedState old_shared_state, new_shared_state;
    memcpy(&old_shared_state, &chat->shared_state, sizeof(GC_SharedState));

    if (unpack_gc_shared_state(&new_shared_state, ss_data, ss_length) == 0) {
        return -1;
    }

    if (validate_gc_shared_state(&new_shared_state) == -1) {
        return -1;
    }

    memcpy(&chat->shared_state, &new_shared_state, sizeof(GC_SharedState));
    memcpy(chat->shared_state_sig, signature, SIGNATURE_SIZE);

    do_gc_shared_state_changes(c, chat, &old_shared_state);

    return 0;
}

/* Handles new mod_list and compares its hash against the mod_list_hash in the shared state.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_mod_list(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint32_t length)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[0].role == GR_FOUNDER) {
        return 0;
    }

    uint16_t num_mods;
    net_unpack_u16(data, &num_mods);

    if (num_mods > MAX_GC_MODERATORS) {
        goto on_error;
    }

    if (mod_list_unpack(chat, data + sizeof(uint16_t), length - sizeof(uint16_t), num_mods) == -1) {
        goto on_error;
    }

    uint8_t mod_list_hash[GC_MODERATION_HASH_SIZE];
    mod_list_make_hash(chat, mod_list_hash);

    if (memcmp(mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE) != 0) {
        goto on_error;
    }

    /* Validate our own role */
    if (validate_gc_peer_role(chat, 0) == -1) {
        chat->group[0].role = GR_USER;
    }

    return 0;

on_error:
    gc_peer_delete(m, group_number, peer_number, (const uint8_t *)"BAD MLIST", 9);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

static int handle_gc_sanctions_list_error(Messenger *m, int group_number,
        uint32_t peer_number, GC_Chat *chat)
{
    if (chat->moderation.sanctions_creds.version > 0) {
        return 0;
    }

    gc_peer_delete(m, group_number, peer_number, (const uint8_t *)"BAD SCREDS", 10);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

static int handle_gc_sanctions_list(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                    uint32_t length)
{
    if (length < sizeof(uint32_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    uint32_t num_sanctions;
    net_unpack_u32(data, &num_sanctions);

    if (num_sanctions > MAX_GC_SANCTIONS) {
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    struct GC_Sanction_Creds creds;

    struct GC_Sanction *sanctions = (struct GC_Sanction *)malloc(num_sanctions * sizeof(struct GC_Sanction));

    if (sanctions == nullptr) {
        return -1;
    }

    int unpacked_num = sanctions_list_unpack(sanctions, &creds, num_sanctions, data + sizeof(uint32_t),
                       length - sizeof(uint32_t), nullptr);

    if (unpacked_num != num_sanctions) {
        fprintf(stderr, "sanctions_list_unpack failed in handle_gc_sanctions_list: %d\n", unpacked_num);
        free(sanctions);
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    if (sanctions_list_check_integrity(chat, &creds, sanctions, num_sanctions) == -1) {
        fprintf(stderr, "sanctions_list_check_integrity failed in handle_gc_sanctions_list\n");
        free(sanctions);
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    sanctions_list_cleanup(chat);

    memcpy(&chat->moderation.sanctions_creds, &creds, sizeof(struct GC_Sanction_Creds));
    chat->moderation.sanctions = sanctions;
    chat->moderation.num_sanctions = num_sanctions;

    /* We cannot verify our own observer role on the initial sync so we do it now */
    if (chat->group[0].role == GR_OBSERVER) {
        if (!sanctions_list_is_observer(chat, chat->self_public_key)) {
            chat->group[0].role = GR_USER;
        }
    }

    return 0;
}

/* Makes a mod_list packet.
 *
 * Returns length of packet data on success.
 * Returns -1 on failure.
 */
static int make_gc_mod_list_packet(const GC_Chat *chat, uint8_t *data, uint32_t maxlen, size_t mod_list_size)
{
    if (maxlen < HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u16(data + HASH_ID_BYTES, chat->moderation.num_mods);

    if (mod_list_size > 0) {
        VLA(uint8_t, packed_mod_list, mod_list_size);
        mod_list_pack(chat, packed_mod_list);
        memcpy(data + HASH_ID_BYTES + sizeof(uint16_t), packed_mod_list, mod_list_size);
    }

    return HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
}

/* Sends the moderator list to peer.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_mod_list(GC_Chat *chat, GC_Connection *gconn)
{
    size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    uint32_t length = HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
    VLA(uint8_t, packet, length);

    int packet_len = make_gc_mod_list_packet(chat, packet, SIZEOF_VLA(packet), mod_list_size);

    if (packet_len != length) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, length, GP_MOD_LIST);
}

/* Makes a sanctions list packet.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_sanctions_list_packet(GC_Chat *chat, uint8_t *data, uint32_t maxlen)
{
    if (maxlen < HASH_ID_BYTES + sizeof(uint32_t)) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, chat->moderation.num_sanctions);
    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t);

    int packed_len = sanctions_list_pack(data + length, maxlen - length, chat->moderation.sanctions,
                                         &chat->moderation.sanctions_creds, chat->moderation.num_sanctions);

    if (packed_len < 0) {
        return -1;
    }

    return length + packed_len;
}

/* Sends the sanctions list to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_sanctions_list(GC_Chat *chat, GC_Connection *gconn)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, packet_len, GP_SANCTIONS_LIST);
}

/* Sends the sanctions list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int broadcast_gc_sanctions_list(GC_Chat *chat)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SANCTIONS_LIST);
    return 0;
}

/* Re-signs all sanctions list entries signed by public_sig_key and broadcasts
 * the updated sanctions list to all group peers.
 *
 * Returns the number of updated entries on success.
 * Returns -1 on failure.
 */
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint32_t num_replaced = sanctions_list_replace_sig(chat, public_sig_key);

    if (num_replaced == 0) {
        return 0;
    }

    if (broadcast_gc_sanctions_list(chat) == -1) {
        return -1;
    }

    return num_replaced;
}

/* Sends mod_list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_mod_list(GC_Chat *chat)
{
    size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    uint32_t length = HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
    VLA(uint8_t, packet, length);

    int packet_len = make_gc_mod_list_packet(chat, packet, SIZEOF_VLA(packet), mod_list_size);

    if (packet_len != length) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_MOD_LIST);
    return 0;
}

/* Sends a parting signal to the group.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the packet failed to send.
 */
static int send_gc_self_exit(GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        return -1;
    }

    if (send_gc_broadcast_message(chat, partmessage, length, GM_PEER_EXIT) == -1) {
        return -2;
    }

    return 0;
}

static int handle_gc_peer_exit(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                               uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        length = MAX_GC_PART_MESSAGE_SIZE;
    }
    fprintf(stderr, "peer exit\n");
    return gc_peer_delete(m, group_number, peer_number, data, length);
}

/*
 * Sets your own nick.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the length is too long.
 * Returns -3 if the length is zero or nick is a NULL pointer.
 * Returns -4 if the nick is already taken.
 * Returns -5 if the packet fails to send.
 */
int gc_set_self_nick(Messenger *m, int group_number, const uint8_t *nick, uint16_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length > MAX_GC_NICK_SIZE) {
        return -2;
    }

    if (length == 0 || nick == nullptr) {
        return -3;
    }

    if (get_nick_peer_number(chat, nick, length) != -1) {
        return -4;
    }

    if (c->nick_change) {
        (*c->nick_change)(m, group_number, chat->group[0].peer_id, nick, length, c->nick_change_userdata);
    }

    memcpy(chat->group[0].nick, nick, length);
    chat->group[0].nick_length = length;

    if (send_gc_broadcast_message(chat, nick, length, GM_NICK) == -1) {
        return -5;
    }

    return 0;
}

/* Copies your own nick to nick */
void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    if (nick) {
        memcpy(nick, chat->group[0].nick, chat->group[0].nick_length);
    }
}

/* Return your own nick length */
uint16_t gc_get_self_nick_size(const GC_Chat *chat)
{
    return chat->group[0].nick_length;
}

/* Return your own group role */
uint8_t gc_get_self_role(const GC_Chat *chat)
{
    return chat->group[0].role;
}

/* Return your own status */
uint8_t gc_get_self_status(const GC_Chat *chat)
{
    return chat->group[0].status;
}

/* Returns your own peer id */
uint32_t gc_get_self_peer_id(const GC_Chat *chat)
{
    return chat->group[0].peer_id;
}

/* Copies your own public key to public_key */
void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key)
{
    if (public_key) {
        memcpy(public_key, chat->self_public_key, ENC_PUBLIC_KEY);
    }
}

/* Copies peer_id's nick to name.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!peer_number_valid(chat, peer_number)) {
        return -1;
    }

    if (name) {
        memcpy(name, chat->group[peer_number].nick, chat->group[peer_number].nick_length);
    }

    return 0;
}

/* Returns peer_id's nick length.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!peer_number_valid(chat, peer_number)) {
        return -1;
    }

    return chat->group[peer_number].nick_length;
}

static int handle_gc_nick(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *nick,
                          uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    /* If this happens malicious behaviour is highly suspect */
    if (length == 0 || length > MAX_GC_NICK_SIZE || get_nick_peer_number(chat, nick, length) != -1) {
        return gc_peer_delete(m, group_number, peer_number, nullptr, 0);
    }

    if (c->nick_change) {
        (*c->nick_change)(m, group_number, chat->group[peer_number].peer_id, nick, length, c->nick_change_userdata);
    }

    memcpy(chat->group[peer_number].nick, nick, length);
    chat->group[peer_number].nick_length = length;

    return 0;
}

/* Copies peer_number's public key to public_key.

 * Returns 0 on success.
 * Returns -1 if peer_number is invalid.
 * Returns -2 if public_key is NULL
 */
int gc_get_peer_public_key(const GC_Chat *chat, uint32_t peer_number, uint8_t *public_key)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    if (!public_key) {
        return -2;
    }

    memcpy(public_key, gconn->addr.public_key, ENC_PUBLIC_KEY);

    return 0;
}

int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);
    if (peer_number < 0) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -2;
    }

    if (!public_key) {
        return -3;
    }

    memcpy(public_key, gconn->addr.public_key, ENC_PUBLIC_KEY);

    return 0;
}

/* Creates a topic packet and puts it in data. Packet includes the topic, topic length,
 * public signature key of the setter, topic version, and the signature.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_topic_packet(GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    uint16_t data_length = HASH_ID_BYTES;

    memcpy(data + data_length, chat->topic_sig, SIGNATURE_SIZE);
    data_length += SIGNATURE_SIZE;

    uint16_t packed_len = pack_gc_topic_info(data + data_length, length - data_length, &chat->topic_info);
    data_length += packed_len;

    if (packed_len != chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    return data_length;
}

/* Sends the group topic to peer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_peer_topic(GC_Chat *chat, GC_Connection *gconn)
{
    VLA(uint8_t, packet, HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    int packet_len = make_gc_topic_packet(chat, packet, SIZEOF_VLA(packet));

    if (packet_len != SIZEOF_VLA(packet)) {
        return -1;
    }

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_TOPIC) == -1) {
        return -1;
    }

    return 0;
}

/* Sends the group topic to all group members.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_topic(GC_Chat *chat)
{
    VLA(uint8_t, packet, HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    int packet_len = make_gc_topic_packet(chat, packet, SIZEOF_VLA(packet));

    if (packet_len != SIZEOF_VLA(packet)) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_TOPIC);
    return 0;
}

/* Sets the group topic and broadcasts it to the group. Setter must be a moderator or founder.
 *
 * Returns 0 on success.
 * Returns -1 if the topic is too long.
 * Returns -2 if the caller does not have the required permissions to set the topic.
 * Returns -3 if the packet cannot be created or signing fails.
 * Returns -4 if the packet fails to send.
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE) {
        return -1;
    }

    if (chat->group[0].role > GR_MODERATOR) {
        return -2;
    }

    GC_TopicInfo old_topic_info;
    uint8_t old_topic_sig[SIGNATURE_SIZE];
    memcpy(&old_topic_info, &chat->topic_info, sizeof(GC_TopicInfo));
    memcpy(old_topic_sig, chat->topic_sig, SIGNATURE_SIZE);

    if (chat->topic_info.version != UINT32_MAX) {   /* TODO (jfreegman) improbable, but an overflow would break everything */
        ++chat->topic_info.version;
    }

    chat->topic_info.length = length;
    memcpy(chat->topic_info.topic, topic, length);
    memcpy(chat->topic_info.public_sig_key, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY);

    int err = -3;
    VLA(uint8_t, packed_topic, length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    uint16_t packed_len = pack_gc_topic_info(packed_topic, SIZEOF_VLA(packed_topic), &chat->topic_info);

    if (packed_len != SIZEOF_VLA(packed_topic)) {
        goto on_error;
    }

    if (crypto_sign_detached(chat->topic_sig, nullptr, packed_topic, packed_len, get_sig_sk(chat->self_secret_key)) == -1) {
        goto on_error;
    }

    if (broadcast_gc_topic(chat) == -1) {
        err = -4;
        goto on_error;
    }

    return 0;

on_error:
    memcpy(&chat->topic_info, &old_topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, old_topic_sig, SIGNATURE_SIZE);
    return err;
}

/* Copies the group topic to topic. */
void gc_get_topic(const GC_Chat *chat, uint8_t *topic)
{
    if (topic) {
        memcpy(topic, chat->topic_info.topic, chat->topic_info.length);
    }
}

/* Returns topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_info.length;
}

/* If public_sig_key is equal to the key of the topic setter, replaces topic credentials
 * and re-broadcast the updated topic info to the group.
 *
 * Returns 0 on success
 * Returns -1 on failure.
 */
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key)
{
    if (memcmp(public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY) != 0) {
        return 0;
    }

    if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
        return -1;
    }

    return 0;
}

static int handle_gc_topic(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                           uint32_t length)
{
    if (length > SIGNATURE_SIZE + MAX_GC_TOPIC_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    if (length < SIGNATURE_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_TopicInfo topic_info;
    int unpacked_len = unpack_gc_topic_info(&topic_info, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE);

    if (unpacked_len == -1) {
        return -1;
    }

    if (!mod_list_verify_sig_pk(chat, topic_info.public_sig_key)) {
        return -1;
    }

    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, data, SIGNATURE_SIZE);

    if (crypto_sign_verify_detached(signature, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE,
                                    topic_info.public_sig_key) == -1) {
        return -1;
    }

    if (topic_info.version < chat->topic_info.version) {
        return 0;
    }

    /* Prevents sync issues from triggering the callback needlessly. */
    bool skip_callback = chat->topic_info.length == topic_info.length
                         && memcmp(chat->topic_info.topic, topic_info.topic, topic_info.length) == 0;

    memcpy(&chat->topic_info, &topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, signature, SIGNATURE_SIZE);

    if (!skip_callback && chat->connection_state == CS_CONNECTED && c->topic_change)
        (*c->topic_change)(m, group_number, chat->group[peer_number].peer_id, topic_info.topic, topic_info.length,
                           c->topic_change_userdata);

    return 0;
}

/* Copies group name to groupname */
void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name)
{
    if (group_name) {
        memcpy(group_name, chat->shared_state.group_name, chat->shared_state.group_name_len);
    }
}

/* Returns group name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->shared_state.group_name_len;
}

/* Copies the group password to password */
void gc_get_password(const GC_Chat *chat, uint8_t *password)
{
    if (password) {
        memcpy(password, chat->shared_state.password, chat->shared_state.password_length);
    }
}

/* Returns the group password length */
uint16_t gc_get_password_size(const GC_Chat *chat)
{
    return chat->shared_state.password_length;
}

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    uint16_t oldlen = chat->shared_state.password_length;
    uint8_t *const oldpasswd = (uint8_t *)malloc(oldlen);
    memcpy(oldpasswd, chat->shared_state.password, oldlen);

    if (set_gc_password_local(chat, password, password_length) == -1) {
        free(oldpasswd);
        return -2;
    }

    if (sign_gc_shared_state(chat) == -1) {
        set_gc_password_local(chat, oldpasswd, oldlen);
        free(oldpasswd);
        return -2;
    }

    free(oldpasswd);

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

static int handle_gc_set_mod(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                             uint32_t length)
{
    if (length < 1 + SIG_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].role != GR_FOUNDER) {
        return -1;
    }

    bool add_mod = data[0] != 0;
    uint8_t mod_data[GC_MOD_LIST_ENTRY_SIZE];
    int target_peernum;

    if (add_mod) {
        if (length < 1 + GC_MOD_LIST_ENTRY_SIZE) {
            return -1;
        }

        memcpy(mod_data, data + 1, GC_MODERATION_HASH_SIZE);
        target_peernum = get_peernum_of_sig_pk(chat, mod_data);

        if (peer_number == target_peernum) {
            return -1;
        }

        if (mod_list_add_entry(chat, mod_data) == -1) {
            return -1;
        }
    } else {
        memcpy(mod_data, data + 1, SIG_PUBLIC_KEY);
        target_peernum = get_peernum_of_sig_pk(chat, mod_data);

        if (peer_number == target_peernum) {
            return -1;
        }

        if (mod_list_remove_entry(chat, mod_data) == -1) {
            return -1;
        }
    }

    if (!peer_number_valid(chat, target_peernum)) {
        return 0;
    }

    chat->group[target_peernum].role = add_mod ? GR_MODERATOR : GR_USER;

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[peer_number].peer_id, chat->group[target_peernum].peer_id,
                         add_mod ? MV_MODERATOR : MV_USER, c->moderation_userdata);
    }

    return 0;
}

static int send_gc_set_mod(GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    uint32_t length = 1 + SIG_PUBLIC_KEY;
    VLA(uint8_t, data, length);
    data[0] = add_mod ? 1 : 0;
    memcpy(data + 1, get_sig_pk(gconn->addr.public_key), SIG_PUBLIC_KEY);

    if (send_gc_broadcast_message(chat, data, length, GM_SET_MOD) == -1) {
        return -1;
    }

    return 0;
}

/* Adds or removes gconn from moderator list if add_mod is true or false respectively.
 * Re-signs and re-distributes an updated mod_list hash.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int founder_gc_set_moderator(GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    if (add_mod) {
        if (chat->moderation.num_mods >= MAX_GC_MODERATORS) {
            prune_gc_mod_list(chat);
        }

        if (mod_list_add_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    } else {
        if (mod_list_remove_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_sanctions_list(chat,  get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_topic(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    }

    uint8_t old_hash[GC_MODERATION_HASH_SIZE];
    memcpy(old_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE);

    mod_list_make_hash(chat, chat->shared_state.mod_list_hash);

    if (sign_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (send_gc_set_mod(chat, gconn, add_mod) == -1) {
        return -1;
    }

    return 0;
}

static int handle_gc_set_observer(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                  uint32_t length)
{
    if (length <= 1 + EXT_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].role >= GR_USER) {
        return -1;
    }

    bool add_obs = data[0] != 0;

    uint8_t public_key[EXT_PUBLIC_KEY];
    memcpy(public_key, data + 1, EXT_PUBLIC_KEY);

    if (mod_list_verify_sig_pk(chat, get_sig_pk(public_key))) {
        return -1;
    }

    int target_peernum = get_peernum_of_enc_pk(chat, public_key);

    if (target_peernum == peer_number) {
        return -1;
    }

    GC_Connection *target_gconn = gcc_get_connection(chat, target_peernum);

    if (add_obs) {
        struct GC_Sanction sanction;
        struct GC_Sanction_Creds creds;

        if (sanctions_list_unpack(&sanction, &creds, 1, data + 1 + EXT_PUBLIC_KEY, length - 1 - EXT_PUBLIC_KEY, nullptr) != 1) {
            return -1;
        }

        if (sanctions_list_add_entry(chat, &sanction, &creds) == -1) {
            return -1;
        }
    } else {
        struct GC_Sanction_Creds creds;

        if (sanctions_creds_unpack(&creds, data + 1 + EXT_PUBLIC_KEY, length - 1 - EXT_PUBLIC_KEY)
                != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        if (sanctions_list_remove_observer(chat, public_key, &creds) == -1) {
            return -1;
        }
    }

    if (target_gconn != nullptr) {
        chat->group[target_peernum].role = add_obs ? GR_OBSERVER : GR_USER;

        if (c->moderation) {
            (*c->moderation)(m, group_number, chat->group[peer_number].peer_id, chat->group[target_peernum].peer_id,
                             add_obs ? MV_OBSERVER : MV_USER, c->moderation_userdata);
        }
    }

    return 0;
}

/* Broadcasts observer role data to the group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_set_observer(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sanction_data,
                                uint32_t length, bool add_obs)
{
    uint32_t packet_len = 1 + EXT_PUBLIC_KEY + length;
    VLA(uint8_t, packet, packet_len);
    packet[0] = add_obs ? 1 : 0;
    memcpy(packet + 1, gconn->addr.public_key, EXT_PUBLIC_KEY);
    memcpy(packet + 1 + EXT_PUBLIC_KEY, sanction_data, length);

    if (send_gc_broadcast_message(chat, packet, packet_len, GM_SET_OBSERVER) == -1) {
        return -1;
    }

    return 0;
}

/* Adds or removes peer_number from the observer list if add_obs is true or false respectively.
 * Broadcasts this change to the entire group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int mod_gc_set_observer(GC_Chat *chat, uint32_t peer_number, bool add_obs)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->group[0].role >= GR_USER) {
        return -1;
    }

    uint8_t sanction_data[sizeof(struct GC_Sanction) + sizeof(struct GC_Sanction_Creds)];
    uint32_t length = 0;

    if (add_obs) {
        struct GC_Sanction sanction;

        if (sanctions_list_make_entry(chat, peer_number, &sanction, SA_OBSERVER) == -1) {
            fprintf(stderr, "sanctions_list_make_entry failed in mod_gc_set_observer\n");
            return -1;
        }

        int packed_len = sanctions_list_pack(sanction_data, sizeof(sanction_data), &sanction,
                                             &chat->moderation.sanctions_creds, 1);

        if (packed_len == -1) {
            return -1;
        }

        length += packed_len;
    } else {
        if (sanctions_list_remove_observer(chat, gconn->addr.public_key, nullptr) == -1) {
            return -1;
        }

        uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, sanction_data,
                              sizeof(sanction_data));

        if (packed_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        length += packed_len;
    }

    if (send_gc_set_observer(chat, gconn, sanction_data, length, add_obs) == -1) {
        return -1;
    }

    return 0;
}

/* Sets the role of peer_number. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if caller does not have sufficient permissions for the action.
 * Returns -4 if the role assignment is invalid.
 * Returns -5 if the role failed to be set.
 */
int gc_set_peer_role(Messenger *m, int group_number, uint32_t peer_id, uint8_t role)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (role != GR_MODERATOR && role != GR_USER && role != GR_OBSERVER) {
        return -4;
    }

    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (peer_number == 0 || gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    if (chat->group[0].role >= GR_USER) {
        return -3;
    }

    if (chat->group[peer_number].role == GR_FOUNDER) {
        return -3;
    }

    if (chat->group[0].role != GR_FOUNDER && (role == GR_MODERATOR || chat->group[peer_number].role <= GR_MODERATOR)) {
        return -3;
    }

    if (chat->group[peer_number].role == role) {
        return -4;
    }

    uint8_t mod_event = MV_USER;

    /* New role must be applied after the old role is removed */
    switch (chat->group[peer_number].role) {
        case GR_MODERATOR: {
            if (founder_gc_set_moderator(chat, gconn, false) == -1) {
                return -5;
            }

            chat->group[peer_number].role = GR_USER;

            if (role == GR_OBSERVER) {
                mod_event = MV_OBSERVER;

                if (mod_gc_set_observer(chat, peer_number, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        case GR_OBSERVER: {
            if (mod_gc_set_observer(chat, peer_number, false) == -1) {
                return -5;
            }

            chat->group[peer_number].role = GR_USER;

            if (role == GR_MODERATOR) {
                mod_event = MV_MODERATOR;

                if (founder_gc_set_moderator(chat, gconn, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        case GR_USER: {
            if (role == GR_MODERATOR) {
                mod_event = MV_MODERATOR;

                if (founder_gc_set_moderator(chat, gconn, true) == -1) {
                    return -5;
                }
            } else if (role == GR_OBSERVER) {
                mod_event = MV_OBSERVER;

                if (mod_gc_set_observer(chat, peer_number, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        default: {
            return -4;
        }
    }

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[0].peer_id, chat->group[peer_number].peer_id, mod_event,
                         c->moderation_userdata);
    }

    chat->group[peer_number].role = role;
    return 0;
}

/* Returns group privacy state */
uint8_t gc_get_privacy_state(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state;
}

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the privacy state is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the group is disconnected.
 * Returns -5 if the privacy state could not be set.
 * Returns -6 if the packet failed to send.
 */
int gc_founder_set_privacy_state(Messenger *m, int group_number, uint8_t new_privacy_state)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (new_privacy_state >= GI_INVALID) {
        return -2;
    }

    if (chat->group[0].role != GR_FOUNDER) {
        return -3;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        return -4;
    }

    uint8_t old_privacy_state = chat->shared_state.privacy_state;

    if (new_privacy_state == old_privacy_state) {
        return 0;
    }

    chat->shared_state.privacy_state = new_privacy_state;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.privacy_state = old_privacy_state;
        return -5;
    }

    if (new_privacy_state == GI_PRIVATE) {
        cleanup_gca(c->announces_list, get_chat_id(chat->chat_public_key));
        m_remove_friend_gc(c->messenger, chat);
    } else {
        m_add_friend_gc(c->messenger, chat);
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -6;
    }

    return 0;
}

/* Returns the group peer limit. */
uint32_t gc_get_max_peers(const GC_Chat *chat)
{
    return chat->shared_state.maxpeers;
}

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, uint32_t max_peers)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    max_peers = min_u32(max_peers, MAX_GC_NUM_PEERS);
    uint32_t old_maxpeers = chat->shared_state.maxpeers;

    if (max_peers == chat->shared_state.maxpeers) {
        return 0;
    }

    chat->shared_state.maxpeers = max_peers;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.maxpeers = old_maxpeers;
        return -2;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

/* Sends a plain message or an action, depending on type.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the message type is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_message(GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    if (type != GC_MESSAGE_TYPE_NORMAL && type != GC_MESSAGE_TYPE_ACTION) {
        return -3;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -4;
    }

    uint8_t packet_type = type == GC_MESSAGE_TYPE_NORMAL ? GM_PLAIN_MESSAGE : GM_ACTION_MESSAGE;

    if (send_gc_broadcast_message(chat, message, length, packet_type) == -1) {
        return -5;
    }

    return 0;
}

static int handle_gc_message(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint32_t length,
                             uint8_t type)
{
    if (!data || length > MAX_GC_MESSAGE_SIZE || length == 0) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    if (type != GM_PLAIN_MESSAGE && type != GM_ACTION_MESSAGE) {
        return -1;
    }

    unsigned int cb_type = (type == GM_PLAIN_MESSAGE) ? MESSAGE_NORMAL : MESSAGE_ACTION;

    if (c->message) {
        (*c->message)(m, group_number, chat->group[peer_number].peer_id, cb_type, data, length, c->message_userdata);
    }

    return 0;
}

/* Sends a private message to peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peer_id is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_private_message(GC_Chat *chat, uint32_t peer_id, uint8_t type, const uint8_t *message, uint16_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (type > MESSAGE_ACTION) {
        return -4;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -5;
    }

    uint8_t message_with_type[length + 1];
    message_with_type[0] = type;
    memcpy(message_with_type + 1, message, length);

    uint8_t packet[length + 1 + GC_BROADCAST_ENC_HEADER_SIZE];
    uint32_t packet_len = make_gc_broadcast_header(chat, message_with_type, length + 1, packet, GM_PRIVATE_MESSAGE);

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_BROADCAST) == -1) {
        return -6;
    }

    return 0;
}

static int handle_gc_private_message(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                     uint32_t length)
{
    if (!data || length > MAX_GC_MESSAGE_SIZE || length <= 1) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    unsigned int message_type = data[0];
    if (message_type > MESSAGE_ACTION) {
        return -1;
    }

    if (c->private_message) {
        (*c->private_message)(m, group_number, chat->group[peer_number].peer_id, message_type,
                              data + 1, length - 1, c->private_message_userdata);
    }

    return 0;
}

/* Sends a custom packet to the group. If lossless is true, the packet will be lossless.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 */
int gc_send_custom_packet(GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -2;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -3;
    }

    if (lossless) {
        send_gc_lossless_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    } else {
        send_gc_lossy_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    }

    return 0;
}

/* Handles a custom packet.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_custom_packet(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                   uint32_t length)
{
    if (!data || length == 0 || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    if (c->custom_packet) {
        (*c->custom_packet)(m, group_number, chat->group[peer_number].peer_id, data, length, c->custom_packet_userdata);
    }

    return 0;
}

static int handle_gc_remove_peer(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                 uint32_t length)
{
    if (length < 1 + ENC_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].role >= GR_USER) {
        return -1;
    }

    uint8_t mod_event = data[0];

    if (mod_event != MV_KICK && mod_event != MV_BAN) {
        return -1;
    }

    uint8_t target_pk[ENC_PUBLIC_KEY];
    memcpy(target_pk, data + 1, ENC_PUBLIC_KEY);

    int target_peer_number = get_peernum_of_enc_pk(chat, target_pk);

    if (peer_number_valid(chat, target_peer_number)) {
        /* Even if they're offline or this guard is removed a ban on a mod or founder won't work */
        if (chat->group[target_peer_number].role != GR_USER) {
            return -1;
        }
    }

    if (target_peer_number == 0) {
        if (c->moderation) {
            (*c->moderation)(m, group_number, chat->group[peer_number].peer_id,
                             chat->group[target_peer_number].peer_id, mod_event, c->moderation_userdata);
        }

        while (chat->numpeers > 1) {
            gc_peer_delete(m, group_number, 1, nullptr, 0);
        }

        return 0;
    }

    struct GC_Sanction_Creds creds;

    if (mod_event == MV_BAN) {
        struct GC_Sanction sanction;

        if (sanctions_list_unpack(&sanction, &creds, 1, data + 1 + ENC_PUBLIC_KEY,
                                  length - 1 - ENC_PUBLIC_KEY, nullptr) != 1) {
            return -1;
        }

        if (sanctions_list_add_entry(chat, &sanction, &creds) == -1) {
            fprintf(stderr, "sanctions_list_add_entry failed in remove peer\n");
            return -1;
        }
    }

    if (target_peer_number == -1) {   /* we don't need to/can't kick a peer that isn't in our peerlist */
        return 0;
    }

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[peer_number].peer_id, chat->group[target_peer_number].peer_id,
                         mod_event, c->moderation_userdata);
    }

    if (gc_peer_delete(m, group_number, target_peer_number, nullptr, 0) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a packet to instruct all peers to remove gconn from their peerlist.
 *
 * If mod_event is MV_BAN an updated sanctions list along with new credentials will be added to
 * the ban list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_remove_peer(GC_Chat *chat, GC_Connection *gconn, struct GC_Sanction *sanction,
                               uint8_t mod_event, bool send_new_creds)
{
    uint32_t length = 1 + ENC_PUBLIC_KEY;
    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = mod_event;
    memcpy(packet + 1, gconn->addr.public_key, ENC_PUBLIC_KEY);

    if (mod_event == MV_BAN) {
        int packed_len = sanctions_list_pack(packet + length, sizeof(packet) - length, sanction,
                                             &chat->moderation.sanctions_creds, 1);

        if (packed_len < 0) {
            fprintf(stderr, "sanctions_list_pack failed in send_gc_remove_peer\n");
            return -1;
        }

        length += packed_len;
    }

    return send_gc_broadcast_message(chat, packet, length, GM_REMOVE_PEER);
}

/* Instructs all peers to remove peer_id from their peerlist.
 * If set_ban is true peer will be added to the ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 */
int gc_remove_peer(Messenger *m, int group_number, uint32_t peer_id, bool set_ban, uint8_t ban_type)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    if (chat->group[0].role >= GR_USER || chat->group[peer_number].role == GR_FOUNDER) {
        return -3;
    }

    if (chat->group[0].role != GR_FOUNDER && chat->group[peer_number].role == GR_MODERATOR) {
        return -3;
    }

    if (peer_number == 0) {
        return -2;
    }

    if (ban_type >= SA_OBSERVER && set_ban) {
        return -6;
    }

    if (chat->group[peer_number].role == GR_MODERATOR || chat->group[peer_number].role == GR_OBSERVER) {
        /* this first removes peer from any lists they're on and broadcasts new lists to group */
        if (gc_set_peer_role(m, group_number, peer_id, GR_USER) < 0) {
            return -4;
        }
    }

    uint8_t mod_event = set_ban ? MV_BAN : MV_KICK;
    struct GC_Sanction sanction;

    if (set_ban) {
        if (sanctions_list_make_entry(chat, peer_number, &sanction, ban_type) == -1) {
            fprintf(stderr, "sanctions_list_make_entry failed\n");
            return -4;
        }
    }

    bool send_new_creds = !set_ban && chat->group[peer_number].role == GR_OBSERVER;

    if (send_gc_remove_peer(chat, gconn, &sanction, mod_event, send_new_creds) == -1) {
        return -5;
    }

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[0].peer_id, chat->group[peer_number].peer_id, mod_event,
                         c->moderation_userdata);
    }

    if (gc_peer_delete(m, group_number, peer_number, nullptr, 0) == -1) {
        return -4;
    }

    return 0;
}

static int handle_gc_remove_ban(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                uint32_t length)
{
    if (length < sizeof(uint32_t)) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peer_number].role >= GR_USER) {
        return -1;
    }

    uint32_t ban_id;
    net_unpack_u32(data, &ban_id);

    struct GC_Sanction_Creds creds;
    uint16_t unpacked_len = sanctions_creds_unpack(&creds, data + sizeof(uint32_t), length - sizeof(uint32_t));

    if (unpacked_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
        return -1;
    }

    if (sanctions_list_remove_ban(chat, ban_id, &creds) == -1) {
        fprintf(stderr, "sanctions_list_remove_ban failed in handle_bc_remove_ban\n");
    }

    return 0;
}

/* Sends a packet instructing all peers to remove a ban entry from the sanctions list.
 * Additionally sends updated sanctions credentials.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_remove_ban(GC_Chat *chat, uint32_t ban_id)
{
    uint8_t packet[sizeof(uint32_t) + GC_SANCTIONS_CREDENTIALS_SIZE];
    net_pack_u32(packet, ban_id);
    uint32_t length = sizeof(uint32_t);

    uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, packet + length,
                          sizeof(packet) - length);

    if (packed_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
        return -1;
    }

    length += packed_len;

    return send_gc_broadcast_message(chat, packet, length, GM_REMOVE_BAN);
}

/* Instructs all peers to remove ban_id from their ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the entry could not be removed.
 * Returns -3 if the packet failed to send.
 */
int gc_remove_ban(GC_Chat *chat, uint32_t ban_id)
{
    if (chat->group[0].role >= GR_USER) {
        return -1;
    }

    if (sanctions_list_remove_ban(chat, ban_id, nullptr) == -1) {
        return -2;
    }

    if (send_gc_remove_ban(chat, ban_id) == -1) {
        return -3;
    }

    return 0;
}

#define VALID_GC_MESSAGE_ACK(a, b) (((a) == 0) || ((b) == 0))

/* If read_id is non-zero sends a read-receipt for read_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t read_id, uint64_t request_id)
{
    if (!VALID_GC_MESSAGE_ACK(read_id, request_id)) {
        return -1;
    }

    uint32_t length = HASH_ID_BYTES + (MESSAGE_ID_BYTES * 2);
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u64(data + HASH_ID_BYTES, read_id);
    net_pack_u64(data + HASH_ID_BYTES + MESSAGE_ID_BYTES, request_id);

    return send_lossy_group_packet(chat, gconn, data, length, GP_MESSAGE_ACK);
}

/* If packet contains a non-zero request_id we try to resend its respective packet.
 * If packet contains a non-zero read_id we remove the packet from our send array.
 *
 * Returns non-negative value on success.
 * Return -1 if error or we fail to send a packet in case of a request response.
 */
static int handle_gc_message_ack(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length != MESSAGE_ID_BYTES * 2) {
        return -1;
    }

    uint64_t read_id, request_id;
    net_unpack_u64(data, &read_id);
    net_unpack_u64(data + MESSAGE_ID_BYTES, &request_id);

    if (!VALID_GC_MESSAGE_ACK(read_id, request_id)) {
        return -1;
    }

    if (read_id > 0) {
        return gcc_handle_ack(gconn, read_id);
    }

    uint64_t tm = mono_time_get(chat->mono_time);
    uint16_t idx = get_array_index(request_id);

    /* re-send requested packet */
    if (gconn->send_array[idx].message_id == request_id
            && (gconn->send_array[idx].last_send_try != tm || gconn->send_array[idx].time_added == tm)) {
        gconn->send_array[idx].last_send_try = tm;
        return sendpacket(chat->net, gconn->addr.ip_port, gconn->send_array[idx].data, gconn->send_array[idx].data_length);
    }

    return -1;
}

/* Sends a handshake response ack to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int gc_send_hs_response_ack(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_HS_RESPONSE_ACK);
}

/* Handles a handshake response ack.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_hs_response_ack(Messenger *m, int group_number, GC_Connection *gconn)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);
    if (!chat) {
        return -1;
    }

    gconn->handshaked = true;
    gconn->pending_handshake = 0;
    fprintf(stderr, "handshaked - ack\n");

    if (gconn->friend_shared_state_version > gconn->self_sent_shared_state_version
        || (gconn->friend_shared_state_version == gconn->self_sent_shared_state_version
            && id_cmp(chat->self_public_key, gconn->addr.public_key) > 0)) {
        int ret = send_gc_invite_request(chat, gconn);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

/* Toggles ignore for peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the peer_id is invalid.
 */
int gc_toggle_ignore(GC_Chat *chat, uint32_t peer_id, bool ignore)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!peer_number_valid(chat, peer_number)) {
        return -1;
    }

    chat->group[peer_number].ignore = ignore;
    return 0;
}

/* Handles a broadcast packet.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_broadcast(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint32_t length)
{
    if (length < 1 + TIME_STAMP_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    uint8_t broadcast_type;
    memcpy(&broadcast_type, data, sizeof(uint8_t));

    if (!gconn->confirmed) {
        return -1;
    }

    uint32_t m_len = length - (1 + TIME_STAMP_SIZE);
    VLA(uint8_t, message, m_len);
    memcpy(message, data + 1 + TIME_STAMP_SIZE, m_len);

    switch (broadcast_type) {
        case GM_STATUS:
            return handle_gc_status(m, group_number, peer_number, message, m_len);

        case GM_NICK:
            return handle_gc_nick(m, group_number, peer_number, message, m_len);

        case GM_ACTION_MESSAGE:  // intentional fallthrough
        case GM_PLAIN_MESSAGE:
            return handle_gc_message(m, group_number, peer_number, message, m_len, broadcast_type);

        case GM_PRIVATE_MESSAGE:
            return handle_gc_private_message(m, group_number, peer_number, message, m_len);

        case GM_PEER_EXIT:
            return handle_gc_peer_exit(m, group_number, peer_number, message, m_len);

        case GM_REMOVE_PEER:
            return handle_gc_remove_peer(m, group_number, peer_number, message, m_len);

        case GM_REMOVE_BAN:
            return handle_gc_remove_ban(m, group_number, peer_number, message, m_len);

        case GM_SET_MOD:
            return handle_gc_set_mod(m, group_number, peer_number, message, m_len);

        case GM_SET_OBSERVER:
            return handle_gc_set_observer(m, group_number, peer_number, message, m_len);

        default:
            fprintf(stderr, "Warning: handle_gc_broadcast received an invalid broadcast type %u\n", broadcast_type);
            return -1;
    }

    return -1;
}

/* Decrypts data of length using self secret key and sender's public key.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int uwrap_group_handshake_packet(const uint8_t *self_sk, uint8_t *sender_pk, uint8_t *plain,
                                        size_t plain_size, const uint8_t *packet, uint16_t length)
{
    if (plain_size < length - 1 - HASH_ID_BYTES - ENC_PUBLIC_KEY - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);
    memcpy(nonce, packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);

    int plain_len = decrypt_data(sender_pk, self_sk, nonce,
                                 packet + (1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE),
                                 length - (1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE), plain);

    if (plain_len != plain_size) {
        fprintf(stderr, "decrypt handshake request failed\n");
        return -1;
    }

    return plain_len;
}

/* Encrypts data of length using the peer's shared key a new nonce. Packet must have room
 * for GC_ENCRYPTED_HS_PACKET_SIZE bytes.
 *
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_handshake_packet(const uint8_t *self_pk, const uint8_t *self_sk, const uint8_t *sender_pk,
                                       uint8_t *packet, uint32_t packet_size, const uint8_t *data,
                                       uint16_t length, uint32_t chat_id_hash)
{
    if (packet_size < GC_ENCRYPTED_HS_PACKET_SIZE + sizeof(Node_format)) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    VLA(uint8_t, encrypt, length + CRYPTO_MAC_SIZE);
    int enc_len = encrypt_data(sender_pk, self_sk, nonce, data, length, encrypt);

    if (enc_len != SIZEOF_VLA(encrypt)) {
        fprintf(stderr, "encrypt handshake request failed (len: %d)\n", enc_len);
        return -1;
    }

    packet[0] = NET_PACKET_GC_HANDSHAKE;
    net_pack_u32(packet + 1, chat_id_hash);
    memcpy(packet + 1 + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    return 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE + enc_len;
}

/* Makes, wraps and encrypts a group handshake packet (both request and response are the same format).
 *
 * Packet contains the handshake header, the handshake type, self pk hash, session pk, self public signature key,
 * the request type (GROUP_HANDSHAKE_REQUEST_TYPE), the join type (GROUP_HANDSHAKE_JOIN_TYPE),
 * and a list of tcp relay nodes we share with this peer.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
int make_gc_handshake_packet(GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
                             uint8_t request_type, uint8_t join_type, uint8_t *packet, size_t packet_size, Node_format *node)
{
    if (packet_size < GC_ENCRYPTED_HS_PACKET_SIZE + sizeof(Node_format)) {
        return -1;
    }

    if (!chat || !gconn || !node) {
        return -1;
    }

    uint8_t data[GC_PLAIN_HS_PACKET_SIZE + sizeof(Node_format)];

    data[0] = handshake_type;
    uint16_t length = sizeof(uint8_t);
    net_pack_u32(data + length, chat->self_public_key_hash);
    length += HASH_ID_BYTES;
    memcpy(data + length, gconn->session_public_key, ENC_PUBLIC_KEY);
    length += ENC_PUBLIC_KEY;
    memcpy(data + length, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY);
    length += SIG_PUBLIC_KEY;
    memcpy(data + length, &request_type, sizeof(uint8_t));
    length += sizeof(uint8_t);
    memcpy(data + length, &join_type, sizeof(uint8_t));
    length += sizeof(uint8_t);

    uint32_t state =
            gconn->self_sent_shared_state_version != UINT32_MAX ? gconn->self_sent_shared_state_version :
            chat->connection_state == CS_CONNECTED ? chat->shared_state.version : 0;
    gconn->self_sent_shared_state_version = state;
    net_pack_u32(data + length, state);
    length += sizeof(uint32_t);

    int nodes_size = pack_nodes(data + length, sizeof(Node_format), node, MAX_SENT_GC_NODES);
    if (nodes_size != -1) {
        length += nodes_size;
    } else {
        nodes_size = 0;
    }

    int enc_len = wrap_group_handshake_packet(chat->self_public_key, chat->self_secret_key,
                                              gconn->addr.public_key, packet, packet_size,
                                              data, length, chat->chat_id_hash);

    if (enc_len != GC_ENCRYPTED_HS_PACKET_SIZE + nodes_size) {
        fprintf(stderr, "enc len\n");
        return -1;
    }

    return enc_len;
}

/* Sends a handshake packet where handshake_type is GH_REQUEST or GH_RESPONSE.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_handshake_packet(GC_Chat *chat, uint32_t peer_number, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    uint8_t packet[GC_ENCRYPTED_HS_PACKET_SIZE + sizeof(Node_format)];
    Node_format node[MAX_ANNOUNCED_TCP_RELAYS];
    gcc_copy_tcp_relay(gconn, node);

    int length = make_gc_handshake_packet(chat, gconn, handshake_type, request_type, join_type, packet,
                                          sizeof(packet), node);
    if (length == -1) {
        fprintf(stderr, "length error\n");
        return -1;
    }

    int ret1 = -1, ret2;

    if (!net_family_is_unspec(gconn->addr.ip_port.ip.family)) {
        ret1 = sendpacket(chat->net, gconn->addr.ip_port, packet, length);
    }

    ret2 = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret1 == -1 && ret2 == -1) {
        return -1;
    }

    fprintf(stderr, "send_gc_handshake_packet success\n");

    return 0;
}

static int send_gc_oob_handshake_packet(GC_Chat *chat, uint32_t peer_number, uint8_t handshake_type,
                                        uint8_t request_type, uint8_t join_type)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    Node_format node[1];
    gcc_copy_tcp_relay(gconn, node);

    uint8_t packet[GC_ENCRYPTED_HS_PACKET_SIZE + sizeof(Node_format)];
    int length = make_gc_handshake_packet(chat, gconn, handshake_type, request_type, join_type, packet,
                                          sizeof(packet), node);
    if (length == -1) {
        return -1;
    }

    int ret = tcp_send_oob_packet_using_relay(chat->tcp_conn, gconn->oob_relay_pk,
                                              gconn->addr.public_key, packet, length);

    return ret;
}

/* Handles a handshake response packet and takes appropriate action depending on the value of request_type.
 *
 * Returns peer_number of new connected peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_response(Messenger *m, int group_number, const uint8_t *sender_pk,
                                        const uint8_t *data, uint16_t length)
{
    fprintf(stderr, "handle gc handshake resp\n");
    if (length < ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 1) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);
    if (!chat) {
        return -1;
    }

    int peer_number = get_peernum_of_enc_pk(chat, sender_pk);
    if (peer_number == -1) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);
    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    set_sig_pk(gconn->addr.public_key, data + ENC_PUBLIC_KEY);
    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];

    /* This packet is an implied handshake request acknowledgement */
    gconn->received_message_id++;
    fprintf(stderr, "handshake resp gconn->received_message_id++ %ld\n", gconn->received_message_id);

    gconn->handshaked = true;
    fprintf(stderr, "handshaked - resp\n");
    gconn->pending_handshake = 0;
    gc_send_hs_response_ack(chat, gconn);

    int ret;

    switch (request_type) {
        case HS_INVITE_REQUEST:
            net_unpack_u32(data + ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 2, &gconn->friend_shared_state_version);
            // client with shared version < than friend has will send invite request
            // if shared versions are the same compare public keys of peers
            if (gconn->friend_shared_state_version < gconn->self_sent_shared_state_version
                || (gconn->friend_shared_state_version == gconn->self_sent_shared_state_version
                    && id_cmp(chat->self_public_key, gconn->addr.public_key) > 0)) {
                return peer_number;
            }
            ret = send_gc_invite_request(chat, gconn);
            break;

        case HS_PEER_INFO_EXCHANGE:
            ret = send_gc_peer_exchange(m->group_handler, chat, gconn);
            break;

        default:
            fprintf(stderr, "Warning: received invalid request type in handle_gc_handshake_response\n");
            return -1;
    }

    if (ret == -1) {
        return -1;
    }

    return peer_number;
}

static int send_gc_handshake_response(GC_Chat *chat, uint32_t peer_number, uint8_t request_type)
{
    if (send_gc_handshake_packet(chat, peer_number, GH_RESPONSE, request_type, 0) == -1) {
        return -1;
    }

    return 0;
}

static int peer_reconnect(Messenger *m, const GC_Chat *chat, const uint8_t *peer_pk)
{
    int peer_number = get_peernum_of_enc_pk(chat, peer_pk);
    if (peer_number < 0) {
        return -1;
    }

    gc_peer_delete(m, chat->group_number, peer_number, nullptr, 0);

    return peer_add(m, chat->group_number, nullptr, peer_pk);
}

/* Handles handshake request packets.
 * Peer is added to peerlist and a lossless connection is established.
 *
 * Return new peer's peer_number on success.
 * Return -1 on failure.
 */
#define GC_NEW_PEER_CONNECTION_LIMIT 10
static int handle_gc_handshake_request(Messenger *m, int group_number, IP_Port *ipp, const uint8_t *sender_pk,
                                       const uint8_t *data, uint32_t length)
{
    if (length < ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 6) {
        return -1;
    }
    fprintf(stderr, "in handle gc hs request1\n");

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);
    if (!chat) {
        return -1;
    }

    if (chat->connection_state == CS_FAILED) {
        return -1;
    }
    fprintf(stderr, "in handle gc hs request2\n");

    uint8_t public_sig_key[SIG_PUBLIC_KEY];
    memcpy(public_sig_key, data + ENC_PUBLIC_KEY, SIG_PUBLIC_KEY);

    /* Check if IP or PK is banned and make sure they aren't a moderator or founder */
    if (chat->shared_state.version > 0
        && (sanctions_list_ip_banned(chat, ipp) || sanctions_list_pk_banned(chat, sender_pk))
        && !mod_list_verify_sig_pk(chat, public_sig_key)) {
        return -1;
    }

    if (chat->connection_O_metre >= GC_NEW_PEER_CONNECTION_LIMIT) {
        chat->block_handshakes = true;
        return -1;
    }

    ++chat->connection_O_metre;

    int peer_number = get_peernum_of_enc_pk(chat, sender_pk);
    bool is_new_peer = false;
    fprintf(stderr, "in handle gc hs request3\n");


    if (peer_number < 0) {
        if (!is_public_chat(chat) && !is_peer_confirmed(chat, sender_pk)) {
            return -1; // peer is not allowed to join this chat
        }

        peer_number = peer_add(m, chat->group_number, ipp, sender_pk);
        if (peer_number < 0) {
            return -1;
        }

        is_new_peer = true;
    } else  {
        GC_Connection *gconn = gcc_get_connection(chat, peer_number);
        if (!gconn) {
            return -1;
        }

        if (gconn->handshaked) {
            peer_number = peer_reconnect(m, chat, sender_pk);
            if (peer_number < 0) {
                return -1;
            }

            is_new_peer = true;
        }
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    if (ipp) {
        memcpy(&gconn->addr.ip_port, ipp, sizeof(IP_Port));
    }
    fprintf(stderr, "in handle gc hs request4\n");

    Node_format node[MAX_ANNOUNCED_TCP_RELAYS];
    int processed = ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 6;
    int nodes_count = unpack_nodes(node, MAX_ANNOUNCED_TCP_RELAYS, nullptr, data + processed, length - processed, 1);
    if (nodes_count <= 0 && !ipp) {
        if (is_new_peer) {
            fprintf(stderr, "broken tcp relay for new peer\n");
            gc_peer_delete(m, chat->group_number, peer_number, nullptr, 0);
        }
        return -1;
    }

    if (nodes_count > 0) {
        int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                                      node->ip_port, node->public_key);
        if (add_tcp_result < 0 && is_new_peer && !ipp) {
            fprintf(stderr, "broken tcp relay for new peer\n");
            gc_peer_delete(m, group_number, peer_number, nullptr, 0);
            return -1;
        }

        if (add_tcp_result >= 0) {
            save_tcp_relay(gconn, node);
        }
    }
    fprintf(stderr, "in handle gc hs request6\n");

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);

    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    set_sig_pk(gconn->addr.public_key, public_sig_key);

    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];
    uint8_t join_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 1];

    net_unpack_u32(data + ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 2, &gconn->friend_shared_state_version);

    if (join_type == HJ_PUBLIC && !is_public_chat(chat)) {
        gc_peer_delete(m, group_number, peer_number, (const uint8_t *)"join priv chat as public", 15);
        return -1;
    }

    gconn->received_message_id++;
    fprintf(stderr, "handshake req gconn->received_message_id++ %ld\n", gconn->received_message_id);
    fprintf(stderr, "in handle gc hs request7\n");

    if (!ipp) {
        gconn->pending_handshake_type = request_type;
        gconn->is_oob_handshake = false;
        gconn->is_pending_handshake_response = true;
        gconn->pending_handshake = gconn->last_received_ping_time = mono_time_get(chat->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
    } else {
        send_gc_handshake_response(chat, peer_number, request_type);
        gconn->send_message_id++;
        gconn->pending_handshake = 0;
        fprintf(stderr, "in handle_gc_handshake_request gconn->send_message_id %ld\n", gconn->send_message_id);
    }


    fprintf(stderr, "in handle_gc_handshake_request success\n");

    return peer_number;
}

/* Handles handshake request and handshake response packets.
 *
 * Returns peer_number of connecting peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_packet(Messenger *m, GC_Chat *chat, IP_Port *ipp, const uint8_t *packet,
                                      uint16_t length, bool direct_conn)
{
    if (length < GC_ENCRYPTED_HS_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    VLA(uint8_t, data, length - 1 - HASH_ID_BYTES - ENC_PUBLIC_KEY - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE);

    int plain_len = uwrap_group_handshake_packet(chat->self_secret_key, sender_pk, data, SIZEOF_VLA(data),
                                                 packet, length);

    if (plain_len != SIZEOF_VLA(data)) {
        return -1;
    }

    uint8_t handshake_type = data[0];

    uint32_t public_key_hash;
    net_unpack_u32(data + 1, &public_key_hash);

    if (public_key_hash != get_peer_key_hash(sender_pk)) {
        return -1;
    }

    const uint8_t *real_data = data + (sizeof(uint8_t) + HASH_ID_BYTES);
    uint16_t real_len = plain_len - sizeof(uint8_t) - HASH_ID_BYTES;

    int peer_number;

    if (handshake_type == GH_REQUEST) {
        peer_number = handle_gc_handshake_request(m, chat->group_number, ipp, sender_pk, real_data, real_len);
    } else if (handshake_type == GH_RESPONSE) {
        peer_number = handle_gc_handshake_response(m, chat->group_number, sender_pk, real_data, real_len);
    } else {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (gconn == nullptr) {
        return -1;
    }

    if (peer_number > 0 && direct_conn) {
        gconn->last_received_direct_time = mono_time_get(chat->mono_time);
    }

    return peer_number;
}

int handle_gc_lossless_helper(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    switch (packet_type) {
        case GP_BROADCAST:
            return handle_gc_broadcast(m, group_number, peer_number, data, length);

        case GP_PEER_ANNOUNCE:
            return handle_gc_peer_announcement(m, group_number, data, length);

        case GP_PEER_INFO_REQUEST:
            return handle_gc_peer_info_request(m, group_number, gconn);

        case GP_PEER_INFO_RESPONSE:
            return handle_gc_peer_info_response(m, group_number, peer_number, data, length);

        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(m, group_number, peer_number, gconn, data, length);

        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(m, group_number, peer_number, gconn, data, length);

        case GP_INVITE_REQUEST:
            return handle_gc_invite_request(m, group_number, peer_number, data, length);

        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(m, group_number, gconn, data, length);

        case GP_TOPIC:
            return handle_gc_topic(m, group_number, peer_number, data, length);

        case GP_SHARED_STATE:
            return handle_gc_shared_state(m, group_number, peer_number, data, length);

        case GP_MOD_LIST:
            return handle_gc_mod_list(m, group_number, peer_number, data, length);

        case GP_SANCTIONS_LIST:
            return handle_gc_sanctions_list(m, group_number, peer_number, data, length);

        case GP_HS_RESPONSE_ACK:
            return handle_gc_hs_response_ack(m, group_number, gconn);

        case GP_CUSTOM_PACKET:
            return handle_gc_custom_packet(m, group_number, peer_number, data, length);

        default:
            fprintf(stderr, "Warning: handling invalid lossless group packet type %u\n", packet_type);
            return -1;
    }
}

/* Handles lossless groupchat message packets.
 *
 * return non-negative value if packet is handled correctly.
 * return -1 on failure.
 */
static int handle_gc_lossless_message(Messenger *m, GC_Chat *chat, const uint8_t *packet, uint16_t length,
                                      bool direct_conn)
{
    if (length < MIN_GC_LOSSLESS_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peer_number = get_peernum_of_enc_pk(chat, sender_pk);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;
    uint64_t message_id;

    int len = unwrap_group_packet(gconn->shared_key, data, &message_id, &packet_type, packet, length);

    if (len <= 0) {
        return -1;
    }

    if (packet_type != GP_HS_RESPONSE_ACK && packet_type != GP_INVITE_REQUEST && !gconn->handshaked) {
        fprintf(stderr, "not ack %d\n", packet_type);
        return -1;
    }
    fprintf(stderr, "handle_gc_lossless_message %d\n", packet_type);

    uint32_t sender_pk_hash;
    net_unpack_u32(data, &sender_pk_hash);

    if (!peer_pk_hash_match(gconn, sender_pk_hash)) {
        return -1;
    }

    const uint8_t *real_data = data + HASH_ID_BYTES;
    uint16_t real_len = len - HASH_ID_BYTES;

    bool is_invite_packet = packet_type == GP_INVITE_REQUEST || packet_type == GP_INVITE_RESPONSE || packet_type == GP_INVITE_RESPONSE_REJECT;
    if (message_id == 3 && is_invite_packet && gconn->received_message_id == 1) {
        // probably we missed initial handshake packet. update received packets index
        // TODO: FIXME
        fprintf(stderr, "oops\n");
        gconn->received_message_id++;
    }

    int lossless_ret = gcc_handle_received_message(chat, peer_number, real_data, real_len, packet_type, message_id);

    if (packet_type == GP_INVITE_REQUEST && !gconn->handshaked) {  // race condition
        fprintf(stderr, "race condition %d\n", packet_type);
        return 0;
    }

    if (lossless_ret == -1) {
        fprintf(stderr, "failed to handle packet %llu (type %u)\n", (unsigned long long)message_id, packet_type);
        return -1;
    }

    /* Duplicate packet */
    if (lossless_ret == 0) {
        fprintf(stderr, "got duplicate packet %lu (type %u)\n", message_id, packet_type);
        return gc_send_message_ack(chat, gconn, message_id, 0);
    }

    /* request missing packet */
    if (lossless_ret == 1) {
        fprintf(stderr, "recieved out of order packet. expected %lu, got %lu\n", gconn->received_message_id + 1, message_id);
        return gc_send_message_ack(chat, gconn, 0, gconn->received_message_id + 1);
    }

    int ret = handle_gc_lossless_helper(m, chat->group_number, peer_number, real_data, real_len, message_id, packet_type);

    if (ret == -1) {
        fprintf(stderr, "lossless handler failed (type %u)\n", packet_type);
        return -1;
    }

    /* we need to get the peer_number and gconn again because it may have changed */
    peer_number = get_peernum_of_enc_pk(chat, sender_pk);
    gconn = gcc_get_connection(chat, peer_number);

    if (lossless_ret == 2 && peer_number != -1) {
        gc_send_message_ack(chat, gconn, message_id, 0);
        gcc_check_recieved_array(m, chat->group_number, peer_number);

        if (direct_conn) {
            gconn->last_received_direct_time = mono_time_get(chat->mono_time);
        }
    }

    return ret;
}

/* Handles lossy groupchat message packets.
 *
 * return non-negative value if packet is handled correctly.
 * return -1 on failure.
 */
static int handle_gc_lossy_message(Messenger *m, GC_Chat *chat, const uint8_t *packet, uint16_t length,
                                   bool direct_conn)
{
    if (length < MIN_GC_LOSSY_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peer_number = get_peernum_of_enc_pk(chat, sender_pk);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (!gconn->handshaked) {
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(gconn->shared_key, data, nullptr, &packet_type, packet, length);

    if (len <= 0) {
        return -1;
    }

    uint32_t sender_pk_hash;
    net_unpack_u32(data, &sender_pk_hash);

    const uint8_t *real_data = data + HASH_ID_BYTES;
    len -= HASH_ID_BYTES;

    if (!peer_pk_hash_match(gconn, sender_pk_hash)) {
        return -1;
    }

    int ret;

    switch (packet_type) {
        case GP_MESSAGE_ACK:
            ret = handle_gc_message_ack(chat, gconn, real_data, len);
            break;

        case GP_PING:
            ret = handle_gc_ping(m, chat->group_number, gconn, real_data, len);
            break;

        case GP_INVITE_RESPONSE_REJECT:
            ret = handle_gc_invite_response_reject(m, chat->group_number, real_data, len);
            break;

        case GP_TCP_RELAYS:
            ret = handle_gc_tcp_relays(m, chat->group_number, gconn, real_data, len);
            break;

        case GP_CUSTOM_PACKET:
            ret = handle_gc_custom_packet(m, chat->group_number, peer_number, real_data, len);
            break;

        default:
            fprintf(stderr, "Warning: handling invalid lossy group packet type %u\n", packet_type);
            return -1;
    }

    if (ret != -1 && direct_conn) {
        gconn->last_received_direct_time = mono_time_get(m->mono_time);
    }

    return ret;
}

static bool group_can_handle_packets(GC_Chat *chat)
{
    return chat->connection_state != CS_FAILED && chat->connection_state != CS_MANUALLY_DISCONNECTED;
}

/* Sends a group packet to appropriate handler function.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
int handle_gc_tcp_packet(void *object, int id, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Session *c = m->group_handler;
    GC_Chat *chat = get_chat_by_hash(c, chat_id_hash);

    if (!chat) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    if (packet[0] == NET_PACKET_GC_LOSSLESS) {
        return handle_gc_lossless_message(m, chat, packet, length, false);
    } else if (packet[0] == NET_PACKET_GC_LOSSY) {
        return handle_gc_lossy_message(m, chat, packet, length, false);
    } else if (packet[0] == NET_PACKET_GC_HANDSHAKE) {
        fprintf(stderr, "handle gc tcp handshake packet\n");
        return handle_gc_handshake_packet(m, chat, nullptr, packet, length, false);
    }

    return -1;
}

int handle_gc_tcp_oob_packet(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                             const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Session *c = m->group_handler;
    GC_Chat *chat = get_chat_by_hash(c, chat_id_hash);

    if (!chat) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    if (packet[0] != NET_PACKET_GC_HANDSHAKE) {
        return -1;
    }
    fprintf(stderr, "handle gc tcp oob handshake packet\n");
    if (handle_gc_handshake_packet(m, chat, nullptr, packet, length, false) == -1) {
        return -1;
    }

    return 0;
}

int handle_gc_udp_packet(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Chat *chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat) {
        fprintf(stderr, "get_chat_by_hash failed in handle_gc_udp_packet (type %u)\n", packet[0]);
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    if (packet[0] == NET_PACKET_GC_LOSSLESS) {
        return handle_gc_lossless_message(m, chat, packet, length, true);
    } else if (packet[0] == NET_PACKET_GC_LOSSY) {
        return handle_gc_lossy_message(m, chat, packet, length, true);
    } else if (packet[0] == NET_PACKET_GC_HANDSHAKE) {
        fprintf(stderr, "handle gc udp handshake packet\n");
        return handle_gc_handshake_packet(m, chat, &ipp, packet, length, true);
    }

    return -1;
}

void gc_callback_message(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int,
                         const uint8_t *, size_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->message = function;
    c->message_userdata = userdata;
}

void gc_callback_private_message(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int,
                                                                const uint8_t *, size_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
    c->private_message_userdata = userdata;
}

void gc_callback_custom_packet(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t,
                               const uint8_t *, size_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->custom_packet = function;
    c->custom_packet_userdata = userdata;
}

void gc_callback_moderation(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, uint32_t, unsigned int,
                            void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->moderation = function;
    c->moderation_userdata = userdata;
}

void gc_callback_nick_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *,
                             size_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
    c->nick_change_userdata = userdata;
}

void gc_callback_status_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int, void *),
                               void *userdata)
{
    GC_Session *c = m->group_handler;
    c->status_change = function;
    c->status_change_userdata = userdata;
}

void gc_callback_topic_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *,
                              size_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->topic_change = function;
    c->topic_change_userdata = userdata;
}

void gc_callback_peer_limit(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_limit = function;
    c->peer_limit_userdata = userdata;
}

void gc_callback_privacy_state(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int, void *),
                               void *userdata)
{
    GC_Session *c = m->group_handler;
    c->privacy_state = function;
    c->privacy_state_userdata = userdata;
}

void gc_callback_password(Messenger *m, void (*function)(Messenger *m, uint32_t, const uint8_t *, size_t, void *),
                          void *userdata)
{
    GC_Session *c = m->group_handler;
    c->password = function;
    c->password_userdata = userdata;
}

void gc_callback_peer_join(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_join = function;
    c->peer_join_userdata = userdata;
}

void gc_callback_peer_exit(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *, size_t,
                           void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
    c->peer_exit_userdata = userdata;
}

void gc_callback_self_join(Messenger *m, void (*function)(Messenger *m, uint32_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
    c->self_join_userdata = userdata;
}

void gc_callback_rejected(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
    c->rejected_userdata = userdata;
}

/* Deletes peer_number from group.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_peer_delete(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint16_t length)
{

    if (length) fprintf(stderr, "delete: %s\n", data);
    GC_Session *c = m->group_handler;

    GC_Chat *chat = gc_get_group(c, group_number);
    if (!chat) {
        return -1;
    }

    if ((chat->connection_state == CS_DISCONNECTED
         || chat->connection_state == CS_CONNECTING
         || chat->connection_state == CS_MANUALLY_DISCONNECTED)
        && !is_public_chat(chat)) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);
    if (!gconn) {
        return -1;
    }

    if (gconn->handshaked && !is_peer_confirmed(chat, gconn->addr.public_key)) {
        memcpy(chat->confirmed_peers[chat->confirmed_peers_index], gconn->addr.public_key, ENC_PUBLIC_KEY);
        chat->confirmed_peers_index = (chat->confirmed_peers_index + 1) % MAX_GC_CONFIRMED_PEERS;
    }

    /* Needs to occur before peer is removed*/
    if (c->peer_exit && gconn->confirmed) {
        (*c->peer_exit)(m, group_number, chat->group[peer_number].peer_id, data, length, c->peer_exit_userdata);
    }

    kill_tcp_connection_to(chat->tcp_conn, gconn->tcp_connection_num);
    gcc_peer_cleanup(gconn);

    --chat->numpeers;

    if (chat->numpeers != peer_number) {
        memcpy(&chat->group[peer_number], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));
        memcpy(&chat->gcc[peer_number], &chat->gcc[chat->numpeers], sizeof(GC_Connection));
    }

    memset(&chat->group[chat->numpeers], 0, sizeof(GC_GroupPeer));
    memset(&chat->gcc[chat->numpeers], 0, sizeof(GC_Connection));

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (tmp_group == nullptr) {
        return -1;
    }

    chat->group = tmp_group;

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * chat->numpeers);

    if (tmp_gcc == nullptr) {
        return -1;
    }

    chat->gcc = tmp_gcc;

    return 0;
}

/* Updates peer's peer info and generates a new peer_id.
 *
 * Returns peer_number on success.
 * Returns -1 on failure.
 */
static int peer_update(Messenger *m, int group_number, GC_GroupPeer *peer, uint32_t peer_number)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (peer->nick_length == 0) {
        return -1;
    }

    int nick_num = get_nick_peer_number(chat, peer->nick, peer->nick_length);
    bool is_nick_banned = sanctions_list_nick_banned(chat, peer->nick);

    if ((nick_num != -1 && nick_num != peer_number) || is_nick_banned) {   /* duplicate or banned nick */
        if (c->peer_exit) {
            (*c->peer_exit)(m, group_number, chat->group[peer_number].peer_id, nullptr, 0, c->peer_exit_userdata);
        }

        gc_peer_delete(m, group_number, peer_number, (const uint8_t *)"duplicate nick", 13);
        return -1;
    }

    GC_GroupPeer *curr_peer = &chat->group[peer_number];
    curr_peer->role = peer->role;
    curr_peer->status = peer->status;
    curr_peer->nick_length = peer->nick_length;
    memcpy(curr_peer->nick, peer->nick, MAX_GC_NICK_SIZE);

    return peer_number;
}

/* Adds a new peer to group_number's peer list.
 *
 * Return peer_number if success.
 * Return -1 on failure.
 * Returns -2 if a peer with public_key is already in our peerlist.
 */
static int peer_add(Messenger *m, int group_number, IP_Port *ipp, const uint8_t *public_key)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);
    if (!chat) {
        return -1;
    }

    if (get_peernum_of_enc_pk(chat, public_key) != -1) {
        return -2;
    }

    int tcp_connection_num = -1;

    if (chat->numpeers > 0) {
        tcp_connection_num = new_tcp_connection_to(chat->tcp_conn, public_key, 0);

        if (tcp_connection_num == -1) {
            return -1;
        }
    }

    int peer_number = chat->numpeers;

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * (chat->numpeers + 1));

    if (tmp_gcc == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    memset(&tmp_gcc[peer_number], 0, sizeof(GC_Connection));
    chat->gcc = tmp_gcc;

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (tmp_group == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    ++chat->numpeers;
    memset(&tmp_group[peer_number], 0, sizeof(GC_GroupPeer));
    chat->group = tmp_group;

    GC_Connection *gconn = &chat->gcc[peer_number];
    gconn->self_sent_shared_state_version = gconn->friend_shared_state_version = UINT32_MAX;

    if (ipp) {
        ipport_copy(&gconn->addr.ip_port, ipp);
    }

    chat->group[peer_number].role = GR_INVALID;
    chat->group[peer_number].peer_id = get_new_peer_id(chat);
    chat->group[peer_number].ignore = false;

    crypto_box_keypair(gconn->session_public_key, gconn->session_secret_key);
    memcpy(gconn->addr.public_key, public_key, ENC_PUBLIC_KEY);  /* we get the sig key in the handshake */

    gconn->public_key_hash = get_peer_key_hash(public_key);
    gconn->last_received_ping_time = mono_time_get(chat->mono_time) + (rand() % GC_PING_INTERVAL);
    gconn->send_message_id = 1;
    gconn->send_array_start = 1;
    gconn->received_message_id = 0;
    gconn->tcp_connection_num = tcp_connection_num;

    return peer_number;
}

/* Copies own peer data to peer */
static void self_to_peer(const GC_Chat *chat, GC_GroupPeer *peer)
{
    memset(peer, 0, sizeof(GC_GroupPeer));
    memcpy(peer->nick, chat->group[0].nick, chat->group[0].nick_length);
    peer->nick_length = chat->group[0].nick_length;
    peer->status = chat->group[0].status;
    peer->role = chat->group[0].role;
}

/* Returns true if we haven't received a ping from this peer after T seconds.
 * T depends on whether or not the peer has been confirmed.
 */
static bool peer_timed_out(const Mono_Time *mono_time, const GC_Chat *chat, GC_Connection *gconn)
{
    return mono_time_is_timeout(mono_time, gconn->last_received_ping_time, gconn->confirmed
                                ? GC_CONFIRMED_PEER_TIMEOUT
                                : GC_UNCONFIRMED_PEER_TIMEOUT);
}

static void do_peer_connections(Messenger *m, int group_number)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return;
    }

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            if (mono_time_is_timeout(m->mono_time, chat->gcc[i].last_tcp_relays_shared, GCC_TCP_SHARED_RELAYS_TIMEOUT)) {
                send_gc_tcp_relays(m->mono_time, chat, &chat->gcc[i]);
            }
        }

        if (peer_timed_out(m->mono_time, chat, &chat->gcc[i])) {
            gc_peer_delete(m, group_number, i, (const uint8_t *)"Timed out", 9);
        } else {
            gcc_resend_packets(m, chat, i);   // This function may delete the peer
        }

        if (i >= chat->numpeers) {
            break;
        }
    }
}

/* Ping packet includes your confirmed peer count, shared state version
 * and sanctions list version for syncing purposes
 */
static void ping_group(GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_sent_ping_time, GC_PING_INTERVAL)) {
        return;
    }

    uint32_t length = HASH_ID_BYTES + GC_PING_PACKET_DATA_SIZE;
    VLA(uint8_t, data, length);

    uint32_t num_confirmed_peers = get_gc_confirmed_numpeers(chat);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, num_confirmed_peers);
    net_pack_u32(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.version);
    net_pack_u32(data + HASH_ID_BYTES + (sizeof(uint32_t) * 2), chat->moderation.sanctions_creds.version);
    net_pack_u32(data + HASH_ID_BYTES + (sizeof(uint32_t) * 3), chat->topic_info.version);

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossy_group_packet(chat, &chat->gcc[i], data, length, GP_PING);
        }
    }

    chat->last_sent_ping_time = mono_time_get(chat->mono_time);
}

static void do_new_connection_cooldown(GC_Chat *chat)
{
    if (chat->connection_O_metre == 0) {
        return;
    }

    uint64_t tm = mono_time_get(chat->mono_time);

    if (chat->connection_cooldown_timer < tm) {
        chat->connection_cooldown_timer = tm;
        --chat->connection_O_metre;

        if (chat->connection_O_metre == 0) {
            chat->block_handshakes = false;
        }
    }
}

#define PENDING_HANDSHAKE_SENDING_MAX_INTERVAL 15
static int send_pending_handshake(GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number)
{
    if (!chat || !gconn || !peer_number) {
        return 1;
    }

    uint64_t time = mono_time_get(chat->mono_time);
    if (gconn->pending_handshake && chat->should_start_sending_handshakes) {
        gconn->pending_handshake = time;
    }

    if (!gconn->pending_handshake || time < gconn->pending_handshake) {
        return 0;
    }

    if (gconn->handshaked) {
        gconn->pending_handshake = 0;
        return 0;
    }

    int result;

    if (gconn->is_pending_handshake_response) {
        result = send_gc_handshake_response(chat, peer_number, gconn->pending_handshake_type);
    } else if (gconn->is_oob_handshake) {
        fprintf(stderr, "in send pending gc oob handshake\n");
        result = send_gc_oob_handshake_packet(chat, peer_number, GH_REQUEST,
                                              gconn->pending_handshake_type, chat->join_type);
    } else {
        fprintf(stderr, "in send pending gc handshake\n");
        result = send_gc_handshake_packet(chat, peer_number, GH_REQUEST,
                                          gconn->pending_handshake_type, chat->join_type);
    }
    fprintf(stderr, "in send pending handshake result %d\n", result);
    if (!result || time > gconn->pending_handshake + PENDING_HANDSHAKE_SENDING_MAX_INTERVAL) {
        gconn->pending_handshake = 0;
    }

    if (!result) {
        fprintf(stderr, "in send pending handshake  increment %ld\n", gconn->send_message_id);
        if (!gconn->is_pending_handshake_response) {
            gconn->send_message_id = 2;
        } else {
            gconn->send_message_id++;
        }

    }

    return 0;
}

static void do_group_tcp(GC_Chat *chat, void *userdata)
{
    if (!chat->tcp_conn || chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        return;
    }

    do_tcp_connections(chat->tcp_conn, userdata);

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];
        bool tcp_set = !gcc_connection_is_direct(chat->mono_time, gconn);
        set_tcp_connection_to_status(chat->tcp_conn, gconn->tcp_connection_num, tcp_set);

        send_pending_handshake(chat, gconn, i);
    }

    chat->should_start_sending_handshakes = false;
}

#define GROUP_JOIN_ATTEMPT_INTERVAL 20
#define TCP_RELAYS_TEST_COUNT 1

/* CS_CONNECTED: Peers are pinged, unsent packets are resent, and timeouts are checked.
 * CS_CONNECTING: Look for new DHT nodes after an interval.
 * CS_DISCONNECTED: Send an invite request using a random node if our timeout GROUP_JOIN_ATTEMPT_INTERVAL has expired.
 * CS_FAILED: Do nothing. This occurs if we cannot connect to a group or our invite request is rejected.
 */
void do_gc(GC_Session *c, void *userdata)
{
    if (!c) {
        return;
    }

    uint32_t i;
    int j;

    for (i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];
        do_group_tcp(chat, userdata);

        switch (chat->connection_state) {
            case CS_CONNECTED: {
                ping_group(chat);
                do_peer_connections(c->messenger, i);
                do_new_connection_cooldown(chat);
                break;
            }

            case CS_CONNECTING: {
                if (mono_time_is_timeout(chat->mono_time, chat->last_join_attempt, GROUP_JOIN_ATTEMPT_INTERVAL)) {
                    chat->connection_state = CS_DISCONNECTED;
                }

                break;
            }

            case CS_DISCONNECTED: {
                Node_format tcp_relays[TCP_RELAYS_TEST_COUNT];
                int tcp_num = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, TCP_RELAYS_TEST_COUNT);
                if (tcp_num != TCP_RELAYS_TEST_COUNT) {
                    add_tcp_relays_to_chat(c->messenger, chat);
                }

                if (chat->numpeers <= 1 || !mono_time_is_timeout(c->messenger->mono_time, chat->last_join_attempt, GROUP_JOIN_ATTEMPT_INTERVAL)) {
                    break;
                }

                chat->last_join_attempt = mono_time_get(c->messenger->mono_time);
                chat->connection_state = CS_CONNECTING;

                for (j = 1; j < chat->numpeers; j++) {
                    GC_Connection *gconn = &chat->gcc[j];
                    if (!gconn->handshaked && !gconn->pending_handshake) {
                        gconn->pending_handshake = mono_time_get(c->messenger->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
                    }
                }

                break;
            }

            case CS_MANUALLY_DISCONNECTED:
            case CS_FAILED: {
                break;
            }
        }
    }
}

/* Set the size of the groupchat list to n.
 *
 *  return -1 on failure.
 *  return 0 success.
 */
static int realloc_groupchats(GC_Session *c, uint32_t n)
{
    if (n == 0) {
        free(c->chats);
        c->chats = nullptr;
        return 0;
    }

    GC_Chat *temp = (GC_Chat *)realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == nullptr) {
        return -1;
    }

    c->chats = temp;
    return 0;
}

static int get_new_group_index(GC_Session *c)
{
    if (c == nullptr) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state == CS_NONE) {
            return i;
        }
    }

    if (realloc_groupchats(c, c->num_chats + 1) != 0) {
        return -1;
    }

    int new_index = c->num_chats;
    memset(&(c->chats[new_index]), 0, sizeof(GC_Chat));
    memset(&(c->chats[new_index].saved_invites), -1, MAX_GC_SAVED_INVITES * sizeof(uint32_t));

    ++c->num_chats;

    return new_index;
}

static GC_Chat* get_chat_by_tcp_connections(GC_Session *group_handler, TCP_Connections *tcp_c)
{
    uint32_t i;
    for (i = 0; i < group_handler->num_chats; i++) {
        GC_Chat *chat = &group_handler->chats[i];
        if (chat->tcp_conn == tcp_c) {
            return chat;
        }
    }

    return nullptr;
}

static void handle_connection_status_updated_callback(void *object, TCP_Connections *tcp_c, int status)
{
    Messenger *m = (Messenger *)object;

    GC_Chat *chat = get_chat_by_tcp_connections(m->group_handler, tcp_c);
    if (!chat) {
        return;
    }

    fprintf(stderr, "updated gc data\n");

    if (status != TCP_CONNECTIONS_STATUS_REGISTERED) {
        fprintf(stderr, "update self ann\n");
        chat->should_update_self_announces = true;
    }

    if (status == TCP_CONNECTIONS_STATUS_ONLINE) {
        fprintf(stderr, "try send handshakes\n");
        chat->should_start_sending_handshakes = true;
    }
}

static void add_tcp_relays_to_chat(Messenger *m, GC_Chat *chat)
{
    uint16_t num_relays = tcp_connections_count(nc_get_tcp_c(m->net_crypto));

    if (num_relays == 0) {
        // TODO(iphydf): This should be an error, but for now TCP isn't working.
        return 0;
    }

    VLA(Node_format, tcp_relays, num_relays);
    unsigned int i, num = tcp_copy_connected_relays(nc_get_tcp_c(m->net_crypto), tcp_relays, num_relays);

    for (i = 0; i < num; ++i) {
        add_tcp_relay_global(chat->tcp_conn, tcp_relays[i].ip_port, tcp_relays[i].public_key);
    }
}

static int init_gc_tcp_connection(Messenger *m, GC_Chat *chat)
{
    chat->tcp_conn = new_tcp_connections(m->mono_time, chat->self_secret_key, &m->options.proxy_info);

    if (chat->tcp_conn == nullptr) {
        return -1;
    }

    add_tcp_relays_to_chat(m, chat);

    set_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_packet, m);
    set_oob_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_oob_packet, m);
    set_connection_status_updated_callback(chat->tcp_conn, &handle_connection_status_updated_callback, m);

    return 0;
}

static int create_new_group(GC_Session *c, const GC_SelfPeerInfo *peer_info, bool founder)
{
    int group_number = get_new_group_index(c);
    if (group_number == -1) {
        return -1;
    }

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];

    create_extended_keypair(chat->self_public_key, chat->self_secret_key);

    if (init_gc_tcp_connection(m, chat) == -1) {
        group_delete(c, chat);
        return -1;
    }

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_sent_ping_time = mono_time_get(m->mono_time);

    if (peer_add(m, group_number, nullptr, chat->self_public_key) != 0) {    /* you are always peer_number/index 0 */
        group_delete(c, chat);
        return -1;
    }

    memcpy(chat->group[0].nick, peer_info->nick, peer_info->nick_length);
    chat->group[0].nick_length = peer_info->nick_length;
    chat->group[0].status = peer_info->user_status;
    chat->group[0].role = founder ? GR_FOUNDER : GR_USER;
    chat->gcc[0].confirmed = true;
    chat->self_public_key_hash = chat->gcc[0].public_key_hash;
    memcpy(chat->gcc[0].addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);

    return group_number;
}

/* Initializes group shared state and creates a signature for it using the chat secret key.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int init_gc_shared_state(GC_Chat *chat, uint8_t privacy_state, const uint8_t *group_name,
                                uint16_t name_length)
{
    memcpy(chat->shared_state.founder_public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->shared_state.group_name, group_name, name_length);
    chat->shared_state.group_name_len = name_length;
    chat->shared_state.maxpeers = MAX_GC_NUM_PEERS;
    chat->shared_state.privacy_state = privacy_state;

    return sign_gc_shared_state(chat);
}

/* Inits the sanctions list credentials. This should be called by the group founder on creation.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int init_gc_sanctions_creds(GC_Chat *chat)
{
    if (sanctions_list_make_creds(chat) == -1) {
        return -1;
    }

    return 0;
}

void gc_load_peers(Messenger* m, GC_Chat* chat, GC_SavedPeerInfo *addrs, uint16_t num_addrs)
{
    int i;
    for (i = 0; i < num_addrs && i < MAX_GC_PEER_ADDRS; ++i) {
        bool ip_port_is_set = ipport_isset(&addrs[i].ip_port);
        IP_Port *ip_port = ip_port_is_set ? &addrs[i].ip_port : nullptr;
        int peer_number = peer_add(m, chat->group_number, ip_port, addrs[i].public_key);
        if (peer_number < 0) {
            continue;
        }

        GC_Connection *gconn = gcc_get_connection(chat, peer_number);
        if (!gconn) {
            continue;
        }

        add_tcp_relay_global(chat->tcp_conn, addrs[i].tcp_relay.ip_port, addrs[i].tcp_relay.public_key);

        int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                                      addrs[i].tcp_relay.ip_port,
                                                      addrs[i].tcp_relay.public_key);
        if (add_tcp_result < 0 && !ip_port_is_set) {
            fprintf(stderr, "`error adding relay\n");
            continue;
        }

        int save_tcp_result = save_tcp_relay(gconn, &addrs[i].tcp_relay);
        if (save_tcp_result < 0 && !ip_port_is_set) {
            continue;
        }

        memcpy(gconn->oob_relay_pk, addrs[i].tcp_relay.public_key, ENC_PUBLIC_KEY);
        gconn->is_oob_handshake = add_tcp_result == 0;
        gconn->is_pending_handshake_response = false;
        gconn->pending_handshake_type = HS_INVITE_REQUEST;
        gconn->last_received_ping_time = gconn->pending_handshake = mono_time_get(chat->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
    }
}

/* Loads a previously saved group and attempts to connect to it.
 *
 * Returns group number on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, Saved_Group *save, int group_number)
{
    group_number = group_number == -1 ? get_new_group_index(c) : group_number;
    if (group_number == -1) {
        return -1;
    }

    uint64_t tm = mono_time_get(c->messenger->mono_time);

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];
    bool is_active_chat = save->group_connection_state != SGCS_DISCONNECTED;

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->connection_state = is_active_chat ? CS_CONNECTING : CS_MANUALLY_DISCONNECTED;
    chat->join_type = HJ_PRIVATE;
    chat->last_join_attempt = tm;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_sent_ping_time = tm;

    memcpy(chat->shared_state.founder_public_key, save->founder_public_key, EXT_PUBLIC_KEY);
    chat->shared_state.group_name_len = net_ntohs(save->group_name_length);
    memcpy(chat->shared_state.group_name, save->group_name, MAX_GC_GROUP_NAME_SIZE);
    chat->shared_state.privacy_state = save->privacy_state;
    chat->shared_state.maxpeers = net_ntohs(save->maxpeers);
    chat->shared_state.password_length = net_ntohs(save->password_length);
    memcpy(chat->shared_state.password, save->password, MAX_GC_PASSWORD_SIZE);
    memcpy(chat->shared_state.mod_list_hash, save->mod_list_hash, GC_MODERATION_HASH_SIZE);
    chat->shared_state.version = net_ntohl(save->shared_state_version);
    memcpy(chat->shared_state_sig, save->shared_state_signature, SIGNATURE_SIZE);

    chat->topic_info.length = net_ntohs(save->topic_length);
    memcpy(chat->topic_info.topic, save->topic, MAX_GC_TOPIC_SIZE);
    memcpy(chat->topic_info.public_sig_key, save->topic_public_sig_key, SIG_PUBLIC_KEY);
    chat->topic_info.version = net_ntohl(save->topic_version);
    memcpy(chat->topic_sig, save->topic_signature, SIGNATURE_SIZE);

    memcpy(chat->chat_public_key, save->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->chat_secret_key, save->chat_secret_key, EXT_SECRET_KEY);

    uint16_t num_mods = net_ntohs(save->num_mods);
    fprintf(stderr, "num mods %d\n", num_mods);

    if (mod_list_unpack(chat, save->mod_list, num_mods * GC_MOD_LIST_ENTRY_SIZE, num_mods) == -1) {
        return -1;
    }

    memcpy(chat->self_public_key, save->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->self_secret_key, save->self_secret_key, EXT_SECRET_KEY);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->self_public_key_hash = get_peer_key_hash(chat->self_public_key);

    if (peer_add(m, group_number, nullptr, save->self_public_key) != 0) {
        return -1;
    }

    memcpy(chat->gcc[0].addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->group[0].nick, save->self_nick, MAX_GC_NICK_SIZE);
    chat->group[0].nick_length = net_ntohs(save->self_nick_length);
    chat->group[0].role = save->self_role;
    chat->group[0].status = save->self_status;
    chat->gcc[0].confirmed = true;

    if (save->self_role == GR_FOUNDER) {
        if (init_gc_sanctions_creds(chat) == -1) {
            return -1;
        }
    }

    if (!is_active_chat) {
        chat->save = (Saved_Group *)malloc(sizeof(Saved_Group));
        if (!chat->save) {
            return -1;
        }

        memcpy(chat->save, save, sizeof(Saved_Group));

        return group_number;
    }

    if (init_gc_tcp_connection(m, chat) == -1) {
        return -1;
    }

    if (is_public_chat(chat)) {
        m_add_friend_gc(m, chat);
    }

    uint16_t num_addrs = net_ntohs(save->num_addrs);
    gc_load_peers(m, chat, save->addrs, num_addrs);

    return group_number;
}

/* Creates a new group.
 *
 * Return group_number on success.
 * Return -1 if the group name is too long.
 * Return -2 if the group name is empty.
 * Return -3 if the privacy state is an invalid type.
 * Return -4 if the the group object fails to initialize.
 * Return -5 if the group state fails to initialize.
 * Return -6 if the self peer info is invalid
 * Return -7 if the announce was unsuccessful
*/
int gc_group_add(GC_Session *c, uint8_t privacy_state, const uint8_t *group_name, uint16_t group_name_length,
                 const GC_SelfPeerInfo *peer_info)
{
    if (group_name_length > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    if (group_name_length == 0 || group_name == nullptr) {
        return -2;
    }

    if (!is_self_peer_info_valid(peer_info)) {
        return -6;
    }

    if (privacy_state >= GI_INVALID) {
        return -3;
    }

    int group_number = create_new_group(c, peer_info, true);

    if (group_number == -1) {
        return -4;
    }

    GC_Chat *chat = gc_get_group(c, group_number);
    if (chat == nullptr) {
        return -4;
    }

    create_extended_keypair(chat->chat_public_key, chat->chat_secret_key);

    if (init_gc_shared_state(chat, privacy_state, group_name, group_name_length) == -1) {
        group_delete(c, chat);
        return -5;
    }

    if (init_gc_sanctions_creds(chat) == -1) {
        group_delete(c, chat);
        return -5;
    }

    if (gc_set_topic(chat, (const uint8_t *)" ", 1) != 0) {
        group_delete(c, chat);
        return -5;
    }

    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;
    self_gc_connected(c->messenger->mono_time, chat);

    if (is_public_chat(chat)) {
        int friend_number = m_add_friend_gc(c->messenger, chat);
        if (friend_number < 0) {
            group_delete(c, chat);
            return -7;
        }
    }

    return group_number;
}

/* Sends an invite request to a public group using the chat_id.
 *
 * If the group is not password protected password should be set to NULL and password_length should be 0.
 *
 * Return group_number on success.
 * Return -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or a group with chat_id already exists in the chats array.
 * Return -3 if there is an error setting the group password.
 * Return -4 if there is an error adding a friend
 * Return -5 if there is an error setting self name and status
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *passwd, uint16_t passwd_len,
                  const GC_SelfPeerInfo *peer_info)
{
    if (chat_id == nullptr || group_exists(c, chat_id) || getfriend_id(c->messenger, chat_id) != -1) {
        return -2;
    }

    if (!is_self_peer_info_valid(peer_info)) {
        return -5;
    }

    int group_number = create_new_group(c, peer_info, false);

    if (group_number == -1) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PUBLIC;
    chat->last_join_attempt = mono_time_get(chat->mono_time);
    chat->connection_state = CS_CONNECTING;

    if (passwd != nullptr && passwd_len > 0) {
        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            return -3;
        }
    }

    int friend_number = m_add_friend_gc(c->messenger, chat);
    if (friend_number < 0) {
        return -4;
    }

    return group_number;
}

bool gc_disconnect_from_group(GC_Session *c, GC_Chat *chat)
{
    if (!c || !chat) {
        return false;
    }

    uint8_t previous_state = chat->connection_state;
    chat->connection_state = CS_MANUALLY_DISCONNECTED;

    chat->save = (Saved_Group *)malloc(sizeof(Saved_Group));
    if (!chat->save) {
        chat->connection_state = previous_state;

        return false;
    }

    send_gc_broadcast_message(chat, nullptr, 0, GM_PEER_EXIT);

    // save info about group
    pack_group_info(chat, chat->save, false);

    // cleanup gc data
    group_cleanup(c, chat);

    return true;
}

static bool gc_rejoin_disconnected_group(GC_Session *c, GC_Chat *chat)
{
    chat->save->group_connection_state = SGCS_CONNECTED;

    int group_loading_result = gc_group_load(c, chat->save, chat->group_number);
    bool rejoin_successful = group_loading_result != -1;

    if (rejoin_successful) {
        free(chat->save);
        chat->save = nullptr;
    }

    return rejoin_successful;
}

static bool gc_rejoin_connected_group(GC_Session *c, GC_Chat *chat)
{
    GC_SavedPeerInfo peers[GROUP_SAVE_MAX_PEERS];
    uint16_t i, num_addrs = gc_copy_peer_addrs(chat, peers, GROUP_SAVE_MAX_PEERS);
    chat->connection_state = CS_CONNECTED;

    /* Remove all peers except self. Numpeers decrements with each call to gc_peer_delete */
    for (i = 1; chat->numpeers > 1;) {
        gc_peer_delete(c->messenger, chat->group_number, i, nullptr, 0);
    }

    if (is_public_chat(chat)) {
        m_remove_friend_gc(c->messenger, chat);
        m_add_friend_gc(c->messenger, chat);
    }

    gc_load_peers(c->messenger, chat, peers, num_addrs);
    chat->connection_state = CS_CONNECTING;

    return true;
}

/* Resets chat saving all self state and attempts to reconnect to group */
bool gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    if (!c || !chat) {
        return false;
    }

    return (chat->connection_state == CS_MANUALLY_DISCONNECTED ? gc_rejoin_disconnected_group
                                                               : gc_rejoin_connected_group)(c, chat);
}


bool check_group_invite(GC_Session *c, const uint8_t *data, uint32_t length)
{
    if (length <= CHAT_ID_SIZE) {
        return false;
    }

    return !gc_get_group_by_public_key(c, data);
}


/* Invites friendnumber to chat. Packet includes: Type, chat_id, node
 *
 * Return 0 on success.
 * Return -1 if friendnumber does not exist.
 * Return -2 if the packet fails to send.
 */
int gc_invite_friend(GC_Session *c, GC_Chat *chat, int32_t friend_number,
                     int send_group_invite_packet(const Messenger *m, uint32_t friendnumber, const uint8_t *packet, size_t length))
{
    if (friend_not_valid(c->messenger, friend_number)) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE;

    memcpy(packet + 2, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);

    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key, ENC_PUBLIC_KEY);

    length += ENC_PUBLIC_KEY;
    size_t group_name_length = chat->shared_state.group_name_len;
    memcpy(packet + length, chat->shared_state.group_name, group_name_length);
    length += group_name_length;

    if (send_group_invite_packet(c->messenger, friend_number, packet, length) == -1) {
        return -2;
    }

    chat->saved_invites[chat->saved_invites_index] = friend_number;
    chat->saved_invites_index = (chat->saved_invites_index + 1) % MAX_GC_SAVED_INVITES;

    return 0;
}

static int send_gc_invite_accepted_packet(Messenger *m, GC_Chat *chat, uint32_t friend_number)
{
    if (friend_not_valid(m, friend_number)) {
        return -1;
    }

    if (!chat) {
        return -2;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_ACCEPTED;

    memcpy(packet + 2, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);

    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key, ENC_PUBLIC_KEY);

    length += ENC_PUBLIC_KEY;

    fprintf(stderr, "send_gc_invite_accepted_packet\n");

    if (send_group_invite_packet(m, friend_number, packet, length) == -1) {
        fprintf(stderr, "send_gc_invite_accepted_packet error\n");
        return -3;
    }

    return 0;
}

static int send_gc_invite_confirmed_packet(Messenger *m, GC_Chat *chat, uint32_t friend_number,
                                           const uint8_t *data, uint16_t length)
{
    if (friend_not_valid(m, friend_number)) {
        return -1;
    }

    if (!chat) {
        return -2;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_CONFIRMATION;

    memcpy(packet + 2, data, length);

    fprintf(stderr, "send_gc_invite_confirmed_packet\n");

    if (send_group_invite_packet(m, friend_number, packet, length + 2) == -1) {
        return -3;
    }

    return 0;
}

static bool copy_ip_port_to_gconn(Messenger *m, int friend_number, GC_Connection *gconn)
{
    Friend *f = &m->friendlist[friend_number];
    int friend_connection_id = f->friendcon_id;
    Friend_Conn *connection = &m->fr_c->conns[friend_connection_id];
    IP_Port *friend_ip_port = &connection->dht_ip_port;
    if (!ipport_isset(friend_ip_port)) {
        return false;
    }

    memcpy(&gconn->addr.ip_port, friend_ip_port, sizeof(IP_Port));

    return true;
}

int handle_gc_invite_confirmed_packet(GC_Session *c, int friend_number, const uint8_t *data,
                                      uint32_t length)
{
    fprintf(stderr, "handle_gc_invite_confirmed_packet\n");
    if (length < GC_JOIN_DATA_LENGTH) {
        return -1;
    }

    if (friend_not_valid(c->messenger, friend_number)) {
        return -4;
    }

    fprintf(stderr, "handle_gc_invite_confirmed_packet1\n");

    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t invite_chat_pk[ENC_PUBLIC_KEY];

    memcpy(chat_id, data, CHAT_ID_SIZE);
    memcpy(invite_chat_pk, data + CHAT_ID_SIZE, ENC_PUBLIC_KEY);

    GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);

    if (chat == nullptr) {
        return -2;
    }

    int peer_number = get_peernum_of_enc_pk(chat, invite_chat_pk);
    if (peer_number < 0) {
        return -3;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS,
                                 nullptr, data + ENC_PUBLIC_KEY + CHAT_ID_SIZE,
                                 length - GC_JOIN_DATA_LENGTH, 1);

    bool copy_ip_port_result = copy_ip_port_to_gconn(c->messenger, friend_number, gconn);
    if (num_nodes <= 0 && !copy_ip_port_result) {
        return -1;
    }

    int i;
    for (i = 0; i < num_nodes; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
        save_tcp_relay(gconn, &tcp_relays[i]);
    }

    if (copy_ip_port_result) {
        fprintf(stderr, "sending handshake to hell\n");
        send_gc_handshake_packet(chat, peer_number, GH_REQUEST, HS_INVITE_REQUEST, chat->join_type);
        gconn->send_message_id = 2;
    } else {
        gconn->pending_handshake_type = HS_INVITE_REQUEST;
        gconn->is_pending_handshake_response = gconn->is_oob_handshake = false;
        gconn->pending_handshake = mono_time_get(chat->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
    }

    return 0;
}

bool friend_was_invited(GC_Chat *chat, int friend_number)
{
    int i;
    for (i = 0; i < MAX_GC_SAVED_INVITES; i++) {
        if (chat->saved_invites[i] == friend_number) {
            chat->saved_invites[i] = -1;

            return true;
        }
    }

    return false;
}

int handle_gc_invite_accepted_packet(GC_Session *c, int friend_number, const uint8_t *data,
                                     uint32_t length)
{
    fprintf(stderr, "handle_gc_invite_accepted_packet1\n");
    if (length < GC_JOIN_DATA_LENGTH) {
        return -1;
    }
    Messenger *m = c->messenger;

    if (friend_not_valid(m, friend_number)) {
        return -4;
    }
    fprintf(stderr, "handle_gc_invite_accepted_packet2\n");

    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t invite_chat_pk[ENC_PUBLIC_KEY];

    memcpy(chat_id, data, CHAT_ID_SIZE);
    memcpy(invite_chat_pk, data + CHAT_ID_SIZE, ENC_PUBLIC_KEY);

    GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);
    if (!chat || chat->connection_state <= CS_MANUALLY_DISCONNECTED) {
        return -2;
    }

    if (!friend_was_invited(chat, friend_number)) {
        return -2;
    }

    int peer_number = peer_add(m, chat->group_number, nullptr, invite_chat_pk);
    if (peer_number < 0) {
        return -3;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    unsigned int i, num = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    bool copy_ip_port_result = copy_ip_port_to_gconn(m, friend_number, gconn);
    if (num <= 0 && !copy_ip_port_result) {
        return -1;
    }

    uint32_t len = GC_JOIN_DATA_LENGTH;
    uint8_t send_data[MAX_GC_PACKET_SIZE];
    memcpy(send_data, chat_id, CHAT_ID_SIZE);
    memcpy(send_data + CHAT_ID_SIZE, chat->self_public_key, ENC_PUBLIC_KEY);

    if (num > 0) {
        for (i = 0; i < num; ++i) {
            add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                     tcp_relays[i].public_key);
            save_tcp_relay(gconn, &tcp_relays[i]);
        }

        int nodes_len = pack_nodes(send_data + len, sizeof(send_data) - len, tcp_relays, num);

        if (nodes_len <= 0 && !copy_ip_port_result) {
            return -1;
        }

        len += nodes_len;
    }
    fprintf(stderr, "send_gc_invite_confirmed_packet\n");
    if (send_gc_invite_confirmed_packet(m, chat, friend_number, send_data, len)) {
        return -4;
    }

    return 0;
}

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return group_number on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if there is an error setting the password.
 * Return -4 if friend doesn't exist
 * Return -5 if sending packet failed
 * Return -6 if self peer info is invalid
 */
int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length,
                     const uint8_t *passwd, uint16_t passwd_len,
                     const GC_SelfPeerInfo *peer_info)
{
    if (length < CHAT_ID_SIZE + ENC_PUBLIC_KEY) {
        return -1;
    }

    if (friend_not_valid(c->messenger, friend_number)) {
        return -4;
    }

    if (!is_self_peer_info_valid(peer_info)) {
        return -6;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t invite_chat_pk[ENC_PUBLIC_KEY];

    memcpy(chat_id, data, CHAT_ID_SIZE);
    memcpy(invite_chat_pk, data + CHAT_ID_SIZE, ENC_PUBLIC_KEY);

    int err = -2;
    int group_number = create_new_group(c, peer_info, false);

    if (group_number == -1) {
        return err;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        group_delete(c, chat);
        return err;
    }

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;
    chat->shared_state.privacy_state = GI_PRIVATE;
    chat->last_join_attempt = mono_time_get(c->messenger->mono_time);

    if (passwd != nullptr && passwd_len > 0) {
        err = -3;

        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            group_delete(c, chat);
            return err;
        }
    }

    int peer_id = peer_add(c->messenger, group_number, nullptr, invite_chat_pk);
    if (peer_id < 0) {
        return -1;
    }

    if (send_gc_invite_accepted_packet(c->messenger, chat, friend_number)) {
        return -5;
    }

    return group_number;
}

GC_Session *new_dht_groupchats(Messenger *m)
{
    GC_Session *c = (GC_Session *)calloc(sizeof(GC_Session), 1);

    if (c == nullptr) {
        return nullptr;
    }

    c->messenger = m;
    c->announces_list = m->group_announce;

    networking_registerhandler(m->net, NET_PACKET_GC_LOSSLESS, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_LOSSY, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_HANDSHAKE, &handle_gc_udp_packet, m);

    return c;
}

static void group_cleanup(GC_Session *c, GC_Chat *chat)
{
    if (!c || !chat) {
        return;
    }

    m_remove_friend_gc(c->messenger, chat);

    mod_list_cleanup(chat);
    sanctions_list_cleanup(chat);
    if (chat->tcp_conn) {
        kill_tcp_connections(chat->tcp_conn);
    }
    gcc_cleanup(chat);

    if (chat->group) {
        free(chat->group);
        chat->group = nullptr;
    }
}

/* Deletes chat from group chat array and cleans up.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int group_delete(GC_Session *c, GC_Chat *chat)
{
    if (!c || !chat) {
        return -1;
    }

    group_cleanup(c, chat);

    memset(&(c->chats[chat->group_number]), 0, sizeof(GC_Chat));

    uint32_t i;

    for (i = c->num_chats; i > 0; --i) {
        if (c->chats[i - 1].connection_state != CS_NONE) {
            break;
        }
    }

    if (c->num_chats != i) {
        c->num_chats = i;

        if (realloc_groupchats(c, c->num_chats) != 0) {
            return -1;
        }
    }

    return 0;
}

/* Sends parting message to group and deletes group.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length)
{
    bool is_chat_active = chat->connection_state != CS_MANUALLY_DISCONNECTED;
    int ret = is_chat_active ? send_gc_self_exit(chat, message, length) : 0;

    group_delete(c, chat);

    return ret;
}

void kill_dht_groupchats(GC_Session *c)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];
        if (chat->connection_state != CS_NONE && chat->connection_state != CS_MANUALLY_DISCONNECTED) {
            send_gc_self_exit(chat, nullptr, 0);
            group_cleanup(c, chat);
        }
    }

    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSY, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSLESS, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_HANDSHAKE, nullptr, nullptr);

    free(c->chats);
    free(c);
}

/* Return 1 if group_number is a valid group chat index
 * Return 0 otherwise
 */
static bool group_number_valid(const GC_Session *c, int group_number)
{
    if (group_number < 0 || group_number >= c->num_chats) {
        return false;
    }

    if (c->chats == nullptr) {
        return false;
    }

    return c->chats[group_number].connection_state != CS_NONE;
}

/* Count number of active groups.
 *
 * Returns the count.
 */
uint32_t gc_count_groups(const GC_Session *c)
{
    uint32_t i, count = 0;

    for (i = 0; i < c->num_chats; i++) {
        if (c->chats[i].connection_state > CS_NONE && c->chats[i].connection_state < CS_INVALID) {
            count++;
        }
    }

    return count;
}

void gc_copy_groups_numbers(const GC_Session *c, uint32_t *list)
{
    uint32_t i, count = 0;

    for (i = 0; i < c->num_chats; i++) {
        if (c->chats[i].connection_state > CS_NONE && c->chats[i].connection_state < CS_INVALID) {
            list[count++] = i;
        }
    }
}

/* Return group_number's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session *c, int group_number)
{
    if (!group_number_valid(c, group_number)) {
        return nullptr;
    }

    return &c->chats[group_number];
}

GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key)
{
    int i;
    for (i = 0; i < c->num_chats; i++) {
        if (!memcmp(public_key, get_chat_id(c->chats[i].chat_public_key), CHAT_ID_SIZE)) {
            return &c->chats[i];
        }
    }

    return nullptr;
}

/* Return peer_number of peer with nick if nick is taken.
 * Return -1 if nick is not taken.
 */
static int get_nick_peer_number(const GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].nick_length == length && memcmp(chat->group[i].nick, nick, length) == 0) {
            return i;
        }
    }

    return -1;
}

/* Return True if chat_id exists in the session chat array */
static bool group_exists(const GC_Session *c, const uint8_t *chat_id) {
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (memcmp(get_chat_id(c->chats[i].chat_public_key), chat_id, CHAT_ID_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

int add_peers_from_announces(const GC_Session *gc_session, GC_Chat *chat, GC_Announce *announces, uint8_t gc_announces_count)
{
    if (!chat || !announces || !gc_session) {
        return -1;
    }

    int i, j, added_peers = 0;
    for (i = 0; i < gc_announces_count; i++) {
        GC_Announce *curr_announce = &announces[i];

        if (!is_valid_announce(curr_announce)) {
            fprintf(stderr, "invalid ann\n");
            continue;
        }

        bool ip_port_set = curr_announce->ip_port_is_set;
        IP_Port *ip_port = ip_port_set ? &curr_announce->ip_port : nullptr;
        int peer_number = peer_add(gc_session->messenger, chat->group_number,
                                   ip_port, curr_announce->peer_public_key);
        if (peer_number < 0) {
            continue;
        }

        GC_Connection *gconn = gcc_get_connection(chat, peer_number);
        if (!gconn) {
            continue;
        }

        uint8_t tcp_relays_count = curr_announce->tcp_relays_count;
        for (j = 0; j < tcp_relays_count; j++) {
            int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                                          curr_announce->tcp_relays[j].ip_port,
                                                          curr_announce->tcp_relays[j].public_key);
            if (add_tcp_result < 0) {
                continue;
            }

            int save_tcp_result = save_tcp_relay(gconn, &curr_announce->tcp_relays[j]);
            if (save_tcp_result) {
                continue;
            }

            memcpy(gconn->oob_relay_pk, curr_announce->tcp_relays[j].public_key, ENC_PUBLIC_KEY);
        }

        if (ip_port_set && !tcp_relays_count) {
            fprintf(stderr, "ip_port_set && !curr_announce->base_announce.tcp_relays_count\n");
            send_gc_handshake_packet(chat, peer_number, GH_REQUEST, HS_INVITE_REQUEST, chat->join_type);
            gconn->send_message_id = 2;
        } else {
            fprintf(stderr, "send oob %d\n", curr_announce->tcp_relays_count);
            gconn->is_oob_handshake = true;
            gconn->is_pending_handshake_response = false;
            gconn->pending_handshake_type = HS_INVITE_REQUEST;
            gconn->pending_handshake = gconn->last_received_ping_time = mono_time_get(chat->mono_time) + HANDSHAKE_SENDING_TIMEOUT;
        }

        added_peers++;
        fprintf(stderr, "Added peers %s\n", id_toa(curr_announce->peer_public_key));
    }

    return added_peers;
}

size_t group_get_peers_list_size(const GC_Chat *chat)
{
    int i, count = 0;
    for (i = 0; i < chat->numpeers; i++) {
        if (chat->gcc[i].confirmed) {
            count++;
        }
    }

    return count * sizeof(uint32_t);
}

void group_get_peers_list(const GC_Chat *chat, uint32_t *peers_list)
{
    int i, index = 0;
    for (i = 0; i < chat->numpeers; i++) {
        if (chat->gcc[i].confirmed) {
            peers_list[index] = chat->group[i].peer_id;
            index++;
        }
    }
}
