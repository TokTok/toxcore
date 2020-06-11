/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_CHATS_H
#define GROUP_CHATS_H

#include <stdbool.h>
#include "TCP_connection.h"
#include "group_announce.h"

#define TIME_STAMP_SIZE (sizeof(uint64_t))
#define HASH_ID_BYTES (sizeof(uint32_t))

#define MAX_GC_NICK_SIZE 128
#define MAX_GC_TOPIC_SIZE 512
#define MAX_GC_GROUP_NAME_SIZE 48
#define MAX_GC_MESSAGE_SIZE 1372
#define MAX_GC_PART_MESSAGE_SIZE 128
#define MAX_GC_PEER_ADDRS 30
#define MAX_GC_PASSWORD_SIZE 32
#define MAX_GC_MODERATORS 30
#define MAX_GC_SAVED_INVITES 50
#define MAX_GC_PACKET_SIZE ((uint16_t) 1400)

#define GC_MOD_LIST_ENTRY_SIZE SIG_PUBLIC_KEY
#define GC_MODERATION_HASH_SIZE CRYPTO_SHA256_SIZE
#define GC_PING_TIMEOUT 12
#define GC_SEND_IP_PORT_INTERVAL (GC_PING_TIMEOUT * 5)
#define GC_CONFIRMED_PEER_TIMEOUT (GC_PING_TIMEOUT * 6 + 10)
#define GC_UNCONFIRMED_PEER_TIMEOUT GC_PING_TIMEOUT

#define GC_JOIN_DATA_LENGTH (ENC_PUBLIC_KEY + CHAT_ID_SIZE)

typedef enum Self_UDP_Status {
    SELF_UDP_STATUS_NONE,
    SELF_UDP_STATUS_WAN,
    SELF_UDP_STATUS_LAN,
} Self_UDP_Status;

typedef enum Group_Privacy_State {
    GI_PUBLIC,
    GI_PRIVATE,
    GI_INVALID,
} Group_Privacy_State;

typedef enum Group_Moderation_Event {
    MV_KICK,
    MV_OBSERVER,
    MV_USER,
    MV_MODERATOR,
    MV_INVALID,
} Group_Moderation_Event;

typedef enum Group_Exit_Type {
    GC_EXIT_TYPE_QUIT,
    GC_EXIT_TYPE_TIMEOUT,
    GC_EXIT_TYPE_DISCONNECTED,
    GC_EXIT_TYPE_SELF_DISCONNECTED,
    GC_EXIT_TYPE_KICKED,
    GC_EXIT_TYPE_SYNC_ERR,
    GC_EXIT_TYPE_NO_CALLBACK,
    GC_EXIT_TYPE_INVALID,
} Group_Exit_Type;

typedef enum Group_Invite_Message_Type {
    GROUP_INVITE,
    GROUP_INVITE_ACCEPTED,
    GROUP_INVITE_CONFIRMATION,
} Group_Invite_Message_Type;

/* Group roles are hierarchical where each role has a set of privileges plus
 * all the privileges of the roles below it.
 *
 * - FOUNDER is all-powerful. Cannot be demoted or kicked.
 * - MODERATOR may promote or demote peers below them to any role below them.
 *             May also kick peers below them and set the topic.
 * - USER may interact normally with the group.
 * - OBSERVER cannot interact with the group but may observe.
 */
typedef enum Group_Role {
    GR_FOUNDER,
    GR_MODERATOR,
    GR_USER,
    GR_OBSERVER,
    GR_INVALID,
} Group_Role;

typedef enum Group_Peer_Status {
    GS_NONE,
    GS_AWAY,
    GS_BUSY,
    GS_INVALID,
} Group_Peer_Status;

typedef enum GC_Conn_State {
    CS_NONE,
    CS_DISCONNECTED,
    CS_CONNECTING,
    CS_CONNECTED,
    CS_INVALID,
} GC_Conn_State;

typedef enum Saved_GC_Conn_State {
    SGCS_DISCONNECTED,
    SGCS_CONNECTED,
} Saved_GC_Conn_State;

typedef enum Group_Join_Rejected {
    GJ_NICK_TAKEN,
    GJ_GROUP_FULL,
    GJ_INVALID_PASSWORD,
    GJ_INVITE_FAILED,
    GJ_INVALID,
} Group_Join_Rejected;

typedef enum Group_Broadcast_Type {
    GM_STATUS,
    GM_NICK,
    GM_PLAIN_MESSAGE,
    GM_ACTION_MESSAGE,
    GM_PRIVATE_MESSAGE,
    GM_PEER_EXIT,
    GM_KICK_PEER,
    GM_SET_MOD,
    GM_SET_OBSERVER,
} Group_Broadcast_Type;

typedef enum Group_Packet_Type {
    /* lossy packets (ID 0 is reserved) */
    GP_PING                     = 1,
    GP_MESSAGE_ACK              = 2,
    GP_INVITE_RESPONSE_REJECT   = 3,

    /* lossless packets */
    GP_TCP_RELAYS               = 241,
    GP_CUSTOM_PACKET            = 242,
    GP_BROADCAST                = 243,
    GP_PEER_INFO_REQUEST        = 244,
    GP_PEER_INFO_RESPONSE       = 245,
    GP_INVITE_REQUEST           = 246,
    GP_INVITE_RESPONSE          = 247,
    GP_SYNC_REQUEST             = 248,
    GP_SYNC_RESPONSE            = 249,
    GP_TOPIC                    = 250,
    GP_SHARED_STATE             = 251,
    GP_MOD_LIST                 = 252,
    GP_SANCTIONS_LIST           = 253,
    GP_FRIEND_INVITE            = 254,
    GP_HS_RESPONSE_ACK          = 255,
} Group_Packet_Type;

typedef enum Group_Handshake_Join_Type {
    HJ_PUBLIC,
    HJ_PRIVATE,
} Group_Handshake_Join_Type;

typedef enum Group_Message_Type {
    GC_MESSAGE_TYPE_NORMAL,
    GC_MESSAGE_TYPE_ACTION,
} Group_Message_Type;

struct GC_Sanction_Creds {
    uint32_t    version;
    uint8_t     hash[GC_MODERATION_HASH_SIZE];    /* hash of all sanctions list signatures + version */
    uint8_t     sig_pk[SIG_PUBLIC_KEY];    /* Last mod to have modified the sanctions list*/
    uint8_t     sig[SIGNATURE_SIZE];    /* signature of hash, signed by sig_pk */
};

typedef struct GC_Moderation {
    struct GC_Sanction *sanctions;
    struct GC_Sanction_Creds sanctions_creds;
    uint32_t    num_sanctions;

    uint8_t     **mod_list;  /* Array of public signature keys of all the mods */
    uint16_t    num_mods;
} GC_Moderation;

typedef struct GC_PeerAddress {
    uint8_t     public_key[EXT_PUBLIC_KEY];
    IP_Port     ip_port;
} GC_PeerAddress;

typedef struct GC_SavedPeerInfo {
    uint8_t     public_key[EXT_PUBLIC_KEY];
    Node_format tcp_relay;
    IP_Port     ip_port;
} GC_SavedPeerInfo;

typedef struct GC_GroupPeer {
    uint8_t     role;
    uint8_t     nick[MAX_GC_NICK_SIZE];
    uint16_t    nick_length;
    uint8_t     status;

    /* Below variables are not sent to other peers */
    uint32_t    peer_id;    /* Permanent ID (used for the public API) */
    bool        ignore;
} GC_GroupPeer;

typedef struct GC_SharedState {
    uint8_t     founder_public_key[EXT_PUBLIC_KEY];
    uint32_t    maxpeers;
    uint16_t    group_name_len;
    uint8_t     group_name[MAX_GC_GROUP_NAME_SIZE];
    uint8_t     privacy_state;   /* GI_PUBLIC (uses DHT) or GI_PRIVATE (invite only) */
    uint16_t    password_length;
    uint8_t     password[MAX_GC_PASSWORD_SIZE];
    uint8_t     mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint32_t    version;
} GC_SharedState;

typedef struct GC_TopicInfo {
    uint8_t     topic[MAX_GC_TOPIC_SIZE];
    uint16_t    length;
    uint8_t     public_sig_key[SIG_PUBLIC_KEY];   /* Public signature key of the topic setter */
    uint32_t    version;
} GC_TopicInfo;

typedef struct GC_Connection GC_Connection;
typedef struct GC_Exit_Info GC_Exit_Info;

#define GROUP_SAVE_MAX_PEERS MAX_GC_PEER_ADDRS
#define GROUP_SAVE_MAX_MODERATORS 128  // must be <= MAX_GC_MODERATORS (temporary fix to prevent save format breakage)

struct Saved_Group {
    /* Group shared state */
    uint8_t   founder_public_key[EXT_PUBLIC_KEY];
    uint16_t  maxpeers;
    uint16_t  group_name_length;
    uint8_t   group_name[MAX_GC_GROUP_NAME_SIZE];
    uint8_t   privacy_state;
    uint16_t  password_length;
    uint8_t   password[MAX_GC_PASSWORD_SIZE];
    uint8_t   mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint32_t  shared_state_version;
    uint8_t   shared_state_signature[SIGNATURE_SIZE];

    /* Topic info */
    uint16_t  topic_length;
    uint8_t   topic[MAX_GC_TOPIC_SIZE];
    uint8_t   topic_public_sig_key[SIG_PUBLIC_KEY];
    uint32_t  topic_version;
    uint8_t   topic_signature[SIGNATURE_SIZE];

    /* Other group info */
    uint8_t   chat_public_key[EXT_PUBLIC_KEY];
    uint8_t   chat_secret_key[EXT_SECRET_KEY];
    uint16_t  num_addrs;
    GC_SavedPeerInfo addrs[GROUP_SAVE_MAX_PEERS];
    uint16_t  num_mods;
    uint8_t   mod_list[GC_MOD_LIST_ENTRY_SIZE * GROUP_SAVE_MAX_MODERATORS];
    uint8_t   group_connection_state;

    /* self info */
    uint8_t   self_public_key[EXT_PUBLIC_KEY];
    uint8_t   self_secret_key[EXT_SECRET_KEY];
    uint8_t   self_nick[MAX_GC_NICK_SIZE];
    uint16_t  self_nick_length;
    uint8_t   self_role;
    uint8_t   self_status;
};

typedef struct Saved_Group Saved_Group;

typedef struct GC_Chat {
    const Mono_Time *mono_time;
    const Logger    *logger;

    Self_UDP_Status self_udp_status;
    IP_Port         self_ip_port;


    Networking_Core *net;
    TCP_Connections *tcp_conn;

    bool            new_tcp_relay;   // true if we need to send peers a new TCP relay
    uint16_t        tcp_connections; // the number of global TCP relays we're connected to
    uint64_t        last_checked_tcp_relays;

    GC_GroupPeer    *group;
    GC_Connection   *gcc;
    GC_Moderation   moderation;

    GC_Conn_State   connection_state;

    GC_SharedState  shared_state;
    uint8_t         shared_state_sig[SIGNATURE_SIZE];    /* Signed by founder using the chat secret key */

    GC_TopicInfo    topic_info;
    uint8_t         topic_sig[SIGNATURE_SIZE];    /* Signed by a moderator or the founder */

    uint16_t    peers_checksum;   /* A sum of the public key hash of every confirmed peer in the group */
    uint32_t    numpeers;
    uint32_t    base_peer_id;    /* An incrementing counter used to assign peers unique ID's */
    int         group_number;

    uint8_t     chat_public_key[EXT_PUBLIC_KEY];    /* the chat_id is the sig portion */
    uint8_t     chat_secret_key[EXT_SECRET_KEY];    /* only used by the founder */
    uint32_t    chat_id_hash;    /* 32-bit hash of the chat_id */

    uint8_t     self_public_key[EXT_PUBLIC_KEY];
    uint8_t     self_secret_key[EXT_SECRET_KEY];
    uint32_t    self_public_key_hash;

    uint64_t    time_connected;
    uint64_t    last_ping_interval;
    uint64_t    last_sync_request;
    uint8_t     join_type;    /* How we joined the group (invite or DHT) */

    /* keeps track of frequency of new inbound connections */
    uint8_t     connection_O_metre;
    uint64_t    connection_cooldown_timer;
    bool        block_handshakes;

    int32_t     saved_invites[MAX_GC_SAVED_INVITES];
    uint8_t     saved_invites_index;

    bool        update_self_announces;     /* true if we should try to update our announcements */
    uint64_t    last_self_announce_check;  /* the last time we checked if we should update our announcements */

    uint8_t     m_group_public_key[CRYPTO_PUBLIC_KEY_SIZE];    /* Public key for group's messenger friend connection */
    int         friend_connection_id;   /* Identifier for group's messenger friend connection */

    Saved_Group *save;
} GC_Chat;

#ifndef MESSENGER_DEFINED
#define MESSENGER_DEFINED
typedef struct Messenger Messenger;
#endif /* MESSENGER_DEFINED */

typedef void gc_message_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int type,
                           const uint8_t *data, size_t length, void *user_data);
typedef void gc_private_message_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int type,
                                   const uint8_t *data, size_t length, void *user_data);
typedef void gc_custom_packet_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                                 size_t length, void *user_data);
typedef void gc_moderation_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, uint32_t target_peer,
                              unsigned int mod_event, void *user_data);
typedef void gc_nick_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                               size_t length, void *user_data);
typedef void gc_status_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int status,
                                 void *user_data);
typedef void gc_topic_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                                size_t length, void *user_data);
typedef void gc_peer_limit_cb(Messenger *m, uint32_t group_number, uint32_t max_peers, void *user_data);
typedef void gc_privacy_state_cb(Messenger *m, uint32_t group_number, unsigned int state, void *user_data);
typedef void gc_password_cb(Messenger *m, uint32_t group_number, const uint8_t *data, size_t length, void *user_data);
typedef void gc_peer_join_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, void *user_data);
typedef void gc_peer_exit_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int exit_type,
                             const uint8_t *nick, size_t nick_len, const uint8_t *data, size_t length, void *user_data);
typedef void gc_self_join_cb(Messenger *m, uint32_t group_number, void *user_data);
typedef void gc_rejected_cb(Messenger *m, uint32_t group_number, unsigned int type, void *user_data);

typedef struct GC_Session {
    Messenger                 *messenger;
    GC_Chat                   *chats;
    struct GC_Announces_List  *announces_list;

    uint32_t     num_chats;

    gc_message_cb *message;
    void *message_userdata;
    gc_private_message_cb *private_message;
    void *private_message_userdata;
    gc_custom_packet_cb *custom_packet;
    void *custom_packet_userdata;
    gc_moderation_cb *moderation;
    void *moderation_userdata;
    gc_nick_change_cb *nick_change;
    void *nick_change_userdata;
    gc_status_change_cb *status_change;
    void *status_change_userdata;
    gc_topic_change_cb *topic_change;
    void *topic_change_userdata;
    gc_peer_limit_cb *peer_limit;
    void *peer_limit_userdata;
    gc_privacy_state_cb *privacy_state;
    void *privacy_state_userdata;
    gc_password_cb *password;
    void *password_userdata;
    gc_peer_join_cb *peer_join;
    void *peer_join_userdata;
    gc_peer_exit_cb *peer_exit;
    void *peer_exit_userdata;
    gc_self_join_cb *self_join;
    void *self_join_userdata;
    gc_rejected_cb *rejected;
    void *rejected_userdata;
} GC_Session;

void pack_group_info(const GC_Chat *chat, Saved_Group *temp, bool can_use_cached_value);

bool is_public_chat(const GC_Chat *chat);

/* Sends a plain message or an action, depending on type.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the message type is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type);

/* Sends a private message to peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peer_id is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_private_message(const GC_Chat *chat, uint32_t peer_id, uint8_t type, const uint8_t *message,
                            uint16_t length);

/* Sends a custom packet to the group. If lossless is true, the packet will be lossless.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 */
int gc_send_custom_packet(const GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length);

/* Toggles ignore for peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the peer_id is invalid.
 * Returns -2 if the caller attempted to ignore himself.
 */
int gc_toggle_ignore(GC_Chat *chat, uint32_t peer_id, bool ignore);

/* Sets the group topic and broadcasts it to the group.
 *
 * Returns 0 on success. Setter must be a moderator or founder.
 * Returns -1 if the topic is too long.
 * Returns -2 if the caller does not have the required permissions to set the topic.
 * Returns -3 if the packet cannot be created or signing fails.
 * Returns -4 if the packet fails
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length);

/* Copies the group topic to topic. If topic is null this function has no effect.*/
void gc_get_topic(const GC_Chat *chat, uint8_t *topic);

/* Returns topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat);

/* Copies group name to groupname. If group_name is null this function has no effect. */
void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name);

/* Returns group name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat);

/* Copies the group password to password. If password is null this function has no effect. */
void gc_get_password(const GC_Chat *chat, uint8_t *password);

/* Returns the group password length */
uint16_t gc_get_password_size(const GC_Chat *chat);

/* Returns group privacy state */
uint8_t gc_get_privacy_state(const GC_Chat *chat);

/* Returns the group peer limit. */
uint32_t gc_get_max_peers(const GC_Chat *chat);

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
int gc_set_self_nick(const Messenger *m, int group_number, const uint8_t *nick, uint16_t length);

/* Copies your own nick to nick. If nick is null this function has no effect. */
void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick);

/* Return your own nick length */
uint16_t gc_get_self_nick_size(const GC_Chat *chat);

/* Return your own group role */
uint8_t gc_get_self_role(const GC_Chat *chat);

/* Return your own status */
uint8_t gc_get_self_status(const GC_Chat *chat);

/* Returns your own peer id */
uint32_t gc_get_self_peer_id(const GC_Chat *chat);

/* Copies your own public key to public_key. If public_key is null this function has no effect. */
void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key);

/* Copies peer_id's nick to name.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name);

/* Returns peer_id's nick length.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id);

/* Copies peer_id's public key to public_key.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_public_key(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key);

int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key);

/* Sets the caller's status to status
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the status type is invalid.
 * Returns -3 if the packet failed to send.
 */
int gc_set_self_status(const Messenger *m, int group_number, uint8_t status);

/* Returns peer_id's status.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id);

/* Returns peer_id's group role.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id);

/* Sets the role of peer_id. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if caller does not have sufficient permissions for the action.
 * Returns -4 if the role assignment is invalid.
 * Returns -5 if the role failed to be set.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_set_peer_role(const Messenger *m, int group_number, uint32_t peer_id, uint8_t role);

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 * Returns -4 if malloc failed.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length);

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the privacy state is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the privacy state fails to set.
 * Returns -5 if the packet fails to send.
 */
int gc_founder_set_privacy_state(Messenger *m, int group_number, uint8_t new_privacy_state);

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, uint32_t max_peers);

/* Instructs all peers to remove peer_id from their peerlist.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_kick_peer(Messenger *m, int group_number, uint32_t peer_id);

/* Copies the chat_id to dest. If dest is null this function has no effect. */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest);



void gc_callback_message(Messenger *m, gc_message_cb *function, void *userdata);
void gc_callback_private_message(Messenger *m, gc_private_message_cb *function, void *userdata);
void gc_callback_custom_packet(Messenger *m, gc_custom_packet_cb *function, void *userdata);
void gc_callback_moderation(Messenger *m, gc_moderation_cb *function, void *userdata);
void gc_callback_nick_change(Messenger *m, gc_nick_change_cb *function, void *userdata);
void gc_callback_status_change(Messenger *m, gc_status_change_cb *function, void *userdata);
void gc_callback_topic_change(Messenger *m, gc_topic_change_cb *function, void *userdata);
void gc_callback_peer_limit(Messenger *m, gc_peer_limit_cb *function, void *userdata);
void gc_callback_privacy_state(Messenger *m, gc_privacy_state_cb *function, void *userdata);
void gc_callback_password(Messenger *m, gc_password_cb *function, void *userdata);
void gc_callback_peer_join(Messenger *m, gc_peer_join_cb *function, void *userdata);
void gc_callback_peer_exit(Messenger *m, gc_peer_exit_cb *function, void *userdata);
void gc_callback_self_join(Messenger *m, gc_self_join_cb *function, void *userdata);
void gc_callback_rejected(Messenger *m, gc_rejected_cb *function, void *userdata);

/* The main loop. */
void do_gc(GC_Session *c, void *userdata);

/* Returns a NULL pointer if fail.
 * Make sure that DHT is initialized before calling this
 */
GC_Session *new_dht_groupchats(Messenger *m);

/* Cleans up groupchat structures and calls gc_group_exit() for every group chat */
void kill_dht_groupchats(GC_Session *c);

/* Loads a previously saved group and attempts to join it.
 *
 * Returns group_number on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, const Saved_Group *save, int group_number);

/* Creates a new group.
 *
 * Return -1 if the nick or group name is too long.
 * Return -2 if the nick or group name is empty.
 * Return -3 if the privacy state is an invalid type.
 * Return -4 if the the group object fails to initialize.
 * Return -5 if the group state fails to initialize.
 * Return -6 if the Messenger friend connection fails to initialize.
 */
int gc_group_add(GC_Session *c, uint8_t privacy_state, const uint8_t *group_name, uint16_t group_name_length,
                 const uint8_t *nick, size_t nick_length);

/* Sends an invite request to a public group using the chat_id.
 *
 * If the group is not password protected password should be set to NULL and password_length should be 0.
 *
 * Return group_number on success.
 * Return -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or a group with chat_id already exists in the chats array.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the group password.
 * Return -6 if the Messenger friend connection fails to initialize.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *nick, size_t nick_length, const uint8_t *passwd,
                  uint16_t passwd_len);

/* Disconnects from all peers in a group but saves the group state for later use.
 *
 * Return 0 on sucess.
 * Return -1 if the group handler object or chat object is null.
 * Return -2 if malloc fails.
 */
int gc_disconnect_from_group(GC_Session *c, GC_Chat *chat);

/* Resets chat saving all self state and attempts to reconnect to group.
 *
 * Returns 0 on success.
 * Returns -1 if the group handler object or chat object is null.
 * Returns -2 if the Messenger friend connection fails to initialize.
 */
int gc_rejoin_group(GC_Session *c, GC_Chat *chat);

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return group_number on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the password.
 * Return -6 if friend doesn't exist.
 * Return -7 if sending packet failed.
 */
int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length, const uint8_t *nick,
                     size_t nick_length, const uint8_t *passwd, uint16_t passwd_len);

typedef int gc_send_group_invite_packet_cb(const Messenger *m, uint32_t friendnumber, const uint8_t *packet,
        size_t length);

/* Invites friendnumber to chat. Packet includes: Type, chat_id, node
 *
 * Return 0 on success.
 * Return -1 if friendnumber does not exist.
 * Return -2 on failure to create the invite data.
 * Return -3 if the packet fails to send.
 */
int gc_invite_friend(const GC_Session *c, GC_Chat *chat, int32_t friendnum,
                     gc_send_group_invite_packet_cb *send_group_invite_packet);

/* Sends parting message to group and deletes group.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length);

/* Count number of active groups.
 *
 * Returns the count.
 */
uint32_t gc_count_groups(const GC_Session *c);

/* Returns true if peer_number exists */
bool gc_peer_number_is_valid(const GC_Chat *chat, int peer_number);

/* Return group_number's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session *c, int group_number);

/* Copies up to max_addrs peer addresses from chat into addrs.
 *
 * Returns number of addresses copied.
 */
uint16_t gc_copy_peer_addrs(const GC_Chat *chat, GC_SavedPeerInfo *addrs, size_t max_addrs);

/* If read_id is non-zero sends a read-receipt for ack_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t read_id, uint64_t request_id);

int handle_gc_lossless_helper(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type);

int handle_gc_invite_accepted_packet(GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

bool check_group_invite(const GC_Session *c, const uint8_t *data, uint32_t length);

int handle_gc_invite_confirmed_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key);

int add_peers_from_announces(const GC_Session *gc_session, GC_Chat *chat, GC_Announce *announces,
                             uint8_t gc_announces_count);

#endif  /* GROUP_CHATS_H */
