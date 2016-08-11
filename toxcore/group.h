/* group.h
 *
 * Slightly better groupchats implementation.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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


#ifndef GROUP_H
#define GROUP_H

#include "tox.h"
#include "Messenger.h"

enum {
    GROUPCHAT_STATUS_NONE,
    GROUPCHAT_STATUS_VALID,
    GROUPCHAT_STATUS_CONNECTED
};

enum {
    GROUPCHAT_TYPE_TEXT,
    GROUPCHAT_TYPE_AV
};

#define MAX_LOSSY_COUNT 256

typedef struct {
    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t     temp_pk[crypto_box_PUBLICKEYBYTES];

    uint64_t    last_recv;
    uint32_t    last_message_number;

    uint8_t     nick[MAX_NAME_LENGTH];
    uint8_t     nick_len;

    uint16_t peer_number;

    uint8_t  recv_lossy[MAX_LOSSY_COUNT];
    uint16_t bottom_lossy_number, top_lossy_number;

    void *object;
} Group_Peer;

#define DESIRED_CLOSE_CONNECTIONS 4
#define MAX_GROUP_CONNECTIONS 16
#define GROUP_IDENTIFIER_LENGTH (1 + crypto_box_KEYBYTES) /* type + crypto_box_KEYBYTES so we can use new_symmetric_key(...) to fill it */

enum {
    GROUPCHAT_CLOSE_NONE,
    GROUPCHAT_CLOSE_CONNECTION,
    GROUPCHAT_CLOSE_ONLINE
};

typedef struct Group_Chats Group_Chats;
typedef struct Group_c     Group_c;

struct Group_c {
    uint8_t status;

    Group_Peer *group;
    uint32_t numpeers;

    struct {
        uint8_t type; /* GROUPCHAT_CLOSE_* */
        uint8_t closest;
        uint32_t number;
        uint16_t group_number;
    } close[MAX_GROUP_CONNECTIONS];

    uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
    struct {
        uint8_t entry;
        uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
        uint8_t temp_pk[crypto_box_PUBLICKEYBYTES];
    } closest_peers[DESIRED_CLOSE_CONNECTIONS];
    uint8_t changed;

    uint8_t identifier[GROUP_IDENTIFIER_LENGTH];

    uint8_t title[MAX_NAME_LENGTH];
    uint8_t title_len;

    uint32_t message_number;
    uint16_t lossy_message_number;
    uint16_t peer_number;

    uint64_t last_sent_ping;

    int number_joined; /* friendcon_id of person that invited us to the chat. (-1 means none) */

    void *object;

    void (*peer_on_join)(void *, int, int);
    void (*peer_on_leave)(void *, int, int, void *);
    void (*group_on_delete)(void *, int);
};

struct Group_Chats {
    Tox *tox;
    Messenger *m;
    Tox_Connections *fr_c;

    Group_c *chats;
    uint32_t num_chats;

    void (*invite_callback)(Tox *tox, int32_t, uint8_t, const uint8_t *, uint16_t, void *);
    void *invite_callback_userdata;
    void (*message_callback)(Tox *tox, int, int, const uint8_t *, uint16_t, void *);
    void *message_callback_userdata;
    void (*action_callback)(Tox *tox, int, int, const uint8_t *, uint16_t, void *);
    void *action_callback_userdata;
    void (*peer_namelistchange)(Tox *tox, int, int, uint8_t, void *);
    void *group_namelistchange_userdata;
    void (*title_callback)(Tox *tox, int, int, const uint8_t *, uint8_t, void *);
    void *title_callback_userdata;

    struct {
        int (*function)(void *, int, int, void *, const uint8_t *, uint16_t);
    } lossy_packethandlers[256];
};

/* Set the callback for group invites.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t type, uint8_t *data, uint16_t length, void *userdata)
 *
 *  data of length is what needs to be passed to join_groupchat().
 */
void g_callback_group_invite(Tox *tox, void (*function)(Tox *tox, int32_t, uint8_t, const uint8_t *,
                             uint16_t, void *), void *userdata);

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void g_callback_group_message(Tox *tox, void (*function)(Tox *tox, int, int, const uint8_t *, uint16_t,
                              void *), void *userdata);

/* Set the callback for group actions.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void g_callback_group_action(Tox *tox, void (*function)(Tox *tox, int, int, const uint8_t *, uint16_t,
                             void *), void *userdata);

/* Set callback function for title changes.
 *
 * Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * title, uint8_t length, void *userdata)
 * if friendgroupnumber == -1, then author is unknown (e.g. initial joining the group)
 */
void g_callback_group_title(Tox *tox, void (*function)(Tox *tox, int, int, const uint8_t *, uint8_t,
                            void *), void *userdata);

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, int peernumber, TOX_CHAT_CHANGE change, void *userdata)
 */
enum {
    CHAT_CHANGE_PEER_ADD,
    CHAT_CHANGE_PEER_DEL,
    CHAT_CHANGE_PEER_NAME,
};
void g_callback_group_namelistchange(Tox *tox, void (*function)(Tox *tox, int, int, uint8_t, void *),
                                     void *userdata);

/* Creates a new groupchat and puts it in the chats array.
 *
 * type is one of GROUPCHAT_TYPE_*
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Tox *tox, uint8_t type);

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int del_groupchat(Tox *tox, int groupnumber);

/* Copy the public key of peernumber who is in groupnumber to pk.
 * pk must be crypto_box_PUBLICKEYBYTES long.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int group_peer_pubkey(const Tox *tox, int groupnumber, int peernumber, uint8_t *pk);

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if failure
 */
int group_peername(const Tox *tox, int groupnumber, int peernumber, uint8_t *name);

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int invite_friend(Tox *tox, int32_t friendnumber, int groupnumber);

/* Join a group (you need to have been invited first.)
 *
 * expected_type is the groupchat type we expect the chat we are joining is.
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Tox *tox, int32_t friendnumber, uint8_t expected_type, const uint8_t *data, uint16_t length);

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int group_message_send(const Tox *tox, int groupnumber, const uint8_t *message, uint16_t length);

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int group_action_send(const Tox *tox, int groupnumber, const uint8_t *action, uint16_t length);

/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 on failure
 */
int group_title_send(const Tox *tox, int groupnumber, const uint8_t *title, uint8_t title_len);


/* Get group title from groupnumber and put it in title.
 * title needs to be a valid memory location with a max_length size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of copied title if success.
 *  return -1 if failure.
 */
int group_title_get(const Tox *tox, int groupnumber, uint8_t *title, uint32_t max_length);

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int group_number_peers(const Tox *tox, int groupnumber);

/* return 1 if the peernumber corresponds to ours.
 * return 0 on failure.
 */
unsigned int group_peernumber_is_ours(const Tox *tox, int groupnumber, int peernumber);

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NAME_LENGTH] array.
 *
 * Copies the lengths of the names to lengths[length]
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int group_names(const Tox *tox, int groupnumber, uint8_t names[][MAX_NAME_LENGTH], uint16_t lengths[],
                uint16_t length);

/* Set handlers for custom lossy packets.
 *
 * NOTE: Handler must return 0 if packet is to be relayed, -1 if the packet should not be relayed.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber, void *group peer object (set with group_peer_set_object), const uint8_t *packet, uint16_t length)
 */
void group_lossy_packet_registerhandler(Tox *tox, uint8_t byte, int (*function)(void *, int, int, void *,
                                        const uint8_t *, uint16_t));

/* High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_group_lossy_packet(const Tox *tox, int groupnumber, const uint8_t *data, uint16_t length);

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist.
 */
uint32_t count_chatlist(const Tox *tox);

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(const Tox *tox, int32_t *out_list, uint32_t list_size);

/* return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int group_get_type(const Tox *tox, int groupnumber);

/* Send current name (set in messenger) to all online groups.
 */
void send_name_all_groups(Tox *tox);

/* Set the object that is tied to the group chat.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_set_object(const Tox *tox, int groupnumber, void *object);

/* Set the object that is tied to the group peer.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_peer_set_object(const Tox *tox, int groupnumber, int peernumber, void *object);

/* Return the object tide to the group chat previously set by group_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_get_object(const Tox *tox, int groupnumber);

/* Return the object tide to the group chat peer previously set by group_peer_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_peer_get_object(const Tox *tox, int groupnumber, int peernumber);

/* Set a function to be called when a new peer joins a group chat.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_new(const Tox *tox, int groupnumber, void (*function)(void *, int, int));

/* Set a function to be called when a peer leaves a group chat.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber, void *group peer object (set with group_peer_set_object))
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_delete(Tox *tox, int groupnumber, void (*function)(void *, int, int, void *));

/* Set a function to be called when the group chat is deleted.
 *
 * Function(void *group object (set with group_set_object), int groupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_delete(Tox *tox, int groupnumber, void (*function)(void *, int));

/* Create new groupchat instance. */
Group_Chats *new_groupchats(Tox *tox);

/* main groupchats loop. */
void do_groupchats(Tox *tox);

/* Free everything related with group chats. */
void kill_groupchats(Tox *tox);

#endif
