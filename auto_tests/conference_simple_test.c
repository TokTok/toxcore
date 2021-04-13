#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool self_online;
    bool friend_online;
    bool invited_next;

    bool joined;
    uint32_t conference;

    bool received;

    uint32_t peers;
} State;

#include "run_auto_test.h"

static void handle_self_connection_status(Tox *tox, Tox_Connection connection_status, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "self_connection_status(#%u, %d, _)\n", state->index, connection_status);
    state->self_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_friend_connection_status(Tox *tox, uint32_t friend_number, Tox_Connection connection_status,
        void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_friend_connection_status(#%u, %u, %d, _)\n", state->index, friend_number, connection_status);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_conference_invite(Tox *tox, uint32_t friend_number, Tox_Conference_Type type, const uint8_t *cookie,
                                     size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->index, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->index);

    {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK, "failed to join a conference: err = %d", err);
        fprintf(stderr, "tox%u Joined conference %u\n", state->index, state->conference);
        state->joined = true;
    }
}

static void handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                      Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_message(#%u, %u, %u, %d, uint8_t[%u], _)\n",
            state->index, conference_number, peer_number, type, (unsigned)length);

    fprintf(stderr, "tox%u got message: %s\n", state->index, (const char *)message);
    state->received = true;
}

static void handle_conference_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_peer_list_changed(#%u, %u, _)\n",
            state->index, conference_number);

    Tox_Err_Conference_Peer_Query err;
    uint32_t count = tox_conference_peer_count(tox, conference_number, &err);

    if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        fprintf(stderr, "ERROR: %d\n", err);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "tox%u has %u peers online\n", state->index, count);
    state->peers = count;
}

static void handle_conference_connected(Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    // We're tox2, so now we invite tox3.
    if (state->index == 2 && !state->invited_next) {
        Tox_Err_Conference_Invite err;
        tox_conference_invite(tox, 1, state->conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox2 failed to invite tox3: err = %d", err);

        state->invited_next = true;
        fprintf(stderr, "tox2 invited tox3\n");
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    (void)run_auto_test;

    State state[] = {{1}, {2}, {3}};

    // Create toxes.
    Tox *toxes[3];
    toxes[0] = tox_new_log(nullptr, nullptr, &state[0].index);
    toxes[1] = tox_new_log(nullptr, nullptr, &state[1].index);
    toxes[2] = tox_new_log(nullptr, nullptr, &state[2].index);

    set_mono_time_callback(toxes[0], &state[0]);
    set_mono_time_callback(toxes[1], &state[1]);
    set_mono_time_callback(toxes[2], &state[2]);

    // tox1 <-> tox2, tox2 <-> tox3
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(toxes[1], key);
    tox_friend_add_norequest(toxes[0], key, nullptr);  // tox1 -> tox2
    tox_self_get_public_key(toxes[0], key);
    tox_friend_add_norequest(toxes[1], key, nullptr);  // tox2 -> tox1
    tox_self_get_public_key(toxes[2], key);
    tox_friend_add_norequest(toxes[1], key, nullptr);  // tox2 -> tox3
    tox_self_get_public_key(toxes[1], key);
    tox_friend_add_norequest(toxes[2], key, nullptr);  // tox3 -> tox2

    printf("bootstrapping tox2 and tox3 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(toxes[0], dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

    tox_bootstrap(toxes[1], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(toxes[2], "localhost", dht_port, dht_key, nullptr);

    // Connection callbacks.
    tox_callback_self_connection_status(toxes[0], handle_self_connection_status);
    tox_callback_self_connection_status(toxes[1], handle_self_connection_status);
    tox_callback_self_connection_status(toxes[2], handle_self_connection_status);

    tox_callback_friend_connection_status(toxes[0], handle_friend_connection_status);
    tox_callback_friend_connection_status(toxes[1], handle_friend_connection_status);
    tox_callback_friend_connection_status(toxes[2], handle_friend_connection_status);

    // Conference callbacks.
    tox_callback_conference_invite(toxes[0], handle_conference_invite);
    tox_callback_conference_invite(toxes[1], handle_conference_invite);
    tox_callback_conference_invite(toxes[2], handle_conference_invite);

    tox_callback_conference_connected(toxes[0], handle_conference_connected);
    tox_callback_conference_connected(toxes[1], handle_conference_connected);
    tox_callback_conference_connected(toxes[2], handle_conference_connected);

    tox_callback_conference_message(toxes[0], handle_conference_message);
    tox_callback_conference_message(toxes[1], handle_conference_message);
    tox_callback_conference_message(toxes[2], handle_conference_message);

    tox_callback_conference_peer_list_changed(toxes[0], handle_conference_peer_list_changed);
    tox_callback_conference_peer_list_changed(toxes[1], handle_conference_peer_list_changed);
    tox_callback_conference_peer_list_changed(toxes[2], handle_conference_peer_list_changed);

    // Wait for self connection.
    fprintf(stderr, "Waiting for toxes to come online\n");

    do {
        iterate_all_wait(3, toxes, state, 100);
    } while (!state[0].self_online || !state[1].self_online || !state[2].self_online);

    fprintf(stderr, "Toxes are online\n");

    // Wait for friend connection.
    fprintf(stderr, "Waiting for friends to connect\n");

    do {
        iterate_all_wait(3, toxes, state, 100);
    } while (!state[0].friend_online || !state[1].friend_online || !state[2].friend_online);

    fprintf(stderr, "Friends are connected\n");

    {
        // Create new conference, tox1 is the founder.
        Tox_Err_Conference_New err;
        state[0].conference = tox_conference_new(toxes[0], &err);
        state[0].joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK, "failed to create a conference: err = %d", err);
        fprintf(stderr, "Created conference: id = %u\n", state[0].conference);
    }

    {
        // Invite friend.
        Tox_Err_Conference_Invite err;
        tox_conference_invite(toxes[0], 0, state[0].conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "failed to invite a friend: err = %d", err);
        state[0].invited_next = true;
        fprintf(stderr, "tox1 invited tox2\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive\n");

    do {
        iterate_all_wait(3, toxes, state, 100);
    } while (!state[0].joined || !state[1].joined || !state[2].joined);

    fprintf(stderr, "Invitations accepted\n");

    fprintf(stderr, "Waiting for peers to come online\n");

    do {
        iterate_all_wait(3, toxes, state, 100);
    } while (state[0].peers == 0 || state[1].peers == 0 || state[2].peers == 0);

    fprintf(stderr, "All peers are online\n");

    {
        fprintf(stderr, "tox1 sends a message to the group: \"hello!\"\n");
        Tox_Err_Conference_Send_Message err;
        tox_conference_send_message(toxes[0], state[0].conference, TOX_MESSAGE_TYPE_NORMAL,
                                    (const uint8_t *)"hello!", 7, &err);

        if (err != TOX_ERR_CONFERENCE_SEND_MESSAGE_OK) {
            fprintf(stderr, "ERROR: %d\n", err);
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stderr, "Waiting for messages to arrive\n");

    do {
        iterate_all_wait(3, toxes, state, 100);
    } while (!state[1].received || !state[2].received);

    fprintf(stderr, "Messages received. Test complete.\n");

    tox_kill(toxes[2]);
    tox_kill(toxes[1]);
    tox_kill(toxes[0]);

    return 0;
}
