/* Tests that we can send messages to friends.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../toxcore/tox.h"

#define MAX_NUM_PEERS 5
#define TEST_GROUP_NAME "Headquarters"

typedef struct Peer {
    char name[TOX_MAX_NAME_LENGTH];
    size_t name_length;
    uint32_t peer_id;
} Peer;

typedef struct State {
    uint32_t index;
    uint64_t clock;

    char self_name[TOX_MAX_NAME_LENGTH];
    size_t self_name_length;

    uint32_t group_number;

    uint32_t num_peers;
    Peer peers[MAX_NUM_PEERS - 1];

    bool mod_check;
    char mod_name[TOX_MAX_NAME_LENGTH];

    bool observer_check;
    char observer_name[TOX_MAX_NAME_LENGTH];

    bool user_check;  // observer gets promoted back to user
    bool kick_check;  // moderater gets kicked
} State;


#include "run_auto_test.h"


/*
 * Waits for all states to receive the mod event.
 */
static void check_mod_event(State *state, Tox **toxes, size_t num_peers, TOX_GROUP_MOD_EVENT event)
{
    uint32_t peers_recv_changes = 0;

    do {
        peers_recv_changes = 0;

        iterate_all_wait(MAX_NUM_PEERS, toxes, state, ITERATION_INTERVAL);

        for (size_t i = 0; i < num_peers; ++i) {
            bool check = false;

            switch (event) {
                case TOX_GROUP_MOD_EVENT_MODERATOR: {
                    check = state[i].mod_check;
                    break;
                }

                case TOX_GROUP_MOD_EVENT_OBSERVER: {
                    check = state[i].observer_check;
                    break;
                }

                case TOX_GROUP_MOD_EVENT_USER: {
                    check = state[i].user_check;
                    break;
                }

                case TOX_GROUP_MOD_EVENT_KICK: {
                    check = state[i].kick_check;
                    break;
                }

                default: {
                    ck_assert(0);
                }
            }

            if (check) {
                ++peers_recv_changes;
            }
        }

    } while (peers_recv_changes < num_peers);
}

static uint32_t get_peer_id_by_nick(Peer *peers, uint32_t num_peers, const char *name)
{
    ck_assert(name != nullptr);

    for (uint32_t i = 0; i < num_peers; ++i) {
        if (!memcmp(peers[i].name, name, peers[i].name_length)) {
            return peers[i].peer_id;
        }
    }

    ck_assert_msg(0, "Failed to find peer id");
}

static size_t get_state_index_by_nick(State *state, size_t num_peers, const char *name, size_t name_length)
{
    ck_assert(name != nullptr && name_length <= TOX_MAX_NAME_LENGTH);

    for (size_t i = 0; i < num_peers; ++i) {
        if (!memcmp(state[i].self_name, name, name_length)) {
            return i;
        }
    }

    ck_assert_msg(0, "Failed to find index");
}

static void group_join_fail_handler(Tox *tox, uint32_t group_number, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    fprintf(stderr, "Failed to join group: %d", fail_type);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    Peer *peer = &state->peers[state->num_peers];

    peer->peer_id = peer_id;
    memcpy(peer->name, peer_name, peer_name_len);
    peer->name_length = peer_name_len;

    ++state->num_peers;

    ck_assert(state->num_peers < MAX_NUM_PEERS);
}

static void group_mod_event_handler(Tox *tox, uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id,
                                    TOX_GROUP_MOD_EVENT event, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state != nullptr);
    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, target_peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, target_peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    switch (event) {
        case TOX_GROUP_MOD_EVENT_MODERATOR: {
            ck_assert(!memcmp(peer_name, state->mod_name, peer_name_len));
            state->mod_check = true;
            break;
        }

        case TOX_GROUP_MOD_EVENT_OBSERVER: {
            ck_assert(!memcmp(peer_name, state->observer_name, peer_name_len));
            state->observer_check = true;
            break;
        }

        case TOX_GROUP_MOD_EVENT_USER: {
            // The mod is first auto-demoted to user before being kicked. Mod must be kicked after observer is promoted back to user.
            if (state->user_check) {
                ck_assert(!memcmp(peer_name, state->mod_name, peer_name_len));
            } else {
                ck_assert(!memcmp(peer_name, state->observer_name, peer_name_len)); // we promoted the observer back to user
                state->user_check = true;
            }

            break;
        }

        case TOX_GROUP_MOD_EVENT_KICK: {
            ck_assert(!memcmp(peer_name, state->mod_name, peer_name_len));  // we kick the same peer we previously promoted to mod
            state->kick_check = true;
            break;
        }

        default: {
            ck_assert_msg(0, "Got invalid moderator event %d", event);
            return;
        }
    }
}

static void group_message_test(Tox **toxes, State *state)
{
    for (size_t i = 0; i < MAX_NUM_PEERS; ++i) {
        TOX_ERR_SET_INFO name_err;
        char name[TOX_MAX_NAME_LENGTH];
        snprintf(name, sizeof(name), "Toxicle %zu", i);
        size_t length = strlen(name);
        memcpy(state[i].self_name, name, length);
        state[i].self_name_length = length;

        tox_self_set_name(toxes[i], (const uint8_t *)name, length, &name_err);
        ck_assert(name_err == TOX_ERR_SET_INFO_OK);

        tox_callback_group_join_fail(toxes[i], group_join_fail_handler);
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_moderation(toxes[i], group_mod_event_handler);
    }

    fprintf(stderr, "Creating new group\n");

    /* Founder makes new group */
    TOX_ERR_GROUP_NEW err_new;
    state[0].group_number = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)TEST_GROUP_NAME,
                                          strlen(TEST_GROUP_NAME), (const uint8_t *)state[0].self_name, state[0].self_name_length,
                                          &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    /* Founder gets chat ID */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], state[0].group_number, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get chat ID. error: %d", id_err);

    fprintf(stderr, "Peers attemping to join DHT group via the chat ID\n");

    for (size_t i = 1; i < MAX_NUM_PEERS; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        state[i].group_number = tox_group_join(toxes[i], chat_id, (const uint8_t *)state[i].self_name,
                                               state[i].self_name_length,
                                               nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "Peer %zu failed to join group. error %d", i, join_err);
        c_sleep(1000);
    }

    /* Wait for all peers to be connected with one another in the group */
    while (1) {
        iterate_all_wait(MAX_NUM_PEERS, toxes, state, ITERATION_INTERVAL);

        uint32_t peers_connected = 0;

        for (size_t i = 0; i < MAX_NUM_PEERS; ++i) {
            if (state[i].num_peers == MAX_NUM_PEERS - 1) {
                ++peers_connected;
            }
        }

        if (peers_connected == MAX_NUM_PEERS) {
            fprintf(stderr, "%d peers successfully connected to group\n", MAX_NUM_PEERS);
            break;
        }
    }

    // founder doesn't receive callbacks for mod events so we default these to true
    state[0].mod_check = true;
    state[0].observer_check = true;
    state[0].kick_check = true;

    /* manually tell the other peers the names of the peers that will be assigned new roles */
    for (size_t i = 0; i < MAX_NUM_PEERS; ++i) {
        memcpy(state[i].mod_name, state[0].peers[0].name, sizeof(state[i].mod_name));
        memcpy(state[i].observer_name, state[0].peers[1].name, sizeof(state[i].observer_name));
    }

    /* founder sets first peer to moderator */
    fprintf(stderr, "Founder setting %s to moderator\n", state[0].peers[0].name);

    TOX_ERR_GROUP_MOD_SET_ROLE role_err;
    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[0].peer_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);

    check_mod_event(state, toxes, MAX_NUM_PEERS, TOX_GROUP_MOD_EVENT_MODERATOR);

    fprintf(stderr, "All peers successfully received mod event\n");

    /* founder sets second peer to observer */
    fprintf(stderr, "Founder setting %s to observer\n", state[0].peers[1].name);

    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[1].peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set observer. error: %d", role_err);

    check_mod_event(state, toxes, MAX_NUM_PEERS, TOX_GROUP_MOD_EVENT_OBSERVER);

    fprintf(stderr, "All peers successfully received observer event\n");

    /* New moderator promotes second peer back to user */
    uint32_t idx = get_state_index_by_nick(state, MAX_NUM_PEERS, state[0].peers[0].name, state[0].peers[0].name_length);
    uint32_t obs_peer_id = get_peer_id_by_nick(state[idx].peers, MAX_NUM_PEERS - 1, state[idx].observer_name);
    state[idx].user_check = true;  // promoter doesn't receive a callback so default to true

    fprintf(stderr, "%s is promoting %s back to user\n", state[idx].self_name, state[0].peers[1].name);

    tox_group_mod_set_role(toxes[idx], state[idx].group_number, obs_peer_id, TOX_GROUP_ROLE_USER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to promote observer back to user. error: %d",
                  role_err);

    check_mod_event(state, toxes, MAX_NUM_PEERS, TOX_GROUP_MOD_EVENT_USER);

    fprintf(stderr, "All peers successfully received user event\n");

    /* moderator attempts to demote and kick founder */
    uint32_t founder_peer_id = get_peer_id_by_nick(state[idx].peers, MAX_NUM_PEERS - 1, state[0].self_name);
    tox_group_mod_set_role(toxes[idx], state[idx].group_number, founder_peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err != TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Mod set founder to observer");

    TOX_ERR_GROUP_MOD_KICK_PEER k_err;
    tox_group_mod_kick_peer(toxes[idx], state[idx].group_number, founder_peer_id, &k_err);
    ck_assert_msg(k_err != TOX_ERR_GROUP_MOD_KICK_PEER_OK, "mod kicked founder");

    /* founder kicks moderator (this triggers two events: user and kick */
    fprintf(stderr, "Founder is kicking %s\n", state[0].peers[0].name);

    tox_group_mod_kick_peer(toxes[0], state[0].group_number, state[0].peers[0].peer_id, &k_err);
    ck_assert_msg(k_err == TOX_ERR_GROUP_MOD_KICK_PEER_OK, "Failed to kick peer. error: %d", k_err);

    check_mod_event(state, toxes, MAX_NUM_PEERS, TOX_GROUP_MOD_EVENT_KICK);

    fprintf(stderr, "All peers successfully received kick event\n");

    for (size_t i = 0; i < MAX_NUM_PEERS; i++) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], state[i].group_number, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    fprintf(stderr, "Test successful!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(MAX_NUM_PEERS, group_message_test, false);
    return 0;
}

#undef MAX_NUM_PEERS
#undef TEST_GROUP_NAME
