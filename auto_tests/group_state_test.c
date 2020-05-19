/*
 * Tests that we can successfully change the group state and that all peers in the group
 * receive the correct state changes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "check_compat.h"

#define NUM_GROUP_TOXES 5

#define PEER_LIMIT_1 NUM_GROUP_TOXES
#define PEER_LIMIT_2 1

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)

#define TOPIC1 "Eternally indestructible"
#define TOPIC1_LEN (sizeof(TOPIC1) - 1)

#define TOPIC2 "The interjection zone"
#define TOPIC2_LEN (sizeof(TOPIC2) - 1)

#define GROUP_NAME "The Crystal Palace"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define PEER0_NICK "David"

typedef struct State {
    uint32_t index;
    uint64_t clock;
} State;

#include "run_auto_test.h"


/* Returns 0 if group state is equal to the state passed to this function.
 * Returns negative integer if state is invalid.
 */
static int check_group_state(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, TOX_GROUP_PRIVACY_STATE priv_state,
                             const uint8_t *password, size_t pass_len, const uint8_t *topic, size_t topic_len)
{
    TOX_ERR_GROUP_STATE_QUERIES query_err;

    TOX_GROUP_PRIVACY_STATE my_priv_state = tox_group_get_privacy_state(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get privacy state: %d", query_err);

    if (my_priv_state != priv_state) {
        return -1;
    }

    uint32_t my_peer_limit = tox_group_get_peer_limit(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get peer limit: %d", query_err);

    if (my_peer_limit != peer_limit) {
        return -2;
    }

    size_t my_topic_len = tox_group_get_topic_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get topic size: %d", query_err);

    if (my_topic_len != topic_len) {
        return -3;
    }

    VLA(uint8_t, my_topic, my_topic_len + 1);
    tox_group_get_topic(tox, groupnumber, my_topic, &query_err);
    my_topic[my_topic_len] = 0;
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get topic: %d", query_err);

    if (memcmp(my_topic, topic, my_topic_len) != 0) {
        return -4;
    }

    size_t my_pass_len = tox_group_get_password_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password size: %d", query_err);

    if (my_pass_len != pass_len) {
        return -5;
    }

    if (my_pass_len) {
        VLA(uint8_t, my_pass, my_pass_len + 1);
        tox_group_get_password(tox, groupnumber, my_pass, &query_err);
        my_pass[my_pass_len] = 0;
        ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password: %d", query_err);

        if (memcmp(my_pass, password, my_pass_len) != 0) {
            return -6;
        }
    }

    /* Group name should never change */
    size_t my_gname_len = tox_group_get_name_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get group name size: %d", query_err);

    if (my_gname_len != GROUP_NAME_LEN) {
        return -7;
    }

    VLA(uint8_t, my_gname, my_gname_len + 1);
    tox_group_get_name(tox, groupnumber, my_gname, &query_err);
    my_gname[my_gname_len] = 0;

    if (memcmp(my_gname, (const uint8_t *)GROUP_NAME, my_gname_len) != 0) {
        return -8;
    }

    return 0;
}

static void set_group_state(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, TOX_GROUP_PRIVACY_STATE priv_state,
                            const uint8_t *password, size_t pass_len, const uint8_t *topic, size_t topic_len)
{

    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(tox, groupnumber, peer_limit, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "failed to set peer limit: %d", limit_set_err);

    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE priv_err;
    tox_group_founder_set_privacy_state(tox, groupnumber, priv_state, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "failed to set privacy state: %d", priv_err);

    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD pass_set_err;
    tox_group_founder_set_password(tox, groupnumber, password, pass_len, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK, "failed to set password: %d", pass_set_err);

    TOX_ERR_GROUP_TOPIC_SET topic_set_err;
    tox_group_set_topic(tox, groupnumber, topic, topic_len, &topic_set_err);
    ck_assert_msg(topic_set_err == TOX_ERR_GROUP_TOPIC_SET_OK, "failed to set topic: %d", topic_set_err);
}

static void group_state_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    time_t cur_time = time(nullptr);

    ck_assert_msg(NUM_GROUP_TOXES >= 3, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        char name[16];
        snprintf(name, sizeof(name), "test-%zu", i);
        tox_self_set_name(toxes[i], (const uint8_t *)name, strlen(name), nullptr);

        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);
        tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);

        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    uint32_t num_connected = 0;

    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (tox_self_get_connection_status(toxes[i])) {
                ++num_connected;
            }
        }

        if (num_connected == NUM_GROUP_TOXES) {
            break;
        }
    }

    printf("%u Tox instances connected after %u seconds!\n", num_connected, (unsigned)(time(nullptr) - cur_time));

    /* Tox1 creates a group and is a founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnum = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN,
                                      (const uint8_t *)PEER0_NICK, strlen(PEER0_NICK), &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    /* Set default group state */
    set_group_state(toxes[0], groupnum, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)PASSWORD, PASS_LEN,
                    (const uint8_t *)TOPIC1, TOPIC1_LEN);

    /* Tox1 gets the Chat ID and implicitly shares it publicly */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID and password */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        char nick[TOX_MAX_NAME_LENGTH + 1];
        snprintf(nick, sizeof(nick), "Follower%zu", i);
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)nick, strlen(nick), (const uint8_t *)PASSWORD, PASS_LEN,
                       &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
    }

    fprintf(stderr, "Peers attempting to join group\n");

    /* Keep checking if all instances have connected to the group until test times out */
    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (tox_group_get_peer_limit(toxes[i], 0, nullptr) == PEER_LIMIT_1) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            fprintf(stderr, "%u peers successfully joined\n", count);
            break;
        }
    }

    /* Check that all peers have the correct group state */
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
        int ret = check_group_state(toxes[i], 0, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)PASSWORD,
                                    PASS_LEN, (const uint8_t *)TOPIC1, TOPIC1_LEN);
        ck_assert_msg(ret == 0, "Invalid group state: %d", ret);
    }

    /* Change group state and check that all peers received the changes */
    set_group_state(toxes[0], groupnum, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr, 0, (const uint8_t *)TOPIC2,
                    TOPIC2_LEN);

    fprintf(stderr, "Changing state\n");

    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (check_group_state(toxes[i], groupnum, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr, 0,
                                  (const uint8_t *)TOPIC2, TOPIC2_LEN) == 0) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            fprintf(stderr, "%u peers successfully received state changes\n", count);
            break;
        }
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], groupnum, nullptr, 0, &err_exit);
        ck_assert_msg(err_exit == TOX_ERR_GROUP_LEAVE_OK, "%d", err_exit);
    }

    fprintf(stderr, "All tests passed!\n");

#endif /* VANILLA_NACL */
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_GROUP_TOXES, group_state_test, false);
    return 0;
}

#undef PEER0_NICK

#undef GROUP_NAME_LEN
#undef GROUP_NAME

#undef TOPIC2_LEN
#undef TOPIC2

#undef TOPIC1_LEN
#undef TOPIC1

#undef PASS_LEN
#undef PASSWORD

#undef PEER_LIMIT_2
#undef PEER_LIMIT_1

#undef NUM_GROUP_TOXES
