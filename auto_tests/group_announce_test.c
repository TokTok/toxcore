/* Tests that we can send messages to friends.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool peer_joined;
    bool message_sent;
    bool message_received;
} State;

#include "run_auto_test.h"

#define TEST_MESSAGE "The kiosk in my temporal lobe is shaped like Rosalynn Carter"
#define TEST_GROUP_NAME "NASA Headquarters"
#define PEER0_NICK "Lois"
#define PEER1_NICK "Benjamin"

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *group_name, size_t group_name_length, void *user_data)
{
    if (tox != nullptr) {
        ck_abort_msg("we should not get invited");
    }
}

static const char *tox_str_group_join_fail(TOX_GROUP_JOIN_FAIL v)
{
    switch (v) {
        case TOX_GROUP_JOIN_FAIL_NAME_TAKEN:
            return "NAME_TAKEN";

        case TOX_GROUP_JOIN_FAIL_PEER_LIMIT:
            return "PEER_LIMIT";

        case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD:
            return "INVALID_PASSWORD";

        case TOX_GROUP_JOIN_FAIL_UNKNOWN:
            return "UNKNOWN";
    }

    return "<invalid>";
}

static void group_join_fail_handler(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    printf("join failed: %s\n", tox_str_group_join_fail(fail_type));
}

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    printf("peer %u joined, sending message\n", peer_id);
    state->peer_joined = true;
}

static void group_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    if (length > TOX_MAX_MESSAGE_LENGTH) {
        printf("Failed to receive message. Invalid length: %zu\n", length);
        return;
    }

    char message_buf[TOX_MAX_MESSAGE_LENGTH + 1];
    memcpy(message_buf, message, length);
    message_buf[length] = 0;

    State *state = (State *)user_data;
    printf("peer %u sent message: %s\n", peer_id, (const char *)message_buf);
    ck_assert(memcmp(message_buf, TEST_MESSAGE, length) == 0);
    state->message_received = true;
}

static void group_message_test(Tox **toxes, State *state)
{
    tox_self_set_name(toxes[0], (const uint8_t *)"a", 1, nullptr);
    tox_self_set_name(toxes[1], (const uint8_t *)"b", 1, nullptr);

    tox_callback_group_invite(toxes[1], group_invite_handler);
    tox_callback_group_join_fail(toxes[1], group_join_fail_handler);
    tox_callback_group_peer_join(toxes[1], group_peer_join_handler);
    tox_callback_group_message(toxes[0], group_message_handler);

    // tox0 makes new group.
    TOX_ERR_GROUP_NEW err_new;
    uint32_t group_number =
        tox_group_new(
            toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC,
            (const uint8_t *) TEST_GROUP_NAME, strlen(TEST_GROUP_NAME), (const uint8_t *)PEER0_NICK, strlen(PEER0_NICK), &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    // get the chat id of the new group.
    TOX_ERR_GROUP_STATE_QUERIES err_id;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], group_number, chat_id, &err_id);
    ck_assert(err_id == TOX_ERR_GROUP_STATE_QUERIES_OK);

    // tox1 joins it.
    TOX_ERR_GROUP_JOIN err_join;
    tox_group_join(toxes[1], chat_id, (const uint8_t *)PEER1_NICK, strlen(PEER1_NICK), nullptr, 0, &err_join);
    ck_assert(err_join == TOX_ERR_GROUP_JOIN_OK);

    while (!state[0].message_received) {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);

        if (state[1].peer_joined && !state[1].message_sent) {
            TOX_ERR_GROUP_SEND_MESSAGE err_send;
            tox_group_send_message(toxes[1], group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)TEST_MESSAGE,
                                   strlen(TEST_MESSAGE), &err_send);
            ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            state[1].message_sent = true;
        }
    }

    TOX_ERR_GROUP_LEAVE err_exit;
    tox_group_leave(toxes[0], group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    tox_group_leave(toxes[1], group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, group_message_test, false);
    return 0;
}
