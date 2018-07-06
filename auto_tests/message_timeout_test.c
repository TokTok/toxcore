// Test that we can survive 100 iterations (10 seconds) without response from a
// friend and still send a "lossless" packet (a friend message).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    uint32_t index;
    bool message_received;
} State;

#include "run_auto_test.h"

#define POOR_CONNECTION_ITERATIONS 100

static void handle_friend_connection_status(
    Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data)
{
    State *state = (State *)user_data;

    if (connection_status == TOX_CONNECTION_NONE) {
        ck_abort_msg("tox%u: friend %u unexpectedly went offline", state->index, friend_number);
    }
}

static void handle_friend_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "tox%u received message from friend %u\n", state->index, friend_number);
    state->message_received = true;
}

static void connection_timeout_test(Tox **toxes, State *state)
{
    fprintf(stderr, "Running tox0, but not tox1, for %d iterations\n", POOR_CONNECTION_ITERATIONS);

    tox_callback_friend_connection_status(toxes[0], handle_friend_connection_status);
    tox_callback_friend_connection_status(toxes[1], handle_friend_connection_status);

    tox_callback_friend_message(toxes[1], handle_friend_message);

    fprintf(stderr, "Sending message from tox0 to tox1\n");
    TOX_ERR_FRIEND_SEND_MESSAGE err;
    tox_friend_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello", 5, &err);
    ck_assert_msg(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK,
                  "failed to send message from tox0 to tox1: err = %d", err);

    for (uint32_t i = 0; i < POOR_CONNECTION_ITERATIONS; i++) {
        tox_iterate(toxes[0], &state[0]);

        c_sleep(ITERATION_INTERVAL);
    }

    fprintf(stderr, "Continuing tox1\n");

    while (!state[1].message_received) {
        tox_iterate(toxes[0], &state[0]);
        tox_iterate(toxes[1], &state[1]);

        c_sleep(ITERATION_INTERVAL);
    }

    fprintf(stderr, "Message sent successfully despite intermittent poor connection\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, connection_timeout_test);
    return 0;
}
