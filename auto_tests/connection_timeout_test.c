// Test that we notice if a friend is not responding to network packets, we drop
// the connection to them.
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    uint32_t index;
    bool friend_online;
} State;

#include "run_auto_test.h"

static void handle_friend_connection_status(
    Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "Friend %u dropped out\n", friend_number);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void connection_timeout_test(Tox **toxes, State *state)
{
    fprintf(stderr, "Running tox0, but not tox1, waiting for tox1 to drop out\n");

    state[0].friend_online = true;
    tox_callback_friend_connection_status(toxes[0], handle_friend_connection_status);

    uint32_t i;

    for (i = 0; state[0].friend_online; i++) {
        tox_iterate(toxes[0], &state[0]);

        c_sleep(ITERATION_INTERVAL);
    }

    fprintf(stderr, "Friend dropped out successfully after %u iterations\n", i);

}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, connection_timeout_test);
    return 0;
}
