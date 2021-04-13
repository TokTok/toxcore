/* Tests that a friend_connection properly switches to using TCP relays when
 * the direct UDP connection fails, and switches back to using the direct
 * connection if it recovers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

typedef struct State {
    int friend_connection_status;
} State;

#include "run_auto_test.h"


static void handle_friend_connection_status(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    ck_assert(connection_status != TOX_CONNECTION_NONE);
    ck_assert(friend_number == 0);

    state->friend_connection_status = connection_status;
}

static bool all_connection_status(AutoTox *autotoxes, TOX_CONNECTION expected_status)
{
    for (uint32_t i = 1; i < 3; i++) {
        State *state = (State *)autotoxes[i].state;

        if (state->friend_connection_status != expected_status) {
            return false;
        }
    }

    return true;
}

static void init_autotox(AutoTox *autotox, uint32_t n)
{
    tox_callback_friend_connection_status(autotox->tox, handle_friend_connection_status);
}

static void tcp_backup_test(AutoTox *autotoxes)
{
    const uint32_t tox_count = 3;

    ck_assert_msg(all_connection_status(autotoxes, TOX_CONNECTION_UDP),
                  "TCP-relayed friend connection with no packet loss");

    printf("Simulating failure of the direct connection between #1 and #2\n");

    for (uint32_t i = 1; i < tox_count; i++) {
        // TODO(iphydf): Don't rely on toxcore internals.
        Messenger *m = *(Messenger **)autotoxes[i].tox;

        set_simulated_packet_loss_percentage(m->net, 100);
    }

    printf("Waiting for toxes to switch to using TCP relay\n");

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_connection_status(autotoxes, TOX_CONNECTION_TCP));

    printf("Simulating recovery of the direct connection between #1 and #2\n");

    for (uint32_t i = 1; i < tox_count; i++) {
        // TODO(iphydf): Don't rely on toxcore internals.
        Messenger *m = *(Messenger **)autotoxes[i].tox;

        set_simulated_packet_loss_percentage(m->net, 50);
    }

    printf("Waiting for toxes to switch to using direct connection\n");

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_connection_status(autotoxes, TOX_CONNECTION_UDP));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options;
    options.tcp_relays = 1;
    options.tcp_first_port = 33449;
    options.init_autotox = init_autotox;

    run_auto_test(3, tcp_backup_test, sizeof(State), &options);
    return 0;
}
