/* Tests that we can send lossy packets.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    bool custom_packet_received;
} State;

#include "run_auto_test.h"

#define LOSSY_PACKET_FILLER 200

static void handle_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    uint8_t cmp_packet[TOX_MAX_CUSTOM_PACKET_SIZE];
    memset(cmp_packet, LOSSY_PACKET_FILLER, sizeof(cmp_packet));

    if (length == TOX_MAX_CUSTOM_PACKET_SIZE && memcmp(data, cmp_packet, sizeof(cmp_packet)) == 0) {
        const AutoTox *autotox = (AutoTox *)user_data;
        State *state = (State *)autotox->state;
        state->custom_packet_received = true;
    }
}

static void test_lossy_packet(AutoTox *autotoxes)
{
    tox_callback_friend_lossy_packet(autotoxes[1].tox, &handle_lossy_packet);
    uint8_t packet[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memset(packet, LOSSY_PACKET_FILLER, sizeof(packet));

    bool ret = tox_friend_send_lossy_packet(autotoxes[0].tox, 0, packet, sizeof(packet), nullptr);
    ck_assert_msg(ret == false, "should not be able to send custom packets this big %i", ret);

    ret = tox_friend_send_lossy_packet(autotoxes[0].tox, 0, packet, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
    ck_assert_msg(ret == true, "tox_friend_send_lossy_packet fail %i", ret);

    do {
        iterate_all_wait(2, autotoxes, ITERATION_INTERVAL);
    } while (!((State *)autotoxes[1].state)->custom_packet_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, test_lossy_packet, sizeof(State), &default_run_auto_options);
    return 0;
}
