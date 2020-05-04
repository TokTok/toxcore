/* Tests that we can add friends.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../testing/misc_tools.h"
#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
} State;

#include "run_auto_test.h"

#define FR_MESSAGE "Gentoo"

static void accept_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *data, size_t length,
                                  void *userdata)
{
    ck_assert_msg(length == sizeof(FR_MESSAGE) && memcmp(FR_MESSAGE, data, sizeof(FR_MESSAGE)) == 0,
                  "unexpected friend request message");
    tox_friend_add_norequest(tox, public_key, nullptr);
}

static void test_friend_request(Tox **toxes, State *state)
{
    printf("Tox1 adds tox2 as friend, tox2 accepts.\n");
    tox_callback_friend_request(toxes[1], accept_friend_request);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(toxes[1], address);

    Tox_Err_Friend_Add err;
    const uint32_t test = tox_friend_add(toxes[0], address, (const uint8_t *)FR_MESSAGE, sizeof(FR_MESSAGE), &err);
    ck_assert_msg(test == 0, "failed to add friend error code: %u", err);

    do {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
    } while (tox_friend_get_connection_status(toxes[0], 0, nullptr) != TOX_CONNECTION_UDP ||
             tox_friend_get_connection_status(toxes[1], 0, nullptr) != TOX_CONNECTION_UDP);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, test_friend_request, FRIEND_ADD_MODE_NONE);
    return 0;
}
