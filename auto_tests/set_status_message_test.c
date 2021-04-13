/* Tests that we can set our status message
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool status_updated;
} State;

#include "run_auto_test.h"

#define STATUS_MESSAGE "Installing Gentoo"

static void status_callback(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, void *user_data)
{
    ck_assert_msg(length == sizeof(STATUS_MESSAGE) &&
                  memcmp(message, STATUS_MESSAGE, sizeof(STATUS_MESSAGE)) == 0,
                  "incorrect data in status callback");
    State *state = (State *)user_data;
    state->status_updated = true;
}

static void test_set_status_message(Tox **toxes, State *state)
{
    Tox_Err_Set_Info err_n;
    tox_callback_friend_status_message(toxes[1], status_callback);
    bool ret = tox_self_set_status_message(toxes[0], (const uint8_t *)STATUS_MESSAGE, sizeof(STATUS_MESSAGE),
                                           &err_n);
    ck_assert_msg(ret && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_status_message failed because %u\n", err_n);

    state[1].status_updated = false;

    do {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
    } while (!state[1].status_updated);

    ck_assert_msg(tox_friend_get_status_message_size(toxes[1], 0, nullptr) == sizeof(STATUS_MESSAGE),
                  "status message length not correct");
    uint8_t cmp_status[sizeof(STATUS_MESSAGE)];
    tox_friend_get_status_message(toxes[1], 0, cmp_status, nullptr);
    ck_assert_msg(memcmp(cmp_status, STATUS_MESSAGE, sizeof(STATUS_MESSAGE)) == 0,
                  "status message not correct");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, test_set_status_message, FRIEND_ADD_MODE_MESH);
    return 0;
}
