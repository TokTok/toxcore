/* Tests that we can set our name.
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
    bool nickname_updated;
} State;

#include "run_auto_test.h"

#define NICKNAME "Gentoo"

static void nickchange_callback(Tox *tox, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    ck_assert_msg(length == sizeof(NICKNAME) && memcmp(string, NICKNAME, sizeof(NICKNAME)) == 0, "Name not correct");
    State *state = (State *)userdata;
    state->nickname_updated = true;
}

static void test_set_name(Tox **toxes, State *state)
{
    tox_callback_friend_name(toxes[1], nickchange_callback);
    Tox_Err_Set_Info err_n;
    bool ret = tox_self_set_name(toxes[0], (const uint8_t *)NICKNAME, sizeof(NICKNAME), &err_n);
    ck_assert_msg(ret && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_name failed because %u\n", err_n);

    state[1].nickname_updated = false;

    do {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
    } while (!state[1].nickname_updated);

    ck_assert_msg(tox_friend_get_name_size(toxes[1], 0, nullptr) == sizeof(NICKNAME), "Name length not correct");
    uint8_t temp_name[sizeof(NICKNAME)];
    tox_friend_get_name(toxes[1], 0, temp_name, nullptr);
    ck_assert_msg(memcmp(temp_name, NICKNAME, sizeof(NICKNAME)) == 0, "Name not correct");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, test_set_name, FRIEND_ADD_MODE_MESH);
    return 0;
}
