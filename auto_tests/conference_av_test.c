/* Auto Tests: Conferences AV.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../toxav/groupav.h"
#include "../toxav/toxav.h"
#include "check_compat.h"

#define NUM_AV_GROUP_TOX 4
#define NUM_AV_DISCONNECT 2

typedef struct State {
    uint32_t index;
    uint64_t clock;

    bool invited_next;

    uint32_t received_audio_samples;
} State;

#include "run_auto_test.h"

static void handle_self_connection_status(
    Tox *tox, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->index);
    } else {
        printf("tox #%u: is now disconnected\n", state->index);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->index, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->index, friendnumber);
    }
}

static void audio_callback(void *tox, uint32_t groupnumber, uint32_t peernumber, 
        const int16_t *pcm, unsigned int samples, uint8_t channels, uint32_t 
        sample_rate, void *userdata) 
{
    State *state = (State *)userdata;
    state->received_audio_samples += samples;
}

static void handle_conference_invite(
    Tox *tox, uint32_t friendnumber, Tox_Conference_Type type,
    const uint8_t *data, size_t length, void *user_data)
{
    const State *state = (State *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_AV, "tox #%u: wrong conference type: %d", state->index, type);

    ck_assert_msg(toxav_join_av_groupchat(tox, friendnumber, data, length, audio_callback, user_data) == 0,
            "tox #%u: failed to join group", state->index);
}

static void handle_conference_connected(
    Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    if (state->invited_next || tox_self_get_friend_list_size(tox) <= 1) {
        return;
    }

    Tox_Err_Conference_Invite err;
    tox_conference_invite(tox, 1, 0, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", state->index, err);
    printf("tox #%u: invited next friend\n", state->index);
    state->invited_next = true;
}

static bool toxes_are_disconnected_from_group(uint32_t tox_count, Tox **toxes, int disconnected_count,
        bool *disconnected)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (disconnected[i]) {
            continue;
        }

        if (tox_conference_peer_count(toxes[i], 0, nullptr) > tox_count - NUM_AV_DISCONNECT) {
            return false;
        }
    }

    return true;
}

static bool all_connected_to_group(uint32_t tox_count, Tox **toxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (tox_conference_peer_count(toxes[i], 0, nullptr) < tox_count) {
            return false;
        }
    }

    return true;
}

/* returns a random index at which a list of booleans is false
 * (some such index is required to exist)
 * */
static uint32_t random_false_index(bool *list, const uint32_t length)
{
    uint32_t index;

    do {
        index = random_u32() % length;
    } while (list[index]);

    return index;
}

static bool all_got_audio(State *state, uint16_t sender)
{
    for (uint16_t j = 0; j < NUM_AV_GROUP_TOX; ++j) {
        if (j != sender && state[j].received_audio_samples == 0) {
            return false;
        }
    }

    return true;
}

static void test_audio(Tox **toxes, State *state)
{
    printf("testing sending and receiving audio\n");
    const unsigned int samples = 960;
    int16_t *PCM = (int16_t *)calloc(samples, sizeof(int16_t));

    for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        for (uint16_t j = 0; j < NUM_AV_GROUP_TOX; ++j) {
            state[j].received_audio_samples = 0;
        }

        uint64_t start = state[0].clock;
        do {
            ck_assert_msg(toxav_group_send_audio(toxes[i], 0, PCM, samples, 1, 48000) == 0,
                    "#%u failed to send audio", state[i].index);

            iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
        } while (state[0].clock < start + 16*ITERATION_INTERVAL && !all_got_audio(state, i));

        ck_assert_msg(state[0].clock < start + 16*ITERATION_INTERVAL,
                "timed out while waiting for group to receive audio from #%u", 
                state[i].index);

    }
}

static void run_conference_tests(Tox **toxes, State *state)
{
    test_audio(toxes, state);

    printf("letting random toxes timeout\n");
    bool disconnected[NUM_AV_GROUP_TOX] = {0};
    bool restarting[NUM_AV_GROUP_TOX] = {0};

    ck_assert(NUM_AV_DISCONNECT < NUM_AV_GROUP_TOX);

    for (uint16_t i = 0; i < NUM_AV_DISCONNECT; ++i) {
        uint32_t disconnect = random_false_index(disconnected, NUM_AV_GROUP_TOX);
        disconnected[disconnect] = true;

        if (i < NUM_AV_DISCONNECT / 2) {
            restarting[disconnect] = true;
            printf("Restarting #%u\n", state[disconnect].index);
        } else {
            printf("Disconnecting #%u\n", state[disconnect].index);
        }
    }

    uint8_t *save[NUM_AV_GROUP_TOX];
    size_t save_size[NUM_AV_GROUP_TOX];

    for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            save_size[i] = tox_get_savedata_size(toxes[i]);
            ck_assert_msg(save_size[i] != 0, "save is invalid size %u", (unsigned)save_size[i]);
            save[i] = (uint8_t *)malloc(save_size[i]);
            ck_assert_msg(save[i] != nullptr, "malloc failed");
            tox_get_savedata(toxes[i], save[i]);
            tox_kill(toxes[i]);
        }
    }

    do {
        for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            if (!disconnected[i]) {
                tox_iterate(toxes[i], &state[i]);
                state[i].clock += 1000;
            }
        }

        c_sleep(20);
    } while (!toxes_are_disconnected_from_group(NUM_AV_GROUP_TOX, toxes, NUM_AV_DISCONNECT, disconnected));

    for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            struct Tox_Options *const options = tox_options_new(nullptr);
            tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
            tox_options_set_savedata_data(options, save[i], save_size[i]);
            toxes[i] = tox_new_log(options, nullptr, &state[i].index);
            tox_options_free(options);
            free(save[i]);
        }
    }

    printf("reconnecting toxes\n");

    do {
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    } while (!all_connected_to_group(NUM_AV_GROUP_TOX, toxes));

    for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            ck_assert_msg(toxav_groupchat_enable_av(toxes[i], 0, audio_callback, &state[i]) == 0,
                    "#%u failed to re-enable av", state[i].index);
        }
    }

    test_audio(toxes, state);
}

static void test_groupav(Tox **toxes, State *state)
{
    const time_t test_start_time = time(nullptr);

    for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);
        tox_callback_conference_invite(toxes[i], &handle_conference_invite);
        tox_callback_conference_connected(toxes[i], &handle_conference_connected);
    }

    ck_assert_msg(toxav_add_av_groupchat(toxes[0], audio_callback, &state[0]) != UINT32_MAX, "failed to create group");
    printf("tox #%u: inviting its first friend\n", state[0].index);
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, nullptr) != 0, "failed to invite friend");
    state[0].invited_next = true;


    printf("waiting for invitations to be made\n");
    uint16_t invited_count = 0;

    do {
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        invited_count = 0;

        for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            invited_count += state[i].invited_next;
        }
    } while (invited_count != NUM_AV_GROUP_TOX - 1);

    uint64_t pregroup_clock = state[0].clock;
    printf("waiting for all toxes to be in the group\n");
    uint16_t fully_connected_count = 0;

    do {
        fully_connected_count = 0;
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        for (uint16_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            Tox_Err_Conference_Peer_Query err;
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, &err);

            if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peer_count = 0;
            }

            fully_connected_count += peer_count == NUM_AV_GROUP_TOX;
        }
    } while (fully_connected_count != NUM_AV_GROUP_TOX);

    printf("group connected, took %d seconds\n", (int)((state[0].clock - pregroup_clock) / 1000));

    run_conference_tests(toxes, state);

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_AV_GROUP_TOX, test_groupav, true);
    return 0;
}
