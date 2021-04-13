/* Tests that we can save and load Tox data.
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
} State;

#include "run_auto_test.h"

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef TOX_LOCALHOST
#undef TOX_LOCALHOST
#endif
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

#ifdef TCP_RELAY_PORT
#undef TCP_RELAY_PORT
#endif
#define TCP_RELAY_PORT 33430

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

static unsigned int connected_t1;
static void tox_connection_status(Tox *tox, Tox_Connection connection_status, void *user_data)
{
    if (connected_t1 && !connection_status) {
        ck_abort_msg("Tox went offline");
    }

    ck_assert_msg(connection_status == TOX_CONNECTION_UDP, "wrong status %d", connection_status);

    connected_t1 = connection_status;
}

/* validate that:
 * a) saving stays within the confined space
 * b) a saved state can be loaded back successfully
 * c) a second save is of equal size
 * d) the second save is of equal content */
static void reload_tox(Tox **tox, struct Tox_Options *const in_opts, void *user_data)
{
    const size_t extra = 64;
    const size_t save_size1 = tox_get_savedata_size(*tox);
    ck_assert_msg(save_size1 != 0, "save is invalid size %u", (unsigned)save_size1);
    printf("%u\n", (unsigned)save_size1);

    uint8_t *buffer = (uint8_t *)malloc(save_size1 + 2 * extra);
    ck_assert_msg(buffer != nullptr, "malloc failed");
    memset(buffer, 0xCD, extra);
    memset(buffer + extra + save_size1, 0xCD, extra);
    tox_get_savedata(*tox, buffer + extra);
    tox_kill(*tox);

    for (size_t i = 0; i < extra; ++i) {
        ck_assert_msg(buffer[i] == 0xCD, "Buffer underwritten from tox_get_savedata() @%u", (unsigned)i);
        ck_assert_msg(buffer[extra + save_size1 + i] == 0xCD, "Buffer overwritten from tox_get_savedata() @%u", (unsigned)i);
    }

    struct Tox_Options *const options = (in_opts == nullptr) ? tox_options_new(nullptr) : in_opts;

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(options, buffer + extra, save_size1);

    *tox = tox_new_log(options, nullptr, user_data);

    if (in_opts == nullptr) {
        tox_options_free(options);
    }

    ck_assert_msg(*tox != nullptr, "Failed to load back stored buffer");

    const size_t save_size2 = tox_get_savedata_size(*tox);

    ck_assert_msg(save_size1 == save_size2, "Tox save data changed in size from a store/load cycle: %u -> %u",
                  (unsigned)save_size1, (unsigned)save_size2);

    uint8_t *buffer2 = (uint8_t *)malloc(save_size2);

    ck_assert_msg(buffer2 != nullptr, "malloc failed");

    tox_get_savedata(*tox, buffer2);

    ck_assert_msg(!memcmp(buffer + extra, buffer2, save_size2), "Tox state changed by store/load/store cycle");

    free(buffer2);

    free(buffer);
}

static void test_few_clients(void)
{
    State state[] = { {1}, {2}, {3} };
    Tox *toxes[3];
    time_t con_time = 0, cur_time = time(nullptr);

    Tox_Err_New err;

    struct Tox_Options *opts1 = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts1, TCP_RELAY_PORT);
    toxes[0] = tox_new_log(opts1, &err, &state[0].index);
    ck_assert_msg(toxes[0], "Failed to create tox instance 1: %d", err);
    tox_options_free(opts1);
    set_mono_time_callback(toxes[0], &state[0]);

    struct Tox_Options *opts2 = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts2, false);
    tox_options_set_local_discovery_enabled(opts2, false);
    toxes[1] = tox_new_log(opts2, &err, &state[1].index);
    ck_assert_msg(toxes[1], "Failed to create tox instance 2: %d", err);
    set_mono_time_callback(toxes[1], &state[1]);

    struct Tox_Options *opts3 = tox_options_new(nullptr);
    tox_options_set_local_discovery_enabled(opts3, false);
    toxes[2] = tox_new_log(opts3, &err, &state[2].index);
    ck_assert_msg(toxes[2], "Failed to create tox instance 3: %d", err);
    set_mono_time_callback(toxes[2], &state[2]);

    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(toxes[0], dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

    printf("using tox1 as tcp relay for tox2\n");
    tox_add_tcp_relay(toxes[1], TOX_LOCALHOST, TCP_RELAY_PORT, dht_key, nullptr);

    printf("bootstrapping toxes off tox1\n");
    tox_bootstrap(toxes[1], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(toxes[2], "localhost", dht_port, dht_key, nullptr);

    connected_t1 = 0;
    tox_callback_self_connection_status(toxes[0], tox_connection_status);
    tox_callback_friend_request(toxes[1], accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(toxes[1], address);
    uint32_t test = tox_friend_add(toxes[2], address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (true) {
        iterate_all_wait(3, toxes, state, 50);

        if (tox_self_get_connection_status(toxes[0]) && tox_self_get_connection_status(toxes[1])
                && tox_self_get_connection_status(toxes[2])) {
            if (off) {
                printf("Toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(toxes[1], 0, nullptr) == TOX_CONNECTION_TCP
                    && tox_friend_get_connection_status(toxes[2], 0, nullptr) == TOX_CONNECTION_TCP) {
                break;
            }
        }
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    reload_tox(&toxes[1], opts2, &state[1].index);
    reload_tox(&toxes[2], opts3, &state[2].index);

    cur_time = time(nullptr);

    off = 1;

    while (true) {
        iterate_all_wait(3, toxes, state, 50);

        if (tox_self_get_connection_status(toxes[0]) && tox_self_get_connection_status(toxes[1])
                && tox_self_get_connection_status(toxes[2])) {
            if (off) {
                printf("Toxes are online again after reloading, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(toxes[1], 0, nullptr) == TOX_CONNECTION_TCP
                    && tox_friend_get_connection_status(toxes[2], 0, nullptr) == TOX_CONNECTION_TCP) {
                break;
            }
        }
    }

    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    printf("test_few_clients succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));

    tox_kill(toxes[0]);
    tox_kill(toxes[1]);
    tox_kill(toxes[2]);

    tox_options_free(opts2);
    tox_options_free(opts3);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    (void)run_auto_test;

    test_few_clients();
    return 0;
}
