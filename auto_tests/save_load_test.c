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
static void reload_tox(Tox **tox, uint32_t *index)
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

    for (size_t i = 0; i < extra; i++) {
        ck_assert_msg(buffer[i] == 0xCD, "Buffer underwritten from tox_get_savedata() @%u", (unsigned)i);
        ck_assert_msg(buffer[extra + save_size1 + i] == 0xCD, "Buffer overwritten from tox_get_savedata() @%u", (unsigned)i);
    }

    struct Tox_Options *const options = tox_options_new(nullptr);

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(options, buffer + extra, save_size1);

    tox_options_set_local_discovery_enabled(options, false);

    *tox = tox_new_log(options, nullptr, index);

    tox_options_free(options);

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
    uint32_t index[] = { 1, 2, 3 };
    time_t con_time = 0, cur_time = time(nullptr);
    Tox *tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *tox2 = tox_new_log(nullptr, nullptr, &index[1]);
    Tox *tox3 = tox_new_log(nullptr, nullptr, &index[2]);

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    printf("bootstrapping tox2 and tox3 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(tox3, "localhost", dht_port, dht_key, nullptr);

    connected_t1 = 0;
    tox_callback_self_connection_status(tox1, tox_connection_status);
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (true) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(ITERATION_INTERVAL);
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    reload_tox(&tox2, &index[1]);

    cur_time = time(nullptr);

    off = 1;

    while (true) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online again after reloading, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(ITERATION_INTERVAL);
    }

    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    printf("test_few_clients succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_few_clients();
    return 0;
}
