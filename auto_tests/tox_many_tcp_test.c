/* Auto Tests: Many TCP.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}


#define NUM_TOXES_TCP 20
#define TCP_RELAY_PORT 33448

#define NUM_TCP_RELAYS (NUM_TOXES_TCP - 1)
#define NUM_FRIENDS ((NUM_TOXES_TCP - NUM_TCP_RELAYS) * NUM_TCP_RELAYS)

START_TEST(test_many_clients_tcp_b)
{
    long long unsigned int cur_time = time(nullptr);
    Tox *toxes[NUM_TOXES_TCP];
    uint32_t index[NUM_TOXES_TCP];
    uint32_t i, j;
    uint32_t to_comp = 974536;

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        struct Tox_Options *opts = tox_options_new(nullptr);

        if (i < NUM_TCP_RELAYS) {
            tox_options_set_tcp_port(opts, TCP_RELAY_PORT + i);
        } else {
            tox_options_set_udp_enabled(opts, 0);
        }

        index[i] = i + 1;
        toxes[i] = tox_new_log(opts, nullptr, &index[i]);
        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], accept_friend_request);
        uint8_t dpk[TOX_PUBLIC_KEY_SIZE];

        if (i >= NUM_TCP_RELAYS) {
            tox_self_get_dht_id(toxes[i % NUM_TCP_RELAYS], dpk);
            ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, TCP_RELAY_PORT + i % NUM_TCP_RELAYS, dpk, nullptr),
                          "add relay error");

            for (j = 0; j < NUM_TCP_RELAYS; j++) {
                // TCP-only nodes will only announce at nodes they've
                // bootstrapped to, because LAN addresses are ignored in the
                // onion. So we manually bootstrap to all dht nodes.
                tox_self_get_dht_id(toxes[j], dpk);
                uint16_t port = tox_self_get_udp_port(toxes[j], nullptr);
                ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, port, dpk, nullptr), "Bootstrap error");
            }
        } else {
            tox_self_get_dht_id(toxes[0], dpk);
            uint16_t first_port = tox_self_get_udp_port(toxes[0], nullptr);
            ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, first_port, dpk, nullptr), "Bootstrap error");
        }

        tox_options_free(opts);
    }

    uint8_t address[TOX_ADDRESS_SIZE];

    for (i = NUM_TCP_RELAYS; i < NUM_TOXES_TCP; ++i) {
        for (j = 0; j < NUM_TCP_RELAYS; ++j) {

            tox_self_get_address(toxes[i], address);

            TOX_ERR_FRIEND_ADD test;
            uint32_t num = tox_friend_add(toxes[j], address, (const uint8_t *)"Gentoo", 7, &test);

            ck_assert_msg(test == TOX_ERR_FRIEND_ADD_OK, "Tox %u failed to add tox %u", i, j);

            ck_assert_msg(num != UINT32_MAX && test == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend error code: %i", test);
        }
    }

    printf("friends added\n");

    uint16_t last_count = 0;

    while (true) {
        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(30);

        uint16_t failcount = 0;
        uint16_t count = 0;

        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            for (j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                count++;

                if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_NONE) {
                    failcount++;
                }
            }
        }

        if (failcount != last_count) {
            printf("%d:%d\n", failcount, count);
            last_count = failcount;
        }

        if (failcount == 0 && count == NUM_FRIENDS * 2) {
            break;
        }
    }

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients_tcp_b succeeded, took %llu seconds\n", time(nullptr) - cur_time);
}
END_TEST


static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox many tcp");

    DEFTESTCASE(many_clients_tcp_b);

    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
