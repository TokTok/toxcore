#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/forwarders.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6;
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4;
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

#define NUM_FORWARDER 5
#define FORWARDER_TCP_RELAY_PORT 36570
#define FORWARDING_BASE_PORT 36571

typedef struct Test_Data {
    Forwarders *forwarders;
    uint32_t send_back;
    bool sent;
    bool returned;
} Test_Data;

static bool test_forwarded_cb(void *object, IP_Port sender, IP_Port forwarder,
                              const uint8_t *data, uint16_t length, void *userdata)
{
    Test_Data *test_data = (Test_Data *)object;
    uint8_t *index = (uint8_t *)userdata;

    if (length == 11 && memcmp("hello: ", data, 7) == 0) {
        uint8_t reply[11];
        memcpy(reply, "reply: ", 7);
        memcpy(reply + 7, data + 7, 4);
        send_forward_request_to(test_data->forwarders, forwarder, sender, reply, 11);
        return false;
    }

    if (length == 11 && memcmp("reply: ", data, 7) == 0) {
        ck_assert_msg(memcmp(&test_data->send_back, data + 7, 4) == 0,
                      "[%u] got unexpected reply: %u", *index, *(const uint32_t *)(data + 7));
        printf("[%u] got reply\n", *index);
        test_data->returned = true;
        return true;
    }

    printf("[%u] got unexpected data\n", *index);
    return false;
}

static bool all_returned(Test_Data *test_data)
{
    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        if (!test_data[i].returned) {
            return false;
        }
    }

    return true;
}

static void test_forwarding(void)
{
    assert(sizeof(char) == 1);

    uint32_t index[NUM_FORWARDER];
    Logger *logs[NUM_FORWARDER];
    Mono_Time *mono_times[NUM_FORWARDER];
    Networking_Core *nets[NUM_FORWARDER];
    DHT *dhts[NUM_FORWARDER];
    Net_Crypto *cs[NUM_FORWARDER];
    Forwarding *forwardings[NUM_FORWARDER];
    Forwarders *forwarderses[NUM_FORWARDER];

    Test_Data test_data[NUM_FORWARDER];

    IP ip = get_loopback();
    TCP_Proxy_Info inf = {{{{0}}}};

    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        index[i] = i + 1;
        logs[i] = logger_new();
        logger_callback_log(logs[i], (logger_cb *)print_debug_log, nullptr, &index[i]);
        mono_times[i] = mono_time_new();

        nets[i] = new_networking(logs[i], ip, FORWARDING_BASE_PORT + i);

        dhts[i] = new_dht(logs[i], mono_times[i], nets[i], true);
        cs[i] = new_net_crypto(logs[i], mono_times[i], dhts[i], &inf);
        forwardings[i] = new_forwarding(nets[i]);
        forwarderses[i] = new_forwarders(mono_times[i], dhts[i], cs[i]);
        ck_assert_msg((forwarderses[i] != nullptr), "Forwarders failed initializing.");

        test_data[i].forwarders = forwarderses[i];
        test_data[i].send_back = 0;
        test_data[i].sent = false;
        test_data[i].returned = false;
        set_callback_forwarded(forwarderses[i], test_forwarded_cb, &test_data[i]);
    }

    printf("testing forwarding via tcp relays and dht\n");
    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts, FORWARDER_TCP_RELAY_PORT);
    IP_Port relay_ipport_tcp = {ip, net_htons(FORWARDER_TCP_RELAY_PORT)};
    Tox *relay = tox_new_log(opts, nullptr, nullptr);
    ck_assert_msg(relay != nullptr, "Failed to create TCP relay");
    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(relay, dpk);

    printf("1-%d connected only to TCP server; %d-%d connected only to DHT\n",
           NUM_FORWARDER / 2, NUM_FORWARDER / 2 + 1, NUM_FORWARDER);

    for (uint32_t i = 0; i < NUM_FORWARDER / 2; ++i) {
        set_tcp_onion_status(nc_get_tcp_c(cs[i]), 1);
        ck_assert_msg(add_tcp_relay(cs[i], relay_ipport_tcp, dpk) == 0,
                      "Failed to add TCP relay");
    };

    IP_Port relay_ipport_udp = {ip, net_htons(tox_self_get_udp_port(relay, nullptr))};

    for (uint32_t i = NUM_FORWARDER / 2; i < NUM_FORWARDER; ++i) {
        dht_bootstrap(dhts[i % NUM_FORWARDER], relay_ipport_udp, dpk);
    }

    do {
        for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
            if (!test_data[i].sent) {
                uint32_t dest_i = random_u32() % NUM_FORWARDER;
                IP_Port dest = {ip, net_htons(FORWARDING_BASE_PORT + dest_i)};
                uint8_t data[11];

                memcpy(data, "hello: ", 7);
                test_data[i].send_back = random_u32();
                *(uint32_t *)(data + 7) = test_data[i].send_back;

                if (send_forward_request(forwarderses[i], dest, data, 11)) {
                    printf("%u --> ? --> %u\n", i + 1, dest_i + 1);
                    test_data[i].sent = true;
                }
            }

            mono_time_update(mono_times[i]);
            networking_poll(nets[i], &index[i]);
            do_net_crypto(cs[i], &index[i]);
            do_dht(dhts[i]);
        }

        tox_iterate(relay, nullptr);

        c_sleep(50);
    } while (!all_returned(test_data));


    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        kill_forwarders(forwarderses[i]);
        kill_forwarding(forwardings[i]);
        kill_net_crypto(cs[i]);
        kill_dht(dhts[i]);
        kill_networking(nets[i]);
        mono_time_free(mono_times[i]);
        logger_kill(logs[i]);
    }

    tox_kill(relay);
}


int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_forwarding();

    return 0;
}
