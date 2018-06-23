// Test that if UDP is enabled, and an invalid proxy is provided, then we get a
// UDP connection only.
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "helpers.h"

static uint8_t const key[] = {
    0x15, 0xE9, 0xC3, 0x09, 0xCF, 0xCB, 0x79, 0xFD,
    0xDF, 0x0E, 0xBA, 0x05, 0x7D, 0xAB, 0xB4, 0x9F,
    0xE1, 0x5F, 0x38, 0x03, 0xB1, 0xBF, 0xF0, 0x65,
    0x36, 0xAE, 0x2E, 0x5B, 0xA5, 0xE4, 0x69, 0x0E,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, true);
    tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
    tox_options_set_proxy_host(opts, "localhost");
    tox_options_set_proxy_port(opts, 51724);
    Tox *tox = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    tox_add_tcp_relay(tox, "tox.ngc.zone", 33445, key, nullptr);
    tox_bootstrap(tox, "tox.ngc.zone", 33445, key, nullptr);

    printf("Waiting for connection");

    while (tox_self_get_connection_status(tox) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    assert(tox_self_get_connection_status(tox) == TOX_CONNECTION_UDP);
    printf("Connection (UDP): %d\n", tox_self_get_connection_status(tox));

    tox_kill(tox);
    return 0;
}
