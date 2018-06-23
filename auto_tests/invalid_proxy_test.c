// Test that if UDP is enabled, and a invalid proxy is provided, we reject the
// configuration.
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "helpers.h"

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, true);
    tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
    tox_options_set_proxy_host(opts, "localhost");
    tox_options_set_proxy_port(opts, 51724);
    TOX_ERR_NEW err;
    Tox *tox = tox_new_log(opts, &err, nullptr);
    tox_options_free(opts);

    assert(tox == nullptr);
    assert(err == TOX_ERR_NEW_PROXY_WITH_UDP);

    return 0;
}
