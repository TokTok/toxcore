#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "helpers.h"

static uint8_t const key[] = {
    0xF4, 0x04, 0xAB, 0xAA, 0x1C, 0x99, 0xA9, 0xD3,
    0x7D, 0x61, 0xAB, 0x54, 0x89, 0x8F, 0x56, 0x79,
    0x3E, 0x1D, 0xEF, 0x8B, 0xD4, 0x6B, 0x10, 0x38,
    0xB9, 0xD8, 0x22, 0xE8, 0x46, 0x0F, 0xAB, 0x67,
};

int main(void)
{
    Tox *tox = tox_new_log(nullptr, nullptr, nullptr);

    tox_bootstrap(tox, "biribiri.org", 33445, key, nullptr);

    printf("Waiting for connection");

    while (tox_self_get_connection_status(tox) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox, nullptr);
        c_sleep(1000);
    }

    printf("Connection: %d\n", tox_self_get_connection_status(tox));

    tox_kill(tox);
    return 0;
}
