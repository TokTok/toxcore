#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key1[] = {
    0x02, 0x80, 0x7C, 0xF4, 0xF8, 0xBB, 0x8F, 0xB3,
    0x90, 0xCC, 0x37, 0x94, 0xBD, 0xF1, 0xE8, 0x44,
    0x9E, 0x9A, 0x83, 0x92, 0xC5, 0xD3, 0xF2, 0x20,
    0x00, 0x19, 0xDA, 0x9F, 0x1E, 0x81, 0x2E, 0x46,
};

static uint8_t const key2[] = {
    0x3F, 0x0A, 0x45, 0xA2, 0x68, 0x36, 0x7C, 0x1B,
    0xEA, 0x65, 0x2F, 0x25, 0x8C, 0x85, 0xF4, 0xA6,
    0x6D, 0xA7, 0x6B, 0xCA, 0xA6, 0x67, 0xA4, 0x9E,
    0x77, 0x0B, 0xCC, 0x49, 0x17, 0xAB, 0x6A, 0x25,
};

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox1 = tox_new_log(nullptr, nullptr, nullptr);
    Tox *tox2 = tox_new_log(nullptr, nullptr, nullptr);

    ck_assert(tox1 != nullptr);
    ck_assert(tox2 != nullptr);

    Tox_Err_Bootstrap boot_err;
    tox_bootstrap(tox1, "78.46.73.141", 33445, key1, &boot_err);
    ck_assert(boot_err == TOX_ERR_BOOTSTRAP_OK);
    tox_bootstrap(tox2, "78.46.73.141", 33445, key1, &boot_err);
    ck_assert(boot_err == TOX_ERR_BOOTSTRAP_OK);
    tox_bootstrap(tox1, "tox.initramfs.io", 33445, key2, &boot_err);
    ck_assert(boot_err == TOX_ERR_BOOTSTRAP_OK);
    tox_bootstrap(tox2, "tox.initramfs.io", 33445, key2, &boot_err);
    ck_assert(boot_err == TOX_ERR_BOOTSTRAP_OK);

    printf("Waiting for connection");

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    const Tox_Connection status1 = tox_self_get_connection_status(tox1);
    const Tox_Connection status2 = tox_self_get_connection_status(tox2);
    ck_assert_msg(status1 == TOX_CONNECTION_UDP,
                  "expected connection status for tox1 to be UDP, but got %d",
                  status1);
    ck_assert_msg(status2 == TOX_CONNECTION_UDP,
                  "expected connection status for tox2 to be UDP, but got %d",
                  status2);
    printf("Connection for tox1 (UDP): %d\n", status1);
    printf("Connection for tox2 (UDP): %d\n", status2);

    TOX_ERR_FRIEND_ADD friend_add_err;
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];

    tox_self_get_public_key(tox1, pk);
    tox_friend_add_norequest(tox2, pk, &friend_add_err);
    ck_assert(friend_add_err == TOX_ERR_FRIEND_ADD_OK);

    tox_self_get_public_key(tox2, pk);
    tox_friend_add_norequest(tox1, pk, &friend_add_err);
    ck_assert(friend_add_err == TOX_ERR_FRIEND_ADD_OK);

    while (tox_friend_get_connection_status(tox1, 0, nullptr) == TOX_CONNECTION_NONE ||
            tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_NONE) {
        printf(".");
        fflush(stdout);

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        c_sleep(ITERATION_INTERVAL);
    }

    const Tox_Connection friend_status1 = tox_friend_get_connection_status(tox1, 0, nullptr);
    const Tox_Connection friend_status2 = tox_friend_get_connection_status(tox2, 0, nullptr);
    ck_assert_msg(status1 == TOX_CONNECTION_UDP,
                  "expected connection status for tox1->tox2 to be UDP, but got %d",
                  friend_status1);
    ck_assert_msg(status2 == TOX_CONNECTION_UDP,
                  "expected connection status for tox2->tox1 to be UDP, but got %d",
                  friend_status2);
    printf("Connection for tox1->tox2 (UDP): %d\n", friend_status1);
    printf("Connection for tox2->tox1 (UDP): %d\n", friend_status2);

    tox_kill(tox2);
    tox_kill(tox1);
    return 0;
}
