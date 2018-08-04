#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"

#define SAVE_FILE "save.tox"
#define STATUS_MESSAGE "Hello World"

static const char *bootstrap_ip = "185.14.30.213";
static const char *bootstrap_address = "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B";
static const uint16_t udp_port = 443;

static bool write_save(const uint8_t *data, size_t length)
{
    FILE *fp = fopen(SAVE_FILE, "w");

    if (!fp) {
        return false;
    }

    if (fwrite(data, length, 1, fp) != 1) {
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: ./save-generator <name> <friend id>\n");
        return -1;
    }

    Tox *tox = tox_new(nullptr, nullptr);

    if (!tox) {
        printf("Failed to create tox.\n");
        return -1;
    }

    uint8_t *key = hex_string_to_bin(bootstrap_address);

    if (!key) {
        printf("Could not allocate memory for tox address\n");
        return -1;
    }

    tox_bootstrap(tox, bootstrap_ip, udp_port, key, nullptr);
    free(key);

    while (true) {
        tox_iterate(tox, nullptr);

        if (tox_self_get_connection_status(tox) == TOX_CONNECTION_UDP) {
            printf("Connected to the tox network.\n");
            break;
        }

        c_sleep(tox_iteration_interval(tox));
    }

    const uint8_t *name = (uint8_t *)argv[1];
    bool ret = tox_self_set_name(tox, name, strlen((char *)name), nullptr);

    if (!ret) {
        printf("Failed to set name.\n");
    }

    ret = tox_self_set_status_message(tox, (const uint8_t *)STATUS_MESSAGE, strlen(STATUS_MESSAGE), nullptr);

    if (!ret) {
        printf("Failed to set status.\n");
    }

    uint8_t *address = hex_string_to_bin(argv[2]);
    const char *msg = "Add me.";
    uint32_t friend_num = tox_friend_add(tox, address, (const uint8_t *)msg, strlen(msg), nullptr);
    free(address);

    if (friend_num == UINT32_MAX) {
        printf("Failed to add friend.\n");
    }

    size_t length = tox_get_savedata_size(tox);
    uint8_t *savedata = (uint8_t *)malloc(length);

    if (!savedata) {
        printf("Could not allocate memory for savedata.\n");
        return -1;
    }

    tox_get_savedata(tox, savedata);

    ret = write_save(savedata, length);
    free(savedata);

    if (!ret) {
        printf("Failed to write save.\n");
        tox_kill(tox);
        return -1;
    }

    printf("Wrote tox save to %s\n", SAVE_FILE);

    uint8_t tox_id[TOX_ADDRESS_SIZE];
    char tox_id_str[TOX_ADDRESS_SIZE * 2];
    tox_self_get_address(tox, tox_id);
    to_hex(tox_id_str, tox_id, TOX_ADDRESS_SIZE);

    char nospam_str[TOX_NOSPAM_SIZE * 2];
    uint32_t nospam = tox_self_get_nospam(tox);
    sprintf(nospam_str, "%08X", nospam);

    printf("INFORMATION\n");
    printf("----------------------------------\n");
    printf("Tox ID: %.*s.\n", (int)TOX_ADDRESS_SIZE * 2, tox_id_str);
    printf("Nospam: %.*s.\n", (int)TOX_NOSPAM_SIZE * 2, nospam_str);
    printf("Name: %s.\n", name);
    printf("Status message: %s.\n", STATUS_MESSAGE);
    printf("Number of friends: %lu.\n", tox_self_get_friend_list_size(tox));
    printf("----------------------------------\n");

    tox_kill(tox);

    return 0;
}
