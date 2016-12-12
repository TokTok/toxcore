/* Auto Tests: Save and load friends.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../toxcore/tox.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static void random_name(Tox *m)
{
    uint8_t name[TOX_MAX_NAME_LENGTH];
    uint32_t i;

    for (i = 0; i < TOX_MAX_NAME_LENGTH; ++i) {
        name[i] = ('A' + (rand() % 26));
    }
    name[TOX_MAX_NAME_LENGTH - 1] = 0;

    tox_self_set_name(m, name, sizeof(name), 0);
    return;
}

static void random_status(Tox *m)
{
    uint8_t status[TOX_MAX_STATUS_MESSAGE_LENGTH];
    uint32_t i;

    for (i = 0; i < TOX_MAX_STATUS_MESSAGE_LENGTH; ++i) {
        status[i] = ('A' + (rand() % 26));
    }
    status[TOX_MAX_STATUS_MESSAGE_LENGTH - 1] = 0;

    tox_self_set_status_message(m, status, sizeof(status), 0);
    return;
}

#define NUM_TOXES 2

int main(int argc, char *argv[]) 
{
    Tox *tox[NUM_TOXES];

    uint8_t i;
    for (i = 0; i < NUM_TOXES; ++i) {
        tox[i] = tox_new(tox_options_new(NULL), 0);
    }

    // This won't work if you want to test with more Tox instances.
    for (i = 0; i < NUM_TOXES; ++i) {
        uint8_t address[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox[i], address);
        tox_friend_add_norequest(tox[(i + 1) % NUM_TOXES], address, NULL);
    }


    uint8_t name[NUM_TOXES][TOX_MAX_NAME_LENGTH] = { { 0 } };
    uint8_t status[NUM_TOXES][TOX_MAX_STATUS_MESSAGE_LENGTH] = { { 0 } };

    for (i = 0; i < NUM_TOXES; ++i) {
        random_name(tox[i]);
        tox_self_get_name(tox[i], name[i]);

        random_status(tox[i]);
        tox_self_get_status_message(tox[i], status[i]);
    }
    
    const uint32_t iteration_interval = tox_iteration_interval(tox[0]);

    while (tox_friend_get_connection_status(tox[0], 0, NULL) != TOX_CONNECTION_UDP) {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(tox[i], NULL);
        }

        c_sleep(iteration_interval);
    }

    uint8_t status_to_compare[TOX_MAX_STATUS_MESSAGE_LENGTH] = { 0 };
    uint8_t name_to_compare[TOX_MAX_NAME_LENGTH] = { 0 };

    size_t status_length = tox_friend_get_status_message_size(tox[0], 0, 0);
    size_t name_length   = tox_friend_get_name_size(tox[0], 0, 0);

    tox_friend_get_status_message(tox[0], 0, status_to_compare, 0);
    tox_friend_get_name(tox[0], 0, name_to_compare, 0);

    while (memcmp(status[1], status_to_compare, status_length) != 0 &&
           memcmp(name[1],   name_to_compare,   name_length)   != 0) 
    {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(tox[i], NULL);
        }

        status_length = tox_friend_get_status_message_size(tox[0], 0, 0);
        name_length   = tox_friend_get_name_size(tox[0], 0, 0);

        tox_friend_get_status_message(tox[0], 0, status_to_compare, 0);
        tox_friend_get_name(tox[0], 0, name_to_compare, 0);

        c_sleep(iteration_interval);
    }

    size_t save_size = tox_get_savedata_size(tox[0]);
    uint8_t data[save_size];
    tox_get_savedata(tox[0], data);

    struct Tox_Options options;
    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.savedata_data = data;
    options.savedata_length = save_size;

    assert(memcmp(name[1], name_to_compare, name_length) == 0);
    assert(memcmp(status[1], status_to_compare, status_length) == 0);

    printf("1st status_length: %lu\n", status_length);
    printf("1st name_length: %lu\n", name_length);

    Tox *tox_to_compare = tox_new(&options, 0);

    status_length = tox_friend_get_status_message_size(tox[0], 0, 0);
    name_length   = tox_friend_get_name_size(tox[0], 0, 0);

    tox_friend_get_status_message(tox_to_compare, 0, status_to_compare, 0);
    tox_friend_get_name(tox_to_compare, 0, name_to_compare, 0);

    printf("2nd status_length: %lu\n", status_length);
    printf("2nd name_length: %lu\n", name_length);

    assert(memcmp(name[1], name_to_compare, name_length) == 0);
    assert(memcmp(status[1], status_to_compare, status_length) == 0);

    for (i = 0; i < NUM_TOXES; ++i) {
        tox_kill(tox[i]);
    }
    tox_kill(tox_to_compare);
}
