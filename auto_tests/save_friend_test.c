/* Auto Tests: Save and load friends.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static void set_random(Tox *m, bool (*function)(Tox *, const uint8_t *, size_t, TOX_ERR_SET_INFO *), size_t length)
{
    uint8_t text[length];
    uint32_t i;

    for (i = 0; i < length; ++i) {
        text[i] = ('A' + (rand() % 26));
    }
    text[length - 1] = 0;

    function(m, text, sizeof(text), 0);
    return;
}

static uint8_t status_to_compare[TOX_MAX_STATUS_MESSAGE_LENGTH] = { 0 };
static uint8_t name_to_compare[TOX_MAX_NAME_LENGTH] = { 0 };

void namechange_callback(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data)
{
    memcpy(name_to_compare, name, length);
}

void statuschange_callback(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, void *user_data)
{
    memcpy(status_to_compare, message, length);
}

int main(int argc, char *argv[]) 
{
    Tox *tox1 = tox_new(tox_options_new(NULL), 0);
    Tox *tox2 = tox_new(tox_options_new(NULL), 0);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox1, address);
    tox_friend_add_norequest(tox2, address, NULL);
    tox_self_get_address(tox2, address);
    tox_friend_add_norequest(tox1, address, NULL);

    uint8_t reference_name[TOX_MAX_NAME_LENGTH] = { 0 };
    uint8_t reference_status[TOX_MAX_STATUS_MESSAGE_LENGTH] = { 0 };

    set_random(tox1, tox_self_set_name, TOX_MAX_NAME_LENGTH);
    set_random(tox2, tox_self_set_name, TOX_MAX_NAME_LENGTH);
    set_random(tox1, tox_self_set_status_message, TOX_MAX_STATUS_MESSAGE_LENGTH);
    set_random(tox2, tox_self_set_status_message, TOX_MAX_STATUS_MESSAGE_LENGTH);

    tox_self_get_name(tox2, reference_name);
    tox_self_get_status_message(tox2, reference_status);

    tox_callback_friend_name(tox1, namechange_callback);
    tox_callback_friend_status_message(tox1, statuschange_callback);

    const uint32_t iteration_interval = tox_iteration_interval(tox1);

    while (true) {
        if (tox_self_get_connection_status(tox1) &&
                tox_self_get_connection_status(tox2) &&
                tox_friend_get_connection_status(tox1, 0, 0) == TOX_CONNECTION_UDP) {
            printf("Connected.\n");
            break;
        }
        tox_iterate(tox1, NULL);
        tox_iterate(tox2, NULL);

        c_sleep(iteration_interval);
    }

    while (true) {
        if (memcmp(reference_name, name_to_compare, TOX_MAX_NAME_LENGTH) == 0 &&
                memcmp(reference_status, status_to_compare, TOX_MAX_STATUS_MESSAGE_LENGTH) == 0) {
            printf("Exchanged names and status messages.\n");
            break;
        }
        tox_iterate(tox1, NULL);
        tox_iterate(tox2, NULL);

        c_sleep(iteration_interval);
    }

    size_t save_size = tox_get_savedata_size(tox1);
    uint8_t data[save_size];
    tox_get_savedata(tox1, data);

    struct Tox_Options options;
    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.savedata_data = data;
    options.savedata_length = save_size;

    Tox *tox_to_compare = tox_new(&options, 0);

    tox_friend_get_status_message(tox_to_compare, 0, status_to_compare, 0);
    tox_friend_get_name(tox_to_compare, 0, name_to_compare, 0);

    assert(memcmp(reference_name, name_to_compare, TOX_MAX_NAME_LENGTH) == 0);
    assert(memcmp(reference_status, status_to_compare, TOX_MAX_STATUS_MESSAGE_LENGTH) == 0);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox_to_compare);
}
