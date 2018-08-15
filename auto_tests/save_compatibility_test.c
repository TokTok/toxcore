//Tests to make sure new save code is compatible with old save files

#include "../toxcore/tox.h"
#include "check_compat.h"

#include <string.h>

#define SAVE_FILE "../data/save.tox"

// Information from the save file
#define NAME "name"
#define NAME_SIZE strlen(NAME)
#define STATUS_MESSAGE "Hello World"
#define STATUS_MESSAGE_SIZE strlen(STATUS_MESSAGE)
#define NUM_FRIENDS 1

size_t get_file_size(void)
{
    size_t size = 0;

    FILE *fp = fopen(SAVE_FILE, "r");

    if (fp == NULL) {
        return size;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);

    return size;
}

static uint8_t *read_save(size_t *length)
{
    const size_t size = get_file_size();

    if (size == 0) {
        return NULL;
    }

    FILE *fp = fopen(SAVE_FILE, "r");

    if (!fp) {
        return NULL;
    }

    uint8_t *data = malloc(size);

    if (!data) {
        fclose(fp);
        return NULL;
    }

    if (fread(data, size, 1, fp) != 1) {
        free(data);
        fclose(fp);
        return NULL;
    }

    *length = size;

    return data;
}

static void test_save_compatibility(void)
{
    struct Tox_Options options;

    memset(&options, 0, sizeof(struct Tox_Options));
    tox_options_default(&options);

    size_t size = 0;
    uint8_t *save_data = read_save(&size);
    ck_assert_msg(save_data != NULL, "Error while reading save file.");

    options.savedata_data = save_data;
    options.savedata_length = size;
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

    Tox *tox = tox_new(&options, nullptr);

    free(save_data);

    size_t name_size = tox_self_get_name_size(tox);
    ck_assert_msg(name_size == NAME_SIZE, "Name sizes do not match expected %zu got %zu", NAME_SIZE, name_size);

    uint8_t name[name_size];
    tox_self_get_name(tox, name);
    ck_assert_msg(strncmp((char *)name, NAME, name_size) == 0, "Names do not match, expected %s got %s.", NAME, name);

    size_t status_message_size = tox_self_get_status_message_size(tox);
    ck_assert_msg(status_message_size == STATUS_MESSAGE_SIZE, "Status message sizes do not match, expected %zu got %zu.",
                  STATUS_MESSAGE_SIZE, status_message_size);

    uint8_t status_message[status_message_size];
    tox_self_get_status_message(tox, status_message);
    ck_assert_msg(strncmp((char *)status_message, STATUS_MESSAGE, status_message_size) == 0,
                  "Status messages do not match, expeceted %s got %s.",
                  STATUS_MESSAGE, status_message);

    size_t num_friends = tox_self_get_friend_list_size(tox);
    ck_assert_msg(num_friends == NUM_FRIENDS, "Number of friends do not match, expected %d got %zu.", NUM_FRIENDS,
                  num_friends);

    tox_kill(tox);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_save_compatibility();

    return 0;
}
