#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"

#include "auto_test_support.h"

const Run_Auto_Options default_run_auto_options = { GRAPH_COMPLETE, 0, 0, nullptr };

bool all_connected(uint32_t tox_count, AutoTox *autotoxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (tox_self_get_connection_status(autotoxes[i].tox) == TOX_CONNECTION_NONE) {
            return false;
        }
    }

    return true;
}

bool all_friends_connected(uint32_t tox_count, AutoTox *autotoxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        const size_t friend_count = tox_self_get_friend_list_size(autotoxes[i].tox);

        for (size_t j = 0; j < friend_count; j++) {
            if (tox_friend_get_connection_status(autotoxes[i].tox, j, nullptr) == TOX_CONNECTION_NONE) {
                return false;
            }
        }
    }

    return true;
}

void iterate_all_wait(uint32_t tox_count, AutoTox *autotoxes, uint32_t wait)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (!autotoxes[i].alive) {
            continue;
        }

        tox_iterate(autotoxes[i].tox, &autotoxes[i]);
        autotoxes[i].clock += wait;
    }

    /* Also actually sleep a little, to allow for local network processing */
    c_sleep(5);
}

static uint64_t get_state_clock_callback(Mono_Time *mono_time, void *user_data)
{
    const uint64_t *clock = (const uint64_t *)user_data;
    return *clock;
}

void set_mono_time_callback(AutoTox *tox)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    Mono_Time *mono_time = ((Messenger *)tox->tox)->mono_time;

    tox->clock = current_time_monotonic(mono_time);
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, &tox->clock);
}

void save(AutoTox *autotox)
{
    fprintf(stderr, "Saving #%u\n", autotox->index);

    if (autotox->save_state != nullptr) {
        free(autotox->save_state);
    }

    autotox->save_size = tox_get_savedata_size(autotox->tox);
    ck_assert_msg(autotox->save_size > 0, "save is invalid size %u", (unsigned)autotox->save_size);
    autotox->save_state = (uint8_t *)malloc(autotox->save_size);
    ck_assert_msg(autotox->save_state != nullptr, "malloc failed");
    tox_get_savedata(autotox->tox, autotox->save_state);
}

void kill(AutoTox *autotox)
{
    fprintf(stderr, "Killing #%u\n", autotox->index);
    autotox->alive = false;
    tox_kill(autotox->tox);
}

void reload(AutoTox *autotox)
{
    if (autotox->alive) {
        autotox->alive = false;
        tox_kill(autotox->tox);
    }

    fprintf(stderr, "Reloading #%u\n", autotox->index);
    ck_assert(autotox->save_state != nullptr);

    struct Tox_Options *const options = tox_options_new(nullptr);
    ck_assert(options != nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, autotox->save_state, autotox->save_size);
    autotox->tox = tox_new_log(options, nullptr, &autotox->index);
    ck_assert(autotox->tox != nullptr);
    tox_options_free(options);

    set_mono_time_callback(autotox);
    autotox->alive = true;
}

static void initialise_autotox(AutoTox *autotox, uint32_t index, uint32_t state_size, const Run_Auto_Options *options)
{
    struct Tox_Options *opts = tox_options_new(nullptr);
    ck_assert(opts != nullptr);

    if (index < options->tcp_relays) {
        printf("tox #%u is TCP relay\n", index);
        tox_options_set_tcp_port(opts, options->tcp_first_port + index);
    }

    autotox->index = index;
    autotox->tox = tox_new_log(opts, nullptr, &autotox->index);
    ck_assert_msg(autotox->tox != nullptr, "failed to create tox instance #%u", index);

    tox_options_free(opts);

    set_mono_time_callback(autotox);

    autotox->alive = true;
    autotox->save_state = nullptr;

    if (state_size > 0) {
        autotox->state = calloc(1, state_size);
        ck_assert(autotox->state != nullptr);
        ck_assert_msg(autotox->state != nullptr, "failed to allocate state");
    } else {
        autotox->state = nullptr;
    }

    if (options->init_autotox != nullptr) {
        options->init_autotox(autotox, index);
    }
}

static void autotox_add_friend(AutoTox *autotoxes, uint32_t adding, uint32_t added)
{
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(autotoxes[added].tox, public_key);
    Tox_Err_Friend_Add err;
    tox_friend_add_norequest(autotoxes[adding].tox, public_key, &err);
    ck_assert(err == TOX_ERR_FRIEND_ADD_OK);
}

void run_auto_test(uint32_t tox_count, void test(AutoTox *autotoxes),
                   uint32_t state_size, const Run_Auto_Options *options)
{
    printf("initialising %u toxes\n", tox_count);

    AutoTox *autotoxes = (AutoTox *)calloc(tox_count, sizeof(AutoTox));

    ck_assert(autotoxes != nullptr);

    for (uint32_t i = 0; i < tox_count; i++) {
        initialise_autotox(&autotoxes[i], i, state_size, options);
    }

    if (options->graph == GRAPH_LINEAR) {
        printf("toxes #%u-#%u each add adjacent toxes as friends\n", options->tcp_relays, tox_count - 1);

        for (uint32_t i = options->tcp_relays; i < tox_count; i++) {
            for (uint32_t j = i - 1; j != i + 3; j += 2) {
                if (j >= tox_count || j < options->tcp_relays) {
                    continue;
                }

                autotox_add_friend(autotoxes, i, j);
            }
        }
    } else if (options->graph == GRAPH_COMPLETE) {
        printf("toxes #%u-#%u add each other as friends\n", options->tcp_relays, tox_count - 1);

        for (uint32_t i = options->tcp_relays; i < tox_count; i++) {
            for (uint32_t j = options->tcp_relays; j < tox_count; j++) {
                if (i != j) {
                    autotox_add_friend(autotoxes, i, j);
                }
            }
        }
    } else {
        ck_abort_msg("Unknown graph type");
    }

    if (options->tcp_relays) {
        printf("adding tcp relays\n");

        for (uint32_t i = 0; i < tox_count; i++) {
            const uint32_t relay = i % options->tcp_relays;
            uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_dht_id(autotoxes[relay].tox, dht_key);
            Tox_Err_Bootstrap error = TOX_ERR_BOOTSTRAP_OK;
            ck_assert_msg(tox_add_tcp_relay(autotoxes[i].tox, "localhost", options->tcp_first_port + relay, dht_key, &error),
                          "add relay error, %u, %d", i, error);
        }
    }

    printf("bootstrapping all toxes off tox 0\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(autotoxes[0].tox, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(autotoxes[0].tox, nullptr);

    for (uint32_t i = 1; i < tox_count; i++) {
        Tox_Err_Bootstrap err;
        tox_bootstrap(autotoxes[i].tox, "localhost", dht_port, dht_key, &err);
        ck_assert(err == TOX_ERR_BOOTSTRAP_OK);
    }

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_connected(tox_count, autotoxes));

    printf("toxes are online\n");

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_friends_connected(tox_count, autotoxes));

    printf("tox clients connected\n");

    test(autotoxes);

    for (uint32_t i = 0; i < tox_count; i++) {
        tox_kill(autotoxes[i].tox);

        if (autotoxes[i].state != nullptr) {
            free(autotoxes[i].state);
        }

        if (autotoxes[i].save_state != nullptr) {
            free(autotoxes[i].save_state);
        }
    }

    free(autotoxes);
}
