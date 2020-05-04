#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
} State;

#include "run_auto_test.h"

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    (void)run_auto_test;

    State state1 = { 0, 0 };
    Tox *tox1 = tox_new_log_lan(nullptr, nullptr, &state1.index, /* lan_discovery */true);
    set_mono_time_callback(tox1, &state1);
    State state2 = { 0, 0 };
    Tox *tox2 = tox_new_log_lan(nullptr, nullptr, &state2.index, /* lan_discovery */true);
    set_mono_time_callback(tox2, &state2);

    printf("Waiting for LAN discovery. This loop will attempt to run until successful.");

    do {
        fputc('.', stdout);

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        state1.clock += tox_iteration_interval(tox1);
        state2.clock += tox_iteration_interval(tox2);

        c_sleep(1);
    } while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE);

    printf(" %d <-> %d\n",
           tox_self_get_connection_status(tox1),
           tox_self_get_connection_status(tox2));

    tox_kill(tox2);
    tox_kill(tox1);
    return 0;
}
