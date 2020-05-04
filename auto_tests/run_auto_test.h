#ifndef RUN_AUTO_TEST_H
#define RUN_AUTO_TEST_H

#include <stdlib.h> // calloc, free

#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"
#include "check_compat.h"

typedef struct AutoTox {
  Tox *tox;

  uint32_t index;
  uint64_t clock;

  size_t save_size;
  uint8_t *save_state;
  bool alive;

  void *state;
} AutoTox;

bool all_connected(uint32_t tox_count, AutoTox *toxes);

bool all_friends_connected(uint32_t tox_count, AutoTox *toxes);

void iterate_all_wait(uint32_t tox_count, AutoTox *toxes, uint32_t wait);

bool init_null_state(void **state);

void free_null_state(void *state);

void save(AutoTox *autotox);
void kill(AutoTox *autotox);
void reload(AutoTox *autotox);

void set_mono_time_callback(AutoTox *tox);

typedef enum Graph_Type { GRAPH_COMPLETE = 0, GRAPH_LINEAR } Graph_Type;

typedef struct Run_Auto_Options {
  Graph_Type graph;
  uint32_t tcp_relays;
  uint32_t tcp_first_port;

  void (*init_autotox)(AutoTox *autotox, uint32_t n);
} Run_Auto_Options;

const Run_Auto_Options default_run_auto_options;

void run_auto_test(uint32_t tox_count, void test(AutoTox *toxes),
                   uint32_t state_size, const Run_Auto_Options *options);

#endif
