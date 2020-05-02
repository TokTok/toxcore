/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020 Tox project.
 */
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// The actual alloc functions. This only works on glibc.
void *__libc_malloc(size_t size);
void *__libc_calloc(size_t nmemb, size_t size);
void *__libc_realloc(void *ptr, size_t size);
void __libc_free(void *ptr);

typedef struct Oomer_Config {
  /**
   * OOMER_MAX_ALLOCS: the number of allocations to pass through until oomer
   * starts running one of its strategies.
   */
  long max_allocs;
  /**
   * OOMER_DONE_FILE: the file to write when all allocations have been allowed.
   * This means any further tests are pointless because oomer will always allow
   * all of them.
   */
  const char *done_file;
  /**
   * OOMER_FLAKY: after max_allocs, start rejecting random allocations with the
   * specified rate (between 0 and 1).
   */
  double flaky;
  /**
   * Random seed for oomer's RNG. Not configurable through env vars for now.
   */
  uint32_t seed;
  /**
   * OOMER_ONE_SHOT: reject only a single allocation after max_allocs
   * allocations. All allocations after the one rejected one are passed through.
   */
  bool one_shot;
  /**
   * OOMER_TRAP_ON_FAIL: cause a SIGTRAP when rejecting an allocation. Useful
   * when running in a debugger to have a breakpoint at the rejected allocation.
   */
  bool trap_on_fail;
} Oomer_Config;

static Oomer_Config config = { -1, 0, 0, 123456789, false, false };

uint32_t rand_u32(void) {
  config.seed = (1664525 * config.seed + 1013904223);
  return config.seed;
}

static void init_oomer(void) {
  const char *env_max_allocs = getenv("OOMER_MAX_ALLOCS");
  if (env_max_allocs != NULL) {
    char *end;
    config.max_allocs = strtol(env_max_allocs, &end, 10);
    if (end != env_max_allocs + strlen(env_max_allocs)) {
      fprintf(stderr, "invalid value for OOMER_MAX_ALLOCS: %s\n", env_max_allocs);
      abort();
    }
  }

  const char *env_flaky = getenv("OOMER_FLAKY");
  if (env_flaky != NULL) {
    char *end;
    config.flaky = strtod(env_flaky, &end);
    if (end != env_flaky + strlen(env_flaky) || config.flaky < 0 || config.flaky > 1) {
      fprintf(stderr, "invalid value for OOMER_FLAKY: %s\n", env_flaky);
      abort();
    }
  }

  const char *env_one_shot = getenv("OOMER_ONE_SHOT");
  config.one_shot = env_one_shot != NULL && *env_one_shot == '1';

  const char *env_trap_on_fail = getenv("OOMER_TRAP_ON_FAIL");
  config.trap_on_fail = env_trap_on_fail != NULL && *env_trap_on_fail == '1';

  config.done_file = getenv("OOMER_DONE_FILE");

  fprintf(stderr, "oomer: done_file    = %s\n",
          config.done_file != NULL ? config.done_file : "<unset>");
  fprintf(stderr, "oomer: flaky        = %f\n", config.flaky);
  fprintf(stderr, "oomer: seed         = %d\n", config.seed);
  fprintf(stderr, "oomer: one_shot     = %s\n", config.one_shot ? "true" : "false");
  fprintf(stderr, "oomer: trap_on_fail = %s\n", config.trap_on_fail ? "true" : "false");

  if (!config.trap_on_fail) {
      alarm(5);
  }
}

static __attribute__((__destructor__)) void deinit_oomer(void) {
  fprintf(stderr, "deinit_oomer: max_allocs = %ld\n", config.max_allocs);
  if (config.done_file != NULL && config.max_allocs > 0) {
    // Touch the done_file to signal to run_oomer that we've rejected at least
    // one malloc call.
    close(creat(config.done_file, 0644));
  }
}

static bool can_alloc(void) {
  if (config.max_allocs == -1) {
    init_oomer();
  }

  if (config.max_allocs == 0) {
    if (config.one_shot) {
      // Allow all mallocs except this one.
      config.max_allocs = -2;
    }
    if (config.trap_on_fail) {
      __asm__("int $3");
    }
    if (config.flaky > 0) {
      return rand_u32() > config.flaky * UINT32_MAX;
    }
    return false;
  }

  --config.max_allocs;
  return true;
}

void *malloc(size_t size) {
  if (can_alloc()) {
    return __libc_malloc(size);
  }
  return NULL;
}

void *calloc(size_t nmemb, size_t size) {
  if (can_alloc()) {
    return __libc_calloc(nmemb, size);
  }
  return NULL;
}

void *realloc(void *ptr, size_t size) {
  if (can_alloc()) {
    return __libc_realloc(ptr, size);
  }
  return NULL;
}

void free(void *ptr) {
  __libc_free(ptr);
}
