#ifndef TOXCORE_ENV_H
#define TOXCORE_ENV_H

#include <stdbool.h>
#include <stddef.h>

bool env_malloc_check(void);

void *env_malloc(size_t size);
void env_free(void *ptr);
void *env_calloc(size_t nmemb, size_t size);
void *env_realloc(void *ptr, size_t size);

#endif /* TOXCORE_ENV_H */
