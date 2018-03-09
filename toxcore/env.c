#include "env.h"

#include "ccompat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MALLOC_LOG 0
#define STATIC_MEMORY 1

#if STATIC_MEMORY
static char memory[20 * 1024 * 1024];
static char *memory_cur = memory;
static char *memory_end = memory + sizeof memory;
static size_t allocated;
#endif

bool env_malloc_check(void)
{
#if STATIC_MEMORY

    if (allocated != 0) {
        fprintf(stderr, "Memory leak of size %u\n", (unsigned)allocated);
        return false;
    }

#endif
    return true;
}

void *env_malloc(size_t size)
{
#if STATIC_MEMORY
    size_t *ptr = (size_t *)memory_cur;

    if (memory_end - memory_cur < size + sizeof(size_t)) {
        fprintf(stderr, "Out of memory!\n");
        return nullptr;
    }

    *ptr = size;
    memory_cur += size + sizeof(size_t);
#if MALLOC_LOG
    fprintf(stderr, "malloc(size=%u)\n", (unsigned)size);
#endif
    allocated += size;
    return ptr + 1;
#else
    return malloc(size);
#endif
}

void env_free(void *ptr)
{
    if (ptr == nullptr) {
        return;
    }

#if STATIC_MEMORY
    char *cptr = (char *)ptr - sizeof(size_t);
    const size_t size = *(size_t *)cptr;

    if (ptr == memory_cur - size) {
        // We can only free the last allocation.
        memory_cur = cptr;
        fprintf(stderr, "free() success!\n");
    }

#if MALLOC_LOG
    fprintf(stderr, "free(size=%u)\n", (unsigned)size);
#endif
    allocated -= size;
#else
    free(ptr);
#endif
}

void *env_calloc(size_t nmemb, size_t size)
{
#if STATIC_MEMORY
    void *ptr = env_malloc(nmemb * size);

    if (ptr != nullptr) {
        memset(ptr, 0, nmemb * size);
    }

    return ptr;
#else
    return calloc(nmemb, size);
#endif
}

void *env_realloc(void *ptr, size_t size)
{
#if STATIC_MEMORY
    void *new_ptr = env_malloc(size);

    if (new_ptr != nullptr && ptr != nullptr) {
        memcpy(new_ptr, ptr, size);
        env_free(ptr);
    }

    return new_ptr;
#else
    return realloc(ptr, size);
#endif
}
