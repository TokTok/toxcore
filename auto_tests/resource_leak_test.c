#include "helpers.h"

#ifdef _BSD_SOURCE
#include <assert.h>
#include <unistd.h>
#endif

#define ITERATIONS 20000

int main(void)
{
    int i;

    puts("Warming up: creating/deleting 10 tox instances");

    // Warm-up.
    for (i = 0; i < 10; i++) {
        Tox *tox = tox_new(0, 0);
        tox_iterate(tox, NULL);
        tox_kill(tox);
    }

#if _BSD_SOURCE
    // Low water mark.
    char *hwm = NULL;
#endif
    printf("Creating/deleting %d tox instances\n", ITERATIONS);

    for (i = 0; i < ITERATIONS; i++) {
        Tox *tox = tox_new(0, 0);
        tox_iterate(tox, NULL);
        tox_kill(tox);
#if _BSD_SOURCE
        char *next_hwm = (char *)sbrk(0);

        if (!hwm) {
            hwm = next_hwm;
        } else {
            assert(hwm == next_hwm);
        }

#endif
    }

    puts("Success: no resource leaks detected");

    return 0;
}
