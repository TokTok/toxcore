#include "../toxcore/tox.h"

#include "../toxcore/ccompat.h"
#include "../toxcore/env.h"

#include <assert.h>

int main(void)
{
    tox_kill(tox_new(nullptr, nullptr));
    assert(env_malloc_check());
    return 0;
}
