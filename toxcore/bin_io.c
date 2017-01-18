#include "bin_io.h"

#include <assert.h>

/*****************************************************************************
 *
 * :: Writer.
 *
 *****************************************************************************/

struct Bin_W *bin_w_new(void)
{
    assert(!"unimplemented");
    return NULL;
}

void bin_w_free(struct Bin_W *w)
{
    assert(!"unimplemented");
}

uint8_t *bin_w_get(const struct Bin_W *w)
{
    assert(!"unimplemented");
    return NULL;
}

size_t bin_w_size(const struct Bin_W *w)
{
    assert(!"unimplemented");
    return 0;
}

size_t bin_w_copy(const struct Bin_W *w, size_t offset, uint8_t *data, size_t length)
{
    assert(!"unimplemented");
    return 0;
}

bool bin_w_u08(struct Bin_W *w, uint8_t v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_w_u16(struct Bin_W *w, uint16_t v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_w_u32(struct Bin_W *w, uint32_t v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_w_u64(struct Bin_W *w, uint64_t v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_w_arr(struct Bin_W *w, uint8_t *data, size_t length)
{
    assert(!"unimplemented");
    return false;
}

/*****************************************************************************
 *
 * :: Reader.
 *
 *****************************************************************************/

struct Bin_R *bin_r_new(uint8_t *data, size_t length)
{
    assert(!"unimplemented");
    return NULL;
}

void bin_r_free(struct Bin_R *r)
{
    assert(!"unimplemented");
}

bool bin_r_u08(struct Bin_R *r, uint8_t *v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_r_u16(struct Bin_R *r, uint16_t *v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_r_u32(struct Bin_R *r, uint32_t *v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_r_u64(struct Bin_R *r, uint64_t *v)
{
    assert(!"unimplemented");
    return false;
}

bool bin_r_arr(struct Bin_R *r, uint8_t *data, size_t length)
{
    assert(!"unimplemented");
    return false;
}
