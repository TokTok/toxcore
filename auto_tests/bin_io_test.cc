#include "../toxcore/bin_io.h"

#include "tut_test.h"

struct context {
    unsigned int seed;
    Bin_W *w;

    context()
        : seed(rand())
        , w(bin_w_new())
    { }

    ~context()
    {
        bin_w_free(w);
    }

    void reset_rand()
    {
      srand(seed);
    }

    static uint64_t urand()
    {
      uint32_t r1 = rand();
      uint32_t r2 = rand();
      return uint64_t(r1) << 32 | r2;
    }

    static void write_random_sequence(Bin_W *w, size_t length)
    {
      for (size_t i = 0; i < length; i++) {
        switch (urand() % 4) {
        case 0:
          bin_w_u08(w, urand());
          break;
        case 1:
          bin_w_u16(w, urand());
          break;
        case 2:
          bin_w_u32(w, urand());
          break;
        case 3:
          bin_w_u64(w, urand());
          break;
        }
      }
    }
};

TEST_GROUP("bin_io");

namespace tut
{
TEST(1)
{
    ensure_equals("empty should be zero size", bin_w_size(w), 0);
}

TEST(2)
{
    ensure_equals("get() should be repeatable on empty writers", bin_w_get(w), bin_w_get(w));
    write_random_sequence(w, 1);
    ensure_equals("get() should be repeatable after writing", bin_w_get(w), bin_w_get(w));
}

TEST(3)
{
    write_random_sequence(w, 1);
    ensure("size should be non-zero after writing", bin_w_size(w) != 0);
}

TEST(4)
{
    write_random_sequence(w, 100);
    size_t sz1 = bin_w_size(w);
    reset_rand();
    write_random_sequence(w, 100);
    size_t sz2 = bin_w_size(w);
    ensure_equals("writing the same thing twice should not introduce padding", sz2, sz1 * 2);
}

TEST(5)
{
    uint8_t expected = urand();
    bin_w_u08(w, expected);

    Bin_R *r = bin_r_new(bin_w_get(), bin_w_size());

    uint8_t actual;
    ensure(bin_r_u08(r, &actual));
    ensure_equals(actual, expected);

    bin_r_free(r);
}

TEST(6)
{
    uint16_t expected = urand();
    bin_w_u16(w, expected);

    Bin_R *r = bin_r_new(bin_w_get(), bin_w_size());

    uint16_t actual;
    ensure(bin_r_u16(r, &actual));
    ensure_equals(actual, expected);

    bin_r_free(r);
}

TEST(7)
{
    uint32_t expected = urand();
    bin_w_u32(w, expected);

    Bin_R *r = bin_r_new(bin_w_get(), bin_w_size());

    uint32_t actual;
    ensure(bin_r_u32(r, &actual));
    ensure_equals(actual, expected);

    bin_r_free(r);
}

TEST(8)
{
    uint64_t expected = urand();
    bin_w_u64(w, expected);

    Bin_R *r = bin_r_new(bin_w_get(), bin_w_size());

    uint64_t actual;
    ensure(bin_r_u64(r, &actual));
    ensure_equals(actual, expected);

    bin_r_free(r);
}
}

TEST_MAIN
