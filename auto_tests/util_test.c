#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/util.h"

#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "helpers.h"

START_TEST(test_byteswap_u32)
{
    ck_assert_msg(byteswap_u32(0xdeadbeef) == 0xefbeadde, "byteswap_u32 should swap endianness reliably");
}
END_TEST

static Suite *crypto_suite(void)
{
    Suite *s = suite_create("Util");

    DEFTESTCASE(byteswap_u32);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *crypto = crypto_suite();
    SRunner *test_runner = srunner_create(crypto);
    int number_failed = 0;

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
