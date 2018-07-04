#include "../toxcore/tox.h"

#include "check_compat.h"
#include <stdio.h>
#include <stdlib.h>


#define check_good_if(argument)                            \
    do_check(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH,     \
           major, minor, patch,                                         \
           TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch), argument)

#define FUZZ_VERSION \
    for(int major=0; major < 10; major++) { \
        for(int minor=0; minor < 10; minor++) { \
            for(int patch = 0; patch < 10; patch++) {
#define END_FUZZ }}}

static void do_check(int lib_major, int lib_minor, int lib_patch,
                     int cli_major, int cli_minor, int cli_patch,
                     bool actual, bool expected)
{
    ck_assert_msg(actual==expected, "Client version %d.%d.%d is %s compatible with library version %d.%d.%d, but it should %s be.\n",
           cli_major, cli_minor, cli_patch, actual ? "" : "not",
           lib_major, lib_minor, lib_patch, expected ? "" : "not");
}

#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH


int main(void)
{
#define TOX_VERSION_MAJOR 0
#define TOX_VERSION_MINOR 0
#define TOX_VERSION_PATCH 4
    FUZZ_VERSION
    check_good_if(major == 0 && minor == 0 && patch == 4);
    END_FUZZ
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 0
#define TOX_VERSION_MINOR 1
#define TOX_VERSION_PATCH 4
    FUZZ_VERSION
    check_good_if(major == 0 && minor == 1 && patch <= 4);
    END_FUZZ
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 1
#define TOX_VERSION_MINOR 0
#define TOX_VERSION_PATCH 4
    FUZZ_VERSION
    check_good_if(major == 1 && (minor > 0 || (minor == 0 && patch >= 4)));
    END_FUZZ
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH

#define TOX_VERSION_MAJOR 1
#define TOX_VERSION_MINOR 1
#define TOX_VERSION_PATCH 4
    FUZZ_VERSION
    check_good_if(major == 1 && (minor > 1 || (minor == 1 && patch >= 4)));
    END_FUZZ
#undef TOX_VERSION_MAJOR
#undef TOX_VERSION_MINOR
#undef TOX_VERSION_PATCH
}
