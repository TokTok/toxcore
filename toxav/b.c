/*
 * gcc -O0 -g -DUNIT_TESTING_ENABLED dummy_ntp.c b.c -o b.bin
 *
 * cp /cygdrive/c/Users/$USER/Desktop/b.c .
 * cp /cygdrive/c/Users/$USER/Desktop/dummy_ntp.c .
 * cp /cygdrive/c/Users/$USER/Desktop/dummy_ntp.h .
 * i686-w64-mingw32-gcc -O0 -DUNIT_TESTING_ENABLED -g dummy_ntp.c b.c -o b.bin
 */

#include "dummy_ntp.h"
#include <stdio.h>

void unit_test();

int main()
{
	unit_test();
    return 0;
}
