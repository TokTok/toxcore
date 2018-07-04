/*
 * gcc -O0 -g -DUNIT_TESTING_ENABLED ts_buffer.c a.c -o a.bin
 *
 * cp /cygdrive/c/Users/$USER/Desktop/a.c .
 * cp /cygdrive/c/Users/$USER/Desktop/ts_buffer.c .
 * cp /cygdrive/c/Users/$USER/Desktop/ts_buffer.h .
 * i686-w64-mingw32-gcc -O0 -DUNIT_TESTING_ENABLED -g ts_buffer.c a.c -o a.bin
 */

#include "ts_buffer.h"
#include <stdio.h>

void unit_test();

int main()
{
	unit_test();
    return 0;
}
