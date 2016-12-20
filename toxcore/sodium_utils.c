/*
 * ISC License
 *
 * Copyright (c) 2013-2016
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include "sodium_utils.h"
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif

#ifdef VANILLA_NACL

void sodium_memzero(void *const pnt, const size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#elif defined(HAVE_MEMSET_S)

    if (len > 0U && memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        abort(); /* LCOV_EXCL_LINE */
    }

#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
#else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }

#endif
}

int32_t sodium_memcmp(const void *const b1_, const void *const b2_, size_t len)
{
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;

    size_t i;
    unsigned char d = (unsigned char) 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }

    return (1 & ((d - 1) >> 8)) - 1;
}

#endif // VANILLA_NACL
