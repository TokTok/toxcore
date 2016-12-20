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
#ifndef SODIUM_UTILS_H
#define SODIUM_UTILS_H

#include <stdint.h>
#include <stdlib.h>

/**
 * A `memcmp`-like function whose running time does not depend on the input
 * bytes, only on the input length. Useful to compare sensitive data where
 * timing attacks could reveal that data.
 *
 * This means for instance that comparing "aaaa" and "aaaa" takes 4 time, and
 * "aaaa" and "baaa" also takes 4 time. With a regular `memcmp`, the latter may
 * take 1 time, because it immediately knows that the two strings are not equal.
 */
int32_t sodium_memcmp(const void *const b1_, const void *const b2_,
                      size_t len);

/**
 * A `bzero`-like function which won't be optimised away by the compiler. Some
 * compilers will inline `bzero` or `memset` if they can prove that there will
 * be no reads to the written data. Use this function if you want to be sure the
 * memory is indeed zeroed.
 */
void sodium_memzero(void *const pnt, size_t length);

#endif /* SODIUM_UTILS_H */
