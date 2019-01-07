%{
/*
 * Copyright © 2019 The TokTok team.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef C_TOXCORE_TOXCORE_MEM_H
#define C_TOXCORE_TOXCORE_MEM_H

#include <stddef.h>
#include <stdint.h>
%}

static namespace mem {

/**
 * Bump-allocate an array of elements.
 *
 * The bump-allocator strictly requires that the `$bfree` calls are run in
 * reverse order of allocation (`$bcalloc`). Failure to do so will result in
 * undefined behaviour (e.g. an assertion failure). Generally, this means the
 * calls to `$bcalloc` and `$bfree` should be in the same lexical scope.
 *
 * @param nmemb Number of elements in the allocated array.
 * @param size `sizeof(T)`, the size of one element.
 * @return A dynamically allocated `T[nmemb]`, cast to `void *`.
 */
void *bcalloc(uint32_t nmemb, uint32_t size);

/**
 * Free the most recent allocation from the bump allocator.
 *
 * The memory is not cleared on deallocation.
 *
 * @param ptr The pointer last returned by `$bcalloc`.
 */
void bfree(void *ptr);

}  // namespace mem

%{
#endif  // C_TOXCORE_TOXCORE_MEM_H
%}
