/* byte_vector.h
 *
 * Dynamically resizable contiguous memory array implementation.
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef BYTE_VECTOR_H
#define BYTE_VECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Dynamically resizable contiguous memory array implementation.
 *
 * Mimics C++'s std::vector interface to some degree (there are differences).
 * A std::vector-like container that works on elements of specified type size
 * could built using this container.
 */
#ifndef BYTE_VECTOR_DEFINED
#define BYTE_VECTOR_DEFINED
typedef struct Byte_Vector Byte_Vector;
#endif /* BYTE_VECTOR_DEFINED */

/**
 * Create a new empty vector.
 * @param initial_capacity Initial capacity of the internal buffer.
 * @return A new vector on success or NULL on failure.
 */
struct Byte_Vector *byte_vector_new(size_t initial_capacity);

/**
 * Destroy the vector and free all the resources.
 */
void byte_vector_free(struct Byte_Vector *_vector);

/**
 * @return the amount of memory allocated for the internal buffer.
 */
size_t byte_vector_capacity(const struct Byte_Vector *_vector);

/**
 * @return a pointer to the internal buffer.
 *
 * This pointer is invalidated in the following situations:
 * - The vector is freed.
 * - The internal buffer is reallocated. This can happen during byte_vector_insert(),
 *   byte_vector_reserve() and byte_vector_shrink_to_fit() calls.
 */
const uint8_t *byte_vector_data(const struct Byte_Vector *_vector);

/**
 * @return The current size of the data contained in the vector.
 */
size_t byte_vector_size(const struct Byte_Vector *_vector);

/**
 * Make sure that the vector's capacity is at least `required_capacity`.
 *
 * If vector's capacity is below `required_capacity`, vector reallocates its
 * internal buffer and increases the capacity to fit at least
 * `required_capacity`. It's possible the vector will increase the capacity
 * past `required_capacity`.
 *
 * If vector's capacity is already greater or equal to `required_capacity`,
 * nothing happens and the function succeeds.
 *
 * @param required_capacity Minimum capacity the vector should have.
 *
 * @return True if after the function call the capacity of the vector is >=
 * `required_capacity`, false if couldn't reserve at least
 * `required_capacity`.
 *
 * Note that the function returns true even if vector's capacity was  >=
 * `required_capacity` before this function call.
 */
bool byte_vector_reserve(struct Byte_Vector *_vector, size_t required_capacity);

/**
 * Shrink the internal buffer to fit the contained data, making capacity
 * be equal to the size. The internal buffer is reallocated if the vector if
 * not already shrinked to fit.
 * @return True on success, false on failure.
 */
bool byte_vector_shrink_to_fit(struct Byte_Vector *_vector);

/**
 * Extend vector at the specified position by inserting data starting there.
 * Whatever is at and past the specified position gets relocated to new
 * positions. The internal buffer is automatically reallocated if the current
 * capacity is not enough.
 * @param pos Position in the vector starting at which the data should be
 * inserted. The position is zero-indexed.
 * @param src Pointer to the data to be inserted.
 * @param count Number of bytes of the data to insert.
 * @return True on success, false on failure.
 */
bool byte_vector_insert(struct Byte_Vector *_vector, size_t pos, const uint8_t *src, size_t count);

/**
 * Read data at the specified position.
 * @param pos Position to start reading the data from. The position is
 * zero-indexed.
 * @param dest Pointer to where the data will be read into.
 * @param count Number of bytes of the data to read.
 * @return True on success, false on failure.
 */
bool byte_vector_at(const struct Byte_Vector *_vector, size_t pos, uint8_t *dest, size_t count);

/**
 * Shrink the vector at the specified position by erasing data starting there.
 * Whatever is past the removed data gets relocated to new positions.
 * @param pos Position in the vector starting at which the data should be
 * erased. The position is zero-indexed.
 * @param count Number of bytes of the data to erase.
 * @return True on success, false on failure.
 */
bool byte_vector_erase(struct Byte_Vector *_vector, size_t pos, size_t count);

#endif /* BYTE_VECTOR_H */

