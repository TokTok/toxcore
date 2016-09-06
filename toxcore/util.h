/*
 * Utilities.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 * This file is donated to the Tox Project.
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
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POWER_OF_2(x) (((x) != 0) && (((x) & ((~(x)) + 1)) == (x)))

/* Enlarges static buffers returned by id_toa and ip_ntoa so that
 * they can be used multiple times in same output
 */
#define STATIC_BUFFER_COPIES    10
#define STATIC_BUFFER_DEFINE(name,len)  static char stat_buffer_##name[(len)*STATIC_BUFFER_COPIES]; \
                                        static unsigned stat_buffer_counter_##name=0;
#define STATIC_BUFFER_GETBUF(name,len)  (&stat_buffer_##name[(len)*(stat_buffer_counter_##name++%STATIC_BUFFER_COPIES)])

/* Macros for groupchat extended keys */
#define ENC_KEY(key) (key)
#define SIG_PK(key) (key + ENC_PUBLIC_KEY)
#define SIG_SK(key) (key + ENC_SECRET_KEY)
#define CHAT_ID(key) (key + ENC_PUBLIC_KEY)


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);

/* compares two group chat_id's */
bool chat_id_equal(const uint8_t *dest, const uint8_t *src);

uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

// For printing purposes
char *id_toa(const uint8_t *id);

void host_to_net(uint8_t *num, uint16_t numbytes);
void net_to_host(uint8_t *num, uint16_t numbytes);

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items);

/* Converts 8 bytes to uint64_t */
void bytes_to_U64(uint64_t *dest, const uint8_t *bytes);

/* Converts 4 bytes to uint32_t */
void bytes_to_U32(uint32_t *dest, const uint8_t *bytes);

/* Converts 2 bytes to uint16_t */
void bytes_to_U16(uint16_t *dest, const uint8_t *bytes);

/* Convert uint64_t to byte string of size 8 */
void U64_to_bytes(uint8_t *dest, uint64_t value);

/* Convert uint32_t to byte string of size 4 */
void U32_to_bytes(uint8_t *dest, uint32_t value);

/* Convert uint16_t to byte string of size 2 */
void U16_to_bytes(uint8_t *dest, uint16_t value);

/* Returns -1 if failed or 0 if success */
int create_recursive_mutex(pthread_mutex_t *mutex);

// Safe min/max functions with specific types. This forces the conversion to the
// desired type before the comparison expression, giving the choice of
// conversion to the caller. Use these instead of inline comparisons or MIN/MAX
// macros (effectively inline comparisons).
int16_t max_s16(int16_t a, int16_t b);
int32_t max_s32(int32_t a, int32_t b);
int64_t max_s64(int64_t a, int64_t b);

int16_t min_s16(int16_t a, int16_t b);
int32_t min_s32(int32_t a, int32_t b);
int64_t min_s64(int64_t a, int64_t b);

uint16_t max_u16(uint16_t a, uint16_t b);
uint32_t max_u32(uint32_t a, uint32_t b);
uint64_t max_u64(uint64_t a, uint64_t b);

uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_UTIL_H
