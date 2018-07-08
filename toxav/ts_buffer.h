/*
 * Copyright © 2018 zoff@zoff.cc
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

#ifndef TS_BUFFER_H
#define TS_BUFFER_H

#include <stdbool.h>
#include <stdint.h>
#include "../toxcore/logger.h"

/* TimeStamp Buffer */
typedef struct TSBuffer TSBuffer;

bool tsb_full(const TSBuffer *b);
bool tsb_empty(const TSBuffer *b);
void tsb_get_range_in_buffer(TSBuffer *b, uint32_t *timestamp_min, uint32_t *timestamp_max);
void *tsb_write(TSBuffer *b, void *p, const uint64_t data_type, const uint32_t timestamp);
bool tsb_read(TSBuffer *b, Logger *log, void **p, uint64_t *data_type, uint32_t *timestamp_out,
              const uint32_t timestamp_in, const uint32_t timestamp_range,
              uint16_t *removed_entries_back);
TSBuffer *tsb_new(const int size);
void tsb_kill(TSBuffer *b);
void tsb_drain(TSBuffer *b);
uint16_t tsb_size(const TSBuffer *b);

#endif /* TS_BUFFER_H */
