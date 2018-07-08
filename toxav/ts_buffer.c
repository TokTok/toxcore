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

/*
 * TimeStamp Buffer implementation
 */

#include "ts_buffer.h"
#include "rtp.h"
#include "../toxcore/logger.h"

#include <stdlib.h>
#include <stdio.h>

struct TSBuffer {
    uint16_t  size; /* max. number of elements in buffer [ MAX ALLOWED = (UINT16MAX - 1) !! ] */
    uint16_t  start;
    uint16_t  end;
    uint64_t  *type; /* used by caller anyway the caller wants, or dont use it at all */
    uint32_t  *timestamp; /* these dont need to be unix timestamp, they can be nummbers of a counter */
    void    **data;
};

bool tsb_full(const TSBuffer *b)
{
    return (b->end + 1) % b->size == b->start;
}

bool tsb_empty(const TSBuffer *b)
{
    return b->end == b->start;
}

/*
 * returns: NULL on success
 *          oldest element on FAILURE -> caller must free it after tsb_write() call
 */
void *tsb_write(TSBuffer *b, void *p, const uint64_t data_type, const uint32_t timestamp)
{
    void *rc = NULL;

    if (tsb_full(b) == true) {
        rc = b->data[b->start]; // return oldest element
        b->start = (b->start + 1) % b->size; // include empty element if buffer would be empty now
    }

    b->data[b->end] = p;
    b->type[b->end] = data_type;
    b->timestamp[b->end] = timestamp;
    b->end = (b->end + 1) % b->size;

    return rc;
}

static void tsb_move_delete_entry(TSBuffer *b, Logger *log, uint16_t src_index, uint16_t dst_index)
{
    if (log) {
        struct RTPMessage *msg = b->data[dst_index];

        if (msg) {
            const struct RTPHeader *header_v3_0 = & (msg->header);
            int seq = header_v3_0->sequnum;
            LOGGER_WARNING(log, "tsb:free:seq=%d", (int)seq);
        }

        msg = b->data[src_index];

        if (msg) {
            const struct RTPHeader *header_v3_0 = & (msg->header);
            int seq = header_v3_0->sequnum;
            LOGGER_WARNING(log, "tsb:move:seq=%d from %d to %d", (int)seq, (int)src_index, (int)dst_index);
        }
    }

    free(b->data[dst_index]);

    b->data[dst_index] = b->data[src_index];
    b->type[dst_index] = b->type[src_index];
    b->timestamp[dst_index] = b->timestamp[src_index];

    // just to be safe ---
    b->data[src_index] = NULL;
    b->type[src_index] = 0;
    b->timestamp[src_index] = 0;
    // just to be safe ---
}

static void tsb_close_hole(TSBuffer *b, Logger *log, uint16_t start_index, uint16_t hole_index)
{
    int32_t current_index = (int32_t)hole_index;

    if (log) {
        struct RTPMessage *msg = b->data[hole_index];
        const struct RTPHeader *header_v3_0 = & (msg->header);
        int seq = header_v3_0->sequnum;
        LOGGER_WARNING(log, "tsb:hole index:seq=%d", (int)seq);
    }


    while (true) {
        // delete current index by moving the previous entry into it
        // don't change start element pointer in this function!
        if (current_index < 1) {
            tsb_move_delete_entry(b, log, (b->size - 1), current_index);
        } else {
            tsb_move_delete_entry(b, log, (uint16_t)(current_index - 1), current_index);
        }

        if (current_index == (int32_t)start_index) {
            return;
        }

        current_index = current_index - 1;

        if (current_index < 0) {
            current_index = (int32_t)(b->size - 1);
        }
    }
}

static uint16_t tsb_delete_old_entries(TSBuffer *b, Logger *log, const uint32_t timestamp_threshold)
{
    // buffer empty, nothing to delete
    if (tsb_empty(b) == true) {
        return 0;
    }

    uint16_t removed_entries = 0;
    uint16_t start_entry = b->start;
    uint16_t current_element;
    // iterate all entries

    for (int i = 0; i < tsb_size(b); i++) {
        current_element = (start_entry + i) % b->size;

        if (b->timestamp[current_element] < timestamp_threshold) {
            if (log) {
                struct RTPMessage *msg = b->data[current_element];
                const struct RTPHeader *header_v3_0 = & (msg->header);
                int seq = header_v3_0->sequnum;
                LOGGER_WARNING(log, "tsb:kick:seq=%d diff=%d", (int)seq,
                               (int)(timestamp_threshold - b->timestamp[current_element]));
            }

            tsb_close_hole(b, log, start_entry, current_element);
            removed_entries++;
        }
    }

    b->start = (b->start + removed_entries) % b->size;

    return removed_entries;
}

void tsb_get_range_in_buffer(TSBuffer *b, uint32_t *timestamp_min, uint32_t *timestamp_max)
{
    uint16_t current_element;
    uint16_t start_entry = b->start;
    *timestamp_min = UINT32_MAX;
    *timestamp_max = 0;

    for (int i = 0; i < tsb_size(b); i++) {
        current_element = (start_entry + i) % b->size;

        if (b->timestamp[current_element] > *timestamp_max) {
            *timestamp_max = b->timestamp[current_element];
        }

        if (b->timestamp[current_element] < *timestamp_min) {
            *timestamp_min = b->timestamp[current_element];
        }
    }
}

static bool tsb_return_oldest_entry_in_range(TSBuffer *b, Logger *log, void **p, uint64_t *data_type,
        uint32_t *timestamp_out,
        const uint32_t timestamp_in, const uint32_t timestamp_range)
{
    int32_t found_element = -1;
    uint32_t found_timestamp = UINT32_MAX;
    uint16_t start_entry = b->start;
    uint16_t current_element;

    if (log) {
        LOGGER_WARNING(log, "tsb_old:tsb_size=%d", (int)tsb_size(b));
    }

    for (int i = 0; i < tsb_size(b); i++) {
        current_element = (start_entry + i) % b->size;

        if (log) {
            struct RTPMessage *msg = b->data[current_element];

            if (msg) {
                const struct RTPHeader *header_v3_0 = & (msg->header);
                int seq = header_v3_0->sequnum;
                LOGGER_WARNING(log, "tsb_old:iter:seq=%d ts=%d",
                               (int)seq, (int)header_v3_0->frame_record_timestamp);
            }
        }

#define STRANGE_OFFSET (int)(+400)

        if (((b->timestamp[current_element] + STRANGE_OFFSET) >= (timestamp_in - timestamp_range))
                &&
                (b->timestamp[current_element] <= (timestamp_in + 1))) {


            if (log) {
                struct RTPMessage *msg = b->data[current_element];

                if (msg) {
                    const struct RTPHeader *header_v3_0 = & (msg->header);
                    int seq = header_v3_0->sequnum;
                    LOGGER_WARNING(log, "tsb_old:in range:seq=%d range=(%d - %d) -> want=%d prevfound=%d",
                                   (int)seq,
                                   (int)(timestamp_in - timestamp_range),
                                   (int)(timestamp_in + 1),
                                   (int)timestamp_in,
                                   (int)found_timestamp);
                }
            }

            // timestamp of entry is in range
            if ((uint32_t)b->timestamp[current_element] < found_timestamp) {
                // entry is older than previous found entry, or is the first found entry
                found_timestamp = (uint32_t)b->timestamp[current_element];
                found_element = (int32_t)current_element;

                if (log) {
                    struct RTPMessage *msg = b->data[current_element];

                    if (msg) {
                        const struct RTPHeader *header_v3_0 = & (msg->header);
                        int seq = header_v3_0->sequnum;
                        LOGGER_WARNING(log, "tsb_old:iter:seq=%d found_timestamp=%d",
                                       (int)seq, (int)found_timestamp);
                    }
                }

            }
        }
    }

    if (found_element > -1) {
        // swap element with element in "start" position
        if (found_element != (int32_t)b->start) {
            void *p_save = b->data[found_element];
            uint64_t data_type_save = b->type[found_element];
            uint32_t timestamp_save = b->timestamp[found_element];

            b->data[found_element] = b->data[b->start];
            b->type[found_element] = b->type[b->start];
            b->timestamp[found_element] = b->timestamp[b->start];

            b->data[b->start] = p_save;
            b->type[b->start] = data_type_save;
            b->timestamp[b->start] = timestamp_save;
        }

        // fill data to return to caller
        *p = b->data[b->start];
        *data_type = b->type[b->start];
        *timestamp_out = b->timestamp[b->start];

        b->data[b->start] = NULL;
        b->timestamp[b->start] = 0;
        b->type[b->start] = 0;

        // change start element pointer
        b->start = (b->start + 1) % b->size;
        return true;
    }

    *p = NULL;
    return false;
}

bool tsb_read(TSBuffer *b, Logger *log, void **p, uint64_t *data_type, uint32_t *timestamp_out,
              const uint32_t timestamp_in, const uint32_t timestamp_range,
              uint16_t *removed_entries_back)
{
    if (tsb_empty(b) == true) {
        *removed_entries_back = 0;
        *p = NULL;
        return false;
    }

    bool have_found_element = tsb_return_oldest_entry_in_range(b, log, p, data_type,
                              timestamp_out,
                              timestamp_in,
                              timestamp_range);

    if (have_found_element == true) {
        // only delete old entries if we found a "wanted" entry
        uint16_t removed_entries = tsb_delete_old_entries(b, log, (timestamp_in - timestamp_range));
        *removed_entries_back = removed_entries;
    } else {
        *removed_entries_back = 0;
    }

    return have_found_element;
}

TSBuffer *tsb_new(const int size)
{
    TSBuffer *buf = (TSBuffer *)calloc(sizeof(TSBuffer), 1);

    if (!buf) {
        return NULL;
    }

    buf->size = size + 1; /* include empty elem */
    buf->start = 0;
    buf->end = 0;

    if (!(buf->data = (void **)calloc(buf->size, sizeof(void *)))) {
        free(buf);
        return NULL;
    }

    if (!(buf->type = (uint64_t *)calloc(buf->size, sizeof(uint64_t)))) {
        free(buf->data);
        free(buf);
        return NULL;
    }

    if (!(buf->timestamp = (uint32_t *)calloc(buf->size, sizeof(uint32_t)))) {
        free(buf->data);
        free(buf->type);
        free(buf);
        return NULL;
    }

    return buf;
}

void tsb_drain(TSBuffer *b)
{
    if (b) {
        void *dummy = NULL;
        uint64_t dt;
        uint32_t to;
        uint16_t reb;

        while (tsb_read(b, NULL, &dummy, &dt, &to, UINT32_MAX, 0, &reb) == true) {
            free(dummy);
        }
    }
}

void tsb_kill(TSBuffer *b)
{
    if (b) {
        free(b->data);
        free(b->type);
        free(b->timestamp);
        free(b);
    }
}

uint16_t tsb_size(const TSBuffer *b)
{
    if (tsb_empty(b) == true) {
        return 0;
    }

    return
        b->end > b->start ?
        b->end - b->start :
        (b->size - b->start) + b->end;
}


#ifdef UNIT_TESTING_ENABLED

static void tsb_debug_print_entries(const TSBuffer *b)
{
    uint16_t current_element;

    for (int i = 0; i < tsb_size(b); i++) {
        current_element = (b->start + i) % b->size;
        printf("loop=%d val=%d\n", current_element, b->timestamp[current_element]);
    }
}

void unit_test()
{
#ifndef __MINGW32__
#include <time.h>
#endif

    printf("ts_buffer:testing ...\n");
    const int size = 5;
    const int bytes_per_entry = 200;

    TSBuffer *b1 = tsb_new(size);
    printf("b1=%p\n", b1);

    uint16_t size_ = tsb_size(b1);
    printf("size_:1=%d\n", size_);

#ifndef __MINGW32__
    srand(time(NULL));
#else
    // TODO: fixme ---
    srand(localtime());
    // TODO: fixme ---
#endif

    for (int j = 0; j < size + 0; j++) {
        void *tmp_b = calloc(1, bytes_per_entry);

        int val = rand() % 4999 + 1000;
        void *ret_p = tsb_write(b1, tmp_b, 1, val);
        printf("loop=%d val=%d\n", j, val);

        if (ret_p) {
            printf("kick oldest\n");
            free(ret_p);
        }

        size_ = tsb_size(b1);
        printf("size_:2=%d\n", size_);

    }

    size_ = tsb_size(b1);
    printf("size_:3=%d\n", size_);

    void *ptr;
    uint64_t dt;
    uint32_t to;
    uint32_t ti = 3000;
    uint32_t tr = 400;
    uint16_t reb = 0;
    bool res1;

    bool loop = true;

    while (loop) {
        loop = false;
        ti = rand() % 4999 + 1000;
        tr = rand() % 100 + 1;
        res1 = tsb_read(b1, NULL, &ptr, &dt, &to, ti, tr, &reb);
        printf("ti=%d,tr=%d\n", (int)ti, (int)tr);

        if (res1 == true) {
            printf("found:ti=%d,tr=%d,TO=%d\n", (int)ti, (int)tr, (int)to);
            free(ptr);
            tsb_debug_print_entries(b1);
            break;
        } else if (tsb_size(b1) == 0) {
            break;
        }

        size_ = tsb_size(b1);
        printf("size_:4=%d\n", size_);
    }

    tsb_drain(b1);
    printf("drain\n");

    size_ = tsb_size(b1);
    printf("size_:99=%d\n", size_);

    tsb_kill(b1);
    b1 = NULL;
    printf("kill=%p\n", b1);
}

#endif
