/*
 * TimeStamp Buffer implementation
 */

#include "ts_buffer.h"

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

static void tsb_move_delete_entry(TSBuffer *b, uint16_t src_index, uint16_t dst_index)
{
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

static void tsb_close_hole(TSBuffer *b, uint16_t start_index, uint16_t hole_index)
{
    int32_t current_index = (int32_t)hole_index;
    while (true)
    {
        // delete current index by moving the previous entry into it
        // don't change start element pointer in this function!
        if (current_index < 1)
        {
            tsb_move_delete_entry(b, (b->size - 1), current_index);
        }
        else
        {
            tsb_move_delete_entry(b, (uint16_t)(current_index - 1), current_index);
        }

        if (current_index == (int32_t)start_index)
        {
            return;
        }

        current_index = current_index - 1;
        if (current_index < 0)
        {
            current_index = (int32_t)(b->size - 1);
        }
    }
}

static void tsb_delete_old_entries(TSBuffer *b, const uint32_t timestamp_threshold)
{
    // buffer empty, nothing to delete
    if (tsb_empty(b) == true) {
        return;
    }

    uint16_t removed_entries = 0;
    uint16_t start_entry = b->start;
    uint16_t current_element;
    // iterate all entries
    
    for (int i=0;i < tsb_size(b);i++)
    {
        current_element = (start_entry + i) % b->size;
        if (b->timestamp[current_element] < timestamp_threshold)
        {
            tsb_close_hole(b, start_entry, current_element);
            removed_entries++;
        }
    }

    b->start = (b->start + removed_entries) % b->size;
}

static bool tsb_return_oldest_entry_in_range(TSBuffer *b, void **p, uint64_t *data_type, uint32_t *timestamp_out,
              const uint32_t timestamp_in, const uint32_t timestamp_range)
{
    int32_t found_element = -1;
    uint32_t found_timestamp = UINT32_MAX;
    uint16_t start_entry = b->start;
    uint16_t current_element;
    for (int i=0;i < tsb_size(b);i++)
    {
        current_element = (start_entry + i) % b->size;
        if (  (b->timestamp[current_element] >= (timestamp_in - timestamp_range))
        &&
        (  b->timestamp[current_element] <= (timestamp_in + timestamp_range) ))
        {
            // timestamp of entry is in range
            if ((uint32_t)b->timestamp[current_element] < found_timestamp)
            {
                // entry is older than previous found entry, or is the first found entry
                found_timestamp = (uint32_t)b->timestamp[current_element];
                found_element = (int32_t)current_element;
            }
        }
    }

    if (found_element > -1)
    {
        // swap element with element in "start" position
        if (found_element != (int32_t)b->start)
        {
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

bool tsb_read(TSBuffer *b, void **p, uint64_t *data_type, uint32_t *timestamp_out,
              const uint32_t timestamp_in, const uint32_t timestamp_range)
{
    if (tsb_empty(b) == true) {
        *p = NULL;
        return false;
    }

    tsb_delete_old_entries(b, (timestamp_in - timestamp_range));
    return tsb_return_oldest_entry_in_range(b, p, data_type, timestamp_out, timestamp_in, timestamp_range);
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
    if (b)
    {
        void *dummy = NULL;
        uint64_t dt;
        uint32_t to;
        while (tsb_read(b, &dummy, &dt, &to, UINT32_MAX, 0) == true)
        {
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


#if 0

static void tsb_debug_print_entries(const TSBuffer *b)
{
    uint16_t current_element;
    for (int i=0;i < tsb_size(b);i++)
    {
        current_element = (b->start + i) % b->size;
        printf("loop=%d val=%d\n", current_element, b->timestamp[current_element]);
    }
}

void unit_test()
{
    #include <time.h>
    
    printf("ts_buffer:testing ...\n");
    const int size = 200;
    const int bytes_per_entry = 200;

    TSBuffer *b1 = tsb_new(size);
    printf("b1=%p\n", b1);

    uint16_t size_ = tsb_size(b1);
    printf("size_=%d\n", size_);

    srand(time(NULL));

    for(int j=0;j<size+0;j++)
    {
        void *tmp_b = calloc(1, bytes_per_entry);
        
        int val = rand() % 4999 + 1000;
        void *ret_p = tsb_write(b1, tmp_b, 1, val);
        printf("loop=%d val=%d\n", j, val);

        if (ret_p)
        {
            printf("kick oldest\n");
            free(ret_p);
        }

        size_ = tsb_size(b1);
        printf("size_=%d\n", size_);

    }

    size_ = tsb_size(b1);
    printf("size_=%d\n", size_);

    void *ptr;
    uint64_t dt;
    uint32_t to;
    uint32_t ti = 3000;
    uint32_t tr = 400;
    bool res1;

    bool loop = true;
    while (loop)
    {
        loop = false;
        ti = rand() % 4999 + 1000;
        tr = rand() % 100 + 1;
        res1 = tsb_read(b1, &ptr, &dt, &to, ti, tr); 
        if (res1 == true)
        {
            printf("ti=%d,tr=%d,TO=%d\n", (int)ti, (int)tr, (int)to);
            free(ptr);
            tsb_debug_print_entries(b1);
            break;
        }
        else if (tsb_size(b1) == 0)
        {
            break;
        }
        size_ = tsb_size(b1);
        printf("size_=%d\n", size_);
    }

    tsb_drain(b1);
    printf("drain\n");

    size_ = tsb_size(b1);
    printf("size_=%d\n", size_);

    tsb_kill(b1);
    b1 = NULL;
    printf("kill=%p\n", b1);
}

#endif
