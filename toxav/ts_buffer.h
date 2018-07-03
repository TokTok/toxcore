
#ifndef TS_BUFFER_H
#define TS_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

/* TimeStamp Buffer */
typedef struct TSBuffer TSBuffer;

bool tsb_full(const TSBuffer *b);
bool tsb_empty(const TSBuffer *b);
void *tsb_write(TSBuffer *b, void *p, const uint64_t data_type, const uint32_t timestamp);
bool tsb_read(TSBuffer *b, void **p, uint64_t *data_type, uint32_t *timestamp_out,
              const uint32_t timestamp_in, const uint32_t timestamp_range);
TSBuffer *tsb_new(const int size);
void tsb_kill(TSBuffer *b);
void tsb_drain(TSBuffer *b);
uint16_t tsb_size(const TSBuffer *b);

#endif /* TS_BUFFER_H */
