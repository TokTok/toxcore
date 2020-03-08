/*
 * Functions for the core crypto.
 */

#ifndef C_TOXCORE_TOXCORE_RANDOM_H
#define C_TOXCORE_TOXCORE_RANDOM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return a random 8 bit integer.
 */
uint8_t random_u08(void);

/**
 * Return a random 16 bit integer.
 */
uint16_t random_u16(void);

/**
 * Return a random 32 bit integer.
 */
uint32_t random_u32(void);

/**
 * Return a random 64 bit integer.
 */
uint64_t random_u64(void);

/**
 * Fill an array of bytes with random values.
 */
void random_bytes(uint8_t *bytes, size_t length);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_RANDOM_H
