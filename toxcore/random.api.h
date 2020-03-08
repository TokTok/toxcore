%{
/*
 * Functions for the core crypto.
 */

#ifndef C_TOXCORE_TOXCORE_RANDOM_H
#define C_TOXCORE_TOXCORE_RANDOM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
%}

namespace random {

/**
 * Return a random 8 bit integer.
 */
static uint8_t u08();

/**
 * Return a random 16 bit integer.
 */
static uint16_t u16();

/**
 * Return a random 32 bit integer.
 */
static uint32_t u32();

/**
 * Return a random 64 bit integer.
 */
static uint64_t u64();

/**
 * Fill an array of bytes with random values.
 */
static void bytes(uint8_t[length] bytes);

}

%{
#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_RANDOM_H
%}
