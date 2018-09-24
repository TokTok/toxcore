/**
 * The state module is responsible for parsing the Tox save data format and for
 * saving state in that format.
 *
 * This module provides functions for iterating over serialised data sections
 * and reading/writing numbers in the correct format (little endian).
 *
 * Note that unlike the Tox network protocol, the save data stores its values in
 * little endian, which is native to most desktop and server architectures in
 * 2018.
 */
#ifndef C_TOXCORE_TOXCORE_STATE_H
#define C_TOXCORE_TOXCORE_STATE_H

#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATE_COOKIE_GLOBAL 0x15ed1b1f

#define TOP_STATE_COOKIE_TYPE  0x01ce

typedef enum Top_State_Type {
    TOP_STATE_TYPE_NOSPAMKEYS    = 1,
    TOP_STATE_TYPE_DHT           = 2,
    TOP_STATE_TYPE_FRIENDS       = 3,
    TOP_STATE_TYPE_NAME          = 4,
    TOP_STATE_TYPE_STATUSMESSAGE = 5,
    TOP_STATE_TYPE_STATUS        = 6,
    TOP_STATE_TYPE_TCP_RELAY     = 10,
    TOP_STATE_TYPE_PATH_NODE     = 11,
    TOP_STATE_TYPE_CONFERENCES   = 20,
    TOP_STATE_TYPE_END           = 255,
} Top_State_Type;

// Returned by the state_load_cb to instruct the loader on what to do next.
typedef enum State_Load_Status {
    // Continue loading state data sections.
    STATE_LOAD_STATUS_CONTINUE,
    // An error occurred. Stop loading sections.
    STATE_LOAD_STATUS_ERROR,
    // We're at the end of the save data, terminate loading successfully.
    STATE_LOAD_STATUS_END,
} State_Load_Status;

typedef State_Load_Status state_load_cb(void *outer, const uint8_t *data, uint32_t len, uint16_t type);

// state load/save
int state_load(const Logger *log, state_load_cb *state_load_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

uint8_t *state_write_section_header(uint8_t *data, uint16_t cookie_type, uint32_t len, uint32_t section_type);

// Utilities for state data serialisation.

uint16_t lendian_to_host16(uint16_t lendian);
#define host_to_lendian16(x) lendian_to_host16(x)

void host_to_lendian_bytes32(uint8_t *dest, uint32_t num);
void lendian_bytes_to_host32(uint32_t *dest, const uint8_t *lendian);

void host_to_lendian_bytes16(uint8_t *dest, uint16_t num);
void lendian_bytes_to_host16(uint16_t *dest, const uint8_t *lendian);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_STATE_H
