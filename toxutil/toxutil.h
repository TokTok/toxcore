/*
 * Copyright © 2018 Zoff
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

#ifndef TOXUTIL_H
#define TOXUTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void tox_utils_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback);
void tox_utils_self_connection_status_cb(Tox *tox,
        TOX_CONNECTION connection_status, void *user_data);

void tox_utils_callback_friend_connection_status(Tox *tox,
        tox_friend_connection_status_cb *callback);
void tox_utils_friend_connection_status_cb(Tox *tox, uint32_t friendnumber,
        TOX_CONNECTION connection_status, void *user_data);

void tox_utils_callback_friend_lossless_packet(Tox *tox,
        tox_friend_lossless_packet_cb *callback);
void tox_utils_friend_lossless_packet_cb(Tox *tox, uint32_t friend_number,
        const uint8_t *data, size_t length, void *user_data);

void tox_utils_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback);
void tox_utils_file_recv_control_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                    TOX_FILE_CONTROL control, void *user_data);

void tox_utils_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback);
void tox_utils_file_chunk_request_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                     uint64_t position, size_t length, void *user_data);

void tox_utils_callback_file_recv(Tox *tox, tox_file_recv_cb *callback);
void tox_utils_file_recv_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                            uint32_t kind, uint64_t file_size,
                            const uint8_t *filename, size_t filename_length, void *user_data);

void tox_utils_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback);
void tox_utils_file_recv_chunk_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                  uint64_t position, const uint8_t *data, size_t length,
                                  void *user_data);


// ---- Msg V2 API ----

// HINT: you still need to register the "old" callback "tox_friend_message_cb"
//       to get old format messages
typedef void tox_util_friend_message_v2_cb(Tox *tox, uint32_t friend_number,
        const uint8_t *message, size_t length);

void tox_utils_callback_friend_message_v2(Tox *tox, tox_util_friend_message_v2_cb *callback);

// HINT: use only this API function to send messages (it will automatically send old format if needed)
int64_t tox_util_friend_send_message_v2(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                                        uint32_t ts_sec, const uint8_t *message, size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error);

// ---- Msg V2 API ----


Tox *tox_utils_new(const struct Tox_Options *options, TOX_ERR_NEW *error);
void tox_utils_kill(Tox *tox);
bool tox_utils_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error);


#ifdef __cplusplus
}
#endif

#endif
