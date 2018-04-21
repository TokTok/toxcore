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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include "Messenger.h"

#include "logger.h"
#include "network.h"
#include "util.h"
#include "tox.h"
#include "toxutil.h"

#include <assert.h>


#define CAP_PACKET_ID 170
#define CAP_BYTE_0 33
#define CAP_BYTE_1 44

#define TOX_UTIL_EXPIRE_FT_MS 50000 // msgV2 FTs should expire after 50 seconds

typedef struct tox_utils_Node {
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    uint32_t key2;
    void *data;
    struct tox_utils_Node *next;
} tox_utils_Node;

typedef struct tox_utils_List {
    uint32_t size;
    tox_utils_Node *head;
} tox_utils_List;


static tox_utils_List global_friend_capability_list;

typedef struct global_friend_capability_entry {
    bool msgv2_cap;
} global_friend_capability_entry;


static tox_utils_List global_msgv2_incoming_ft_list;

typedef struct global_msgv2_incoming_ft_entry {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint32_t timestamp;
    uint8_t msg_data[TOX_MAX_FILETRANSFER_SIZE_MSGV2];
} global_msgv2_incoming_ft_entry;


static tox_utils_List global_msgv2_outgoing_ft_list;

typedef struct global_msgv2_outgoing_ft_entry {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint32_t timestamp;
    uint8_t msg_data[TOX_MAX_FILETRANSFER_SIZE_MSGV2];
} global_msgv2_outgoing_ft_entry;

static uint16_t global_ts_ms = 0;
static pthread_mutex_t mutex_tox_util[1];

// ------------ UTILS ------------

static time_t get_unix_time(void)
{
    return time(NULL);
}

/* Returns 1 if timed out, 0 otherwise */
static int timed_out(time_t timestamp, time_t timeout)
{
    return timestamp + timeout <= get_unix_time();
}

/* compares 2 items of length len (e.g.: Tox Pubkeys)
   Returns 0 if they are the same, 1 if they differ
 */
static int check_file_signature(const uint8_t *pubkey1, const uint8_t *pubkey2, size_t len)
{
    int ret = memcmp(pubkey1, pubkey2, len);
    return ret == 0 ? 0 : 1;
}



/**
 * @fn
 * get_hex
 *
 * @brief
 * Converts a char into binary string
 *
 * @param[in]
 *     buf Value to be converted to hex string
 * @param[in]
 *     buf_len Length of the buffer
 * @param[in]
 *     hex_ Pointer to space to put Hex string into
 * @param[in]
 *     hex_len Length of the hex string space
 * @param[in]
 *     num_col Number of columns in display hex string
 * @param[out]
 *     hex_ Contains the hex string
 * @return  void
 */
static inline void
get_hex(char *buf, int buf_len, char *hex_, int hex_len, int num_col)
{
    int i;
#define ONE_BYTE_HEX_STRING_SIZE   3
    unsigned int byte_no = 0;

    if (buf_len <= 0) {
        if (hex_len > 0) {
            hex_[0] = '\0';
        }

        return;
    }

    if (hex_len < ONE_BYTE_HEX_STRING_SIZE + 1) {
        return;
    }

    do {
        for (i = 0; ((i < num_col) && (buf_len > 0) && (hex_len > 0)); ++i) {
            snprintf(hex_, hex_len, "%02X ", buf[byte_no++] & 0xff);
            hex_ += ONE_BYTE_HEX_STRING_SIZE;
            hex_len -= ONE_BYTE_HEX_STRING_SIZE;
            buf_len--;
        }

        if (buf_len > 1) {
            snprintf(hex_, hex_len, "\n");
            hex_ += 1;
        }
    } while ((buf_len) > 0 && (hex_len > 0));

}




static void tox_utils_list_init(tox_utils_List *l)
{
    pthread_mutex_lock(mutex_tox_util);
    l->size = 0;
    l->head = NULL;
    pthread_mutex_unlock(mutex_tox_util);
}

static void tox_utils_list_clear(tox_utils_List *l)
{
    pthread_mutex_lock(mutex_tox_util);

    tox_utils_Node *head = l->head;
    tox_utils_Node *next_ = NULL;

    while (head) {
        next_ = head->next;

        l->size--;
        l->head = next_;

        if (head->data) {
            free(head->data);
        }

        free(head);
        head = next_;
    }

    l->size = 0;
    l->head = NULL;

    pthread_mutex_unlock(mutex_tox_util);
}


static void tox_utils_list_add(tox_utils_List *l, uint8_t *key, uint32_t key2, void *data)
{
    pthread_mutex_lock(mutex_tox_util);

    tox_utils_Node *n = calloc(1, sizeof(tox_utils_Node));

    memcpy(n->key, key, TOX_PUBLIC_KEY_SIZE);
    n->key2 = key2;
    n->data = data;

    if (l->head == NULL) {
        n->next = NULL;
    } else {
        n->next = l->head;
    }

    l->head = n;
    l->size++;

    pthread_mutex_unlock(mutex_tox_util);
}

static tox_utils_Node *tox_utils_list_get(tox_utils_List *l, uint8_t *key, uint32_t key2)
{
    pthread_mutex_lock(mutex_tox_util);

    tox_utils_Node *head = l->head;

    while (head) {
        if (head->key2 == key2) {
            if (check_file_signature(head->key, key, TOX_PUBLIC_KEY_SIZE) == 0) {
                pthread_mutex_unlock(mutex_tox_util);
                return head;
            }
        }

        head = head->next;
    }

    pthread_mutex_unlock(mutex_tox_util);
    return NULL;
}

static void tox_utils_list_remove_single_node(tox_utils_List *l, tox_utils_Node *n, tox_utils_Node *n_minus_1)
{
    if (!l) {
        return;
    }

    if (!n) {
        return;
    }

    if (n_minus_1 == NULL) {
        // want to delete the first node
        l->head = n->next;

        if (n->data) {
            free(n->data);
        }

        free(n);
        l->size--;
        n = NULL;
        return;
    } else {
        n_minus_1->next = n->next;

        if (n->data) {
            free(n->data);
        }

        free(n);
        l->size--;
        n = NULL;
    }

}

static void tox_utils_list_remove(tox_utils_List *l, uint8_t *key, uint32_t key2)
{
    pthread_mutex_lock(mutex_tox_util);

    tox_utils_Node *head = l->head;
    tox_utils_Node *prev_ = NULL;
    tox_utils_Node *next_ = NULL;

    while (head) {
        next_ = head->next;

        if (head->key2 == key2) {
            if (check_file_signature(head->key, key, TOX_PUBLIC_KEY_SIZE) == 0) {
                tox_utils_list_remove_single_node(l, head, prev_);
                // start from beginning of the list
                head = l->head;
                prev_ = NULL;
                next_ = NULL;
                continue;
            }
        }

        prev_ = head;
        head = next_;
    }

    pthread_mutex_unlock(mutex_tox_util);
}

static void tox_utils_list_remove_2(tox_utils_List *l, uint8_t *key)
{
    pthread_mutex_lock(mutex_tox_util);

    tox_utils_Node *head = l->head;
    tox_utils_Node *prev_ = NULL;
    tox_utils_Node *next_ = NULL;

    while (head) {
        next_ = head->next;

        if (check_file_signature(head->key, key, TOX_PUBLIC_KEY_SIZE) == 0) {
            tox_utils_list_remove_single_node(l, head, prev_);
            // start from beginning of the list
            head = l->head;
            prev_ = NULL;
            next_ = NULL;
            continue;
        }

        prev_ = head;
        head = next_;
    }

    pthread_mutex_unlock(mutex_tox_util);
}

// ------------ UTILS ------------













// ----------- FUNCS -----------
static int64_t tox_utils_pubkey_to_friendnum(Tox *tox, const uint8_t *public_key)
{
    TOX_ERR_FRIEND_BY_PUBLIC_KEY error;
    uint32_t fnum = tox_friend_by_public_key(tox, public_key, &error);

    if (error == 0) {
        return (int64_t)fnum;
    } else {
        return -1;
    }
}

static bool tox_utils_friendnum_to_pubkey(Tox *tox, uint8_t *public_key, uint32_t friend_number)
{
    TOX_ERR_FRIEND_GET_PUBLIC_KEY error;
    return tox_friend_get_public_key(tox, friend_number, public_key, &error);
}

static bool tox_utils_get_capabilities(Tox *tox, uint32_t friendnumber)
{
    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

    if (friend_pubkey) {
        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friendnumber);

        if (res == true) {
            tox_utils_Node *n = tox_utils_list_get(&global_friend_capability_list, friend_pubkey, 0);

            if (n != NULL) {
                free(friend_pubkey);
                return ((global_friend_capability_entry *)(n->data))->msgv2_cap;
            }
        }

        free(friend_pubkey);
    }

    return false;
}

static void tox_utils_set_capabilities(Tox *tox, uint32_t friendnumber, bool cap)
{
    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

    if (friend_pubkey) {
        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friendnumber);

        if (res == true) {
            global_friend_capability_entry *data = calloc(1, sizeof(global_friend_capability_entry));
            data->msgv2_cap = cap;

            tox_utils_Node *n = tox_utils_list_get(&global_friend_capability_list, friend_pubkey, 0);

            if (n == NULL) {
                if (cap == true) {
                    tox_utils_list_add(&global_friend_capability_list, friend_pubkey, 0, data);
                    Messenger *m = (Messenger *)tox;
                    LOGGER_WARNING(m->log, "toxutil:set_capabilities(add:1)");
                }
            } else {
                tox_utils_list_remove(&global_friend_capability_list, friend_pubkey, 0);
                Messenger *m = (Messenger *)tox;
                LOGGER_WARNING(m->log, "toxutil:set_capabilities(rm)");

                if (cap == true) {
                    tox_utils_list_add(&global_friend_capability_list, friend_pubkey, 0, data);
                    Messenger *m = (Messenger *)tox;
                    LOGGER_WARNING(m->log, "toxutil:set_capabilities(add:2)");
                }
            }
        }

        free(friend_pubkey);
    }
}

static void tox_utils_send_capabilities(Tox *tox, uint32_t friendnumber)
{
    uint8_t data[3];
    data[0] = CAP_PACKET_ID; // packet ID
    data[1] = CAP_BYTE_0;
    data[2] = CAP_BYTE_1;
    TOX_ERR_FRIEND_CUSTOM_PACKET error;
    tox_friend_send_lossless_packet(tox, friendnumber, data, 3, &error);

    if (error == TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ) {
        Messenger *m = (Messenger *)tox;
        LOGGER_WARNING(m->log, "toxutil:tox_utils_send_capabilities fnum=%d error:TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ",
                       (int)friendnumber);
    } else if (error != 0) {
        Messenger *m = (Messenger *)tox;
        LOGGER_WARNING(m->log, "toxutil:tox_utils_send_capabilities fnum=%d errnum:%d",
                       (int)friendnumber, (int)error);
    }
}

static void tox_utils_receive_capabilities(Tox *tox, uint32_t friendnumber, const uint8_t *data,
        size_t length)
{
    if (length == 3) {
        if ((data[0] == CAP_PACKET_ID) && (data[1] == CAP_BYTE_0) && (data[2] == CAP_BYTE_1)) {
            Messenger *m = (Messenger *)tox;
            LOGGER_WARNING(m->log, "toxutil:receive_capabilities fnum=%d data=%d% d %d",
                           (int)friendnumber, (int)data[0], (int)data[1], (int)data[2]);

            // friend has message V2 capability
            tox_utils_set_capabilities(tox, friendnumber, true);
        }
    }
}

static void tox_utils_housekeeping(Tox *tox)
{
#if 0

    pthread_mutex_lock(mutex_tox_util);

    // cancel and clear old outgoing FTs ----------------
    tox_utils_List *l = &global_msgv2_outgoing_ft_list;

    tox_utils_Node *head = l->head;
    tox_utils_Node *next_ = NULL;

    while (head) {
        next_ = head->next;

        if (head->data) {
            global_msgv2_outgoing_ft_entry *e = ((global_msgv2_outgoing_ft_entry *)(head->data));

            if ((e->timestamp + TOX_UTIL_EXPIRE_FT_MS) < current_time_monotonic()) {
                // cancel FT
                uint32_t friend_number = e->friend_number;
                uint32_t file_number = e->file_number;

                bool res = tox_file_control(tox, friend_number, file_number,
                                            (TOX_FILE_CONTROL)TOX_FILE_CONTROL_CANCEL, NULL);

                if (res == true) {
                    // remove FT from list
                    if (head->data) {
                        free(head->data);
                    }

                    l->size--;
                    l->head = next_;
                    free(head);

                    break;
                }
            }
        }

        l->head = next_;
        head = next_;
    }

    // cancel and clear old outgoing FTs ----------------



    // cancel and clear old incoming FTs ----------------
    l = &global_msgv2_incoming_ft_list;

    head = l->head;
    next_ = NULL;

    while (head) {
        next_ = head->next;

        if (head->data) {
            global_msgv2_incoming_ft_entry *e = ((global_msgv2_incoming_ft_entry *)(head->data));

            if ((e->timestamp + TOX_UTIL_EXPIRE_FT_MS) < current_time_monotonic()) {
                // cancel FT
                uint32_t friend_number = e->friend_number;
                uint32_t file_number = e->file_number;

                bool res = tox_file_control(tox, friend_number, file_number,
                                            (TOX_FILE_CONTROL)TOX_FILE_CONTROL_CANCEL, NULL);

                if (res == true) {
                    // remove FT from list
                    if (head->data) {
                        free(head->data);
                    }

                    l->size--;
                    l->head = next_;
                    free(head);

                    break;
                }
            }
        }

        l->head = next_;
        head = next_;
    }

    pthread_mutex_unlock(mutex_tox_util);

    // cancel and clear old incoming FTs ----------------
#endif
}

// ----------- FUNCS -----------




// --- set callbacks ---
void (*tox_utils_selfconnectionstatus)(struct Tox *tox, unsigned int, void *) = NULL;

void tox_utils_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback)
{
    tox_utils_selfconnectionstatus = (void (*)(Tox * tox,
                                      unsigned int, void *))callback;
}


void (*tox_utils_friend_connectionstatuschange)(struct Tox *tox, uint32_t,
        unsigned int, void *) = NULL;

void tox_utils_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
    tox_utils_friend_connectionstatuschange = (void (*)(Tox * tox, uint32_t,
            unsigned int, void *))callback;
    Messenger *m = (Messenger *)tox;
    LOGGER_WARNING(m->log, "toxutil:set callback");
}


void (*tox_utils_friend_losslesspacket)(struct Tox *tox, uint32_t, const uint8_t *,
                                        size_t, void *) = NULL;

void tox_utils_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback)
{
    tox_utils_friend_losslesspacket = (void (*)(Tox * tox, uint32_t,
                                       const uint8_t *, size_t, void *))callback;
}


void (*tox_utils_filerecvcontrol)(struct Tox *tox, uint32_t, uint32_t,
                                  unsigned int, void *) = NULL;

void tox_utils_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback)
{
    tox_utils_filerecvcontrol = (void (*)(Tox * tox, uint32_t, uint32_t,
                                          unsigned int, void *))callback;
}

void (*tox_utils_filechunkrequest)(struct Tox *tox, uint32_t, uint32_t,
                                   uint64_t, size_t, void *) = NULL;

void tox_utils_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback)
{
    tox_utils_filechunkrequest = (void (*)(Tox * tox, uint32_t, uint32_t,
                                           uint64_t, size_t, void *))callback;
}

void (*tox_utils_filerecv)(struct Tox *tox, uint32_t, uint32_t,
                           uint32_t, uint64_t, const uint8_t *, size_t, void *) = NULL;

void tox_utils_callback_file_recv(Tox *tox, tox_file_recv_cb *callback)
{
    tox_utils_filerecv = (void (*)(Tox * tox, uint32_t, uint32_t,
                                   uint32_t, uint64_t, const uint8_t *, size_t, void *))callback;
}

void (*tox_utils_filerecvchunk)(struct Tox *tox, uint32_t, uint32_t, uint64_t,
                                const uint8_t *, size_t, void *) = NULL;


void tox_utils_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback)
{
    tox_utils_filerecvchunk = (void (*)(Tox * tox, uint32_t, uint32_t, uint64_t,
                                        const uint8_t *, size_t, void *))callback;
}

void (*tox_utils_friend_message_v2)(struct Tox *tox, uint32_t, const uint8_t *,
                                    size_t) = NULL;

void tox_utils_callback_friend_message_v2(Tox *tox, tox_util_friend_message_v2_cb *callback)
{
    tox_utils_friend_message_v2 = (void (*)(Tox * tox, uint32_t, const uint8_t *,
                                            size_t))callback;
}

Tox *tox_utils_new(const struct Tox_Options *options, TOX_ERR_NEW *error)
{
    if (pthread_mutex_init(mutex_tox_util, NULL) != 0) {
        if (error) {
            // TODO: find a better error code, use malloc error for now
            *error = TOX_ERR_NEW_MALLOC;
        }

        return NULL;
    }

    tox_utils_list_init(&global_friend_capability_list);
    tox_utils_list_init(&global_msgv2_incoming_ft_list);
    tox_utils_list_init(&global_msgv2_outgoing_ft_list);

    return tox_new(options, error);
}

void tox_utils_kill(Tox *tox)
{
    tox_utils_list_clear(&global_friend_capability_list);
    tox_utils_list_clear(&global_msgv2_incoming_ft_list);
    tox_utils_list_clear(&global_msgv2_outgoing_ft_list);

    tox_kill(tox);

    pthread_mutex_destroy(mutex_tox_util);
}

bool tox_utils_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
{
    // clear all FTs of this friend from incmoning/outgoing FT lists
    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

    if (friend_pubkey) {
        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

        if (res == true) {
            tox_utils_list_remove_2(&global_msgv2_incoming_ft_list, friend_pubkey);
            tox_utils_list_remove_2(&global_msgv2_outgoing_ft_list, friend_pubkey);
        }

        free(friend_pubkey);
    }

    return tox_friend_delete(tox, friend_number, error);
}

// --- set callbacks ---



void tox_utils_friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data,
        size_t length, void *user_data)
{
    // ------- do messageV2 stuff -------
    tox_utils_receive_capabilities(tox, friend_number, data, length);
    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_friend_losslesspacket) {
        tox_utils_friend_losslesspacket(tox, friend_number, data, length, user_data);
    }

    // ------- call the real CB function -------
}


void tox_utils_self_connection_status_cb(Tox *tox,
        TOX_CONNECTION connection_status, void *user_data)
{
    // ------- do messageV2 stuff -------
    if (connection_status == TOX_CONNECTION_NONE) {
        // if we go offline ourselves, remove all FT data
        tox_utils_list_clear(&global_msgv2_incoming_ft_list);
        tox_utils_list_clear(&global_msgv2_outgoing_ft_list);
    }

    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_selfconnectionstatus) {
        tox_utils_selfconnectionstatus(tox, connection_status, user_data);
        // Messenger *m = (Messenger *)tox;
        // LOGGER_WARNING(m->log, "toxutil:selfconnectionstatus");
    }

    // ------- call the real CB function -------
}


void tox_utils_friend_connection_status_cb(Tox *tox, uint32_t friendnumber,
        TOX_CONNECTION connection_status, void *user_data)
{
    // ------- do messageV2 stuff -------
    if (connection_status == TOX_CONNECTION_NONE) {
        tox_utils_set_capabilities(tox, friendnumber, false);

        // remove FT data from list
        uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

        if (friend_pubkey) {
            bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friendnumber);

            if (res == true) {
                tox_utils_list_remove_2(&global_msgv2_incoming_ft_list, friend_pubkey);
                tox_utils_list_remove_2(&global_msgv2_outgoing_ft_list, friend_pubkey);
            }

            free(friend_pubkey);
        }
    } else {
        tox_utils_send_capabilities(tox, friendnumber);
    }

    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_friend_connectionstatuschange) {
        tox_utils_friend_connectionstatuschange(tox, friendnumber, connection_status, user_data);
        // Messenger *m = (Messenger *)tox;
        // LOGGER_WARNING(m->log, "toxutil:friend_connectionstatuschange");
    }

    // ------- call the real CB function -------
}


void tox_utils_file_recv_control_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                    TOX_FILE_CONTROL control, void *user_data)
{
    // ------- do messageV2 stuff -------
    if (control == TOX_FILE_CONTROL_CANCEL) {
        uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

        if (friend_pubkey) {
            bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

            if (res == true) {
                tox_utils_Node *n = tox_utils_list_get(&global_msgv2_outgoing_ft_list,
                                                       friend_pubkey, file_number);

                if (n != NULL) {
                    if (((global_msgv2_outgoing_ft_entry *)(n->data))->kind == TOX_FILE_KIND_MESSAGEV2_SEND) {
                        // remove FT data from list
                        tox_utils_list_remove(&global_msgv2_outgoing_ft_list,
                                              friend_pubkey, file_number);

                        free(friend_pubkey);
                        return;
                    }
                }

                n = tox_utils_list_get(&global_msgv2_incoming_ft_list,
                                       friend_pubkey, file_number);

                if (n != NULL) {
                    if (((global_msgv2_incoming_ft_entry *)(n->data))->kind == TOX_FILE_KIND_MESSAGEV2_SEND) {
                        // remove FT data from list
                        tox_utils_list_remove(&global_msgv2_incoming_ft_list,
                                              friend_pubkey, file_number);

                        free(friend_pubkey);
                        return;
                    }
                }

            }

            free(friend_pubkey);
        }
    }

    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_filerecvcontrol) {
        tox_utils_filerecvcontrol(tox, friend_number, file_number, control, user_data);
        // Messenger *m = (Messenger *)tox;
        // LOGGER_WARNING(m->log, "toxutil:file_recv_control_cb");
    }

    // ------- call the real CB function -------
}


void tox_utils_file_chunk_request_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                     uint64_t position, size_t length, void *user_data)
{
    // ------- do messageV2 stuff -------
    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

    if (friend_pubkey) {
        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

        if (res == true) {
            tox_utils_Node *n = tox_utils_list_get(&global_msgv2_outgoing_ft_list,
                                                   friend_pubkey, file_number);

            if (n != NULL) {
                if (((global_msgv2_outgoing_ft_entry *)(n->data))->kind == TOX_FILE_KIND_MESSAGEV2_SEND) {
                    if (length == 0) {
                        // FT finished
                        // remove FT data from list
                        tox_utils_list_remove(&global_msgv2_outgoing_ft_list,
                                              friend_pubkey, file_number);
                    } else {
                        uint8_t *data_ = ((uint8_t *)((global_msgv2_outgoing_ft_entry *)(n->data))->msg_data);
                        uint64_t filesize = ((global_msgv2_outgoing_ft_entry *)(n->data))->file_size;
                        const uint8_t *data = (const uint8_t *)(data_ + position);

                        if (position >= filesize) {
                            free(friend_pubkey);
                            return;
                        }

                        TOX_ERR_FILE_SEND_CHUNK error_send_chunk;
                        bool result = tox_file_send_chunk(tox, friend_number,
                                                          file_number,
                                                          position, data,
                                                          length, &error_send_chunk);
                    }

                    free(friend_pubkey);
                    return;
                }
            }
        }

        free(friend_pubkey);
    }

    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_filechunkrequest) {
        tox_utils_filechunkrequest(tox, friend_number, file_number, position, length, user_data);
        // Messenger *m = (Messenger *)tox;
        // LOGGER_WARNING(m->log, "toxutil:file_recv_control_cb");
    }

    // ------- call the real CB function -------
}

void tox_utils_file_recv_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                            uint32_t kind, uint64_t file_size,
                            const uint8_t *filename, size_t filename_length, void *user_data)
{
    // ------- do messageV2 stuff -------
    if (kind == TOX_FILE_KIND_MESSAGEV2_SEND) {
        global_msgv2_incoming_ft_entry *data = calloc(1, sizeof(global_msgv2_incoming_ft_entry));

        if (data) {
            data->friend_number = friend_number;
            data->file_number = file_number;
            data->kind = kind;
            data->file_size = file_size;
            data->timestamp = current_time_monotonic();

            uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

            if (friend_pubkey) {
                bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

                if (res == true) {
                    tox_utils_housekeeping(tox);
                    tox_utils_list_add(&global_msgv2_incoming_ft_list, friend_pubkey,
                                       file_number, data);
                    // Messenger *m = (Messenger *)tox;
                    // LOGGER_WARNING(m->log, "toxutil:file_recv_cb:TOX_FILE_KIND_MESSAGEV2_SEND:%d:%d",
                    //               (int)friend_number, (int)file_number);
                }

                free(friend_pubkey);
            } else {
                free(data);
            }
        }

        return;
    } else if (kind == TOX_FILE_KIND_MESSAGEV2_ANSWER) {
    } else if (kind == TOX_FILE_KIND_MESSAGEV2_ALTER) {
    } else {
        // ------- do messageV2 stuff -------

        // ------- call the real CB function -------
        if (tox_utils_filerecv) {
            tox_utils_filerecv(tox, friend_number, file_number, kind, file_size,
                               filename, filename_length, user_data);
            // Messenger *m = (Messenger *)tox;
            // LOGGER_WARNING(m->log, "toxutil:file_recv_cb");
        }

        // ------- call the real CB function -------
    }
}

void tox_utils_file_recv_chunk_cb(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                  uint64_t position, const uint8_t *data, size_t length,
                                  void *user_data)
{
    // ------- do messageV2 stuff -------
    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

    if (friend_pubkey) {
        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

        if (res == true) {
            tox_utils_Node *n = tox_utils_list_get(&global_msgv2_incoming_ft_list,
                                                   friend_pubkey, file_number);

            if (n != NULL) {
                if (((global_msgv2_incoming_ft_entry *)(n->data))->kind == TOX_FILE_KIND_MESSAGEV2_SEND) {
                    if (length == 0) {
                        // FT finished
                        if (tox_utils_friend_message_v2) {
                            const uint8_t *data_ = ((uint8_t *)((global_msgv2_incoming_ft_entry *)
                                                                (n->data))->msg_data);
                            const uint64_t size_ = ((global_msgv2_incoming_ft_entry *)
                                                    (n->data))->file_size;
                            tox_utils_friend_message_v2(tox, friend_number, data_, (size_t)size_);
                        }

                        // remove FT data from list
                        tox_utils_list_remove(&global_msgv2_incoming_ft_list,
                                              friend_pubkey, file_number);
                    } else {
                        uint8_t *data_ = ((uint8_t *)((global_msgv2_incoming_ft_entry *)(n->data))->msg_data);
                        memcpy((data_ + position), data, length);
                    }

                    free(friend_pubkey);
                    return;
                }
            }
        }

        free(friend_pubkey);
    }

    // ------- do messageV2 stuff -------

    // ------- call the real CB function -------
    if (tox_utils_filerecvchunk) {
        tox_utils_filerecvchunk(tox, friend_number, file_number,
                                position, data, length, user_data);
        // Messenger *m = (Messenger *)tox;
        // LOGGER_WARNING(m->log, "toxutil:file_recv_chunk_cb");
    }

    // ------- call the real CB function -------
}


bool tox_util_friend_send_msg_receipt_v2(Tox *tox, uint32_t friend_number, uint8_t *msgid, uint32_t ts_sec)
{
    if (msgid) {
        bool friend_has_msgv2 = tox_utils_get_capabilities(tox, friend_number);

        // DEBUG ==========================
        // DEBUG ==========================
        // friend_has_msgv2 = true;
        // DEBUG ==========================
        // DEBUG ==========================

        if (friend_has_msgv2 == true) {
            uint32_t raw_msg_len = tox_messagev2_size(0, (uint32_t)TOX_FILE_KIND_MESSAGEV2_ANSWER, 0);
            uint8_t *raw_message = calloc(1, (size_t)raw_msg_len);

            if (!raw_message) {
                return false;
            }

            bool result = tox_messagev2_wrap(0,
                                             (uint32_t)TOX_FILE_KIND_MESSAGEV2_ANSWER,
                                             0,
                                             NULL, ts_sec,
                                             0,
                                             raw_message,
                                             msgid);

            if (result == true) {
                // ok we have our raw message in "raw_message" and the length in "raw_msg_len"
                // now send it
                const char *filename = "messagev2ack.txt";
                TOX_ERR_FILE_SEND error_send;
                uint32_t file_num_new = tox_file_send(tox, friend_number,
                                                      (uint32_t)TOX_FILE_KIND_MESSAGEV2_ANSWER,
                                                      (uint64_t)raw_msg_len, (const uint8_t *)msgid,
                                                      (const uint8_t *)filename, (size_t)strlen(filename),
                                                      &error_send);

                if ((file_num_new == UINT32_MAX) || (error_send != TOX_ERR_FILE_SEND_OK)) {
                    free(raw_message);
                    return false;
                }

                global_msgv2_outgoing_ft_entry *data = calloc(1, sizeof(global_msgv2_outgoing_ft_entry));

                if (data) {
                    data->friend_number = friend_number;
                    data->file_number = file_num_new;
                    data->kind = TOX_FILE_KIND_MESSAGEV2_ANSWER;
                    data->file_size = raw_msg_len;
                    data->timestamp = current_time_monotonic();

                    if (raw_msg_len <= TOX_MAX_FILETRANSFER_SIZE_MSGV2) {
                        memcpy(data->msg_data, raw_message, raw_msg_len);
                    } else {
                        // HINT: this should never happen
                        memcpy(data->msg_data, raw_message, TOX_MAX_FILETRANSFER_SIZE_MSGV2);
                    }

                    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

                    if (friend_pubkey) {
                        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

                        if (res == true) {
                            tox_utils_housekeeping(tox);
                            tox_utils_list_add(&global_msgv2_outgoing_ft_list, friend_pubkey,
                                               file_num_new, data);
                            Messenger *m = (Messenger *)tox;
                            LOGGER_WARNING(m->log,
                                           "toxutil:tox_util_friend_send_message_v2:TOX_FILE_KIND_MESSAGEV2_ANSWER:%d:%d",
                                           (int)friend_number, (int)file_num_new);
                        }

                        free(friend_pubkey);
                        free(raw_message);
                        return true;

                    } else {
                        free(data);

                        free(raw_message);
                        return false;
                    }
                }

                free(raw_message);
                return false;
            } else {
                free(raw_message);
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
}

int64_t tox_util_friend_send_message_v2(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                                        uint32_t ts_sec, const uint8_t *message, size_t length,
                                        uint8_t *raw_message_back, uint32_t *raw_msg_len_back,
                                        uint8_t *msgid_back,
                                        TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    if (message) {
        bool friend_has_msgv2 = tox_utils_get_capabilities(tox, friend_number);

        // DEBUG ==========================
        // DEBUG ==========================
        // friend_has_msgv2 = true;
        // DEBUG ==========================
        // DEBUG ==========================

        if (friend_has_msgv2 == true) {
            if (error) {
                // TODO: make this better
                // use some "random" error value for now
                *error = TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ;
            }

            // indicate messageV2 was used to send
            if (length > TOX_MESSAGEV2_MAX_TEXT_LENGTH) {
                return -1;
            }

            uint32_t raw_msg_len = tox_messagev2_size((uint32_t)length,
                                   (uint32_t)TOX_FILE_KIND_MESSAGEV2_SEND, 0);

            uint8_t *raw_message = calloc(1, (size_t)raw_msg_len);

            if (!raw_message) {
                return -1;
            }

            uint8_t *msgid = calloc(1, TOX_PUBLIC_KEY_SIZE);

            if (!msgid) {
                free(raw_message);
                return -1;
            }

            bool result = tox_messagev2_wrap((uint32_t)length,
                                             (uint32_t)TOX_FILE_KIND_MESSAGEV2_SEND,
                                             0,
                                             message, ts_sec,
                                             global_ts_ms,
                                             raw_message,
                                             msgid);


// --- DEBUG ---
#if 0
            Messenger *m = (Messenger *)tox;
            char      data_hex_str[5000];
            get_hex((raw_message + 32 + 4 + 2), (raw_msg_len - 32 - 4 - 2), data_hex_str, 5000, 16);
            LOGGER_WARNING(m->log, "%s", data_hex_str);


            LOGGER_WARNING(m->log,
                           "toxutil:tox_util_friend_send_message_v2:0:FT:%d:%d",
                           (int)raw_msg_len, (int)length);
            LOGGER_WARNING(m->log,
                           "toxutil:tox_util_friend_send_message_v2:A:FT:%s",
                           message);
            LOGGER_WARNING(m->log,
                           "toxutil:tox_util_friend_send_message_v2:B:FT:%s",
                           (char *)(raw_message + 32 + 4 + 2));
#endif
// --- DEBUG ---


            // every message should have an increasing "dummy" ms-timestamp part
            global_ts_ms++;

            if (result == true) {
                // ok we have our raw message in "raw_message" and the length in "raw_msg_len"

                // give raw message and the length back to caller
                if (raw_message_back) {
                    memcpy(raw_message_back, raw_message, raw_msg_len);

                    if (raw_msg_len_back) {
                        *raw_msg_len_back = raw_msg_len;
                    }
                }

                // give message id (= message hash) back to caller
                if (msgid_back) {
                    memcpy(msgid_back, msgid, TOX_PUBLIC_KEY_SIZE);
                }

                // now send it
                const char *filename = "messagev2.txt";
                TOX_ERR_FILE_SEND error_send;
                uint32_t file_num_new = tox_file_send(tox, friend_number,
                                                      (uint32_t)TOX_FILE_KIND_MESSAGEV2_SEND,
                                                      (uint64_t)raw_msg_len, (const uint8_t *)msgid,
                                                      (const uint8_t *)filename, (size_t)strlen(filename),
                                                      &error_send);

                if ((file_num_new == UINT32_MAX) || (error_send != TOX_ERR_FILE_SEND_OK)) {
                    free(raw_message);
                    free(msgid);

                    return -1;
                }

                global_msgv2_outgoing_ft_entry *data = calloc(1, sizeof(global_msgv2_outgoing_ft_entry));

                if (data) {
                    data->friend_number = friend_number;
                    data->file_number = file_num_new;
                    data->kind = TOX_FILE_KIND_MESSAGEV2_SEND;
                    data->file_size = raw_msg_len;
                    data->timestamp = current_time_monotonic();

                    if (raw_msg_len <= TOX_MAX_FILETRANSFER_SIZE_MSGV2) {
                        memcpy(data->msg_data, raw_message, raw_msg_len);
                    } else {
                        // HINT: this should never happen
                        memcpy(data->msg_data, raw_message, TOX_MAX_FILETRANSFER_SIZE_MSGV2);
                    }

                    uint8_t *friend_pubkey = calloc(1, TOX_PUBLIC_KEY_SIZE);

                    if (friend_pubkey) {
                        bool res = tox_utils_friendnum_to_pubkey(tox, friend_pubkey, friend_number);

                        if (res == true) {
                            tox_utils_housekeeping(tox);
                            tox_utils_list_add(&global_msgv2_outgoing_ft_list, friend_pubkey,
                                               file_num_new, data);
                            Messenger *m = (Messenger *)tox;
                            LOGGER_WARNING(m->log,
                                           "toxutil:tox_util_friend_send_message_v2:TOX_FILE_KIND_MESSAGEV2_SEND:%d:%d",
                                           (int)friend_number, (int)file_num_new);
                        }

                        free(friend_pubkey);
                    } else {
                        free(data);
                    }
                }

                free(raw_message);
                free(msgid);

                if (error) {
                    *error = TOX_ERR_FRIEND_SEND_MESSAGE_OK;
                }
            }

            return -1;
        } else {
            // wrap old message send function

            Messenger *m = (Messenger *)tox;
            LOGGER_WARNING(m->log,
                           "toxutil:tox_util_friend_send_message_v2:WRAP-OLD:%d",
                           (int)friend_number);

            return tox_friend_send_message(tox, friend_number, type, message,
                                           length, error);
        }
    } else {
        return -1;
    }
}





