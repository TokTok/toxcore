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

#include <assert.h>


// ----------- FUNCS -----------
static void tox_utils_send_capabilities(Tox *tox, uint32_t friendnumber)
{
    uint8_t data[3];
    data[0] = 170; // packet ID
    data[1] = 33;
    data[2] = 44;
    TOX_ERR_FRIEND_CUSTOM_PACKET error;
    tox_friend_send_lossless_packet(tox, friendnumber, data, 3, &error);
}

static void tox_utils_receive_capabilities(Tox *tox, uint32_t friendnumber, const uint8_t *data,
        size_t length)
{
    if (length == 3)
    {
        if ((data[0] == 170) && (data[1] == 33) && (data[2] == 44))
        {
            // friend has message V2 capability
            // TODO: write it into a list now
            Messenger *m = (Messenger *)tox;
            LOGGER_WARNING(m->log, "toxutil:receive_capabilities fnum=%d data=%d% d %d",
                    (int)friendnumber, (int)data[0], (int)data[1], (int)data[2]);
        }
    }
}

// ----------- FUNCS -----------




// --- set callbacks ---
void (*tox_utils_friend_connectionstatuschange)(struct Tox *tox, uint32_t,
        unsigned int, void *) = NULL;

void tox_utils_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
	tox_utils_friend_connectionstatuschange = (void (*)(Tox *tox, uint32_t,
            unsigned int, void *))callback;
    Messenger *m = (Messenger *)tox;
    LOGGER_WARNING(m->log, "toxutil:set callback");
}


// /home/pi/inst//include/tox/tox.h:2957:6: note: expected
// ‘void (*)(struct Tox *, uint32_t,  const uint8_t *, size_t,  void *)’ but argument is of
// type
// ‘void (*)(struct Tox *, void (*)(struct Tox *, uint32_t,  const uint8_t *, size_t,  void *))’
 void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback);



void (*tox_utils_friend_losslesspacket)(struct Tox *tox, uint32_t, const uint8_t *,
        size_t, void *) = NULL;

void tox_utils_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback)
{
	tox_utils_friend_losslesspacket = (void (*)(Tox *tox, uint32_t,
            const uint8_t *, size_t, void *))callback;
}

// --- set callbacks ---



void tox_utils_friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data,
        size_t length, void *user_data)
{
	// ------- do messageV2 stuff -------
    tox_utils_receive_capabilities(tox, friend_number, data, length);
	// ------- do messageV2 stuff -------

	// ------- call the real CB function -------
	if (tox_utils_friend_losslesspacket)
	{
		tox_utils_friend_losslesspacket(tox, friend_number, data, length, user_data);
	}
	// ------- call the real CB function -------
}



void tox_utils_friend_connection_status_cb(Tox *tox, uint32_t friendnumber,
        TOX_CONNECTION connection_status, void *user_data)
{
	// ------- do messageV2 stuff -------
    tox_utils_send_capabilities(tox, friendnumber);
	// ------- do messageV2 stuff -------

	// ------- call the real CB function -------
	if (tox_utils_friend_connectionstatuschange)
	{
		tox_utils_friend_connectionstatuschange(tox, friendnumber, connection_status, user_data);
        Messenger *m = (Messenger *)tox;
        LOGGER_WARNING(m->log, "toxutil:friend_connectionstatuschange");
	}
	// ------- call the real CB function -------
}













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


typedef struct tox_utils_Node {
    uint32_t key;
    void *data;
    struct tox_utils_Node *next;
} tox_utils_Node;

typedef struct tox_utils_List {
    uint32_t size;
    tox_utils_Node *head; 
} tox_utils_List;



static void tox_utils_init_list(tox_utils_List *l)
{
    l->size = 0;
    l->head = NULL;
}

static void tox_utils_add(tox_utils_List *l, uint32_t key, void *data)
{
    tox_utils_Node *n = calloc(1, sizeof(tox_utils_Node));

    n->key = key;
    n->data = data;
    if (l->head == NULL)
    {
        n->next = NULL;
    }
    else
    {
        n->next = l->head;
    }

    l->head = n;
    l->size++;
}

static void tox_utils_remove(tox_utils_List *l, uint32_t key)
{
    tox_utils_Node *head = l->head;
    tox_utils_Node *prev_ = NULL;
    tox_utils_Node *next_ = NULL;
    while (head)
    {
        prev_ = head;
        next_ = head->next;
        
        if (head->key == key)
        {
            if (prev_)
            {
                if (next_)
                {
                    prev_->next = next_;
                }
                else
                {
                    prev_->next = NULL;
                }
            }
            
            if (head->data)
            {
                free(head->data);
            }
            
            free(head);
            l->size--;

            if (l->size == 0)
            {
                // list empty
                // TODO: more to do here?
                l->head = NULL;
            }

            break;
        }

        head = next_;
    }
}

// ------------ UTILS ------------


