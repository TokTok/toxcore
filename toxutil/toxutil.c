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

#include "Messenger.h"

#include "logger.h"
#include "network.h"
#include "util.h"
#include "tox.h"

#include <assert.h>

// --- set callbacks ---
void (*tox_utils_friend_connectionstatuschange)(struct Tox *tox, uint32_t, unsigned int, void *);

void tox_utils_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
	tox_utils_friend_connectionstatuschange = (void (*)(Tox *tox, uint32_t, unsigned int, void *))callback;
    Messenger *m = (Messenger *)tox;
    LOGGER_WARNING(m->log, "toxutil:set callback");
}
// --- set callbacks ---



void tox_utils_friend_connection_status_cb(Tox *tox, uint32_t friendnumber, TOX_CONNECTION connection_status, void *user_data)
{
	// ------- do messageV2 stuff -------

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



