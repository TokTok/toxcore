/*
 * Copyright © 2019 The TokTok team.
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

#include "timed_auth.h"

#include <string.h>

#include "ccompat.h"

static void create_timed_auth_to_hash(const Mono_Time *mono_time, uint16_t timeout, bool previous, const uint8_t *data,
                                      uint16_t length, uint8_t *to_hash)
{
    const uint64_t t = (mono_time_get(mono_time) / timeout) - previous;
    memcpy(to_hash, &t, sizeof(t));
    memcpy(to_hash + sizeof(t), data, length);
}

void generate_timed_auth(const Mono_Time *mono_time, uint16_t timeout, const uint8_t *key,
                         const uint8_t *data, uint16_t length, uint8_t *timed_auth)
{
    VLA(uint8_t, to_hash, sizeof(uint64_t) + length);
    create_timed_auth_to_hash(mono_time, timeout, false, data, length, to_hash);
    crypto_hmac(timed_auth, key, to_hash, SIZEOF_VLA(to_hash));
}

bool check_timed_auth(const Mono_Time *mono_time, uint16_t timeout, const uint8_t *key, const uint8_t *data,
                      uint16_t length, const uint8_t *timed_auth)
{
    VLA(uint8_t, to_hash, sizeof(uint64_t) + length);

    for (uint8_t i = 0; i < 2; ++i) {
        create_timed_auth_to_hash(mono_time, timeout, i, data, length, to_hash);

        if (crypto_hmac_verify(timed_auth, key, to_hash, SIZEOF_VLA(to_hash))) {
            return true;
        }
    }

    return false;
}
