/*
 * Copyright © 2018 zoff@zoff.cc
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

#ifndef DUMMY_NTP_H
#define DUMMY_NTP_H

#include <stdbool.h>
#include <stdint.h>

/* NTP formula implementation */
bool dntp_drift(int64_t *current_offset, const int64_t new_offset, const int64_t max_offset_for_drift);
int64_t dntp_calc_offset(uint32_t remote_tstart, uint32_t remote_tend,
                         uint32_t local_tstart, uint32_t local_tend);
uint32_t dntp_calc_roundtrip_delay(uint32_t remote_tstart, uint32_t remote_tend,
                                   uint32_t local_tstart, uint32_t local_tend);

#endif /* DUMMY_NTP_H */
