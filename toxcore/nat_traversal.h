/* nat_traversal.h -- Functions to traverse a NAT (UPnP, NAT-PMP).
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NAT_TRAVERSAL_H
#define NAT_TRAVERSAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "logger.h"
#include "tox.h"


/**
 * The protocol that will be used by the nat traversal.
 */
typedef enum NAT_TRAVERSAL_PROTO {

    NAT_TRAVERSAL_UDP,

    NAT_TRAVERSAL_TCP,

} NAT_TRAVERSAL_PROTO;


/* Setup port forwarding */
void nat_map_port(Logger *log, TOX_TRAVERSAL_TYPE traversal_type, NAT_TRAVERSAL_PROTO proto, uint16_t port);

#endif
