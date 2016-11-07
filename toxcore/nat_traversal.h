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

#include <stdbool.h>
#include <stdint.h>

#include "logger.h"


/**
 * Allowed traversal types.
 */
enum TRAVERSAL_TYPE {

    TRAVERSAL_TYPE_UPNP = 1,

    TRAVERSAL_TYPE_NATPMP = 2,

};

/**
 * The protocol that will be used by the nat traversal.
 */
typedef enum NAT_TRAVERSAL_PROTO {

    NAT_TRAVERSAL_UDP,

    NAT_TRAVERSAL_TCP,

} NAT_TRAVERSAL_PROTO;

/**
 * Possible status values.
 */
typedef enum NAT_TRAVERSAL_STATUS {

    /* Port mapped successfully */
    NAT_TRAVERSAL_OK,

    /* UPnP/NAT-PMP not compiled */
    NAT_TRAVERSAL_ERR_DISABLED,

    /* Unknown error */
    NAT_TRAVERSAL_ERR_UNKNOWN,

    /* Unknown protocol specified by user */
    NAT_TRAVERSAL_ERR_UNKNOWN_PROTO,

    /* UPnP/NAT-PMP port mapping failed */
    NAT_TRAVERSAL_ERR_MAPPING_FAIL,

    /* UPnP discovery failed */
    NAT_TRAVERSAL_ERR_DISCOVERY_FAIL,

    /* UPnP no IGD found */
    NAT_TRAVERSAL_ERR_NO_IGD_FOUND,

    /* UPnP IGD found, but not connected */
    NAT_TRAVERSAL_ERR_IGD_NO_CONN,

    /* UPnP device found, but not IGD */
    NAT_TRAVERSAL_ERR_NOT_IGD,

    /* NAT-PMP initialization failed */
    NAT_TRAVERSAL_ERR_INIT_FAIL,

    /* NAT-PMP send request failed */
    NAT_TRAVERSAL_ERR_SEND_REQ_FAIL,

} NAT_TRAVERSAL_STATUS;

/**
 * Struct to report nat traversal success/fail.
 */
typedef struct nat_traversal_status_t {

    NAT_TRAVERSAL_STATUS upnp;

    NAT_TRAVERSAL_STATUS natpmp;

} nat_traversal_status_t;


/* Setup port forwarding */
bool nat_map_port(Logger *log, uint8_t traversal_type, NAT_TRAVERSAL_PROTO proto, uint16_t port,
                  nat_traversal_status_t *status);

/* Return error string from status */
const char *str_nat_traversal_error(NAT_TRAVERSAL_STATUS status);

#endif
