/* nat_traversal.c -- Functions to traverse a NAT (UPnP, NAT-PMP).
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "nat_traversal.h"

#include <stdbool.h>

#ifdef HAVE_LIBMINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#include <stdio.h>
#endif

#ifdef HAVE_LIBNATPMP
#include <natpmp.h>
#include <unistd.h>
#endif

#define UNUSED(x) (void)(x)

#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
NAT_TRAVERSAL_STATUS upnp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    LOGGER_DEBUG(log, "Attempting to set up UPnP port forwarding");

    int error;
    NAT_TRAVERSAL_STATUS status;

#if MINIUPNPC_API_VERSION < 14
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, 0, &error);
#else
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, 0, 2, &error);
#endif

    if (error) {
        LOGGER_WARNING(log, "UPnP discovery failed (%s)", strupnperror(error));
        return NAT_TRAVERSAL_ERR_DISCOVERY_FAIL;
    }

    struct UPNPUrls urls;

    struct IGDdatas data;

    char lanaddr[64];

    error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));

    freeUPNPDevlist(devlist);

    switch (error) {
        case 0:
            LOGGER_WARNING(log, "No IGD was found.");
            status = NAT_TRAVERSAL_ERR_NO_IGD_FOUND;
            break;

        case 1:
            LOGGER_INFO(log, "A valid IGD has been found.");

            char portstr[10];
            snprintf(portstr, sizeof(portstr), "%d", port);

            switch (proto) {
                case NAT_TRAVERSAL_UDP:
                    error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "UDP", 0, "0");
                    break;

                case NAT_TRAVERSAL_TCP:
                    error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "TCP", 0, "0");
                    break;

                default:
                    LOGGER_WARNING(log, "UPnP port mapping failed (unknown NAT_TRAVERSAL_PROTO)");
                    FreeUPNPUrls(&urls);
                    return NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
            }

            if (error) {
                LOGGER_WARNING(log, "UPnP port mapping failed (%s)", strupnperror(error));
                status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
            } else {
                LOGGER_INFO(log, "UPnP mapped port %d", port);
                status = NAT_TRAVERSAL_OK;
            }

            break;

        case 2:
            LOGGER_WARNING(log, "IGD was found but reported as not connected.");
            status = NAT_TRAVERSAL_ERR_IGD_NO_CONN;
            break;

        case 3:
            LOGGER_WARNING(log, "UPnP device was found but not recognised as IGD.");
            status = NAT_TRAVERSAL_ERR_NOT_IGD;
            break;

        default:
            LOGGER_WARNING(log, "Unknown error finding IGD (%s)", strupnperror(error));
            status = NAT_TRAVERSAL_ERR_UNKNOWN;
            break;
    }

    FreeUPNPUrls(&urls);

    return status;
}
#endif


#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
NAT_TRAVERSAL_STATUS natpmp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    LOGGER_DEBUG(log, "Attempting to set up NAT-PMP port forwarding");

    natpmp_t natpmp;
    int error = initnatpmp(&natpmp, 0, 0);

    if (error) {
        LOGGER_WARNING(log, "NAT-PMP initialization failed (%s)", strnatpmperr(error));
        return NAT_TRAVERSAL_ERR_INIT_FAIL;
    }

    switch (proto) {
        case NAT_TRAVERSAL_UDP:
            error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 3600);
            break;

        case NAT_TRAVERSAL_TCP:
            error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
            break;

        default:
            LOGGER_WARNING(log, "NAT-PMP port mapping failed (unknown NAT_TRAVERSAL_PROTO)");
            closenatpmp(&natpmp);
            return NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
    }

    // From line 171 of natpmp.h: "12 = OK (size of the request)"
    if (error != 12) {
        LOGGER_WARNING(log, "NAT-PMP send request failed (%s)", strnatpmperr(error));
        closenatpmp(&natpmp);
        return NAT_TRAVERSAL_ERR_SEND_REQ_FAIL;
    }

    natpmpresp_t resp;
    error = readnatpmpresponseorretry(&natpmp, &resp);

    for (; error == NATPMP_TRYAGAIN; error = readnatpmpresponseorretry(&natpmp, &resp)) {
        sleep(1);
    }

    NAT_TRAVERSAL_STATUS status;

    if (error) {
        LOGGER_WARNING(log, "NAT-PMP port mapping failed (%s)", strnatpmperr(error));
        status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
    } else {
        LOGGER_INFO(log, "NAT-PMP mapped port %d", port);
        status = NAT_TRAVERSAL_OK;
    }

    closenatpmp(&natpmp);

    return status;
}
#endif


/* Setup port forwarding */
void nat_map_port(Logger *log, TOX_TRAVERSAL_TYPE traversal_type, NAT_TRAVERSAL_PROTO proto, uint16_t port,
                  nat_traversal_status_t *status)
{
    bool use_status = (status != NULL) ? true : false;

    if (use_status) {
        status->upnp = NAT_TRAVERSAL_ERR_DISABLED;
        status->natpmp = NAT_TRAVERSAL_ERR_DISABLED;
    }

    if ((traversal_type != TOX_TRAVERSAL_TYPE_NONE) && (traversal_type != TOX_TRAVERSAL_TYPE_UPNP)
            && (traversal_type != TOX_TRAVERSAL_TYPE_NATPMP) && (traversal_type != TOX_TRAVERSAL_TYPE_ALL)) {
        if (use_status) {
            status->upnp = NAT_TRAVERSAL_ERR_UNKNOWN_TYPE;
            status->natpmp = NAT_TRAVERSAL_ERR_UNKNOWN_TYPE;
        }

        return;
    }

#ifdef HAVE_LIBMINIUPNPC

    if ((traversal_type == TOX_TRAVERSAL_TYPE_UPNP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        if (use_status) {
            status->upnp = upnp_map_port(log, proto, port);
        } else {
            upnp_map_port(log, proto, port);
        }
    }

#endif
#ifdef HAVE_LIBNATPMP

    if ((traversal_type == TOX_TRAVERSAL_TYPE_NATPMP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        if (use_status) {
            status->natpmp = natpmp_map_port(log, proto, port);
        } else {
            natpmp_map_port(log, proto, port);
        }
    }

#endif

    // Silence warnings if no libraries are found
    UNUSED(log);
    UNUSED(proto);
    UNUSED(port);
}
