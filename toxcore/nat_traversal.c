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

#ifdef HAVE_LIBMINIUPNPC
#include <stdio.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#ifdef HAVE_LIBNATPMP
#include <unistd.h>
#include <natpmp.h>
#endif

#include "nat_traversal.h"

#define UNUSED(x) (void)(x)

#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
void upnp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    int error;
    struct UPNPDev *devlist = NULL;

    LOGGER_DEBUG(log, "Attempting to set up UPnP port forwarding");

#if MINIUPNPC_API_VERSION < 14
    devlist = upnpDiscover(1000, NULL, NULL, 0, 0, &error);
#else
    devlist = upnpDiscover(1000, NULL, NULL, 0, 0, 2, &error);
#endif

    if (error) {
        LOGGER_WARNING(log, "UPnP discovery failed (%s)", strupnperror(error));
        return;
    }

    struct UPNPUrls urls;

    struct IGDdatas data;

    char lanaddr[64];

    error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));

    freeUPNPDevlist(devlist);

    switch (error) {
        case 0:
            LOGGER_WARNING(log, "No IGD was found.");
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
                    break;
            }

            if (error) {
                LOGGER_WARNING(log, "UPnP port mapping failed (%s)", strupnperror(error));
            } else {
                LOGGER_INFO(log, "UPnP mapped port %d", port);
            }

            break;

        case 2:
            LOGGER_WARNING(log, "IGD was found but reported as not connected.");
            break;

        case 3:
            LOGGER_WARNING(log, "UPnP device was found but not recoginzed as IGD.");
            break;

        default:
            LOGGER_WARNING(log, "Unknown error finding IGD (%s)", strupnperror(error));
            break;
    }

    FreeUPNPUrls(&urls);
}
#endif


#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
void natpmp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    int error;
    natpmp_t natpmp;
    natpmpresp_t resp;

    LOGGER_DEBUG(log, "Attempting to set up NAT-PMP port forwarding");

    error = initnatpmp(&natpmp, 0, 0);

    if (error) {
        LOGGER_WARNING(log, "NAT-PMP initialization failed (error = %d)", error);
        return;
    }

    if (proto == NAT_TRAVERSAL_UDP) {
        error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 3600);
    } else if (proto == NAT_TRAVERSAL_TCP) {
        error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
    } else {
        LOGGER_WARNING(log, "NAT-PMP port mapping failed (unknown NAT_TRAVERSAL_PROTO)");
        closenatpmp(&natpmp);
        return;
    }

    // From line 171 of natpmp.h: "12 = OK (size of the request)"
    if (error != 12) {
        LOGGER_WARNING(log, "NAT-PMP send request failed (error = %d)", error);
        closenatpmp(&natpmp);
        return;
    }

    error = readnatpmpresponseorretry(&natpmp, &resp);

    for (; error == NATPMP_TRYAGAIN ; error = readnatpmpresponseorretry(&natpmp, &resp)) {
        sleep(1);
    }

    if (error) {
        LOGGER_WARNING(log, "NAT-PMP port mapping failed (error = %d)", error);
    } else {
        LOGGER_INFO(log, "NAT-PMP mapped port %d", port);
    }

    closenatpmp(&natpmp);

}
#endif


/* Setup port forwarding */
void nat_map_port(Logger *log, TOX_TRAVERSAL_TYPE traversal_type, NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
#ifdef HAVE_LIBMINIUPNPC

    if ((traversal_type == TOX_TRAVERSAL_TYPE_UPNP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        upnp_map_port(log, proto, port);
    }

#endif
#ifdef HAVE_LIBNATPMP

    if ((traversal_type == TOX_TRAVERSAL_TYPE_NATPMP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        natpmp_map_port(log, proto, port);
    }

#endif

    // Silence warnings if no libraries are found
    UNUSED(log);
    UNUSED(traversal_type);
    UNUSED(proto);
    UNUSED(port);
}
