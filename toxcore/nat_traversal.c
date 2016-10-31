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
#include <stdlib.h>
#include <string.h>

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
static bool upnp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port, NAT_TRAVERSAL_STATUS *status)
{
    LOGGER_DEBUG(log, "Attempting to set up UPnP port forwarding");

    bool ret = false;
    int error;

#if MINIUPNPC_API_VERSION < 14
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, 0, &error);
#else
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, 0, 2, &error);
#endif

    if (error) {
        *status = NAT_TRAVERSAL_ERR_DISCOVERY_FAIL;
        LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status), strupnperror(error));
        return false;
    }

    struct UPNPUrls urls;

    struct IGDdatas data;

    char lanaddr[64];

    error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));

    freeUPNPDevlist(devlist);

    switch (error) {
        case 0:
            *status = NAT_TRAVERSAL_ERR_NO_IGD_FOUND;
            LOGGER_WARNING(log, "UPnP: %s ", str_nat_traversal_error(*status));
            break;

        case 1:
            LOGGER_INFO(log, "UPnP: A valid IGD has been found");

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
                    *status = NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
                    LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
                    FreeUPNPUrls(&urls);
                    return false;
            }

            if (error) {
                *status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
                LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status), strupnperror(error));
            } else {
                *status = NAT_TRAVERSAL_OK;
                LOGGER_INFO(log, "UPnP: %s (port %d)", str_nat_traversal_error(*status), port);
                ret = true;
            }

            break;

        case 2:
            *status = NAT_TRAVERSAL_ERR_IGD_NO_CONN;
            LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
            break;

        case 3:
            *status = NAT_TRAVERSAL_ERR_NOT_IGD;
            LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
            break;

        default:
            *status = NAT_TRAVERSAL_ERR_UNKNOWN;
            LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status), strupnperror(error));
            break;
    }

    FreeUPNPUrls(&urls);

    return ret;
}
#endif /* HAVE_LIBMINIUPNPC */


#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
static bool natpmp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port, NAT_TRAVERSAL_STATUS *status)
{
    LOGGER_DEBUG(log, "Attempting to set up NAT-PMP port forwarding");

    natpmp_t natpmp;
    int error = initnatpmp(&natpmp, 0, 0);

    if (error) {
        *status = NAT_TRAVERSAL_ERR_INIT_FAIL;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        return false;
    }

    switch (proto) {
        case NAT_TRAVERSAL_UDP:
            error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 3600);
            break;

        case NAT_TRAVERSAL_TCP:
            error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
            break;

        default:
            *status = NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
            LOGGER_WARNING(log, "NAT-PMP: %s", str_nat_traversal_error(*status));
            closenatpmp(&natpmp);
            return false;
    }

    // From line 171 of natpmp.h: "12 = OK (size of the request)"
    if (error != 12) {
        *status = NAT_TRAVERSAL_ERR_SEND_REQ_FAIL;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        closenatpmp(&natpmp);
        return false;
    }

    natpmpresp_t resp;
    error = readnatpmpresponseorretry(&natpmp, &resp);

    for (; error == NATPMP_TRYAGAIN; error = readnatpmpresponseorretry(&natpmp, &resp)) {
        sleep(1);
    }

    bool ret;

    if (error) {
        *status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        ret = false;
    } else {
        *status = NAT_TRAVERSAL_OK;
        LOGGER_INFO(log, "NAT-PMP: %s (port %d)", str_nat_traversal_error(*status), port);
        ret = true;
    }

    closenatpmp(&natpmp);

    return ret;
}
#endif /* HAVE_LIBNATPMP */


/* Setup port forwarding */
bool nat_map_port(Logger *log, TOX_TRAVERSAL_TYPE traversal_type, NAT_TRAVERSAL_PROTO proto, uint16_t port,
                  nat_traversal_status_t *status)
{
    if (status != NULL) {
        status->upnp = NAT_TRAVERSAL_ERR_DISABLED;
        status->natpmp = NAT_TRAVERSAL_ERR_DISABLED;
    }

#if !defined(HAVE_LIBMNIUPNPC) && !defined(HAVE_LIBNATPMP)
    // Silence warnings if no libraries are found
    UNUSED(log);
    UNUSED(proto);
    UNUSED(port);

    return false;
#else
    bool upnp = true;
    bool natpmp = true;

    if ((traversal_type != TOX_TRAVERSAL_TYPE_NONE) && (traversal_type != TOX_TRAVERSAL_TYPE_UPNP)
            && (traversal_type != TOX_TRAVERSAL_TYPE_NATPMP) && (traversal_type != TOX_TRAVERSAL_TYPE_ALL)) {
        if (status != NULL) {
            status->upnp = NAT_TRAVERSAL_ERR_UNKNOWN_TYPE;
            status->natpmp = NAT_TRAVERSAL_ERR_UNKNOWN_TYPE;
        }

        return false;
    }

#ifdef HAVE_LIBMINIUPNPC

    if ((traversal_type == TOX_TRAVERSAL_TYPE_UPNP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        if (status != NULL) {
            upnp = upnp_map_port(log, proto, port, &status->upnp);
        } else {
            NAT_TRAVERSAL_STATUS status;
            upnp = upnp_map_port(log, proto, port, &status);
        }
    }

#endif /* HAVE_LIBMINIUPNPC */
#ifdef HAVE_LIBNATPMP

    if ((traversal_type == TOX_TRAVERSAL_TYPE_NATPMP) || (traversal_type == TOX_TRAVERSAL_TYPE_ALL)) {
        if (status != NULL) {
            natpmp = natpmp_map_port(log, proto, port, &status->natpmp);
        } else {
            NAT_TRAVERSAL_STATUS status;
            natpmp = natpmp_map_port(log, proto, port, &status);
        }
    }

#endif /* HAVE_LIBNATPMP */

    return upnp && natpmp;
#endif /* !HAVE_LIBMINIUPNPC && !HAVE_LIBNATPMP */
}


/* Return error string from status */
const char *str_nat_traversal_error(NAT_TRAVERSAL_STATUS status)
{
    switch (status) {
        case NAT_TRAVERSAL_OK:
            return "Port mapped successfully";

        case NAT_TRAVERSAL_ERR_DISABLED:
            return "Feature not available";

        case NAT_TRAVERSAL_ERR_UNKNOWN_TYPE:
            return "Unknown traversal type";

        case NAT_TRAVERSAL_ERR_UNKNOWN_PROTO:
            return "Unknown NAT_TRAVERSAL_PROTO";

        case NAT_TRAVERSAL_ERR_MAPPING_FAIL:
            return "Port mapping failed";

        case NAT_TRAVERSAL_ERR_DISCOVERY_FAIL:
            return "Discovery failed";

        case NAT_TRAVERSAL_ERR_NO_IGD_FOUND:
            return "No IGD was found";

        case NAT_TRAVERSAL_ERR_IGD_NO_CONN:
            return "IGD found but reported as not connected";

        case NAT_TRAVERSAL_ERR_NOT_IGD:
            return "Device found but not recognised as IGD";

        case NAT_TRAVERSAL_ERR_INIT_FAIL:
            return "Initialization failed";

        case NAT_TRAVERSAL_ERR_SEND_REQ_FAIL:
            return "Send request failed";

        case NAT_TRAVERSAL_ERR_UNKNOWN:
        default:
            return "Unknown error";
    }
}
