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
#include "util.h"

#ifdef HAVE_LIBMINIUPNPC
//#include <miniupnpc/miniupnpc-async.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#include <stdio.h>
#include "../toxupnp/toxupnp.h"
#endif

#ifdef HAVE_LIBNATPMP
#define ENABLE_STRNATPMPERR
#include <natpmp.h>
#include <unistd.h>
#endif

#define UNUSED(x) (void)(x)
#define NAT_TRAVERSAL_LEASE_TIMEOUT 60
#define NAT_TRAVERSAL_TRYAGAIN_TIMEOUT 1


/**
 * Allowed traversal types (they are bitmasks).
 */
typedef enum TRAVERSAL_TYPE {

    TRAVERSAL_TYPE_NONE = 0,

    TRAVERSAL_TYPE_UPNP = 1,

    TRAVERSAL_TYPE_NATPMP = 2,

} TRAVERSAL_TYPE;

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

    /* NAT-PMP waiting for reply */
    NAT_TRAVERSAL_TRYAGAIN,

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


#if defined(HAVE_LIBMINIUPNPC) || defined(HAVE_LIBNATPMP)
/* Return error string from status */
static const char *str_nat_traversal_error(NAT_TRAVERSAL_STATUS status)
{
    switch (status) {
        case NAT_TRAVERSAL_OK:
            return "Port mapped successfully";

        case NAT_TRAVERSAL_TRYAGAIN:
            return "Waiting for reply";

        case NAT_TRAVERSAL_ERR_DISABLED:
            return "Feature not available";

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
#endif /* HAVE_LIBMINIUPNPC || HAVE_LIBNATPMP */


#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
static bool upnp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port, uint32_t lifetime, bool ipv6_enabled,
                          UPNPDiscoverOpts *opts, NAT_TRAVERSAL_STATUS *status)
{
    LOGGER_INFO(log, "Attempting to set up UPnP port forwarding");

    bool ret = false;
    int error;

    /*#if MINIUPNPC_API_VERSION < 14
        struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, ipv6_enabled, &error);
    #else
        struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, ipv6_enabled, 2, &error);
    #endif

        if (error) {
            *status = NAT_TRAVERSAL_ERR_DISCOVERY_FAIL;
            LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status), strupnperror(error));
            return false;
        }*/

    error = upnpDiscoverAsyncGetStatus(opts);

    if (error == UPNPDISCOVER_RUNNING) {
        *status = NAT_TRAVERSAL_TRYAGAIN;
        LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
        return false;
    } else if (error) {
        *status = NAT_TRAVERSAL_ERR_DISCOVERY_FAIL;
        LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status), strupnperror(error));
        upnpDiscoverAsyncSetDelay(opts, 1000);
        upnpDiscoverAsyncSetIPv6(opts, ipv6_enabled);
        upnpDiscoverAsync(opts);
        return false;
    }

    /*if (upnp->state == EFinalized) {
        error = upnpc_init(upnp, NULL);

        if (error < 0) {
            *status = NAT_TRAVERSAL_ERR_INIT_FAIL;
            LOGGER_WARNING(log, "UPnP: %s (%d)", str_nat_traversal_error(*status), error);

            return false;
        }
    } else if ((upnp->status != EReady) && (upnp->status != EError)) {
        *status = NAT_TRAVERSAL_TRYAGAIN;
        LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));

        return false;
    }

    if (upnp->state == EReady) {
        if (upnp->http_response_code == 200) {
            *status = NAT_TRAVERSAL_OK;
            LOGGER_INFO(log, "UPnP: %s (port %d)", str_nat_traversal_error(*status), port);

            upnpc_finalize(upnp);

            return true;
        } else {
            *status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
            LOGGER_WARNING(log, "UPnP: %s (%s)", str_nat_traversal_error(*status),
                           GetValueFromNameValueList(&upnp->soap_response_data, "errorDescription"));
        }
    } else {
        *status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
        LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
    }

    switch (proto) {
        case NAT_TRAVERSAL_UDP:
            upnpc_add_port_mapping(upnp, NULL, port, port, "", "UDP", "Tox", lifetime);
            break;

        case NAT_TRAVERSAL_TCP:
            upnpc_add_port_mapping(upnp, NULL, port, port, "", "TCP", "Tox", lifetime);
            break;

        default:
            *status = NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
            LOGGER_WARNING(log, "UPnP: %s", str_nat_traversal_error(*status));
            break;
    }

    return false;*/

    struct UPNPUrls urls;

    struct IGDdatas data;

    char lanaddr[64];

    //error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    error = UPNP_GetValidIGDAsync(opts, &urls, &data, lanaddr, sizeof(lanaddr));

    //freeUPNPDevlist(devlist);
    upnpDiscoverAsyncFreeDevlist(opts);

    switch (error) {
        case 0:
            *status = NAT_TRAVERSAL_ERR_NO_IGD_FOUND;
            LOGGER_WARNING(log, "UPnP: %s ", str_nat_traversal_error(*status));
            return false;

        case 1:
            LOGGER_INFO(log, "UPnP: A valid IGD has been found");

            char portstr[10], lifetimestr[10];
            snprintf(portstr, sizeof(portstr), "%d", port);
            snprintf(lifetimestr, sizeof(lifetimestr), "%d", lifetime);

            switch (proto) {
                case NAT_TRAVERSAL_UDP:
                    error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "UDP", 0,
                                                lifetimestr);
                    break;

                case NAT_TRAVERSAL_TCP:
                    error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "TCP", 0,
                                                lifetimestr);
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


/* Renew UDP UPnP mapped ports */
static void do_upnp_map_port_udp(Messenger *m)
{
    NAT_TRAVERSAL_STATUS status;

    if ((m->nat_traversal.upnp_udp_ip4_retries > 0) && is_timeout(m->nat_traversal.upnp_udp_ip4_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_UDP, m->net->port, NAT_TRAVERSAL_LEASE_TIMEOUT, false,
                      (UPNPDiscoverOpts *)m->nat_traversal.upnp_udp_ip4, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_udp_ip4_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            m->nat_traversal.upnp_udp_ip4_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
        } else {
            m->nat_traversal.upnp_udp_ip4_retries--;
        }
    }

    if (m->options.ipv6enabled && (m->nat_traversal.upnp_udp_ip6_retries > 0)
            && is_timeout(m->nat_traversal.upnp_udp_ip6_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_UDP, m->net->port, NAT_TRAVERSAL_LEASE_TIMEOUT, true,
                      (UPNPDiscoverOpts *)m->nat_traversal.upnp_udp_ip6, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_udp_ip6_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            m->nat_traversal.upnp_udp_ip6_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
        } else {
            m->nat_traversal.upnp_udp_ip6_retries--;
        }
    }
}


/* Renew TCP UPnP mapped ports */
static void do_upnp_map_port_tcp(Messenger *m)
{
    NAT_TRAVERSAL_STATUS status;

    if ((m->nat_traversal.upnp_tcp_ip4_retries > 0) && is_timeout(m->nat_traversal.upnp_tcp_ip4_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_TCP, m->options.tcp_server_port, NAT_TRAVERSAL_LEASE_TIMEOUT, false,
                      (UPNPDiscoverOpts *) m->nat_traversal.upnp_tcp_ip4, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_tcp_ip4_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            m->nat_traversal.upnp_tcp_ip4_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
        } else {
            m->nat_traversal.upnp_tcp_ip4_retries--;
        }
    }

    if (m->options.ipv6enabled && (m->nat_traversal.upnp_tcp_ip6_retries > 0)
            && is_timeout(m->nat_traversal.upnp_tcp_ip6_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_TCP, m->options.tcp_server_port, NAT_TRAVERSAL_LEASE_TIMEOUT, true,
                      (UPNPDiscoverOpts *) m->nat_traversal.upnp_tcp_ip6, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_tcp_ip6_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            m->nat_traversal.upnp_tcp_ip6_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
        } else {
            m->nat_traversal.upnp_tcp_ip6_retries--;
        }
    }
}
#endif /* HAVE_LIBMINIUPNPC */


#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
static bool natpmp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port, uint32_t lifetime, natpmp_t *natpmp,
                            NAT_TRAVERSAL_STATUS *status)
{
    LOGGER_INFO(log, "Attempting to set up NAT-PMP port forwarding");

    natpmpresp_t resp;
    int error = readnatpmpresponseorretry(natpmp, &resp);

    if (!error) {
        *status = NAT_TRAVERSAL_OK;
        LOGGER_INFO(log, "NAT-PMP: %s (port %d)", str_nat_traversal_error(*status), port);
        natpmp->has_pending_request = 0;
        closenatpmp(natpmp);
        return true;
    } else if (error == NATPMP_TRYAGAIN) {
        *status = NAT_TRAVERSAL_TRYAGAIN;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        return false;
    } else {
        natpmp->has_pending_request = 0;
        closenatpmp(natpmp);
    }

    error = initnatpmp(natpmp, 0, 0);

    if (error) {
        *status = NAT_TRAVERSAL_ERR_INIT_FAIL;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        return false;
    }

    switch (proto) {
        case NAT_TRAVERSAL_UDP:
            error = sendnewportmappingrequest(natpmp, NATPMP_PROTOCOL_UDP, port, port, lifetime);
            break;

        case NAT_TRAVERSAL_TCP:
            error = sendnewportmappingrequest(natpmp, NATPMP_PROTOCOL_TCP, port, port, lifetime);
            break;

        default:
            *status = NAT_TRAVERSAL_ERR_UNKNOWN_PROTO;
            LOGGER_WARNING(log, "NAT-PMP: %s", str_nat_traversal_error(*status));
            natpmp->has_pending_request = 0;
            closenatpmp(natpmp);
            return false;
    }

    // From line 171 of natpmp.h: "12 = OK (size of the request)"
    if (error != 12) {
        *status = NAT_TRAVERSAL_ERR_SEND_REQ_FAIL;
        LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));
        natpmp->has_pending_request = 0;
        closenatpmp(natpmp);
        return false;
    }

    error = readnatpmpresponseorretry(natpmp, &resp);

    if (!error) {
        *status = NAT_TRAVERSAL_OK;
        LOGGER_INFO(log, "NAT-PMP: %s (port %d)", str_nat_traversal_error(*status), port);
        natpmp->has_pending_request = 0;
        closenatpmp(natpmp);
        return true;
    } else if (error == NATPMP_TRYAGAIN) {
        *status = NAT_TRAVERSAL_TRYAGAIN;
    } else {
        *status = NAT_TRAVERSAL_ERR_MAPPING_FAIL;
        natpmp->has_pending_request = 0;
        closenatpmp(natpmp);
    }

    LOGGER_WARNING(log, "NAT-PMP: %s (%s)", str_nat_traversal_error(*status), strnatpmperr(error));

    return false;
}


/* Renew UDP NAT-PMP mapped ports */
static void do_natpmp_map_port_udp(Messenger *m)
{
    NAT_TRAVERSAL_STATUS status;

    if ((m->nat_traversal.natpmp_udp_retries > 0) && is_timeout(m->nat_traversal.natpmp_udp_timeout, 0)) {
        natpmp_map_port(m->log, NAT_TRAVERSAL_UDP, m->net->port, NAT_TRAVERSAL_LEASE_TIMEOUT,
                        (natpmp_t *)m->nat_traversal.natpmp_udp, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.natpmp_udp_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            struct timeval t;

            if (!getnatpmprequesttimeout((natpmp_t *)m->nat_traversal.natpmp_udp, &t)) {
                m->nat_traversal.natpmp_udp_timeout = unix_time() + t.tv_sec + 1;
            } else {
                m->nat_traversal.natpmp_udp_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
            }
        } else {
            m->nat_traversal.natpmp_udp_retries--;
        }
    }
}


/* Renew TCP NAT-PMP mapped ports */
static void do_natpmp_map_port_tcp(Messenger *m)
{
    NAT_TRAVERSAL_STATUS status;

    if ((m->nat_traversal.natpmp_tcp_retries > 0) && is_timeout(m->nat_traversal.natpmp_tcp_timeout, 0)) {
        natpmp_map_port(m->log, NAT_TRAVERSAL_TCP, m->options.tcp_server_port, NAT_TRAVERSAL_LEASE_TIMEOUT,
                        (natpmp_t *)m->nat_traversal.natpmp_tcp, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.natpmp_tcp_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            struct timeval t;

            if (!getnatpmprequesttimeout((natpmp_t *)m->nat_traversal.natpmp_tcp, &t)) {
                m->nat_traversal.natpmp_tcp_timeout = unix_time() + t.tv_sec + 1;
            } else {
                m->nat_traversal.natpmp_tcp_timeout = unix_time() + NAT_TRAVERSAL_TRYAGAIN_TIMEOUT;
            }
        } else {
            m->nat_traversal.natpmp_tcp_retries--;
        }
    }
}
#endif /* HAVE_LIBNATPMP */


/* Renew mapped ports (called in "do_messenger()") */
void do_nat_map_ports(Messenger *m)
{
#if !defined(HAVE_LIBMINIUPNPC) && !defined(HAVE_LIBNATPMP)
    // Silence warnings if no libraries are found
    UNUSED(m);
#endif /* !HAVE_LIBMINIUPNPC && !HAVE_LIBNATPMP */

#ifdef HAVE_LIBMINIUPNPC

    if (m->options.traversal_type & TRAVERSAL_TYPE_UPNP) {
        if ((!m->options.udp_disabled) && (m->nat_traversal.upnp_udp_ip4 != NULL) && (m->nat_traversal.upnp_udp_ip6 != NULL)) {
            do_upnp_map_port_udp(m);
        }

        if ((m->tcp_server) && (m->nat_traversal.upnp_tcp_ip4 != NULL) && (m->nat_traversal.upnp_tcp_ip6 != NULL)) {
            do_upnp_map_port_tcp(m);
        }
    }

#endif /* HAVE_LIBMINIUPNPC */

#ifdef HAVE_LIBNATPMP

    if (m->options.traversal_type & TRAVERSAL_TYPE_NATPMP) {
        if ((!m->options.udp_disabled) && (m->nat_traversal.natpmp_udp != NULL)) {
            do_natpmp_map_port_udp(m);
        }

        if ((m->tcp_server) && (m->nat_traversal.natpmp_tcp != NULL)) {
            do_natpmp_map_port_tcp(m);
        }
    }

#endif /* HAVE_LIBNATPMP */
}
