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
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#include <stdio.h>
#endif

#ifdef HAVE_LIBNATPMP
#define ENABLE_STRNATPMPERR
#include <natpmp.h>
#include <unistd.h>
#endif

#define UNUSED(x) (void)(x)

#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
static bool upnp_map_port(Logger *log, NAT_TRAVERSAL_PROTO proto, uint16_t port, uint32_t lifetime, bool ipv6_enabled,
                          NAT_TRAVERSAL_STATUS *status)
{
    LOGGER_INFO(log, "Attempting to set up UPnP port forwarding");

    bool ret = false;
    int error;

#if MINIUPNPC_API_VERSION < 14
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, ipv6_enabled, &error);
#else
    struct UPNPDev *devlist = upnpDiscover(1000, NULL, NULL, 0, ipv6_enabled, 2, &error);
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
        upnp_map_port(m->log, NAT_TRAVERSAL_UDP, m->net->port, NAT_TRAVERSAL_LEASE_TIMEOUT, false, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_udp_ip4_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else {
            m->nat_traversal.upnp_udp_ip4_retries--;
        }
    }

    if (m->options.ipv6enabled && (m->nat_traversal.upnp_udp_ip6_retries > 0)
            && is_timeout(m->nat_traversal.upnp_udp_ip6_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_UDP, m->net->port, NAT_TRAVERSAL_LEASE_TIMEOUT, true, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_udp_ip6_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
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
        upnp_map_port(m->log, NAT_TRAVERSAL_TCP, m->options.tcp_server_port, NAT_TRAVERSAL_LEASE_TIMEOUT, false, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_tcp_ip4_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else {
            m->nat_traversal.upnp_tcp_ip4_retries--;
        }
    }

    if (m->options.ipv6enabled && (m->nat_traversal.upnp_tcp_ip6_retries > 0)
            && is_timeout(m->nat_traversal.upnp_tcp_ip6_timeout, 0)) {
        upnp_map_port(m->log, NAT_TRAVERSAL_TCP, m->options.tcp_server_port, NAT_TRAVERSAL_LEASE_TIMEOUT, true, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.upnp_tcp_ip6_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else {
            m->nat_traversal.upnp_tcp_ip6_retries--;
        }
    }
}


/* Renew UPnP mapped ports thread */
static void *do_upnp_map_ports_thread(void *arg)
{
    Messenger *m = (Messenger *) arg;

    if (!pthread_mutex_trylock(&m->nat_traversal.upnp_lock)) {
        if (!m->options.udp_disabled) {
            do_upnp_map_port_udp(m);
        }

        if (m->tcp_server) {
            do_upnp_map_port_tcp(m);
        }

        pthread_mutex_unlock(&m->nat_traversal.upnp_lock);
    }

    return NULL;
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
                        (natpmp_t *)m->nat_traversal.natpmp, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.natpmp_udp_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            struct timeval t;

            if (!getnatpmprequesttimeout((natpmp_t *)m->nat_traversal.natpmp, &t)) {
                m->nat_traversal.natpmp_udp_timeout = unix_time() + t.tv_sec + 1;
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
                        (natpmp_t *)m->nat_traversal.natpmp, &status);

        if (status == NAT_TRAVERSAL_OK) {
            m->nat_traversal.natpmp_tcp_timeout = unix_time() + NAT_TRAVERSAL_LEASE_TIMEOUT;
        } else if (status == NAT_TRAVERSAL_TRYAGAIN) {
            struct timeval t;

            if (!getnatpmprequesttimeout((natpmp_t *)m->nat_traversal.natpmp, &t)) {
                m->nat_traversal.natpmp_tcp_timeout = unix_time() + t.tv_sec + 1;
            }
        } else {
            m->nat_traversal.natpmp_tcp_retries--;
        }
    }
}


/* Renew NAT-PMP mapped ports thread */
static void *do_natpmp_map_ports_thread(void *arg)
{
    Messenger *m = (Messenger *) arg;

    if (!pthread_mutex_trylock(&m->nat_traversal.natpmp_lock)) {
        if (!m->options.udp_disabled) {
            do_natpmp_map_port_udp(m);
        }

        if (m->tcp_server) {
            do_natpmp_map_port_tcp(m);
        }

        pthread_mutex_unlock(&m->nat_traversal.natpmp_lock);
    }

    return NULL;
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
        pthread_t pth;

        pthread_create(&pth, NULL, do_upnp_map_ports_thread, m);
        pthread_detach(pth);
    }

#endif /* HAVE_LIBMINIUPNPC */

#ifdef HAVE_LIBNATPMP

    if (m->options.traversal_type & TRAVERSAL_TYPE_NATPMP) {
        pthread_t pth;

        pthread_create(&pth, NULL, do_natpmp_map_ports_thread, m);
        pthread_detach(pth);
    }

#endif /* HAVE_LIBNATPMP */
}


/* Return error string from status */
const char *str_nat_traversal_error(NAT_TRAVERSAL_STATUS status)
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
