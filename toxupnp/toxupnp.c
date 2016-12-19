/* toxupnp.c -- Async wrapper for miniupnp library.
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

#include "toxupnp.h"

#include <pthread.h>
#include <stdlib.h>


static void *upnpDiscoverThread(void *arg)
{
    if (arg == NULL) {
        return NULL;
    }

    UPNPDiscoverOpts *opts = (UPNPDiscoverOpts *) arg;
    struct UPNPDev *devlist;

    opts->is_running = true;
    freeUPNPDevlist(opts->devlist);

#if MINIUPNPC_API_VERSION < 14
    devlist = upnpDiscover(opts->delay, opts->multicastif, opts->minissdpdsock, opts->localport, opts->ipv6, &opts->error);
#else
    devlist = upnpDiscover(opts->delay, opts->multicastif, opts->minissdpdsock, opts->localport, opts->ipv6, opts->ttl,
                           &opts->error);
#endif

    if (opts->error) {
        opts->devlist = NULL;
    } else {
        opts->devlist = devlist;
    }

    opts->is_running = false;

    return NULL;
}


static void initUPNPDiscoverOpts(UPNPDiscoverOpts *opts)
{
    opts->is_running = false;
    opts->devlist = NULL;

    defaultUPNPDiscoverOpts(opts);
}


UPNPDiscoverOpts *newUPNPDiscoverOpts()
{
    UPNPDiscoverOpts *opts = (UPNPDiscoverOpts *) calloc(1, sizeof(UPNPDiscoverOpts));

    if (opts == NULL) {
        return NULL;
    }

    initUPNPDiscoverOpts(opts);

    return opts;
}


bool freeUPNPDiscoverOpts(UPNPDiscoverOpts *opts)
{
    if (opts == NULL) {
        return true;
    }

    if (upnpDiscoverAsyncIsRunning(opts)) {
        return false;
    }

    opts->is_running = true;
    freeUPNPDevlist(opts->devlist);
    free(opts);

    return true;
}


void defaultUPNPDiscoverOpts(UPNPDiscoverOpts *opts)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return;
    }

    opts->is_running = true;

    opts->delay = 0;
    opts->multicastif = NULL;
    opts->minissdpdsock = NULL;
    opts->localport = 0;
    opts->ipv6 = 0;
    opts->ttl = 2;
    opts->error = UPNPDISCOVER_READY;

    freeUPNPDevlist(opts->devlist);
    opts->devlist = NULL;

    opts->is_running = false;
}


void upnpDiscoverAsyncSetDelay(UPNPDiscoverOpts *opts, int delay)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return;
    }

    opts->is_running = true;
    opts->delay = delay;
    opts->is_running = false;
}


void upnpDiscoverAsyncSetIPv6(UPNPDiscoverOpts *opts, int ipv6)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return;
    }

    opts->is_running = true;
    opts->ipv6 = ipv6;
    opts->is_running = false;
}


bool upnpDiscoverAsyncIsRunning(UPNPDiscoverOpts *opts)
{
    if (opts == NULL) {
        return false;
    }

    return opts->is_running;
}


int upnpDiscoverAsyncGetStatus(UPNPDiscoverOpts *opts)
{
    if (opts == NULL) {
        return UPNPDISCOVER_UNKNOWN_ERROR;
    }

    if (upnpDiscoverAsyncIsRunning(opts)) {
        return UPNPDISCOVER_RUNNING;
    }

    return opts->error;
}


/*UPNPDev *upnpDiscoverAsyncGetDevlist(UPNPDiscoverOpts *opts)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return NULL;
    }

    return opts->devlist;
}*/


void upnpDiscoverAsyncFreeDevlist(UPNPDiscoverOpts *opts)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return;
    }

    opts->is_running = true;

    freeUPNPDevlist(opts->devlist);
    opts->devlist = NULL;
    opts->error = UPNPDISCOVER_READY;

    opts->is_running = false;
}


void upnpDiscoverAsync(UPNPDiscoverOpts *opts)
{
    if (opts == NULL) {
        return;
    }

    if (!upnpDiscoverAsyncIsRunning(opts)) {
        pthread_t pth;

        pthread_create(&pth, NULL, upnpDiscoverThread, opts);
        pthread_detach(pth);
    }
}


int UPNP_GetValidIGDAsync(UPNPDiscoverOpts *opts, struct UPNPUrls *urls, struct IGDdatas *data, char *lanaddr,
                          int lanaddrlen)
{
    if ((opts == NULL) || (upnpDiscoverAsyncIsRunning(opts))) {
        return 0;
    }

    int error;

    opts->is_running = true;
    error = UPNP_GetValidIGD(opts->devlist, urls, data, lanaddr, lanaddrlen);
    opts->is_running = false;

    return error;
}
