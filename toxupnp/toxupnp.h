/* toxupnp.h -- Async wrapper for miniupnp library.
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

#ifndef TOXUPNP_H
#define TOXUPNP_H

#include <miniupnpc/miniupnpc.h>
#include <stdbool.h>

#define UPNPDISCOVER_RUNNING (-103)
#define UPNPDISCOVER_READY (-104)


typedef struct {
    int delay;
    char *multicastif;
    char *minissdpdsock;
    int localport;
    int ipv6;
    unsigned char ttl;
    int error;
    bool is_running;
    struct UPNPDev *devlist;
} UPNPDiscoverOpts;


UPNPDiscoverOpts *newUPNPDiscoverOpts();
bool freeUPNPDiscoverOpts(UPNPDiscoverOpts *opts);
void defaultUPNPDiscoverOpts(UPNPDiscoverOpts *opts);
void upnpDiscoverAsyncSetDelay(UPNPDiscoverOpts *opts, int delay);
void upnpDiscoverAsyncSetIPv6(UPNPDiscoverOpts *opts, int ipv6);
bool upnpDiscoverAsyncIsRunning(UPNPDiscoverOpts *opts);
int upnpDiscoverAsyncGetStatus(UPNPDiscoverOpts *opts);
//UPNPDev *upnpDiscoverAsyncGetDevlist(UPNPDiscoverOpts *opts);
void upnpDiscoverAsyncFreeDevlist(UPNPDiscoverOpts *opts);
void upnpDiscoverAsync(UPNPDiscoverOpts *opts);
int UPNP_GetValidIGDAsync(UPNPDiscoverOpts *opts, struct UPNPUrls *urls, struct IGDdatas *data, char *lanaddr,
                          int lanaddrlen);

#endif
