/* traversal_test.c
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
 *
 * How to compile (with both miniupnpc and libnatpmp in standard path):
 * gcc -o traversal_test traversal_test.c ../toxcore*.c \
 * -DMIN_LOGGER_LEVEL=LOG_DEBUG -DHAVE_LIBMINIUPNPC -DHAVE_LIBNATPMP \
 * -g -pthread `pkg-config --cflags --libs libsodium` -lminiupnpc -lnatpmp
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../toxcore/tox.h"

#define UNUSED(x) (void)(x)


typedef enum TYPE {
    TYPE_NONE,
    TYPE_UPNP,
    TYPE_NATPMP,
    TYPE_ALL
} TYPE;

typedef enum PROTO {
    PROTO_UDP,
    PROTO_TCP,
    PROTO_ALL
} PROTO;


static void log_callback(Tox *tox, TOX_LOG_LEVEL level, const char *path, uint32_t line, const char *func,
                         const char *msg, void *user_data)
{
    UNUSED(tox);
    UNUSED(user_data);

    const char *file = strrchr(path, '/');

    file = file ? file + 1 : path;

    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            printf("[TRACE]   ");
            break;

        case TOX_LOG_LEVEL_DEBUG:
            printf("[DEBUG]   ");
            break;

        case TOX_LOG_LEVEL_INFO:
            printf("[INFO]    ");
            break;

        case TOX_LOG_LEVEL_WARNING:
            printf("[WARNING] ");
            break;

        case TOX_LOG_LEVEL_ERROR:
            printf("[ERROR]   ");
            break;

        default:
            printf("[???]     ");
            break;
    }

    printf("%s:%d   %s(): %s\n", file, line, func, msg);
}

Tox *tox_traversal_new(TYPE t, PROTO p, uint16_t tcp_port, TOX_ERR_NEW *error)
{
    TOX_ERR_OPTIONS_NEW err;

    struct Tox_Options *opts = tox_options_new(&err);

    // Set log callback
    opts->log_callback = &log_callback;

    switch (t) {
        case TYPE_UPNP:
            opts->traversal_type = TOX_TRAVERSAL_TYPE_UPNP;
            break;

        case TYPE_NATPMP:
            opts->traversal_type = TOX_TRAVERSAL_TYPE_NATPMP;
            break;

        case TYPE_ALL:
            opts->traversal_type = TOX_TRAVERSAL_TYPE_UPNP | TOX_TRAVERSAL_TYPE_NATPMP;
            break;

        case TYPE_NONE:
        default:
            break;
    }

    switch (p) {
        case PROTO_ALL:
            if (tcp_port == 0) {
                opts->tcp_port = 44300;
            } else {
                opts->tcp_port = tcp_port;
            }

            break;

        case PROTO_TCP:
            opts->udp_enabled = 0;

            if (tcp_port == 0) {
                opts->tcp_port = 44300;
            } else {
                opts->tcp_port = tcp_port;
            }

            break;

        case PROTO_UDP:
        default:
            break;
    }

    Tox *tox = tox_new(opts, error);
    tox_options_free(opts);

    return tox;
}

int main(int argc, char *argv[])
{
    int i;
    TOX_ERR_NEW err;
    TOX_ERR_BOOTSTRAP boot_err;

    Tox *upnp_udp = tox_traversal_new(TYPE_UPNP, PROTO_UDP, 0, &err);
    Tox *upnp_tcp = tox_traversal_new(TYPE_UPNP, PROTO_TCP, 0, &err);
    Tox *natpmp_udp = tox_traversal_new(TYPE_NATPMP, PROTO_UDP, 44300, &err);
    Tox *natpmp_tcp = tox_traversal_new(TYPE_NATPMP, PROTO_TCP, 44301, &err);

    char udp_key_str[] = "04119E835DF3E78BACF0F84235B300546AF8B936F035185E2A8E9E0A67C8924F";
    char tcp_key_str[] = "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707";
    char udp_key[TOX_PUBLIC_KEY_SIZE];
    char tcp_key[TOX_PUBLIC_KEY_SIZE];

    for (i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sscanf(&udp_key_str[i * 2], "%2hhx", &udp_key[i]);
        sscanf(&tcp_key_str[i * 2], "%2hhx", &tcp_key[i]);
    }

    for (i = 0; i < 100; i++) {
        if (tox_self_get_connection_status(upnp_udp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(upnp_udp, "144.76.60.215", 33445, (uint8_t *) udp_key, &boot_err);
            tox_add_tcp_relay(upnp_udp, "46.101.197.175", 443, (uint8_t *) tcp_key, &boot_err);
        }

        if (tox_self_get_connection_status(upnp_tcp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(upnp_tcp, "144.76.60.215", 33445, (uint8_t *) udp_key, &boot_err);
            tox_add_tcp_relay(upnp_udp, "46.101.197.175", 443, (uint8_t *) tcp_key, &boot_err);
        }

        if (tox_self_get_connection_status(natpmp_udp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(natpmp_udp, "144.76.60.215", 33445, (uint8_t *) udp_key, &boot_err);
            tox_add_tcp_relay(upnp_udp, "46.101.197.175", 443, (uint8_t *) tcp_key, &boot_err);
        }

        if (tox_self_get_connection_status(natpmp_tcp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(natpmp_tcp, "144.76.60.215", 33445, (uint8_t *) udp_key, &boot_err);
            tox_add_tcp_relay(upnp_udp, "46.101.197.175", 443, (uint8_t *) tcp_key, &boot_err);
        }

        tox_iterate(upnp_udp, NULL);
        tox_iterate(upnp_tcp, NULL);
        tox_iterate(natpmp_udp, NULL);
        tox_iterate(natpmp_tcp, NULL);

        sleep(1);
    }

    tox_kill(upnp_udp);
    tox_kill(upnp_tcp);
    tox_kill(natpmp_udp);
    tox_kill(natpmp_tcp);

    return 0;
}
