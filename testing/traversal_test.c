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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
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

typedef struct my_node_t {
    char ip[16];
    uint16_t port;
    //char key_str[2 * TOX_PUBLIC_KEY_SIZE + 1];
    char *key;
} my_node_t;


static const char *level_str(TOX_LOG_LEVEL level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "[TRACE]";

        case TOX_LOG_LEVEL_DEBUG:
            return "[DEBUG]";

        case TOX_LOG_LEVEL_INFO:
            return "[INFO]";

        case TOX_LOG_LEVEL_WARNING:
            return "[WARNING]";

        case TOX_LOG_LEVEL_ERROR:
            return "[ERROR]";

        default:
            return "[???]";
    }
}


static void log_callback(Tox *tox, TOX_LOG_LEVEL level, const char *path, uint32_t line, const char *func,
                         const char *msg, void *user_data)
{
    UNUSED(tox);
    const struct timeval *start = (const struct timeval *)user_data;
    assert(start != NULL);

    const char *file = strrchr(path, '/');

    file = file ? file + 1 : path;

    struct timeval now;
    gettimeofday(&now, NULL);

    struct timeval diff;
    timersub(&now, start, &diff);
    printf("[%3d.%06d] %-9s %s:%d   %s(): %s\n", diff.tv_sec, diff.tv_usec, level_str(level), file, line, func, msg);
}

static char *str_to_key(const char *str)
{
    if (strlen(str) != 2 * TOX_PUBLIC_KEY_SIZE) {
        return NULL;
    }

    int i;
    char *key = calloc(TOX_PUBLIC_KEY_SIZE, sizeof(char));

    if (key == NULL) {
        return NULL;
    }

    for (i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sscanf(&str[i * 2], "%2hhx", &key[i]);
    }

    return key;
}

static Tox *tox_traversal_new(TYPE t, PROTO p, uint16_t tcp_port, struct timeval *start)
{
    struct Tox_Options *opts = tox_options_new(NULL);

    // Set log callback
    tox_options_set_log_callback(opts, &log_callback);
    tox_options_set_log_user_data(opts, start);

    switch (t) {
        case TYPE_UPNP:
            tox_options_set_traversal_type(opts, TOX_TRAVERSAL_TYPE_UPNP);
            break;

        case TYPE_NATPMP:
            tox_options_set_traversal_type(opts, TOX_TRAVERSAL_TYPE_NATPMP);
            break;

        case TYPE_ALL:
            tox_options_set_traversal_type(opts, TOX_TRAVERSAL_TYPE_UPNP | TOX_TRAVERSAL_TYPE_NATPMP);
            break;

        case TYPE_NONE:
        default:
            break;
    }

    switch (p) {
        case PROTO_ALL:
            if (tcp_port == 0) {
                tox_options_set_tcp_port(opts, 44300);
            } else {
                tox_options_set_tcp_port(opts, tcp_port);
            }

            break;

        case PROTO_TCP:
            tox_options_set_udp_enabled(opts, 0);

            if (tcp_port == 0) {
                tox_options_set_tcp_port(opts, 44300);
            } else {
                tox_options_set_tcp_port(opts, tcp_port);
            }

            break;

        case PROTO_UDP:
        default:
            break;
    }

    Tox *tox = tox_new(opts, NULL);
    tox_options_free(opts);

    return tox;
}

int main(int argc, char *argv[])
{
    int i, j;

    struct timeval start;
    gettimeofday(&start, NULL);

    log_callback(NULL, TOX_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__,
                 "Initialising tox instances", &start);
    Tox *upnp_udp = tox_traversal_new(TYPE_UPNP, PROTO_UDP, 0, &start);
    Tox *upnp_tcp = tox_traversal_new(TYPE_UPNP, PROTO_TCP, 44300, &start);
    Tox *natpmp_udp = tox_traversal_new(TYPE_NATPMP, PROTO_UDP, 0, &start);
    Tox *natpmp_tcp = tox_traversal_new(TYPE_NATPMP, PROTO_TCP, 44301, &start);
    log_callback(NULL, TOX_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__,
                 "Initialisation complete", &start);

    my_node_t udp_node[] = {
        { "144.76.60.215",   33445, str_to_key("04119E835DF3E78BACF0F84235B300546AF8B936F035185E2A8E9E0A67C8924F") },
        { "195.154.119.113", 33445, str_to_key("E398A69646B8CEACA9F0B84F553726C1C49270558C57DF5F3C368F05A7D71354") },
        { "46.38.239.179",   33445, str_to_key("F5A1A38EFB6BD3C2C8AF8B10D85F0F89E931704D349F1D0720C3C4059AF2440A") },
        { "178.62.250.138",  33445, str_to_key("788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B") },
        { "130.133.110.14",  33445, str_to_key("461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F") },
        { "104.167.101.29",  33445, str_to_key("5918AC3C06955962A75AD7DF4F80A5D7C34F7DB9E1498D2E0495DE35B3FE8A57") },
        { "205.185.116.116", 33445, str_to_key("A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702") },
        { "198.98.51.198",   33445, str_to_key("1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F") },
        { "80.232.246.79",   33445, str_to_key("CF6CECA0A14A31717CC8501DA51BE27742B70746956E6676FF423A529F91ED5D") },
        { "108.61.165.198",  33445, str_to_key("8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832") }
    };
    my_node_t tcp_node[] = {
        { "46.101.197.175",  443,   str_to_key("CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707") }
    };

    srand(time(NULL));

    for (i = 0; i < 100; i++) {
        j = rand() % 10;

        if (tox_self_get_connection_status(upnp_udp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(upnp_udp, udp_node[j].ip, udp_node[j].port, (uint8_t *) udp_node[j].key, NULL);
            tox_add_tcp_relay(upnp_udp, tcp_node[0].ip, tcp_node[0].port, (uint8_t *) tcp_node[0].key, NULL);
        }

        if (tox_self_get_connection_status(upnp_tcp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(upnp_tcp, udp_node[j].ip, udp_node[j].port, (uint8_t *) udp_node[j].key, NULL);
            tox_add_tcp_relay(upnp_tcp, tcp_node[0].ip, tcp_node[0].port, (uint8_t *) tcp_node[0].key, NULL);
        }

        if (tox_self_get_connection_status(natpmp_udp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(natpmp_udp, udp_node[j].ip, udp_node[j].port, (uint8_t *) udp_node[j].key, NULL);
            tox_add_tcp_relay(natpmp_udp, tcp_node[0].ip, tcp_node[0].port, (uint8_t *) tcp_node[0].key, NULL);
        }

        if (tox_self_get_connection_status(natpmp_tcp) == TOX_CONNECTION_NONE) {
            tox_bootstrap(natpmp_tcp, udp_node[j].ip, udp_node[j].port, (uint8_t *) udp_node[j].key, NULL);
            tox_add_tcp_relay(natpmp_tcp, tcp_node[0].ip, tcp_node[0].port, (uint8_t *) tcp_node[j].key, NULL);
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
