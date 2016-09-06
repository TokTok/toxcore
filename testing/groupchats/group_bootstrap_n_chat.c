/* Basic group chats testing
 */

#define _XOPEN_SOURCE 600
#include "../../toxcore/DHT.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/network.h"
#include "../../toxcore/ping.h"
#include "../../toxcore/util.h"
#include "../../toxcore/Messenger.h"
#include "../misc_tools.c"

#include <stdio.h>
#include <stdlib.h>

#define PEERCOUNT       20
#define min(a,b) ((a)>(b)?(b):(a))

static void on_group_peer_join(Messenger *m, uint32_t groupnumber, uint32_t peernumber, void *userdata)
{
    GC_Chat *ct = gc_get_group(m->group_handler, groupnumber);
    printf("Number of peers in the chat: %d\n", ct->numpeers);
}

int main(int argc, char *argv[])
{
    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    IP localhost;
    ip_init(&localhost, 1);
    localhost.ip.v6.uint8[15] = 1;
    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;

    Messenger *tox[PEERCOUNT];
    Messenger *chat;
    chat = new_messenger(&options, 0);

    int i;

    for (i = 0; i < PEERCOUNT; i++) {
        tox[i] = new_messenger(&options, 0);
    }

    printf("%s\n", id_toa(dht_get_self_public_key(tox[0]->dht)));
    IP_Port ip_port;
    ip_copy(&ip_port.ip, &localhost);
    ip_port.port = net_port(dht_get_net(tox[0]->dht));
    char buf[IP_NTOA_LEN];
    printf("%s\n", ip_ntoa(&ip_port.ip, buf, sizeof(buf)));
    printf("%d\n", ip_port.port);

    printf("Bootstrapping from node\n");

    for (i = 1; i < PEERCOUNT; i++) {
        DHT_bootstrap(tox[0]->dht, ip_port, dht_get_self_public_key(tox[0]->dht));
    }

    DHT_bootstrap(chat->dht, ip_port, dht_get_self_public_key(tox[0]->dht));

    printf("Waiting until every Tox is connected\n");

    for (;;) {
        for (i = 0; i < PEERCOUNT; i++) {
            do_messenger(tox[i], nullptr);
        }

        do_messenger(chat, nullptr);

        int numconnected = 0;

        for (i = 0; i < PEERCOUNT; i++) {
            numconnected += DHT_isconnected(tox[i]->dht);
        }

        //printf("%d\n", numconnected);

        if (numconnected > PEERCOUNT * min(PEERCOUNT - 1, LCLIENT_LIST)) {
            break;
        }

        /* TODO: busy wait might be slightly more efficient here */
        c_sleep(500); /* millis */
    }

    printf("Network is connected\n");

    chat->group_handler = new_dht_groupchats(chat);
    int groupnumber = gc_group_add(chat->group_handler, 0, (const uint8_t *)"Test", 4);

    if (groupnumber < 0) {
        printf("Cannot create group\n");
    }

    GC_Chat *ct = gc_get_group(chat->group_handler, groupnumber);
    printf("CHAT ENC: %s\n CHAT SIG: %s\n", id_toa(ENC_KEY(ct->chat_public_key)), id_toa(SIG_PK(ct->chat_public_key)));

    gc_callback_peer_join(chat, on_group_peer_join, nullptr);

    while (true) {
        for (i = 0; i < PEERCOUNT; i++) {
            do_messenger(tox[i], nullptr);
        }

        do_messenger(chat, nullptr);
        c_sleep(500); /* millis */
    }
}
