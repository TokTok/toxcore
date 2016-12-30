#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tox/tox.h>

uint8_t peerkeys[3][TOX_PUBLIC_KEY_SIZE];
int peer_gn[3];

int peer_fn[2];

uint8_t address[3][TOX_ADDRESS_SIZE];

uint8_t flag;

Tox *tox[3];

struct Tox_Options *options;

char bootstrap_addr[] = "127.0.0.1";
uint16_t bootstrap_port = 33445;
char bootstrap_key[] = "6FA44C7E1D2E2B0455E38B2D764ED34A559157D4B1A7F3D1BB57A8C768DE633D";

void
conference_invite_callback(Tox *tox, uint32_t fn, TOX_CONFERENCE_TYPE type,
                           const uint8_t *cookie, size_t cookie_len, void *data)
{
    int peer_num = *((int *)data);
    printf("peer %d: invited by %d\n", peer_num, fn);
    peer_gn[peer_num] = tox_conference_join(tox, fn, cookie, cookie_len, NULL);
    flag = 1;
}

void
friend_request_callback(Tox *tox, const uint8_t *pk, const uint8_t *message,
                        size_t message_len, void *data)
{
    int peer_num = *((int *)data);
    printf("peer %d: friend added\n", peer_num);
    tox_friend_add_norequest(tox, pk, NULL);
    flag = 1;
}

void
connection_status_callback(Tox *tox, TOX_CONNECTION status, void *data)
{
    int peer_num = *((int *)data);
    printf("peer %d: online\n", peer_num);
    flag = 1;
}

void
conference_namelist_change(Tox *tox, 
                           uint32_t group_number, uint32_t peer_number,
                           TOX_CONFERENCE_STATE_CHANGE change_type,
                           void *data)
{
    int peer_num = *((int *)data);
    printf("peer namelist change: %d %d\n", peer_num, change_type);
    if (change_type == TOX_CONFERENCE_STATE_CHANGE_PEER_JOIN)
    {
        tox_conference_peer_get_public_key(tox, group_number, peer_number, peerkeys[peer_num], NULL);
    }
    if (change_type == TOX_CONFERENCE_STATE_CHANGE_PEER_EXIT)
    {
        uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
        tox_conference_peer_get_public_key(tox, group_number, peer_number, pubkey, NULL);
        int memcmp_res = memcmp(pubkey, peerkeys[peer_num], TOX_PUBLIC_KEY_SIZE);
        if (memcmp_res != 0)
        {
            printf("test failed!\n");
            exit(1);
        }
        else
            printf("peer key match!\n");
    }
    flag = 1;
}

int main()
{
    int peer_num;
    options = tox_options_new(NULL);
    tox[0] = tox_new(options, NULL);
    tox_self_get_address(tox[0], address[0]);
    tox[1] = tox_new(options, NULL);
    tox_self_get_address(tox[1], address[1]);
    tox[2] = tox_new(options, NULL);
    tox_self_get_address(tox[2], address[2]);

    tox_callback_self_connection_status(tox[0], connection_status_callback);
    tox_callback_self_connection_status(tox[1], connection_status_callback);
    tox_callback_self_connection_status(tox[2], connection_status_callback);
    tox_callback_friend_request(tox[0], friend_request_callback);
    tox_callback_friend_request(tox[1], friend_request_callback);
    tox_callback_friend_request(tox[2], friend_request_callback);
    tox_callback_conference_invite(tox[0], conference_invite_callback);
    tox_callback_conference_invite(tox[1], conference_invite_callback);
    tox_callback_conference_invite(tox[2], conference_invite_callback);
    tox_callback_conference_namelist_change(tox[0], conference_namelist_change);
    tox_bootstrap(tox[0], bootstrap_addr, bootstrap_port, bootstrap_key, NULL);
    flag = 0;
    // waiting first instance to go online
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    tox_bootstrap(tox[1], bootstrap_addr, bootstrap_port, bootstrap_key, NULL);
    flag = 0;
    // waiting second instance to go online
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    tox_bootstrap(tox[2], bootstrap_addr, bootstrap_port, bootstrap_key, NULL);
    flag = 0;
    // waiting third instance to go online
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    peer_fn[0] = tox_friend_add(tox[0], address[1], "foobar", 6, NULL);
    flag = 0;
    // waiting first friend to be added
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    peer_fn[1] = tox_friend_add(tox[0], address[2], "foobar", 6, NULL);
    flag = 0;
    // waiting second friend to be added
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    peer_gn[0] = tox_conference_new(tox[0], NULL);
    for (int i = 0; i < 20; i++)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    printf("wait finished\n");
    tox_conference_invite(tox[0], peer_fn[0], peer_gn[0], NULL);
    flag = 0;
    // waiting first friend to join
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    flag = 0;
    // waiting for namelist change event
    while (!flag)
    {
        peer_num = 1;
        tox_iterate(tox[0], &peer_num);
        tox_iterate(tox[peer_num], NULL);
        tox_iterate(tox[peer_num], NULL);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    for (int i = 0; i < 20; i++)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    printf("wait finished\n");
    flag = 0;
    tox_conference_invite(tox[0], peer_fn[1], peer_gn[0], NULL);
    // waiting second friend to join
    while (!flag)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    flag = 0;
    // waiting for namelist change event
    while (!flag)
    {
        peer_num = 2;
        tox_iterate(tox[0], &peer_num);
        tox_iterate(tox[peer_num], NULL);
        tox_iterate(tox[peer_num], NULL);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    for (int i = 0; i < 20; i++)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    printf("wait finished\n");
    tox_conference_delete(tox[1], peer_gn[1], NULL);
    flag = 0;
    // wait for peer 1 exit
    while (!flag)
    {
        peer_num = 1;
        tox_iterate(tox[0], &peer_num);
        tox_iterate(tox[peer_num], NULL);
        tox_iterate(tox[peer_num], NULL);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    for (int i = 0; i < 20; i++)
    {
        peer_num = 0;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 1;
        tox_iterate(tox[peer_num], &peer_num);
        peer_num = 2;
        tox_iterate(tox[peer_num], &peer_num);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
    printf("wait finished\n");
    tox_conference_delete(tox[2], peer_gn[2], NULL);
    flag = 0;
    // wait for peer 2 exit
    while (!flag)
    {
        peer_num = 2;
        tox_iterate(tox[0], &peer_num);
        tox_iterate(tox[peer_num], NULL);
        tox_iterate(tox[peer_num], NULL);
        usleep(1000*tox_iteration_interval(tox[0]));
    }
}
