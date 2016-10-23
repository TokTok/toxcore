#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>

#include "../toxcore/DHT.h"
// #include "../toxcore/DHT.c"
#include "../toxcore/tox.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/query.c"

#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static unsigned int response_cookie = 348394;
static uint8_t name[] = "requested_user.this_domain.tld";
static size_t name_length = strlen("requested_user.this_domain.tld") - 1;
static uint8_t toxid[TOX_ADDRESS_SIZE] = {0xDD, 0x2A, 0x13, 0x40, 0xFE, 0xCE, 0x44, 0x12, 0x06, 0xB5, 0xF3,
                                          0xD2, 0x02, 0xE6, 0x14, 0x6E, 0x76, 0x61, 0x72, 0x70, 0x21, 0x44,
                                          0x99, 0xB7, 0x2C, 0x55, 0x11, 0xFC, 0xE8, 0x39, 0xF8, 0x5B, 0x28,
                                          0xD7, 0xEA, 0xCB, 0xC4, 0x6C
                                         };

static bool done = false;

static void tox_query_response(Tox *tox, const uint8_t *request, size_t length, const uint8_t *tox_id,
                               void *user_data)
{
    ck_assert_msg(user_data == &response_cookie, "Invalid Cookie in response callback");
    ck_assert_msg(memcmp(tox_id, toxid, TOX_ADDRESS_SIZE) == 0, "Unexpected ToxID from callback");
    done = true;
}


static int query_handle_toxid_request(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata)
{

    Messenger *m = (Messenger *)object;

    if (pkt[0] != NET_PACKET_DATA_REQUEST) {
        ck_assert_msg(pkt[0] == NET_PACKET_DATA_REQUEST, "Bad incoming query request -- Packet = %u && length %u", pkt[0],
                      length);
    }

    length -= 1;
    ck_assert_msg(length > crypto_box_PUBLICKEYBYTES, "Bad length after 1 %u", length);

    uint8_t sender_key[crypto_box_PUBLICKEYBYTES];
    memcpy(sender_key, pkt + 1, crypto_box_PUBLICKEYBYTES);
    length -= crypto_box_PUBLICKEYBYTES;
    ck_assert_msg(length > crypto_box_NONCEBYTES, "Bad length after key %u", length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, pkt + 1 + crypto_box_PUBLICKEYBYTES, crypto_box_NONCEBYTES);
    length -= crypto_box_NONCEBYTES;
    ck_assert_msg(length == name_length + crypto_box_MACBYTES , "Bad length after nonce, %u instead of %u", length,
                  name_length + crypto_box_MACBYTES);

    uint8_t clear[length];

    decrypt_data(sender_key, m->dht->self_secret_key, nonce, pkt + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                 length, clear);

    ck_assert_msg(memcmp(clear, name, name_length) == 0, "Incoming packet is NOT the name");

    uint8_t encrypted[QUERY_PKT_ENCRYPTED_SIZE(TOX_ADDRESS_SIZE)];

    q_build_pkt(sender_key, m->dht->self_public_key, m->dht->self_secret_key, NET_PACKET_DATA_RESPONSE, toxid,
                TOX_ADDRESS_SIZE, encrypted);

    return sendpacket(m->dht->net, source, encrypted, QUERY_PKT_ENCRYPTED_SIZE(TOX_ADDRESS_SIZE));
}

START_TEST(test_query_ip4)
{
    time_t start_time = time(NULL);

    TOX_ERR_NEW error = 0;
    Tox *server = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create server");
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build server
    networking_registerhandler(((Messenger *)server)->dht->net, NET_PACKET_DATA_REQUEST, &query_handle_toxid_request,
                               server);

    // Build client
    tox_callback_query_response(client, tox_query_response);

    uint16_t server_port = tox_self_get_udp_port(server, NULL);

    TOX_ERR_QUERY_REQUEST r_error = 0;
    tox_query_request(client, "127.0.0.1", server_port, ((Messenger *)server)->dht->self_public_key,
                      name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_OK, "Error Sending Query Packet %i", r_error);

    while (!done) {
        tox_iterate(server, NULL);
        tox_iterate(client, &response_cookie);

        c_sleep(20);
    }

    tox_kill(client);
    tox_kill(server);
}
END_TEST

#ifndef TRAVIS_ENV
START_TEST(test_query_ip6)
{
    time_t start_time = time(NULL);

    TOX_ERR_NEW error = 0;
    Tox *server = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create server");
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build server
    networking_registerhandler(((Messenger *)server)->dht->net, NET_PACKET_DATA_REQUEST, &query_handle_toxid_request,
                               server);

    // Build client
    tox_callback_query_response(client, tox_query_response);

    uint16_t server_port = tox_self_get_udp_port(server, NULL);

    TOX_ERR_QUERY_REQUEST r_error = 0;
    tox_query_request(client, "::1", server_port, ((Messenger *)server)->dht->self_public_key,
                      name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_OK, "Error Sending Query Packet %i", r_error);

    while (!done) {
        tox_iterate(server, NULL);
        tox_iterate(client, &response_cookie);

        c_sleep(20);
    }

    tox_kill(client);
    tox_kill(server);
}
END_TEST
#endif

START_TEST(test_query_store)
{

    TOX_ERR_NEW error = 0;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    TOX_ERR_QUERY_REQUEST r_error = 0;
    tox_query_request(client, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                      name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_OK, "Error Sending Query Packet %i", r_error);

    c_sleep(1);


    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_query_request(client, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                      name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_PENDING, "Existing Query didn't pend! %i", r_error);

    tox_kill(client);
}
END_TEST

START_TEST(test_query_host)
{

    TOX_ERR_NEW error = 0;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    TOX_ERR_QUERY_REQUEST r_error = 0;
    tox_query_request(client, "baonethuaoreucaoeustaohdsatnhkbgcypidstnkbcgasrcpidancgubkagduhtou",
                      33445, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_BAD_HOST, "BAD_HOST WAS ACCEPTED %i", r_error);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);

    error = 0;
    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    r_error = 0;
    tox_query_request(client, "baonethuaoreucaoeustaohdsatnhkbgcypidstnkbcgasrcpidancgubkagduhtou",
                      0, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_BAD_PORT, "BAD_PORT WAS ACCEPTED %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);
}
END_TEST

START_TEST(test_query_null)
{
    TOX_ERR_NEW error = 0;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    TOX_ERR_QUERY_REQUEST r_error = 0;
    tox_query_request(client, NULL, 33445, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_NULL, "BAD ADDRESS WAS ACCEPTED %i", r_error);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);


    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    r_error = 0;
    tox_query_request(client, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key, NULL, name_length, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_NULL, "BAD NAME WAS ACCEPTED %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);


    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_callback_query_response(client, tox_query_response);
    r_error = 0;
    tox_query_request(client, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key, name, 0, &r_error);
    ck_assert_msg(r_error == TOX_ERR_QUERY_REQUEST_NULL, "BAD NAME_LENGTH WAS ACCEPTED %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);
}
END_TEST

START_TEST(test_query_functions)
{

    // testing q_grow
        PENDING_QUERIES testing_MAIN = {0};
        P_QUERY         testing_SINGEL;

        memset(&testing_MAIN, 0, sizeof(PENDING_QUERIES));
        memset(&testing_SINGEL, 0, sizeof(P_QUERY));


        testing_MAIN.count = 1;
        ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() small");
        ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
        ck_assert_msg(testing_MAIN.size == 1 + 2, "query_list unexpected size");

        free(testing_MAIN.query_list);
        testing_MAIN.query_list = NULL;
        memset(&testing_MAIN, 0, sizeof(PENDING_QUERIES));

        testing_MAIN.count = 100;
        ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() med");
        ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
        ck_assert_msg(testing_MAIN.size == 100 + 2, "query_list unexpected size");

        free(testing_MAIN.query_list);
        testing_MAIN.query_list = NULL;
        memset(&testing_MAIN, 0, sizeof(PENDING_QUERIES));

        testing_MAIN.count = 1000;
        ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() huge");
        ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
        ck_assert_msg(testing_MAIN.size == 1000 + 2, "query_list unexpected size");

        free(testing_MAIN.query_list);
        testing_MAIN.query_list = NULL;
        memset(&testing_MAIN, 0, sizeof(PENDING_QUERIES));

        testing_MAIN.count = -3;
        ck_assert_msg(q_grow(&testing_MAIN) == false, "ABLE to realloc in grow() UNREASONABLE");
        ck_assert_msg(testing_MAIN.query_list == NULL, "query_list is NOT_NULL");
        ck_assert_msg(testing_MAIN.size == 0, "query_list unexpected size");

    // testing q_verify_server(IP_Port existing, IP_Port pending)

    // testing  int q_check(PENDING_QUERIES *queries, P_QUERY pend, bool outgoing)
    // testing  bool q_add(PENDING_QUERIES *queries, P_QUERY pend)
    // testing  bool q_drop(PENDING_QUERIES *queries, size_t loc)
    // testing  size_t q_build_pkt(const uint8_t *their_public_key, const uint8_t *our_public_key, const uint8_t *our_secret_key,
    //                             uint8_t type, const uint8_t *data, size_t length, uint8_t *built)
    // testing int q_send(DHT *dht, P_QUERY send)
    // testing  P_QUERY q_make(IP_Port ipp, const uint8_t key[TOX_PUBLIC_KEY_SIZE], const uint8_t *name, size_t length)
    // testing  query_send_request(Tox *tox, const char *address, uint16_t port, const uint8_t *key,
    //                             const uint8_t *name, size_t length)
    // testing int query_handle_toxid_response(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata)
    // testing PENDING_QUERIES *query_new(Networking_Core *net)
    // testing void query_iterate(void *object)
}
END_TEST


static Suite *tox_named_s(void)
{
    Suite *s = suite_create("tox_named");

    DEFTESTCASE_SLOW(query_ip4, 10);
#ifndef TRAVIS_ENV
    DEFTESTCASE_SLOW(query_ip6, 10);
#endif
    DEFTESTCASE_SLOW(query_store, 10);
    DEFTESTCASE_SLOW(query_host, 20);
    DEFTESTCASE_SLOW(query_null, 10);

    DEFTESTCASE_SLOW(query_functions, 2);
    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *named = tox_named_s();
    SRunner *test_runner = srunner_create(named);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
