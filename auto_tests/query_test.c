#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>

#include "../toxcore/DHT.h"
#include "../toxcore/Messenger.h"
#include "../toxqnl/query.c"
#include "../toxqnl/tqnl.h"

#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static const uint8_t name[] = "requested_user.this_domain.tld";
static const size_t name_length = sizeof name - 1;
static const uint8_t toxid[TOX_ADDRESS_SIZE] = {
    0xDD, 0x2A, 0x13, 0x40, 0xFE, 0xCE, 0x44, 0x12, 0x06, 0xB5, 0xF3, 0xD2, 0x02, 0xE6,
    0x14, 0x6E, 0x76, 0x61, 0x72, 0x70, 0x21, 0x44, 0x99, 0xB7, 0x2C, 0x55, 0x11, 0xFC,
    0xE8, 0x39, 0xF8, 0x5B, 0x28, 0xD7, 0xEA, 0xCB, 0xC4, 0x6C
};

static void tox_query_response(Tox_QNL *tqnl, const uint8_t *request, size_t length, const uint8_t *tox_id,
                               void *user_data)
{
    (void)tqnl;    // Unused variables
    (void)request;
    (void)length;

    ck_assert_msg(user_data != NULL, "Invalid Cookie in response callback");
    ck_assert_msg(memcmp(tox_id, toxid, TOX_ADDRESS_SIZE) == 0, "Unexpected ToxID from callback");
    *(bool *)user_data = true;
}


static int query_handle_toxid_request(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata)
{
    Messenger *m = (Messenger *)object;

    (void)userdata; // unused

    if (pkt[0] != NET_PACKET_DATA_NAME_REQUEST) {
        ck_assert_msg(pkt[0] == NET_PACKET_DATA_NAME_REQUEST, "Bad incoming query request -- Packet = %u && length %u", pkt[0],
                      length);
    }

    length -= 1;
    ck_assert_msg(length > CRYPTO_PUBLIC_KEY_SIZE, "Bad length after 1 %u", length);

    uint8_t sender_key[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(sender_key, pkt + 1, CRYPTO_PUBLIC_KEY_SIZE);
    length -= CRYPTO_PUBLIC_KEY_SIZE;
    ck_assert_msg(length > CRYPTO_NONCE_SIZE, "Bad length after key %u", length);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, pkt + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
    length -= CRYPTO_NONCE_SIZE;
    ck_assert_msg(length == name_length + CRYPTO_MAC_SIZE, "Bad length after nonce, %u instead of %u", length,
                  name_length + CRYPTO_MAC_SIZE);

    uint8_t clear[length];

    decrypt_data(sender_key, m->dht->self_secret_key, nonce, pkt + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                 length, clear);

    ck_assert_msg(memcmp(clear, name, name_length) == 0, "Incoming packet is not equal to the name");

    uint8_t encrypted[QUERY_PKT_ENCRYPTED_SIZE + TOX_ADDRESS_SIZE];

    size_t pkt_size = q_build_packet(sender_key, m->dht->self_public_key, m->dht->self_secret_key,
                                     NET_PACKET_DATA_NAME_RESPONSE,
                                     toxid,
                                     TOX_ADDRESS_SIZE, encrypted);
    ck_assert_msg(pkt_size == QUERY_PKT_ENCRYPTED_SIZE + TOX_ADDRESS_SIZE, "Build packet callback broken size!");

    int send_res = sendpacket(m->dht->net, source, encrypted, pkt_size);
    ck_assert_msg(send_res != -1, "unable to send packet");
    return send_res;
}

START_TEST(test_query_ip4)
{
    TOX_ERR_NEW error;
    Tox *server = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create server");

    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build server
    networking_registerhandler(((Messenger *)server)->dht->net, NET_PACKET_DATA_NAME_REQUEST, &query_handle_toxid_request,
                               server);

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_query_response);

    uint16_t server_port = tox_self_get_udp_port(server, NULL);

    int res = query_send_request(tqnl, "127.0.0.1", server_port, ((Messenger *)server)->dht->self_public_key, name,
                                 name_length);
    ck_assert_msg(res == 0, "Error Sending Query Packet");

    bool done = false;

    while (!done) {
        tox_iterate(server, NULL);
        tox_iterate(client, &done);

        c_sleep(20);
    }

    tox_kill(client);
    tox_kill(server);
}
END_TEST

#ifndef TRAVIS_ENV
START_TEST(test_query_ip6)
{
    TOX_ERR_NEW error;
    Tox *server = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create server");

    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build server
    networking_registerhandler(((Messenger *)server)->dht->net, NET_PACKET_DATA_NAME_REQUEST, &query_handle_toxid_request,
                               server);

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_query_response);

    uint16_t server_port = tox_self_get_udp_port(server, NULL);

    int res = query_send_request(tqnl, "::1", server_port, ((Messenger *)server)->dht->self_public_key, name, name_length);
    ck_assert_msg(res == 0, "Error Sending Query Packet");

    bool done = false;

    while (!done) {
        tox_iterate(server, NULL);
        tox_iterate(client, &done);

        c_sleep(20);
    }

    tox_kill(client);
    tox_kill(server);
}
END_TEST
#endif

START_TEST(test_query_store)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_query_response);
    int res = query_send_request(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                                 name, name_length);
    ck_assert_msg(res == 0, "Error Sending Query Packet");

    c_sleep(1);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    res = query_send_request(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                             name, name_length);
    ck_assert_msg(res == -2, "Existing Query didn't pend! %i");

    tox_kill(client);
}
END_TEST

START_TEST(test_query_host)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_query_response);
    int res = query_send_request(tqnl, "BAD_HOST", 33445, ((Messenger *)client)->dht->self_public_key, name, name_length);
    ck_assert_msg(res == -1, "BAD_HOST was accepted");

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);
}
END_TEST

START_TEST(test_query_null)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_query_response);
    int res = query_send_request(tqnl, NULL, 33445, ((Messenger *)client)->dht->self_public_key, name, name_length);
    ck_assert_msg(res == -1, "BAD ADDRESS was accepted");

    int i = 3;

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
    Pending_Queries testing_MAIN = {0};
    Query           testing_SINGLE;

    memset(&testing_MAIN, 0, sizeof(Pending_Queries));
    memset(&testing_SINGLE, 0, sizeof(Query));


    testing_MAIN.count = 1;
    ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() small");
    ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
    ck_assert_msg(testing_MAIN.size == 1 + 2, "query_list unexpected size");

    free(testing_MAIN.query_list);
    testing_MAIN.query_list = NULL;
    memset(&testing_MAIN, 0, sizeof(Pending_Queries));

    testing_MAIN.count = 100;
    ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() med");
    ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
    ck_assert_msg(testing_MAIN.size == 100 + 2, "query_list unexpected size");

    free(testing_MAIN.query_list);
    testing_MAIN.query_list = NULL;
    memset(&testing_MAIN, 0, sizeof(Pending_Queries));

    testing_MAIN.count = 1000;
    ck_assert_msg(q_grow(&testing_MAIN) == true, "Unable to realloc in grow() huge");
    ck_assert_msg(testing_MAIN.query_list != NULL, "query_list is NULL");
    ck_assert_msg(testing_MAIN.size == 1000 + 2, "query_list unexpected size");

    free(testing_MAIN.query_list);
    testing_MAIN.query_list = NULL;
    memset(&testing_MAIN, 0, sizeof(Pending_Queries));

    testing_MAIN.count = -3;
    ck_assert_msg(q_grow(&testing_MAIN) == false, "ABLE to realloc in grow() UNREASONABLE");
    ck_assert_msg(testing_MAIN.query_list == NULL, "query_list is NOT_NULL");
    ck_assert_msg(testing_MAIN.size == 0, "query_list unexpected size");

#if 0
    // TODO(grayhatter) finish all unit tests for the commented functions
    q_verify_server()
    q_check()
    bool q_add()
    bool q_drop()
    size_t q_build_packet()
#endif
    uint8_t key[CRYPTO_PUBLIC_KEY_SIZE];
    new_symmetric_key(key);
    uint8_t build_pkt[QUERY_PKT_ENCRYPTED_SIZE + sizeof name];
    size_t build_size = q_build_packet(key, key, key, NET_PACKET_DATA_NAME_REQUEST, name, name_length, build_pkt);
    ck_assert_msg(build_size != SIZE_MAX, "q_build_packet failed, encryption failed.");
    ck_assert_msg(build_pkt[0] == NET_PACKET_DATA_NAME_REQUEST, "q_build_packet malformed packet.");
    ck_assert_msg(memcmp(build_pkt + 1, key, CRYPTO_PUBLIC_KEY_SIZE) == 0, "q_build_packet malformed packet.");
    ck_assert_msg(build_size == QUERY_PKT_ENCRYPTED_SIZE + name_length, "q_build_packet, invalid returned size.");

#if 0
    q_send()
    q_make()
    int res = query_send_request()
              query_handle_toxid_response()
              query_new()
              query_iterate()
#endif
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
