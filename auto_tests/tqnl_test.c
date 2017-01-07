#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>

#include "../toxqnl/tqnl.h"

#include "../toxcore/Messenger.h"

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

static void tox_tqnl_response(Tox_QNL *tqnl, const uint8_t *request, size_t length, const uint8_t *tox_id,
                              void *user_data)
{
    (void)tqnl;    // Unused variables
    (void)request;
    (void)length;

    ck_assert_msg(user_data != NULL, "Invalid Cookie in response callback");
    ck_assert_msg(memcmp(tox_id, toxid, TOX_ADDRESS_SIZE) == 0, "Unexpected ToxID from callback");
    *(bool *)user_data = true;
}


START_TEST(test_tqnl_create)
{
    TOX_ERR_NEW tox_error;
    Tox *tox = tox_new(NULL, &tox_error);
    ck_assert_msg(tox_error == TOX_ERR_NEW_OK, "Unable to create standard *tox");

    // Verify it CAN work.
    TOX_QNL_ERR_NEW error;
    Tox_QNL *tqnl = tox_qnl_new(tox, &error);
    ck_assert_msg(error == TOX_QNL_ERR_NEW_OK, "Unable to create *tqnl");
    ck_assert_msg(tqnl != NULL, "tox_tqnl_new reported OK, but returned NULL");
    tox_qnl_kill(tqnl);
    tox_kill(tox);

    // Verify NULL fails.
    Tox_QNL *tqnl_null = tox_qnl_new(NULL, &error);
    ck_assert_msg(error == TOX_QNL_ERR_NEW_TOX_NULL, "tox_qnl_new accepted a NULL *tox");
    ck_assert_msg(tqnl_null == NULL, "tox_qnl_new accepted a NULL *tox");


    // Mess around with the tox instance
    Tox *tox_invalid = tox_new(NULL, &tox_error);
    ck_assert_msg(tox_error == TOX_ERR_NEW_OK, "Unable to create standard *tox");

    ((Messenger *)tox_invalid)->net = NULL;
    Tox_QNL *tqnl_invalid = tox_qnl_new(tox_invalid, &error);
    ck_assert_msg(error == TOX_QNL_ERR_NEW_TOX_INVALID, "tox_qnl_new accepted an invalid *tox");
    ck_assert_msg(tqnl_invalid == NULL, "tox_qnl_new returned non-NULL on invalid *tox");
    tox_kill(tox_invalid);

    tox = tox_new(NULL, &tox_error);
    ck_assert_msg(tox_error == TOX_ERR_NEW_OK, "Unable to create standard *tox");

    Tox_QNL *tqnl_malloc = tox_qnl_new(tox, &error);
    ck_assert_msg(error != TOX_QNL_ERR_NEW_MALLOC
                  && tqnl_malloc != NULL, "tox_qnl_new returned non-NULL and a malloc error");
    ck_assert_msg(error != TOX_QNL_ERR_NEW_MALLOC, "tox_qnl_new was unable to malloc");
    tox_qnl_kill(tqnl);
    tox_kill(tox);
}
END_TEST

START_TEST(test_tqnl_send)
{
    TOX_ERR_NEW tox_error;
    Tox *tox = tox_new(NULL, &tox_error);
    ck_assert_msg(tox_error == TOX_ERR_NEW_OK, "Unable to create standard *tox");
    TOX_QNL_ERR_NEW error;
    Tox_QNL *tqnl = tox_qnl_new(tox, &error);
    ck_assert_msg(error == TOX_QNL_ERR_NEW_OK, "Unable to create *tqnl");
    ck_assert_msg(tqnl != NULL, "tox_tqnl_new reported OK, but returned NULL");

    TOX_QNL_ERR_REQUEST_SEND r_error;
    tox_qnl_request_send(tqnl, "127.0.0.1", 33445, ((Messenger *)tox)->dht->self_public_key,
                         name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_OK, "Error Sending Query Packet %i", r_error);

    tox_qnl_kill(tqnl);
    tox_kill(tox);
}
END_TEST

START_TEST(test_tqnl_store)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    TOX_QNL_ERR_REQUEST_SEND r_error;
    tox_qnl_request_send(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                         name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_OK, "Error Sending Query Packet %i", r_error);

    c_sleep(1);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_qnl_request_send(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key,
                         name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_PENDING, "Existing Query didn't pend! %i", r_error);

    tox_kill(client);
}
END_TEST

START_TEST(test_tqnl_host)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    TOX_QNL_ERR_REQUEST_SEND r_error;
    tox_qnl_request_send(tqnl, "BAD_HOST", 33445, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_BAD_HOST, "BAD_HOST was accepted %i", r_error);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);

    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    r_error = 0;
    tox_qnl_request_send(tqnl, "BAD_HOST", 0, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_BAD_PORT, "BAD_PORT was accepted %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);
}
END_TEST

START_TEST(test_tqnl_null)
{
    TOX_ERR_NEW error;
    Tox *client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");
    TOX_QNL_ERR_NEW qnl_err;
    Tox_QNL *tqnl = tox_qnl_new(client, &qnl_err);
    ck_assert_msg(qnl_err == TOX_QNL_ERR_NEW_OK, "Unable to create TQNL");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    TOX_QNL_ERR_REQUEST_SEND r_error;
    tox_qnl_request_send(tqnl, NULL, 33445, ((Messenger *)client)->dht->self_public_key, name, name_length, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_NULL, "BAD ADDRESS was accepted %i", r_error);

    int i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);


    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    r_error = 0;
    tox_qnl_request_send(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key, NULL, name_length,
                         &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_NULL, "BAD NAME was accepted %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);

    client = tox_new(NULL, &error);
    ck_assert_msg(error == TOX_ERR_NEW_OK, "Unable to create client");

    // Build client
    tox_qnl_callback_request_response(tqnl, tox_tqnl_response);
    r_error = 0;
    tox_qnl_request_send(tqnl, "127.0.0.1", 33445, ((Messenger *)client)->dht->self_public_key, name, 0, &r_error);
    ck_assert_msg(r_error == TOX_QNL_ERR_REQUEST_SEND_NULL, "BAD NAME_LENGTH was accepted %i", r_error);

    i = 3;

    while (i--) {
        tox_iterate(client, NULL);
        c_sleep(20);
    }

    tox_kill(client);
}
END_TEST



static Suite *tox_named_s(void)
{
    Suite *s = suite_create("tox_named");

    DEFTESTCASE_SLOW(tqnl_create, 10);
    DEFTESTCASE_SLOW(tqnl_send, 10);
    DEFTESTCASE_SLOW(tqnl_store, 10);
    DEFTESTCASE_SLOW(tqnl_host, 10);
    DEFTESTCASE_SLOW(tqnl_null, 10);
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
