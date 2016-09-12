

#include "helpers.h"

#include "../toxcore/tox.h"

#include <check.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TCP_RELAY_PORT 33448
/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

struct loop_test {
    int start_count, stop_count;
    pthread_mutex_t mutex;
    Tox *tox;
};

void tox_loop_cb_start(Tox *tox, void *user_data)
{
    struct loop_test *userdata = user_data;
    pthread_mutex_lock(&userdata->mutex);
    userdata->start_count++;
}

void tox_loop_cb_stop(Tox *tox, void *user_data)
{
    struct loop_test *userdata = user_data;
    userdata->stop_count++;
    pthread_mutex_unlock(&userdata->mutex);
}

void *tox_loop_worker(void *data)
{
    struct loop_test *userdata = data;
    return tox_loop(userdata->tox, data);
}

START_TEST(test_tox_loop)
{
    pthread_t worker1, worker2;
    struct Tox_Options opts;
    struct loop_test userdata;
    userdata.start_count = 0;
    userdata.stop_count = 0;
    pthread_mutex_init(&userdata.mutex, NULL);

    tox_options_default(&opts);
    opts.tcp_port = TCP_RELAY_PORT;
    userdata.tox = tox_new(&opts, 0);
    tox_callback_loop_start(userdata.tox, tox_loop_cb_start);
    tox_callback_loop_stop(userdata.tox, tox_loop_cb_stop);
    pthread_create(&worker1, NULL, tox_loop_worker, &userdata);


    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(userdata.tox, dpk);

    tox_options_default(&opts);
    struct loop_test userdata_tcp;
    userdata_tcp.start_count = 0;
    userdata_tcp.stop_count = 0;
    pthread_mutex_init(&userdata_tcp.mutex, NULL);
    userdata_tcp.tox = tox_new(&opts, 0);
    tox_callback_loop_start(userdata_tcp.tox, tox_loop_cb_start);
    tox_callback_loop_stop(userdata_tcp.tox, tox_loop_cb_stop);
    pthread_create(&worker2, NULL, tox_loop_worker, &userdata_tcp);

    pthread_mutex_lock(&userdata_tcp.mutex);
    TOX_ERR_BOOTSTRAP error = 0;
    ck_assert_msg(tox_add_tcp_relay(userdata_tcp.tox, TOX_LOCALHOST, TCP_RELAY_PORT, dpk, &error), "add relay error, %i",
                  error);
    ck_assert_msg(tox_bootstrap(userdata_tcp.tox, TOX_LOCALHOST, 33445, dpk, 0), "Bootstrap error");
    pthread_mutex_unlock(&userdata_tcp.mutex);


    sleep(10);

    tox_loop_stop(userdata.tox);
    pthread_mutex_lock(&userdata.mutex);
    tox_kill(userdata.tox);
    ck_assert_msg(userdata.start_count == userdata.stop_count, "start and stop must match");

    tox_loop_stop(userdata_tcp.tox);
    pthread_mutex_lock(&userdata_tcp.mutex);
    tox_kill(userdata_tcp.tox);
    ck_assert_msg(userdata_tcp.start_count == userdata_tcp.stop_count, "start and stop must match");
}
END_TEST

#ifdef TRAVIS_ENV
uint8_t timeout_mux = 20;
#else
uint8_t timeout_mux = 10;
#endif

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox");

    /* test the new tox_loop function */
    DEFTESTCASE_SLOW(tox_loop, 4 * timeout_mux);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
