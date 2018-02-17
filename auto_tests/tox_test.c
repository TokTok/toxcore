/* Auto Tests
 *
 * Tox Tests
 *
 * The following tests were written with a small Tox network in mind. Therefore,
 * each test timeout was set to one for a small Tox Network. If connected to the
 * 'Global' Tox Network, traversing the DHT would take MUCH longer than the
 * timeouts allow. Because of this running these tests require NO other Tox
 * clients running or accessible on/to localhost.
 *
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "check_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

static uint64_t size_recv;
static uint64_t sending_pos;

static uint8_t file_cmp_id[TOX_FILE_ID_LENGTH];
static uint32_t file_accepted;
static uint64_t file_size;
static void tox_file_receive(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind, uint64_t filesize,
                             const uint8_t *filename, size_t filename_length, void *userdata)
{
    if (kind != TOX_FILE_KIND_DATA) {
        ck_abort_msg("Bad kind");
    }

    if (!(filename_length == sizeof("Gentoo.exe") && memcmp(filename, "Gentoo.exe", sizeof("Gentoo.exe")) == 0)) {
        ck_abort_msg("Bad filename");
    }

    uint8_t file_id[TOX_FILE_ID_LENGTH];

    if (!tox_file_get_file_id(tox, friend_number, file_number, file_id, nullptr)) {
        ck_abort_msg("tox_file_get_file_id error");
    }

    if (memcmp(file_id, file_cmp_id, TOX_FILE_ID_LENGTH) != 0) {
        ck_abort_msg("bad file_id");
    }

    uint8_t empty[TOX_FILE_ID_LENGTH] = {0};

    if (memcmp(empty, file_cmp_id, TOX_FILE_ID_LENGTH) == 0) {
        ck_abort_msg("empty file_id");
    }

    file_size = filesize;

    if (filesize) {
        sending_pos = size_recv = 1337;

        TOX_ERR_FILE_SEEK err_s;

        if (!tox_file_seek(tox, friend_number, file_number, 1337, &err_s)) {
            ck_abort_msg("tox_file_seek error");
        }

        ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_OK, "tox_file_seek wrong error");
    } else {
        sending_pos = size_recv = 0;
    }

    TOX_ERR_FILE_CONTROL error;

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, &error)) {
        ++file_accepted;
    } else {
        ck_abort_msg("tox_file_control failed. %i", error);
    }

    TOX_ERR_FILE_SEEK err_s;

    if (tox_file_seek(tox, friend_number, file_number, 1234, &err_s)) {
        ck_abort_msg("tox_file_seek no error");
    }

    ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_DENIED, "tox_file_seek wrong error");
}

static uint32_t sendf_ok;
static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                               void *userdata)
{
    /* First send file num is 0.*/
    if (file_number == 0 && control == TOX_FILE_CONTROL_RESUME) {
        sendf_ok = 1;
    }
}

static uint64_t max_sending;
static bool m_send_reached;
static uint8_t sending_num;
static bool file_sending_done;
static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                   size_t length, void *user_data)
{
    if (!sendf_ok) {
        ck_abort_msg("Didn't get resume control");
    }

    if (sending_pos != position) {
        ck_abort_msg("Bad position %llu", (unsigned long long)position);
    }

    if (length == 0) {
        if (file_sending_done) {
            ck_abort_msg("File sending already done.");
        }

        file_sending_done = 1;
        return;
    }

    if (position + length > max_sending) {
        if (m_send_reached) {
            ck_abort_msg("Requested done file transfer.");
        }

        length = max_sending - position;
        m_send_reached = 1;
    }

    TOX_ERR_FILE_SEND_CHUNK error;
    VLA(uint8_t, f_data, length);
    memset(f_data, sending_num, length);

    if (tox_file_send_chunk(tox, friend_number, file_number, position, f_data, length, &error)) {
        ++sending_num;
        sending_pos += length;
    } else {
        ck_abort_msg("Could not send chunk, error num=%d pos=%d len=%d", (int)error, (int)position, (int)length);
    }

    if (error != TOX_ERR_FILE_SEND_CHUNK_OK) {
        ck_abort_msg("Wrong error code");
    }
}


static uint8_t num;
static bool file_recv;
static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
    if (size_recv != position) {
        ck_abort_msg("Bad position");
    }

    if (length == 0) {
        file_recv = 1;
        return;
    }

    VLA(uint8_t, f_data, length);
    memset(f_data, num, length);
    ++num;

    if (memcmp(f_data, data, length) == 0) {
        size_recv += length;
    } else {
        ck_abort_msg("FILE_CORRUPTED");
    }
}

START_TEST(test_few_clients)
{
    printf("Starting test: few_clients\n");
    uint32_t index[] = { 1, 2, 3 };
    long long unsigned int cur_time = time(nullptr);
    TOX_ERR_NEW t_n_error;
    Tox *tox1 = tox_new_log(nullptr, &t_n_error, &index[0]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox2 = tox_new_log(nullptr, &t_n_error, &index[1]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox3 = tox_new_log(nullptr, &t_n_error, &index[2]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    {
        TOX_ERR_GET_PORT error;
        uint16_t first_port = tox_self_get_udp_port(tox1, &error);
        ck_assert_msg(33445 <= first_port && first_port <= 33545 - 2,
                      "First Tox instance did not bind to udp port inside [33445, 33543].\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");

        ck_assert_msg(tox_self_get_udp_port(tox2, &error) == first_port + 1,
                      "Second Tox instance did not bind to udp port %d.\n", first_port + 1);
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");

        ck_assert_msg(tox_self_get_udp_port(tox3, &error) == first_port + 2,
                      "Third Tox instance did not bind to udp port %d.\n", first_port + 2);
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t dhtKey[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dhtKey);
    uint16_t dhtPort = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, TOX_LOCALHOST, dhtPort, dhtKey, nullptr);
    tox_bootstrap(tox3, TOX_LOCALHOST, dhtPort, dhtKey, nullptr);

    printf("Waiting for toxes to come online\n");

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(tox3) == TOX_CONNECTION_NONE ||
            tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_NONE ||
            tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_NONE) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        printf("Connections: self (%d, %d, %d), friends (%d, %d)\n",
               tox_self_get_connection_status(tox1),
               tox_self_get_connection_status(tox2),
               tox_self_get_connection_status(tox3),
               tox_friend_get_connection_status(tox2, 0, nullptr),
               tox_friend_get_connection_status(tox3, 0, nullptr));
        c_sleep(1000);
    }

    printf("Starting file transfer test.\n");

    file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    max_sending = UINT64_MAX;
    long long unsigned int f_time = time(nullptr);
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    uint64_t totalf_size = 100 * 1024 * 1024;
    uint32_t fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr, (const uint8_t *)"Gentoo.exe",
                                  sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    TOX_ERR_FILE_GET gfierr;
    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    while (1) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (file_sending_done) {
            if (sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size && sending_pos == size_recv
                    && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %llu %llu %llu", sendf_ok, file_recv,
                         totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1,
                         (unsigned long long)totalf_size, (unsigned long long)size_recv,
                         (unsigned long long)sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("100MB file sent in %llu seconds\n", time(nullptr) - f_time);

    printf("Starting file streaming transfer test.\n");

    file_sending_done = file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    totalf_size = UINT64_MAX;
    fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr,
                         (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    max_sending = 100 * 1024;
    m_send_reached = 0;

    while (1) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (file_sending_done) {
            if (sendf_ok && file_recv && m_send_reached && totalf_size == file_size && size_recv == max_sending
                    && sending_pos == size_recv && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %u %llu %llu %llu %llu", sendf_ok, file_recv,
                         m_send_reached, totalf_size == file_size, size_recv == max_sending, sending_pos == size_recv, file_accepted == 1,
                         (unsigned long long)totalf_size, (unsigned long long)file_size,
                         (unsigned long long)size_recv, (unsigned long long)sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("Starting file 0 transfer test.\n");

    file_sending_done = file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    totalf_size = 0;
    fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr,
                         (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    while (1) {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        if (file_sending_done) {
            if (sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size && sending_pos == size_recv
                    && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %llu %llu %llu", sendf_ok, file_recv,
                         totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1,
                         (unsigned long long)totalf_size, (unsigned long long)size_recv,
                         (unsigned long long)sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("test_few_clients succeeded, took %llu seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}
END_TEST

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox few clients");

    DEFTESTCASE(few_clients);

    return s;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    srand((unsigned int) time(nullptr));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
