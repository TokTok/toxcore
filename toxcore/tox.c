/*
 * The Tox public API.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _XOPEN_SOURCE 600

#define TOX_DEFINED
typedef struct Messenger Tox;
#include "tox.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "Messenger.h"
#include "group.h"
#include "group_chats.h"
#include "group_moderation.h"
#include "logger.h"

#include "../toxencryptsave/defines.h"

#define SET_ERROR_PARAMETER(param, x) do { if (param) { *param = x; } } while (0)

#if TOX_HASH_LENGTH != CRYPTO_SHA256_SIZE
#error "TOX_HASH_LENGTH is assumed to be equal to CRYPTO_SHA256_SIZE"
#endif

#if FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error "FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE"
#endif

#if TOX_FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error "TOX_FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE"
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error "TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH"
#endif

#if TOX_PUBLIC_KEY_SIZE != CRYPTO_PUBLIC_KEY_SIZE
#error "TOX_PUBLIC_KEY_SIZE is assumed to be equal to CRYPTO_PUBLIC_KEY_SIZE"
#endif

#if TOX_SECRET_KEY_SIZE != CRYPTO_SECRET_KEY_SIZE
#error "TOX_SECRET_KEY_SIZE is assumed to be equal to CRYPTO_SECRET_KEY_SIZE"
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error "TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH"
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error "TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH"
#endif


bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    return TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch);
}


Tox *tox_new(const struct Tox_Options *options, Tox_Err_New *error)
{
    Messenger_Options m_options = {0};

    bool load_savedata_sk = false, load_savedata_tox = false;

    struct Tox_Options *default_options = nullptr;

    if (options == nullptr) {
        Tox_Err_Options_New err;
        default_options = tox_options_new(&err);

        switch (err) {
            case TOX_ERR_OPTIONS_NEW_OK:
                break;

            case TOX_ERR_OPTIONS_NEW_MALLOC:
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
                return nullptr;
        }
    }

    const struct Tox_Options *const opts = options != nullptr ? options : default_options;
    assert(opts != nullptr);

    if (tox_options_get_savedata_type(opts) != TOX_SAVEDATA_TYPE_NONE) {
        if (tox_options_get_savedata_data(opts) == nullptr || tox_options_get_savedata_length(opts) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            return nullptr;
        }
    }

    if (tox_options_get_savedata_type(opts) == TOX_SAVEDATA_TYPE_SECRET_KEY) {
        if (tox_options_get_savedata_length(opts) != TOX_SECRET_KEY_SIZE) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            return nullptr;
        }

        load_savedata_sk = true;
    } else if (tox_options_get_savedata_type(opts) == TOX_SAVEDATA_TYPE_TOX_SAVE) {
        if (tox_options_get_savedata_length(opts) < TOX_ENC_SAVE_MAGIC_LENGTH) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            return nullptr;
        }

        if (crypto_memcmp(tox_options_get_savedata_data(opts), TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
            tox_options_free(default_options);
            return nullptr;
        }

        load_savedata_tox = true;
    }

    m_options.ipv6enabled = tox_options_get_ipv6_enabled(opts);
    m_options.udp_disabled = !tox_options_get_udp_enabled(opts);
    m_options.port_range[0] = tox_options_get_start_port(opts);
    m_options.port_range[1] = tox_options_get_end_port(opts);
    m_options.tcp_server_port = tox_options_get_tcp_port(opts);
    m_options.hole_punching_enabled = tox_options_get_hole_punching_enabled(opts);
    m_options.local_discovery_enabled = tox_options_get_local_discovery_enabled(opts);

    m_options.log_callback = (logger_cb *)tox_options_get_log_callback(opts);
    m_options.log_user_data = tox_options_get_log_user_data(opts);

    switch (tox_options_get_proxy_type(opts)) {
        case TOX_PROXY_TYPE_HTTP:
            m_options.proxy_info.proxy_type = TCP_PROXY_HTTP;
            break;

        case TOX_PROXY_TYPE_SOCKS5:
            m_options.proxy_info.proxy_type = TCP_PROXY_SOCKS5;
            break;

        case TOX_PROXY_TYPE_NONE:
            m_options.proxy_info.proxy_type = TCP_PROXY_NONE;
            break;

        default:
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_TYPE);
            tox_options_free(default_options);
            return nullptr;
    }

    if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
        if (tox_options_get_proxy_port(opts) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
            tox_options_free(default_options);
            return nullptr;
        }

        ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

        if (m_options.ipv6enabled) {
            m_options.proxy_info.ip_port.ip.family = net_family_unspec;
        }

        if (addr_resolve_or_parse_ip(tox_options_get_proxy_host(opts), &m_options.proxy_info.ip_port.ip, nullptr) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
            // TODO(irungentoo): TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
            tox_options_free(default_options);
            return nullptr;
        }

        m_options.proxy_info.ip_port.port = net_htons(tox_options_get_proxy_port(opts));
    }

    unsigned int m_error;
    Messenger *m = new_messenger(&m_options, &m_error);

    if (!new_groupchats(m)) {
        kill_messenger(m);

        if (m_error == MESSENGER_ERROR_PORT) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else if (m_error == MESSENGER_ERROR_TCP_SERVER) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        }

        tox_options_free(default_options);
        return nullptr;
    }

    if (load_savedata_tox
            && messenger_load(m, tox_options_get_savedata_data(opts), tox_options_get_savedata_length(opts)) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else if (load_savedata_sk) {
        load_secret_key(m->net_crypto, tox_options_get_savedata_data(opts));
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

    tox_options_free(default_options);
    return m;
}

void tox_kill(Tox *tox)
{
    if (tox == nullptr) {
        return;
    }

    Messenger *m = tox;
    kill_groupchats((Group_Chats *)m->conferences_object);
#ifndef VANILLA_NACL
    kill_dht_groupchats(m->group_handler);
#endif /* VANILLA_NACL */
    kill_messenger(m);
}

size_t tox_get_savedata_size(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_size(m);
}

void tox_get_savedata(const Tox *tox, uint8_t *savedata)
{
    if (savedata) {
        const Messenger *m = tox;
        messenger_save(m, savedata);
    }
}

bool tox_bootstrap(Tox *tox, const char *host, uint16_t port, const uint8_t *public_key, Tox_Err_Bootstrap *error)
{
    if (!host || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    int32_t count = net_getipport(host, &root, TOX_SOCK_DGRAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    for (i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        Messenger *m = tox;
        onion_add_bs_path_node(m->onion_c, root[i], public_key);
        dht_bootstrap(m->dht, root[i], public_key);
    }

    net_freeipport(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

bool tox_add_tcp_relay(Tox *tox, const char *host, uint16_t port, const uint8_t *public_key,
                       Tox_Err_Bootstrap *error)
{
    if (!host || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    int32_t count = net_getipport(host, &root, TOX_SOCK_STREAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    for (i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        Messenger *m = tox;
        add_tcp_relay(m->net_crypto, root[i], public_key);
    }

    net_freeipport(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

Tox_Connection tox_self_get_connection_status(const Tox *tox)
{
    const Messenger *m = tox;

    unsigned int ret = onion_connection_status(m->onion_c);

    if (ret == 2) {
        return TOX_CONNECTION_UDP;
    }

    if (ret == 1) {
        return TOX_CONNECTION_TCP;
    }

    return TOX_CONNECTION_NONE;
}


void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback)
{
    Messenger *m = tox;
    m_callback_core_connection(m, (m_self_connection_status_cb *)callback);
}

uint32_t tox_iteration_interval(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_run_interval(m);
}

void tox_iterate(Tox *tox, void *user_data)
{
    Messenger *m = tox;
    do_messenger(m, user_data);
    do_groupchats((Group_Chats *)m->conferences_object, user_data);
}

void tox_self_get_address(const Tox *tox, uint8_t *address)
{
    if (address) {
        const Messenger *m = tox;
        getaddress(m, address);
    }
}

void tox_self_set_nospam(Tox *tox, uint32_t nospam)
{
    Messenger *m = tox;
    set_nospam(m->fr, net_htonl(nospam));
}

uint32_t tox_self_get_nospam(const Tox *tox)
{
    const Messenger *m = tox;
    return net_ntohl(get_nospam(m->fr));
}

void tox_self_get_public_key(const Tox *tox, uint8_t *public_key)
{
    const Messenger *m = tox;

    if (public_key) {
        memcpy(public_key, nc_get_self_public_key(m->net_crypto), CRYPTO_PUBLIC_KEY_SIZE);
    }
}

void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key)
{
    const Messenger *m = tox;

    if (secret_key) {
        memcpy(secret_key, nc_get_self_secret_key(m->net_crypto), CRYPTO_SECRET_KEY_SIZE);
    }
}

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, Tox_Err_Set_Info *error)
{
    if (!name && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (setname(m, name, length) == 0) {
        // TODO(irungentoo): function to set different per group names?
        send_name_all_groups((Group_Chats *)m->conferences_object);
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    return 0;
}

size_t tox_self_get_name_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_name_size(m);
}

void tox_self_get_name(const Tox *tox, uint8_t *name)
{
    if (name) {
        const Messenger *m = tox;
        getself_name(m, name);
    }
}

bool tox_self_set_status_message(Tox *tox, const uint8_t *status_message, size_t length, Tox_Err_Set_Info *error)
{
    if (!status_message && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (m_set_statusmessage(m, status_message, length) == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    return 0;
}

size_t tox_self_get_status_message_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_statusmessage_size(m);
}

void tox_self_get_status_message(const Tox *tox, uint8_t *status_message)
{
    if (status_message) {
        const Messenger *m = tox;
        m_copy_self_statusmessage(m, status_message);
    }
}

void tox_self_set_status(Tox *tox, Tox_User_Status status)
{
    Messenger *m = tox;
    m_set_userstatus(m, status);
}

Tox_User_Status tox_self_get_status(const Tox *tox)
{
    const Messenger *m = tox;
    const uint8_t status = m_get_self_userstatus(m);
    return (Tox_User_Status)status;
}

static void set_friend_error(int32_t ret, Tox_Err_Friend_Add *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_MALLOC);
            break;
    }
}

uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        Tox_Err_Friend_Add *error)
{
    if (!address || !message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend(m, address, message, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, Tox_Err_Friend_Add *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend_norequest(m, public_key);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

bool tox_friend_delete(Tox *tox, uint32_t friend_number, Tox_Err_Friend_Delete *error)
{
    Messenger *m = tox;
    int ret = m_delfriend(m, friend_number);

    // TODO(irungentoo): handle if realloc fails?
    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_OK);
    return 1;
}

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, Tox_Err_Friend_By_Public_Key *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL);
        return UINT32_MAX;
    }

    const Messenger *m = tox;
    int32_t ret = getfriend_id(m, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    return ret;
}

bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               Tox_Err_Friend_Get_Public_Key *error)
{
    if (!public_key) {
        return 0;
    }

    const Messenger *m = tox;

    if (get_real_pk(m, friend_number, public_key) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);
    return 1;
}

bool tox_friend_exists(const Tox *tox, uint32_t friend_number)
{
    const Messenger *m = tox;
    return m_friend_exists(m, friend_number);
}

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Get_Last_Online *error)
{
    const Messenger *m = tox;
    uint64_t timestamp = m_get_last_online(m, friend_number);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND);
        return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    return timestamp;
}

size_t tox_self_get_friend_list_size(const Tox *tox)
{
    const Messenger *m = tox;
    return count_friendlist(m);
}

void tox_self_get_friend_list(const Tox *tox, uint32_t *friend_list)
{
    if (friend_list) {
        const Messenger *m = tox;
        // TODO(irungentoo): size parameter?
        copy_friendlist(m, friend_list, tox_self_get_friend_list_size(tox));
    }
}

size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    const Messenger *m = tox;
    int ret = m_get_name_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, Tox_Err_Friend_Query *error)
{
    if (!name) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    int ret = getname(m, friend_number, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *callback)
{
    Messenger *m = tox;
    m_callback_namechange(m, callback);
}

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    const Messenger *m = tox;
    int ret = m_get_statusmessage_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *status_message,
                                   Tox_Err_Friend_Query *error)
{
    if (!status_message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    // TODO(irungentoo): size parameter?
    int ret = m_copy_statusmessage(m, friend_number, status_message, m_get_statusmessage_size(m, friend_number));

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *callback)
{
    Messenger *m = tox;
    m_callback_statusmessage(m, callback);
}

Tox_User_Status tox_friend_get_status(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    const Messenger *m = tox;

    int ret = m_get_userstatus(m, friend_number);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return (Tox_User_Status)(TOX_USER_STATUS_BUSY + 1);
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (Tox_User_Status)ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback)
{
    Messenger *m = tox;
    m_callback_userstatus(m, (m_friend_status_cb *)callback);
}

Tox_Connection tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    const Messenger *m = tox;

    int ret = m_get_friend_connectionstatus(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (Tox_Connection)ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
    Messenger *m = tox;
    m_callback_connectionstatus(m, (m_friend_connection_status_cb *)callback);
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    const Messenger *m = tox;
    int ret = m_get_istyping(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return !!ret;
}

void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *callback)
{
    Messenger *m = tox;
    m_callback_typingchange(m, callback);
}

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, Tox_Err_Set_Typing *error)
{
    Messenger *m = tox;

    if (m_set_usertyping(m, friend_number, typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    return 1;
}

static void set_message_error(int ret, Tox_Err_Friend_Send_Message *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
            break;

        case -5:
            /* can't happen */
            break;
    }
}

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message,
                                 size_t length, Tox_Err_Friend_Send_Message *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_NULL);
        return 0;
    }

    if (!length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY);
        return 0;
    }

    Messenger *m = tox;
    uint32_t message_id = 0;
    set_message_error(m_send_message_generic(m, friend_number, type, message, length, &message_id), error);
    return message_id;
}

void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *callback)
{
    Messenger *m = tox;
    m_callback_read_receipt(m, callback);
}

void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *callback)
{
    Messenger *m = tox;
    m_callback_friendrequest(m, callback);
}

void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *callback)
{
    Messenger *m = tox;
    m_callback_friendmessage(m, (m_friend_message_cb *)callback);
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || (length && !data)) {
        return 0;
    }

    crypto_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, Tox_File_Control control,
                      Tox_Err_File_Control *error)
{
    Messenger *m = tox;
    int ret = file_control(m, friend_number, file_number, control);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_FOUND);
            return 0;

        case -4:
            /* can't happen */
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_ALREADY_PAUSED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_DENIED);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_PAUSED);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                   Tox_Err_File_Seek *error)
{
    Messenger *m = tox;
    int ret = file_seek(m, friend_number, file_number, position);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_NOT_FOUND);
            return 0;

        case -4: // fall-through
        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_DENIED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_INVALID_POSITION);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback)
{
    Messenger *m = tox;
    callback_file_control(m, (m_file_recv_control_cb *)callback);
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          Tox_Err_File_Get *error)
{
    if (!file_id) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NULL);
        return 0;
    }

    const Messenger *m = tox;
    int ret = file_get_id(m, friend_number, file_number, file_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_OK);
        return 1;
    }

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_FRIEND_NOT_FOUND);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NOT_FOUND);
    }

    return 0;
}

uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, Tox_Err_File_Send *error)
{
    if (filename_length && !filename) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NULL);
        return UINT32_MAX;
    }

    uint8_t f_id[FILE_ID_LENGTH];

    if (!file_id) {
        /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
        new_symmetric_key(f_id);
        file_id = f_id;
    }

    Messenger *m = tox;
    long int file_num = new_filesender(m, friend_number, kind, file_size, file_id, filename, filename_length);

    if (file_num >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_OK);
        return file_num;
    }

    switch (file_num) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NAME_TOO_LONG);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_TOO_MANY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, Tox_Err_File_Send_Chunk *error)
{
    Messenger *m = tox;
    int ret = file_data(m, friend_number, file_number, position, data, length);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_SENDQ);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback)
{
    Messenger *m = tox;
    callback_file_reqchunk(m, callback);
}

void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *callback)
{
    Messenger *m = tox;
    callback_file_sendrequest(m, callback);
}

void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback)
{
    Messenger *m = tox;
    callback_file_data(m, callback);
}

void tox_callback_conference_invite(Tox *tox, tox_conference_invite_cb *callback)
{
    Messenger *m = tox;
    g_callback_group_invite((Group_Chats *)m->conferences_object, (g_conference_invite_cb *)callback);
}

void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback)
{
    Messenger *m = tox;
    g_callback_group_message((Group_Chats *)m->conferences_object, (g_conference_message_cb *)callback);
}

void tox_callback_conference_title(Tox *tox, tox_conference_title_cb *callback)
{
    Messenger *m = tox;
    g_callback_group_title((Group_Chats *)m->conferences_object, callback);
}

void tox_callback_conference_peer_name(Tox *tox, tox_conference_peer_name_cb *callback)
{
    Messenger *m = tox;
    g_callback_peer_name((Group_Chats *)m->conferences_object, callback);
}

void tox_callback_conference_peer_list_changed(Tox *tox, tox_conference_peer_list_changed_cb *callback)
{
    Messenger *m = tox;
    g_callback_peer_list_changed((Group_Chats *)m->conferences_object, callback);
}

uint32_t tox_conference_new(Tox *tox, Tox_Err_Conference_New *error)
{
    Messenger *m = tox;
    int ret = add_groupchat((Group_Chats *)m->conferences_object, GROUPCHAT_TYPE_TEXT);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_INIT);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_OK);
    return ret;
}

bool tox_conference_delete(Tox *tox, uint32_t conference_number, Tox_Err_Conference_Delete *error)
{
    Messenger *m = tox;
    int ret = del_groupchat((Group_Chats *)m->conferences_object, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_OK);
    return true;
}

uint32_t tox_conference_peer_count(const Tox *tox, uint32_t conference_number, Tox_Err_Conference_Peer_Query *error)
{
    const Messenger *m = tox;
    int ret = group_number_peers((Group_Chats *)m->conferences_object, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

size_t tox_conference_peer_get_name_size(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
        Tox_Err_Conference_Peer_Query *error)
{
    const Messenger *m = tox;
    int ret = group_peername_size((Group_Chats *)m->conferences_object, conference_number, peer_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_peer_get_name(const Tox *tox, uint32_t conference_number, uint32_t peer_number, uint8_t *name,
                                  Tox_Err_Conference_Peer_Query *error)
{
    const Messenger *m = tox;
    int ret = group_peername((Group_Chats *)m->conferences_object, conference_number, peer_number, name);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_get_public_key(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        uint8_t *public_key, Tox_Err_Conference_Peer_Query *error)
{
    const Messenger *m = tox;
    int ret = group_peer_pubkey((Group_Chats *)m->conferences_object, conference_number, peer_number, public_key);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_number_is_ours(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        Tox_Err_Conference_Peer_Query *error)
{
    const Messenger *m = tox;
    int ret = group_peernumber_is_ours((Group_Chats *)m->conferences_object, conference_number, peer_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_invite(Tox *tox, uint32_t friend_number, uint32_t conference_number,
                           Tox_Err_Conference_Invite *error)
{
    Messenger *m = tox;
    int ret = invite_friend((Group_Chats *)m->conferences_object, friend_number, conference_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_OK);
    return true;
}

uint32_t tox_conference_join(Tox *tox, uint32_t friend_number, const uint8_t *cookie, size_t length,
                             Tox_Err_Conference_Join *error)
{
    Messenger *m = tox;
    int ret = join_groupchat((Group_Chats *)m->conferences_object, friend_number, GROUPCHAT_TYPE_TEXT, cookie, length);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_DUPLICATE);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INIT_FAIL);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FAIL_SEND);
            return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_OK);
    return ret;
}

bool tox_conference_send_message(Tox *tox, uint32_t conference_number, Tox_Message_Type type, const uint8_t *message,
                                 size_t length, Tox_Err_Conference_Send_Message *error)
{
    Messenger *m = tox;
    int ret = 0;

    if (type == TOX_MESSAGE_TYPE_NORMAL) {
        ret = group_message_send((Group_Chats *)m->conferences_object, conference_number, message, length);
    } else {
        ret = group_action_send((Group_Chats *)m->conferences_object, conference_number, message, length);
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION);
            return false;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_OK);
    return true;
}

size_t tox_conference_get_title_size(const Tox *tox, uint32_t conference_number, Tox_Err_Conference_Title *error)
{
    const Messenger *m = tox;
    int ret = group_title_get_size((Group_Chats *)m->conferences_object, conference_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return ret;
}

bool tox_conference_get_title(const Tox *tox, uint32_t conference_number, uint8_t *title,
                              Tox_Err_Conference_Title *error)
{
    const Messenger *m = tox;
    int ret = group_title_get((Group_Chats *)m->conferences_object, conference_number, title);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

bool tox_conference_set_title(Tox *tox, uint32_t conference_number, const uint8_t *title, size_t length,
                              Tox_Err_Conference_Title *error)
{
    Messenger *m = tox;
    int ret = group_title_send((Group_Chats *)m->conferences_object, conference_number, title, length);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

size_t tox_conference_get_chatlist_size(const Tox *tox)
{
    const Messenger *m = tox;
    return count_chatlist((Group_Chats *)m->conferences_object);
}

void tox_conference_get_chatlist(const Tox *tox, uint32_t *chatlist)
{
    const Messenger *m = tox;
    size_t list_size = tox_conference_get_chatlist_size(tox);
    copy_chatlist((Group_Chats *)m->conferences_object, chatlist, list_size);
}

Tox_Conference_Type tox_conference_get_type(const Tox *tox, uint32_t conference_number,
        Tox_Err_Conference_Get_Type *error)
{
    const Messenger *m = tox;
    int ret = group_get_type((Group_Chats *)m->conferences_object, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND);
        return (Tox_Conference_Type)ret;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_OK);
    return (Tox_Conference_Type)ret;
}

static void set_custom_packet_error(int ret, Tox_Err_Friend_Custom_Packet *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED);
            break;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ);
            break;
    }
}

bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  Tox_Err_Friend_Custom_Packet *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    if (data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
        return 0;
    }

    int ret = m_send_custom_lossy_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *callback)
{
    Messenger *m = tox;
    custom_lossy_packet_registerhandler(m, callback);
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     Tox_Err_Friend_Custom_Packet *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    int ret = send_custom_lossless_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback)
{
    Messenger *m = tox;
    custom_lossless_packet_registerhandler(m, callback);
}

void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id)
{
    if (dht_id) {
        const Messenger *m = tox;
        memcpy(dht_id, dht_get_self_public_key(m->dht), CRYPTO_PUBLIC_KEY_SIZE);
    }
}

uint16_t tox_self_get_udp_port(const Tox *tox, Tox_Err_Get_Port *error)
{
    const Messenger *m = tox;
    uint16_t port = net_htons(net_port(m->net));

    if (port) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    }

    return port;
}

uint16_t tox_self_get_tcp_port(const Tox *tox, Tox_Err_Get_Port *error)
{
    const Messenger *m = tox;

    if (m->tcp_server) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
        return m->options.tcp_server_port;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    return 0;
}

/**************** GROUPCHAT FUNCTIONS *****************/

#ifndef VANILLA_NACL
void tox_callback_group_invite(Tox *tox, tox_group_invite_cb *function, void *userdata)
{
    Messenger *m = tox;
    m_callback_group_invite(m, function, userdata);
}

void tox_callback_group_message(Tox *tox, tox_group_message_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_message(m, (void (*)(struct Messenger *, uint32_t, uint32_t, unsigned int, const uint8_t *, size_t,
                                     void *))function, userdata);
}

void tox_callback_group_private_message(Tox *tox, tox_group_private_message_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_private_message(m, (void (*)(struct Messenger *, uint32_t, uint32_t, unsigned int, const uint8_t *,
                                             size_t, void *))function, userdata);
}

void tox_callback_group_custom_packet(Tox *tox, tox_group_custom_packet_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_custom_packet(m, function, user_data);
}

void tox_callback_group_moderation(Tox *tox, tox_group_moderation_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_moderation(m, (void (*)(struct Messenger *, uint32_t, uint32_t, uint32_t, unsigned int, void *))function,
                           userdata);
}

void tox_callback_group_peer_name(Tox *tox, tox_group_peer_name_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_nick_change(m, function, userdata);
}

void tox_callback_group_peer_status(Tox *tox, tox_group_peer_status_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_status_change(m, (void (*)(struct Messenger *, uint32_t, uint32_t, unsigned int, void *))function,
                              userdata);
}

void tox_callback_group_topic(Tox *tox, tox_group_topic_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_topic_change(m, function, userdata);
}

void tox_callback_group_privacy_state(Tox *tox, tox_group_privacy_state_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_privacy_state(m, (void (*)(struct Messenger *, uint32_t, unsigned int, void *))function, user_data);
}

void tox_callback_group_peer_limit(Tox *tox, tox_group_peer_limit_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_peer_limit(m, function, user_data);
}

void tox_callback_group_password(Tox *tox, tox_group_password_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_password(m, function, user_data);
}

void tox_callback_group_peer_join(Tox *tox, tox_group_peer_join_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_join(m, function, userdata);
}

void tox_callback_group_peer_exit(Tox *tox, tox_group_peer_exit_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_exit(m, function, userdata);
}

void tox_callback_group_self_join(Tox *tox, tox_group_self_join_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_self_join(m, function, userdata);
}

void tox_callback_group_join_fail(Tox *tox, tox_group_join_fail_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_rejected(m, (void (*)(struct Messenger *, uint32_t, unsigned int, void *))function, userdata);
}

Group_Chat_Self_Peer_Info *tox_group_self_peer_info_new(TOX_ERR_GC_SELF_PEER_INFO *error)
{
    Group_Chat_Self_Peer_Info *peer_info = (Group_Chat_Self_Peer_Info*)calloc(1, sizeof(Group_Chat_Self_Peer_Info));

    SET_ERROR_PARAMETER(error, peer_info ? TOX_ERR_GC_SELF_PEER_INFO_OK : TOX_ERR_GC_SELF_PEER_INFO_MALLOC);
    return peer_info;
}

void tox_group_self_peer_info_free(Group_Chat_Self_Peer_Info *self_peer_info)
{
    free(self_peer_info);
}

static GC_SelfPeerInfo* create_self_peer_info(const Group_Chat_Self_Peer_Info *peer_info)
{
    if (!peer_info ||
        !peer_info->nick ||
        !peer_info->nick_length ||
        peer_info->nick_length > TOX_MAX_GC_PEER_LENGTH ||
        peer_info->user_status > TOX_USER_STATUS_BUSY) {
        return nullptr;
    }

    GC_SelfPeerInfo *self_peer_info = (GC_SelfPeerInfo *)calloc(1, sizeof(GC_SelfPeerInfo));
    if (self_peer_info) {
        self_peer_info->user_status = (GROUP_PEER_STATUS)peer_info->user_status;
        self_peer_info->nick_length = peer_info->nick_length;
        memcpy(self_peer_info->nick, peer_info->nick, peer_info->nick_length);
    }

    return self_peer_info;
}

uint32_t tox_group_new(Tox *tox, TOX_GROUP_PRIVACY_STATE privacy_state, const uint8_t *group_name,
                       size_t group_name_length, Group_Chat_Self_Peer_Info *peer_info, TOX_ERR_GROUP_NEW *error)
{
    Messenger *m = tox;
    GC_SelfPeerInfo *self_peer_info = create_self_peer_info(peer_info);
    int ret = gc_group_add(m->group_handler, privacy_state, group_name, group_name_length, self_peer_info);
    free(self_peer_info);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_TOO_LONG);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_EMPTY);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_PRIVACY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_INIT);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_STATE);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_PEER_INFO);
            return UINT32_MAX;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_ANNOUNCE);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

uint32_t tox_group_join(Tox *tox, const uint8_t *chat_id, const uint8_t *password, size_t password_length,
                        struct Group_Chat_Self_Peer_Info *peer_info, TOX_ERR_GROUP_JOIN *error)
{
    Messenger *m = tox;
    GC_SelfPeerInfo *self_peer_info = create_self_peer_info(peer_info);
    int ret = gc_group_join(m->group_handler, chat_id, password, password_length, self_peer_info);
    free(self_peer_info);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_INIT);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_BAD_CHAT_ID);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_is_connected(Tox *tox, uint32_t group_number, TOX_ERR_GROUP_IS_CONNECTED *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_IS_CONNECTED_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_IS_CONNECTED_OK);

    return chat->connection_state != CS_MANUALLY_DISCONNECTED;
}

bool tox_group_disconnect(Tox *tox, uint32_t group_number, TOX_ERR_GROUP_DISCONNECT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_DISCONNECT_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_DISCONNECT_ALREADY_DISCONNECTED);
        return 0;
    }

    bool disconnection_result = gc_disconnect_from_group(m->group_handler, chat);
    SET_ERROR_PARAMETER(error, disconnection_result ? TOX_ERR_GROUP_DISCONNECT_OK : TOX_ERR_GROUP_DISCONNECT_ERROR);

    return disconnection_result;
}

bool tox_group_reconnect(Tox *tox, uint32_t group_number, TOX_ERR_GROUP_RECONNECT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND);
        return 0;
    }

    bool reconnection_result = gc_rejoin_group(m->group_handler, chat);
    SET_ERROR_PARAMETER(error, reconnection_result ? TOX_ERR_GROUP_RECONNECT_OK : TOX_ERR_GROUP_RECONNECT_MALLOC);

    return reconnection_result;
}

bool tox_group_leave(Tox *tox, uint32_t group_number, const uint8_t *partmessage, size_t length,
                     TOX_ERR_GROUP_LEAVE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_group_exit(m->group_handler, chat, partmessage, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_FAIL_SEND);
            return 1;   /* the group was still successfully deleted */

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_DELETE_FAIL);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_self_set_name(Tox *tox, uint32_t group_number, const uint8_t *name, size_t length,
                             TOX_ERR_GROUP_SELF_NAME_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_nick(m, group_number, name, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_INVALID);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TAKEN);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_self_get_name_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_nick_size(chat);
}

bool tox_group_self_get_name(const Tox *tox, uint32_t group_number, uint8_t *name, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_nick(chat, name);
    return 1;
}

bool tox_group_self_set_status(Tox *tox, uint32_t group_number, TOX_USER_STATUS status,
                               TOX_ERR_GROUP_SELF_STATUS_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_status(m, group_number, status);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

TOX_USER_STATUS tox_group_self_get_status(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (TOX_USER_STATUS) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t status = gc_get_self_status(chat);
    return (TOX_USER_STATUS)status;
}

TOX_GROUP_ROLE tox_group_self_get_role(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (TOX_GROUP_ROLE) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t role = gc_get_self_role(chat);
    return (TOX_GROUP_ROLE)role;
}

uint32_t tox_group_self_get_peer_id(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_peer_id(chat);
}

bool tox_group_self_get_public_key(const Tox *tox, uint32_t group_number, uint8_t *public_key,
                                   TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_public_key(chat, public_key);
    return 1;
}

size_t tox_group_get_peers_list_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_PEER_LIST_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_LIST_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_LIST_QUERY_OK);

    return group_get_peers_list_size(chat);
}

bool tox_group_get_peers_list(const Tox *tox, uint32_t group_number, uint32_t *peers_list, TOX_ERR_GROUP_PEER_LIST_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_LIST_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    if (!peers_list) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_LIST_QUERY_PARAMETER_IS_NULL);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_LIST_QUERY_OK);
    group_get_peers_list(chat, peers_list);

    return 1;
}


size_t tox_group_peer_get_name_size(const Tox *tox, uint32_t group_number, uint32_t peer_id,
                                    TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    int ret = gc_get_peer_nick_size(chat, peer_id);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
        return ret;
    }
}

bool tox_group_peer_get_name(const Tox *tox, uint32_t group_number, uint32_t peer_id, uint8_t *name,
                             TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_nick(chat, peer_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

TOX_USER_STATUS tox_group_peer_get_status(const Tox *tox, uint32_t group_number, uint32_t peer_id,
        TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return (TOX_USER_STATUS) - 1;
    }

    uint8_t ret = gc_get_status(chat, peer_id);

    if (ret == (uint8_t) - 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return (TOX_USER_STATUS) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return (TOX_USER_STATUS)ret;
}

TOX_GROUP_ROLE tox_group_peer_get_role(const Tox *tox, uint32_t group_number, uint32_t peer_id,
                                       TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return (TOX_GROUP_ROLE) - 1;
    }

    uint8_t ret = gc_get_role(chat, peer_id);

    if (ret == (uint8_t) - 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return (TOX_GROUP_ROLE) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return (TOX_GROUP_ROLE)ret;
}

bool tox_group_peer_get_public_key(const Tox *tox, uint32_t group_number, uint32_t peer_id, uint8_t *public_key,
                                   TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_public_key_by_peer_id(chat, peer_id, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

bool tox_group_set_topic(Tox *tox, uint32_t group_number, const uint8_t *topic, size_t length,
                         TOX_ERR_GROUP_TOPIC_SET *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_set_topic(chat, topic, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_get_topic_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_topic_size(chat);
}

bool tox_group_get_topic(const Tox *tox, uint32_t group_number, uint8_t *topic, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_topic(chat, topic);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

size_t tox_group_get_name_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_group_name_size(chat);
}

bool tox_group_get_name(const Tox *tox, uint32_t group_number, uint8_t *groupname, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_group_name(chat, groupname);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

bool tox_group_get_chat_id(const Tox *tox, uint32_t group_number, uint8_t *chat_id, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_chat_id(chat, chat_id);
    return 1;
}

uint32_t tox_group_get_number_groups(const Tox *tox)
{
    const Messenger *m = tox;
    return gc_count_groups(m->group_handler);
}

void tox_groups_get_list(const Tox *tox, uint32_t *list)
{
    const Messenger *m = tox;
    const GC_Session *c = m->group_handler;

    gc_copy_groups_numbers(c, list);
}

TOX_GROUP_PRIVACY_STATE tox_group_get_privacy_state(const Tox *tox, uint32_t group_number,
        TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return (TOX_GROUP_PRIVACY_STATE) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    uint8_t state = gc_get_privacy_state(chat);
    return (TOX_GROUP_PRIVACY_STATE)state;
}

uint32_t tox_group_get_peer_limit(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_max_peers(chat);
}

size_t tox_group_get_password_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_password_size(chat);
}

bool tox_group_get_password(const Tox *tox, uint32_t group_number, uint8_t *password, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_password(chat, password);
    return 1;
}

bool tox_group_send_message(Tox *tox, uint32_t group_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                            size_t length, TOX_ERR_GROUP_SEND_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_send_message(chat, message, length, type);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_private_message(Tox *tox, uint32_t group_number, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                    const uint8_t *message, size_t length, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_send_private_message(chat, peer_id, type, message, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_BAD_TYPE);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_custom_packet(Tox *tox, uint32_t group_number, bool lossless, const uint8_t *data,
                                  size_t length, TOX_ERR_GROUP_SEND_CUSTOM_PACKET *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_send_custom_packet(chat, lossless, data, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_invite_friend(Tox *tox, uint32_t group_number, uint32_t friend_number, TOX_ERR_GROUP_INVITE_FRIEND *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_GROUP_IS_DISCONNECTED);
        return 0;
    }

    if (friend_not_valid(m, friend_number)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND);
        return 0;
    }

    int ret = gc_invite_friend(m->group_handler, chat, friend_number,
                               send_group_invite_packet);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

uint32_t tox_group_invite_accept(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *password, size_t password_length, struct Group_Chat_Self_Peer_Info *peer_info,
                                 TOX_ERR_GROUP_INVITE_ACCEPT *error)
{
    Messenger *m = tox;
    GC_SelfPeerInfo *self_peer_info = create_self_peer_info(peer_info);
    int ret = gc_accept_invite(m->group_handler, friend_number, invite_data, length, password, password_length, self_peer_info);
    free(self_peer_info);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_founder_set_password(Tox *tox, uint32_t group_number, const uint8_t *password, size_t length,
                                    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_founder_set_password(chat, password, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_privacy_state(Tox *tox, uint32_t group_number, TOX_GROUP_PRIVACY_STATE privacy_state,
        TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE *error)
{
    Messenger *m = tox;
    int ret = gc_founder_set_privacy_state(m, group_number, privacy_state);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS);
            return 0;

        case -4:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_IS_DISCONNECTED);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_peer_limit(Tox *tox, uint32_t group_number, uint32_t maxpeers,
                                      TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_founder_set_max_peers(chat, maxpeers);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_toggle_ignore(Tox *tox, uint32_t group_number, uint32_t peer_id, bool ignore,
                             TOX_ERR_GROUP_TOGGLE_IGNORE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_toggle_ignore(chat, peer_id, ignore);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_PEER_NOT_FOUND);
        return 0;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_OK);
        return 1;
    }
}

bool tox_group_mod_set_role(Tox *tox, uint32_t group_number, uint32_t peer_id, TOX_GROUP_ROLE role,
                            TOX_ERR_GROUP_MOD_SET_ROLE *error)
{
    Messenger *m = tox;
    int ret = gc_set_peer_role(m, group_number, peer_id, role);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_peer(Tox *tox, uint32_t group_number, uint32_t peer_id, TOX_ERR_GROUP_MOD_REMOVE_PEER *error)
{
    Messenger *m = tox;
    int ret = gc_remove_peer(m, group_number, peer_id, false, -1);

    switch (ret) {
        case 0:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_OK);
            return 1;

        case -1:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_GROUP_NOT_FOUND);
            return 0;

        case -2:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PEER_NOT_FOUND);
            return 0;

        case -3:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PERMISSIONS);
            return 0;

        case -4:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_ACTION);
            return 0;

        case -5:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_ban_peer(Tox *tox, uint32_t group_number, uint32_t peer_id,
                            TOX_GROUP_BAN_TYPE ban_type, TOX_ERR_GROUP_MOD_REMOVE_PEER *error)
{
    Messenger *m = tox;
    int ret = gc_remove_peer(m, group_number, peer_id, true, ban_type);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_ACTION);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_SEND);
            return 0;

        case -6:
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_INVALID_BAN_TYPE);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_ban(Tox *tox, uint32_t group_number, uint32_t ban_id, TOX_ERR_GROUP_MOD_REMOVE_BAN *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_IS_DISCONNECTED);
        return 0;
    }

    int ret = gc_remove_ban(chat, ban_id);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_ACTION);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_ban_get_list_size(const Tox *tox, uint32_t group_number, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return sanctions_list_num_banned(chat);
}

bool tox_group_ban_get_list(const Tox *tox, uint32_t group_number, uint32_t *list, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return 0;
    }

    sanctions_list_get_ban_list(chat, list);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

TOX_GROUP_BAN_TYPE tox_group_ban_get_type(const Tox *tox, uint32_t group_number, uint32_t ban_id,
                                          TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return (TOX_GROUP_BAN_TYPE)0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return (TOX_GROUP_BAN_TYPE)0;
    }

    int ret = sanctions_list_get_ban_type(chat, ban_id);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return (TOX_GROUP_BAN_TYPE)0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return (TOX_GROUP_BAN_TYPE)ret;
}

size_t tox_group_ban_get_target_size(const Tox *tox, uint32_t group_number, uint32_t ban_id,
                                     TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return -1;
    }

    uint16_t ret = sanctions_list_get_ban_target_length(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}

bool tox_group_ban_get_target(const Tox *tox, uint32_t group_number, uint32_t ban_id, char *name,
                              TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return -1;
    }

    int ret = sanctions_list_get_ban_target(chat, ban_id, name);

    if (!ret) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

uint64_t tox_group_ban_get_time_set(const Tox *tox, uint32_t group_number, uint32_t ban_id,
                                    TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    if (chat->connection_state == CS_MANUALLY_DISCONNECTED) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_IS_DISCONNECTED);
        return -1;
    }

    uint64_t ret = sanctions_list_get_ban_time_set(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}
#endif /* VANILLA_NACL */
