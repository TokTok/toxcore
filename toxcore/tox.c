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

#include <string.h>

#include "Messenger.h"
#include "group.h"
#include "group_chats.h"
#include "group_moderation.h"
#include "logger.h"

#include "../toxencryptsave/defines.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#if TOX_HASH_LENGTH != CRYPTO_SHA256_SIZE
#error TOX_HASH_LENGTH is assumed to be equal to CRYPTO_SHA256_SIZE
#endif

#if FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE
#endif

#if TOX_FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error TOX_FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH
#endif

#if TOX_PUBLIC_KEY_SIZE != CRYPTO_PUBLIC_KEY_SIZE
#error TOX_PUBLIC_KEY_SIZE is assumed to be equal to CRYPTO_PUBLIC_KEY_SIZE
#endif

#if TOX_SECRET_KEY_SIZE != CRYPTO_SECRET_KEY_SIZE
#error TOX_SECRET_KEY_SIZE is assumed to be equal to CRYPTO_SECRET_KEY_SIZE
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH
#endif

#if TOX_CONFERENCE_UID_SIZE != (GROUP_IDENTIFIER_LENGTH - 1)
#error TOX_CONFERENCE_UID_SIZE is assumed to be equal to (GROUP_IDENTIFIER_LENGTH - 1)
#endif

bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    return TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch);
}


Tox *tox_new(const struct Tox_Options *options, TOX_ERR_NEW *error)
{
    Messenger_Options m_options = {0};

    bool load_savedata_sk = false, load_savedata_tox = false;

    if (options == nullptr) {
        m_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    } else {
        if (tox_options_get_savedata_type(options) != TOX_SAVEDATA_TYPE_NONE) {
            if (tox_options_get_savedata_data(options) == nullptr || tox_options_get_savedata_length(options) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return nullptr;
            }
        }

        if (tox_options_get_savedata_type(options) == TOX_SAVEDATA_TYPE_SECRET_KEY) {
            if (tox_options_get_savedata_length(options) != TOX_SECRET_KEY_SIZE) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return nullptr;
            }

            load_savedata_sk = true;
        } else if (tox_options_get_savedata_type(options) == TOX_SAVEDATA_TYPE_TOX_SAVE) {
            if (tox_options_get_savedata_length(options) < TOX_ENC_SAVE_MAGIC_LENGTH) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return nullptr;
            }

            if (crypto_memcmp(tox_options_get_savedata_data(options), TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
                return nullptr;
            }

            load_savedata_tox = true;
        }

        m_options.ipv6enabled = tox_options_get_ipv6_enabled(options);
        m_options.udp_disabled = !tox_options_get_udp_enabled(options);
        m_options.port_range[0] = tox_options_get_start_port(options);
        m_options.port_range[1] = tox_options_get_end_port(options);
        m_options.tcp_server_port = tox_options_get_tcp_port(options);
        m_options.hole_punching_enabled = tox_options_get_hole_punching_enabled(options);
        m_options.local_discovery_enabled = tox_options_get_local_discovery_enabled(options);

        m_options.log_callback = (logger_cb *)tox_options_get_log_callback(options);
        m_options.log_user_data = tox_options_get_log_user_data(options);

        switch (tox_options_get_proxy_type(options)) {
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
                return nullptr;
        }

        if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
            if (tox_options_get_proxy_port(options) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
                return nullptr;
            }

            ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

            if (m_options.ipv6enabled) {
                m_options.proxy_info.ip_port.ip.family = net_family_unspec;
            }

            if (addr_resolve_or_parse_ip(tox_options_get_proxy_host(options), &m_options.proxy_info.ip_port.ip, nullptr) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
                // TODO(irungentoo): TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
                return nullptr;
            }

            m_options.proxy_info.ip_port.port = net_htons(tox_options_get_proxy_port(options));
        }
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

        return nullptr;
    }

    if (load_savedata_tox
            && messenger_load(m, tox_options_get_savedata_data(options), tox_options_get_savedata_length(options)) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else if (load_savedata_sk) {
        load_secret_key(m->net_crypto, tox_options_get_savedata_data(options));
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

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

bool tox_bootstrap(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key, TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    int32_t count = net_getipport(address, &root, TOX_SOCK_DGRAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    for (i = 0; i < count; i++) {
        root[i].port = net_htons(port);

        Messenger *m = tox;
        onion_add_bs_path_node(m->onion_c, root[i], public_key);
        DHT_bootstrap(m->dht, root[i], public_key);
    }

    net_freeipport(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

bool tox_add_tcp_relay(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key,
                       TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    int32_t count = net_getipport(address, &root, TOX_SOCK_STREAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    for (i = 0; i < count; i++) {
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

TOX_CONNECTION tox_self_get_connection_status(const Tox *tox)
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
    m_callback_core_connection(m, (void (*)(Messenger *, unsigned int, void *))callback);
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

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, TOX_ERR_SET_INFO *error)
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

bool tox_self_set_status_message(Tox *tox, const uint8_t *status_message, size_t length, TOX_ERR_SET_INFO *error)
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

void tox_self_set_status(Tox *tox, TOX_USER_STATUS status)
{
    Messenger *m = tox;
    m_set_userstatus(m, status);
}

TOX_USER_STATUS tox_self_get_status(const Tox *tox)
{
    const Messenger *m = tox;
    const uint8_t status = m_get_self_userstatus(m);
    return (TOX_USER_STATUS)status;
}

static void set_friend_error(int32_t ret, TOX_ERR_FRIEND_ADD *error)
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
                        TOX_ERR_FRIEND_ADD *error)
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

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_ADD *error)
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

bool tox_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
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

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_BY_PUBLIC_KEY *error)
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
                               TOX_ERR_FRIEND_GET_PUBLIC_KEY *error)
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

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_GET_LAST_ONLINE *error)
{
    const Messenger *m = tox;
    uint64_t timestamp = m_get_last_online(m, friend_number);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND)
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

size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
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

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, TOX_ERR_FRIEND_QUERY *error)
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

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
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
                                   TOX_ERR_FRIEND_QUERY *error)
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

TOX_USER_STATUS tox_friend_get_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_userstatus(m, friend_number);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return (TOX_USER_STATUS)(TOX_USER_STATUS_BUSY + 1);
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (TOX_USER_STATUS)ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback)
{
    Messenger *m = tox;
    m_callback_userstatus(m, (void (*)(Messenger *, uint32_t, unsigned int, void *))callback);
}

TOX_CONNECTION tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_friend_connectionstatus(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (TOX_CONNECTION)ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
    Messenger *m = tox;
    m_callback_connectionstatus(m, (void (*)(Messenger *, uint32_t, unsigned int, void *))callback);
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
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

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, TOX_ERR_SET_TYPING *error)
{
    Messenger *m = tox;

    if (m_set_usertyping(m, friend_number, typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    return 1;
}

static void set_message_error(int ret, TOX_ERR_FRIEND_SEND_MESSAGE *error)
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

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error)
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
    m_callback_friendmessage(m, (void (*)(Messenger *, uint32_t, unsigned int, const uint8_t *, size_t, void *))callback);
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || (length && !data)) {
        return 0;
    }

    crypto_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                      TOX_ERR_FILE_CONTROL *error)
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
                   TOX_ERR_FILE_SEEK *error)
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
    callback_file_control(m, (void (*)(Messenger *, uint32_t, uint32_t, unsigned int, void *))callback);
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          TOX_ERR_FILE_GET *error)
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
                       const uint8_t *filename, size_t filename_length, TOX_ERR_FILE_SEND *error)
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
                         size_t length, TOX_ERR_FILE_SEND_CHUNK *error)
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
    g_callback_group_invite((Group_Chats *)m->conferences_object, (void (*)(Messenger * m, uint32_t, int, const uint8_t *,
                            size_t,
                            void *))callback);
}

void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback)
{
    Messenger *m = tox;
    g_callback_group_message((Group_Chats *)m->conferences_object, (void (*)(Messenger * m, uint32_t, uint32_t, int,
                             const uint8_t *,
                             size_t, void *))callback);
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

uint32_t tox_conference_new(Tox *tox, TOX_ERR_CONFERENCE_NEW *error)
{
    Messenger *m = tox;
    int ret = add_groupchat((Group_Chats *)m->conferences_object, GROUPCHAT_TYPE_TEXT, nullptr);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_INIT);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_OK);
    return ret;
}

bool tox_conference_delete(Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_DELETE *error)
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

bool tox_conference_enter(Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_ENTER *error)
{
    Messenger *m = tox;
    int ret = enter_conference((Group_Chats *)m->conferences_object, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_ENTER_NOT_FOUND);
        return false;
    }

    if (ret == -2) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_ENTER_ALREADY);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_ENTER_OK);
    return true;
}

bool tox_conference_leave(Tox *tox, uint32_t conference_number, bool keep_leave, TOX_ERR_CONFERENCE_LEAVE *error)
{
    Messenger *m = tox;
    int ret = leave_conference((Group_Chats *)m->conferences_object, conference_number, keep_leave);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_LEAVE_NOT_FOUND);
        return false;
    }

    if (ret == -2) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_LEAVE_ALREADY);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_LEAVE_OK);
    return true;
}

uint32_t tox_conference_peer_count(const Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_PEER_QUERY *error)
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
        TOX_ERR_CONFERENCE_PEER_QUERY *error)
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
                                  TOX_ERR_CONFERENCE_PEER_QUERY *error)
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
                                        uint8_t *public_key, TOX_ERR_CONFERENCE_PEER_QUERY *error)
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
                                        TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    const Messenger *m = tox;
    int ret = group_peer_index_is_ours((Group_Chats *)m->conferences_object, conference_number, peer_number);

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
                           TOX_ERR_CONFERENCE_INVITE *error)
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
                             TOX_ERR_CONFERENCE_JOIN *error)
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

bool tox_conference_send_message(Tox *tox, uint32_t conference_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_CONFERENCE_SEND_MESSAGE *error)
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

size_t tox_conference_get_title_size(const Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_TITLE *error)
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
                              TOX_ERR_CONFERENCE_TITLE *error)
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
                              TOX_ERR_CONFERENCE_TITLE *error)
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

TOX_CONFERENCE_TYPE tox_conference_get_type(const Tox *tox, uint32_t conference_number,
        TOX_ERR_CONFERENCE_GET_TYPE *error)
{
    const Messenger *m = tox;
    int ret = group_get_type((Group_Chats *)m->conferences_object, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND);
        return (TOX_CONFERENCE_TYPE)ret;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_OK);
    return (TOX_CONFERENCE_TYPE)ret;
}

bool tox_conference_get_uid(const Tox *tox, uint32_t conference_number, uint8_t *uid /* TOX_CONFERENCE_ID_SIZE bytes */)
{
    const Messenger *m = tox;
    return conference_get_id((Group_Chats *)m->conferences_object, conference_number, uid);
}

uint32_t tox_conference_by_uid(const Tox *tox, const uint8_t *uid, TOX_ERR_CONFERENCE_BY_UID *error)
{
    if (!uid) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_NULL);
        return UINT32_MAX;
    }

    const Messenger *m = tox;
    int32_t ret = conference_by_uid((Group_Chats *)m->conferences_object, uid);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_OK);
    return ret;
}


static void set_custom_packet_error(int ret, TOX_ERR_FRIEND_CUSTOM_PACKET *error)
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
                                  TOX_ERR_FRIEND_CUSTOM_PACKET *error)
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
                                     TOX_ERR_FRIEND_CUSTOM_PACKET *error)
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

uint16_t tox_self_get_udp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
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

uint16_t tox_self_get_tcp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
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
    gc_callback_private_message(m, function, userdata);
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

uint32_t tox_group_new(Tox *tox, TOX_GROUP_PRIVACY_STATE privacy_state, const uint8_t *group_name, size_t length,
                       TOX_ERR_GROUP_NEW *error)
{
    Messenger *m = tox;
    int ret = gc_group_add(m->group_handler, privacy_state, group_name, length);

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
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_ANNOUNCE);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

uint32_t tox_group_join(Tox *tox, const uint8_t *chat_id, const uint8_t *password, size_t length,
                        TOX_ERR_GROUP_JOIN *error)
{
    Messenger *m = tox;
    int ret = gc_group_join(m->group_handler, chat_id, password, length);

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

bool tox_group_reconnect(Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_RECONNECT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND);
        return 0;
    }

    gc_rejoin_group(m->group_handler, chat);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_OK);
    return 1;
}

bool tox_group_leave(Tox *tox, uint32_t groupnumber, const uint8_t *partmessage, size_t length,
                     TOX_ERR_GROUP_LEAVE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND);
        return 0;
    }

    if (chat->shared_state.privacy_state != TOX_GROUP_PRIVACY_STATE_PRIVATE) {
        m_remove_friend_gc(m, chat);
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

bool tox_group_self_set_name(Tox *tox, uint32_t groupnumber, const uint8_t *name, size_t length,
                             TOX_ERR_GROUP_SELF_NAME_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_nick(m, groupnumber, name, length);

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

size_t tox_group_self_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_nick_size(chat);
}

bool tox_group_self_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *name, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_nick(chat, name);
    return 1;
}

bool tox_group_self_set_status(Tox *tox, uint32_t groupnumber, TOX_USER_STATUS status,
                               TOX_ERR_GROUP_SELF_STATUS_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_status(m, groupnumber, status);

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

TOX_USER_STATUS tox_group_self_get_status(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (TOX_USER_STATUS) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t status = gc_get_self_status(chat);
    return (TOX_USER_STATUS)status;
}

TOX_GROUP_ROLE tox_group_self_get_role(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (TOX_GROUP_ROLE) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t role = gc_get_self_role(chat);
    return (TOX_GROUP_ROLE)role;
}

uint32_t tox_group_self_get_peer_id(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_peer_id(chat);
}

bool tox_group_self_get_public_key(const Tox *tox, uint32_t groupnumber, uint8_t *public_key,
                                   TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_public_key(chat, public_key);
    return 1;
}

size_t tox_group_peer_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                    TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

bool tox_group_peer_get_name(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *name,
                             TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

TOX_USER_STATUS tox_group_peer_get_status(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
        TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

TOX_GROUP_ROLE tox_group_peer_get_role(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                       TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

bool tox_group_peer_get_public_key(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *public_key,
                                   TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_public_key(chat, peer_id, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

bool tox_group_set_topic(Tox *tox, uint32_t groupnumber, const uint8_t *topic, size_t length,
                         TOX_ERR_GROUP_TOPIC_SET *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND);
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

size_t tox_group_get_topic_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_topic_size(chat);
}

bool tox_group_get_topic(const Tox *tox, uint32_t groupnumber, uint8_t *topic, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_topic(chat, topic);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

size_t tox_group_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_group_name_size(chat);
}

bool tox_group_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *groupname, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_group_name(chat, groupname);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

bool tox_group_get_chat_id(const Tox *tox, uint32_t groupnumber, uint8_t *chat_id, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

TOX_GROUP_PRIVACY_STATE tox_group_get_privacy_state(const Tox *tox, uint32_t groupnumber,
        TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return (TOX_GROUP_PRIVACY_STATE) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    uint8_t state = gc_get_privacy_state(chat);
    return (TOX_GROUP_PRIVACY_STATE)state;
}

uint32_t tox_group_get_peer_limit(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_max_peers(chat);
}

size_t tox_group_get_password_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_password_size(chat);
}

bool tox_group_get_password(const Tox *tox, uint32_t groupnumber, uint8_t *password, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_password(chat, password);
    return 1;
}

bool tox_group_send_message(Tox *tox, uint32_t groupnumber, TOX_MESSAGE_TYPE type, const uint8_t *message,
                            size_t length, TOX_ERR_GROUP_SEND_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND);
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

bool tox_group_send_private_message(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *message,
                                    size_t length, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_private_message(chat, peer_id, message, length);

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
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_custom_packet(Tox *tox, uint32_t groupnumber, bool lossless, const uint8_t *data,
                                  size_t length, TOX_ERR_GROUP_SEND_CUSTOM_PACKET *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND);
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

bool tox_group_invite_friend(Tox *tox, uint32_t groupnumber, uint32_t friend_number, TOX_ERR_GROUP_INVITE_FRIEND *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND);
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
                                 const uint8_t *password, size_t password_length, TOX_ERR_GROUP_INVITE_ACCEPT *error)
{
    Messenger *m = tox;
    int ret = gc_accept_invite(m->group_handler, friend_number, invite_data, length, password, password_length);

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

bool tox_group_founder_set_password(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND);
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

bool tox_group_founder_set_privacy_state(Tox *tox, uint32_t groupnumber, TOX_GROUP_PRIVACY_STATE privacy_state,
        TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE *error)
{
    Messenger *m = tox;
    int ret = gc_founder_set_privacy_state(m, groupnumber, privacy_state);

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
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_peer_limit(Tox *tox, uint32_t groupnumber, uint32_t maxpeers,
                                      TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_founder_set_max_peers(chat, groupnumber, maxpeers);

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

bool tox_group_toggle_ignore(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool ignore,
                             TOX_ERR_GROUP_TOGGLE_IGNORE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

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

bool tox_group_mod_set_role(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_GROUP_ROLE role,
                            TOX_ERR_GROUP_MOD_SET_ROLE *error)
{
    Messenger *m = tox;
    int ret = gc_set_peer_role(m, groupnumber, peer_id, role);

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

bool tox_group_mod_remove_peer(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool set_ban,
                               TOX_ERR_GROUP_MOD_REMOVE_PEER *error)
{
    Messenger *m = tox;
    int ret = gc_remove_peer(m, groupnumber, peer_id, set_ban);

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

bool tox_group_mod_remove_ban(Tox *tox, uint32_t groupnumber, uint32_t ban_id, TOX_ERR_GROUP_MOD_REMOVE_BAN *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_NOT_FOUND);
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

size_t tox_group_ban_get_list_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return sanctions_list_num_banned(chat);
}

bool tox_group_ban_get_list(const Tox *tox, uint32_t groupnumber, uint32_t *list, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    sanctions_list_get_ban_list(chat, list);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

size_t tox_group_ban_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                   TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint16_t ret = sanctions_list_get_ban_nick_length(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}

bool tox_group_ban_get_name(const Tox *tox, uint32_t groupnumber, uint32_t ban_id, uint8_t *name,
                            TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = sanctions_list_get_ban_nick(chat, ban_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

uint64_t tox_group_ban_get_time_set(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                    TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
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
