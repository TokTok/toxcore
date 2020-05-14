/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Functions for the core network crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "net_crypto.h"

//#include <noise/protocol.h>

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mono_time.h"
#include "util.h"

typedef struct Packet_Data {
    uint64_t sent_time;
    uint16_t length;
    uint8_t data[MAX_CRYPTO_DATA_SIZE ];
} Packet_Data;

typedef struct Packets_Array {
    Packet_Data *buffer[CRYPTO_PACKET_BUFFER_SIZE];
    uint32_t  buffer_start;
    uint32_t  buffer_end; /* packet numbers in array: `{buffer_start, buffer_end)` */
} Packets_Array;

typedef enum Crypto_Conn_State {
    CRYPTO_CONN_FREE = 0,            /* the connection slot is free. This value is 0 so it is valid after
                                      * `crypto_memzero(...)` of the parent struct
                                      */
    CRYPTO_CONN_NO_CONNECTION,       /* the connection is allocated, but not yet used */
    CRYPTO_CONN_COOKIE_REQUESTING,   /* we are sending cookie request packets */
    CRYPTO_CONN_HANDSHAKE_SENT,      /* we are sending handshake packets */
    CRYPTO_CONN_NOT_CONFIRMED,       /* we are sending handshake packets. // AKE: accepted
                                      * we have received one from the other, but no data */
    CRYPTO_CONN_ESTABLISHED,         /* the connection is established */ // AKE: confirmed
} Crypto_Conn_State;

typedef struct Crypto_Connection {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The real public key of the peer. */
    //AKE NEW: nonces not needed for Noise => handshake object
//  uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
//  uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    //AKE NEW: session keys not needed for Noise => handshake object
//  uint8_t sessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* Our public key for this session. */
//  uint8_t sessionsecret_key[CRYPTO_SECRET_KEY_SIZE]; /* Our private key for this session. */
//  uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The session public key of the peer. */
    //AKE NEW: This shared_key should be hashed (HKDF) => done automatically in Noise => saved in handshake object
    //AKE NEW: shared_key still necessary for cookie phase / DHT-based shared_key
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]; /* The precomputed shared key from encrypt_precompute. */
    Crypto_Conn_State status; /* See Crypto_Conn_State documentation */
    uint64_t cookie_request_number; /* number used in the cookie request packets for this connection (echoID!) */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer */

    //AKE NEW: Needed for Noise
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher;
    NoiseCipherState *recv_cipher;

    uint8_t *temp_packet; /* Where the cookie request/handshake packet is stored while it is being sent. */
    uint16_t temp_packet_length;
    uint64_t temp_packet_sent_time; /* The time at which the last temp_packet was sent in ms. */
    uint32_t temp_packet_num_sent;

    IP_Port ip_portv4; /* The ip and port to contact this guy directly.*/
    IP_Port ip_portv6;
    uint64_t direct_lastrecv_timev4; /* The Time at which we last received a direct packet in ms. */
    uint64_t direct_lastrecv_timev6;

    uint64_t last_tcp_sent; /* Time the last TCP packet was sent. */

    Packets_Array send_array;
    Packets_Array recv_array;

    connection_status_cb *connection_status_callback;
    void *connection_status_callback_object;
    int connection_status_callback_id;

    connection_data_cb *connection_data_callback;
    void *connection_data_callback_object;
    int connection_data_callback_id;

    connection_lossy_data_cb *connection_lossy_data_callback;
    void *connection_lossy_data_callback_object;
    int connection_lossy_data_callback_id;

    uint64_t last_request_packet_sent;
    uint64_t direct_send_attempt_time;

    uint32_t packet_counter;
    double packet_recv_rate;
    uint64_t packet_counter_set;

    double packet_send_rate;
    uint32_t packets_left;
    uint64_t last_packets_left_set;
    double last_packets_left_rem;

    double packet_send_rate_requested;
    uint32_t packets_left_requested;
    uint64_t last_packets_left_requested_set;
    double last_packets_left_requested_rem;

    uint32_t last_sendqueue_size[CONGESTION_QUEUE_ARRAY_SIZE];
    uint32_t last_sendqueue_counter;
    long signed int last_num_packets_sent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    long signed int last_num_packets_resent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    uint32_t packets_sent;
    uint32_t packets_resent;
    uint64_t last_congestion_event;
    uint64_t rtt_time;

    /* TCP_connection connection_number */
    unsigned int connection_number_tcp;

    uint8_t maximum_speed_reached;

    /* Must be a pointer, because the struct is moved in memory */
    pthread_mutex_t *mutex;

    dht_pk_cb *dht_pk_callback;
    void *dht_pk_callback_object;
    uint32_t dht_pk_callback_number;
} Crypto_Connection;

struct Net_Crypto {
    const Logger *log;
    Mono_Time *mono_time;

    DHT *dht;
    TCP_Connections *tcp_c;

    Crypto_Connection *crypto_connections;
    pthread_mutex_t tcp_mutex;

    pthread_mutex_t connections_mutex;
    unsigned int connection_use_counter;

    uint32_t crypto_connections_length; /* Length of connections array. */

    /* Our public and secret keys. */
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    /* The secret key used for cookies */
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];

    new_connection_cb *new_connection_callback;
    void *new_connection_callback_object;

    /* The current optimal sleep time */
    uint32_t current_sleep_time;

    BS_List ip_port_list;
};

const uint8_t *nc_get_self_public_key(const Net_Crypto *c)
{
    return c->self_public_key;
}

const uint8_t *nc_get_self_secret_key(const Net_Crypto *c)
{
    return c->self_secret_key;
}

TCP_Connections *nc_get_tcp_c(const Net_Crypto *c)
{
    return c->tcp_c;
}

DHT *nc_get_dht(const Net_Crypto *c)
{
    return c->dht;
}

static bool crypt_connection_id_is_valid(const Net_Crypto *c, int crypt_connection_id)
{
    if ((uint32_t)crypt_connection_id >= c->crypto_connections_length) {
        return false;
    }

    if (c->crypto_connections == nullptr) {
        return false;
    }

    const Crypto_Conn_State status = c->crypto_connections[crypt_connection_id].status;

    if (status == CRYPTO_CONN_NO_CONNECTION || status == CRYPTO_CONN_FREE) {
        return false;
    }

    return true;
}

/* cookie timeout in seconds */
#define COOKIE_TIMEOUT 15
#define COOKIE_DATA_LENGTH (uint16_t)(CRYPTO_PUBLIC_KEY_SIZE * 2)
#define COOKIE_CONTENTS_LENGTH (uint16_t)(sizeof(uint64_t) + COOKIE_DATA_LENGTH)
#define COOKIE_LENGTH (uint16_t)(CRYPTO_NONCE_SIZE + COOKIE_CONTENTS_LENGTH + CRYPTO_MAC_SIZE)

#define COOKIE_REQUEST_PLAIN_LENGTH (uint16_t)(COOKIE_DATA_LENGTH + sizeof(uint64_t))
#define COOKIE_REQUEST_LENGTH (uint16_t)(1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE)
#define COOKIE_RESPONSE_LENGTH (uint16_t)(1 + CRYPTO_NONCE_SIZE + COOKIE_LENGTH + sizeof(uint64_t) + CRYPTO_MAC_SIZE)

/* Create a cookie request packet and put it in packet.
 * dht_public_key is the dht public key of the other
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * AKE: Peer A/Initiator creates a cookie request
 * AKE NEW: same function as old handshake
 *
 * return -1 on failure.
 * return COOKIE_REQUEST_LENGTH on success.
 */
static int create_cookie_request(const Net_Crypto *c, uint8_t *packet, uint8_t *dht_public_key, uint64_t number,
                                 uint8_t *shared_key)
{
    fprintf(stderr, "ENTERING: create_cookie_request()\n");
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH ];
    uint8_t padding[CRYPTO_PUBLIC_KEY_SIZE] = { 0 };

    memcpy(plain, c->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, padding, CRYPTO_PUBLIC_KEY_SIZE);
    // AKE: number is echoID
    memcpy(plain + (CRYPTO_PUBLIC_KEY_SIZE * 2), &number, sizeof(uint64_t));

    // AKE: shared key in case of cookie request is calculated by using initiators DHT secret key and receivers DHT public key
    dht_get_shared_key_sent(c->dht, shared_key, dht_public_key);
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);
    // AKE: set NET_PACKET_COOKIE_REQUEST => for packet handling
    packet[0] = NET_PACKET_COOKIE_REQUEST;
    memcpy(packet + 1, dht_get_self_public_key(c->dht), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    // AKE: shared key for encryption is based on DHT keys (for cookies)
    int len = encrypt_data_symmetric(shared_key, nonce, plain, sizeof(plain),
                                     packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE) {
        return -1;
    }

    return (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + len);
}

/* Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * AKE: cookie creation helper function
 * AKE NEW: same function as old handshake
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_cookie(const Logger *log, const Mono_Time *mono_time, uint8_t *cookie, const uint8_t *bytes,
                         const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH ];
    const uint64_t temp_time = mono_time_get(mono_time);
    // AKE:add the time to the Cookie content (will be encrypted)
    memcpy(contents, &temp_time, sizeof(temp_time));

    memcpy(contents + sizeof(temp_time), bytes, COOKIE_DATA_LENGTH);
    // AKE: "cookie" contains the Nonce used to encrypt the encrypted part of the cookie
    random_nonce(cookie);
    int len = encrypt_data_symmetric(encryption_key, cookie, contents, sizeof(contents), cookie + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_LENGTH - CRYPTO_NONCE_SIZE) {
        return -1;
    }

    return 0;
}

/* Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * AKE: Open Cookie helper function - peer verifies if cookie is from him
 * AKE NEW: same function as old handshake
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int open_cookie(const Logger *log, const Mono_Time *mono_time, uint8_t *bytes, const uint8_t *cookie,
                       const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH ];
    const int len = decrypt_data_symmetric(encryption_key, cookie, cookie + CRYPTO_NONCE_SIZE,
                                           COOKIE_LENGTH - CRYPTO_NONCE_SIZE, contents);

    if (len != sizeof(contents)) {
        return -1;
    }

    // AKE: Verify cookie timestamp (Toxcore has a time out of 15 seconds for cookie packets.)
    uint64_t cookie_time;
    memcpy(&cookie_time, contents, sizeof(cookie_time));
    const uint64_t temp_time = mono_time_get(mono_time);

    if (cookie_time + COOKIE_TIMEOUT < temp_time || temp_time < cookie_time) {
        return -1;
    }

    // AKE: copy static public key and DHT public key to bytes[]
    memcpy(bytes, contents + sizeof(cookie_time), COOKIE_DATA_LENGTH);
    return 0;
}

/* Create a cookie response packet and put it in packet.
 * request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
 * packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
 *
 * AKE: Peer B (receiver) receives a cookie request from another peer (e.g. Peer A)
 * AKE: Peer creates a cookie & the cookie response packet (using echoID_A from Initiator)
 * AKE NEW: same function as old handshake
 *
 * return -1 on failure.
 * return COOKIE_RESPONSE_LENGTH on success.
 */
static int create_cookie_response(const Net_Crypto *c, uint8_t *packet, const uint8_t *request_plain,
                                  const uint8_t *shared_key, const uint8_t *dht_public_key)
{
    fprintf(stderr, "ENTERING: create_cookie_response()\n");

    uint8_t cookie_plain[COOKIE_DATA_LENGTH ];
    // AKE copy the initiators/Peer A static public key to the (plain) cookie data
    memcpy(cookie_plain, request_plain, CRYPTO_PUBLIC_KEY_SIZE);

    /*
     * AKE NEW:########################################################
     * Here I would know the public key of the peer and could initialize the handshake!
     * But I don't have access to "conn" and conn->handshake
     * Also the peer shouldn't allocate any memory during the cookie phase (according to spec)
     * -> no temporary handshake variable
     */

    // AKE copy the initiators/Peer A DHT public key to the (plain) cookie data
    memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

    if (create_cookie(c->log, c->mono_time, plain, cookie_plain, c->secret_symmetric_key) != 0) {
        return -1;
    }

    // AKE: this should be the line copying the echoID_A to the plaintext
    memcpy(plain + COOKIE_LENGTH, request_plain + COOKIE_DATA_LENGTH, sizeof(uint64_t));
    // AKE: set NET_PACKET_COOKIE_RESPONSE => for packet handling
    packet[0] = NET_PACKET_COOKIE_RESPONSE;
    // AKE: Nonce used to encrypt cookie response packet
    random_nonce(packet + 1);
    int len = encrypt_data_symmetric(shared_key, packet + 1, plain, sizeof(plain), packet + 1 + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_RESPONSE_LENGTH - (1 + CRYPTO_NONCE_SIZE)) {
        return -1;
    }

    return COOKIE_RESPONSE_LENGTH ;
}

/* Handle the cookie request packet of length length.
 * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
 * Put the key used to decrypt the request into shared_key (of size CRYPTO_SHARED_KEY_SIZE) for use in the response.
 *
 * AKE: Peer B (receiver) handling a cookie request, retrieve plaintext from cookie request (echoID_A)
 * AKE NEW: same function as old handshake
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_cookie_request(const Net_Crypto *c, uint8_t *request_plain, uint8_t *shared_key,
                                 uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    fprintf(stderr, "ENTERING: handle_cookie_request()\n");

    if (length != COOKIE_REQUEST_LENGTH) {
        return -1;
    }

    // AKE: copy initiators/Peer A DHT public key from cookie request packet
    memcpy(dht_public_key, packet + 1, CRYPTO_PUBLIC_KEY_SIZE);
    // AKE: calculate shared key from DHT keys
    dht_get_shared_key_sent(c->dht, shared_key, dht_public_key);
    // AKE: request plain contains: S_A^{pub}+Padding(32 bytes)+echoID_A
    int len = decrypt_data_symmetric(shared_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                     packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE,
                                     request_plain);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH) {
        return -1;
    }

    return 0;
}

/* Handle the cookie request packet (for raw UDP)
 *
 * AKE: First of three functions triggering handle_cookie_request().
 * Triggered by receiving of NET_PACKET_COOKIE_REQUEST packet
 */
static int udp_handle_cookie_request(void *object, IP_Port source, const uint8_t *packet, uint16_t length,
                                     void *userdata)
{
    Net_Crypto *c = (Net_Crypto *) object;
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH ];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0) {
        return 1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH ];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return 1;
    }

    if ((uint32_t) sendpacket(dht_get_net(c->dht), source, data, sizeof(data)) != sizeof(data)) {
        return 1;
    }

    return 0;
}

/* Handle the cookie request packet (for TCP)
 *
 * AKE: Second of three functions triggering handle_cookie_request().
 * Triggered by receiving of NET_PACKET_COOKIE_REQUEST packet
 */
static int tcp_handle_cookie_request(Net_Crypto *c, int connections_number, const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH ];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0) {
        return -1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH ];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return -1;
    }

    int ret = send_packet_tcp_connection(c->tcp_c, connections_number, data, sizeof(data));
    return ret;
}

/* Handle the cookie request packet (for TCP oob packets)
 *
 * AKE: Third of three functions triggering handle_cookie_request().
 * Triggered by receiving of NET_PACKET_COOKIE_REQUEST packet
 */
static int tcp_oob_handle_cookie_request(const Net_Crypto *c, unsigned int tcp_connections_number,
        const uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH ];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key_temp[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key_temp, packet, length) != 0) {
        return -1;
    }

    if (public_key_cmp(dht_public_key, dht_public_key_temp) != 0) {
        return -1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH ];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return -1;
    }

    int ret = tcp_send_oob_packet(c->tcp_c, tcp_connections_number, dht_public_key, data, sizeof(data));
    return ret;
}

/* Handle a cookie response packet of length encrypted with shared_key.
 * put the cookie in the response in cookie
 *
 * cookie must be of length COOKIE_LENGTH.
 *
 * AKE: Peer A/initiator receives a cookie response packet after sending a cookie request packet
 * AKE: Retrieve cookie from the other peer and verify echoID
 * AKE NEW: same funtion as in old handshake
 *
 *
 * return -1 on failure.
 * return COOKIE_LENGTH on success.
 */
static int handle_cookie_response(const Logger *log, uint8_t *cookie, uint64_t *number,
                                  const uint8_t *packet, uint16_t length,
                                  const uint8_t *shared_key)
{
    fprintf(stderr, "ENTERING: handle_cookie_response()\n");

    if (length != COOKIE_RESPONSE_LENGTH) {
        return -1;
    }

    //AKE: Plaintext contains Cookie from responder + echoID from initiatior
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];
    const int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE,
                                           length - (1 + CRYPTO_NONCE_SIZE), plain);

    if (len != sizeof(plain)) {
        return -1;
    }

    // AKE: copy the decrypted cookie into cookie
    memcpy(cookie, plain, COOKIE_LENGTH);
    // AKE: copy the echoID into number to compare it afterwards
    memcpy(number, plain + COOKIE_LENGTH, sizeof(uint64_t));
    return COOKIE_LENGTH ;
}

//AKE: Old handshake packet length
//#define HANDSHAKE_PACKET_LENGTH (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
//AKE NEW: first one with base nonce, second one without base nonce
//#define HANDSHAKE_PACKET_LENGTH_RESPONDER (1 + COOKIE_LENGTH + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
#define HANDSHAKE_PACKET_LENGTH_RESPONDER (1 + COOKIE_LENGTH + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
//AKE NEW: Initiator also sends ENCRYPTED static public key with MAC (first one with, second one without base nonce)
//#define HANDSHAKE_PACKET_LENGTH_INITIATOR (1 + COOKIE_LENGTH + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
#define HANDSHAKE_PACKET_LENGTH_INITIATOR (1 + COOKIE_LENGTH + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)

/* Create a handshake packet and put it in packet.
 * cookie must be COOKIE_LENGTH bytes.
 * packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
 *
 * AKE: create a crypto handshake packet (both peers)
 * AKE NEW: function adapted, different handshake packets for INITIATOR and RESPONDER
 *
 * return -1 on failure.
 * return HANDSHAKE_PACKET_LENGTH on success.
 */
static int create_crypto_handshake(const Net_Crypto *c, uint8_t *packet, const uint8_t *cookie,
                                   const uint8_t *peer_real_pk, const uint8_t *peer_dht_pubkey, NoiseHandshakeState *handshake)
{
    fprintf(stderr, "ENTERING: create_crypto_handshake()\n");
    int role = noise_handshakestate_get_role(handshake);

    //AKE NEW: RESPONDER HANDSHAKE
    if (role == NOISE_ROLE_RESPONDER) {
        //AKE NEW: NOISE HANDSHAKE PACKET RESPONDER
        /* Handshake packet structure
         [uint8_t 26]
         [Cookie 112 bytes]
         [session public key of the peer (32 bytes)] => handled by Noise
         [Encrypted message containing:
         ~~[24 bytes base nonce]~~ => NO base Nonce -> handled by Noise/XSalsa20 not possible
         [64 bytes sha512 hash of the entire Cookie sitting outside the encrypted part]
         [112 bytes Other Cookie (used by the other to respond to the handshake packet)]
         ]
         [MAC 16 bytes]
         */
        //AKE NEW: Noise message + Application chosen payload
        NoiseBuffer noise_message;
        //AKE NEW: ephemeral public key of the RESPONDER + encrypted payload + MAC of encrypted payload (with and without base nonce)
//      uint8_t noise_message_buf[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE];
        uint8_t noise_message_buf[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE];
        //AKE NEW: Application chosen payload of Noise message
        NoiseBuffer noise_payload;
        //AKE NEW: Payload contains NO base nonce, but sha512 hash of cookie (Initiator), and other cookie (Responder)
//      uint8_t noise_payload_buf[CRYPTO_NONCE_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
        uint8_t noise_payload_buf[CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
        //AKE NEW: Add Nonce to payload => NOT necessary
//      memcpy(noise_payload_buf, nonce, CRYPTO_NONCE_SIZE);
        //AKE NEW: Add SHA512 of cookie to payload
//      crypto_sha512(noise_payload_buf + CRYPTO_NONCE_SIZE, cookie, COOKIE_LENGTH);
        crypto_sha512(noise_payload_buf, cookie, COOKIE_LENGTH);
        uint8_t othercookie_plain[COOKIE_DATA_LENGTH ];
        // AKE: The cookie contains the static and DHT pubkey of the peer! not from the sender!
        memcpy(othercookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        // AKE: The cookie contains the static and DHT pubkey of the peer! not from the sender!
        memcpy(othercookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);

        // AKE: This is to create the OTHER cookie from Peer A/initiator
        // AKE: Also Peer B/responder sends a cookie again in the handshake packet
        if (create_cookie(c->log, c->mono_time, noise_payload_buf + CRYPTO_SHA512_SIZE,
                          othercookie_plain, c->secret_symmetric_key) != 0) {
            return -1;
        }

        //AKE NEW: Format the message payload into "payloadbuf".
        noise_buffer_set_input(noise_payload, noise_payload_buf, sizeof(noise_payload_buf));
        //AKE NEW: Points to the message buffer to be populated with handshake details and the message payload.
        noise_buffer_set_output(noise_message, noise_message_buf, sizeof(noise_message_buf));
        //AKE NEW: Computes Noise message B pattern "e, ee, se"
        int err = noise_handshakestate_write_message(handshake, &noise_message, &noise_payload);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("write handshake", err);
            //AKE NEW: Nothing to do here, cannot really fail here
            return -1;
        }

        //AKE NEW: write packet kind, cookie and noise message incl. payload to packet
        packet[0] = NET_PACKET_CRYPTO_HS;
        memcpy(packet + 1, cookie, COOKIE_LENGTH);
        memcpy(packet + 1 + COOKIE_LENGTH, noise_message_buf, sizeof(noise_message_buf));

        return HANDSHAKE_PACKET_LENGTH_RESPONDER;
    } else if (role == NOISE_ROLE_INITIATOR) {
        //AKE NEW: NOISE HANDSHAKE PACKET RESPONDER
        /* Handshake packet structure
         [uint8_t 26]
         [Cookie 112 bytes]
         [session public key of the peer (32 bytes)] => handled by Noise
         [static public key of the INITIATOR (32 bytes)] => handled by Noise
         [Encrypted message containing:
         ~~[24 bytes base nonce]~~ => NO base Nonce -> handled by Noise/XSalsa20 not possible
         [64 bytes sha512 hash of the entire Cookie sitting outside the encrypted part]
         [112 bytes Other Cookie (used by the other to respond to the handshake packet)]
         ]
         [MAC 16 bytes]
         */
        //AKE NEW: Noise message + Application chosen payload
        NoiseBuffer noise_message;
        //AKE NEW: ephemeral pubkey INITIATOR + static pubkey INITIATOR + MAC static pubkey + encrypted payload (without base nonce) + MAC of encrypted payload
        uint8_t noise_message_buf[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_SHA512_SIZE
                                                         + COOKIE_LENGTH
                                                         + CRYPTO_MAC_SIZE];
        //AKE NEW: Application chosen payload of Noise message
        NoiseBuffer noise_payload;
        // AKE NEW: Payload contains NO base nonce, but sha512 hash of cookie (RESPONDER), and other cookie (INITIATOR)
        uint8_t noise_payload_buf[CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
        // AKE NEW: Add Nonce to payload => NOT necessary
//      memcpy(noise_payload_buf, nonce, CRYPTO_NONCE_SIZE);
        crypto_sha512(noise_payload_buf, cookie, COOKIE_LENGTH);
        uint8_t othercookie_plain[COOKIE_DATA_LENGTH ];
        // AKE: The cookie contains the static and DHT pubkey of the peer! not from the sender!
        memcpy(othercookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        // AKE: The cookie contains the static and DHT pubkey of the peer! not from the sender!
        memcpy(othercookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);

        // AKE: This is to create the OTHER cookie from Peer A/initiator
        // AKE: Also Peer B sends a cookie again in the handshake packet
        if (create_cookie(c->log, c->mono_time, noise_payload_buf + CRYPTO_SHA512_SIZE,
                          othercookie_plain, c->secret_symmetric_key) != 0) {
            return -1;
        }

        //AKE NEW: Format the message payload into "payloadbuf".
        noise_buffer_set_input(noise_payload, noise_payload_buf, sizeof(noise_payload_buf));
        //AKE NW: Points to the message buffer to be populated with handshake details and the message payload.
        noise_buffer_set_output(noise_message, noise_message_buf, sizeof(noise_message_buf));
        //AKE NEW: Computes Noise message A pattern "e, es, s, ss"
        int err = noise_handshakestate_write_message(handshake, &noise_message, &noise_payload);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("write handshake", err);
            //AKE NEW: Nothing to do here, cannot really fail here
            return -1;
        }

        //AKE NEW: write packet kind, cookie and noise message incl. payload to packet
        packet[0] = NET_PACKET_CRYPTO_HS;
        memcpy(packet + 1, cookie, COOKIE_LENGTH);
        memcpy(packet + 1 + COOKIE_LENGTH, noise_message_buf, sizeof(noise_message_buf));
        return HANDSHAKE_PACKET_LENGTH_INITIATOR;
    } else {
        return -1;
    }

    /*##################################################################################*/
    //AKE NEW: OLD HANDSHAKE PACKET
    //AKE NEW TODO: remove old stuff
    /* Handshake packet structure
     [uint8_t 26]
     [Cookie]
     [nonce (24 bytes)]
     [Encrypted message containing:
     [24 bytes base nonce]
     [session public key of the peer (32 bytes)]
     [sha512 hash of the entire Cookie sitting outside the encrypted part]
     [Other Cookie (used by the other to respond to the handshake packet)]
     ]
     */
//  uint8_t plain[CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
//  memcpy(plain, nonce, CRYPTO_NONCE_SIZE);
//  memcpy(plain + CRYPTO_NONCE_SIZE, session_pk, CRYPTO_PUBLIC_KEY_SIZE);
//  // AKE: This is the cookie from Peer B/receiver which is sent in plain (see handshake packet in spec)
//  crypto_sha512(plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE, cookie, COOKIE_LENGTH);
//  uint8_t cookie_plain[COOKIE_DATA_LENGTH ];
//  memcpy(cookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
//  memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
//
//  // AKE: This is to create the OTHER cookie from Peer A/initiator
//  // AKE: Also Peer B sends a cookie again in the handshake packet
//  if (create_cookie(c->log, c->mono_time, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE,
//          cookie_plain, c->secret_symmetric_key) != 0) {
//      return -1;
//  }
//
//  random_nonce(packet + 1 + COOKIE_LENGTH);
//  // AKE: handshake packet is using peers real STATIC public and self STATIC secret key for encryption
//  int len = encrypt_data(peer_real_pk, c->self_secret_key, packet + 1 + COOKIE_LENGTH, plain, sizeof(plain),
//          packet + 1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE);
//
//  //AKE NEW: I think in the Noise handshake this is not necessary
//  if (len != HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE)) {
//      return -1;
//  }
//
//  packet[0] = NET_PACKET_CRYPTO_HS;
//  memcpy(packet + 1, cookie, COOKIE_LENGTH);
//
//  return HANDSHAKE_PACKET_LENGTH;
}

/* Handle a crypto handshake packet of length.
 * put the nonce contained in the packet in nonce,
 * the session public key in session_pk
 * the real public key of the peer in peer_real_pk
 * the dht public key of the peer in dht_public_key and
 * the cookie inside the encrypted part of the packet in cookie.
 *
 * if expected_real_pk isn't NULL it denotes the real public key
 * the packet should be from.
 *
 * nonce must be at least CRYPTO_NONCE_SIZE
 * session_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
 * peer_real_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
 * cookie must be at least COOKIE_LENGTH
 *
 * AKE: Peer B/receiver handle incoming handshake packet
 * AKE NEW: This function is called if Noise handshake state is NOISE_ACTION_READ_MESSAGE
 * AKE NEW: function adapted because of different handshake packets for INITIATOR and RESPONDER
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_crypto_handshake(const Net_Crypto *c, uint8_t *peer_real_pk,
                                   uint8_t *dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const uint8_t *expected_real_pk,
                                   NoiseHandshakeState *handshake)
{
    fprintf(stderr, "ENTERING: handle_crypto_handshake()\n");
    //AKE NEW: get handhake role => different handshake packet lengths
    int role = noise_handshakestate_get_role(handshake);

    if (role == NOISE_ROLE_RESPONDER) {
        if (length != HANDSHAKE_PACKET_LENGTH_INITIATOR) {
            return -1;
        }
    } else if (role == NOISE_ROLE_INITIATOR) {
        if (length != HANDSHAKE_PACKET_LENGTH_RESPONDER) {
            return -1;
        }
    } else {
        return -1;
    }

    uint8_t cookie_plain[COOKIE_DATA_LENGTH ];

    /*
     * AKE: COOKIES ARE ENCRYPTED WITH AN ADDITIONAL SECRET SYMMETRIC KEY WHICH IS ONLY KNOWN TO THE PEER HIMSELF!
     * AKE: The peer opens his cookie to verify it's really from him!
     * AKE: cookie_plain contains static public key and DHT public key of THIS peer
     */
    if (open_cookie(c->log, c->mono_time, cookie_plain, packet + 1, c->secret_symmetric_key) != 0) {
        return -1;
    }

    if (expected_real_pk) {
        if (public_key_cmp(cookie_plain, expected_real_pk) != 0) {
            return -1;
        }
    }

    uint8_t cookie_hash[CRYPTO_SHA512_SIZE];
    // AKE: calculating the hash of the cookie outside of the Noise payload
    crypto_sha512(cookie_hash, packet + 1, COOKIE_LENGTH);

    //AKE NEW: until here it's be the same
    /*###############################################################################*/

    //AKE NEW: RESPONDER receives handshake packet from INITIATOR = longer packet
    if (role == NOISE_ROLE_RESPONDER) {
        //AKE NEW: Noise message + Application chosen payload
        NoiseBuffer noise_message;
        //AKE NEW: ephemeral pubkey + encrypted INITIATOR static pubkey + MAC static pubkey + encrypted payload (without base nonce) + MAC of encrypted payload
        uint8_t noise_message_buf[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_SHA512_SIZE
                                                         + COOKIE_LENGTH
                                                         + CRYPTO_MAC_SIZE];
        //AKE NEW: Copy the data from packet to the noise_message_buf
        memcpy(noise_message_buf, packet + 1 + COOKIE_LENGTH, HANDSHAKE_PACKET_LENGTH_INITIATOR - 1 - COOKIE_LENGTH);
        //AKE NEW: Application chosen payload of Noise message
        NoiseBuffer noise_payload;
        //AKE NEW: Payload contains NO base nonce, but sha512 hash of cookie (RESPONDER), and other cookie (INITIATOR)
        uint8_t noise_payload_buf[CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
        //AKE NEW: Format the message payload into "payloadbuf".
        noise_buffer_set_input(noise_payload, noise_payload_buf, sizeof(noise_payload_buf));
        //AKE NEW: Points to the message buffer to be populated with handshake details and the message payload.
        noise_buffer_set_input(noise_message, noise_message_buf, sizeof(noise_message_buf));
        //AKE NEW: Computes Noise message A pattern "e, es, s, ss" on RESPONDER side
        int err = noise_handshakestate_read_message(handshake, &noise_message, &noise_payload);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("read handshake", err);
            return -1;
        }

        //AKE NEW: copy nonce from the decrypted payload => NOT necessary
//      memcpy(nonce, noise_payload.data, CRYPTO_NONCE_SIZE);
        //AKE NEW: copy other cookie
        memcpy(cookie, noise_payload.data + CRYPTO_SHA512_SIZE, COOKIE_LENGTH);

        if (crypto_memcmp(cookie_hash, noise_payload.data, CRYPTO_SHA512_SIZE) != 0) {
            return -1;
        }

        //AKE NEW: memcpy peer_real_pk from cookie_plain + dht_public_key
        memcpy(peer_real_pk, cookie_plain, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
        //AKE NEW: memcpy session_pk shouldn't be necessary
    }
    //AKE NEW: INITIATOR receives handshake packet from RESPONDER = shorter packet
    else if (role == NOISE_ROLE_INITIATOR) {
        //AKE NEW: Noise message + Application chosen payload
        NoiseBuffer noise_message;
        //AKE NEW: ephemeral pubkey RESPONDER + encrypted payload (without base nonce) + MAC of encrypted payload
        uint8_t noise_message_buf[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE];
        //AKE NEW: Copy the data from packet to the noise_message_buf
        memcpy(noise_message_buf, packet + 1 + COOKIE_LENGTH, HANDSHAKE_PACKET_LENGTH_RESPONDER - 1 - COOKIE_LENGTH);
        //AKE NEW: Application chosen payload of Noise message
        NoiseBuffer noise_payload;
        //AKE NEW: Payload contains NO base nonce, sha512 hash of cookie, and other cookie
        uint8_t noise_payload_buf[CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
        //AKE NEW: Format the message payload into "payloadbuf".
        noise_buffer_set_input(noise_payload, noise_payload_buf, sizeof(noise_payload_buf));
        //AKE NEW: Points to the message buffer to be populated with handshake details and the message payload.
        noise_buffer_set_input(noise_message, noise_message_buf, sizeof(noise_message_buf));
        //AKE NEW: Computes Noise message B pattern "e, ee, se" on INITIATOR side
        int err = noise_handshakestate_read_message(handshake, &noise_message, &noise_payload);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("read handshake", err);
            return -1;
        }

        //AKE NEW: copy nonce from the decrypted payload => NOT necessary
//      memcpy(nonce, noise_payload.data, CRYPTO_NONCE_SIZE);
        //AKE NEW: copy other cookie
        memcpy(cookie, noise_payload.data + CRYPTO_SHA512_SIZE, COOKIE_LENGTH);

        if (crypto_memcmp(cookie_hash, noise_payload.data, CRYPTO_SHA512_SIZE) != 0) {
            return -1;
        }

        //AKE NEW: memcpy peer_real_pk from cookie_plain + dht_public_key
        memcpy(peer_real_pk, cookie_plain, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
        //AKE NEW: memcpy session_pk shouldn't be necessary
    } else {
        return -1;
    }

    /*AKE NEW FINISHED####################################################################*/

    /* AKE OLD START #################################################################### */
    // AKE: everything in plaintext that was encrypted in the handshake packet
//  uint8_t plain[CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH ];
//  int len = decrypt_data(cookie_plain, c->self_secret_key, packet + 1 + COOKIE_LENGTH,
//          packet + 1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE,
//          HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE), plain);
//
//  if (len != sizeof(plain)) {
//      return -1;
//  }
//
//  if (crypto_memcmp(cookie_hash, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
//  CRYPTO_SHA512_SIZE) != 0) {
//      return -1;
//  }
//
//  memcpy(nonce, plain, CRYPTO_NONCE_SIZE);
//  memcpy(session_pk, plain + CRYPTO_NONCE_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
//  // AKE: This is the OTHER cookie from Peer A/initiator
//  memcpy(cookie, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE, COOKIE_LENGTH);
//  memcpy(peer_real_pk, cookie_plain, CRYPTO_PUBLIC_KEY_SIZE);
//  memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
    /* AKE OLD FINISHED #################################################################### */

    return 0;
}

static Crypto_Connection *get_crypto_connection(const Net_Crypto *c, int crypt_connection_id)
{
    if (!crypt_connection_id_is_valid(c, crypt_connection_id)) {
        return nullptr;
    }

    return &c->crypto_connections[crypt_connection_id];
}

/* Associate an ip_port to a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_ip_port_connection(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (net_family_is_ipv4(ip_port.ip.family)) {
        if (!ipport_equal(&ip_port, &conn->ip_portv4) && !ip_is_lan(conn->ip_portv4.ip)) {
            if (!bs_list_add(&c->ip_port_list, (uint8_t *) &ip_port, crypt_connection_id)) {
                return -1;
            }

            bs_list_remove(&c->ip_port_list, (uint8_t *) &conn->ip_portv4, crypt_connection_id);
            conn->ip_portv4 = ip_port;
            return 0;
        }
    } else if (net_family_is_ipv6(ip_port.ip.family)) {
        if (!ipport_equal(&ip_port, &conn->ip_portv6)) {
            if (!bs_list_add(&c->ip_port_list, (uint8_t *) &ip_port, crypt_connection_id)) {
                return -1;
            }

            bs_list_remove(&c->ip_port_list, (uint8_t *) &conn->ip_portv6, crypt_connection_id);
            conn->ip_portv6 = ip_port;
            return 0;
        }
    }

    return -1;
}

/* Return the IP_Port that should be used to send packets to the other peer.
 *
 * return IP_Port with family 0 on failure.
 * return IP_Port on success.
 */
static IP_Port return_ip_port_connection(Net_Crypto *c, int crypt_connection_id)
{
    const IP_Port empty = { { { 0 } } };

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return empty;
    }

    const uint64_t current_time = mono_time_get(c->mono_time);
    bool v6 = 0;
    bool v4 = 0;

    if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time) {
        v4 = 1;
    }

    if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time) {
        v6 = 1;
    }

    /* Prefer IP_Ports which haven't timed out to those which have.
     * To break ties, prefer ipv4 lan, then ipv6, then non-lan ipv4.
     */
    if (v4 && ip_is_lan(conn->ip_portv4.ip)) {
        return conn->ip_portv4;
    }

    if (v6 && net_family_is_ipv6(conn->ip_portv6.ip.family)) {
        return conn->ip_portv6;
    }

    if (v4 && net_family_is_ipv4(conn->ip_portv4.ip.family)) {
        return conn->ip_portv4;
    }

    if (ip_is_lan(conn->ip_portv4.ip)) {
        return conn->ip_portv4;
    }

    if (net_family_is_ipv6(conn->ip_portv6.ip.family)) {
        return conn->ip_portv6;
    }

    if (net_family_is_ipv4(conn->ip_portv4.ip.family)) {
        return conn->ip_portv4;
    }

    return empty;
}

/*
 * AKE NEW: Initializes a NoiseHandshakeState with provided secret key and peer public key (if INITIATOR)
 * AKE NEW: Noise prologue used in Tox is CRYPTO_NOISE_PROTOCOL_NAME
 * AKE NEW: don't need *prologue and prologue_len as parameters (since it's fixed in Tox)
 *
 * return -1 on failure
 * return 0 on success
 */
static int initialize_handshake
//(NoiseHandshakeState *handshake, const Net_Crypto *c, int crypt_connection_id)
(NoiseHandshakeState *handshake, const uint8_t *self_secret_key, const uint8_t *peer_public_key)
{
    printf("ENTERING: initialize_handshake()");
    //AKE NEW: don't think this is necessary, just pass conn stuff diretly
    //Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //AKE NEW: DHState objects are used to store the keypairs for the local party or the public keys for remote parties.
    NoiseDHState *dh;
    size_t key_len = 0;
    int err;

    //AKE NEW: set prologue to CRYPTO_NOISE_PROTOCOL_NAME
    err = noise_handshakestate_set_prologue(handshake, CRYPTO_NOISE_PROTOCOL_NAME, sizeof(CRYPTO_NOISE_PROTOCOL_NAME));

    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return -1;
    }

    if (self_secret_key) {
        //AKE NEW: we need to load the local key pair of this peer
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        key_len = noise_dhstate_get_private_key_length(dh);
        //AKE NEW: set local peer "key" from Net_crypto *c: c->self_secret_key
        //err = noise_dhstate_set_keypair_private(dh, c->self_secret_key, key_len);
        err = noise_dhstate_set_keypair_private(dh, self_secret_key, key_len);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("set client private key", err);
            return -1;
        }
    } else {
        fprintf(stderr, "Client private key required, but not provided.\n");
        return -1;
    }

    //AKE NEW: IK pattern: if role = INITIATOR => peer_public_key is also necessary
    int role = noise_handshakestate_get_role(handshake);

    if (role == NOISE_ROLE_INITIATOR) {
        if (peer_public_key) {
            fprintf(stderr, "ENTERING: initialize_handshake() / peer_public_key\n");
            dh = noise_handshakestate_get_remote_public_key_dh(handshake);
            key_len = noise_dhstate_get_public_key_length(dh);
            //AKE NEW: set remote peer "key" to Crypto_Connection *conn: conn->public_key
            //err = noise_dhstate_set_public_key(dh, conn->public_key, key_len);
            err = noise_dhstate_set_public_key(dh, peer_public_key, key_len);

            if (err != NOISE_ERROR_NONE) {
                noise_perror("set server public key", err);
                return -1;
            }
        } else {
            fprintf(stderr, "Server public key required, but not provided.\n");
            return -1;
        }
    }

    /* Ready to go */
    return 0;
}

/* Sends a packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_packet_to(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
// TODO(irungentoo): TCP, etc...
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    int direct_send_attempt = 0;

    pthread_mutex_lock(conn->mutex);
    IP_Port ip_port = return_ip_port_connection(c, crypt_connection_id);

    // TODO(irungentoo): on bad networks, direct connections might not last indefinitely.
    if (!net_family_is_unspec(ip_port.ip.family)) {
        bool direct_connected = 0;

        // FIXME(sudden6): handle return value
        crypto_connection_status(c, crypt_connection_id, &direct_connected, nullptr);

        if (direct_connected) {
            if ((uint32_t) sendpacket(dht_get_net(c->dht), ip_port, data, length) == length) {
                pthread_mutex_unlock(conn->mutex);
                return 0;
            }

            pthread_mutex_unlock(conn->mutex);
            return -1;
        }

        // TODO(irungentoo): a better way of sending packets directly to confirm the others ip.
        const uint64_t current_time = mono_time_get(c->mono_time);

        if ((((UDP_DIRECT_TIMEOUT / 2) + conn->direct_send_attempt_time) < current_time && length < 96)
                || data[0] == NET_PACKET_COOKIE_REQUEST || data[0] == NET_PACKET_CRYPTO_HS) {
            if ((uint32_t) sendpacket(dht_get_net(c->dht), ip_port, data, length) == length) {
                direct_send_attempt = 1;
                conn->direct_send_attempt_time = mono_time_get(c->mono_time);
            }
        }
    }

    pthread_mutex_unlock(conn->mutex);
    pthread_mutex_lock(&c->tcp_mutex);
    int ret = send_packet_tcp_connection(c->tcp_c, conn->connection_number_tcp, data, length);
    pthread_mutex_unlock(&c->tcp_mutex);

    pthread_mutex_lock(conn->mutex);

    if (ret == 0) {
        conn->last_tcp_sent = current_time_monotonic(c->mono_time);
    }

    pthread_mutex_unlock(conn->mutex);

    if (ret == 0 || direct_send_attempt) {
        return 0;
    }

    return -1;
}

/** START: Array Related functions */

/* Return number of packets in array
 * Note that holes are counted too.
 */
static uint32_t num_packets_array(const Packets_Array *array)
{
    return array->buffer_end - array->buffer_start;
}

/* Add data with packet number to array.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_data_to_buffer(const Logger *log, Packets_Array *array, uint32_t number, const Packet_Data *data)
{
    if (number - array->buffer_start >= CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num]) {
        return -1;
    }

    Packet_Data *new_d = (Packet_Data *) malloc(sizeof(Packet_Data));

    if (new_d == nullptr) {
        return -1;
    }

    memcpy(new_d, data, sizeof(Packet_Data));
    array->buffer[num] = new_d;

    if (number - array->buffer_start >= num_packets_array(array)) {
        array->buffer_end = number + 1;
    }

    return 0;
}

/* Get pointer of data with packet number.
 *
 * return -1 on failure.
 * return 0 if data at number is empty.
 * return 1 if data pointer was put in data.
 */
static int get_data_pointer(const Logger *log, const Packets_Array *array, Packet_Data **data, uint32_t number)
{
    const uint32_t num_spots = num_packets_array(array);

    if (array->buffer_end - number > num_spots || number - array->buffer_start >= num_spots) {
        return -1;
    }

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num]) {
        return 0;
    }

    *data = array->buffer[num];
    return 1;
}

/* Add data to end of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t add_data_end_of_buffer(const Logger *log, Packets_Array *array, const Packet_Data *data)
{
    const uint32_t num_spots = num_packets_array(array);

    if (num_spots >= CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    Packet_Data *new_d = (Packet_Data *) malloc(sizeof(Packet_Data));

    if (new_d == nullptr) {
        return -1;
    }

    memcpy(new_d, data, sizeof(Packet_Data));
    uint32_t id = array->buffer_end;
    array->buffer[id % CRYPTO_PACKET_BUFFER_SIZE] = new_d;
    ++array->buffer_end;
    return id;
}

/* Read data from beginning of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t read_data_beg_buffer(const Logger *log, Packets_Array *array, Packet_Data *data)
{
    if (array->buffer_end == array->buffer_start) {
        return -1;
    }

    const uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num]) {
        return -1;
    }

    memcpy(data, array->buffer[num], sizeof(Packet_Data));
    uint32_t id = array->buffer_start;
    ++array->buffer_start;
    free(array->buffer[num]);
    array->buffer[num] = nullptr;
    return id;
}

/* Delete all packets in array before number (but not number)
 *
 * return -1 on failure.
 * return 0 on success
 */
static int clear_buffer_until(const Logger *log, Packets_Array *array, uint32_t number)
{
    const uint32_t num_spots = num_packets_array(array);

    if (array->buffer_end - number >= num_spots || number - array->buffer_start > num_spots) {
        return -1;
    }

    uint32_t i;

    for (i = array->buffer_start; i != number; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

static int clear_buffer(Packets_Array *array)
{
    uint32_t i;

    for (i = array->buffer_start; i != array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

/* Set array buffer end to number.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int set_buffer_end(const Logger *log, Packets_Array *array, uint32_t number)
{
    if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    if (number - array->buffer_end > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    array->buffer_end = number;
    return 0;
}

/* Create a packet request packet from recv_array and send_buffer_end into
 * data of length.
 *
 * return -1 on failure.
 * return length of packet on success.
 */
static int generate_request_packet(const Logger *log, uint8_t *data, uint16_t length, const Packets_Array *recv_array)
{
    if (length == 0) {
        return -1;
    }

    data[0] = PACKET_ID_REQUEST;

    uint16_t cur_len = 1;

    if (recv_array->buffer_start == recv_array->buffer_end) {
        return cur_len;
    }

    if (length <= cur_len) {
        return cur_len;
    }

    uint32_t n = 1;

    for (uint32_t i = recv_array->buffer_start; i != recv_array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (!recv_array->buffer[num]) {
            data[cur_len] = n;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        } else if (n == 255) {
            data[cur_len] = 0;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        }

        ++n;
    }

    return cur_len;
}

/* Handle a request data packet.
 * Remove all the packets the other received from the array.
 *
 * return -1 on failure.
 * return number of requested packets on success.
 */
static int handle_request_packet(Mono_Time *mono_time, const Logger *log, Packets_Array *send_array,
                                 const uint8_t *data, uint16_t length, uint64_t *latest_send_time, uint64_t rtt_time)
{
    if (length == 0) {
        return -1;
    }

    if (data[0] != PACKET_ID_REQUEST) {
        return -1;
    }

    if (length == 1) {
        return 0;
    }

    ++data;
    --length;

    uint32_t n = 1;
    uint32_t requested = 0;

    const uint64_t temp_time = current_time_monotonic(mono_time);
    uint64_t l_sent_time = -1;

    for (uint32_t i = send_array->buffer_start; i != send_array->buffer_end; ++i) {
        if (length == 0) {
            break;
        }

        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (n == data[0]) {
            if (send_array->buffer[num]) {
                uint64_t sent_time = send_array->buffer[num]->sent_time;

                if ((sent_time + rtt_time) < temp_time) {
                    send_array->buffer[num]->sent_time = 0;
                }
            }

            ++data;
            --length;
            n = 0;
            ++requested;
        } else {
            if (send_array->buffer[num]) {
                uint64_t sent_time = send_array->buffer[num]->sent_time;

                if (l_sent_time < sent_time) {
                    l_sent_time = sent_time;
                }

                free(send_array->buffer[num]);
                send_array->buffer[num] = nullptr;
            }
        }

        if (n == 255) {
            n = 1;

            if (data[0] != 0) {
                return -1;
            }

            ++data;
            --length;
        } else {
            ++n;
        }
    }

    if (*latest_send_time < l_sent_time) {
        *latest_send_time = l_sent_time;
    }

    return requested;
}

/** END: Array Related functions */

#define MAX_DATA_DATA_PACKET_SIZE (MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE))

/* Creates and sends a data packet to the peer using the fastest route.
 *
 * AKE NEW: function adapted because we need to use ChaCha20 via noise_cipherstate_encrypt() because
 * there is (currently) no possibility to retrieve the symmetric key from a NoiseCipherState.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    //AKE NEW: + sizeof(uint16_t) + => last 2 bytes nonce used for encryption -> removed
    //const uint16_t max_length = MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE);
    const uint16_t max_length = MAX_CRYPTO_PACKET_SIZE - (1 + CRYPTO_MAC_SIZE);

    if (length == 0 || length > max_length) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(conn->mutex);
    //AKE NEW: removed sizeof(uint16_t) => last 2 bytes of base nonce => NO base nonce
    //VLA(uint8_t, packet, 1 + sizeof(uint16_t) + length + CRYPTO_MAC_SIZE);
    VLA(uint8_t, packet, 1 + length + CRYPTO_MAC_SIZE);
    packet[0] = NET_PACKET_CRYPTO_DATA;
    //AKE NEW: copies the last 2 bytes of the nonce => NO base nonce
//  memcpy(packet + 1, conn->sent_nonce + (CRYPTO_NONCE_SIZE - sizeof(uint16_t)), sizeof(uint16_t));
    //AKE NEW: can't use conn->send_cipher directly because it's not only the key
//  const int len = encrypt_data_symmetric(conn->shared_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t));

    /* AKE NEW: Encrypt the message and send it */
    NoiseBuffer noise_message;
    //AKE NEW: we cannot just use *data directly => we need memory for MAC
    uint8_t noise_message_buf[length + CRYPTO_MAC_SIZE];
    memcpy(noise_message_buf, data, length);
    noise_buffer_set_inout(noise_message, noise_message_buf, length, sizeof(noise_message_buf));
    //AKE NEW: Encryption of packet payload
    //AKE NEW TODO: OR noise_cipherstate_encrypt_with_ad? What would be ad?
    int err = noise_cipherstate_encrypt(conn->send_cipher, &noise_message);

    if (err != NOISE_ERROR_NONE) {
        if (err == NOISE_ERROR_INVALID_NONCE) {
            /*
             * AKE NEW: The threshold for the counter-based nonce in Noise is 2^64-1
             * From Noise paper:
             * "Incrementing nonces: Reusing a nonce value for n with the same key k for encryption would be catastrophic.
             * Implementations must carefully follow the rules for nonces. Nonces are not allowed to wrap back to zero due
             * to integer overflow, and the maximum nonce value is reserved. This means parties are not allowed to send more
             * than 2^64-1 transport messages."
             * "If EncryptWithAd() or DecryptWithAd() signal an error due to nonce exhaustion, then
             * the application must delete the CipherState and terminate the session."
             * => noise_cipherstate_decrypt() -> NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
             */
            //AKE NEW TODO: connection_kill() / crypto_kill() / wipe_crypto_connection()? => wipe not available here
//          wipe_crypto_connection(c, crypt_connection_id);
            return -1;
        } else {
            noise_perror("noise_cipherstate_encrypt", err);
            return -1;
        }
    }

    //AKE NEW: copy ciphertext to packet
    memcpy(packet + 1, noise_message_buf, sizeof(noise_message_buf));
    /*
     * AKE NEW: own Noise encryption function like encrypt_data_symmetric() -> also there is padding?
     * => I think not necessary
     * Padding:
     * <@iphy> tb`: WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API.
     * Specifically: The caller must ensure, before calling the C NaCl crypto_box function, that the first
     * crypto_box_ZEROBYTES bytes of the message m are all 0. Typical higher-level applications
     * will work with the remaining bytes of the message; note, however, that mlen counts all of the bytes,
     * including the bytes required to be 0.
     */

    //AKE NEW TODO: do I need this?
//  if (len + 1 + sizeof(uint16_t) != SIZEOF_VLA(packet)) {
//      pthread_mutex_unlock(conn->mutex);
//      return -1;
//  }
    //AKE NEW: not necessary
//  increment_nonce(conn->sent_nonce);
    pthread_mutex_unlock(conn->mutex);

    return send_packet_to(c, crypt_connection_id, packet, SIZEOF_VLA(packet));
}

/* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet_helper(Net_Crypto *c, int crypt_connection_id, uint32_t buffer_start, uint32_t num,
                                   const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -1;
    }

    num = net_htonl(num);
    buffer_start = net_htonl(buffer_start);
    uint16_t padding_length = (MAX_CRYPTO_DATA_SIZE - length) % CRYPTO_MAX_PADDING;
    VLA(uint8_t, packet, sizeof(uint32_t) + sizeof(uint32_t) + padding_length + length);
    memcpy(packet, &buffer_start, sizeof(uint32_t));
    memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
    memset(packet + (sizeof(uint32_t) * 2), PACKET_ID_PADDING, padding_length);
    memcpy(packet + (sizeof(uint32_t) * 2) + padding_length, data, length);

    return send_data_packet(c, crypt_connection_id, packet, SIZEOF_VLA(packet));
}

static int reset_max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    /* If last packet send failed, try to send packet again.
     If sending it fails we won't be able to send the new packet. */
    if (conn->maximum_speed_reached) {
        Packet_Data *dt = nullptr;
        const uint32_t packet_num = conn->send_array.buffer_end - 1;
        const int ret = get_data_pointer(c->log, &conn->send_array, &dt, packet_num);

        if (ret == 1 && dt->sent_time == 0) {
            if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num,
                                        dt->data, dt->length) != 0) {
                return -1;
            }

            dt->sent_time = current_time_monotonic(c->mono_time);
        }

        conn->maximum_speed_reached = 0;
    }

    return 0;
}

/*  return -1 if data could not be put in packet queue.
 *  return positive packet number if data was put into the queue.
 */
static int64_t send_lossless_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                                    uint8_t congestion_control)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    /* If last packet send failed, try to send packet again.
     If sending it fails we won't be able to send the new packet. */
    reset_max_speed_reached(c, crypt_connection_id);

    if (conn->maximum_speed_reached && congestion_control) {
        return -1;
    }

    Packet_Data dt;
    dt.sent_time = 0;
    dt.length = length;
    memcpy(dt.data, data, length);
    pthread_mutex_lock(conn->mutex);
    int64_t packet_num = add_data_end_of_buffer(c->log, &conn->send_array, &dt);
    pthread_mutex_unlock(conn->mutex);

    if (packet_num == -1) {
        return -1;
    }

    if (!congestion_control && conn->maximum_speed_reached) {
        return packet_num;
    }

    if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, data, length) == 0) {
        Packet_Data *dt1 = nullptr;

        if (get_data_pointer(c->log, &conn->send_array, &dt1, packet_num) == 1) {
            dt1->sent_time = current_time_monotonic(c->mono_time);
        }
    } else {
        conn->maximum_speed_reached = 1;
        LOGGER_DEBUG(c->log, "send_data_packet failed");
    }

    return packet_num;
}

/* Get the lowest 2 bytes from the nonce and convert
 * them to host byte format before returning them.
 */
static uint16_t get_nonce_uint16(const uint8_t *nonce)
{
    uint16_t num;
    memcpy(&num, nonce + (CRYPTO_NONCE_SIZE - sizeof(uint16_t)), sizeof(uint16_t));
    return net_ntohs(num);
}

#define DATA_NUM_THRESHOLD 21845

/* Handle a data packet.
 * Decrypt packet of length and put it into data.
 * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
 *
 * AKE NEW: function adapted because we need to use ChaCha20 via noise_cipherstate_encrypt() because
 * there is (currently) no possibility to retrieve the symmetric key from a NoiseCipherState.
 * AKE NEW: Base nonce not necessary because nonce is included in NoiseCipherState
 *
 * return -1 on failure.
 * return length of data on success.
 */
static int handle_data_packet(const Net_Crypto *c, int crypt_connection_id, uint8_t *data, const uint8_t *packet,
                              uint16_t length)
{
    //AKE NEW: removed nonce from packet
    //const uint16_t crypto_packet_overhead = 1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE;
    const uint16_t crypto_packet_overhead = 1 + CRYPTO_MAC_SIZE;

    //AKE NEW: length is 1 + encrypted payload + MAC
    if (length <= crypto_packet_overhead || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    //AKE NEW: Nonce stuff not necessary
//  uint8_t nonce[CRYPTO_NONCE_SIZE];
//  // AKE: copy BASENONCE (= recv_nonce) into nonce
//  memcpy(nonce, conn->recv_nonce, CRYPTO_NONCE_SIZE);
//  uint16_t num_cur_nonce = get_nonce_uint16(nonce);
//  uint16_t num;
//  net_unpack_u16(packet + 1, &num);
//  uint16_t diff = num - num_cur_nonce;
//  increment_nonce_number(nonce, diff);
    //AKE NEW: instead of conn->shared_key Noise receiving key conn->recv_cipher => NOT POSSIBLE
//  int len = decrypt_data_symmetric(conn->shared_key, nonce, packet + 1 + sizeof(uint16_t),
//          length - (1 + sizeof(uint16_t)), data);

    NoiseBuffer noise_message;
    //AKE NEW: can't just use *data direclty => need memory for MAC
    uint8_t noise_message_buf[length - 1];
    //AKE NEW: copy encrypted payload and MAC
    memcpy(noise_message_buf, packet + 1, length - 1);

    /* AKE NEW: Decrypt the incoming message */
    noise_buffer_set_input(noise_message, noise_message_buf, sizeof(noise_message_buf));
    int err = noise_cipherstate_decrypt(conn->recv_cipher, &noise_message);

    if (err != NOISE_ERROR_NONE) {
        //AKE NEW: verify if Nonce overflowed
        if (err == NOISE_ERROR_INVALID_NONCE) {
            /*
             * NEW TODO: The threshold for the counter-based nonce in Noise is 2^64-1
             * From Noise paper:
             * "Incrementing nonces: Reusing a nonce value for n with the same key k for encryption would be catastrophic.
             * Implementations must carefully follow the rules for nonces. Nonces are not allowed to wrap back to zero due
             * to integer overflow, and the maximum nonce value is reserved. This means parties are not allowed to send more
             * than 2^64-1 transport messages."
             * "If EncryptWithAd() or DecryptWithAd() signal an error due to nonce exhaustion, then
             * the application must delete the CipherState and terminate the session."
             * => noise_cipherstate_decrypt() -> NOISE_ERROR_INVALID_NONCE if the nonce previously overflowed.
             */
            //AKE NEW TODO: connection_kill() / wipe? => wipe not available here
//          wipe_crypto_connection(c, crypt_connection_id);
            return -1;
        } else {
            noise_perror("noise_cipherstate_decrypt", err);
            return -1;
        }
    }

    //AKE NEW: memcpy plaintext to data
    memcpy(data, noise_message.data, noise_message.size);

    //AKE NEW: IIUC this is checked by noise_cipherstate_decrypt() anyway
//  if ((unsigned int) len != length - crypto_packet_overhead) {
//      return -1;
//  }

    //AKE NEW: verified via noise_cipherstate_decrypt() (see above)
//  if (diff > DATA_NUM_THRESHOLD * 2) {
//      increment_nonce_number(conn->recv_nonce, DATA_NUM_THRESHOLD);
//  }
    //return len;
    return noise_message.size;
}

/* Send a request packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_request_packet(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t data[MAX_CRYPTO_DATA_SIZE ];
    int len = generate_request_packet(c->log, data, sizeof(data), &conn->recv_array);

    if (len == -1) {
        return -1;
    }

    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end, data,
                                   len);
}

/* Send up to max num previously requested data packets.
 *
 * return -1 on failure.
 * return number of packets sent on success.
 */
static int send_requested_packets(Net_Crypto *c, int crypt_connection_id, uint32_t max_num)
{
    if (max_num == 0) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    const uint64_t temp_time = current_time_monotonic(c->mono_time);
    const uint32_t array_size = num_packets_array(&conn->send_array);
    uint32_t num_sent = 0;

    for (uint32_t i = 0; i < array_size; ++i) {
        Packet_Data *dt;
        const uint32_t packet_num = i + conn->send_array.buffer_start;
        const int ret = get_data_pointer(c->log, &conn->send_array, &dt, packet_num);

        if (ret == -1) {
            return -1;
        }

        if (ret == 0) {
            continue;
        }

        if (dt->sent_time) {
            continue;
        }

        if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, dt->data,
                                    dt->length) == 0) {
            dt->sent_time = temp_time;
            ++num_sent;
        }

        if (num_sent >= max_num) {
            break;
        }
    }

    return num_sent;
}

/* Add a new temp packet to send repeatedly.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int new_temp_packet(const Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t *temp_packet = (uint8_t *) malloc(length);

    if (temp_packet == nullptr) {
        return -1;
    }

    if (conn->temp_packet) {
        free(conn->temp_packet);
    }

    memcpy(temp_packet, packet, length);
    conn->temp_packet = temp_packet;
    conn->temp_packet_length = length;
    conn->temp_packet_sent_time = 0;
    conn->temp_packet_num_sent = 0;
    return 0;
}

/* Clear the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int clear_temp_packet(const Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (conn->temp_packet) {
        free(conn->temp_packet);
    }

    conn->temp_packet = nullptr;
    conn->temp_packet_length = 0;
    conn->temp_packet_sent_time = 0;
    conn->temp_packet_num_sent = 0;
    return 0;
}

/* Send the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_temp_packet(Net_Crypto *c, int crypt_connection_id)
{
    //fprintf(stderr, "ENTERING: send_temp_packet()\n");
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (!conn->temp_packet) {
        return -1;
    }

    if (send_packet_to(c, crypt_connection_id, conn->temp_packet, conn->temp_packet_length) != 0) {
        return -1;
    }

    conn->temp_packet_sent_time = current_time_monotonic(c->mono_time);
    ++conn->temp_packet_num_sent;
    return 0;
}

/* Create a handshake packet and set it as a temp packet.
 * cookie must be COOKIE_LENGTH.
 *
 * AKE: Peer A/Initiator sends handshake packet after receiving of cookie response. Function also used by Peer B/receiver
 * AKE NEW: function adapted because handshake packet lengths are now different for INITIATOR and RESPONDER
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_send_handshake(Net_Crypto *c, int crypt_connection_id, const uint8_t *cookie,
                                 const uint8_t *dht_public_key)
{
    fprintf(stderr, "ENTERING: create_send_handshake()\n");
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    //AKE NEW: Handshake packet length is different for INITIATOR and RESPONDER
    int role = noise_handshakestate_get_role(conn->handshake);

    if (role == NOISE_ROLE_INITIATOR) {
        uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH_INITIATOR];

        if (create_crypto_handshake(c, handshake_packet, cookie,
                                    conn->public_key, dht_public_key, conn->handshake) != sizeof(handshake_packet)) {
            return -1;
        }

        if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0) {
            return -1;
        }
    } else if (role == NOISE_ROLE_RESPONDER) {
        uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH_RESPONDER];

        if (create_crypto_handshake(c, handshake_packet, cookie,
                                    conn->public_key, dht_public_key, conn->handshake) != sizeof(handshake_packet)) {
            return -1;
        }

        if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0) {
            return -1;
        }
    } else {
        return -1;
    }

    send_temp_packet(c, crypt_connection_id);
    return 0;
}

/* Send a kill packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_kill_packet(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t kill_packet = PACKET_ID_KILL;
    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end,
                                   &kill_packet, sizeof(kill_packet));
}

static void connection_kill(Net_Crypto *c, int crypt_connection_id, void *userdata)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return;
    }

    if (conn->connection_status_callback) {
        conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 0,
                                         userdata);
    }

    while (1) { /* TODO(irungentoo): is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (!c->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    crypto_kill(c, crypt_connection_id);
    pthread_mutex_unlock(&c->connections_mutex);
}

/* Handle a received data packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_data_packet_core(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                   bool udp, void *userdata)
{
    fprintf(stderr, "ENTERING: handle_data_packet_core(); PACKET: %d\n", packet[0]);

    if (length > MAX_CRYPTO_PACKET_SIZE || length <= CRYPTO_DATA_PACKET_MIN_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t data[MAX_DATA_DATA_PACKET_SIZE];
    int len = handle_data_packet(c, crypt_connection_id, data, packet, length);

    if (len <= (int)(sizeof(uint32_t) * 2)) {
        return -1;
    }

    uint32_t buffer_start;
    uint32_t num;
    memcpy(&buffer_start, data, sizeof(uint32_t));
    memcpy(&num, data + sizeof(uint32_t), sizeof(uint32_t));
    buffer_start = net_ntohl(buffer_start);
    num = net_ntohl(num);

    uint64_t rtt_calc_time = 0;

    if (buffer_start != conn->send_array.buffer_start) {
        Packet_Data *packet_time;

        if (get_data_pointer(c->log, &conn->send_array, &packet_time, conn->send_array.buffer_start) == 1) {
            rtt_calc_time = packet_time->sent_time;
        }

        if (clear_buffer_until(c->log, &conn->send_array, buffer_start) != 0) {
            return -1;
        }
    }

    uint8_t *real_data = data + (sizeof(uint32_t) * 2);
    uint16_t real_length = len - (sizeof(uint32_t) * 2);

    while (real_data[0] == PACKET_ID_PADDING) { /* Remove Padding */
        ++real_data;
        --real_length;

        if (real_length == 0) {
            return -1;
        }
    }

    if (real_data[0] == PACKET_ID_KILL) {
        connection_kill(c, crypt_connection_id, userdata);
        return 0;
    }

    if (conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
        clear_temp_packet(c, crypt_connection_id);
        conn->status = CRYPTO_CONN_ESTABLISHED;

        if (conn->connection_status_callback) {
            conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 1,
                                             userdata);
        }
    }

    if (real_data[0] == PACKET_ID_REQUEST) {
        uint64_t rtt_time;

        if (udp) {
            rtt_time = conn->rtt_time;
        } else {
            rtt_time = DEFAULT_TCP_PING_CONNECTION;
        }

        int requested = handle_request_packet(c->mono_time, c->log, &conn->send_array, real_data, real_length, &rtt_calc_time,
                                              rtt_time);

        if (requested == -1) {
            return -1;
        }

        set_buffer_end(c->log, &conn->recv_array, num);
    } else if (real_data[0] >= PACKET_ID_RANGE_LOSSLESS_START && real_data[0] <= PACKET_ID_RANGE_LOSSLESS_END) {
        Packet_Data dt = { 0 };
        dt.length = real_length;
        memcpy(dt.data, real_data, real_length);

        if (add_data_to_buffer(c->log, &conn->recv_array, num, &dt) != 0) {
            return -1;
        }

        while (1) {
            pthread_mutex_lock(conn->mutex);
            int ret = read_data_beg_buffer(c->log, &conn->recv_array, &dt);
            pthread_mutex_unlock(conn->mutex);

            if (ret == -1) {
                break;
            }

            if (conn->connection_data_callback) {
                conn->connection_data_callback(conn->connection_data_callback_object, conn->connection_data_callback_id, dt.data,
                                               dt.length, userdata);
            }

            /* conn might get killed in callback. */
            conn = get_crypto_connection(c, crypt_connection_id);

            if (conn == nullptr) {
                return -1;
            }
        }

        /* Packet counter. */
        ++conn->packet_counter;
    } else if (real_data[0] >= PACKET_ID_RANGE_LOSSY_START && real_data[0] <= PACKET_ID_RANGE_LOSSY_END) {

        set_buffer_end(c->log, &conn->recv_array, num);

        if (conn->connection_lossy_data_callback) {
            conn->connection_lossy_data_callback(conn->connection_lossy_data_callback_object,
                                                 conn->connection_lossy_data_callback_id, real_data, real_length, userdata);
        }
    } else {
        return -1;
    }

    if (rtt_calc_time != 0) {
        uint64_t rtt_time = current_time_monotonic(c->mono_time) - rtt_calc_time;

        if (rtt_time < conn->rtt_time) {
            conn->rtt_time = rtt_time;
        }
    }

    return 0;
}

/* Handle a packet that was received for the connection.
 *
 * AKE: handling of Cookie response packets, crypto handshake packets and crypto data packets
 * -> therefore used by Peer A/INITIATOR _AND_ Peer B/RESPONDER
 * AKE NEW: adapted for Noise handshake
 *
 * return -1 on failure.
 * return 0 on success.
 */
//
static int handle_packet_connection(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                    bool udp, void *userdata)
{
    fprintf(stderr, "ENTERING: handle_packet_connection(); PACKET: %d\n", packet[0]);

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    switch (packet[0]) {
        // AKE: case to handle cookie response packets (Peer A/initiator)
        case NET_PACKET_COOKIE_RESPONSE: {
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING) {
                return -1;
            }

            uint8_t cookie[COOKIE_LENGTH ];
            uint64_t number;

            if (handle_cookie_response(c->log, cookie, &number, packet, length, conn->shared_key) != sizeof(cookie)) {
                return -1;
            }

            if (number != conn->cookie_request_number) {
                return -1;
            }

            //AKE NEW: This function can only be called if new_crypto_connection() was already called. No initialization necessary
            //AKE NEW TODO: But maybe it's better if we set the initiator here and not already in new_crypto_connection?

            //AKE NEW: Noise init
//      if (noise_init() != NOISE_ERROR_NONE) {
//          fprintf(stderr, "Noise initialization failed\n");
//          return -1;
//      }
//      //AKE NEW: If I receive a cockie response, I'm initiator
//      int err = noise_handshakestate_new_by_name(&conn->handshake, CRYPTO_NOISE_PROTOCOL_NAME, NOISE_ROLE_INITIATOR);
//      if (err != NOISE_ERROR_NONE) {
//          noise_perror(CRYPTO_NOISE_PROTOCOL_NAME, err);
//          return -1;
//      }
//      //AKE NEW: initialize_handshake
//      if (initialize_handshake(conn->handshake, c->self_secret_key, conn->public_key) == -1) {
//          noise_handshakestate_free(conn->handshake);
//          return -1;
//      }

            int role = noise_handshakestate_get_role(conn->handshake);

            if (role == NOISE_ROLE_INITIATOR) {
                int err = noise_handshakestate_start(conn->handshake);

                if (err != NOISE_ERROR_NONE) {
                    if (err == NOISE_ERROR_INVALID_STATE) {
                        //AKE NEW TODO kill crypto connection
                        // connection_kill() would be possible here
                    } else {
                        noise_perror("start handshake", err);
                    }

                    return -1;
                }

                int action = noise_handshakestate_get_action(conn->handshake);

                if (action == NOISE_ACTION_WRITE_MESSAGE) {
                    // AKE: if cookie response was ok, create and send handshake packet to Peer B/receiver
                    if (create_send_handshake(c, crypt_connection_id, cookie, conn->dht_public_key) != 0) {
                        return -1;
                    }
                }

            } else {
                return -1;
            }

            // AKE: change crypto conn state to CRYPTO_CONN_HANDSHAKE_SENT
            conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            return 0;
        }

        // AKE: case to handle handshake packets (Peer B/receiver)
        //AKE NEW TODO: but maybe possible by differentiating role by using CRYPTO_CONN_STATE?
        //AKE NEW: THIS SEEMS TO BE THE ONLY POSSIBILITY TO HANDLE A HANDSHAKE PACKET AS INITIATOR!
        case NET_PACKET_CRYPTO_HS: {
            fprintf(stderr, "ENTERING: handle_packet_connection(); PACKET: %d => NET_PACKET_CRYPTO_HS => CRYPTO CONN STATE: %d\n",
                    packet[0],
                    conn->status);

            // AKE: very likely, that "Peer B"/receiver (or Peer A/initiator) is in one of these states
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING
                    && conn->status != CRYPTO_CONN_HANDSHAKE_SENT
                    // TODO AKE: why is this status also checked? If it's set after the if
                    && conn->status != CRYPTO_CONN_NOT_CONFIRMED) {
                return -1;
            }

            uint8_t peer_real_pk[CRYPTO_PUBLIC_KEY_SIZE];
            uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];
            uint8_t cookie[COOKIE_LENGTH ];

            int role = noise_handshakestate_get_role(conn->handshake);

            if (role == NOISE_ROLE_INITIATOR) {
                int action = noise_handshakestate_get_action(conn->handshake);

                if (action == NOISE_ACTION_READ_MESSAGE) {
                    fprintf(stderr, "handle_packet_connection(); ACTION: NOISE_ACTION_READ_MESSAGE\n");

                    if (handle_crypto_handshake(c, peer_real_pk, dht_public_key, cookie,
                                                packet, length, conn->public_key, conn->handshake) != 0) {
                        return -1;
                    }
                }

                //AKE NEW: INITIATOR is now finished with the handshake
                /*AKE NEW: If the action is not "split", then the handshake has failed */
                if (noise_handshakestate_get_action(conn->handshake) != NOISE_ACTION_SPLIT) {
                    fprintf(stderr, "protocol handshake failed\n");
                    noise_handshakestate_free(conn->handshake);
                    conn->handshake = 0;
                    //AKE NEW TODO: connection_kill() is possible here, or crypto_kill() or wipe_crypto_connection() => wipe not available here
//              wipe_crypto_connection(c, crypt_connection_id);
                    return -1;
                }
                /*AKE NEW: Split out the two CipherState objects for send and receive */
                else {
                    int err = noise_handshakestate_split(conn->handshake, &conn->send_cipher, &conn->recv_cipher);

                    if (err != NOISE_ERROR_NONE) {
                        noise_perror("split to start data transfer", err);
                        noise_handshakestate_free(conn->handshake);
                        conn->handshake = 0;
                        //AKE NEW TODO: crypto_kill() / wipe_crypto_connection() in this case? connection_kill is possible here wipe not available here
//                  wipe_crypto_connection(c, crypt_connection_id);
                        return -1;
                    }

                    fprintf(stderr, "handle_packet_connection(): NOISE SPLIT OK\n");
                    /*AKE NEW: We no longer need the HandshakeState */
                    noise_handshakestate_free(conn->handshake);
                    conn->handshake = 0;
                }
            } else {
                return -1;
            }

            //AKE NEW TODO: adapt? Don't think this is working with INITIATOR/RESPONDER roles
            //AKE NEW TODO: try to handle with Noise action/state
            if (public_key_cmp(dht_public_key, conn->dht_public_key) == 0) {
                // AKE: Peer B (or Peer A, whoever receives the handshake packet) calculation of shared session key
                //AKE NEW: handled by Noise
                //encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

                /*
                 * AKE: This seems to be an (error/not perfect handshake) case of Peer A
                 * i.e. if Peer A receives handshake packet from Peer B, but has already sent a cookie request to Peer B himself
                 */
                if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
                    if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0) {
                        return -1;
                    }
                }

                // AKE: change crypto conn state to CRYPTO_CONN_HANDSHAKE_SENT (cf. accepted in spec)
                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
            } else {
                if (conn->dht_pk_callback) {
                    conn->dht_pk_callback(conn->dht_pk_callback_object, conn->dht_pk_callback_number, dht_public_key, userdata);
                }
            }

            return 0;
        }

        case NET_PACKET_CRYPTO_DATA: {
            if (conn->status != CRYPTO_CONN_NOT_CONFIRMED && conn->status != CRYPTO_CONN_ESTABLISHED) {
                fprintf(stderr, "ENTERING: handle_packet_connection(); PACKET: %d => ERROR => CRYPTO CONN STATE: %d\n", packet[0],
                        conn->status);
                return -1;
            }

            return handle_data_packet_core(c, crypt_connection_id, packet, length, udp, userdata);
        }

        default: {
            return -1;
        }
    }
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_cryptoconnection(Net_Crypto *c, uint32_t num)
{
    if (num == 0) {
        free(c->crypto_connections);
        c->crypto_connections = nullptr;
        return 0;
    }

    Crypto_Connection *newcrypto_connections = (Crypto_Connection *) realloc(c->crypto_connections,
            num * sizeof(Crypto_Connection));

    if (newcrypto_connections == nullptr) {
        return -1;
    }

    c->crypto_connections = newcrypto_connections;
    return 0;
}

/* Create a new empty crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int create_crypto_connection(Net_Crypto *c)
{
    while (1) { /* TODO(irungentoo): is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (!c->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    int id = -1;

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_FREE) {
            id = i;
            break;
        }
    }

    if (id == -1) {
        if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == 0) {
            id = c->crypto_connections_length;
            ++c->crypto_connections_length;
            memset(&c->crypto_connections[id], 0, sizeof(Crypto_Connection));
        }
    }

    if (id != -1) {
        // Memsetting float/double to 0 is non-portable, so we explicitly set them to 0
        c->crypto_connections[id].packet_recv_rate = 0;
        c->crypto_connections[id].packet_send_rate = 0;
        c->crypto_connections[id].last_packets_left_rem = 0;
        c->crypto_connections[id].packet_send_rate_requested = 0;
        c->crypto_connections[id].last_packets_left_requested_rem = 0;
        c->crypto_connections[id].mutex = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));

        if (c->crypto_connections[id].mutex == nullptr) {
            pthread_mutex_unlock(&c->connections_mutex);
            return -1;
        }

        if (pthread_mutex_init(c->crypto_connections[id].mutex, nullptr) != 0) {
            free(c->crypto_connections[id].mutex);
            pthread_mutex_unlock(&c->connections_mutex);
            return -1;
        }

        c->crypto_connections[id].status = CRYPTO_CONN_NO_CONNECTION;
    }

    pthread_mutex_unlock(&c->connections_mutex);
    return id;
}

/* Wipe a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_crypto_connection(Net_Crypto *c, int crypt_connection_id)
{
    if ((uint32_t) crypt_connection_id >= c->crypto_connections_length) {
        return -1;
    }

    if (c->crypto_connections == nullptr) {
        return -1;
    }

    const Crypto_Conn_State status = c->crypto_connections[crypt_connection_id].status;

    if (status == CRYPTO_CONN_FREE) {
        return -1;
    }

    uint32_t i;

    pthread_mutex_destroy(c->crypto_connections[crypt_connection_id].mutex);
    free(c->crypto_connections[crypt_connection_id].mutex);
    crypto_memzero(&c->crypto_connections[crypt_connection_id], sizeof(Crypto_Connection));

    /* check if we can resize the connections array */
    for (i = c->crypto_connections_length; i != 0; --i) {
        if (c->crypto_connections[i - 1].status != CRYPTO_CONN_FREE) {
            break;
        }
    }

    if (c->crypto_connections_length != i) {
        c->crypto_connections_length = i;
        realloc_cryptoconnection(c, c->crypto_connections_length);
    }

    return 0;
}

/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
static int getcryptconnection_id(const Net_Crypto *c, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        if (!crypt_connection_id_is_valid(c, i)) {
            continue;
        }

        if (public_key_cmp(public_key, c->crypto_connections[i].public_key) == 0) {
            return i;
        }
    }

    return -1;
}

/* Add a source to the crypto connection.
 * This is to be used only when we have received a packet from that source.
 *
 *  return -1 on failure.
 *  return positive number on success.
 *  0 if source was a direct UDP connection.
 */
static int crypto_connection_add_source(Net_Crypto *c, int crypt_connection_id, IP_Port source)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (net_family_is_ipv4(source.ip.family) || net_family_is_ipv6(source.ip.family)) {
        if (add_ip_port_connection(c, crypt_connection_id, source) != 0) {
            return -1;
        }

        if (net_family_is_ipv4(source.ip.family)) {
            conn->direct_lastrecv_timev4 = mono_time_get(c->mono_time);
        } else {
            conn->direct_lastrecv_timev6 = mono_time_get(c->mono_time);
        }

        return 0;
    }

    if (net_family_is_tcp_family(source.ip.family)) {
        if (add_tcp_number_relay_connection(c->tcp_c, conn->connection_number_tcp, source.ip.ip.v6.uint32[0]) == 0) {
            return 1;
        }
    }

    return -1;
}

/* Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, new_connection_cb *new_connection_callback, void *object)
{
    c->new_connection_callback = new_connection_callback;
    c->new_connection_callback_object = object;
}

/* Handle a handshake packet by someone who wants to initiate a new connection with us.
 * This calls the callback set by new_connection_handler() if the handshake is ok.
 *
 * AKE: Peer B/receiver handles incoming handshake packet and sends a handshake packet himself
 * AKE NEW: function adapted for Noise handshake => RESPONDER case
 * AKE NEW: PROBLEM - I don't know the peers public key to initialize a handshake in this case!
 * => SOLUTION: Changed from KK to IK pattern
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_new_connection_handshake(Net_Crypto *c, IP_Port source, const uint8_t *data, uint16_t length,
        void *userdata)
{
    fprintf(stderr, "ENTERING: handle_new_connection_handshake()\n");
    /*
     * AKE: This function seems to be called if Peer B/receiver doesn't have a Crypto_Connection
     * conn yet (with the peer it received the handshake packet from)!
     * => is called during normal handshake and if new friend is added
     */
    New_Connection n_c;
    n_c.cookie = (uint8_t *) malloc(COOKIE_LENGTH);

    if (n_c.cookie == nullptr) {
        return -1;
    }

    n_c.source = source;
    n_c.cookie_length = COOKIE_LENGTH;

    //AKE NEW: add HandshakeState to New_Connection? Or a local variable here? => New_Connection for accept_crypto_connection!
    //NoiseHandshakeState *handshake_temp;

    //AKE NEW: IN THIS CASE THIS PEER IS DEFINATELY RESPONDER!
    //AKE NEW: Noise init
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return -1;
    }

    //AKE NEW: If I receive a handshake packet, I'm responder
    int err = noise_handshakestate_new_by_name(&n_c.handshake_temp, CRYPTO_NOISE_PROTOCOL_NAME, NOISE_ROLE_RESPONDER);

    if (err != NOISE_ERROR_NONE) {
        noise_perror(CRYPTO_NOISE_PROTOCOL_NAME, err);
        return -1;
    }

    //AKE NEW: initialize_handshake
    //AKE NEW: IMPORTANT n_c.publicy_key is empty/not defined here, it's set handle_crypto_handshake()...
    if (initialize_handshake(n_c.handshake_temp, c->self_secret_key, n_c.public_key) == -1) {
        noise_handshakestate_free(n_c.handshake_temp);
        return -1;
    }

    int role = noise_handshakestate_get_role(n_c.handshake_temp);

    if (role == NOISE_ROLE_RESPONDER) {
        int err = noise_handshakestate_start(n_c.handshake_temp);

        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            //AKE NEW: kill / wipe crypto connection? => no crypto connection here (is created afterwards)
            return -1;
        }

        int action = noise_handshakestate_get_action(n_c.handshake_temp);

        if (action == NOISE_ACTION_READ_MESSAGE) {
            // AKE: Handle the crypto handshake packet from Peer A/initiator (incl. Other Cookie from A)
            if (handle_crypto_handshake(c, n_c.public_key, n_c.dht_public_key,
                                        n_c.cookie, data, length, nullptr, n_c.handshake_temp) != 0) {
                free(n_c.cookie);
                return -1;
            }
        }

    } else {
        return -1;
    }

    const int crypt_connection_id = getcryptconnection_id(c, n_c.public_key);

    // AKE: Case where accept_crypto_connection() is _NOT_ necessary
    if (crypt_connection_id != -1) {
        Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

        if (conn == nullptr) {
            return -1;
        }

        if (public_key_cmp(n_c.dht_public_key, conn->dht_public_key) != 0) {
            connection_kill(c, crypt_connection_id, userdata);
        } else {
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING && conn->status != CRYPTO_CONN_HANDSHAKE_SENT) {
                free(n_c.cookie);
                return -1;
            }

            //AKE NEW: memcpy handshake_temp into conn->handshake
//          memcpy(conn->handshake, handshake_temp, sizeof(handshake_temp));
            conn->handshake = n_c.handshake_temp;
            //AKE NEW: free handshake -> No:
            /*
             * An important note about the copying: It's a shallow copy, just like with memcpy.
             * That means if you have e.g. a structure containing pointers, it's only the actual
             * pointers that will be copied and not what they point to, so after the copy you will
             * have two pointers pointing to the same memory.
             * https://stackoverflow.com/questions/9127246/copy-struct-to-struct-in-c
             */
//          noise_handshakestate_free(handshake_temp);
            //AKE NEW: Not necessary, nonce handled by Noise
//          memcpy(conn->recv_nonce, n_c.recv_nonce, CRYPTO_NONCE_SIZE);
            // AKE: Peer A/initiator session pk is copied into the crypto connection from the new connection
            //AKE NEW: conn->peersessionpublic_key is NOT needed for new handshake
//          memcpy(conn->peersessionpublic_key, n_c.peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);
            // AKE: Peer B/receiver calculates shared session key from Peer A/initiator public key and self session secret key
            // AKE: Where is conn->sessionsecret_key coming from? => conn already existed -> there it is saved! Keys are generated in new_net_crypto()!
            //AKE NEW: handeled by noise
//          encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);
            crypto_connection_add_source(c, crypt_connection_id, source);

            // AKE: Send handshake packet/message 2 Peer B/receiver -> Peer A/initiator
            int role = noise_handshakestate_get_role(conn->handshake);

            if (role == NOISE_ROLE_RESPONDER) {
                int action = noise_handshakestate_get_action(conn->handshake);

                if (action == NOISE_ACTION_WRITE_MESSAGE) {
                    // AKE: if cookie response was ok, create and send handshake packet to Peer B/receiver
                    if (create_send_handshake(c, crypt_connection_id, n_c.cookie, n_c.dht_public_key) != 0) {
                        free(n_c.cookie);
                        return -1;
                    }
                }

                //AKE NEW: no else needed here, because of split if?
                /*AKE NEW: If the action is not "split", then the handshake has failed */
                if (noise_handshakestate_get_action(conn->handshake) != NOISE_ACTION_SPLIT) {
                    fprintf(stderr, "protocol handshake failed\n");
                    //AKE NEW: handshake failed, free memory
                    noise_handshakestate_free(conn->handshake);
                    //AKE NEW: Only free one of the handshake objects, otherwise it's a double free/segfault
//                  noise_handshakestate_free(n_c.handshake_temp);
                    conn->handshake = 0;
//                  n_c.handshake_temp = 0;
                    //AKE NEW TODO: or wipe_crypto_connection() or kill?
                    wipe_crypto_connection(c, crypt_connection_id);
                    return -1;
                }
                /*AKE NEW: Split out the two CipherState objects for send and receive */
                else {
                    int err = noise_handshakestate_split(conn->handshake, &conn->send_cipher, &conn->recv_cipher);

                    if (err != NOISE_ERROR_NONE) {
                        noise_perror("split to start data transfer", err);
                        noise_handshakestate_free(conn->handshake);
                        //AKE NEW: Only free one of the handshake objects, otherwise it's a double free/segfault
//                      noise_handshakestate_free(n_c.handshake_temp);
                        conn->handshake = 0;
//                      n_c.handshake_temp = 0;
                        return -1;
                    }

                    fprintf(stderr, "handle_new_connection_handshake(): NOISE SPLIT OK\n");
                    /*AKE NEW: We no longer need the HandshakeState */
                    noise_handshakestate_free(conn->handshake);
                    //AKE NEW: Only free one of the handshake objects, otherwise it's a double free/segfault
//                  noise_handshakestate_free(n_c.handshake_temp);
                    conn->handshake = 0;
//                  n_c.handshake_temp = 0;
                }
            } else {
                //AKE NEW TODO: what to do in this case?
                wipe_crypto_connection(c, crypt_connection_id);
                return -1;
            }

            // AKE: Peer B/receiver accepts the connection (cf. spec)
            // AKE: TODO in accept_crypto_connection this happens before this peer calls create_send_handshake() -> shoudldn't this be also the case here?
            conn->status = CRYPTO_CONN_NOT_CONFIRMED;
            free(n_c.cookie);
            return 0;
        }
    }

    // AKE: THIS SEEMS TO CALL accept_crypto_connection() => That's also why encrypt_precompute() and create_send_handshake() are called twice
    int ret = c->new_connection_callback(c->new_connection_callback_object, &n_c);
    free(n_c.cookie);
    return ret;
}

/* Accept a crypto connection.
 *
 * AKE: Peer B/receiver handshake (message 2)
 * AKE: This function needs to be called by Peer B/receiver, otherwise he cannot calculate his ephemeral keypair!
 * (only if he also starts a handshake / calls new_crypto_connection())
 * AKE: This is the related section in the spec:
 * AKE: "If there is no existing connection to the peer identified by the long term
 * AKE: public key to set to 'Accepted', one will be created with that status."
 * AKE: This function doesn't call handle_crypto_handshake() because it's called via
 * handle_new_connection_handshake() and there also handle_crypto_handshake() is called.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int accept_crypto_connection(Net_Crypto *c, New_Connection *n_c)
{
    fprintf(stderr, "ENTERING: accept_crypto_connection()\n");

    if (getcryptconnection_id(c, n_c->public_key) != -1) {
        return -1;
    }

    //NEW AKE: here the crypto connection gets created for the RESPONDER
    const int crypt_connection_id = create_crypto_connection(c);

    if (crypt_connection_id == -1) {
        LOGGER_ERROR(c->log, "Could not create new crypto connection");
        return -1;
    }

    Crypto_Connection *conn = &c->crypto_connections[crypt_connection_id];

    if (n_c->cookie_length != COOKIE_LENGTH) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    const int connection_number_tcp = new_tcp_connection_to(c->tcp_c, n_c->dht_public_key, crypt_connection_id);
    pthread_mutex_unlock(&c->tcp_mutex);

    if (connection_number_tcp == -1) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    conn->connection_number_tcp = connection_number_tcp;
    memcpy(conn->public_key, n_c->public_key, CRYPTO_PUBLIC_KEY_SIZE);

    //AKE NEW: Nonce not necessary - handled by Noise
//  memcpy(conn->recv_nonce, n_c->recv_nonce, CRYPTO_NONCE_SIZE);
    // AKE: the peer's session pubkey is copied into the crypto connection from new connection
    //AKE NEW: NOT NECESSARY - handled by Noise
    //memcpy(conn->peersessionpublic_key, n_c->peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);
    // AKE: Nonce is set here, therefore call to handle_new_connection_handshake() only possible after call of this function!
    //AKE NEW: Nonce not necessary - handled by Noise
//  random_nonce(conn->sent_nonce);
    // AKE: Message 2: generate new session public/private keypair -> peer receiving the handshake packet
    //AKE NEW: not necessary
    //crypto_new_keypair(conn->sessionpublic_key, conn->sessionsecret_key);
    // AKE: Session Key Derivation by using session secret key and peer's session public key
    // AKE: peers session pk (handshake receiving peer) -> it's coming from New_Connection n_c
    // AKE: This shared_key should be hashed (HKDF) and not just the raw ECDH result as secret used.
    //AKE NEW: not necessary (handled by Noise)
    //encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

    // AKE: CRYPTO_CONN_NOT_CONFIRMED = ACCEPTED state of connection (need to send handshake packet)
    conn->status = CRYPTO_CONN_NOT_CONFIRMED;

    //AKE NEW: IN THIS CASE THIS PEER IS DEFINATELY RESPONDER!
    conn->handshake = n_c->handshake_temp;

    int role = noise_handshakestate_get_role(conn->handshake);

    if (role == NOISE_ROLE_RESPONDER) {
        int action = noise_handshakestate_get_action(conn->handshake);

        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            // AKE: if cookie response was ok, create and send handshake packet to Peer B/receiver
            if (create_send_handshake(c, crypt_connection_id, n_c->cookie, n_c->dht_public_key) != 0) {
                pthread_mutex_lock(&c->tcp_mutex);
                kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
                pthread_mutex_unlock(&c->tcp_mutex);
                wipe_crypto_connection(c, crypt_connection_id);
                return -1;
            }
        }

        //AKE NEW: no else needed here, because of split if?
        /*AKE NEW: If the action is not "split", then the handshake has failed */
        if (noise_handshakestate_get_action(conn->handshake) != NOISE_ACTION_SPLIT) {
            fprintf(stderr, "protocol handshake failed\n");
            //AKE NEW: handshake failed, free memory
            noise_handshakestate_free(conn->handshake);
            //AKE NEW: only free one of the handshake objects because otherwise it's a double free/segfault
//          noise_handshakestate_free(n_c->handshake_temp);
            conn->handshake = 0;
//          n_c->handshake_temp = 0;
            //AKE NEW TODO: or wipe_crypto_connection() or kill?
            wipe_crypto_connection(c, crypt_connection_id);
            return -1;
        }
        /*AKE NEW: Split out the two CipherState objects for send and receive */
        else {
            int err = noise_handshakestate_split(conn->handshake, &conn->send_cipher, &conn->recv_cipher);

            if (err != NOISE_ERROR_NONE) {
                noise_perror("split to start data transfer", err);
                noise_handshakestate_free(conn->handshake);
                //AKE NEW: only free one of the handshake objects because otherwise it's a double free/segfault
//              noise_handshakestate_free(n_c->handshake_temp);
                conn->handshake = 0;
//              n_c->handshake_temp = 0;
                //AKE NEW TODO: or wipe_crypto_connection() or kill?
                wipe_crypto_connection(c, crypt_connection_id);
                return -1;
            }

            fprintf(stderr, "accept_crypto_connection(): NOISE SPLIT OK\n");
            /*AKE NEW: We no longer need the HandshakeState */
            noise_handshakestate_free(conn->handshake);
            //AKE NEW: only free one of the handshake objects because otherwise it's a double free/segfault
//          noise_handshakestate_free(n_c->handshake_temp);
            conn->handshake = 0;
//          n_c->handshake_temp = 0;
            fprintf(stderr, "accept_crypto_connection(): Segmentation fault here?\n");
        }
    } else {
        //AKE NEW TODO: what to do in this case?
        //AKE NEW: or wipe_crypto_connection() or kill?
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    memcpy(conn->dht_public_key, n_c->dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    conn->rtt_time = DEFAULT_PING_CONNECTION;
    crypto_connection_add_source(c, crypt_connection_id, n_c->source);

    return crypt_connection_id;
}

/* Create a crypto connection.
 * If one to that real public key already exists, return it.
 * AKE: Perfect handshake: Peer A initiates handshake by creating and sending a cookie request.
 * AKE: Realistic handshake: also called by Peer B
 * AKE NEW: Function adapted for new handshake - INITIATOR CASE
 * AKE NEW: This function is likely to be called also by the other peer (at least if they are already friends)!
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *c, const uint8_t *real_public_key, const uint8_t *dht_public_key)
{
    int crypt_connection_id = getcryptconnection_id(c, real_public_key);

    if (crypt_connection_id != -1) {
        return crypt_connection_id;
    }

    // AKE NEW: here the the crypto connection gets created by the initiator
    crypt_connection_id = create_crypto_connection(c);

    if (crypt_connection_id == -1) {
        return -1;
    }

    Crypto_Connection *conn = &c->crypto_connections[crypt_connection_id];

    pthread_mutex_lock(&c->tcp_mutex);
    // AKE: Initate handshake, create tcp connection to peer
    /* AKE: Sometimes toxcore might receive the DHT public key of the peer first with a handshake
     * packet so it is important that this case is handled and that the implementation passes the
     * DHT public key to the other modules (DHT, TCP_connection) because this does happen.
     */
    const int connection_number_tcp = new_tcp_connection_to(c->tcp_c, dht_public_key, crypt_connection_id);
    pthread_mutex_unlock(&c->tcp_mutex);

    if (connection_number_tcp == -1) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    conn->connection_number_tcp = connection_number_tcp;
    memcpy(conn->public_key, real_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    // AKE: Nonce generation for handshake encrypted part
    //AKE NEW: not necessary
//  random_nonce(conn->sent_nonce);
    // AKE: Peer A handshake initiator _session_ public/private key pair generation
    //AKE NEW: Not necessary - handled by Noise
    //crypto_new_keypair(conn->sessionpublic_key, conn->sessionsecret_key);

    // AKE: Peer A crypto conn state is set to cookie requested
    conn->status = CRYPTO_CONN_COOKIE_REQUESTING;
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    conn->rtt_time = DEFAULT_PING_CONNECTION;
    memcpy(conn->dht_public_key, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    //AKE NEW: Noise init
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return -1;
    }

    //AKE NEW: Create NoiseHandshakState as INITIATOR
    int err = noise_handshakestate_new_by_name(&conn->handshake, CRYPTO_NOISE_PROTOCOL_NAME, NOISE_ROLE_INITIATOR);

    if (err != NOISE_ERROR_NONE) {
        noise_perror(CRYPTO_NOISE_PROTOCOL_NAME, err);
        return -1;
    }

    fprintf(stderr, "START: new_crypto_connection() initialize_handshake()\n");

    //AKE NEW: initialize_handshake
    if (initialize_handshake(conn->handshake, c->self_secret_key, conn->public_key) == -1) {
        noise_handshakestate_free(conn->handshake);
        return -1;
    }

    fprintf(stderr, "END: new_crypto_connection() initialize_handshake()\n");

    conn->cookie_request_number = random_u64();
    uint8_t cookie_request[COOKIE_REQUEST_LENGTH ];

    // AKE: Call: Create cookie request -> Initiator of handshake and send cookie request
    // AKE: Cookie request of initiator doesn't contain a cookie! Just to request one from peer!
    // AKE: conn->cookie_request_number is the echoID in the cookie request packet!
    if (create_cookie_request(c, cookie_request, conn->dht_public_key, conn->cookie_request_number,
                              conn->shared_key) != sizeof(cookie_request)
            || new_temp_packet(c, crypt_connection_id, cookie_request, sizeof(cookie_request)) != 0) {
        pthread_mutex_lock(&c->tcp_mutex);
        kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
        pthread_mutex_unlock(&c->tcp_mutex);
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    return crypt_connection_id;
}

/* Set the direct ip of the crypto connection.
 *
 * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_direct_ip_port(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port, bool connected)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (add_ip_port_connection(c, crypt_connection_id, ip_port) != 0) {
        return -1;
    }

    const uint64_t direct_lastrecv_time = connected ? mono_time_get(c->mono_time) : 0;

    if (net_family_is_ipv4(ip_port.ip.family)) {
        conn->direct_lastrecv_timev4 = direct_lastrecv_time;
    } else {
        conn->direct_lastrecv_timev6 = direct_lastrecv_time;
    }

    return 0;
}

static int tcp_data_callback(void *object, int crypt_connection_id, const uint8_t *data, uint16_t length,
                             void *userdata)
{
    Net_Crypto *c = (Net_Crypto *) object;

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (data[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_handle_cookie_request(c, conn->connection_number_tcp, data, length);
    }

    // This unlocks the mutex that at this point is locked by do_tcp before
    // calling do_tcp_connections.
    pthread_mutex_unlock(&c->tcp_mutex);
    // AKE: One possiblity for Peer A/initator to handle a received cookie response packet
    int ret = handle_packet_connection(c, crypt_connection_id, data, length, 0, userdata);
    pthread_mutex_lock(&c->tcp_mutex);

    if (ret != 0) {
        return -1;
    }

    // TODO(irungentoo): detect and kill bad TCP connections.
    return 0;
}

static int tcp_oob_callback(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                            const uint8_t *data, uint16_t length, void *userdata)
{
    Net_Crypto *c = (Net_Crypto *) object;

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    // AKE: cookie request packet received
    if (data[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_oob_handle_cookie_request(c, tcp_connections_number, public_key, data, length);
    }

    // AKE: handshake packet received
    if (data[0] == NET_PACKET_CRYPTO_HS) {
        IP_Port source;
        source.port = 0;
        source.ip.family = net_family_tcp_family;
        source.ip.ip.v6.uint32[0] = tcp_connections_number;

        if (handle_new_connection_handshake(c, source, data, length, userdata) != 0) {
            return -1;
        }

        return 0;
    }

    return -1;
}

/* Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay_peer(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port, const uint8_t *public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    int ret = add_tcp_relay_connection(c->tcp_c, conn->connection_number_tcp, ip_port, public_key);
    pthread_mutex_unlock(&c->tcp_mutex);
    return ret;
}

/* Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay(Net_Crypto *c, IP_Port ip_port, const uint8_t *public_key)
{
    pthread_mutex_lock(&c->tcp_mutex);
    int ret = add_tcp_relay_global(c->tcp_c, ip_port, public_key);
    pthread_mutex_unlock(&c->tcp_mutex);
    return ret;
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(Net_Crypto *c)
{
    pthread_mutex_lock(&c->tcp_mutex);
    int ret = get_random_tcp_onion_conn_number(c->tcp_c);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto *c, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length)
{
    pthread_mutex_lock(&c->tcp_mutex);
    int ret = tcp_send_onion_request(c->tcp_c, tcp_connections_number, data, length);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/* Copy a maximum of num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(Net_Crypto *c, Node_format *tcp_relays, uint16_t num)
{
    if (num == 0) {
        return 0;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    unsigned int ret = tcp_copy_connected_relays(c->tcp_c, tcp_relays, num);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

static void do_tcp(Net_Crypto *c, void *userdata)
{
    pthread_mutex_lock(&c->tcp_mutex);
    do_tcp_connections(c->log, c->tcp_c, userdata);
    pthread_mutex_unlock(&c->tcp_mutex);

    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        if (conn->status != CRYPTO_CONN_ESTABLISHED) {
            continue;
        }

        bool direct_connected = 0;

        if (!crypto_connection_status(c, i, &direct_connected, nullptr)) {
            continue;
        }

        if (direct_connected) {
            pthread_mutex_lock(&c->tcp_mutex);
            set_tcp_connection_to_status(c->tcp_c, conn->connection_number_tcp, 0);
            pthread_mutex_unlock(&c->tcp_mutex);
        } else {
            pthread_mutex_lock(&c->tcp_mutex);
            set_tcp_connection_to_status(c->tcp_c, conn->connection_number_tcp, 1);
            pthread_mutex_unlock(&c->tcp_mutex);
        }
    }
}

/* Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_status_handler(const Net_Crypto *c, int crypt_connection_id,
                              connection_status_cb *connection_status_callback, void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_status_callback = connection_status_callback;
    conn->connection_status_callback_object = object;
    conn->connection_status_callback_id = id;
    return 0;
}

/* Set function to be called when connection with crypt_connection_id receives a data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *c, int crypt_connection_id,
                            connection_data_cb *connection_data_callback, void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_data_callback = connection_data_callback;
    conn->connection_data_callback_object = object;
    conn->connection_data_callback_id = id;
    return 0;
}

/* Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(Net_Crypto *c, int crypt_connection_id,
                                  connection_lossy_data_cb *connection_lossy_data_callback,
                                  void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_lossy_data_callback = connection_lossy_data_callback;
    conn->connection_lossy_data_callback_object = object;
    conn->connection_lossy_data_callback_id = id;
    return 0;
}

/* Set the function for this friend that will be callbacked with object and number if
 * the friend sends us a different dht public key than we have associated to him.
 *
 * If this function is called, the connection should be recreated with the new public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int nc_dht_pk_callback(Net_Crypto *c, int crypt_connection_id, dht_pk_cb *function, void *object, uint32_t number)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    conn->dht_pk_callback = function;
    conn->dht_pk_callback_object = object;
    conn->dht_pk_callback_number = number;
    return 0;
}

/* Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int crypto_id_ip_port(const Net_Crypto *c, IP_Port ip_port)
{
    return bs_list_find(&c->ip_port_list, (uint8_t *) &ip_port);
}

#define CRYPTO_MIN_PACKET_SIZE (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE)

/* Handle raw UDP packets coming directly from the socket.
 *
 * Handles:
 * Cookie response packets.
 * Crypto handshake packets.
 * Crypto data packets.
 *
 */
static int udp_handle_packet(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Net_Crypto *c = (Net_Crypto *) object;

    if (length <= CRYPTO_MIN_PACKET_SIZE || length > MAX_CRYPTO_PACKET_SIZE) {
        return 1;
    }

    const int crypt_connection_id = crypto_id_ip_port(c, source);

    // AKE: No crypto connection yet
    if (crypt_connection_id == -1) {
        if (packet[0] != NET_PACKET_CRYPTO_HS) {
            return 1;
        }

        if (handle_new_connection_handshake(c, source, packet, length, userdata) != 0) {
            return 1;
        }

        return 0;
    }

    // AKE: One possiblity for Peer A/initator to handle a received cookie response packet
    if (handle_packet_connection(c, crypt_connection_id, packet, length, 1, userdata) != 0) {
        return 1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(conn->mutex);

    if (net_family_is_ipv4(source.ip.family)) {
        conn->direct_lastrecv_timev4 = mono_time_get(c->mono_time);
    } else {
        conn->direct_lastrecv_timev6 = mono_time_get(c->mono_time);
    }

    pthread_mutex_unlock(conn->mutex);
    return 0;
}

/* The dT for the average packet receiving rate calculations.
 Also used as the */
#define PACKET_COUNTER_AVERAGE_INTERVAL 50

/* Ratio of recv queue size / recv packet rate (in seconds) times
 * the number of ms between request packets to send at that ratio
 */
#define REQUEST_PACKETS_COMPARE_CONSTANT (0.125 * 100.0)

/* Timeout for increasing speed after congestion event (in ms). */
#define CONGESTION_EVENT_TIMEOUT 1000

/* If the send queue is SEND_QUEUE_RATIO times larger than the
 * calculated link speed the packet send speed will be reduced
 * by a value depending on this number.
 */
#define SEND_QUEUE_RATIO 2.0

static void send_crypto_packets(Net_Crypto *c)
{
    const uint64_t temp_time = current_time_monotonic(c->mono_time);
    double total_send_rate = 0;
    uint32_t peak_request_packet_interval = -1;

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        if ((CRYPTO_SEND_PACKET_INTERVAL + conn->temp_packet_sent_time) < temp_time) {
            send_temp_packet(c, i);
        }

        if ((conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED)
                && (CRYPTO_SEND_PACKET_INTERVAL + conn->last_request_packet_sent) < temp_time) {
            if (send_request_packet(c, i) == 0) {
                conn->last_request_packet_sent = temp_time;
            }
        }

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            if (conn->packet_recv_rate > CRYPTO_PACKET_MIN_RATE) {
                double request_packet_interval = (REQUEST_PACKETS_COMPARE_CONSTANT / ((num_packets_array(
                                                      &conn->recv_array) + 1.0) / (conn->packet_recv_rate + 1.0)));

                double request_packet_interval2 = ((CRYPTO_PACKET_MIN_RATE / conn->packet_recv_rate) *
                                                   (double) CRYPTO_SEND_PACKET_INTERVAL) + (double) PACKET_COUNTER_AVERAGE_INTERVAL;

                if (request_packet_interval2 < request_packet_interval) {
                    request_packet_interval = request_packet_interval2;
                }

                if (request_packet_interval < PACKET_COUNTER_AVERAGE_INTERVAL) {
                    request_packet_interval = PACKET_COUNTER_AVERAGE_INTERVAL;
                }

                if (request_packet_interval > CRYPTO_SEND_PACKET_INTERVAL) {
                    request_packet_interval = CRYPTO_SEND_PACKET_INTERVAL;
                }

                if (temp_time - conn->last_request_packet_sent > (uint64_t) request_packet_interval) {
                    if (send_request_packet(c, i) == 0) {
                        conn->last_request_packet_sent = temp_time;
                    }
                }

                if (request_packet_interval < peak_request_packet_interval) {
                    peak_request_packet_interval = request_packet_interval;
                }
            }

            if ((PACKET_COUNTER_AVERAGE_INTERVAL + conn->packet_counter_set) < temp_time) {
                const double dt = temp_time - conn->packet_counter_set;

                conn->packet_recv_rate = (double) conn->packet_counter / (dt / 1000.0);
                conn->packet_counter = 0;
                conn->packet_counter_set = temp_time;

                uint32_t packets_sent = conn->packets_sent;
                conn->packets_sent = 0;

                uint32_t packets_resent = conn->packets_resent;
                conn->packets_resent = 0;

                /* conjestion control
                 calculate a new value of conn->packet_send_rate based on some data
                 */

                unsigned int pos = conn->last_sendqueue_counter % CONGESTION_QUEUE_ARRAY_SIZE;
                conn->last_sendqueue_size[pos] = num_packets_array(&conn->send_array);

                long signed int sum = 0;
                sum = (long signed int) conn->last_sendqueue_size[pos] -
                      (long signed int) conn->last_sendqueue_size[(pos + 1) % CONGESTION_QUEUE_ARRAY_SIZE];

                unsigned int n_p_pos = conn->last_sendqueue_counter % CONGESTION_LAST_SENT_ARRAY_SIZE;
                conn->last_num_packets_sent[n_p_pos] = packets_sent;
                conn->last_num_packets_resent[n_p_pos] = packets_resent;

                conn->last_sendqueue_counter = (conn->last_sendqueue_counter + 1) %
                                               (CONGESTION_QUEUE_ARRAY_SIZE * CONGESTION_LAST_SENT_ARRAY_SIZE);

                bool direct_connected = 0;
                /* return value can be ignored since the `if` above ensures the connection is established */
                crypto_connection_status(c, i, &direct_connected, nullptr);

                /* When switching from TCP to UDP, don't change the packet send rate for CONGESTION_EVENT_TIMEOUT ms. */
                if (!(direct_connected && conn->last_tcp_sent + CONGESTION_EVENT_TIMEOUT > temp_time)) {
                    long signed int total_sent = 0;
                    long signed int total_resent = 0;

                    // TODO(irungentoo): use real delay
                    unsigned int delay = (unsigned int)((conn->rtt_time / PACKET_COUNTER_AVERAGE_INTERVAL) + 0.5);
                    unsigned int packets_set_rem_array = (CONGESTION_LAST_SENT_ARRAY_SIZE - CONGESTION_QUEUE_ARRAY_SIZE);

                    if (delay > packets_set_rem_array) {
                        delay = packets_set_rem_array;
                    }

                    for (unsigned j = 0; j < CONGESTION_QUEUE_ARRAY_SIZE; ++j) {
                        unsigned int ind = (j + (packets_set_rem_array - delay) + n_p_pos) % CONGESTION_LAST_SENT_ARRAY_SIZE;
                        total_sent += conn->last_num_packets_sent[ind];
                        total_resent += conn->last_num_packets_resent[ind];
                    }

                    if (sum > 0) {
                        total_sent -= sum;
                    } else {
                        if (total_resent > -sum) {
                            total_resent = -sum;
                        }
                    }

                    /* if queue is too big only allow resending packets. */
                    uint32_t npackets = num_packets_array(&conn->send_array);
                    double min_speed = 1000.0 * (((double)(total_sent)) / ((double)(CONGESTION_QUEUE_ARRAY_SIZE) *
                                                 PACKET_COUNTER_AVERAGE_INTERVAL));

                    double min_speed_request = 1000.0 * (((double)(total_sent + total_resent)) / ((double)(
                            CONGESTION_QUEUE_ARRAY_SIZE) * PACKET_COUNTER_AVERAGE_INTERVAL));

                    if (min_speed < CRYPTO_PACKET_MIN_RATE) {
                        min_speed = CRYPTO_PACKET_MIN_RATE;
                    }

                    double send_array_ratio = (((double) npackets) / min_speed);

                    // TODO(irungentoo): Improve formula?
                    if (send_array_ratio > SEND_QUEUE_RATIO && CRYPTO_MIN_QUEUE_LENGTH < npackets) {
                        conn->packet_send_rate = min_speed * (1.0 / (send_array_ratio / SEND_QUEUE_RATIO));
                    } else if (conn->last_congestion_event + CONGESTION_EVENT_TIMEOUT < temp_time) {
                        conn->packet_send_rate = min_speed * 1.2;
                    } else {
                        conn->packet_send_rate = min_speed * 0.9;
                    }

                    conn->packet_send_rate_requested = min_speed_request * 1.2;

                    if (conn->packet_send_rate < CRYPTO_PACKET_MIN_RATE) {
                        conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
                    }

                    if (conn->packet_send_rate_requested < conn->packet_send_rate) {
                        conn->packet_send_rate_requested = conn->packet_send_rate;
                    }
                }
            }

            if (conn->last_packets_left_set == 0 || conn->last_packets_left_requested_set == 0) {
                conn->last_packets_left_requested_set = temp_time;
                conn->last_packets_left_set = temp_time;
                conn->packets_left_requested = CRYPTO_MIN_QUEUE_LENGTH;
                conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
            } else {
                if (((uint64_t)((1000.0 / conn->packet_send_rate) + 0.5) + conn->last_packets_left_set) <= temp_time) {
                    double n_packets = conn->packet_send_rate * (((double)(temp_time - conn->last_packets_left_set)) / 1000.0);
                    n_packets += conn->last_packets_left_rem;

                    uint32_t num_packets = n_packets;
                    double rem = n_packets - (double) num_packets;

                    if (conn->packets_left > num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH) {
                        conn->packets_left = num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH;
                    } else {
                        conn->packets_left += num_packets;
                    }

                    conn->last_packets_left_set = temp_time;
                    conn->last_packets_left_rem = rem;
                }

                if (((uint64_t)((1000.0 / conn->packet_send_rate_requested) + 0.5) + conn->last_packets_left_requested_set) <=
                        temp_time) {
                    double n_packets = conn->packet_send_rate_requested
                                       * (((double)(temp_time - conn->last_packets_left_requested_set)) /
                                          1000.0);
                    n_packets += conn->last_packets_left_requested_rem;

                    uint32_t num_packets = n_packets;
                    double rem = n_packets - (double) num_packets;
                    conn->packets_left_requested = num_packets;

                    conn->last_packets_left_requested_set = temp_time;
                    conn->last_packets_left_requested_rem = rem;
                }

                if (conn->packets_left > conn->packets_left_requested) {
                    conn->packets_left_requested = conn->packets_left;
                }
            }

            int ret = send_requested_packets(c, i, conn->packets_left_requested);

            if (ret != -1) {
                conn->packets_left_requested -= ret;
                conn->packets_resent += ret;

                if ((unsigned int) ret < conn->packets_left) {
                    conn->packets_left -= ret;
                } else {
                    conn->last_congestion_event = temp_time;
                    conn->packets_left = 0;
                }
            }

            if (conn->packet_send_rate > CRYPTO_PACKET_MIN_RATE * 1.5) {
                total_send_rate += conn->packet_send_rate;
            }
        }
    }

    c->current_sleep_time = -1;
    uint32_t sleep_time = peak_request_packet_interval;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }

    if (total_send_rate > CRYPTO_PACKET_MIN_RATE) {
        sleep_time = (1000.0 / total_send_rate);

        if (c->current_sleep_time > sleep_time) {
            c->current_sleep_time = sleep_time + 1;
        }
    }

    sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }
}

/* Return 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * Return 0 if it wasn't reached.
 */
bool max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    return reset_max_speed_reached(c, crypt_connection_id) != 0;
}

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(const Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return 0;
    }

    uint32_t max_packets = CRYPTO_PACKET_BUFFER_SIZE - num_packets_array(&conn->send_array);

    if (conn->packets_left < max_packets) {
        return conn->packets_left;
    }

    return max_packets;
}

/* Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * The first byte of data must in the PACKET_ID_RANGE_LOSSLESS.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t write_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                          uint8_t congestion_control)
{
    if (length == 0) {
        return -1;
    }

    if (data[0] < PACKET_ID_RANGE_LOSSLESS_START || data[0] > PACKET_ID_RANGE_LOSSLESS_END) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (conn->status != CRYPTO_CONN_ESTABLISHED) {
        return -1;
    }

    if (congestion_control && conn->packets_left == 0) {
        return -1;
    }

    int64_t ret = send_lossless_packet(c, crypt_connection_id, data, length, congestion_control);

    if (ret == -1) {
        return -1;
    }

    if (congestion_control) {
        --conn->packets_left;
        --conn->packets_left_requested;
        ++conn->packets_sent;
    }

    return ret;
}

/* Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * Note: The condition `buffer_end - buffer_start < packet_number - buffer_start` is
 * a trick which handles situations `buffer_end >= buffer_start` and
 * `buffer_end < buffer_start` (when buffer_end overflowed) both correctly.
 *
 * It CANNOT be simplified to `packet_number < buffer_start`, as it will fail
 * when `buffer_end < buffer_start`.
 */
int cryptpacket_received(Net_Crypto *c, int crypt_connection_id, uint32_t packet_number)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint32_t num = num_packets_array(&conn->send_array);
    uint32_t num1 = packet_number - conn->send_array.buffer_start;

    if (num >= num1) {
        return -1;
    }

    return 0;
}

/* Sends a lossy cryptopacket.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * The first byte of data must in the PACKET_ID_RANGE_LOSSY.
 */
int send_lossy_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -1;
    }

    if (data[0] < PACKET_ID_RANGE_LOSSY_START || data[0] > PACKET_ID_RANGE_LOSSY_END) {
        return -1;
    }

    pthread_mutex_lock(&c->connections_mutex);
    ++c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    int ret = -1;

    if (conn) {
        pthread_mutex_lock(conn->mutex);
        uint32_t buffer_start = conn->recv_array.buffer_start;
        uint32_t buffer_end = conn->send_array.buffer_end;
        pthread_mutex_unlock(conn->mutex);
        ret = send_data_packet_helper(c, crypt_connection_id, buffer_start, buffer_end, data, length);
    }

    pthread_mutex_lock(&c->connections_mutex);
    --c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    return ret;
}

/* Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    int ret = -1;

    if (conn) {
        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            send_kill_packet(c, crypt_connection_id);
        }

        pthread_mutex_lock(&c->tcp_mutex);
        kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
        pthread_mutex_unlock(&c->tcp_mutex);

        bs_list_remove(&c->ip_port_list, (uint8_t *) &conn->ip_portv4, crypt_connection_id);
        bs_list_remove(&c->ip_port_list, (uint8_t *) &conn->ip_portv6, crypt_connection_id);
        clear_temp_packet(c, crypt_connection_id);
        clear_buffer(&conn->send_array);
        clear_buffer(&conn->recv_array);
        //AKE NEW TODO: Verify if this is ok; freeing Noise CipherState memory
        noise_cipherstate_free(conn->send_cipher);
        noise_cipherstate_free(conn->recv_cipher);
        ret = wipe_crypto_connection(c, crypt_connection_id);
    }

    return ret;
}

bool crypto_connection_status(const Net_Crypto *c, int crypt_connection_id, bool *direct_connected,
                              unsigned int *online_tcp_relays)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return false;
    }

    if (direct_connected) {
        *direct_connected = 0;

        const uint64_t current_time = mono_time_get(c->mono_time);

        if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time) {
            *direct_connected = 1;
        }

        if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time) {
            *direct_connected = 1;
        }
    }

    if (online_tcp_relays) {
        *online_tcp_relays = tcp_connection_to_online_tcp_relays(c->tcp_c, conn->connection_number_tcp);
    }

    return true;
}

void new_keys(Net_Crypto *c)
{
    crypto_new_keypair(c->self_public_key, c->self_secret_key);
}

/* Save the public and private keys to the keys array.
 * Length must be CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE.
 *
 * TODO(irungentoo): Save only secret key.
 */
void save_keys(const Net_Crypto *c, uint8_t *keys)
{
    memcpy(keys, c->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, c->self_secret_key, CRYPTO_SECRET_KEY_SIZE);
}

/* Load the secret key.
 * Length must be CRYPTO_SECRET_KEY_SIZE.
 */
void load_secret_key(Net_Crypto *c, const uint8_t *sk)
{
    memcpy(c->self_secret_key, sk, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(c->self_public_key, c->self_secret_key);
}

/* Run this to (re)initialize net_crypto.
 * Sets all the global connection variables to their default values.
 */
// AKE: important function for every part of the handshake besides cookie request
Net_Crypto *new_net_crypto(const Logger *log, Mono_Time *mono_time, DHT *dht, TCP_Proxy_Info *proxy_info)
{
    if (dht == nullptr) {
        return nullptr;
    }

    Net_Crypto *temp = (Net_Crypto *) calloc(1, sizeof(Net_Crypto));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->log = log;
    temp->mono_time = mono_time;

    temp->tcp_c = new_tcp_connections(mono_time, dht_get_self_secret_key(dht), proxy_info);

    if (temp->tcp_c == nullptr) {
        free(temp);
        return nullptr;
    }

    // AKE: callback for TCP data packets
    set_packet_tcp_connection_callback(temp->tcp_c, &tcp_data_callback, temp);
    // AKE: callback for TCP onion packets
    set_oob_packet_tcp_connection_callback(temp->tcp_c, &tcp_oob_callback, temp);

    if (create_recursive_mutex(&temp->tcp_mutex) != 0 ||
            pthread_mutex_init(&temp->connections_mutex, nullptr) != 0) {
        kill_tcp_connections(temp->tcp_c);
        free(temp);
        return nullptr;
    }

    temp->dht = dht;

    // AKE: there is a new public/private key pair generated and set. Therefore this should only be called once initially
    new_keys(temp);
    new_symmetric_key(temp->secret_symmetric_key);

    temp->current_sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    // AKE: registering UDP packet handlers
    networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_HS, &udp_handle_packet, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_DATA, &udp_handle_packet, temp);

    bs_list_init(&temp->ip_port_list, sizeof(IP_Port), 8);

    return temp;
}
//TODO test
static void kill_timedout(Net_Crypto *c, void *userdata)
{
    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT
                || conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
            if (conn->temp_packet_num_sent < MAX_NUM_SENDPACKET_TRIES) {
                continue;
            }

            connection_kill(c, i, userdata);
        }

#if 0

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            // TODO(irungentoo): add a timeout here?
            do_timeout_here();
        }

#endif
    }
}

/* return the optimal interval in ms for running do_net_crypto.
 */
uint32_t crypto_run_interval(const Net_Crypto *c)
{
    return c->current_sleep_time;
}

/* Main loop. */
void do_net_crypto(Net_Crypto *c, void *userdata)
{
    kill_timedout(c, userdata);
    do_tcp(c, userdata);
    send_crypto_packets(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    pthread_mutex_destroy(&c->tcp_mutex);
    pthread_mutex_destroy(&c->connections_mutex);

    kill_tcp_connections(c->tcp_c);
    bs_list_free(&c->ip_port_list);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_COOKIE_REQUEST, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_COOKIE_RESPONSE, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_CRYPTO_HS, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_CRYPTO_DATA, nullptr, nullptr);
    crypto_memzero(c, sizeof(Net_Crypto));
    free(c);
}
