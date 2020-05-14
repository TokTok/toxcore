# Tox handshake/Authenticated Key Exchange (AKE)

**Disclaimer**: only functions calls with relevant acitivity for the handshake (or crypto operations)

**Open questions/points**: are marked with a TODO in this document.

**Call flow was rebuilt (mostly) by using Eclipse' "Open Call Hierarchy" built-in feature.**

**Comments added to net_crypto.c are prefixed with "AKE:"**

## Handshake description from Tox specification:

In this section I added all information from the Tox specification I deemed relevant for understanding the Tox handshake/AKE. Some information I deemed important is bold, also I added some comments (search for "Comment").

**Tox Specification:**

- https://github.com/TokTok/spec/blob/master/spec.md
- https://toktok.ltd/spec.html

### Section: Goals

-   **Authentication:** Tox aims to provide authenticated communication. This
    means that during a communication session, both parties can be sure of the
    other party's identity. Users are identified by their public key. The
    initial key exchange is currently not in scope for the Tox protocol. In the
    future, Tox may provide a means for initial authentication using a
    challenge/response or shared secret based exchange.

    If the secret key is compromised, the user's identity is compromised, and
    an attacker can impersonate that user. When this happens, the user must
    create a new identity with a new public key.

-   **End-to-end encryption:** The Tox protocol establishes end-to-end
    encrypted communication links. Shared keys are deterministically derived
    using a Diffie-Hellman-like method, so keys are never transferred over the
    network.

-   **Forward secrecy**: Session keys are re-negotiated when the peer
    connection is established.

-   **Privacy**: When Tox establishes a communication link, it aims to avoid
    leaking to any third party the identities of the parties involved (i.e.
    their public keys).

    Furthermore, it aims to avoid allowing third parties to determine the IP
    address of a given user.
    
-   **Resilience:**

    -   Independence of infrastructure: Tox avoids relying on servers as much
        as possible. Communications are not transmitted via or stored on
        central servers. Joining a Tox network requires connecting to a
        well-known node called a bootstrap node. Anyone can run a bootstrap
        node, and users need not put any trust in them.

    -   Tox tries to establish communication paths in difficult network
        situations. This includes connecting to peers behind a NAT or firewall.
        Various techniques help achieve this, such as UDP hole-punching, UPnP,
        NAT-PMP, other untrusted nodes acting as relays, and DNS tunnels.

    -   Resistance to basic denial of service attacks: short timeouts make the
        network dynamic and resilient against poisoning attempts.

-   **Minimum configuration:** Tox aims to be nearly zero-conf.
    User-friendliness is an important aspect to security. Tox aims to make
    security easy to achieve for average users.

### Section: Non-goals

-   **Anonymity** is not in scope for the Tox protocol itself, but it provides
    an easy way to integrate with software providing anonymity, such as Tor.

    By default, Tox tries to establish direct connections between peers; as a
    consequence, each is aware of the other's IP address, and third parties may
    be able to determine that a connection has been established between those
    IP addresses. One of the reasons for making direct connections is that
    relaying real-time multimedia conversations over anonymity networks is not
    feasible with the current network infrastructure.

### Section: Integers

The protocol uses four bounded unsigned integer types. Bounded means they have
an upper bound beyond which incrementing is not defined. The integer types
support modular arithmetic, so overflow wraps around to zero. Unsigned means
their lower bound is 0. Signed integer types are not used. The binary encoding
of all integer types is a fixed-width byte sequence with the integer encoded in
[Big Endian](https://en.wikipedia.org/wiki/Endianness) unless stated otherwise.

| Type name | C type     | Length | Upper bound                               |
|:----------|:-----------|:-------|:------------------------------------------|
| Word8     | `uint8_t`  | 1      | 255 (0xff)                                |
| Word16    | `uint16_t` | 2      | 65535 (0xffff)                            |
| Word32    | `uint32_t` | 4      | 4294967295 (0xffffffff)                   |
| Word64    | `uint64_t` | 8      | 18446744073709551615 (0xffffffffffffffff) |

### Section: Crypto

The Crypto module contains all the functions and data types related to
cryptography. This includes random number generation, encryption and
decryption, key generation, operations on nonces and generating random nonces.

#### Key

A Crypto Number is a large fixed size unsigned (non-negative) integer. Its
binary encoding is as a Big Endian integer in exactly the encoded byte size.
Its human-readable encoding is as a base-16 number encoded as String. The NaCl
implementation [libsodium](https://github.com/jedisct1/libsodium) supplies the
functions `sodium_bin2hex` and `sodium_hex2bin` to aid in implementing the
human-readable encoding. The in-memory encoding of these crypto numbers in NaCl
already satisfies the binary encoding, so for applications directly using those
APIs, binary encoding and decoding is the [identity
function](https://en.wikipedia.org/wiki/Identity_function).

Tox uses four kinds of Crypto Numbers:

| Type         | Bits | Encoded byte size |
|:-------------|:-----|:------------------|
| Public Key   | 256  | 32                |
| Secret Key   | 256  | 32                |
| Combined Key | 256  | 32                |
| Nonce        | 192  | 24                |

#### Key Pair

A Key Pair is a pair of Secret Key and Public Key. A new key pair is generated
using the `crypto_box_keypair` function of the NaCl crypto library. Two
separate calls to the key pair generation function must return distinct key
pairs. See the [NaCl documentation](https://nacl.cr.yp.to/box.html) for
details.

A Public Key can be computed from a Secret Key using the NaCl function
`crypto_scalarmult_base`, which computes the scalar product of a standard group
element and the Secret Key. See the [NaCl
documentation](https://nacl.cr.yp.to/scalarmult.html) for details.

#### Combined Key

=> **Comment:** In Tox/net_crypto.c it is called shared key `uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]` which is defined in struct `Crypto_connection` in net_crypto.c.

A Combined Key is computed from a Secret Key and a Public Key using the NaCl
function `crypto_box_beforenm`. Given two Key Pairs KP1 (SK1, PK1) and KP2
(SK2, PK2), the Combined Key computed from (SK1, PK2) equals the one computed
from (SK2, PK1). This allows for symmetric encryption, as peers can derive the
same shared key from their own secret key and their peer's public key.

In the Tox protocol, packets are encrypted using the public key of the receiver
and the secret key of the sender. The receiver decrypts the packets using the
receiver's secret key and the sender's public key.

The fact that the same key is used to encrypt and decrypt packets on both sides
means that packets being sent could be replayed back to the sender if there is
nothing to prevent it.

The shared key generation is the most resource intensive part of the
encryption/decryption which means that resource usage can be reduced
considerably by saving the shared keys and reusing them later as much as
possible.

#### Nonce

A random nonce is generated using the cryptographically secure random number
generator from the NaCl library `randombytes`.

A nonce is incremented by interpreting it as a Big Endian number and adding 1.
If the nonce has the maximum value, the value after the increment is 0.

Most parts of the protocol use random nonces. This prevents new nonces from
being associated with previous nonces. If many different packets could be tied
together due to how the nonces were generated, it might for example lead to
tying DHT and onion announce packets together. This would introduce a flaw in
the system as non friends could tie some people's DHT keys and long term keys
together.

### Section: Box

The encryption function takes a Combined Key, a Nonce, and a Plain Text, and
returns a Cipher Text. It uses `crypto_box_afternm` to perform the encryption.
The meaning of the sentence "encrypting with a secret key, a public key, and a
nonce" is: compute a combined key from the secret key and the public key and
then use the encryption function for the transformation.

The decryption function takes a Combined Key, a Nonce, and a Cipher Text, and
returns either a Plain Text or an error. It uses `crypto_box_open_afternm` from
the NaCl library. Since the cipher is symmetric, the encryption function can
also perform decryption, but will not perform message authentication, so the
implementation must be careful to use the correct functions.

`crypto_box` uses xsalsa20 symmetric encryption and poly1305 authentication.

### Section: Protocol packet

A Protocol Packet is the top level Tox protocol element. All other packet types
are wrapped in Protocol Packets. It consists of a Packet Kind and a payload.
The binary representation of a Packet Kind is a single byte (8 bits). The
payload is an arbitrary sequence of bytes.

| Length | Type        | Contents                   |
|:-------|:------------|:---------------------------|
| `1`    | Packet Kind | The packet kind identifier |
| `[0,]` | Bytes       | Payload                    |

These top level packets can be transported in a number of ways, the most common
way being over the network using UDP or TCP. The protocol itself does not
prescribe transport methods, and an implementation is free to implement
additional transports such as WebRTC, IRC, or pipes.

Inside Protocol Packets payload, other packet types can specify additional
packet kinds. E.g. inside a Crypto Data packet (`0x1b`), the
Messenger module defines its protocols for messaging, file
transfers, etc. Top level Protocol Packets are themselves not encrypted, though
their payload may be.

#### Packet Kinds (relevant for the handshake)

| Byte value | Packet Kind         |
|:-----------|:--------------------|
| `0x18`     | Cookie Request      |
| `0x19`     | Cookie Response     |
| `0x1a`     | Crypto Handshake    |
| `0x1b`     | Crypto Data         |

### Section: TCP Client + TCP Server

**Comment:** TCP Client+Server stuff is no "real" handshake -> TCP Client/Server stuff has it's own handshake and is therefore out of scope. The shared session keys are generated in TCP_client.c+TCP_server.c and not in net_crypto.c.

### Section: Friend connection

`friend_connection` is the module that sits on top of the DHT, onion and
`net_crypto` modules and takes care of linking the 3 together.

Friends in `friend_connection` are represented by their real public key. When a
friend is added in `friend_connection`, an onion search entry is created for
that friend. This means that the onion module will start looking for this
friend and send that friend their DHT public key, and the TCP relays it is
connected to, in case a connection is only possible with TCP.

**Comment: Important!**
Once the onion returns the DHT public key of the peer, the DHT public key is
saved, added to the DHT friends list and a new `net_crypto` connection is
created. Any TCP relays returned by the onion for this friend are passed to the
`net_crypto` connection.

If the DHT establishes a direct UDP connection with the friend,
`friend_connection` will pass the IP/port of the friend to `net_crypto` and
also save it to be used to reconnect to the friend if they disconnect.

**Comment: On DHT key change the net_crypto connection will be klled a new one with the correct DHT public key created!**
If `net_crypto` finds that the friend has a different DHT public key, which can
happen if the friend restarted their client, `net_crypto` will pass the new DHT
public key to the onion module and will remove the DHT entry for the old DHT
public key and replace it with the new one. The current `net_crypto` connection
will also be killed and a new one with the correct DHT public key will be
created.

=> **Comment:** Ok this is not `kill_net_crypto()`, but `connection_kill()` which is triggered in this case by `handle_new_connection_handshake()`

When the `net_crypto` connection for a friend goes online, `friend_connection`
will tell the onion module that the friend is online so that it can stop
spending resources looking for the friend. When the friend connection goes
offline, `friend_connection` will tell the onion module so that it can start
looking for the friend again.

There are 2 types of data packets sent to friends with the `net_crypto`
connection handled at the level of `friend_connection`, Alive packets and TCP
relay packets. Alive packets are packets with the packet id or first byte of
data (only byte in this packet) being 16. They are used in order to check if
the other friend is still online. `net_crypto` does not have any timeout when
the connection is established so timeouts are caught using this packet. In
toxcore, this packet is sent every 8 seconds. If none of these packets are
received for 32 seconds, the connection is timed out and killed. These numbers
seem to cause the least issues and 32 seconds is not too long so that, if a
friend times out, toxcore won't falsely see them online for too long. Usually
when a friend goes offline they have time to send a disconnect packet in the
`net_crypto` connection which makes them appear offline almost instantly.

`friend_connection` sends a list of 3 relays (the same number as the target
number of TCP relay connections in `TCP_connections`) to each connected friend
every 5 minutes in toxcore. Immediately before sending the relays, they are
associated to the current `net_crypto->TCP_connections` connection. This
facilitates connecting the two friends together using the relays as the friend
who receives the packet will associate the sent relays to the `net_crypto`
connection they received it from. When both sides do this they will be able to
connect to each other using the relays. The packet id or first byte of the
packet of share relay packets is 0x11. This is then followed by some TCP relays
stored in packed node format.

For all other data packets, are passed by `friend_connection` up to the upper
Messenger module. It also separates lossy and lossless packets from
`net_crypto`.

**Comment: Important!**
**Friend connection takes care of establishing the connection to the friend and
gives the upper messenger layer a simple interface to receive and send
messages, add and remove friends and know if a friend is connected (online) or
not connected (offline).**

### Section: Net Crypto (Comment: most important sections!)

The Tox transport protocol is what Tox uses to establish and send data securely
to friends and provides encryption, ordered delivery, and perfect forward
secrecy. It is a UDP protocol but it is also used when 2 friends connect over
TCP relays.

Before sending the actual handshake packet the peer must obtain a cookie. This cookie step serves as a way for the receiving peer to confirm that the peer initiating the connection can receive the responses in order to prevent certain types of DoS attacks.

The peer receiving a cookie request packet must not allocate any resources to the connection. They will simply respond to the packet with a cookie response packet containing the cookie that the requesting peer must then use in the handshake to initiate the actual connection.

The cookie response must be sent back using the exact same link the cookie
request packet was sent from. The reason for this is that if it is sent back
using another link, the other link might not work and the peer will not be
expecting responses from another link. For example, if a request is sent from
UDP with ip port X, it must be sent back by UDP to ip port X. If it was
received from a TCP OOB packet it must be sent back by a TCP OOB packet via the
same relay with the destination being the peer who sent the request. If it was
received from an established TCP relay connection it must be sent back via that
same exact connection.

When a cookie request is received, the peer must not use the information in the request packet for anything, he must not store it, he must only create a cookie and cookie response from it, then send the created cookie response packet and forget them. The reason for this is to prevent possible attacks. For example if a peer would allocate long term memory for each cookie request packet received then a simple packet flood would be enough to achieve an effective denial of service attack by making the program run out of memory.

#### Cookie request packet (145 bytes):

    [uint8_t 24]
    [Sender's DHT Public key (32 bytes)]
    [Random nonce (24 bytes)]
    [Encrypted message containing:
        [Sender's real public key (32 bytes)]
        [padding (32 bytes)]
        [uint64_t echo id (must be sent back untouched in cookie response)]
    ]


Encrypted message is encrypted with sender's DHT private key, receiver's DHT
public key and the nonce.

The packet id for cookie request packets is 24. The request contains the DHT
public key of the sender which is the key used (The DHT private key) (along
with the DHT public key of the receiver) to encrypt the encrypted part of the
cookie packet and a nonce also used to encrypt the encrypted part of the
packet. Padding is used to maintain backwards-compatibility with previous
versions of the protocol. The echo id in the cookie request must be sent back
untouched in the cookie response. This echo id is how the peer sending the
request can be sure that the response received was a response to the packet
that he sent.

The reason for sending the DHT public key and real public key in the cookie
request is that both are contained in the cookie sent back in the response.

Toxcore currently sends 1 cookie request packet every second 8 times before it kills the connection if there are no responses.

#### Cookie response packet (161 bytes):

    [uint8_t 25]
    [Random nonce (24 bytes)]
    [Encrypted message containing:
        [Cookie]
        [uint64_t echo id (that was sent in the request)]
    ]

Encrypted message is encrypted with the exact same symmetric key as the cookie
request packet it responds to but with a different nonce.

The packet id for cookie request packets is 25. The response contains a nonce
and an encrypted part encrypted with the nonce. The encrypted part is encrypted
with the same key used to decrypt the encrypted part of the request meaning the
expensive shared key generation needs to be called only once in order to handle
and respond to a cookie request packet with a cookie response.

The Cookie (see below) and the echo id that was sent in the request are the
contents of the encrypted part.

#### The Cookie should be (112 bytes):

    [nonce]
    [encrypted data:
        [uint64_t time]
        [Sender's real public key (32 bytes)]
        [Sender's DHT public key (32 bytes)]
    ]

The cookie is a 112 byte piece of data that is created and sent to the
requester as part of the cookie response packet. A peer who wants to connect to
another must obtain a cookie packet from the peer they are trying to connect
to. The only way to send a valid handshake packet to another peer is to first
obtain a cookie from them.

The cookie contains information that will both prove to the receiver of the
handshake that the peer has received a cookie response and contains encrypted
info that tell the receiver of the handshake packet enough info to both decrypt
and validate the handshake packet and accept the connection.

When toxcore is started it generates a symmetric encryption key that it uses to
encrypt and decrypt all cookie packets (using NaCl authenticated encryption
exactly like encryption everywhere else in toxcore). Only the instance of
toxcore that create the packets knows the encryption key meaning any cookie it
successfully decrypts and validates were created by it.

The time variable in the cookie is used to prevent cookie packets that are too
old from being used. Toxcore has a time out of 15 seconds for cookie packets.
If a cookie packet is used more than 15 seconds after it is created toxcore
will see it as invalid.

When responding to a cookie request packet the sender's real public key is the
known key sent by the peer in the encrypted part of the cookie request packet
and the senders DHT public key is the key used to encrypt the encrypted part of
the cookie request packet.

When generating a cookie to put inside the encrypted part of the handshake: One
of the requirements to connect successfully to someone else is that we know
their DHT public key and their real long term public key meaning there is
enough information to construct the cookie.

#### Handshake packet:

    [uint8_t 26]
    [Cookie]
    [nonce (24 bytes)]
    [Encrypted message containing:
        [24 bytes base nonce]
        [session public key of the peer (32 bytes)]
        [sha512 hash of the entire Cookie sitting outside the encrypted part]
        [Other Cookie (used by the other to respond to the handshake packet)]
    ]

The packet id for handshake packets is 26. The cookie is a cookie obtained by sending a cookie request packet to the peer and getting a cookie response packet with a cookie in it. **It may also be obtained in the handshake packet by a peer receiving a handshake packet (Other Cookie).**

The nonce is a nonce used to encrypt the encrypted part of the handshake packet. **The encrypted part of the handshake packet is encrypted with the long term keys of both peers. This is to prevent impersonation.**
=> **Comment:** This is used for authenticating the public session key
	
Inside the encrypted part of the handshake packet there is a 'base nonce' and a
session public key. The 'base nonce' is a nonce that the other should use to
encrypt each data packet, adding + 1 to it for each data packet sent. (first
packet is 'base nonce' + 0, next is 'base nonce' + 1, etc. Note that for
mathematical operations the nonce is considered to be a 24 byte number in big
endian format). The session key is the temporary connection public key that the
peer has generated for this connection and it sending to the other. This
session key is used so that the connection has perfect forward secrecy. It is
important to save the private key counterpart of the session public key sent in
the handshake, the public key received by the other and both the received and
sent base nonces as they are used to encrypt/decrypt the data packets.

The hash of the cookie in the encrypted part is used to make sure that an attacker has not taken an older valid handshake packet and then replaced the cookie packet inside with a newer one which would be bad as they could replay it and might be able to make a mess.

The **'Other Cookie'** is a valid cookie that we put in the handshake so that the
other can respond with a valid handshake without having to make a cookie
request to obtain one.

The handshake packet is sent by both sides of the connection. If a peer receives a handshake it will check if the cookie is valid, if the encrypted section decrypts and validates, if the cookie hash is valid, if long term public key belongs to a known friend. If all these are true then the connection is considered 'Accepted' but not 'Confirmed'.

If there is no existing connection to the peer identified by the long term
public key to set to 'Accepted', one will be created with that status. If a
connection to such peer with a not yet 'Accepted' status to exists, this
connection is set to accepted. If a connection with a 'Confirmed' status exists
for this peer, the handshake packet will be ignored and discarded (The reason
for discarding it is that we do not want slightly late handshake packets to
kill the connection) except if the DHT public key in the cookie contained in
the handshake packet is different from the known DHT public key of the peer. If
this happens the connection will be immediately killed because it means it is
no longer valid and a new connection will be created immediately with the
'Accepted' status.

Sometimes toxcore might receive the DHT public key of the peer first with a handshake packet so it is important that this case is handled and that the implementation passes the DHT public key to the other modules (DHT, TCP_connection) because this does happen.

Handshake packets must be created only once during the connection but must be sent in intervals until we are sure the other received them. This happens when a valid encrypted data packet is received and decrypted.

**The states of a connection:**

1.  Not accepted: Send handshake packets.

2.  Accepted: A handshake packet has been received from the other peer but no
    encrypted packets: continue (or start) sending handshake packets because
    the peer can't know if the other has received them.

3.  Confirmed: A valid encrypted packet has been received from the other peer:
    Connection is fully established: stop sending handshake packets.
    
Toxcore sends handshake packets every second 8 times and times out the
connection if the connection does not get confirmed (no encrypted packet is
received) within this time.

#### Perfect handshake scenario:

```
Peer 1/A                	Peer 2/B
Cookie request   ->
                      		<- Cookie response
Handshake packet ->
                      		*accepts connection*
                      		<- Handshake packet
*accepts connection*
Encrypted packet ->   		<- Encrypted packet
*confirms connection*  		*confirms connection*
       		Connection successful.
Encrypted packets -> 		<- Encrypted packets
```

#### More realistic handshake scenario:

```
Peer 1/A                	Peer 2/B
Cookie request   ->   		*packet lost*
Cookie request   ->
                      		<- Cookie response
                      		*Peer 2 randomly starts new connection to peer 1*
                      		<- Cookie request
Cookie response  ->
Handshake packet ->   		<- Handshake packet
*accepts connection*   		*accepts connection*
Encrypted packet ->   		<- Encrypted packet
*confirms connection*  		*confirms connection*
       		Connection successful.
Encrypted packets -> 		<- Encrypted packets
```

**The reason why the handshake is like this is because of certain design requirements:**

1.  The handshake must not leak the long term public keys of the peers to a
    possible attacker who would be looking at the packets but each peer must
    know for sure that they are connecting to the right peer and not an
    impostor.

2.  A connection must be able of being established if only one of the peers has
    the information necessary to initiate a connection (DHT public key of the
    peer and a link to the peer).

3.  If both peers initiate a connection to each other at the same time the
    connection must succeed without issues.

4.  There must be perfect forward secrecy.

5.  Must be resistant to any possible attacks.

Due to how it is designed only one connection is possible at a time between 2
peers.

#### Encrypted packets:

| Length   | Contents                                                      |
|:---------|:--------------------------------------------------------------|
| `1`      | `uint8_t` (0x1b)                                              |
| `2`      | `uint16_t` The last 2 bytes of the nonce used to encrypt this |
| variable |  Payload                                                      |

The payload is encrypted with the session key and 'base nonce' set by the
receiver in their handshake + packet number (starting at 0, big endian math).

The packet id for encrypted packets is 27. Encrypted packets are the packets
used to send data to the other peer in the connection. Since these packets can
be sent over UDP the implementation must assume that they can arrive out of
order or even not arrive at all.

To get the key used to encrypt/decrypt each packet in the connection a peer
takes the session public key received in the handshake and the private key
counterpart of the key it sent it the handshake and generates a shared key from
it. This shared key will be identical for both peers. It is important to note
that connection keys must be wiped when the connection is killed.

To create an encrypted packet to be sent to the other peer, the data is
encrypted with the shared key for this connection and the base nonce that the
other peer sent in the handshake packet with the total number of encrypted
packets sent in the connection added to it ('base nonce' + 0 for the first
encrypted data packet sent, 'base nonce' + 1 for the second, etc. Note that the
nonce is treated as a big endian number for mathematical operations like
additions). The 2 byte (`uint16_t`) number at the beginning of the encrypted
packet is the last 2 bytes of this 24 byte nonce.

To decrypt a received encrypted packet, the nonce the packet was encrypted with
is calculated using the base nonce that the peer sent to the other and the 2
byte number at the beginning of the packet. First we assume that packets will
most likely arrive out of order and that some will be lost but that packet loss
and out of orderness will never be enough to make the 2 byte number need an
extra byte. The packet is decrypted using the shared key for the connection and
the calculated nonce.

## Callbacks

**Comment:** Added this section because I didn't really know about callbacks when I started to work through the code to identify the handshake/AKE relevant parts.

Source: https://www.enlightenment.org/docs/c/start:

Callbacks are simply a formal way of naming a function pointer to be called back at another point. This is used commonly among software like GUI toolkits for useful behavior handling, such as when someone “clicks” a button, or when a window resizes, or a slider changes value etc. It literally is saying “When X happens, call function Y”. For example: 

```c=
static void
win_del(void *data, Evas_Object *obj, void *event_info)
{
   elm_exit();
}
 
// ...
 
Evas_Object *win;
 
win = elm_win_add(NULL, "tst", ELM_WIN_BASIC);
evas_object_smart_callback_add(win, "delete,request", win_del, NULL);
```

In this example, the code creates a new window and then adds a callback to the object to be called on the “delete,request” event. The function to call whenever this happens is the win_del function. This function simple calls another function that triggers an exit. Callbacks will keep being be called whenever such an event happens until they are deleted and/or unregistered.

In most cases such callbacks for a GUI toolkit will be called from the main loop function. This main loop will process events and eventually when an event does end up being one that asks to delete a window, then the logic code in the toolkit that figures this out will end up calling all callbacks registered for this event.

Callbacks are a very simple, yet very powerful concept. It is important to understand them and be comfortable with them once you write less trivial C code.

=> **Comment: Main loop function in Tox => tox_iterate()-> do_messenger()**

### network.txt (from Tox spec)

=> **Comment:** This is the part of Tox that is responsible for the callbacks to handle the packets. 

The network module is the lowest file in toxcore that everything else depends on. This module is basically a UDP socket wrapper, serves as the sorting ground for packets received by the socket, initializes and uninitializes the socket. It also contains many socket, networking related and some other functions like a monotonic time function used by other toxcore modules.

Things of note in this module are the maximum UDP packet size define (MAX_UDP_PACKET_SIZE) which sets the maximum UDP packet size toxcore can send and receive. The **list of all UDP packet ids**: **NET_PACKET_**. **UDP packet ids are the value of the first byte of each UDP packet** and is how each packet gets sorted to the right module that can handle it. **networking_registerhandler()** is used by higher level modules in order to tell the network object which packets to send to which module via a callback.

Since the network module interacts directly with the underlying operating system with its socket functions it has code to make it work on windows, linux, etc... unlike most modules that sit at a higher level.

The network module currently uses the polling method to read from the UDP socket. **The networking_poll() function is called to read all the packets from the socket and pass them to the callbacks set using the networking_registerhandler() function**. The reason it uses polling is simply because it was easier to write it that way, another method would be better here.

The goal of this module is to provide an easy interface to a UDP socket and other networking related functions.

## Infos from IRC `#toktok`

### TCP IRC infos:

- there's nothing distributed about a friend_connection, it's just direct or going via tcp relays
- 17:15 <+tb> tcp relays = bootstrap nodes? (**Comment**)
	- no, though there's a big overlap
	- then i maybe finally able to solve the mystery if TCP relays exists outside of the bootstrap nodes
		- that are actually used
		- connected dht nodes and tcp relays are stored in the savedata

### IRC communication regarding how cookie response is triggered:

- 10:29:08 <+tb> Is new_net_crypto() only called on the "initial" startup or at every startup? Since there are is new crypto key pair generated IMHO this should only be calle once. But it also calls networking_registerhandler() which confuses me.
	- tb: that gets called exactly once per tox instance
	- there is one Net_Crypto per tox instance
	- 18:47:22 <+tb> iphy: zugz_: if this gets only called once per tox instance, does that mean that the networking_registerhandler() is (needs to be) persisted? because this is triggering the handshake related functions, that's why I'm asking
	- 18:50:42 <+tb> iphy: asked differently, I want to know how e.g. udp_handle_cookie_request() is called, if new_net_crypto() is only called once
		- yes, registering a handler makes the network layer pass packets to that handler whenever it gets one with that packet id
		- handler registrations are permament (per instance)
		- 19:07:45 <+tb> iphy: what does permanent mean in this case? i.e. toxccore stuff is only RAM IIUC
			- it goes away when the tox instance goes out of scope
			- (i.e. tox_kill)
		- 19:12:29 <+tb> iphy: mhm, but would that mean that everything that wasn't saved on disk is lost afterwards? or do I completely misunderstand something here?
		- but yes, your understanding is correct
		- everything that isn't stored on disk is lost when a process terminates
		- 19:13:27 <+tb> the static key pair most importantly
			- the key pair is stored on disk
			- only the secret key is stored, actually
			- because the public key can be computed from it
		- 19:21 <+tb> <@iphy> tb: there is a function to produce a sequence of bytes that represent the persistent state <- that's what I meant	
			- yes, tox_get_savedata
			- **Comment**: `tox_get_savedata()` saves the messenger "object" which also includes the net_crypto "object". Network handlers are persisted this way and can be reloaded. Therefore the handshake functions still get called (without a need to call new_net_crypto() again). 
		- 19:23 <+tb> ok, so one last question (at least for now ;) -> if I persist it that way and load it again, the network handling stuff is also there again?
			- yes
		- maybe you should read tox_new
			- **Comment:** In tox_new() it's possible to provide Tox_options which enable the loading of a saved secret key and also load Tox saved data (incl. messenger "object" which include the net_crypto "object")

## Call Flow for "Perfect handshake scenario"

### Peer A/Handshake initiator: This for outgoing/initiating of a handshake (Cookie request)

A peer starts/initiates a handshake by calling `create_cookie_request()`.

=> new_crypto_connection() resp. create_cookie_request() gets called regularly via tox_iterate() or via dht_pk_callback() (i.e. DHT public key of friend changes) or via dht_ip_callback() (i.e. IP/Port of friend changes) (see create_cookie_request() call hierarchy below).
=> Additionally it is called via DHT ip/pk callbacks.

From tox.h: 

- A common way to run Tox (multiple or single instance) is to have one thread running a simple tox_iterate loop, sleeping for tox_iteration_interval milliseconds on each iteration.
- The main loop that needs to be run in intervals of tox_iteration_interval() milliseconds.

From c-toxcore/README.md:

- Toxcore works with a main event loop function tox_iterate that you need to call at a certain frequency dictated by tox_iteration_interval. This is a polling function that receives new network messages and processes them.
- => tox_iterate() is called in the main event loop at a certain frequency (see above)
- => do_messenger() gets called 20 times per second. Next call of do_messenger() calls net_crypto.c:do_net_crypto() which calls net_crypto.c:send_crypto_packets() which sends out all Crypto conn temp_packets! Therefore also all cookie request packets!

```
tox.c: tox_iterate()
	-> Messenger.c: do_messenger()
		-> friend_connection.c: do_friend_connections()
			-> friend_connection.c: friend_new_connection() // Spec: Once the onion returns the DHT public key of the peer, the DHT public key is saved, added to the DHT friends list and a new net_crypto connection is created. Any TCP relays returned by the onion for this friend are passed to the net_crypto connection.
				-> net_crypto.c: new_crypto_connection()		// set Crypto conn status = CRYPTO_CONN_COOKIE_REQUESTING
					-> net_crypto.c: getcryptconnection_id()
					-> net_crypto.c: create_crypto_connection()
					-> net_crypto.c: new_tcp_connection_to()
					-> crypto_core.c: random_nonce()
					-> crypto_core.c: crypto_new_keypair()		// session public/private key pair generation
					-> net_crypto.c: create_cookie_request()		// set NET_PACKET_COOKIE_REQUEST
						-> DHT.c: `dht_get_shared_key_sent()` 		// shared key in case of cookie request is calculated by using initiators DHT secret key and receivers DHT public key
						-> crypto_core.c: `random_nonce()`
						-> DHT.c: `dht_get_self_public_key()`
						-> crypto_core.c: `encrypt_data_symmetric()`
					-> net_crypto.c: new_temp_packet()
				<- return crypt_connection_id
			<- return	
			-> friend_connection.c: set_direct_ip_port()
			-> friend_connection.c: connect_to_saved_tcp_relays()
		<- void	
	<- void
<- void		
```

#### Eclipse Call Hierarchy for create_cookie_request():

```
create_cookie_request(const Net_Crypto *, uint8_t *, uint8_t *, uint64_t, uint8_t *) : int
	new_crypto_connection(Net_Crypto *, const uint8_t *, const uint8_t *) : int
		friend_new_connection(Friend_Connections *, int) : int
			dht_ip_callback(void *, int32_t, IP_Port) : void
				change_dht_pk(Friend_Connections *, int, const uint8_t *) : void
			dht_pk_callback(void *, int32_t, const uint8_t *, void *) : void
				friend_new_connection(Friend_Connections *, int) : int
				handle_new_connections(void *, New_Connection *) : int
					new_friend_connections(const Mono_Time *, Onion_Client *, _Bool) : Friend_Connections *
						new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
							main(int, char * *) : int
							main(int, char * *) : int
							tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
				new_friend_connection(Friend_Connections *, const uint8_t *) : int
					add_closest_connections(Group_Chats *, uint32_t, void *) : void
					init_new_friend(Messenger *, const uint8_t *, uint8_t) : int32_t
						m_addfriend_norequest(Messenger *, const uint8_t *) : int32_t
							friends_list_load(Messenger *, const uint8_t *, uint32_t) : State_Load_Status
							main(int, char * *) : int
							print_request(Messenger *, const uint8_t *, const uint8_t *, size_t, void *) : void
							tox_friend_add_norequest(Tox *, const uint8_t *, Tox_Err_Friend_Add *) : uint32_t
						m_addfriend(Messenger *, const uint8_t *, const uint8_t *, uint16_t) : int32_t
							friends_list_load(Messenger *, const uint8_t *, uint32_t) : State_Load_Status
							main(int, char * *) : int
							test_m_addfriend() : void (4 matches)
							tox_friend_add(Tox *, const uint8_t *, const uint8_t *, size_t, Tox_Err_Friend_Add *) : uint32_t
				set_dht_temp_pk(Friend_Connections *, int, const uint8_t *, void *) : void
			do_friend_connections(Friend_Connections *, void *) : void
				do_messenger(Messenger *, void *) : void
					main(int, char * *) : int
					tox_iterate(Tox *, void *) : void
```

#### Function descriptions from net_crypto.c and comments from myself:

- net_crypto.c: create_cookie_request(): Create a cookie request packet and put it in packet.
	- dht_public_key is the dht public key of the other
	- packet must be of size COOKIE_REQUEST_LENGTH or bigger.
	- return -1 on failure.
	- return COOKIE_REQUEST_LENGTH on success.
- **int new_crypto_connection(Net_Crypto *c, const uint8_t *real_public_key, const uint8_t *dht_public_key)**
	- Create a crypto connection.
	- If one to that real public key already exists, return it.
	- return -1 on failure.
	- return connection id on success.
	- **Comment:** AKE: Peer A initiates a handshake by creating and sending a cookie request

### Peer B/Receiver: This is for incoming/receiving handshakes (Cookie response)

The peer receiving a `NET_PACKET_COOKIE_REQUEST` packet, answers to a cookie request (pre handshake) by calling `create_cookie_response()`. 

- Threre are three possible calls to answer a cookie request (all called via new_net_crypto and new_messenger()) on initialization/startup.   
	- ~~What's with during operation?~~ -> callbacks!
		- There are no direct calls afterwards. Therefore this is triggered through the callbacks if there are packets received.

#### 1. Handle the cookie request packet (for raw UDP)

```
net_crypto.c: udp_handle_cookie_request()		// receives/triggered by NET_PACKET_COOKIE_REQUEST packet
	-> net_crypto.c: handle_cookie_request()
		-> DHT.c: dht_get_shared_key_sent()	// shared key in case of cookie response is calculated by using receivers DHT secret key and initiators DHT public key
		-> crypto_core.c: decrypt_data_symmetric()
	<- return
	-> net_crypto.c: create_cookie_response()		// NET_PACKET_COOKIE_RESPONSE packet as answer to initiator/Peer A
		-> net_crypto.c: create_cookie()
			-> crypto_core.c: random_nonce()
			-> crypto_core.c: encrypt_data_symmetric()
		<- return	
		crypto_core.c:	random_nonce()
		crypto_core.c:	encrypt_data_symmetric()
	<- return
	-> network.c: sendpacket()	
<-
```

**Eclipse Call Hierarchy for udp_handle_cookie_request():**

```
udp_handle_cookie_request(void *, IP_Port, const uint8_t *, uint16_t, void *) : int
	new_net_crypto(const Logger *, Mono_Time *, DHT *, TCP_Proxy_Info *) : Net_Crypto *
		new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
			main(int, char * *) : int
			main(int, char * *) : int
			tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
				main(int, char * *) : int
				make_toxes(const vector<Action,allocator<Action>> &) : Global_State
				tox_new_log_lan(Tox_Options *, Tox_Err_New *, void *, _Bool) : Tox *
		new_onions(uint16_t, uint32_t *) : Onions *
```

#### 2. Handle the cookie request packet (for TCP)

```
net_crypto.c: tcp_oob_handle_cookie_request() 	// receives/triggered by NET_PACKET_COOKIE_REQUEST packet
	-> net_crypto.c: handle_cookie_request()
		-> DHT.c: dht_get_shared_key_sent()	// shared key in case of cookie response is calculated by using receivers DHT secret key and initiators DHT public key
		-> crypto_core.c: decrypt_data_symmetric()
	-> crypto_core.c: public_key_cmp()
	-> net_crypto.c: create_cookie_response()		// NET_PACKET_COOKIE_RESPONSE packet as answer to initiator/Peer A
		-> net_crypto.c: create_cookie()
			-> crypto_core.c: random_nonce()
			-> crypto_core.c: encrypt_data_symmetric()
		<- return	
		crypto_core.c:	random_nonce()
		crypto_core.c:	encrypt_data_symmetric()
	<- return	
	-> TCP_connection: tcp_send_oob_packet()
<-
```

**Eclipse Call Hierarchy for tcp_oob_handle_cookie_request():**

```
tcp_oob_handle_cookie_request(const Net_Crypto *, unsigned int, const uint8_t *, const uint8_t *, uint16_t) : int
	tcp_oob_callback(void *, const uint8_t *, unsigned int, const uint8_t *, uint16_t, void *) : int
		new_net_crypto(const Logger *, Mono_Time *, DHT *, TCP_Proxy_Info *) : Net_Crypto *
			new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
				main(int, char * *) : int
				main(int, char * *) : int
				tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
			new_onions(uint16_t, uint32_t *) : Onions *
```

#### 3. Handle the cookie request packet (for TCP oob packets)

```
net_crypto.c: tcp_handle_cookie_request()		// receives/triggered by NET_PACKET_COOKIE_REQUEST packet
	-> net_crypto.c: handle_cookie_request()
		-> DHT.c: dht_get_shared_key_sent()	// shared key in case of cookie response is calculated by using receivers DHT secret key and initiators DHT public key
		-> crypto_core.c: decrypt_data_symmetric()
	-> net_crypto.c: create_cookie_response()	// NET_PACKET_COOKIE_RESPONSE packet as answer to initiator/Peer A
		-> net_crypto.c: create_cookie()
			-> crypto_core.c: random_nonce()
			-> crypto_core.c: encrypt_data_symmetric()
		<- return	
		-> crypto_core.c: random_nonce()
		-> crypto_core.c: encrypt_data_symmetric()
	<- return	
	-> TCP_connection.c: send_packet_tcp_connection()
<- return
```

**Eclipse Call Hierarchy for tcp_handle_cookie_request():**

```
tcp_handle_cookie_request(Net_Crypto *, int, const uint8_t *, uint16_t) : int
	tcp_data_callback(void *, int, const uint8_t *, uint16_t, void *) : int
		new_net_crypto(const Logger *, Mono_Time *, DHT *, TCP_Proxy_Info *) : Net_Crypto *
			new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
				main(int, char * *) : int
				main(int, char * *) : int
				tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
			new_onions(uint16_t, uint32_t *) : Onions *
```

#### Function descriptions from net_crypto.c and comments from myself:

- net_crypto.c: `Net_Crypto *new_net_crypto(const Logger *log, Mono_Time *mono_time, DHT *dht, TCP_Proxy_Info *proxy_info)`
	- **Comment:** In this function there is a new public/private key pair generated and set. Therefore this function should only be called once initially. => It is only called once and data of the created Tox "object" should be saved. 
		- Or if a users wants to reset everything.
    		- i.e. new_keys(temp);
    		- => **Comment**: is only called once and Tox "objects" needs to saved
    	- Run this to (re)initialize net_crypto.
	- Sets all the global connection variables to their default values.
		- networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    		- networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, temp);
    		- networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_HS, &udp_handle_packet, temp);
    		- networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_DATA, &udp_handle_packet, temp);
    - list of all UDP packet ids: NET_PACKET_
    - TODO Therefore all handshake related packets are sent via UDP? At least cookie response also seems to be sent (also) via TCP.
    - From Tox spec:
    		- "**networking_registerhandler()** is used by higher level modules in order to tell the network object which packets to send to which module via a callback"
		- "The networking_poll() function is called to read all the packets from the socket and pass them to the callbacks set using the networking_registerhandler() function."
- **net_crypto.c:create_cookie():** Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
	- return -1 on failure.
	- return 0 on success.
- **net_crypto.c: create_cookie_response():** Create a cookie response packet and put it in packet.
	- request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
	- packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
	- return -1 on failure.
	- return COOKIE_RESPONSE_LENGTH on success.
- **net_crypto.c:	handle_cookie_request():** Handle the cookie request packet of length length.
	- Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
	- Put the key used to decrypt the request into shared_key (of size CRYPTO_SHARED_KEY_SIZE) for use in the response.
	- return -1 on failure.
	- return 0 on success.

### Peer A/Initiator: Incoming cookie response (Message 1: Handshake packet from Peer A to Peer B will be sent)

Peer A/initiator receives a `NET_PACKET_COOKIE_RESPONSE` packet from Peer B and sends a `NET_PACKET_CRYPTO_HS` packet to Peer B/receiver.

**Handshake packet structure:** 

```
[uint8_t 26]
[Cookie]
[nonce (24 bytes)]
[Encrypted message containing:
    [24 bytes base nonce]
    [session public key of the peer (32 bytes)]
    [sha512 hash of the entire Cookie sitting outside the encrypted part]
    [Other Cookie (used by the other to respond to the handshake packet)]
]
```

Handling of a cookie response is either triggered via tcp_data_callback() or udp_handle_packet().

```
Messenger.c: new_messenger()
	-> net_crypto.c: new_net_crypto()
		-> net_crypto.c: tcp_data_callback()		// same call flow/graph if handle_packet_connection() is called via net_crypto.c:udp_handle_packet()
			-> net_crypto.c: handle_packet_connection()	// case: NET_PACKET_COOKIE_RESPONSE 
				-> net_crypto.c: get_crypto_connection()
				-> net_crypto.c: handle_cookie_response()
					-> crypto_core.c: decrypt_data_symmetric()
				<- return
				-> net_crypto.c: create_send_handshake()		// if cookie response was ok, send create and send handshake packet/Message 1 Peer A/initiator -> Peer B/receiver
					-> net_crypto.c: get_crypto_connection()
					-> net_crypto.c: create_crypto_handshake()	
						-> crypto_core.c: crypto_sha512()		// This is the cookie from Peer B/receiver which is sent in plain (see handshake packet in spec)
						-> net_crypto.c: create_cookie()		// Peer A/initiator creates 'Other Cookie'
							-> crypto_core.c: random_nonce()
							-> crypto_core.c: encrypt_data_symmetric()
						<- return
						-> crypto_core.c: random_nonce()
						-> crypto_core.c: encrypt_data()		// handshake packet is using peers real STATIC pk and self STATIC secret key for encryption
						// set NET_PACKET_CRYPTO_HS
					<- return	
					-> net_crypto.c: new_temp_packet()
						-> net_crypto.c: get_crypto_connection()
					<- return
					-> net_crypto.c: send_temp_packet()
						-> net_crypto.c: send_packet_to()
						-> mono_time.c: current_time_monotonic()
					<- return
				<- return
				// set Crypto conn status = CRYPTO_CONN_HANDSHAKE_SENT
			<- return	
		<- return
	<-		
<-
```

**Function descriptions from net_crypto.c and comments from myself:**

- net_crypto.c: `static int udp_handle_packet(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)`:
	- Handle raw UDP packets coming directly from the socket.
	- Handles:
		- Cookie response packets.
 		- Crypto handshake packets.
 		- Crypto data packets.
 		- **Comment:** AKE: One possiblity for Peer A/initiator if he receives a cookie response packet
- **net_crypto.c: handle_cookie_response():** Handle a cookie response packet of length encrypted with shared_key.
	- put the cookie in the response in cookie
	- cookie must be of length COOKIE_LENGTH. 
	- return -1 on failure.
	- return COOKIE_LENGTH on success.
- **net_crypto.c: create_crypto_handshake():** Create a handshake packet and put it in packet.
	- cookie must be COOKIE_LENGTH bytes.
	- packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
	- return -1 on failure.
 	- return HANDSHAKE_PACKET_LENGTH on success.
 - `static int handle_crypto_handshake(const Net_Crypto *c, uint8_t *nonce, uint8_t *session_pk, uint8_t *peer_real_pk, uint8_t *dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const uint8_t *expected_real_pk)`
	- Handle a crypto handshake packet of length.
	- put the nonce contained in the packet in nonce,
	- the session public key in session_pk
	- the real public key of the peer in peer_real_pk
	- the dht public key of the peer in dht_public_key and
	- the cookie inside the encrypted part of the packet in cookie.
	- if expected_real_pk isn't NULL it denotes the real public key
	- the packet should be from.
	- nonce must be at least CRYPTO_NONCE_SIZE
	- session_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
	- peer_real_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
	- cookie must be at least COOKIE_LENGTH
	- return -1 on failure.
	- return 0 on success.
- `static int create_send_handshake(Net_Crypto *c, int crypt_connection_id, const uint8_t *cookie, const uint8_t *dht_public_key)`
	- Create a handshake packet and set it as a temp packet.
	- cookie must be COOKIE_LENGTH.
	- return -1 on failure.
	- return 0 on success.
	- **Comment:** Peer A/Initiator sends handshake packet after receiving of cookie response

### Peer B: Incoming handshake Paket (Message 2: Handshake packet from Peer B to Peer A will be sent)

Peer B receives a `NET_PACKET_CRYPTO_HS` packet from Peer A. 

**Case: Peer B didn't yet try to initiate a connection to Peer A**

```
Messenger.c: new_messenger()
	-> net_crypto.c: new_net_crypto()
		// In this case crypt connection is already existing -> getcryptconnection_id() != -1
		// This is the call flow for Peer B/receiver sending a handshake packet to Peer A/initiator (after receiving a handshake packet from A)
		// second possibility is via net_crypto.c:udp_handle_packet()
		-> net_crypto.c: tcp_oob_callback() // (via set_oob_packet_tcp_connection_callback())	
			-> net_crypto.c: handle_new_connection_handshake()	// case: NET_PACKET_CRYPTO_HS packet received
				-> net_crypto.c: handle_crypto_handshake()		// Handle the crypto handshake packet from Peer A/initiator (incl. Other Cookie from A)
				-> net_crypto.c: open_cookie()
					-> crypto_core.c: public_key_cmp()
					-> crypto_core.c: crypto_sha512()
					-> crypto_core.c: decrypt_data()		// extract i.a. OTHER cookie from Peer A
					-> libsodium?:	 crypto_memcmp()
				<- return
				-> net_crypto.c: getcryptconnection_id()
				-> net_crypto.c: get_crypto_connection()
				-> crypto_core.c: public_key_cmp()
				-> crypto_core.c: encrypt_precompute()		// Peer B/receiver calculates shared session key from Peer A/initiator session public key and self session secret key
				-> net_crypto.c: crypto_connection_add_source()
				-> net_crypto.c: create_send_handshake()		// Send handshake packet/message 2 Peer B/receiver -> Peer A/initiator
					-> net_crypto.c: get_crypto_connection()
					-> net_crypto.c: create_crypto_handshake()	
						-> crypto_core.c: crypto_sha512()
						-> net_crypto.c: create_cookie()
							-> crypto_core.c: random_nonce()
							-> crypto_core.c: encrypt_data_symmetric()
						<- return
						-> crypto_core.c: random_nonce()
						-> crypto_core.c: encrypt_data()		// handshake packet is using peers real STATIC pk and self STATIC secret key for encryption
						// set NET_PACKET_CRYPTO_HS
					<- return	
					-> net_crypto.c: new_temp_packet()
						-> net_crypto.c: get_crypto_connection()
					<- return
					-> net_crypto.c: send_temp_packet()
						-> net_crypto.c: send_packet_to()
						-> mono_time.c: current_time_monotonic()
					<- return
				<- return
				// conn->status = CRYPTO_CONN_NOT_CONFIRMED => accepts connection (cf. spec)
			<-	
		<-
	<-	 
<-
```

**Case: Peer B also tried to initiate a connection to Peer A: call flow via handle_packet_connection()**

```
Messenger.c: new_messenger()
	-> net_crypto.c: new_net_crypto()
		// This is the call flow for Peer B sending a handshake packet to Peer A (after receiving a handshake packet from A)
		// second possibility is via net_crypto.c:udp_handle_packet()
		// in this case only a Handshake packet is sent if Peer (B) is in conn state CRYPTO_CONN_COOKIE_REQUESTING
		-> net_crypto.c: tcp_data_callback() 	// (via set_packet_tcp_connection_callback())	
			// or via udp_handle_packet()
			-> net_crypto.c: handle_packet_connection()		// case: NET_PACKET_CRYPTO_HS packet received
				-> net_crypto.c: get_crypto_connection()
				-> net_crypto.c: handle_crypto_handshake()	// Peer B/receiver handle incoming handshake packet
					-> net_crypto.c: open_cookie()
					-> crypto_core.c: public_key_cmp()
					-> crypto_core.c: crypto_sha512()
					-> crypto_core.c: decrypt_data()		// extract u.a. OTHER cookie from Peer A/initiator
					-> libsodium?:	 crypto_memcmp()
				<- return
				-> crypto_core.c: public_key_cmp()
				-> crypto_core.c: encrypt_precompute()		// derive shared session key from Peer A session public key and Peer B session private key
				// if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) -> create_send_handshake() => This seems to be an (error) case of Peer A/initiator, if Peer A/initiator receives handshake packet from Peer B/receiver, but has already sent a cookie request to Peer B/receiver himself
			// set Crypto conn status = CRYPTO_CONN_NOT_CONFIRMED => accepts connection (cf. spec)
			<- return
		<-
	<-	 
<-
```

#### Function descriptions from net_crypto.c and comments from myself:

- net_crypto.c: `udp_handle_packet()`: Handle raw UDP packets coming directly from the socket.
	- Handles:
		- Cookie response packets.
 		- Crypto handshake packets.
 		- Crypto data packets.
- net_crypto.c: `handle_new_connection_handshake`: Handle a handshake packet by someone who wants to initiate a new connection with us.
	- This calls the callback set by new_connection_handler() if the handshake is ok.
	- return -1 on failure.
	- return 0 on success.
- net_crypto.c: open_cookie(): Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
	- return -1 on failure.
	- return 0 on success.
- net_crypto.c: `static int handle_packet_connection(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length, bool udp, void *userdata)`
	- **Comment**: handling of Cookie response packets, crypto handshake packets and crypto data packets

### Peer A: Incoming handshake Paket from Peer B (needs to accept the connection)

```
Messenger.c: new_messenger()
	-> net_crypto.c: new_net_crypto()
		// second possibility is via net_crypto.c:udp_handle_packet()
		-> net_crypto.c: tcp_data_callback() // (via set_packet_tcp_connection_callback())	
			// or via udp_handle_packet()
			-> net_crypto.c: handle_packet_connection()	// case: NET_PACKET_CRYPTO_HS && CRYPTO_CONN_HANDSHAKE_SENT
				-> net_crypto.c: get_crypto_connection()
				-> net_crypto.c: handle_crypto_handshake()	// Peer A/initiator handle incoming handshake packet
					-> net_crypto.c: open_cookie()
					-> crypto_core.c: public_key_cmp()
					-> crypto_core.c: crypto_sha512()
					-> crypto_core.c: decrypt_data()		// extract u.a. OTHER cookie from Peer B
					-> libsodium?:	 crypto_memcmp()
				<- return
				-> crypto_core.c: public_key_cmp()
				-> crypto_core.c: encrypt_precompute()		// Peer A derive shared session key from Peer B session public key and Peer A session private key
				// set Crypto conn status = CRYPTO_CONN_NOT_CONFIRMED
			<- return
		<-
	<-	 
<-
```

=> **Handshake finished!** (Although the Crypto conn state is still _not_ CRYPTO_CONN_ESTABLISHED, but this is considered out of scope (in regard to the handshake/AKE).

### accept_crypto_connection() handshake case (Message 2 / Peer B)

~~don't know when this gets called, coming somehow via new_friend_connections()~~
AKE: This is the related section in the spec:
AKE: "If there is no existing connection to the peer identified by the long term
AKE: public key to set to 'Accepted', one will be created with that status."
But there is also another function for this?!
**TODO This function needs to be called by Peer B/receiver in order to calculate a ephemeral session keypair**
Is this the case if a peer (Peer B) doesn't have a crypto conn for Peer (A) yet? This also doesn't call handle_crypto_handshake() which is necessary in every case IIUC.

```
tox.c: tox_new()
	-> Messenger.c: new_messenger()
		-> friend_connection.c: `new_friend_connections()`
			-> friend_connection.c: handle_new_connections()
				-> net_crypto.c: accept_crypto_connection()
					-> net_crypto.c: getcryptconnection_id()
					-> net_crypto.c: create_crypto_connection()
					-> TCP_connection.c: new_tcp_connection_to()
					-> net_crypto.c: create_crypto_connection()
					-> net_crypto.c: random_nonce()
					-> net_crypto.c: crypto_new_keypair()		// Peer B generation of new public/private key pair
				-> net_crypto.c: encrypt_precompute()		// session key derivation
				// conn->status = CRYPTO_CONN_NOT_CONFIRMED;
				-> net_crypto.c: create_send_handshake()		// send handshake message
					-> net_crypto.c: create_crypto_handshake()
						-> net_crypto.c: create_cookie()
						-> net_crypto.c: random_nonce()
						-> net_crypto.c: encrypt_data()
					-> net_crypto.c: new_temp_packet()
					-> net_crypto.c: send_temp_packet()
				-> net_crypto.c: crypto_connection_add_source()	
			<- return crypt_connection_id
		<-
	<-
<-			
```

## Out of scope for handshake/AKE: sending of encrypting packets to confirm connections

Sending of encrypting packets to confirm connections (i.e. `conn->status = CRYPTO_CONN_ESTABLISHED`)

In handle_data_packet_core() -> `conn->status = CRYPTO_CONN_ESTABLISHED` is set

**Eclipse Call Hierarchy for handle_data_packet_core():**

```
handle_data_packet_core(Net_Crypto *, int, const uint8_t *, uint16_t, _Bool, void *) : int
	handle_packet_connection(Net_Crypto *, int, const uint8_t *, uint16_t, _Bool, void *) : int
		tcp_data_callback(void *, int, const uint8_t *, uint16_t, void *) : int
			new_net_crypto(const Logger *, Mono_Time *, DHT *, TCP_Proxy_Info *) : Net_Crypto *
				new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
					main(int, char * *) : int
					main(int, char * *) : int
					tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
						main(int, char * *) : int
						make_toxes(const vector<Action,allocator<Action>> &) : Global_State
						tox_new_log_lan(Tox_Options *, Tox_Err_New *, void *, _Bool) : Tox *
				new_onions(uint16_t, uint32_t *) : Onions *
		udp_handle_packet(void *, IP_Port, const uint8_t *, uint16_t, void *) : int
			new_net_crypto(const Logger *, Mono_Time *, DHT *, TCP_Proxy_Info *) : Net_Crypto * (3 matches)
				new_messenger(Mono_Time *, Messenger_Options *, unsigned int *) : Messenger *
					main(int, char * *) : int
					main(int, char * *) : int
					tox_new(const Tox_Options *, Tox_Err_New *) : Tox *
				new_onions(uint16_t, uint32_t *) : Onions *
```

send_crypto_packets() 

- net_crypto.c: send_data_packet(): Creates and sends a data packet to the peer using the fastest route.
	- return -1 on failure.
	- return 0 on success.
	- **Comment:** this function uses the shared_key to encrypt stuff

- net_crypto.c: handle_data_packet(): Handle a data packet.
	- Decrypt packet of length and put it into data.
	- data must be at least MAX_DATA_DATA_PACKET_SIZE big.
	- return -1 on failure.
 	- return length of data on success.
 	- **Comment:** this function uses the shared_key to encrypt stuff



