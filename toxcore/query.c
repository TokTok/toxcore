/** query.c
 *
 * Makes requests for information using the DHT or Onion as approitate.
 *
 * This file should include a licence, but if you're reading this, it doesn't yet so everything in
 * this file is donated to both tox, toktok, and you under a BSD or MIT licence at any option.
 */

int query_send_request(Tox *tox, const uint8_t *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length)
{
    Messenger *m = tox;
    struct addrinfo *addr;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        return -1;
    }

    int count = 0;
    do {
        IP_Port ip_port;
        ip_port.port = htons(port);
        ip_port.ip.family = info->ai_family;

        if (info->ai_socktype && info->ai_socktype != SOCK_DGRAM) {
            continue;
        }

        if (addr->ai_family == AF_INET) {
            ip_port.ip.ip4.in_addr = ((struct sockaddr_in *)addr->ai_addr)->sin_addr;
        } else if (addr->ai_family == AF_INET6) {
            ip_port.ip.ip6.in6_addr = ((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr;
        } else {
            continue;
        }

        ++count;
    } while ((info = info->ai_next));

    freeaddrinfo(root);



    // Verify name isn't currently pending response
    // return -2

    // Send request
    // succeed  0
    // fail    -3
    

    return 0; /* Can't work without code... */
}
