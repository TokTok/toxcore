/** query.h
 *
 * Makes requests for information using the DHT or Onion as approitate.
 *
 * This file should include a licence, but if you're reading this, it doesn't yet so everything in
 * this file is donated to both tox, toktok, and you under a BSD or MIT licence at any option.
 */

int query_send_request(Tox *tox, const uint8_t *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length);
