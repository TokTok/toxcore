%{

#ifndef TOXQNL_H
#define TOXQNL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
%}

/**
 * External Tox type.
 */
class tox {
  struct this;
}

/**
 * Tox_QNL.
 */
class tox_QNL {
  struct this;

  static this new(tox::this *tox) {
    NO_TOX,
    INVALID_TOX,
    MALLOC,
    NULL,
  }

  void kill();


  /**
   * Main loop for the session. This function needs to be called in intervals of
   * tox_qnl_iteration_interval() milliseconds.
   */
  void iterate();

namespace request {
  /**
   * Queries the server at given address, port, public key, for the ToxID associated with supplied name.
   *
   * TODO(grayhatter) add a bool to send request from a one time use keypair. (Needs net_crypto/dht refactor)
   * NOTE(requires net_crypto.c support)
   *
   * @param address the IPv4 or IPv6 address for the server. Will attempt to resolve DNS addresses.
   * @param port the port the server is listening on.
   * @param public_key the long term public key for the name server.
   * @param name the string (name) you want to give to the server to request the associated ToxID.
   *
   * @return true on success.
   */
  bool send(string address, uint16_t port, const uint8_t[PUBLIC_KEY_SIZE] public_key,
    const uint8_t[length <= MAX_QUERY_NAME_SIZE] name) {
      NULL,
    /**
     * The address could not be resolved to an IP address, or the IP address
     * passed was invalid.
     */
    BAD_HOST,
    /**
     * The port passed was invalid. The valid port range is (1, 65535).
     */
    BAD_PORT,
    /**
     * There is an existing request at this address with this name.
     */
    PENDING,
    /**
     * Unable to allocate the needed memory for this query.
     */
    MALLOC,
    /**
     * Unknown error of some kind; this indicates an error in toxcore. Please report this bug!
     */
    UNKNOWN,
  }

  event response const {
      /**
     * This callback will be invoked when a response from a pending query was received.
     * Once this callback is received, the query will have already been removed.
     */
    typedef void(const uint8_t[length <= MAX_QUERY_NAME_SIZE] request, const uint8_t[ADDRESS_SIZE] tox_id);
  }
}

}

%{

#ifdef __cplusplus
}
#endif
#endif /* TOXQNL_H */
%}
