%{
/* toxencryptsave.h
 *
 * The Tox encrypted save functions.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef TOXENCRYPTSAVE_H
#define TOXENCRYPTSAVE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef TOXES_DEFINED
#define TOXES_DEFINED
#endif /* TOXES_DEFINED */

%}

class tox {

const PASS_SALT_LENGTH                  = 32;
const PASS_KEY_LENGTH                   = 32;
const PASS_ENCRYPTION_EXTRA_LENGTH      = 80;

/**
 * This module is conceptually organized into two parts. The first part are the functions
 * with "key" in the name. To use these functions, first derive an encryption key
 * from a password with ${pass_Key.derive_from_pass}, and use the returned key to
 * encrypt the data. The second part takes the password itself instead of the key,
 * and then delegates to the first part to derive the key before de/encryption,
 * which can simplify client code; however, key derivation is very expensive
 * compared to the actual encryption, so clients that do a lot of encryption should
 * favor using the first part intead of the second part.
 *
 * The encrypted data is prepended with a magic number, to aid validity checking
 * (no guarantees are made of course). Any data to be decrypted must start with
 * the magic number.
 *
 * Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

error for key_derivation {
  NULL,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue. The functions accepting keys
   * do not produce this error.
   */
  FAILED,
}

error for encryption {
  NULL,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue. The functions accepting keys
   * do not produce this error.
   */
  KEY_DERIVATION_FAILED,
  /**
   * The encryption itself failed.
   */
  FAILED,
}

error for decryption {
  NULL,
  /**
   * The input data was shorter than $PASS_ENCRYPTION_EXTRA_LENGTH bytes
   */
  INVALID_LENGTH,
  /**
   * The input data is missing the magic number (i.e. wasn't created by this
   * module, or is corrupted)
   */
  BAD_FORMAT,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue. The functions accepting keys
   * do not produce this error.
   */
  KEY_DERIVATION_FAILED,
  /**
   * The encrypted byte array could not be decrypted. Either the data was
   * corrupt or the password/key was incorrect.
   */
  FAILED,
}


/**
 * ****************************** BEGIN PART 2 *******************************
 * For simplicty, the second part of the module is presented first. The API for
 * the first part is analgous, with some extra functions for key handling. If
 * your code spends too much time using these functions, consider using the part
 * 1 functions instead.
 */

/**
 * Encrypts the given data with the given passphrase. The output array must be
 * at least data_len + $PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
 * to ${pass_Key.derive_from_pass} and ${pass_Key.encrypt}.
 *
 * returns true on success
 */
static bool pass_encrypt(const uint8_t[data_len] data, const uint8_t[pplength] passphrase, uint8_t *out)
    with error for encryption;


/**
 * Decrypts the given data with the given passphrase. The output array must be
 * at least data_len - $PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
 * to ${pass_Key.decrypt}.
 *
 * the output data has size data_length - $PASS_ENCRYPTION_EXTRA_LENGTH
 *
 * returns true on success
 */
static bool pass_decrypt(const uint8_t[length] data, const uint8_t[pplength] passphrase, uint8_t *out)
    with error for decryption;


/**
 * ****************************** BEGIN PART 1 *******************************
 * And now part "1", which does the actual encryption, and is rather less cpu
 * intensive than part one. The first 3 functions are for key handling.
 */

/**
 * This key structure's internals should not be used by any client program, even
 * if they are straightforward here.
 */
class pass_Key {
  struct this;

  static this new();
  void free();

  /**
   * Generates a secret symmetric key from the given passphrase. out_key must be at least
   * $PASS_KEY_LENGTH bytes long.
   * Be sure to not compromise the key! Only keep it in memory, do not write to disk.
   * The password is zeroed after key derivation.
   * The key should only be used with the other functions in this module, as it
   * includes a salt.
   * Note that this function is not deterministic; to derive the same key from a
   * password, you also must know the random salt that was used. See below.
   *
   * returns true on success
   */
  bool derive_from_pass(const uint8_t[pplength] passphrase)
      with error for key_derivation;

  /**
   * Same as above, except use the given salt for deterministic key derivation.
   * The salt must be $PASS_SALT_LENGTH bytes in length.
   */
  bool derive_with_salt(const uint8_t[pplength] passphrase, const uint8_t[PASS_SALT_LENGTH] salt)
      with error for key_derivation;

  /**
   * Now come the functions that are analogous to the part 2 functions.
   */

  /**
   * Encrypt arbitrary with a key produced by tox_pass_key_derive_*. The output
   * array must be at least data_len + $PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
   * key must be $PASS_KEY_LENGTH bytes.
   * If you already have a symmetric key from somewhere besides this module, simply
   * call encrypt_data_symmetric in toxcore/crypto_core directly.
   *
   * returns true on success
   */
  const bool encrypt(const uint8_t[data_len] data, uint8_t *out)
      with error for encryption;

  /**
   * This is the inverse of $encrypt, also using only keys produced by
   * $derive_from_pass.
   *
   * the output data has size data_length - $PASS_ENCRYPTION_EXTRA_LENGTH
   *
   * returns true on success
   */
  const bool decrypt(const uint8_t[length] data, uint8_t *out)
      with error for decryption;
}

/**
 * This retrieves the salt used to encrypt the given data, which can then be passed to
 * derive_key_with_salt to produce the same key as was previously used. Any encrpyted
 * data with this module can be used as input.
 *
 * returns true if magic number matches
 * success does not say anything about the validity of the data, only that data of
 * the appropriate size was copied
 */
static bool get_salt(const uint8_t *data, uint8_t[PASS_SALT_LENGTH] salt);

/**
 * Determines whether or not the given data is encrypted (by checking the magic number)
 */
static bool is_data_encrypted(const uint8_t *data);

}

%{

#ifdef __cplusplus
}
#endif

#endif

%}
