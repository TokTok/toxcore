/* Public key cracker.
 *
 * Can be used to find public keys starting with specific hex (ABCD) for example.
 *
 * NOTE: There's probably a way to make this faster.
 *
 * Usage: ./cracker ABCDEF
 *
 * Will try to find a public key starting with: ABCDEF
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Sodium includes*/
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/randombytes.h>

#define KEY_LEN 32

#if defined(_OPENMP)
#include <omp.h>
#define NUM_THREADS() ((unsigned) omp_get_max_threads())
#else
    NUM_THREADS() (1U)
#endif

static void print_key(const uint8_t *client_id)
{
    for (uint32_t j = 0; j < 32; j++) {
        printf("%02X", client_id[j]);
    }
}

/// bytes needs to be at least (hex_len+1)/2 long
static size_t hex_string_to_bin(const char *hex_string, size_t hex_len, uint8_t *bytes)
{
    size_t i;
    const char *pos = hex_string;
    // make even

    for (i = 0; i < hex_len/2; ++i, pos += 2) {
        uint8_t val;
        if (sscanf(pos, "%02hhx", &val) != 1) {
            return 0;
        }

        bytes[i] = val;
    }

    if (i*2 < hex_len) {
        uint8_t val;
        if (sscanf(pos, "%hhx", &val) != 1) {
            return 0;
        }

        bytes[i] = (uint8_t) (val << 4);
        ++i;
    }

    return i;
}

static size_t match_hex_prefix(const uint8_t *key, const uint8_t *prefix, size_t prefix_len)
{
    size_t same = 0;
    uint8_t diff = 0;
    size_t i;
    for(i = 0; i < prefix_len / 2; i++) {
        diff = key[i] ^ prefix[i];
        // First check high nibble
        if((diff & 0xF0) == 0) {
            same++;
        }
        // Then low nibble
        if(diff == 0) {
            same++;
        } else {
            break;
        }
    }

    // check last high nibble
    if ((prefix_len % 2) && diff == 0) {
        diff = key[i] ^ prefix[i];
        // First check high nibble
        if((diff & 0xF0) == 0) {
            same++;
        }
    }

    return same;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: ./cracker public_key(or beginning of one in hex format)\n");
        return 0;
    }

    size_t prefix_chars_len = strlen(argv[1]);

    /*
     * If you can afford the hardware to crack longer prefixes, you can probably
     * afford to rewrite this program.
     */
    if (strlen(argv[1]) > 16) {
        printf("Finding a key with more than 16 hex chars as prefix is not supported\n");
        return -1;
    }

    uint8_t hex_prefix[8] = {0};

    size_t prefix_len = hex_string_to_bin(argv[1], prefix_chars_len, hex_prefix);
    if (prefix_len == 0) {
        printf("Invalid hex key specified\n");
        return -1;
    }

    printf("Searching for key with prefix: %s\n", argv[1]);

    time_t start_time = time(NULL);
    uint8_t pub_key[KEY_LEN];
    uint64_t priv_key_shadow[KEY_LEN/8];
    uint8_t *priv_key = (uint8_t *) priv_key_shadow;
    randombytes(priv_key, 32);

    /*
     * We can't use the first and last bytes because they are masked in
     * curve25519. Offset by 16 bytes to get better alignment.
     */
    uint64_t *counter = priv_key_shadow + 2;

    // Can't check this case inside the loop because of uint64_t overflow
    *counter += UINT64_MAX;

    uint32_t longest_match = 0;

    /* Maybe we're lucky */
    crypto_scalarmult_curve25519_base(pub_key, priv_key);
    uint32_t matching = (uint32_t) match_hex_prefix(pub_key, hex_prefix, prefix_chars_len);
    if (matching > 0) {
        longest_match = matching;
        printf("Longest match after ~1 tries\n");
        printf("Public key: ");
        print_key(pub_key);
        printf("\nSecret key: ");
        print_key(priv_key);
        printf("\n");
        if (longest_match >= prefix_chars_len) {
            printf("Found matching prefix, exiting...\n");
            return 0;
        }
    }

    // Finishes a batch every ~10s on my PC
    uint64_t batch_size = (UINT64_C(1) << 17) * NUM_THREADS();

    double seconds_passed = 0.0;
    double old_seconds_passed = seconds_passed;

    for(uint64_t tries = 0; tries < UINT64_MAX; tries += batch_size) {
#pragma omp parallel for firstprivate(priv_key_shadow) shared(longest_match, tries, batch_size, hex_prefix, prefix_chars_len) schedule(static) default(none)
        for (uint64_t batch = tries; batch < (tries + batch_size); batch++) {
            uint8_t *priv_key = (uint8_t *) priv_key_shadow;
            uint64_t *counter = priv_key_shadow + 2;
            *counter += batch;
            uint8_t pub_key[KEY_LEN] = {0};

            crypto_scalarmult_curve25519_base(pub_key, priv_key);

            uint32_t matching = (uint32_t) match_hex_prefix(pub_key, hex_prefix, prefix_chars_len);

            // Global compare and update
            uint32_t l_longest_match;
            #pragma omp atomic read
            l_longest_match = longest_match;

            if (matching > l_longest_match) {
                #pragma omp atomic write
                longest_match = matching;

                #pragma omp critical
                {
                    printf("Longest match after ~%e tries\n", (double)batch);
                    printf("Public key: ");
                    print_key(pub_key);
                    printf("\nSecret key: ");
                    print_key(priv_key);
                    printf("\n");
                }
            }
        }

        seconds_passed = difftime(time(NULL), start_time);

        if (longest_match >= prefix_chars_len) {
            printf("Runtime: %lus, Calculating %e keys/s\n", (unsigned long) seconds_passed, (tries + batch_size)/seconds_passed);
            printf("Found matching prefix, exiting...\n");
            return 0;
        }

        if (seconds_passed - old_seconds_passed > 5.0) {
            old_seconds_passed = seconds_passed;
            printf("Runtime: %lus, Calculating %e keys/s\n", (unsigned long) seconds_passed, (tries + batch_size)/seconds_passed);
            fflush(stdout);
        }

    }

    *counter = 0;
    printf("Didn't find anything from:\n");
    print_key(priv_key);
    printf("\nto:\n");
    *counter = UINT64_MAX;
    print_key(priv_key);
    printf("\n");
    return -2;
}
