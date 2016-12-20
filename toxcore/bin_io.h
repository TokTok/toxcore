#ifndef BIN_IO_H
#define BIN_IO_H

#include <stddef.h>
#include <stdint.h>


typedef enum BIN_ERR_NEW {

    /**
     * The function returned successfully.
     */
    BIN_ERR_NEW_OK,

    /**
     * Insufficient memory to allocate the writer or its initial buffer.
     */
    BIN_ERR_NEW_MALLOC,

} BIN_ERR_NEW;


typedef enum BIN_ERR_WRITE {

    /**
     * The function returned successfully.
     */
    BIN_ERR_WRITE_OK,

    /**
     * Out of memory.
     */
    BIN_ERR_WRITE_MALLOC,

} BIN_ERR_WRITE;


/**
 * The abstract data type of a binary writer. Must be allocated using bin_w_new
 * and freed using bin_w_free.
 *
 * The binary writer can be used to serialise arbitrary structures in a
 * portable way. It provides primitives for writing machine integers to a byte
 * array. Using a sequence of function calls, we can implement serialisers for
 * more complex data structures.
 *
 * Integers are written in network byte order (Big Endian), i.e. with the most
 * significant byte first.
 *
 * The writer currently intentionally does not support a reset functionality,
 * making it write-once.
 */
#ifndef BIN_W_DEFINED
#define BIN_W_DEFINED
typedef struct Bin_W Bin_W;
#endif /* BIN_W_DEFINED */

/**
 * Create a new empty binary writer.
 *
 * bin_w_size() will return 0 on the returned writer.
 */
struct Bin_W *bin_w_new(BIN_ERR_NEW *error);

/**
 * Deallocate the binary writer and its buffer. If you hold a pointer to the
 * buffer, that pointer becomes invalid, so make sure you copied the data if
 * you intend to use it after deleting the writer.
 */
void bin_w_free(struct Bin_W *w);

/**
 * Get a pointer to the internal buffer.
 *
 * This pointer is invalidated in the following situations:
 * - The writer is deleted.
 * - The internal buffer is reallocated. This can happen during any write
 *   operation, so you must assume the pointer is invalid after write.
 */
uint8_t *bin_w_get(const struct Bin_W *w);

/**
 * Get the number of bytes written to the writer so far.
 */
size_t bin_w_size(const struct Bin_W *w);

/**
 * Copy up to the specified number of bytes from the buffer to the array
 * pointer at by `data`. If the length specified is more than the buffer
 * currently holds, only the number of bytes currently held are written.
 *
 * @param offset The starting point from which to read. If the offset is
 * larger than the buffer, no data is copied.
 * @param data The buffer to write to.
 * @param length The maximum number of bytes to write.
 *
 * @return The actual number of bytes written.
 */
size_t bin_w_copy(const struct Bin_W *w, size_t offset, uint8_t *data, size_t length);

/**
 * Write an 8 bit unsigned integer to the writer.
 */
void bin_w_u08(struct Bin_W *w, uint8_t v, BIN_ERR_WRITE *error);

/**
 * Write a 16 bit unsigned integer to the writer as 2 bytes in big endian.
 */
void bin_w_u16(struct Bin_W *w, uint16_t v, BIN_ERR_WRITE *error);

/**
 * Write a 32 bit unsigned integer to the writer as 4 bytes in big endian.
 */
void bin_w_u32(struct Bin_W *w, uint32_t v, BIN_ERR_WRITE *error);

/**
 * Write a 64 bit unsigned integer to the writer as 8 bytes in big endian.
 */
void bin_w_u64(struct Bin_W *w, uint64_t v, BIN_ERR_WRITE *error);

/**
 * Write a byte array to the writer.
 */
void bin_w_arr(struct Bin_W *w, uint8_t *data, size_t length, BIN_ERR_WRITE *error);

/**
 * The abstract data type of a binary reader. Must be allocated using bin_r_new
 * and freed using bin_r_free.
 *
 * The reader is the data retrieval counterpart of the writer specified above.
 * Integers read by the reader are written to the argument in host byte order.
 *
 * Each retrieval function advances the reader by the number of bytes read.
 * There is no way to reset the reader. If you need to read the same data
 * again, create a new reader.
 *
 * Each reader function returns a boolean value signalling success. The
 * contents of the passed values are unspecified in case of error. Once the
 * reader is in error state, it will remain in the error state and all
 * subsequent reads will result in an error. It is safe to perform a sequence
 * of reads and only check the last read for an error.
 */
#ifndef BIN_R_DEFINED
#define BIN_R_DEFINED
typedef struct Bin_R Bin_R;
#endif /* BIN_R_DEFINED */

/**
 * Create a new binary reader for the given data of the given length.
 *
 * The reader will not own the data passed, so the caller must ensure that
 * the data outlives the reader.
 */
struct Bin_R *bin_r_new(uint8_t *data, size_t length, BIN_ERR_NEW *error);

/**
 * Deallocate the reader object. The data pointer is not deallocated.
 */
void bin_r_free(struct Bin_R *r);

/**
 * Read an 8 bit unsigned integer and advance the reader by 1 byte.
 */
bool bin_r_u08(struct Bin_R *r, uint8_t *v);

/**
 * Read a 16 bit unsigned integer in big endian and advance the reader by
 * 2 bytes.
 */
bool bin_r_u16(struct Bin_R *r, uint16_t *v);

/**
 * Read a 32 bit unsigned integer in big endian and advance the reader by
 * 4 bytes.
 */
bool bin_r_u32(struct Bin_R *r, uint32_t *v);

/**
 * Read a 64 bit unsigned integer in big endian and advance the reader by
 * 8 bytes.
 */
bool bin_r_u64(struct Bin_R *r, uint64_t *v);

/**
 * Read a byte array of the given length and write it to the passed data
 * buffer. In case of error, the values of the bytes pointed to by the data
 * pointer are unspecified.
 */
bool bin_r_arr(struct Bin_R *r, uint8_t *data, size_t length);

#endif /* BIN_IO_H */
