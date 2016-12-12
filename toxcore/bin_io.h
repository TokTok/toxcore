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
 * Create a new binary writer with a given initial capacity.
 *
 * The buffer will be resized automatically when writing beyond the initial
 * capacity.
 *
 * @param initial The initial capacity of the writer.
 */
struct Bin_W *bin_w_new(size_t initial, BIN_ERR_NEW *error);

/**
 * Deallocate the binary writer and its buffer. If you hold a pointer to the
 * buffer, that pointer becomes invalid, so make sure you copied the data if
 * you intend to use it after deleting the writer.
 */
void bin_w_free(struct Bin_W *w);

/**
 * Get a pointer to the internal buffer. When the writer is deleted, this
 * pointer becomes invalid.
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

typedef enum BIN_ERR_READ {

    /**
     * The function returned successfully.
     */
    BIN_ERR_READ_OK,

    /**
     * Insufficient bytes remaining in the reader.
     */
    BIN_ERR_READ_EOF,

} BIN_ERR_READ;


/**
 * The abstract data type of a binary reader. Must be allocated using bin_r_new
 * and freed using bin_r_free.
 *
 * The reader is the data retrieval counterpart of the writer specified above.
 * It reads integers in network byte order as written by the writer.
 *
 * Each retrieval function advances the reader by the number of bytes read.
 * There is no way to reset the reader. If you need to read the same data
 * again, create a new reader.
 *
 * The return value for each of the reader functions is unspecified in case
 * of error. Once the reader is in error state, it will remain in the error
 * state and all subsequent reads will result in an error. It is safe to
 * perform a sequence of reads and only check the last read for an error.
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
 * Create a new reader from the current one at the current offset.
 *
 * This reader will also not own the data passed, so the data must outlive
 * every child reader created from the initial one.
 */
struct Bin_R *bin_r_clone(struct Bin_R *r, BIN_ERR_NEW *error);

/**
 * Deallocate the reader object. The data pointer is not deallocated.
 */
void bin_r_free(struct Bin_R *r);

/**
 * Read an 8 bit unsigned integer and advance the reader by 1 byte.
 */
uint8_t bin_r_u08(struct Bin_R *r, BIN_ERR_READ *error);

/**
 * Read a 16 bit unsigned integer in big endian and advance the reader by
 * 2 bytes.
 */
uint16_t bin_r_u16(struct Bin_R *r, BIN_ERR_READ *error);

/**
 * Read a 32 bit unsigned integer in big endian and advance the reader by
 * 4 bytes.
 */
uint32_t bin_r_u32(struct Bin_R *r, BIN_ERR_READ *error);

/**
 * Read a 64 bit unsigned integer in big endian and advance the reader by
 * 8 bytes.
 */
uint64_t bin_r_u64(struct Bin_R *r, BIN_ERR_READ *error);

/**
 * Read a byte array of the given length and write it to the passed data
 * buffer. In case of error, the values of the bytes pointed to by the data
 * pointer are unspecified.
 */
void bin_r_arr(struct Bin_R *r, uint8_t *data, size_t length, BIN_ERR_READ *error);

#endif /* BIN_IO_H */

