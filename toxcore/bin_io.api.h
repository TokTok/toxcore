%{
#ifndef BIN_IO_H
#define BIN_IO_H

#include <stddef.h>
#include <stdint.h>

%}

// TODO(iphydf): This should be namespace. Fix apidsl.
class bin
{

error for new {
  /**
   * Insufficient memory to allocate the writer or its initial buffer.
   */
  MALLOC,
}

error for write {
  /**
   * Out of memory.
   */
  MALLOC,
}

class w
{
  /**
   * The abstract data type of a binary writer. Must be allocated using $new
   * and freed using $free.
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
  struct this;

  /**
   * Create a new binary writer with a given initial capacity.
   *
   * The buffer will be resized automatically when writing beyond the initial
   * capacity.
   *
   * @param initial The initial capacity of the writer.
   */
  static this new(size_t initial)
      with error for new;

  /**
   * Deallocate the binary writer and its buffer. If you hold a pointer to the
   * buffer, that pointer becomes invalid, so make sure you copied the data if
   * you intend to use it after deleting the writer.
   */
  void free();

  /**
   * Get a pointer to the internal buffer. When the writer is deleted, this
   * pointer becomes invalid.
   */
  const uint8_t *get();

  /**
   * Get the number of bytes written to the writer so far.
   */
  const size_t size();

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
  const size_t copy(size_t offset, uint8_t[length] data);

  /**
   * Write an 8 bit unsigned integer to the writer.
   */
  void u08(uint8_t  v) with error for write;
  /**
   * Write a 16 bit unsigned integer to the writer as 2 bytes in big endian.
   */
  void u16(uint16_t v) with error for write;
  /**
   * Write a 32 bit unsigned integer to the writer as 4 bytes in big endian.
   */
  void u32(uint32_t v) with error for write;
  /**
   * Write a 64 bit unsigned integer to the writer as 8 bytes in big endian.
   */
  void u64(uint64_t v) with error for write;
  /**
   * Write a byte array to the writer.
   */
  void arr(uint8_t[length] data) with error for write;
}

error for read {
  /**
   * Insufficient bytes remaining in the reader.
   */
  EOF,
}

class r
{
  /**
   * The abstract data type of a binary reader. Must be allocated using $new
   * and freed using $free.
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
  struct this;

  /**
   * Create a new binary reader for the given data of the given length.
   *
   * The reader will not own the data passed, so the caller must ensure that
   * the data outlives the reader.
   */
  static this new(uint8_t[length] data)
      with error for new;

  /**
   * Create a new reader from the current one at the current offset.
   *
   * This reader will also not own the data passed, so the data must outlive
   * every child reader created from the initial one.
   */
  this clone()
      with error for new;

  /**
   * Deallocate the reader object. The data pointer is not deallocated.
   */
  void free();

  /**
   * Read an 8 bit unsigned integer and advance the reader by 1 byte.
   */
  uint8_t  u08() with error for read;
  /**
   * Read a 16 bit unsigned integer in big endian and advance the reader by
   * 2 bytes.
   */
  uint16_t u16() with error for read;
  /**
   * Read a 32 bit unsigned integer in big endian and advance the reader by
   * 4 bytes.
   */
  uint32_t u32() with error for read;
  /**
   * Read a 64 bit unsigned integer in big endian and advance the reader by
   * 8 bytes.
   */
  uint64_t u64() with error for read;
  /**
   * Read a byte array of the given length and write it to the passed data
   * buffer. In case of error, the values of the bytes pointed to by the data
   * pointer are unspecified.
   */
  void     arr(uint8_t[length] data) with error for read;
}

}

%{
#endif /* BIN_IO_H */
%}
