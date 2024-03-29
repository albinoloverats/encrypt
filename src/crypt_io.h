/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2024, albinoloverats ~ Software Development
 * email: encrypt@albinoloverats.net
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _ENCRYPT_CRYPTIO_H_
#define _ENCRYPT_CRYPTIO_H_

/*!
 * \file    crypt_io.h
 * \author  Ashley M Anderson
 * \date    2009-2024
 * \brief   IO functions for encrypt
 *
 * Advanced IO functions for encryption/compression. Wraps read/write
 * with crypto functions and LZMA compression for encrypt.
 */

#include <stdint.h> /*!< Necessary include as c99 standard integer types are referenced in this header */
#include <stdbool.h> /*!< Necessary include as c99 boolean type is referenced in this header */

#define IO_STDIN_FILENO  io_use_stdin() /*!< Macro wrapper for io_use_stdin() */
#define IO_STDOUT_FILENO io_use_stdout() /*!< Macro wrapper for io_use_stdout() */
#define IO_UNINITIALISED io_dummy_handle() /*!< Macro wrapper for io_dummy_handle() */

typedef void * IO_HANDLE; /*<! Handle type for IO functions */

#if defined _WIN32 && !defined _MODE_T_
#define _MODE_T_
typedef unsigned short mode_t;
#endif

/*!
 * \brief  How the IV should be generated
 *
 * The IV can be generated in one of a few ways; it depends on the
 * (compatibility) version of encrypt. Basically the only valid choice
 * is the latest.
 */
typedef enum
{
	IV_BROKEN, /*!< The oldest version of encrypt didn’t do a good job of IV generation */
	IV_SIMPLE, /*!< More recent versions did a better job, but it’s still not great */
	IV_RANDOM  /*!< The next/current version does the best job (so far) */
}
x_iv_e;

/*!
 * \brief  Extra options passed to IO crypto init
 *
 * A structure for any additional options necessary to revert to an
 * older setup for encryption/decryption. As things are imporved going
 * forward, it is still necessary to keep backwards compatibility with
 * previous versions.
 */
typedef struct
{
	x_iv_e x_iv;    /*!< Whether to use the older (less correct) IV generation */
	bool x_encrypt; /*!< Encrypt (or decrypt) */
}
io_extra_t;

/*!
 * \brief         Open a file
 * \param[in]  n  The file name
 * \param[in]  f  File open flags
 * \param[in]  m  File open mode
 * \return        A new IO instance for the specified file
 *
 * Open a file. Using these IO functions wraps the typical IO functions
 * with encryption and compression support.
 */
extern IO_HANDLE io_open(const char *n, int f, mode_t m) __attribute__((malloc, nonnull(1)));

/*!
 * \brief         Destroy an IO instance
 * \param[in]  h  An IO instance to destroy
 *
 * Closes the file and free resources when no longer needed.
 */
extern int io_close(IO_HANDLE h) __attribute__((nonnull(1)));

/*!
 * \brief         Release an IO instance
 * \param[in]  h  An IO instance to destroy
 *
 * Free the memory of an IO instance [automatically called by
 * io_close()], the only other use is for destroying an invalid IO
 * instance.
 */
extern void io_release(IO_HANDLE ptr) __attribute__((nonnull(1)));

/*!
 * \brief         Creates a dummy file handle
 * \returns       An uninitialised file handle
 *
 * Creates a dummy, uninitialised, file handle. Useful in situations
 * where a IO instance is needed but not yet ready to be initialised
 * or opened.
 *
 * NB: Use IO_UNINITIALISED instead.
 */
extern IO_HANDLE io_dummy_handle(void);

/*!
 * \brief         Get IO instance for STDIN
 * \return        An IO instance for STDIN
 *
 * Get an IO_HANDLE instance for STDIN stream.
 * instead.
 *
 * NB: Use IO_STDIN_FILENO instead.
 */
extern IO_HANDLE io_use_stdin(void);

/*!
 * \brief         Get IO instance for STDOUT
 * \return        An IO instance for STDOUT
 *
 * Get an IO_HANDLE instance for STDOUT stream.
 *
 * NB: Use IO_STDOUT_FILENO instead.
 */
extern IO_HANDLE io_use_stdout(void);

/*!
 * \brief         Check if IO instance is initialised
 * \param[in]  h  An IO instance
 * \return        Whether IO instance is initialised
 *
 * Returns true if IO_HANDLE instance is a valid stream.
 */
extern bool io_is_initialised(IO_HANDLE) __attribute__((nonnull(1)));

/*!
 * \brief         Check if IO instance is STDIN
 * \param[in]  h  An IO instance
 * \return        Whether IO instance is STDIN
 *
 * Returns true if IO_HANDLE instance is STDIN stream.
 */
extern bool io_is_stdin(IO_HANDLE h) __attribute__((nonnull(1)));

/*!
 * \brief         Check if IO instance is STDOUT
 * \param[in]  h  An IO instance
 * \return        Whether IO instance is STDOUT
 *
 * Returns true if IO_HANDLE instance is STDOUT stream.
 */
extern bool io_is_stdout(IO_HANDLE h) __attribute__((nonnull(1)));

/*!
 * \brief         Write data
 * \param[in]  f  An IO instance
 * \param[in]  d  The data to write
 * \param[in]  l  The length of data to write
 * \return        The number of bytes written
 *
 * Write the given data to the given file descriptor, performing any
 * necessary operations before it is actually written. Returns the
 * number of bytes actually written.
 */
extern ssize_t io_write(IO_HANDLE f, const void *d, size_t l) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Read data
 * \param[in]  f  An IO instance
 * \param[out] d  The data read
 * \param[in]  l  The length of data to read (size of d)
 * \return        The number of bytes read
 *
 * Read the specified number of bytes from the given file descriptor,
 * performing any necessary operations before it’s returned.
 */
extern ssize_t io_read(IO_HANDLE f, void *d, size_t l) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Sync data waiting to be written
 * \param[in]  f  An IO instance
 *
 * Performs a sync of all outstanding data to be written.
 */
extern int io_sync(IO_HANDLE f) __attribute__((nonnull(1)));

/*!
 * \brief         Seek to position in file
 * \param[in]  f  An IO instance
 * \param[in]  o  The offset set position
 * \param[in]  w  From whence the fofset should be measured
 * \return        The new offset within the file
 *
 * This function is the same as lseek(), in both the accepted values
 * for the offset and whence, as well as the return value.
 */
extern off_t io_seek(IO_HANDLE f, off_t o, int w) __attribute__((nonnull(1)));

/*!
 * \brief         Encryption/Decryption initialisation
 * \param[in]  f  An IO instance
 * \param[in]  c  The ID of the cipher to use
 * \param[in]  h  The ID of the hash to use for key generation
 * \param[in]  m  The ID of the mode to use
 * \param[in]  a  The ID of the MAC to use
 * \param[in]  i  Number of iterations for key derivation function
 * \param[in]  k  Raw key data
 * \param[in]  l  The length of the key data
 * \param[in]  x  Any extra modifing options
 * \return        True on success, false otherwise.
 *
 * Initialise encryption/decryption of data read/written. This is then
 * active for the rest of the life of the IO_HANDLE.
 */
extern bool io_encryption_init(IO_HANDLE f, enum gcry_cipher_algos c, enum gcry_md_algos h, enum gcry_cipher_modes m, enum gcry_mac_algos a, uint64_t i, const uint8_t *k, size_t l, io_extra_t x) __attribute__((nonnull(1, 7)));

/*!
 * \brief         Compression initialisation
 * \param[in]  f  An IO instance
 *
 * Turn on compression/decompression for the rest of the life of this
 * handle.
 */
extern void io_compression_init(IO_HANDLE f) __attribute__((nonnull(1)));

/*!
 * \brief         Read/Write data checksum initialisation
 * \param[in]  f  An IO instance
 * \param[in]  h  The ID of the hash to use for checksum calculations
 *
 * For all subsequent data that is read/written feed it through a hash
 * function as a way of generating a checksum to detect errors.
 */
extern void io_encryption_checksum_init(IO_HANDLE f, enum gcry_md_algos h) __attribute__((nonnull(1)));

/*!
 * \brief         Read/Write data checksum generation
 * \param[in]  f  An IO instance
 * \param[out] b  A pointer to the calculated checksum
 * \param[out] l  The length of the checksum
 *
 * Retrieve the hash checksum of all encrypted data read/written so far.
 */
extern void io_encryption_checksum(IO_HANDLE f, uint8_t **b, size_t *l) __attribute__((nonnull(1)));

/*!
 * \brief
 * \param[in]  f  An IO instance
 * \param[out] b  A pointer to the MAC
 * \param[out] l  The length of the MAC
 *
 * Retrieve the MAC of all the encrypted data read/written.
 */
extern void io_encryption_mac(IO_HANDLE f, uint8_t **b, size_t *l) __attribute__((nonnull(1)));

/*!
 * \brief         Enable ECC
 * \param[in]  f  An IO instance
 *
 * Enable error correction in IO. Uses Reed-Solomon error correction.
 */
extern void io_correction_init(IO_HANDLE f) __attribute__((nonnull(1)));

#endif /* ! _ENCRYPT_CRYPTIO_H_ */
