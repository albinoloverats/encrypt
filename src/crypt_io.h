/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2025, albinoloverats ~ Software Development
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
 * \date    2009-2025
 * \brief   IO functions for encrypt
 *
 * File and standard-stream handles with optional encryption, LZMA
 * compression, checksum/MAC, and error-correction processing.
 */

#include <stdint.h> /*!< Necessary include as c99 standard integer types are referenced in this header */
#include <stdbool.h> /*!< Necessary include as c99 boolean type is referenced in this header */

#define IO_STDIN_FILENO  io_use_stdin() /*!< Macro wrapper for io_use_stdin() */
#define IO_STDOUT_FILENO io_use_stdout() /*!< Macro wrapper for io_use_stdout() */
#define IO_UNINITIALISED io_dummy_handle() /*!< Macro wrapper for io_dummy_handle() */

/*! \brief Opaque handle for the wrapped I/O instance. */
typedef void * IO_HANDLE;

#if defined _WIN32 && !defined _MODE_T_
#define _MODE_T_
typedef unsigned short mode_t;
#endif

/*!
 * \brief  How the IV should be generated
 *
 * Selects the initialization-vector behavior required by a container
 * version: IV_BROKEN for the earliest formats, IV_SIMPLE for older
 * formats, and IV_RANDOM for versions from 2015.01 onward.
 */
typedef enum
{
	IV_BROKEN, /*!< Legacy IV generation used by versions through 2012.11 */
	IV_SIMPLE, /*!< Deterministic IV generation used by versions 2013.02 through 2014.06 */
	IV_RANDOM  /*!< Random IV generation used by versions from 2015.01 onward */
}
x_iv_e;

/*!
 * \brief  Extra options passed to IO crypto init
 *
 * Options controlling compatibility behavior and whether initialization
 * material is generated for encryption or read for decryption.
 */
typedef struct
{
	x_iv_e x_iv;    /*!< Whether to use the older (less correct) IV generation */
	bool x_encrypt; /*!< True to generate/write salt and IV; false to read them */
}
io_extra_s;

/*!
 * \brief         Open a file
 * \param[in]  n  The file name
 * \param[in]  f  File open flags
 * \param[in]  m  File open mode
 * \return        A new handle, or NULL if the file could not be opened
 *
 * The handle owns the opened file descriptor; io_close() closes it.
 * Subsequent reads and writes can apply the configured transformations.
 */
extern IO_HANDLE io_open(const char *n, int f, mode_t m) __attribute__((malloc, nonnull(1)));

/*!
 * \brief         Create an IO instance from an open file descriptor
 * \param[in]  fd An open file descriptor transferred to the returned handle
 * \return        A new handle, or NULL if fd is negative
 *
 * The returned handle closes fd when passed to io_close().
 */
extern IO_HANDLE io_wrap_fd(int64_t fd);

/*!
 * \brief         Destroy an IO instance
 * \param[in]  h  An IO instance to destroy
 *
 * Closes the underlying descriptor and frees the handle. Any previously
 * recorded I/O error is returned in preference to a close error.
 */
extern int io_close(IO_HANDLE h) __attribute__((nonnull(1)));

/*!
 * \brief         Release an IO instance
 * \param[in]  ptr  An IO instance to release
 *
 * Frees the handle and its processing state without closing its
 * underlying descriptor. io_close() calls this before closing the
 * descriptor.
 */
extern void io_release(IO_HANDLE ptr) __attribute__((nonnull(1)));

/*!
 * \brief         Create a dummy file handle
 * \return        An uninitialised handle
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
 * Returns a wrapper around STDIN_FILENO. Closing the wrapper also closes
 * the standard descriptor.
 *
 * NB: Use IO_STDIN_FILENO instead.
 */
extern IO_HANDLE io_use_stdin(void);

/*!
 * \brief         Get IO instance for STDOUT
 * \return        An IO instance for STDOUT
 *
 * Returns a wrapper around STDOUT_FILENO. Closing the wrapper also closes
 * the standard descriptor.
 *
 * NB: Use IO_STDOUT_FILENO instead.
 */
extern IO_HANDLE io_use_stdout(void);

/*!
 * \brief         Check if IO instance is initialised
 * \param[in]  h  An IO instance
 * \return        Whether IO instance is initialised
 *
 * Returns true when the handle contains a nonnegative file descriptor.
 * A dummy handle is not initialized.
 */
extern bool io_is_initialised(IO_HANDLE h) __attribute__((nonnull(1)));

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
 * \brief         Check whether a path identifies the same file as an IO handle
 * \param[in]  f  An IO instance
 * \param[in]  n  A file name
 * \return        Whether both identify the same file
 */
extern bool io_same_file(IO_HANDLE f, const char *n) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Write data
 * \param[in]  f  An IO instance
 * \param[in]  d  The data to write
 * \param[in]  l  The length of data to write
 * \return        The requested length on success, or -1 on error
 *
 * Write the given data through the configured processing pipeline.
 * A short underlying write is completed internally; any incomplete
 * operation is reported as an error.
 */
extern ssize_t io_write(IO_HANDLE f, const void *d, size_t l) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Read data
 * \param[in]  f  An IO instance
 * \param[out] d  The data read
 * \param[in]  l  The length of data to read (size of d)
 * \return        The number of bytes read (possibly fewer than requested), or -1 on error
 *
 * Reads up to the requested number of bytes, applying enabled
 * decompression, decryption, and error correction. A zero return for a
 * nonzero request indicates EOF.
 */
extern ssize_t io_read(IO_HANDLE f, void *d, size_t l) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Read an exact number of bytes
 * \param[in]  f  An IO instance
 * \param[out] d  The data read
 * \param[in]  l  The number of bytes to read
 * \return        True if all requested bytes were read, false on EOF or error
 *
 * Early EOF is recorded as an I/O error.
 */
extern bool io_read_exact(IO_HANDLE f, void *d, size_t l) __attribute__((nonnull(1, 2)));

/*!
 * \brief         Return the first I/O error recorded by this instance
 * \param[in]  f  An IO instance
 * \return        The first error recorded by the handle, or zero if none
 */
extern int io_error(IO_HANDLE f) __attribute__((nonnull(1)));

/*!
 * \brief         Sync data waiting to be written
 * \param[in]  f  An IO instance
 *
 * Flushes pending processing buffers and syncs regular files to storage.
 */
extern int io_sync(IO_HANDLE f) __attribute__((nonnull(1)));

/*!
 * \brief         Seek to position in file
 * \param[in]  f  An IO instance
 * \param[in]  o  The offset set position
 * \param[in]  w  Whence the offset should be measured
 * \return        The new offset within the file
 *
 * Seeks the underlying descriptor using lseek(); this does not adjust
 * any buffered transformed data.
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
 * \param[in]  x  Compatibility IV behavior and encrypt/decrypt direction
 * \return        True on success, false otherwise.
 *
 * Initializes encryption or decryption for subsequent I/O. When
 * x.x_encrypt is true, required salt/IV material is generated and
 * written; otherwise it is read from the handle.
 */
extern bool io_encryption_init(IO_HANDLE f, enum gcry_cipher_algos c, enum gcry_md_algos h, enum gcry_cipher_modes m, enum gcry_mac_algos a, uint64_t i, const uint8_t *k, size_t l, io_extra_s x) __attribute__((nonnull(1, 7)));

/*!
 * \brief         Compression initialisation
 * \param[in]  f  An IO instance
 *
 * Enable LZMA compression for writes or decompression for reads on this
 * handle.
 */
extern void io_compression_init(IO_HANDLE f) __attribute__((nonnull(1)));

/*!
 * \brief         Read/Write data checksum initialisation
 * \param[in]  f  An IO instance
 * \param[in]  h  The ID of the hash to use for checksum calculations
 *
 * Start (or reset) the digest used to checksum subsequent data read or
 * written through this handle.
 */
extern void io_encryption_checksum_init(IO_HANDLE f, enum gcry_md_algos h) __attribute__((nonnull(1)));

/*!
 * \brief         Read/Write data checksum generation
 * \param[in]  f  An IO instance
 * \param[in,out] b  Buffer pointer, reallocated as needed with secure allocation
 * \param[out]    l  Digest length in bytes
 *
 * Retrieve the digest of data processed since checksum initialization.
 * If no digest is active, the returned length is zero.
 * The caller owns the returned buffer and must release it with gcry_free().
 */
extern void io_encryption_checksum(IO_HANDLE f, uint8_t **b, size_t *l) __attribute__((nonnull(1)));

/*!
 * \brief         Get the MAC of processed data
 * \param[in]  f  An IO instance
 * \param[in,out] b  Buffer pointer, reallocated as needed with secure allocation
 * \param[out]    l  MAC length in bytes
 *
 * Retrieve the MAC of data processed through this handle. If no MAC is
 * active, the returned length is zero. The caller owns the returned
 * buffer and must release it with gcry_free().
 */
extern void io_encryption_mac(IO_HANDLE f, uint8_t **b, size_t *l) __attribute__((nonnull(1)));

/*!
 * \brief         Enable ECC
 * \param[in]  f  An IO instance
 *
 * Enable Reed-Solomon error correction for subsequent I/O.
 */
extern void io_correction_init(IO_HANDLE f) __attribute__((nonnull(1)));

#endif /* ! _ENCRYPT_CRYPTIO_H_ */
