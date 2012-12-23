/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_IO_H_
#define _ENCRYPT_IO_H_

/*!
 * \file    io.h
 * \author  Ashley M Anderson
 * \date    2009-2012
 * \brief   IO functions for encrypt
 *
 * Advanced IO functions for encryption/compression. Wraps read/write
 * with crypto functions and LZMA compression for encrypt.
 */

#include <stdint.h> /*!< Necessary include as c99 standard integer types are referenced in this header */

typedef void * IO_HANDLE; /*<! Handle type for IO functions */

/*!
 * \brief         Open a file
 * \param[in]  n  The file name
 * \param[in]  f  File open flags
 * \param[in]  m  File open mode
 *
 * Open a file. Using these IO functions wraps the typical IO functions
 * with encryption and compression support.
 */
extern IO_HANDLE io_open(const char *n, int f, mode_t m);

/*!
 * \brief         Destroy an IO instance
 * \param[in]  h  An IO instance to destroy
 *
 * Close's the file and free resources when no longer needed.
 */
extern int io_close(IO_HANDLE h);

extern IO_HANDLE io_use_stdin(void);
extern IO_HANDLE io_use_stdout(void);

extern bool io_is_stdin(IO_HANDLE h);
extern bool io_is_stdout(IO_HANDLE h);

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
extern ssize_t io_write(IO_HANDLE f, const void *d, size_t l);

/*!
 * \brief         Read data
 * \param[in]  f  An IO instance
 * \param[out] d  The data read
 * \param[in]  l  The length of data to read (size of d)
 * \return        The number of bytes read
 *
 * Read the specified number of bytes from the given file descriptor,
 * performing any necessary operations before it's returned.
 */
extern ssize_t io_read(IO_HANDLE f, void *d, size_t l);

/*!
 * \brief         Sync data waiting to be written
 * \param[in]  f  An IO instance
 *
 * Performs a sync of all outstanding data to be written.
 */
extern int io_sync(IO_HANDLE f);

extern off_t io_seek(IO_HANDLE f, off_t, int);

extern void io_encryption_init(IO_HANDLE f, const char *c, const char *h, const uint8_t *k, size_t l, bool g);
extern void io_compression_init(IO_HANDLE f);
extern void io_encryption_checksum_init(IO_HANDLE f, char *h);
extern void io_encryption_checksum(IO_HANDLE ptr, uint8_t **b, size_t *l);

#endif /* ! _ENCRYPT_IO_H_ */
