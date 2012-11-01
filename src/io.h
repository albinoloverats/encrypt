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

#ifndef _IO_H_
#define _IO_H_

#include <gcrypt.h>
#include <lzma.h>

typedef struct io_params_t
{
    gcry_cipher_hd_t cipher;
    int algorithm;
    lzma_stream *lzma;
}
io_params_t;

extern int lzma_sync(int64_t f, io_params_t *c);
extern ssize_t lzma_write(int64_t f, const void * const restrict d, size_t l, io_params_t *c);
extern ssize_t lzma_read(int64_t f, void * const d, size_t l, io_params_t *c);

extern int enc_sync(int64_t f, io_params_t *c);
extern ssize_t enc_write(int64_t f, const void * const restrict d, size_t l, io_params_t *c);
extern ssize_t enc_read(int64_t f, void * const d, size_t l, io_params_t *c);

#endif /* _IO_H_ */
