/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_ENCRYPT_H_
#define _ENCRYPT_ENCRYPT_H_

/*!
 * \file    encrypt.h
 * \author  Ashley M Anderson
 * \date    2009-2014
 * \brief   Main encryption routine
 *
 * The main encryption routine; the only visible function is for the
 * initialisation, which produces a crypto instance that can be executed
 * in the background when so desired.
 */

#include "crypto.h"

/*!
 * \brief         Create a new encryption instance
 * \param[in]  i  The source to encrypt
 * \param[in]  o  The output after encryption
 * \param[in]  c  The name of the cipher
 * \param[in]  h  The name of the hash
 * \param[in]  m  The name of the mode
 * \param[in]  k  Key data
 * \param[in]  l  Size of key data
 * \param[in]  n  Raw - don't write a header or any verification
 * \param[in]  x  Compress data before encryption
 * \param[in]  f  Follow symlinks
 * \param[in]  v  Backwards compatibility version
 * \return        A new encryption instance
 *
 * Create a new encryption instance, which if the status is INIT, is
 * ready to be executed. Any other status is a failure. If the input and
 * output file names are NULL, stdin/stdout will be used instead.
 */
extern crypto_t *encrypt_init(const char * const restrict i,
                              const char * const restrict o,
                              const char * const restrict c,
                              const char * const restrict h,
                              const char * const restrict m,
                              const void * const restrict k,
                              size_t l,
                              bool n,
                              bool x,
                              bool f,
                              version_e v) __attribute__((nonnull(3, 4, 5, 6)));

#endif /* ! _ENCRYPT_ENCRYPT_H */
