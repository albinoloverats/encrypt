/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2026, albinoloverats ~ Software Development
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

#if !defined _ENCRYPT_DECRYPT_H_
#define _ENCRYPT_DECRYPT_H_

/*!
 * \file    decrypt.h
 * \author  Ashley M Anderson
 * \date    2009-2026
 * \brief   Main decryption routine
 *
 * The main decryption routine; the only visible function is for the
 * initialisation, which produces a crypto instance that can be executed
 * in the background when so desired.
 */

#include "crypt.h"

/*!
 * \brief         Create a new decryption instance
 * \param[in]  i  Source path, or NULL to read from standard input
 * \param[in]  o  Output path, or NULL to write to standard output
 * \param[in]  c  The name of the cipher (optional)
 * \param[in]  h  The name of the hash   (optional)
 * \param[in]  m  The name of the mode   (optional)
 * \param[in]  a  The name of the MAC    (optional)
 * \param[in]  k  Key bytes when l is nonzero; otherwise a key-file path
 * \param[in]  l  Key length in bytes, or zero when k names a key file
 * \param[in]  n  KDF iterations for raw input that has no container metadata
 * \param[in]  r  Raw mode: input has no container header or verification data
 * \return        A crypto instance; check its status for initialization success
 *
 * If the returned instance has STATUS_INIT, it is ready for execute().
 * Otherwise its status describes the initialization failure. A NULL
 * source or output uses standard input or output respectively.
 *
 * In non-raw mode, algorithm settings are read from the encrypted
 * container. Raw mode requires the cipher, hash, mode, and MAC names to
 * be supplied because the input contains no algorithm metadata.
 */
extern crypto_s *decrypt_init(const char * const restrict i,
                              const char * const restrict o,
                              const char * const restrict c,
                              const char * const restrict h,
                              const char * const restrict m,
                              const char * const restrict a,
                              const void * const restrict k,
                              size_t l, uint64_t n, bool r) __attribute__((nonnull(7)));

#endif /* ! _ENCRYPT_DECRYPT_H_ */
