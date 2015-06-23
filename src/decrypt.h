/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2015, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_DECRYPT_H_
#define _ENCRYPT_DECRYPT_H_

/*!
 * \file    decrypt.h
 * \author  Ashley M Anderson
 * \date    2009-2015
 * \brief   Main decryption routine
 *
 * The main decryption routine; the only visible function is for the
 * initialisation, which produces a crypto instance that can be executed
 * in the background when so desired.
 */

#include "crypt.h"

/*!
 * \brief         Create a new decryption instance
 * \param[in]  i  The source to decrypt
 * \param[in]  o  The plaintext after decryption
 * \param[in]  c  The name of the cipher (optional)
 * \param[in]  h  The name of the hash   (optional)
 * \param[in]  m  The name of the mode   (optional)
 * \param[in]  k  Key data
 * \param[in]  l  Size of key data
 * \param[in]  n  Raw - don’t check for a header or any verification
 * \return        A new decryption instance
 *
 * Create a new decryption instance, which if the status is INIT, is
 * ready to be executed. Any other status is a failure. If the input and
 * output file names are NULL, stdin/stdout will be used instead.
 *
 * The cipher/hash/mode should be NULL, then they will be parsed from
 * the encrypted file; the only reason to set them is if there is no
 * header information.
 */
extern crypto_t *decrypt_init(const char * const restrict i, const char * const restrict o, const char * const restrict c, const char * const restrict h, const char * const restrict m, const void * const restrict k, size_t l, bool n) __attribute__((nonnull(6)));

#endif /* ! _ENCRYPT_DECRYPT_H_ */
