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

#ifndef _ENCRYPT_DECRYPT_H_
#define _ENCRYPT_DECRYPT_H_

/*!
 * \file    decrypt.h
 * \author  Ashley M Anderson
 * \date    2009-2012
 * \brief   Main encryption routine
 *
 * The main decryption routine; the only visible function is for the
 * initialisation, which produces a crypto instance that can be executed
 * in the background when so desired.
 */

#include "crypto.h"

/*!
 * \brief         Create a new decryption instance
 * \param[in]  i  The source to decrypt
 * \param[in]  o  The plaintext after decryption
 * \param[in]  k  Key data
 * \param[in]  l  Size of key data
 * \return        A new decryption instance
 *
 * Create a new decryption instance, which if the status is INIT, is
 * ready to be executed. Any other status is a failure. If the input and
 * output file names are NULL, stdin/stdout will be used instead.
 */
extern crypto_t *decrypt_init(const char * const restrict, const char * const restrict, const void * const restrict, size_t);

#endif /* ! _ENCRYPT_DECRYPT_H_ */
