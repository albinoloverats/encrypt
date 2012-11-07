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

#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#include <stdint.h>

#define ENCRYPT_VERSION "2012.11"

#define HEADER_VERSION_201108 0x72761df3e497c983LL
#define HEADER_VERSION_201110 0xbb116f7d00201110LL
#define HEADER_VERSION_201211 0x51d28245e1216c45LL
#define HEADER_0 0x3697de5d96fca0faLL
#define HEADER_1 0xc845c2fa95e2f52dLL
#define HEADER_2 HEADER_VERSION_201211

#define NAME_SHA1 "SHA1"
#define NAME_SHA160 "SHA160"
#define NAME_TIGER "TIGER"
#define NAME_TIGER192 "TIGER192"

#define NAME_AES "AES"
#define NAME_RIJNDAEL "RIJNDAEL"
#define NAME_BLOWFISH "BLOWFISH"
#define NAME_BLOWFISH128 "BLOWFISH128"
#define NAME_TWOFISH "TWOFISH"
#define NAME_TWOFISH256 "TWOFISH256"

#define ALGORITHM_BLOCKS_PER_FILE_BLOCK 16
#define BLOCK_SIZE 1024

typedef enum raw_key_e
{
    KEYFILE = 1,
    PASSWORD
}
raw_key_e;

typedef struct key_t
{
    uint8_t *p_data;
    uint64_t p_length;
    uint8_t *h_data;
    uint64_t h_length;
}
raw_key_t;

typedef struct encrypt_t
{
    char *cipher;
    char *hash;
    raw_key_t key;
    bool blocked:1;
    bool compressed:1;
}
encrypt_t;

typedef enum status_e
{
    PREPROCESSING,
    RUNNING,
    SUCCEEDED,
    CANCELLED,
    FAILED_PARAMETER,
    FAILED_ALGORITHM,
    FAILED_DECRYPTION,
    FAILED_TAG,
    FAILED_CHECKSUM,
    FAILED_OTHER
}
status_e;

extern char *FAILED_MESSAGE[];

typedef enum file_info_e
{
    TAG_SIZE,
    TAG_BLOCKED,
    TAG_COMPRESSED,
} __attribute__((packed))
file_info_e;

extern char **get_algorithms_hash(void);
extern char **get_algorithms_crypt(void);

#define IS_ENCRYPTED_ARGS_COUNT(...) IS_ENCRYPTED_ARGS_COUNT2(__VA_ARGS__, 2, 1)
#define IS_ENCRYPTED_ARGS_COUNT2(_1, _2, _, ...) _

#define file_encrypted_1(A)       file_encrypted_aux(__builtin_types_compatible_p(__typeof__( A ), char *) * 1 + \
                                                     __builtin_types_compatible_p(__typeof__( A ), int64_t) * 2, (intptr_t)A, NULL)
#define file_encrypted_2(A, B)    file_encrypted_aux(2, (intptr_t)A, B)
#define file_encrypted(...) CONCAT(file_encrypted_, IS_ENCRYPTED_ARGS_COUNT(__VA_ARGS__))(__VA_ARGS__)

#define LABEL_ENCRYPT "Encrypt"
#define LABEL_DECRYPT "Decrypt"

#define STATUS_NEW_VERSION "A new version of encrypt is available!"
#define STATUS_READY "Ready"
#define STATUS_DONE "Done"

/*!
 * \brief         Check whether the file/stream encrypted
 * \param[in]  t  Type pointed to by p
 * \param[in]  p  Either: pointer to file name, or a file descriptor
 * \param[out] e  (Optional) Pointer to information about encrypted stream
 *                (If not NULL)
 *
 * Determine if the file or stream given is encrypted or not. And possibly
 * provide back information about the encrypted data.
 */
extern uint64_t file_encrypted_aux(int t, intptr_t p, encrypt_t *e);

/*!
 * \brief         Main encryption function
 * \param[in]  f  File descriptor for source
 * \param[in]  g  File descriptor for output
 * \param[in]  e  Details for processing the data
 *
 * Encrypt the input and dump it to the output, performing any user
 * requested operations as necessary.
 */
extern status_e main_encrypt(int64_t f, int64_t g, encrypt_t e);

/*!
 * \brief         Main decryption function
 * \param[in]  f  File descriptor for source
 * \param[in]  g  File descriptor for output
 * \param[in]  e  Details for processing the data
 *
 * Decrypt the input and dump it to the output.
 */
extern status_e main_decrypt(int64_t f, int64_t g, encrypt_t e);

/*!
 * \brief         Get the size of the decrypted data
 * \return        The decrypted size
 *
 * Return the descrypted size of the data (if possible/known).
 */
extern uint64_t get_decrypted_size();

/*!
 * \brief         Get the number of bytes processed
 * \return        The number of bytes processed
 *
 * Return the number of bytes processed so far.
 */
extern uint64_t get_bytes_processed();

/*!
 * \brief         Get the current status
 * \return        The current status
 *
 * Get the current status of what's currently going on
 * internally.
 */
extern status_e get_status();

/*!
 * \brief         Force stop the process
 *
 * Force the background process to stop.
 */
extern void stop_running();

#endif /* _ENCRYPT_H_ */
