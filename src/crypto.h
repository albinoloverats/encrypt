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

#ifndef _ENCRYPT_CRYPTO_H_
#define _ENCRYPT_CRYPTO_H_

#include <stdint.h> /*!< Necessary include as c99 standard integer types are referenced in this header */
#include <stdbool.h> /*!< Necessary include as c99 standard boolean type is referenced in this header */

#include <time.h> /*!< Necessary include as time_t type is referenced in this header */
#include <pthread.h> /*!< Necessary include as pthread handle is referenced in this header */

#include "io.h"

#define ENCRYPT_VERSION "2013.00"
#define UPDATE_URL "https://albinoloverats.net/encrypt.release"

#define HEADER_VERSION_201108 0x72761df3e497c983llu /*!< The third 8 bytes of the original version (2011.08) */
#define HEADER_VERSION_201110 0xbb116f7d00201110llu /*!< The third 8 bytes of the second release (2011.10) */
#define HEADER_VERSION_201211 0x51d28245e1216c45llu /*!< The third 8 bytes of the current release (2012.11) */
#define HEADER_VERSION_NEXT   0xa5a5a5a5a5a5a5a5llu /*!< The third 8 bytes of the current development version */
#define HEADER_0 0x3697de5d96fca0fallu              /*!< The first 8 bytes of an encrypted file */
#define HEADER_1 0xc845c2fa95e2f52dllu              /*!< The second 8 bytes of an encrypted file */
#define HEADER_2 HEADER_VERSION_NEXT                /*!< The third 8 bytes of an encrypted file (version indicator) */

#define BLOCK_SIZE 1024 /*!< Default IO block size */

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

/*!
 * \brief  Encryption status
 *
 * The value used by the encryption/decryption routines to indicate
 * their status.
 */
typedef enum
{
    SUCCESS,                 /*!< Success */
    INIT,                    /*!< Initialisation in progress or complete */
    RUNNING,                 /*!< Execution is in progress */
    CANCELLED,               /*!< User cancelled the operation */
    FAILED_INIT,             /*!< Error during initialisation */
    FAILED_UNKNOWN_VERSION,  /*!< Failed due to unknown/unsupported encrypt data stream version */
    FAILED_UNKNOWN_ALGORITH, /*!< Failed due to unknown/unsupported algorithm (cipher or hash) */
    FAILED_DECRYPTION,       /*!< Failed decryption verification (likely wrong password) */
    FAILED_UNKNOWN_TAG,      /*!< Failed due to unknown tag */
    FAILED_CHECKSUM,         /*!< Data checksum was invalid, possible data corruption */
    FAILED_IO,               /*!< Read/write error */
    FAILED_OUTPUT_MISMATCH,  /*!< Tried to write directory into a file or vice-versa */
    FAILED_OTHER             /*!< Unknown error */
}
crypto_status_e;

/*!
 * \brief  File type tags
 *
 * File type when encryption entire directory hierarchies. Packed as it
 * will only be stored as a single byte in the encrypted data. (Whether
 * it's packed in memory is not actually up to us, but hey, we tried.)
 */
typedef enum
{
    FILE_DIRECTORY, /*!< File is a directory */
    FILE_REGULAR    /*!< File is a file */
} __attribute__((packed))
file_type_e;

/*!
 * \brief  Stream metadata tags
 *
 * Tag values used to provide metadata capabilities to the encrypted
 * data stream. NB new tags obviously break backward compatibility.
 */
typedef enum
{
    TAG_SIZE,       /*!< Encrypted data size */
    TAG_BLOCKED,    /*!< Data is split into blocks (of given size) */
    TAG_COMPRESSED, /*!< Data is compressed */
    TAG_DIRECTORY   /*!< Data is a directory hierarchy */
} __attribute__((packed))
stream_tags_e;

/*!
 * \brief  Current progress
 *
 * Provide the foreground thread a way to check on the progress. Thus a
 * percentage can be calculated using 100 * offset / size. Either the
 * number of bytes, or directory entries depending on what you're taking
 * the progress of.
 */
typedef struct
{
    time_t started;  /*!< Start time */
    uint64_t offset; /*!< Progress */
    uint64_t size;   /*!< Maximum */
    uint64_t total;  /*<! Total bytes processed */
}
progress_t;

/*!
 * \brief  Main cryptographic structure
 *
 * This is essentially the cryptographic handle, produced by the encrypt
 * or decrypt initialisation functions and given to execute. Some
 * information can be extracted, such as progress and status.
 */
typedef struct
{
    IO_HANDLE source;         /*!< Where to get data from */
    IO_HANDLE output;         /*!< Where to put data to */

    char *path;
    char *cipher;
    char *hash;
    uint8_t *key;
    size_t length;

    void *(*process)(void *); /*!< Main processing function; used by execute() */
    crypto_status_e status;   /*!< Current status */
    progress_t current;       /*!< Progress of current file */
    progress_t total;         /*!< Overall progress (all files) */

    uint64_t blocksize;       /*!< Whether data is split into blocks, and thus their size */
    bool compressed:1;        /*!< Whether data stream is compress */
    bool directory:1;         /*!< Whether data stream is a directory hierarchy */
}
crypto_t;

extern void init_crypto(void);

/*!
 * \brief          Execute crypto routine
 * \params[in]  c  Cryptographic instance
 * \return         A thread instance
 *
 * Launches a background thread (which is returned and can then be
 * controlled) that performs the desired cryptographic action setup by
 * either encrypt_init() or decrypt_init(). The task is backgrounded to
 * allow the foreground to keep the UI updated (if necessary).
 */
extern pthread_t execute(crypto_t *c);

/*!
 * \brief         Get a meaningful status message
 * \param[in]  c  Cryptographic instance
 * \return        Status message
 *
 * Get a meaningful status message which corresponds to the current
 * status of the crypto instance.
 */
extern const char *status(const crypto_t * const restrict c);

/*!
 * \brief         Deinitialise a cryptographic instance
 * \param[in]  c  A pointer to the instance to release
 *
 * Free's the resources used by the crypto instance after it is no
 * longer needed.
 */
extern void deinit(crypto_t **c);

extern char **list_of_ciphers(void);
extern char **list_of_hashes(void);

extern int cipher_id_from_name(const char * const restrict n);
extern int hash_id_from_name(const char * const restrict n);

extern bool file_encrypted(const char *n);

#endif /* ! _ENCRYPT_CRYPTO_H */
