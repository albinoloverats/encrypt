/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2013, albinoloverats ~ Software Development
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

/*!
 * \file    crypto.h
 * \author  Ashley M Anderson
 * \date    2009-2013
 * \brief   Main crypto header file
 *
 * What is essentially the parent class for enc/decryption routines.
 * Many of the constants, wrapper functions exist here.
 */

#include <stdint.h>  /*!< Necessary include as c99 standard integer types are referenced in this header */
#include <stdbool.h> /*!< Necessary include as c99 standard boolean type is referenced in this header */
#include <time.h>    /*!< Necessary include as time_t type is referenced in this header */
#include <pthread.h> /*!< Necessary include as pthread handle is referenced in this header */
#include "io.h"      /*!< Necessary as IO_HANDLE type is referenced in this header */

#define ENCRYPT_VERSION "2013.09" /*!< Current version of encrypt application */
#define UPDATE_URL "https://albinoloverats.net/encrypt.release" /*!< URI to check for updates */

#define HEADER_VERSION_201108 0x72761df3e497c983llu /*!< The third 8 bytes of the original version (2011.08) */
#define HEADER_VERSION_201110 0xbb116f7d00201110llu /*!< The third 8 bytes of the second release (2011.10) */
#define HEADER_VERSION_201211 0x51d28245e1216c45llu /*!< The third 8 bytes of the 2012.11 release */
#define HEADER_VERSION_201302 0x5b7132ab5abb3c47llu /*!< The third 8 bytes of the 2013.02 release */

/* TODO consider whether bug fixes should break backwards compatibility */

#define HEADER_VERSION_201309 0xf1f68e5f2a43aa5fllu /*!< The final 8 bytes of the next release */
#define HEADER_VERSION_LATEST HEADER_VERSION_201309 /*!< The third 8 bytes of the current development version */

#define HEADER_0 0x3697de5d96fca0fallu              /*!< The first 8 bytes of an encrypted file */
#define HEADER_1 0xc845c2fa95e2f52dllu              /*!< The second 8 bytes of an encrypted file */
#define HEADER_2 HEADER_VERSION_LATEST              /*!< The third 8 bytes of an encrypted file (version indicator) */

#define BLOCK_SIZE 1024 /*!< Default IO block size */

/*!
 * \brief  Encryption status
 *
 * The value used by the encryption/decryption routines to indicate
 * their status.
 */
typedef enum
{
    STATUS_SUCCESS,                 /*!< Success */
    STATUS_INIT,                    /*!< Initialisation in progress or complete */
    STATUS_RUNNING,                 /*!< Execution is in progress */
    STATUS_CANCELLED,               /*!< User cancelled the operation */
    STATUS_FAILED_INIT,             /*!< Error during initialisation */
    STATUS_FAILED_UNKNOWN_VERSION,  /*!< Failed due to unknown/unsupported encrypt data stream version */
    STATUS_FAILED_UNKNOWN_ALGORITH, /*!< Failed due to unknown/unsupported algorithm (cipher or hash) */
    STATUS_FAILED_DECRYPTION,       /*!< Failed decryption verification (likely wrong password) */
    STATUS_FAILED_UNKNOWN_TAG,      /*!< Failed due to unknown tag */
    STATUS_FAILED_CHECKSUM,         /*!< Data checksum was invalid, possible data corruption */
    STATUS_FAILED_IO,               /*!< Read/write error */
    STATUS_FAILED_OUTPUT_MISMATCH,  /*!< Tried to write directory into a file or vice-versa */
    STATUS_FAILED_OTHER             /*!< Unknown error */
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
    FILE_REGULAR,   /*!< File is a file */
    FILE_SYMLINK,   /*!, File is a soft link */
    FILE_LINK       /*!, File is a hard link */
} __attribute__((packed))
file_type_e;

/*!
 * \brief  File container version
 *
 * An enum of the encrypted file container version. The values
 * correspond to the #defined values.
 */
typedef enum
{
    VERSION_UNKNOWN = 0,                     /*!< Unknown version, or not encrypted  */
    VERSION_2011_08 = HEADER_VERSION_201108, /*!< Version 2011.08 */
    VERSION_2011_10 = HEADER_VERSION_201110, /*!< Version 2011.10 */
    VERSION_2012_11 = HEADER_VERSION_201211, /*!< Version 2012.11 */
    VERSION_2013_02 = HEADER_VERSION_201302, /*!< Version 2013.02 */
    VERSION_2013_09 = HEADER_VERSION_201309, /*!< Version 2013.0 (current development version) */
    VERSION_CURRENT = HEADER_VERSION_LATEST  /*!< Next release / current development version */
}
version_e;

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
        /*
         * TODO add tags for stat data (mode, atime, ctime, mtime)
         */
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
    uint64_t offset; /*!< Progress */
    uint64_t size;   /*!< Maximum */
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

    pthread_t *thread;        /*!< Execution thread */
    void *(*process)(void *); /*!< Main processing function; used by execute() */
    crypto_status_e status;   /*!< Current status */
    progress_t current;       /*!< Progress of current file */
    progress_t total;         /*!< Overall progress (all files) */

    void *misc;               /*!< Miscellaneous data, specific to either encryption or decryption only */

    version_e version;        /*!< Version of the encrypted file container */
    uint64_t blocksize;       /*!< Whether data is split into blocks, and thus their size */
    bool compressed:1;        /*!< Whether data stream is compress */
    bool directory:1;         /*!< Whether data stream is a directory hierarchy */
    bool follow_links:1;      /*!< Whether encrypt should follow symlinks (true: store the file it points to; false: store the link itself */
}
crypto_t;

/*!
 * \brief          Initialise libgcrypt library
 *
 * Initialise the libgcrypt library. Subsequent calls to the function
 * are ignored.
 */
extern void init_crypto(void);

/*!
 * \brief          Execute crypto routine
 * \params[in]  c  Cryptographic instance
 *
 * Launches a background thread that performs the desired cryptographic
 * action setup by either encrypt_init() or decrypt_init(). The task is
 * backgrounded to allow the foreground to keep the UI updated (if
 * necessary).
 */
extern void execute(crypto_t *c) __attribute__((nonnull(1)));

/*!
 * \brief         Get a meaningful status message
 * \param[in]  c  Cryptographic instance
 * \return        Status message
 *
 * Get a meaningful status message which corresponds to the current
 * status of the crypto instance.
 */
extern const char *status(const crypto_t * const restrict c) __attribute__((nonnull(1)));

/*!
 * \brief         Deinitialise a cryptographic instance
 * \param[in]  c  A pointer to the instance to release
 *
 * Free's the resources used by the crypto instance after it is no
 * longer needed.
 */
extern void deinit(crypto_t **c) __attribute__((nonnull(1)));

/*!
 * \brief         Get list of usable ciphers
 * \return        An array of char* of cipher names
 *
 * Get an array of strings which lists the names of usable cipher
 * algorithms. NB: The array is allocated statically and SHOULD NOT be
 * free'd (or otherwise altered).
 */
extern const char **list_of_ciphers(void) __attribute__((pure));

/*!
 * \brief         Get list of usable hashes
 * \return        An array of char* of hash names
 *
 * Get an array of strings which lists the names of usable hash
 * algorithms. NB: The array is allocated statically and SHOULD NOT be
 * free'd (or otherwise altered).
 */
extern const char **list_of_hashes(void) __attribute__((pure));

/*!
 * \brief         Get cipher ID, given its name
 * \param[in]  n  Cipher name
 * \return        The ID used by libgcrypt
 *
 * Get the ID used internally by libgcrypt for the given cipher name.
 */
extern int cipher_id_from_name(const char * const restrict n) __attribute__((pure, nonnull(1)));

/*!
 * \brief         Get hash ID, given its name
 * \param[in]  n  Hash name
 * \return        The ID used by libgcrypt
 *
 * Get the ID used internally by libgcrypt for the given hash name.
 */
extern int hash_id_from_name(const char * const restrict n) __attribute__((pure, nonnull(1)));


#define IS_ENCRYPTED_ARGS_COUNT(...) IS_ENCRYPTED_ARGS_COUNT2(__VA_ARGS__, 3, 2, 1)
#define IS_ENCRYPTED_ARGS_COUNT2(_1, _2, _3, _, ...) _

#define is_encrypted_1(A)        is_encrypted_aux(false, A, NULL, NULL)
#define is_encrypted_3(A, B, C)  is_encrypted_aux(true, A, B, C)
#define is_encrypted(...) CONCAT(is_encrypted_, IS_ENCRYPTED_ARGS_COUNT(__VA_ARGS__))(__VA_ARGS__)

/*!
 * \brief         Determine if a file is encrypted
 * \param[in]  b  Whether passing in 3 arguments or not
 * \param[in]  n  The file path/name
 * \param[out] c  Pointer to cipher (free when no longer needed)
 * \param[out] h  Pointer to hash (free when no longer needed)
 * \return        The version of encrypted used
 *
 * Returns the version of encrypt used to encrypt the file, or 0 if it's
 * not encrypted.
 */
extern version_e is_encrypted_aux(bool b, const char *n, char **c, char **h) __attribute__((nonnull(2)));

/*!
 * \brief         Log which version the file is encrypted with
 * \param[in]  m  The bytes read from the file
 * \return        The version; 0 if unknown
 *
 * Logs which version of encrypted a file was encrypted with; the actual
 * return value is the same as parameter m. This function (more than
 * anything) removes duplicated code.
 */
extern version_e check_version(uint64_t m);

/*!
 * \brief         Get the version as a string
 * \param[in]  v  The version
 * \return        The version as a string
 *
 * Get the version string which corresponds to the version enum.
 */
extern const char *get_version(version_e v);

/*!
 * \brief         Parse the version from a string
 * \param[in]  v  The version as a string
 * \return        The version
 *
 * Parse the version string and return the corresponds version enum.
 */
extern version_e parse_version(char *v);

#endif /* ! _ENCRYPT_CRYPTO_H */
