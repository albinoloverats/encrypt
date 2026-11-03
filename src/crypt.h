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

#ifndef _ENCRYPT_CRYPT_H_
#define _ENCRYPT_CRYPT_H_

/*!
 * \file    crypt.h
 * \author  Ashley M Anderson
 * \date    2009-2025
 * \brief   Main crypt header file
 *
 * Shared types, constants, and APIs for encryption and decryption.
 */

#include <stdint.h>     /*!< Necessary include as c99 standard integer types are referenced in this header */
#include <stdbool.h>    /*!< Necessary include as c99 standard boolean type is referenced in this header */
#include <time.h>       /*!< Necessary include as time_t type is referenced in this header */
#include <pthread.h>    /*!< Necessary include as pthread handle is referenced in this header */
#include <gcrypt.h>     /*!< Necessary include as encryption modes are referenced in this header */

/* submodule includes */

#include "src/cli.h" /*!< Used for progress bar on command line */

/* project includes */

#include "crypt_io.h"   /*!< Necessary as IO_HANDLE type is referenced in this header */

#define ENCRYPT "encrypt"
#define ENCRYPT_VERSION "2025.05" /*!< Current (display) version of encrypt application */
#define UPDATE_URL "https://albinoloverats.net/encrypt.release" /*!< URI to check for updates */
#define PROJECT_URL "https://albinoloverats.net/projects/encrypt"
#define ENCRYPTRC ".encryptrc"

#if defined _WIN32
	#define DOWNLOAD_URL_TEMPLATE "https://albinoloverats.net/downloads/encrypt/%s/encrypt-%s-install.exe"
#elif defined __APPLE__
	#define DOWNLOAD_URL_TEMPLATE "https://albinoloverats.net/downloads/encrypt/%s/encrypt-%s.dmg"
#else
	#define DOWNLOAD_URL_TEMPLATE NULL
#endif

#define FINISHING_UP "Finishing up"

#define HEADER_0 0x3697de5d96fca0fallu              /*!< The first 8 bytes of an encrypted file */
#define HEADER_1 0xc845c2fa95e2f52dllu              /*!< The second 8 bytes of an encrypted file */

#define BLOCK_SIZE     1024 /*!< Default IO block size; not currently configurable */
#define KEY_ITERATIONS_201709   1024 /*!< Default number of iterations for key derivation algorithm for version 2017.09 */
#define KEY_ITERATIONS_DEFAULT 32768 /*!< Default number of iterations for key derivation function for version 2020.01 (now user configurable) */
/* 32,768 : 147,055μs 147.06ms 0.14s / 1,424ms */

#define DEFAULT_CIPHER "AES"
#define DEFAULT_HASH "SHA256"
#define DEFAULT_MODE "OFB"
#define DEFAULT_MAC "HMAC_SHA512"

/*!
 * \brief  Encryption status
 *
 * The value used by the encryption/decryption routines to indicate
 * their status.
 */
typedef enum
{
	/* success and running states */
	STATUS_SUCCESS,                         /*!< Success */
	STATUS_INIT,                            /*!< Initialisation in progress or complete */
	STATUS_RUNNING,                         /*!< Execution is in progress */
	STATUS_CANCELLED,                       /*!< User cancelled the operation */
	/* failures - decryption did not complete */
	STATUS_FAILED_INIT,                     /*!< Error during initialisation */
	STATUS_FAILED_UNKNOWN_VERSION,          /*!< Failed due to unknown/unsupported encrypt data stream version */
	STATUS_FAILED_UNKNOWN_CIPHER_ALGORITHM, /*!< Cipher algorithm is unknown or unsupported */
	STATUS_FAILED_UNKNOWN_HASH_ALGORITHM,   /*!< Hash algorithm is unknown or unsupported */
	STATUS_FAILED_UNKNOWN_CIPHER_MODE,      /*!< Cipher mode is unknown or unsupported */
	STATUS_FAILED_UNKNOWN_MAC_ALGORITHM,    /*!< MAC algorithm is unknown or unsupported */
	STATUS_FAILED_GCRYPT_INIT,              /*!< Failed to initialise cryptographic processing */
	STATUS_FAILED_CIPHER_MODE_MISMATCH,     /*!< Cipher mode not compatible with cipher algorithm */
	STATUS_FAILED_DECRYPTION,               /*!< Failed decryption verification (likely wrong password) */
	STATUS_FAILED_UNKNOWN_TAG,              /*!< Failed due to an unsupported or unrecognized metadata tag */
	STATUS_FAILED_IO,                       /*!< Read/write error */
	STATUS_FAILED_LZMA,                     /*!< LZMA decompression error */
	STATUS_FAILED_KEY,                      /*!< Key generation/read error */
	STATUS_FAILED_OUTPUT_MISMATCH,          /*!< Invalid, conflicting, or incompatible output target */
	STATUS_FAILED_OTHER,                    /*!< Unknown error */
	/* warnings - decryption finished but with possible errors */
	STATUS_WARNING_CHECKSUM,                /*!< Data checksum was invalid, possible data corruption */
	STATUS_WARNING_LINK                     /*!< Warning where links are unsupported by the system */
}
crypto_status_e;

/*!
 * \brief  File type tags
 *
 * File type when encryption entire directory hierarchies. Packed as it
 * will only be stored as a single byte in the encrypted data. (Whether
 * it’s packed in memory is not actually up to us, but hey, we tried.)
 */
typedef enum
{
	FILE_DIRECTORY, /*!< File is a directory */
	FILE_REGULAR,   /*!< File is a file */
	FILE_SYMLINK,   /*!< File is a symbolic link */
	FILE_LINK       /*!< File is a hard link */
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
	VERSION_UNKNOWN = 0, /*!< Unknown version, or not encrypted  */
	VERSION_2011_08,     /*!< Version 2011.08 */
	VERSION_2011_10,     /*!< Version 2011.10 */
	VERSION_2012_11,     /*!< Version 2012.11 */
	VERSION_2013_02,     /*!< Version 2013.02 */
	VERSION_2013_11,     /*!< Version 2013.11 */
	VERSION_2014_06,     /*!< Version 2014.06 */
	VERSION_2015_01,     /*!< Version 2015.01 */
	VERSION_2015_10,     /*!< Version 2015.10 */
	VERSION_2017_09,     /*!< Version 2017.09 */
	VERSION_2020_01,     /*!< Version 2020.01 */
	VERSION_2022_01,     /*!< Version 2022.01 */
	VERSION_2024_01,     /*!< Version 2024.01 */
	VERSION_2025_05,     /*!< Version 2025.05 */
	VERSION_CURRENT = VERSION_2025_05 /*!< Next release / current development version */
}
version_e;

/*!
 * \brief  Stream metadata tags
 *
 * Tag values used to describe the encrypted data stream. Older readers
 * may ignore tags they do not recognize, depending on the container version.
 */
typedef enum
{
	TAG_SIZE,       /*!< Encrypted data size */
	TAG_BLOCKED,    /*!< Data is split into blocks (of given size) */
	TAG_COMPRESSED, /*!< Data is compressed */
	TAG_DIRECTORY,  /*!< Data is a directory hierarchy */
	TAG_FILENAME    /*!< Single file name */
	/*
	 * TODO add tags for stat data (mode, atime, ctime, mtime)
	 */
} __attribute__((packed))
stream_tags_e;

#if 0
/*!
 * \brief  Key data structure
 *
 * Key the user key data/length together
 */
typedef struct
{
	uint8_t *data;  /*!< Key data */
	size_t length; /*!< Key data length */
}
raw_key_s;
#endif

/*!
 * \brief  Main cryptographic structure
 *
 * This is essentially the cryptographic handle, produced by the encrypt
 * or decrypt initialisation functions and given to execute. Some
 * information can be extracted, such as progress and status.
 */
typedef struct
{
	IO_HANDLE source;              /*!< Where to get data from */
	IO_HANDLE output;              /*!< Where to put data to */

	char *path;                    /*!< Source or destination path used for directory operations */
	char *name;                    /*!< Name of single encrypted file */
	enum gcry_cipher_algos cipher; /*!< The chosen cipher algorithm */
	enum gcry_md_algos hash;       /*!< The chosen key hash algorithm */
	enum gcry_cipher_modes mode;   /*!< The chosen encryption mode */
	enum gcry_mac_algos mac;       /*!< The chosen MAC algorithm */

#if 0
	raw_key_s *raw_key;            /*!< Encryption key (NB Not yet used) */
#endif
	uint8_t *key;                  /*!< Key data */
	size_t length;                 /*!< Key data length */
	uint64_t kdf_iterations;       /*!< KDF iterations */

	pthread_t *thread;             /*!< Joinable execution thread, or NULL when run synchronously */
	void *(*process)(void *);      /*!< Encryption or decryption worker invoked by execute() */
	crypto_status_e status;        /*!< Current status */
	cli_progress_s current;        /*!< Progress of the current file or stream */
	cli_progress_s total;          /*!< Overall progress for all files or the stream */

	void *misc;                    /*!< Miscellaneous data, specific to either encryption or decryption only */

	version_e version;             /*!< Version of the encrypted file container */
	uint64_t blocksize;            /*!< Data framing block size, or zero when not block-framed */
	bool compressed:1;             /*!< Whether the data stream is compressed */
	bool directory:1;              /*!< Whether data stream is a directory hierarchy */
	bool follow_links:1;           /*!< Whether encryption follows symlinks or stores the links themselves */
	bool raw:1;                    /*!< Whether to omit/skip the container header and verification data */
}
crypto_s;

/*!
 * \brief          Execute crypto routine
 * \param[in]  c  Cryptographic instance
 *
 * Runs the worker configured by encrypt_init() or decrypt_init(). In a
 * normal build it starts a joinable background thread; debug builds run
 * the worker synchronously.
 */
extern void execute(crypto_s *c) __attribute__((nonnull(1)));

/*!
 * \brief         Get a meaningful status message
 * \param[in]  c  Cryptographic instance
 * \return        Status message
 *
 * Get a meaningful status message which corresponds to the current
 * status of the crypto instance.
 */
extern const char *status(const crypto_s * const restrict c) __attribute__((nonnull(1)));

/*!
 * \brief         Deinitialise a cryptographic instance
 * \param[in]  c  A pointer to the instance to release
 *
 * Joins any worker thread, releases the instance's resources, and sets
 * the caller's pointer to NULL.
 */
extern void deinit(crypto_s **c) __attribute__((nonnull(1)));

#if 0
/*!
 * \brief         Destroy key structure
 * \param[in]  k  A pointer to a key structure
 *
 * Free the given key data structure; the key data is cleared (memset to
 * zero and then freed).
 */
extern void key_free(raw_key_s **k);
#endif


#define IS_ENCRYPTED_ARGS_COUNT(...) IS_ENCRYPTED_ARGS_COUNT2(__VA_ARGS__, 6, 5, 4, 3, 2, 1)
#define IS_ENCRYPTED_ARGS_COUNT2(_1, _2, _3, _4, _5, _6, _, ...) _

#define is_encrypted_1(A)                 is_encrypted_aux(false, A, NULL, NULL, NULL, NULL, NULL)
#define is_encrypted_6(A, B, C, D, E, F)  is_encrypted_aux(true, A, B, C, D, E, F)
#define is_encrypted(...) CONCAT(is_encrypted_, IS_ENCRYPTED_ARGS_COUNT(__VA_ARGS__))(__VA_ARGS__)

/*!
 * \brief         Read a complete key file into secure memory
 * \param[in]  path Key-file path
 * \param[out] data Receives the allocated key bytes
 * \param[out] size Receives the key length
 * \return         True when a nonempty key file was read completely
 *
 * Fails if the file cannot be opened, sized, rewound, or read completely.
 * The returned key bytes are allocated with libgcrypt secure memory and
 * must be released with gcry_free().
 */
extern bool read_key_file(const char *path, uint8_t **data, size_t *size) __attribute__((nonnull(1, 2, 3)));

/*!
 * \brief         Determine if a file is encrypted
 * \param[in]  b  Internal selector for whether metadata outputs were requested
 * \param[in]  n  File path/name to inspect
 * \param[in,out] c  Address of cipher-name pointer; set *c non-NULL to request output
 * \param[in,out] h  Address of hash-name pointer; set *h non-NULL to request output
 * \param[in,out] m  Address of mode-name pointer; set *m non-NULL to request output
 * \param[in,out] a  Address of MAC-name pointer; set *a non-NULL to request output
 * \param[out] k  Optional KDF-iteration output
 * \return        Detected container version, or VERSION_UNKNOWN
 *
 * The one-argument is_encrypted(path) form checks only the container
 * version. In the six-argument form, provide addresses for all four
 * string pointers and set each requested output pointer to a non-NULL
 * value; it is replaced with an allocated string. Returned strings are
 * caller-owned and must be freed. The KDF output may be NULL.
 */
extern version_e is_encrypted_aux(bool b, const char *n, char **c, char **h, char **m, char **a, uint64_t *k) __attribute__((nonnull(2)));

/*!
 * \brief         Determine which container version a file uses
 * \param[in]  m  The bytes read from the file
 * \return        The version; 0 if unknown
 *
 * Map a container's numeric version identifier to its version enum.
 */
extern version_e check_version(uint64_t m);

/*!
 * \brief         Get the version ID
 * \param[in]  v  The version
 * \return        The version ID
 *
 * Return the numeric container identifier corresponding to the version.
 */
extern uint64_t get_version(version_e v);

/*!
 * \brief         Get the version as a string
 * \param[in]  v  The version
 * \return        The version as a string
 *
 * Return a static version string corresponding to the version.
 */
extern const char *get_version_string(version_e v);

/*!
 * \brief         Parse the version from a string
 * \param[in]  v  The version as a string
 * \return        The version
 *
 * Match a version string to its enum. A NULL or unrecognized string
 * selects VERSION_CURRENT.
 */
extern version_e parse_version(const char *v);

#endif /* ! _ENCRYPT_CRYPT_H */
