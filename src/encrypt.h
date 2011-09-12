/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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

#include "common/list.h"

#define E_ENCRYPT "encrypt"
#define E_VERSION "2011.09"

#define HEADER_0 0x3697de5d96fca0faLL
#define HEADER_1 0xc845c2fa95e2f52dLL
#define HEADER_2 0x72761df3e497c983LL

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

typedef enum status_e
{
    PREPROCESSING,
    RUNNING,
    SUCCEEDED,
    CANCELLED,
    FAILED_INITIALISATION,
    FAILED_DECRYPTION,
    FAILED_CHECKSUM,
    FAILED_OTHER
}
status_e;

typedef enum file_info_e
{
    TAG_SIZE
}
file_info_e;

extern list_t *get_algorithms_hash(void);
extern list_t *get_algorithms_crypt(void);

#define IS_ENCRYPTED_ARGS_COUNT(...) IS_ENCRYPTED_ARGS_COUNT2(__VA_ARGS__, 3, 2, 1)
#define IS_ENCRYPTED_ARGS_COUNT2(_1, _2, _3, _, ...) _

#define file_encrypted_1(A)       file_encrypted_aux(__builtin_types_compatible_p(typeof( A ), char *) * 1 + \
                                                     __builtin_types_compatible_p(typeof( A ), int64_t) * 2, A, (char **)-1, (char **)-1)
#define file_encrypted_2(A, B)    file_encrypted_aux(2, A, B, (char **)-1)
#define file_encrypted_3(A, B, C) file_encrypted_aux(2, A, B, C)

#define file_encrypted(...) COMMON_CONCAT(file_encrypted_, IS_ENCRYPTED_ARGS_COUNT(__VA_ARGS__))(__VA_ARGS__)

extern bool file_encrypted_aux(int t, int64_t f, char **c, char **h); // free(c), don't free(h)

extern status_e main_encrypt(int64_t f, int64_t g, raw_key_t *k, const char *h, const char *c);
extern status_e main_decrypt(int64_t f, int64_t g, raw_key_t *k);

extern uint64_t get_decrypted_size();
extern uint64_t get_bytes_processed();
extern status_e get_status();
extern void stop_running();

#endif /* _ENCRYPT_H_ */

#ifdef __ENCRYPT__H__

static void init_gcrypt_library(void);

static int ewrite(int64_t f, const void *d, size_t l, gcry_cipher_hd_t c);
static int eread(int64_t f, void * const d, size_t l, gcry_cipher_hd_t c);

static int get_algorithm_hash(const char * const restrict n);
static int get_algorithm_crypt(const char * const restrict n);

static const char *get_name_algorithm_hash(int a);
static const char *get_name_algorithm_crypt(int a);

static char *correct_sha1(const char * const restrict n);
static char *correct_tiger192(const char * const restrict n);
static char *correct_aes_rijndael(const char * const restrict n);
static char *correct_blowfish128(const char * const restrict n);
static char *correct_twofish256(const char * const restrict n);

static bool algorithm_is_duplicate(const char * const restrict n);

#undef __ENCRYPT__H__
#endif /* __ENCRYPT__H__ */
