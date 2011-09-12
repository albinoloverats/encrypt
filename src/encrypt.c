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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <inttypes.h>
#include <stdbool.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <gcrypt.h>

#define __ENCRYPT__H__
#include "encrypt.h"

#include "common/common.h"
#include "common/list.h"
#include "common/tlv.h"

static bool lib_init = false;
static uint8_t *stream = NULL; 
static size_t length = 0;
static size_t block = 0;

static uint64_t decrypted_size = 0;
static uint64_t bytes_processed = 0;
static status_e status = RUNNING;

extern bool file_encrypted_aux(int t, int64_t f, char **c, char **h)
{
    log_message(LOG_DEBUG, "check for file header");
    if (t == 1)
    {
        void *x = (intptr_t *)f;
        char *n = strdup((char *)x);
        f = open(n, O_RDONLY | O_BINARY);
        free(n);
        if (f < 0)
            return false;
    }
    bool r_val = false;
    uint64_t head[3] = {0x0};
    lseek(f, 0, SEEK_SET);
    read(f, head, sizeof( head ));
    if (head[0] != htonll(HEADER_0) || head[1] != htonll(HEADER_1) || head[2] != htonll(HEADER_2))
        goto clean_up;
    r_val = true;
    if (c == (char **)-1 || h == (char **)-1)
        goto clean_up;
    log_message(LOG_DEBUG, "check for known algorithms");
    uint8_t l = 0;
    read(f, &l, sizeof( uint8_t ));
    *c = calloc(l + 1, sizeof( char ));
    read(f, *c, l);
    *h = strchr(*c, '/');
    **h = '\0';
    (*h)++;
    log_message(LOG_VERBOSE, "file has cipher %s", *c);
    log_message(LOG_VERBOSE, "file has hash %s", *h);
clean_up:
    if (t == 1)
        close(f);
    return r_val;
}

extern status_e main_encrypt(int64_t f, int64_t g, raw_key_t *key, const char *h, const char *c)
{
    status = RUNNING;

    log_message(LOG_DEBUG, "encrypting...");
    /*
     * initialise GNU Crypt library
     */
    if (!lib_init)
        init_gcrypt_library();
    /*
     * get the algorithms
     */
    log_message(LOG_DEBUG, "find algorithms");
    int mdi = 0;
    if (!(mdi = get_algorithm_hash(h)))
        die("could not find hash %s", h);
    int cyi = 0;
    if (!(cyi = get_algorithm_crypt(c)))
        die("could not find cipher %s", c);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_hd_t cy = NULL;
    gcry_cipher_open(&cy, cyi, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * write the default header
     */
    log_message(LOG_DEBUG, "writing standard header");
    uint64_t head[3] = {htonll(HEADER_0), htonll(HEADER_1), htonll(HEADER_2)};
    write(g, head, sizeof( head ));
    char *algos = NULL;
    asprintf(&algos, "%s/%s", get_name_algorithm_crypt(cyi), get_name_algorithm_hash(mdi));
    uint8_t l1 = (uint8_t)strlen(algos);
    write(g, &l1, sizeof( uint8_t ));
    write(g, algos, l1);
    free(algos);

    gcry_cipher_algo_info(cyi, GCRYCTL_GET_BLKLEN, NULL, &block);
    log_message(LOG_VERBOSE, "encryption block size %zu bytes", block);
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    key->h_length = gcry_md_get_algo_dlen(ma);
    key->h_data = malloc(key->h_length);
    if (!key->h_data)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, key->h_data, key->p_data, key->p_length);
    /*
     * setup algorithm (key and IV) - copy no more than the length of the key
     * into a new buffer (pad with 0x0 if necessary) then hash back to the
     * original buffer the IV
     */
    size_t lk = 0;
    gcry_cipher_algo_info(cyi, GCRYCTL_GET_KEYLEN, NULL, &lk);
    uint8_t *buffer = calloc(lk, sizeof( uint8_t ));
    if (!buffer)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    memmove(buffer, key->h_data, lk < key->h_length ? lk : key->h_length);
    gcry_cipher_setkey(cy, buffer, lk);
    uint8_t *iv = calloc(key->h_length, sizeof( uint8_t ));
    if (!iv)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, iv, key->h_data, key->h_length);
    memmove(buffer, iv, lk < key->h_length ? lk : key->h_length);
    free(iv);
    free(key->h_data);
    gcry_cipher_setiv(cy, buffer, lk);
    /*
     * all data written from here on is encrypted
     */
    log_message(LOG_DEBUG, "write source file info");
    /*
     * write simple addition (x ^ y = z) where x, y are random
     * 64bit signed integers
     */
    int64_t x = 0;
    int64_t y = 0;
    gcry_create_nonce(&x, sizeof( x ));
    gcry_create_nonce(&y, sizeof( y ));
    int64_t z = x ^ y;
    log_message(LOG_INFO, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    x = htonll(x);
    y = htonll(y);
    z = htonll(z);
    log_message(LOG_INFO, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    ewrite(g, &x, sizeof( x ), cy);
    ewrite(g, &y, sizeof( y ), cy);
    ewrite(g, &z, sizeof( z ), cy);
    /*
     * write a random length of random bytes
     */
    gcry_create_nonce(&l1, sizeof( l1 ));

    uint8_t *q = realloc(buffer, l1);
    if (!q)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    gcry_create_nonce(buffer, l1);
    ewrite(g, &l1, sizeof( l1 ), cy);
    ewrite(g, buffer, l1, cy);
    /*
     * write various metadata about the original file (if any); start
     * off writing the number of metadata entries (not the total number
     * of bytes) and then a list of tlv's
     *
     * TODO store more than just size (required in all instances)
     */
    l1 = 1;
    ewrite(g, &l1, sizeof( l1 ), cy);

    l1 = TAG_SIZE;
    ewrite(g, &l1, sizeof( l1 ), cy);
    uint16_t l2 = htons(sizeof( uint64_t ));
    ewrite(g, &l2, sizeof( uint16_t ), cy);
    decrypted_size = lseek(f, 0, SEEK_END);
    uint64_t l8 = htonll(decrypted_size);
    ewrite(g, &l8, sizeof( uint64_t ), cy);

    lseek(f, 0, SEEK_SET);
    /*
     * main encryption loop
     */
    log_message(LOG_DEBUG, "starting encryption process");
    q = realloc(buffer, block);
    if (!q)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    for (bytes_processed = 0; bytes_processed < decrypted_size; bytes_processed += block)
    {
        if (status == CANCELLED)
            goto cleanup;
        memset(buffer, 0x00, block);
        size_t y = block;
        if (bytes_processed + block > decrypted_size)
            y = block - (bytes_processed + block - decrypted_size);
        ssize_t r = read(f, buffer, y);
        gcry_md_write(md, buffer, r);
        ewrite(g, buffer, r, cy);
    }
    /*
     * write data checksum
     */
    gcry_md_final(md);
    uint8_t *cs = gcry_md_read(md, ma);
    if (!(q = realloc(buffer, key->h_length)))
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    memmove(buffer, cs, key->h_length);
    ewrite(g, buffer, key->h_length, cy);
    log_binary(LOG_DEBUG, buffer, key->h_length);
    /*
     * add some random data at the end
     */
    log_message(LOG_DEBUG, "appending file random data");
    gcry_create_nonce(&l1, sizeof( l1 ));
    if (!(q = realloc(buffer, l1)))
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    gcry_create_nonce(buffer, l1);
    ewrite(g, buffer, l1, cy);

    status = SUCCEEDED;

cleanup:
    /*
     * done
     */
    free(buffer);
    free(stream);

    gcry_cipher_close(cy);
    gcry_md_close(md);

    return status;
}

extern status_e main_decrypt(int64_t f, int64_t g, raw_key_t *key)
{
    status = RUNNING;

    log_message(LOG_DEBUG, "decrypting...");
    /*
     * initialise GNU Crypt library
     */
    if (!lib_init)
        init_gcrypt_library();
    /*
     * read the standard header
     */
    char *algonc = NULL, *algonh = NULL;
    if (!file_encrypted(f, &algonc, &algonh))
    {
        log_message(LOG_ERROR, "file is not encrypted");
        return FAILED_OTHER;
    }
    int mdi = 0;
    if (!(mdi = get_algorithm_hash(algonh)))
        die("could not find hash %s", algonh);
    int cyi = 0;
    if (!(cyi = get_algorithm_crypt(algonc)))
        die("could not find cipher %s", algonc);
    free(algonc);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_hd_t cy = NULL;
    gcry_cipher_open(&cy, cyi, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);

    gcry_cipher_algo_info(cyi, GCRYCTL_GET_BLKLEN, NULL, &block);
    log_message(LOG_VERBOSE, "decryption block size %zu bytes", block);
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    key->h_length = gcry_md_get_algo_dlen(ma);
    key->h_data = malloc(key->h_length);
    if (!key->h_data)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, key->h_data, key->p_data, key->p_length);
    /*
     * setup algorithm (key and IV)
     */
    size_t lk = 0;
    gcry_cipher_algo_info(cyi, GCRYCTL_GET_KEYLEN, NULL, &lk);
    uint8_t *buffer = calloc(lk, sizeof( uint8_t ));
    if (!buffer)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    memmove(buffer, key->h_data, lk < key->h_length ? lk : key->h_length);
    gcry_cipher_setkey(cy, buffer, lk);
    uint8_t *iv = calloc(key->h_length, sizeof( uint8_t ));
    if (!iv)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, iv, key->h_data, key->h_length);
    memmove(buffer, iv, lk < key->h_length ? lk : key->h_length);
    free(iv);
    free(key->h_data);
    gcry_cipher_setiv(cy, buffer, lk);

    log_message(LOG_DEBUG, "reading source file info");
    /*
     * read three 64bit signed integers and assert that x ^ y = z
     */
    int64_t x = 0;
    int64_t y = 0;
    int64_t z = 0;
    eread(f, &x, sizeof( x ), cy);
    eread(f, &y, sizeof( y ), cy);
    eread(f, &z, sizeof( z ), cy);
    log_message(LOG_DEBUG, "verifying x ^ y = z");
    log_message(LOG_INFO, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    x = ntohll(x);
    y = ntohll(y);
    z = ntohll(z);
    log_message(LOG_INFO, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    if ((x ^ y) != z)
    {
        log_message(LOG_ERROR, "failed decryption attempt");
        free(buffer);
        return FAILED_DECRYPTION;
    }
    /*
     * skip past random data
     */
    uint8_t l1 = 0;
    eread(f, &l1, sizeof( uint8_t ), cy);
    uint8_t *q = realloc(buffer, l1);
    if (!q)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    eread(f, buffer, l1, cy);
    /*
     * read the original file metadata - skip any unknown tag values
     */
    eread(f, &l1, sizeof( l1 ), cy);
    for (int i = 0; i < l1; i++)
    {
        tlv_t tlv;
        eread(f, &tlv.tag, sizeof( uint8_t ), cy);
        eread(f, &tlv.length, sizeof( uint16_t ), cy);
        tlv.length = ntohs(tlv.length);
        tlv.value = malloc(tlv.length);
        eread(f, tlv.value, tlv.length, cy);
        switch (tlv.tag)
        {
            case TAG_SIZE:
                memcpy(&decrypted_size, tlv.value, sizeof( uint64_t ));
                decrypted_size = ntohll(decrypted_size);
                log_message(LOG_DEBUG, "found size: %ju", decrypted_size);
                break;

            default:
                break;
        }
        free(tlv.value);
    }
    /*
     * main decryption loop
     */
    log_message(LOG_DEBUG, "startng decryption process");
    q = realloc(buffer, block);
    if (!q)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    for (bytes_processed = 0; bytes_processed < decrypted_size; bytes_processed += block)
    {
        if (status == CANCELLED)
            goto cleanup;
        memset(buffer, 0x00, block);
        size_t y = block;
        if (bytes_processed + block > decrypted_size)
            y = block - (bytes_processed + block - decrypted_size);
        ssize_t r = eread(f, buffer, y, cy);
        gcry_md_write(md, buffer, r);
        write(g, buffer, r);
    }
    /*
     * compare data checksum
     */
    gcry_md_final(md);
    ma = gcry_md_get_algo(md);
    uint8_t *cs = gcry_md_read(md, ma);
    if (!(q = realloc(buffer, key->h_length)))
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    buffer = q;
    eread(f, buffer, key->h_length, cy);
    log_message(LOG_DEBUG, "verifying checksum");
    if (memcmp(cs, buffer, key->h_length))
    {
        log_message(LOG_ERROR, "checksum verification failed");
        log_binary(LOG_DEBUG, cs, key->h_length);
        log_binary(LOG_DEBUG, buffer, key->h_length);
        status = FAILED_CHECKSUM;
    }
    else
        status = SUCCEEDED;

cleanup:
    /*
     * done
     */
    free(buffer);
    free(stream);

    gcry_cipher_close(cy);
    gcry_md_close(md);

    return status;
}

extern uint64_t get_decrypted_size()
{
    return decrypted_size;
}

extern uint64_t get_bytes_processed()
{
    return bytes_processed;
}

extern status_e get_status()
{
    return status;
}

extern void stop_running()
{
    status = CANCELLED;
}

extern list_t *get_algorithms_hash(void)
{
    if (!lib_init)
        init_gcrypt_library();
    list_t *l = list_create((int (*)(const void *, const void *))strcmp);
    int list[0xff] = {0x00};
    int len = sizeof(list);
    gcry_md_list(list, &len);
    for (int i = 0; i < len; i++)
    {
        const char *n = gcry_md_algo_name(list[i]);
        if (algorithm_is_duplicate(n))
            continue;
        if (!strcasecmp(n, NAME_TIGER192))
            list_append(&l, correct_tiger192(n));
        else if (!strncasecmp(n, NAME_SHA1, strlen(NAME_SHA1) - 1))
            list_append(&l, correct_sha1(n));
        else
            list_append(&l, n);
    }
    return list_sort(&l);
}

extern list_t *get_algorithms_crypt(void)
{
    if (!lib_init)
        init_gcrypt_library();
    list_t *l = list_create((int (*)(const void *, const void *))strcmp);
    int list[0xff] = {0x00};
    int len = sizeof(list);
    gcry_cipher_list(list, &len);
    for (int i = 0; i < len; i++)
    {
        const char *n = gcry_cipher_algo_name(list[i]);
        if (algorithm_is_duplicate(n))
            continue;
        if (!strncasecmp(n, NAME_AES, strlen(NAME_AES)))
            list_append(&l, correct_aes_rijndael(n));
        else if (!strcasecmp(n, NAME_BLOWFISH))
            list_append(&l, correct_blowfish128(n));
        else if (!strcasecmp(n, NAME_TWOFISH))
            list_append(&l, correct_twofish256(n));
        else
            list_append(&l, n);
    }
    return list_sort(&l);
}

static void init_gcrypt_library(void)
{
    /*
     * initialise GNU Crypt library
     */
    log_message(LOG_VERBOSE, "Initialise GNU Crypt library");
    if (!gcry_check_version(GCRYPT_VERSION))
        die("could not find GNU Crypt library");
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    errno = 0; /* need to reset errno after gcry_check_version() */
    lib_init = true;
}

static int ewrite(int64_t f, const void *d, size_t l, gcry_cipher_hd_t c)
{
    if (!stream)
        if (!(stream = calloc(block, sizeof( uint8_t ))))
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    int e = EXIT_SUCCESS;
    size_t i = 0, j = l;
    while (length + j >= block)
    {
        memmove(stream + length, d + i, block - length);
        gcry_cipher_encrypt(c, stream, block, NULL, 0);
        e = write(f, stream, block);
        j = length + j - block;
        i += block;
        memset(stream, 0x00, block);
        length = 0;
    }
    memmove(stream + length, d + (l - j), j);
    length += j;
    return e;
}

static int eread(int64_t f, void * const d, size_t l, gcry_cipher_hd_t c)
{
    if (!stream)
        if (!(stream = calloc(2 * block, sizeof( uint8_t ))))
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    if (length == l)
    {
        memcpy(d, stream, l);
        length = 0;
        return l;
    }
    if (length > l)
    {
        memcpy(d, stream, l);
        length -= l;
        memmove(stream, stream + l, length);
        return l;
    }
    int e = EXIT_SUCCESS;
    memcpy(d, stream, length);
    size_t i = length;
    length = 0;
    while (i < l)
    {
        e = read(f, stream, block);
        gcry_cipher_decrypt(c, stream, block, NULL, 0);
        size_t j = block;
        if (i + block > l)
            j = block - (i + block - l);
        memcpy(d + i, stream, j);
        i += j;
        length = block - j;
    }
    memmove(stream, stream + block - length, length);
    return e < 0 ? e : (int)l;
}

static int get_algorithm_hash(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = {0x00};
    int len = sizeof(list);
    gcry_md_list(list, &len);
    for (int i = 0; i < len; i++)
    {
        const char *x = gcry_md_algo_name(list[i]);
        if (algorithm_is_duplicate(x))
            continue;
        char *y = NULL;
        if (!strncasecmp(x, NAME_SHA1, strlen(NAME_SHA1) - 1))
            y = correct_sha1(x);
        else
            y = strdup(x);
        if (!strcasecmp(y, n))
        {
            free(y);
            log_message(LOG_DEBUG, "found hash algorithm %s", gcry_md_algo_name(list[i]));
            return list[i];
        }
        free(y);
    }
    return 0;
}

static int get_algorithm_crypt(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = {0x00};
    int len = sizeof(list);
    gcry_cipher_list(list, &len);
    for (int i = 0; i < len; i++)
    {
        const char *x = gcry_cipher_algo_name(list[i]);
        char *y = NULL;
        if (!strncasecmp(x, NAME_AES, strlen(NAME_AES)))
            y = correct_aes_rijndael(x);
        else if (!strcasecmp(x, NAME_BLOWFISH))
            y = correct_blowfish128(x);
        else if (!strcasecmp(x, NAME_TWOFISH))
            y = correct_twofish256(x);
        else
            y = strdup(x);
        if (!strcasecmp(y, n))
        {
            log_message(LOG_DEBUG, "found crypto algorithm %s", gcry_cipher_algo_name(list[i]));
            free(y);
            return list[i];
        }
        free(y);
    }
    return 0;
}

static const char *get_name_algorithm_hash(int a)
{
    const char *n = gcry_md_algo_name(a);
    if (strncasecmp(n, NAME_SHA1, strlen(NAME_SHA1) - 1))
        return n;
    return correct_sha1(n);
}

static const char *get_name_algorithm_crypt(int a)
{
    const char *x = gcry_cipher_algo_name(a);
    if (!strncasecmp(x, NAME_AES, strlen(NAME_AES)))
        return correct_aes_rijndael(x);
    else if (!strcasecmp(x, NAME_BLOWFISH))
        return correct_blowfish128(x);
    else if (!strcasecmp(x, NAME_TWOFISH))
        return correct_twofish256(x);
    return x;
}

static char *correct_sha1(const char * const restrict n)
{
    if (strcasecmp(n, NAME_SHA1))
        return strdup(n);
    return strdup(NAME_SHA160);
}

static char *correct_tiger192(const char * const restrict n)
{
#ifndef _WIN32
    return strndup(n, strlen(NAME_TIGER));
#else
    char *x = calloc(strlen(NAME_TIGER) + 1, sizeof( char ));
    memcpy(x, n, strlen(NAME_TIGER));
    return x;
#endif
}

static char *correct_aes_rijndael(const char * const restrict n)
{
    if (!strcasecmp(NAME_AES, n))
        return strdup(n); /* use AES (bits/blocks/etc) */
    /*
     * use rijndael instead of AES as that's the actual cipher name
     */
    char *x = NULL;
    asprintf(&x, "%s%s", NAME_RIJNDAEL, n + strlen(NAME_AES));
    if (!x)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    return x;
}

static char *correct_blowfish128(const char * const restrict n)
{
    return strdup(NAME_BLOWFISH128);
}

static char *correct_twofish256(const char * const restrict n)
{
    return strdup(NAME_TWOFISH256);
}

static bool algorithm_is_duplicate(const char * const restrict n)
{
    if (!strcmp(NAME_TIGER192, n))
        return true;
    return false;
}
