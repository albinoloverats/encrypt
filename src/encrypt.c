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
static uint64_t decrypted_size = 0;
static uint64_t bytes_processed = 0;
static status_e status = RUNNING;

char *FAILED_MESSAGE[] =
{
    NULL,
    NULL,
    NULL, /* "Success", */ /* ignore success, no message, just finish */
    "User cancelled operation!",
    "Invalid parameter!",
    "Unsupported algorithm!",
    "Decryption verification failed!",
    "Unknown tag value!",
    "Finished but with possible file corruption!"
    "An unknown error has occurred!",
};

extern bool file_encrypted_aux(int t, int64_t f, encrypt_t *e)
{
    log_message(LOG_INFO, "check for file header");
    if (t == 1)
    {
        void *x = (intptr_t *)f;
        char *n = strdup((char *)x);
        f = open(n, O_RDONLY | O_BINARY);
        free(n);
        n = NULL;
        if (f < 0)
            return false;
    }
    bool r_val = false;
    uint64_t head[3] = {0x0};
    lseek(f, 0, SEEK_SET);
    read(f, head, sizeof( head ));
    /*
     * check which (previous) version file was encrypted with
     */
    if (head[0] != htonll(HEADER_0) || head[1] != htonll(HEADER_1))
        goto clean_up;
    /*
     * check which version the file was encrypted with - obviously we
     * cannot handle releases newer than ourselves because features
     * we don't understand may have been used
     */
    switch (htonll(head[2]))
    {
        case HEADER_VERSION_201008: /* original release 2011.08 */
            if (e)
            {
                e->blocked = false;
#if 0
                e->compressed = false;
#endif
            }
            break;
        case HEADER_VERSION_201110:
            if (e)
            {
                e->blocked = true;
#if 0 /* no compression yet */
                e->compressed = true; /* this file may be compressed */
#endif
            }
            break;
        default:
            log_message(LOG_ERROR, "file encrypted with more recent release of encrypt");
            goto clean_up;
    }
    r_val = true;
    if (!e)
        goto clean_up;
    log_message(LOG_DEBUG, "check for known algorithms");
    uint8_t l = 0;
    read(f, &l, sizeof( uint8_t ));
    char *c = calloc(l + 1, sizeof( char ));
    read(f, c, l);
    char *h = strchr(c, '/');
    *h = '\0';
    h++;
    e->cipher = strdup(c);
    e->hash = strdup(h);
    h = NULL;
    free(c);
    c = NULL;
    log_message(LOG_INFO, "file has cipher %s", e->cipher);
    log_message(LOG_INFO, "file has hash %s", e->hash);
clean_up:
    if (t == 1)
        close(f);
    return r_val;
}

extern status_e main_encrypt(int64_t f, int64_t g, encrypt_t e)
{
    status = RUNNING;

    log_message(LOG_INFO, "encrypting...");
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
    if (!(mdi = get_algorithm_hash(e.hash)))
        return (status = FAILED_ALGORITHM);
    gcrypt_wrapper_t c_wrapper = { NULL, 0 };
    if (!(c_wrapper.algorithm = get_algorithm_crypt(e.cipher)))
        return (status = FAILED_ALGORITHM);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_open(&c_wrapper.cipher, c_wrapper.algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * write the default header
     */
    log_message(LOG_DEBUG, "writing standard header");
    uint64_t head[3] = {htonll(HEADER_0), htonll(HEADER_1), htonll(HEADER_2)};
    write(g, head, sizeof( head ));
    char *algos = NULL;
    asprintf(&algos, "%s/%s", get_name_algorithm_crypt(c_wrapper.algorithm), get_name_algorithm_hash(mdi));
    uint8_t l1 = (uint8_t)strlen(algos);
    write(g, &l1, sizeof( uint8_t ));
    write(g, algos, l1);
    free(algos);
    algos = NULL;
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    e.key.h_length = gcry_md_get_algo_dlen(ma);
    if (!(e.key.h_data = malloc(e.key.h_length)))
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, e.key.h_data, e.key.p_data, e.key.p_length);
    /*
     * setup algorithm (key and IV) - copy no more than the length of the key
     * into a new buffer (pad with 0x0 if necessary) then hash back to the
     * original buffer the IV
     */
    size_t lk = 0;
    gcry_cipher_algo_info(c_wrapper.algorithm, GCRYCTL_GET_KEYLEN, NULL, &lk);
    uint8_t buffer[0xFF] = { 0x00 };
    memcpy(buffer, e.key.h_data, lk < e.key.h_length ? lk : e.key.h_length);
    gcry_cipher_setkey(c_wrapper.cipher, buffer, lk);
    memset(buffer, 0x00, 0xFF);
    uint8_t *iv = malloc(e.key.h_length);
    if (!iv)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, iv, e.key.h_data, e.key.h_length);
    memcpy(buffer, iv, lk < e.key.h_length ? lk : e.key.h_length);
    free(iv);
    iv = NULL;
    free(e.key.h_data);
    e.key.h_data = NULL;
    gcry_cipher_setiv(c_wrapper.cipher, buffer, lk);
    memset(buffer, 0x00, 0xFF);
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
    gcry_create_nonce(&x, sizeof( int64_t ));
    gcry_create_nonce(&y, sizeof( int64_t ));
    int64_t z = x ^ y;
    log_message(LOG_VERBOSE, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    x = htonll(x);
    y = htonll(y);
    z = htonll(z);
    log_message(LOG_VERBOSE, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    ewrite(g, &x, sizeof( int64_t ), c_wrapper);
    ewrite(g, &y, sizeof( int64_t ), c_wrapper);
    ewrite(g, &z, sizeof( int64_t ), c_wrapper);
    /*
     * write a random length of random bytes
     */
    gcry_create_nonce(&l1, sizeof( uint8_t ));
    gcry_create_nonce(buffer, l1);
    ewrite(g, &l1, sizeof( uint8_t ), c_wrapper);
    ewrite(g, buffer, l1, c_wrapper);
    memset(buffer, 0x00, 0xFF);
    /*
     * write various metadata about the original file (if any); start
     * off writing the number of metadata entries and then a list of
     * tlv's
     *
     * NB Old style (version 2011.08) only stored the size; newer
     * versions don't need to: they store a block size, and an
     * indicator whether there are more blocks to come, however we
     * do still store the original file size so that during the
     * decryption process we can display a rough guess at current
     * progress
     */
    l1 = 2;
#if 0
    if (e.compressed)
        l1++;
#endif
    ewrite(g, &l1, sizeof( uint8_t ), c_wrapper);

    l1 = TAG_SIZE;
    decrypted_size = lseek(f, 0, SEEK_END);
    ewrite(g, &l1, sizeof( uint8_t ), c_wrapper);
    uint16_t l2 = htons(sizeof( uint64_t ));
    ewrite(g, &l2, sizeof( uint16_t ), c_wrapper);
    uint64_t l8 = htonll(decrypted_size);
    ewrite(g, &l8, sizeof( uint64_t ), c_wrapper);

    uint64_t block_size = BLOCK_SIZE /* TODO eventually allow user defined block size */;
    l1 = TAG_BLOCKED;
    ewrite(g, &l1, sizeof( uint8_t ), c_wrapper);
    l2 = htons(sizeof( uint64_t ));
    ewrite(g, &l2, sizeof( uint16_t ), c_wrapper);
    l8 = htonll(block_size);
    ewrite(g, &l8, sizeof( uint64_t ), c_wrapper);

#if 0
    if (e.compressed)
    {
        /*
         * TODO actually compress the data if requested
         *   ...find a way to store the compressed size...
         */
        l1 = TAG_COMPRESSED;
        ewrite(g, &l1, sizeof( uint8_t ), c_wrapper);
        l2 = htons(sizeof( bool ));
        ewrite(g, &l2, sizeof( uint16_t ), c_wrapper);
        b1 = e.compressed;
        ewrite(g, &b1, sizeof( bool ), c_wrapper);
    }
#endif
    /*
     * main encryption loop
     */
    log_message(LOG_DEBUG, "starting encryption process");
    lseek(f, 0, SEEK_SET);
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    bool b1 = true;
    uint8_t *read_buffer = malloc(block_size);
    while (b1)
    {
        if (status == CANCELLED)
            goto clean_up;
        gcry_create_nonce(read_buffer, block_size);
        uint64_t r = read(f, read_buffer, block_size);
        gcry_md_write(md, read_buffer, r);
        if (r < block_size)
            b1 = false;
        ewrite(g, &b1, sizeof( bool ), c_wrapper);
        ewrite(g, read_buffer, block_size, c_wrapper);
        if (!b1)
        {
            r = htonll(r);
            ewrite(g, &r, sizeof( uint64_t ), c_wrapper);
        }
        bytes_processed += block_size;
    }
    free(read_buffer);
    read_buffer = NULL;
    /*
     * write data checksum
     */
    gcry_md_final(md);
    uint8_t *cs = gcry_md_read(md, ma);
    log_message(LOG_DEBUG, "writing data checksum");
    ewrite(g, cs, e.key.h_length, c_wrapper);
    log_binary(LOG_VERBOSE, cs, e.key.h_length);
    /*
     * add some random data at the end
     */
    log_message(LOG_DEBUG, "appending file random data");
    gcry_create_nonce(&l1, sizeof( uint8_t ));
    gcry_create_nonce(buffer, l1);
    ewrite(g, buffer, l1, c_wrapper);
    memset(buffer, 0x00, 0xFF);

    ewrite(g, NULL, 0, c_wrapper);
    status = SUCCEEDED;

clean_up:
    /*
     * done
     */

    gcry_cipher_close(c_wrapper.cipher);
    gcry_md_close(md);

    return status;
}

extern status_e main_decrypt(int64_t f, int64_t g, encrypt_t e)
{
    status = RUNNING;

    log_message(LOG_INFO, "decrypting...");
    /*
     * initialise GNU Crypt library
     */
    if (!lib_init)
        init_gcrypt_library();
    /*
     * read the standard header
     */
    if (!file_encrypted(f, &e))
        return (status = FAILED_PARAMETER);
    int mdi = 0;
    if (!(mdi = get_algorithm_hash(e.hash)))
        return (status = FAILED_ALGORITHM);
    gcrypt_wrapper_t c_wrapper = { NULL, 0 };
    if (!(c_wrapper.algorithm = get_algorithm_crypt(e.cipher)))
        return (status = FAILED_ALGORITHM);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_open(&c_wrapper.cipher, c_wrapper.algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    e.key.h_length = gcry_md_get_algo_dlen(ma);
    if (!(e.key.h_data = malloc(e.key.h_length)))
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, e.key.h_data, e.key.p_data, e.key.p_length);
    /*
     * setup algorithm (key and IV)
     */
    size_t lk = 0;
    gcry_cipher_algo_info(c_wrapper.algorithm, GCRYCTL_GET_KEYLEN, NULL, &lk);
    uint8_t buffer[0xFF] = { 0x00 };
    memcpy(buffer, e.key.h_data, lk < e.key.h_length ? lk : e.key.h_length);
    gcry_cipher_setkey(c_wrapper.cipher, buffer, lk);
    memset(buffer, 0x00, 0xFF);
    uint8_t *iv = malloc(e.key.h_length);
    if (!iv)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    gcry_md_hash_buffer(ma, iv, e.key.h_data, e.key.h_length);
    memcpy(buffer, iv, lk < e.key.h_length ? lk : e.key.h_length);
    free(iv);
    iv = NULL;
    free(e.key.h_data);
    e.key.h_data = NULL;
    gcry_cipher_setiv(c_wrapper.cipher, buffer, lk);
    memset(buffer, 0x00, 0xFF);

    log_message(LOG_DEBUG, "reading source file info");
    /*
     * read three 64bit signed integers and assert that x ^ y = z
     */
    int64_t x = 0;
    int64_t y = 0;
    int64_t z = 0;
    eread(f, &x, sizeof( int64_t ), c_wrapper);
    eread(f, &y, sizeof( int64_t ), c_wrapper);
    eread(f, &z, sizeof( int64_t ), c_wrapper);
    log_message(LOG_DEBUG, "verifying x ^ y = z");
    log_message(LOG_VERBOSE, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    x = ntohll(x);
    y = ntohll(y);
    z = ntohll(z);
    log_message(LOG_VERBOSE, "x = %jx ; y = %jx ; z = %jx", x, y, z);
    if ((x ^ y) != z)
    {
        log_message(LOG_ERROR, "failed decryption attempt");
        return (status = FAILED_DECRYPTION);
    }
    /*
     * skip past random data
     */
    uint8_t l1 = 0;
    eread(f, &l1, sizeof( uint8_t ), c_wrapper);
    eread(f, buffer, l1, c_wrapper);
    memset(buffer, 0x00, 0xFF);
    /*
     * read the original file metadata - skip any unknown tag values
     */
    eread(f, &l1, sizeof( l1 ), c_wrapper);
    uint64_t block_size = 0;
    for (int i = 0; i < l1; i++)
    {
        tlv_t tlv = { 1, 0, NULL };
        eread(f, &tlv.tag, sizeof( uint8_t ), c_wrapper);
        eread(f, &tlv.length, sizeof( uint16_t ), c_wrapper);
        tlv.length = ntohs(tlv.length);
        if (!(tlv.value = malloc(tlv.length)))
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
        eread(f, tlv.value, tlv.length, c_wrapper);
        switch (tlv.tag)
        {
            case TAG_SIZE:
                memcpy(&decrypted_size, tlv.value, sizeof( uint64_t ));
                decrypted_size = ntohll(decrypted_size);
                log_message(LOG_VERBOSE, "found size: %ju", decrypted_size);
                break;
            case TAG_BLOCKED:
                memcpy(&block_size, tlv.value, sizeof( uint64_t ));
                block_size = ntohll(block_size);
                e.blocked = true;
                log_message(LOG_VERBOSE, "file split into blocks of size: %ju", block_size);
                break;
            default:
                log_message(LOG_WARNING, "unknown parameter: %hhx", tlv.tag);
                status = FAILED_TAG;
                break;
        }
        free(tlv.value);
        tlv.value = NULL;
        if (status != RUNNING)
            goto clean_up;
    }
    /*
     * main decryption loop
     */
    log_message(LOG_DEBUG, "starting decryption process");
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    if (e.blocked)
    {
        bool b1 = true;
        uint8_t *read_buffer = malloc(block_size);
        while (b1)
        {
            if (status == CANCELLED)
                goto clean_up;
            eread(f, &b1, sizeof( bool ), c_wrapper);
            uint64_t r = eread(f, read_buffer, block_size, c_wrapper);
            if (!b1)
            {
                eread(f, &r, sizeof( uint64_t ), c_wrapper);
                r = ntohll(r);
            }
            gcry_md_write(md, read_buffer, r);
            write(g, read_buffer, r);
            bytes_processed += r;
        }
        free(read_buffer);
        read_buffer = NULL;
    }
    else /* old style decryption - relied on knowing the original size */
        for (bytes_processed = 0; bytes_processed < decrypted_size; bytes_processed += BLOCK_SIZE)
        {
            if (status == CANCELLED)
                goto clean_up;
            size_t l = BLOCK_SIZE;
            if (bytes_processed + BLOCK_SIZE > decrypted_size)
                l = BLOCK_SIZE - (bytes_processed + BLOCK_SIZE - decrypted_size);
            uint8_t read_buffer[BLOCK_SIZE] = { 0x00 };
            ssize_t r = eread(f, read_buffer, l, c_wrapper);
            gcry_md_write(md, read_buffer, r);
            write(g, read_buffer, r);
        }
    /*
     * compare data checksum (but only if the file was encrypted
     * with a recent version that create the checksum correctly)
     */
    status = SUCCEEDED;
    if (e.blocked)
    {
        gcry_md_final(md);
        ma = gcry_md_get_algo(md);
        uint8_t *cs = gcry_md_read(md, ma);
        eread(f, buffer, e.key.h_length, c_wrapper);
        log_message(LOG_DEBUG, "verifying checksum");
        log_binary(LOG_VERBOSE, cs, e.key.h_length);
        log_binary(LOG_VERBOSE, buffer, e.key.h_length);
        if (memcmp(cs, buffer, e.key.h_length))
        {
            log_message(LOG_ERROR, "checksum verification failed");
            status = FAILED_CHECKSUM;
        }
    }
    memset(buffer, 0x00, 0xFF);

clean_up:
    /*
     * done
     */

    gcry_cipher_close(c_wrapper.cipher);
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
    int list[0xff] = { 0x00 };
    int len = sizeof( list );
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
    int list[0xff] = { 0x00 };
    int len = sizeof( list );
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

static int ewrite(int64_t f, const void * const restrict d, size_t l, gcrypt_wrapper_t c)
{
    static uint8_t *stream = NULL;
    static size_t block = 0;
    static off_t offset[2] = { 0, 0 };
    if (!block)
        gcry_cipher_algo_info(c.algorithm, GCRYCTL_GET_BLKLEN, NULL, &block);
    if (!stream)
        if (!(stream = calloc(block, sizeof( uint8_t ))))
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);

    size_t remainder[2] = { l, block - offset[0] };
    if (!d && !l)
    {
        gcry_create_nonce(stream + offset[0], remainder[1]);
#ifndef DEBUGGING
        gcry_cipher_encrypt(c.cipher, stream, block, NULL, 0);
#endif /* !DEBUGGING */
        int e = write(f, stream, block);
        block = 0;
        free(stream);
        stream = NULL;
        memset(offset, 0x00, sizeof( offset ));
        fsync(f);
        return e;
    }

    offset[1] = 0;
    while (remainder[0])
    {
        if (remainder[0] < remainder[1])
        {
            memcpy(stream + offset[0], d + offset[1], remainder[0]);
            offset[0] += remainder[0];
            return l;
        }
        memcpy(stream + offset[0], d + offset[1], remainder[1]);
#ifndef DEBUGGING
        gcry_cipher_encrypt(c.cipher, stream, block, NULL, 0);
#endif /* !DEBUGGING */
        int e = EXIT_SUCCESS;
        if ((e = write(f, stream, block)) < 0)
            return e;
        offset[0] = 0;
        memset(stream, 0x00, block);
        offset[1] += remainder[1];
        remainder[0] -= remainder[1];
        remainder[1] = block - offset[0];
    }
    return l;
}

static int eread(int64_t f, void * const d, size_t l, gcrypt_wrapper_t c)
{
    static uint8_t *stream = NULL;
    static size_t block = 0;
    static size_t offset[3] = { 0, 0, 0 };
    if (!block)
        gcry_cipher_algo_info(c.algorithm, GCRYCTL_GET_BLKLEN, NULL, &block);
    if (!stream)
        if (!(stream = calloc(block, sizeof( uint8_t ))))
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);

    offset[1] = l;
    offset[2] = 0;
    while (true)
    {
        if (offset[0] >= offset[1])
        {
            memcpy(d + offset[2], stream, offset[1]);
            offset[0] -= offset[1];
            uint8_t *x = calloc(block, sizeof( uint8_t ));
            memcpy(x, stream + offset[1], offset[0]);
            memset(stream, 0x00, block);
            memcpy(stream, x, offset[0]);
            free(x);
            x = NULL;
            return l;
        }

        memcpy(d + offset[2], stream, offset[0]);
        offset[2] += offset[0];
        offset[1] -= offset[0];
        offset[0] = 0;

        int e = EXIT_SUCCESS;
        if ((e = read(f, stream, block)) < 0)
            return e;
#ifndef DEBUGGING
        gcry_cipher_decrypt(c.cipher, stream, block, NULL, 0);
#endif /* !DEBUGGING */
        offset[0] = block;
    }
}

static int get_algorithm_hash(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = { 0x00 };
    int len = sizeof( list );
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
    int list[0xff] = { 0x00 };
    int len = sizeof( list );
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
