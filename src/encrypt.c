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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#ifndef _WIN32
    #include <netinet/in.h>
#endif
#include <gcrypt.h>
#include <lzma.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "init.h"
#include "encrypt.h"
#include "io.h"

static void init_gcrypt_library(void);


static int get_algorithm_hash(const char * const restrict n);
static int get_algorithm_crypt(const char * const restrict n);

static int algorithm_compare(const void *a, const void *b);

static char *get_name_algorithm_hash(int a);
static char *get_name_algorithm_crypt(int a);


static char *correct_sha1(const char * const restrict n);
static char *correct_tiger192(const char * const restrict n);
static char *correct_aes_rijndael(const char * const restrict n);
static char *correct_blowfish128(const char * const restrict n);
static char *correct_twofish256(const char * const restrict n);

static bool algorithm_is_duplicate(const char * const restrict n);


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
    "An unknown error has occurred!"
};

extern uint64_t file_encrypted_aux(int t, intptr_t p, encrypt_t *e)
{
    int64_t f = 0;
    log_message(LOG_INFO, _("Checking for file header"));
    if (t == 1)
    {
        void *x = (intptr_t *)p;
        char *n = strdup((char *)x);
        f = open(n, O_RDONLY | O_BINARY);
        free(n);
        n = NULL;
        if (f < 0)
            return false;
    }
    else
        f = (int64_t)p;
    uint64_t r_val = 0;
    uint64_t head[3] = {0x0};
    lseek(f, 0, SEEK_SET);
    if ((read(f, head, sizeof head)) < 0)
    {
        log_message(LOG_ERROR, NULL);
        goto clean_up;
    }
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
    switch (ntohll(head[2]))
    {
        case HEADER_VERSION_201108: /* original release 2011.08 */
            if (e)
            {
                e->blocked = false;
                e->compressed = false;
            }
            r_val = HEADER_VERSION_201108;
            break;
        case HEADER_VERSION_201110:
            if (e)
            {
                e->blocked = true;
                e->compressed = false;
            }
            r_val = HEADER_VERSION_201110;
            break;
        case HEADER_VERSION_201211:
            if (e)
            {
                e->blocked = true;
                e->compressed = true;
            }
            r_val = HEADER_VERSION_201211;
            break;
        default:
            log_message(LOG_ERROR, _("File encrypted with more recent release of encrypt"));
            goto clean_up;
    }
    if (!e)
        goto clean_up;
    log_message(LOG_DEBUG, _("Checking for known algorithms"));
    uint8_t l = 0;
    read(f, &l, sizeof l);
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
    log_message(LOG_INFO, _("File encrypted using algorithm: %s"), e->cipher);
    log_message(LOG_INFO, _("Encryption key generated using hash: %s"), e->hash);
clean_up:
    if (t == 1)
        close(f);
    return r_val;
}

extern status_e main_encrypt(int64_t f, int64_t g, encrypt_t e)
{
    status = RUNNING;

    log_message(LOG_INFO, _("Encrypting..."));
    /*
     * initialise GNU Crypt library
     */
    if (!lib_init)
        init_gcrypt_library();
    /*
     * get the algorithms
     */
    log_message(LOG_DEBUG, _("Searching for known algorithms"));
    int mdi = 0;
    if (!(mdi = get_algorithm_hash(e.hash)))
        return (status = FAILED_ALGORITHM);
    lzma_stream lzs = LZMA_STREAM_INIT;
    io_params_t io_params = { NULL, 0, &lzs };
    if (!(io_params.algorithm = get_algorithm_crypt(e.cipher)))
        return (status = FAILED_ALGORITHM);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_open(&io_params.cipher, io_params.algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * write the default header
     */
    log_message(LOG_DEBUG, _("Writing standard header"));
    uint64_t head[3] = {htonll(HEADER_0), htonll(HEADER_1), htonll(HEADER_2)};
    write(g, head, sizeof head);
    char *algos = NULL;
    char *nac = get_name_algorithm_crypt(io_params.algorithm);
    char *nah = get_name_algorithm_hash(mdi);
    asprintf(&algos, "%s/%s", nac, nah);
    free(nac);
    free(nah);
    uint8_t l1 = (uint8_t)strlen(algos);
    write(g, &l1, sizeof l1);
    write(g, algos, l1);
    free(algos);
    algos = NULL;
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    e.key.h_length = gcry_md_get_algo_dlen(ma);
    if (!(e.key.h_data = malloc(e.key.h_length)))
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, e.key.h_length);
    gcry_md_hash_buffer(ma, e.key.h_data, e.key.p_data, e.key.p_length);
    /*
     * setup algorithm (key and IV) - copy no more than the length of the key
     * into a new buffer (pad with 0x0 if necessary) then hash back to the
     * original buffer the IV
     */
    size_t key_len = 0;
    gcry_cipher_algo_info(io_params.algorithm, GCRYCTL_GET_KEYLEN, NULL, &key_len);
    uint8_t buffer[0xFF] = { 0x00 };
    memcpy(buffer, e.key.h_data, key_len < e.key.h_length ? key_len : e.key.h_length);
    gcry_cipher_setkey(io_params.cipher, buffer, key_len);
    memset(buffer, 0x00, sizeof buffer);
    uint8_t *iv = malloc(e.key.h_length);
    if (!iv)
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, e.key.h_length);
    gcry_md_hash_buffer(ma, iv, e.key.h_data, e.key.h_length);
    size_t iv_len = 0;
    gcry_cipher_algo_info(io_params.algorithm, GCRYCTL_GET_BLKLEN, NULL, &iv_len);
    memcpy(buffer, iv, iv_len < e.key.h_length ? iv_len : e.key.h_length);
    free(iv);
    iv = NULL;
    free(e.key.h_data);
    e.key.h_data = NULL;
    gcry_cipher_setiv(io_params.cipher, buffer, iv_len);
    memset(buffer, 0x00, sizeof buffer);
    /*
     * all data written from here on is encrypted
     */
    log_message(LOG_DEBUG, _("Writing source file info"));
    /*
     * write simple addition (x ^ y = z) where x, y are random
     * 64bit signed integers
     */
    uint64_t x = 0;
    uint64_t y = 0;
    gcry_create_nonce(&x, sizeof x);
    gcry_create_nonce(&y, sizeof y);
    uint64_t z = x ^ y;
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    x = htonll(x);
    y = htonll(y);
    z = htonll(z);
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    enc_write(g, &x, sizeof x, &io_params);
    enc_write(g, &y, sizeof y, &io_params);
    enc_write(g, &z, sizeof z, &io_params);
    /*
     * write a random length of random bytes
     */
#ifndef __DEBUG__
    gcry_create_nonce(&l1, sizeof l1);
    gcry_create_nonce(buffer, l1);
    enc_write(g, &l1, sizeof l1, &io_params);
    enc_write(g, buffer, l1, &io_params);
    memset(buffer, 0x00, sizeof buffer);
#endif
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
    int (*write_func)(int64_t, const void * const restrict, size_t, io_params_t *) = enc_write;
    int (*sync_func)(int64_t, io_params_t *) = enc_sync;
    if (e.compressed)
    {
#ifndef __DEBUG_NO_LZMA__
        /*
         * setup for liblzma compression
         */
        log_message(LOG_VERBOSE, _("Initialising xz compression"));
        lzma_filter lzf[2];
        lzma_options_lzma lzo;
        lzma_lzma_preset(&lzo, LZMA_PRESET_DEFAULT);
        lzf[0].id = LZMA_FILTER_LZMA2;
        lzf[0].options = &lzo;
        lzf[1].id = LZMA_VLI_UNKNOWN;
        if (lzma_stream_encoder(io_params.lzma, lzf, LZMA_CHECK_NONE) == LZMA_OK)
        {
            l1++;
            write_func = lzma_write;
            sync_func = lzma_sync;
        }
        else
#endif
            e.compressed = false;
    }
    enc_write(g, &l1, sizeof l1, &io_params);

    l1 = TAG_SIZE;
    decrypted_size = lseek(f, 0, SEEK_END);
    enc_write(g, &l1, sizeof l1, &io_params);
    uint16_t l2 = htons(sizeof( uint64_t ));
    enc_write(g, &l2, sizeof l2, &io_params);
    uint64_t l8 = htonll(decrypted_size);
    enc_write(g, &l8, sizeof l8, &io_params);

    uint64_t block_size = BLOCK_SIZE /* TODO eventually allow user defined block size */;
    l1 = TAG_BLOCKED;
    enc_write(g, &l1, sizeof l1, &io_params);
    l2 = htons(sizeof( uint64_t ));
    enc_write(g, &l2, sizeof l2, &io_params);
    l8 = htonll(block_size);
    enc_write(g, &l8, sizeof l8, &io_params);

    if (e.compressed)
    {
        /*
         * write the tag which indicates the encrypted data is compressed
         */
        l1 = TAG_COMPRESSED;
        enc_write(g, &l1, sizeof l1, &io_params);
        l2 = htons(sizeof( bool ));
        enc_write(g, &l2, sizeof l2, &io_params);
        bool b1 = true;
        enc_write(g, &b1, sizeof b1, &io_params);
    }
    /*
     * main encryption loop; if we're compressing the output then everything
     * from here will be compressed
     */
    log_message(LOG_DEBUG, _("Starting encryption process"));
    lseek(f, 0, SEEK_SET);
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    bool b1 = true;
    uint8_t *read_buffer = malloc(block_size + sizeof b1);
    do
    {
        if (status == CANCELLED)
            goto clean_up;
        gcry_create_nonce(read_buffer, block_size + sizeof b1);
        uint64_t r = read(f, read_buffer + sizeof b1, block_size);
        gcry_md_write(md, read_buffer + sizeof b1, r);
        if (r < block_size)
            b1 = false;
        memcpy(read_buffer, &b1, sizeof b1);
        write_func(g, read_buffer, block_size + sizeof b1, &io_params);
        if (!b1)
        {   /*
             * after the last block write the size of the last block
             */
            r = htonll(r);
            write_func(g, &r, sizeof r, &io_params);
        }
        bytes_processed += block_size;
    }
    while (b1);
    free(read_buffer);
    read_buffer = NULL;
    /*
     * write data checksum
     */
    gcry_md_final(md);
    uint8_t *cs = gcry_md_read(md, ma);
    log_message(LOG_DEBUG, _("Writing data checksum"));
    write_func(g, cs, e.key.h_length, &io_params);
    log_binary(LOG_VERBOSE, cs, e.key.h_length);
    /*
     * add some random data at the end
     */
#ifndef __DEBUG__
    log_message(LOG_DEBUG, _("Appending file random data"));
    gcry_create_nonce(&l1, sizeof l1);
    gcry_create_nonce(buffer, l1);
    write_func(g, buffer, l1, &io_params);
    memset(buffer, 0x00, sizeof buffer);
#endif
    sync_func(g, &io_params);
    status = SUCCEEDED;

clean_up:
    /*
     * done
     */
    gcry_cipher_close(io_params.cipher);
    gcry_md_close(md);

    return status;
}

extern status_e main_decrypt(int64_t f, int64_t g, encrypt_t e)
{
    status = RUNNING;

    log_message(LOG_INFO, _("Decrypting..."));
    /*
     * initialise GNU Crypt library
     */
    if (!lib_init)
        init_gcrypt_library();
    /*
     * read the standard header
     */
    uint64_t ver = 0;
    if (!(ver = file_encrypted(f, &e)))
        return (status = FAILED_PARAMETER);
    int mdi = 0;
    if (!(mdi = get_algorithm_hash(e.hash)))
        return (status = FAILED_ALGORITHM);
    lzma_stream lzs = LZMA_STREAM_INIT;
    io_params_t io_params = { NULL, 0, &lzs };
    if (!(io_params.algorithm = get_algorithm_crypt(e.cipher)))
        return (status = FAILED_ALGORITHM);

    gcry_md_hd_t md = NULL;
    gcry_md_open(&md, mdi, GCRY_MD_FLAG_SECURE);
    gcry_cipher_open(&io_params.cipher, io_params.algorithm, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * generate key hash
     */
    int ma = gcry_md_get_algo(md);
    e.key.h_length = gcry_md_get_algo_dlen(ma);
    if (!(e.key.h_data = malloc(e.key.h_length)))
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, e.key.h_length);
    gcry_md_hash_buffer(ma, e.key.h_data, e.key.p_data, e.key.p_length);
    /*
     * setup algorithm (key and IV)
     */
    size_t key_len = 0;
    gcry_cipher_algo_info(io_params.algorithm, GCRYCTL_GET_KEYLEN, NULL, &key_len);
    uint8_t buffer[0xFF] = { 0x00 };
    memcpy(buffer, e.key.h_data, key_len < e.key.h_length ? key_len : e.key.h_length);
    gcry_cipher_setkey(io_params.cipher, buffer, key_len);
    memset(buffer, 0x00, sizeof buffer);
    uint8_t *iv = malloc(e.key.h_length);
    if (!iv)
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, e.key.h_length);
    gcry_md_hash_buffer(ma, iv, e.key.h_data, e.key.h_length);
    size_t iv_len = 0;
    switch (ver)
    {
        case HEADER_VERSION_201108:
        case HEADER_VERSION_201110:
            iv_len = key_len;
            break;
        default:
            gcry_cipher_algo_info(io_params.algorithm, GCRYCTL_GET_BLKLEN, NULL, &iv_len);
    }
    memcpy(buffer, iv, iv_len < e.key.h_length ? iv_len : e.key.h_length);
    free(iv);
    iv = NULL;
    free(e.key.h_data);
    e.key.h_data = NULL;
    gcry_cipher_setiv(io_params.cipher, buffer, iv_len);
    memset(buffer, 0x00, sizeof buffer);

    log_message(LOG_DEBUG, _("Reading source file info"));
    /*
     * read three 64bit signed integers and assert that x ^ y = z
     */
    uint64_t x = 0;
    uint64_t y = 0;
    uint64_t z = 0;
    enc_read(f, &x, sizeof x, &io_params);
    enc_read(f, &y, sizeof y, &io_params);
    enc_read(f, &z, sizeof z, &io_params);
    log_message(LOG_DEBUG, _("Verifying x ^ y = z"));
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    x = ntohll(x);
    y = ntohll(y);
    z = ntohll(z);
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    if ((x ^ y) != z)
    {
        log_message(LOG_ERROR, _("Failed decryption attempt"));
        return (status = FAILED_DECRYPTION);
    }
    /*
     * skip past random data
     */
    uint8_t l1 = 0;
#ifndef __DEBUG__
    enc_read(f, &l1, sizeof l1, &io_params);
    enc_read(f, buffer, l1, &io_params);
    memset(buffer, 0x00, sizeof buffer);
#endif
    /*
     * read the original file metadata - skip any unknown tag values
     */
    enc_read(f, &l1, sizeof l1, &io_params);
    uint64_t block_size = 0;
    int (*read_func)(int64_t, void * const, size_t, io_params_t *) = enc_read;
    for (int i = 0; i < l1; i++)
    {
        uint8_t tag = 0;
        uint16_t length = 0;
        uint8_t *value = NULL;
        enc_read(f, &tag, sizeof tag, &io_params);
        enc_read(f, &length, sizeof length, &io_params);
        length = ntohs(length);
        if (!(value = malloc(length)))
            die(_("Out of memory @ %s:%d:%s [%d]"), __FILE__, __LINE__, __func__, length);
        enc_read(f, value, length, &io_params);
        switch (tag)
        {
            case TAG_SIZE:
                memcpy(&decrypted_size, value, sizeof decrypted_size);
                decrypted_size = ntohll(decrypted_size);
                log_message(LOG_VERBOSE, _("Original file size: %" PRIu64), decrypted_size);
                break;
            case TAG_BLOCKED:
                memcpy(&block_size, value, sizeof block_size);
                block_size = ntohll(block_size);
                e.blocked = true;
                log_message(LOG_VERBOSE, _("File split into blocks of size: %" PRIu64), block_size);
                break;
            case TAG_COMPRESSED:
#ifndef __DEBUG_NO_LZMA__
                if ((e.compressed = value[0])) /* yes, this is what i actually want */
                {
                    log_message(LOG_VERBOSE, _("Data stream is compressed"));
                    if (lzma_stream_decoder(io_params.lzma, UINT64_MAX, 0) != LZMA_OK)
                        die(_("Expecting compressed data but could not setup liblzma"));
                    read_func = lzma_read;
                }
                else
#endif
                {
                    log_message(LOG_VERBOSE, _("Data stream is not compressed"));
                    e.compressed = false;
                }
                break;
            default:
                log_message(LOG_WARNING, _("Encountered unknown tlv tag: %hhx"), tag);
                status = FAILED_TAG;
                break;
        }
        free(value);
        value = NULL;
        if (status != RUNNING)
            goto clean_up;
    }
    /*
     * main decryption loop
     */
    log_message(LOG_DEBUG, _("Starting decryption process"));
    /*
     * reset hash algorithm, so we can use it to generate a checksum of the plaintext data
     */
    gcry_md_reset(md);
    if (e.blocked)
    {
        bool b1 = true;
        uint8_t *read_buffer = malloc(block_size + sizeof b1);
        while (b1)
        {
            if (status == CANCELLED)
                goto clean_up;
            uint64_t r = read_func(f, read_buffer, block_size + sizeof b1, &io_params);
            memcpy(&b1, read_buffer, sizeof b1);
            r -= sizeof b1;
            memmove(read_buffer, read_buffer + sizeof b1, r);
            if (!b1)
            {
                read_func(f, &r, sizeof r, &io_params);
                r = ntohll(r);
            }
            gcry_md_write(md, read_buffer, r);
            write(g, read_buffer, r);
            bytes_processed += r;
        }
        free(read_buffer);
        read_buffer = NULL;
    }
    else /*
          * old style decryption - relied on knowing the original size
          */
        for (bytes_processed = 0; bytes_processed < decrypted_size; bytes_processed += BLOCK_SIZE)
        {
            if (status == CANCELLED)
                goto clean_up;
            size_t l = BLOCK_SIZE;
            if (bytes_processed + BLOCK_SIZE > decrypted_size)
                l = BLOCK_SIZE - (bytes_processed + BLOCK_SIZE - decrypted_size);
            uint8_t read_buffer[BLOCK_SIZE] = { 0x00 };
            ssize_t r = read_func(f, read_buffer, l, &io_params);
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
        read_func(f, buffer, e.key.h_length, &io_params);
        log_message(LOG_DEBUG, _("Verifying checksum"));
        log_binary(LOG_VERBOSE, cs, e.key.h_length);
        log_binary(LOG_VERBOSE, buffer, e.key.h_length);
        if (memcmp(cs, buffer, e.key.h_length))
        {
            log_message(LOG_ERROR, _("Checksum verification failed"));
            status = FAILED_CHECKSUM;
        }
    }
    memset(buffer, 0x00, sizeof buffer);

clean_up:
    /*
     * done
     */
    gcry_cipher_close(io_params.cipher);
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

extern char **get_algorithms_hash(void)
{
    if (!lib_init)
        init_gcrypt_library();
    int lid[0xff] = { 0x00 };
    int len = sizeof lid;
    gcry_md_list(lid, &len);
    char **l = malloc(sizeof( char * ) * (len + 1));
    for (int i = 0; i < len; i++)
    {
        const char *n = gcry_md_algo_name(lid[i]);
        if (algorithm_is_duplicate(n))
            l[i] = strdup(""); // a duplicate of another algorithm already in the list (empty strings will be ignored)
        else if (!strcasecmp(n, NAME_TIGER192))
            l[i] = correct_tiger192(n);
        else if (!strncasecmp(n, NAME_SHA1, strlen(NAME_SHA1) - 1))
            l[i] = correct_sha1(n);
        else
            l[i] = strdup(n);
    }
    l[len] = NULL;
    qsort(l, len, sizeof( char * ), algorithm_compare);
    return l;
}

extern char **get_algorithms_crypt(void)
{
    if (!lib_init)
        init_gcrypt_library();
    int lid[0xff] = { 0x00 };
    int len = sizeof lid;
    gcry_cipher_list(lid, &len);
    char **l = malloc(sizeof( char * ) * (len + 1));
    for (int i = 0; i < len; i++)
    {
        const char *n = gcry_cipher_algo_name(lid[i]);
        if (algorithm_is_duplicate(n))
            l[i] = strdup(""); // ditto to above
        else if (!strncasecmp(n, NAME_AES, strlen(NAME_AES)))
            l[i] = correct_aes_rijndael(n);
        else if (!strcasecmp(n, NAME_BLOWFISH))
            l[i] = correct_blowfish128(n);
        else if (!strcasecmp(n, NAME_TWOFISH))
            l[i] = correct_twofish256(n);
        else
            l[i] = strdup(n);
    }
    l[len] = NULL;
    qsort(l, len, sizeof( char * ), algorithm_compare);
    return l;
}

static int algorithm_compare(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}
        
static void init_gcrypt_library(void)
{
    /*
     * initialise GNU Crypt library
     */
    log_message(LOG_VERBOSE, _("Initialising GNU Crypt library"));
    if (!gcry_check_version(GCRYPT_VERSION))
        die(_("Could not find GNU Crypt library"));
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    errno = 0; /* need to reset errno after gcry_check_version() */
    lib_init = true;
}

static int get_algorithm_hash(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = { 0x00 };
    int len = sizeof list;
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
            log_message(LOG_DEBUG, _("Found requested hash: %s"), gcry_md_algo_name(list[i]));
            return list[i];
        }
        free(y);
    }
    log_message(LOG_ERROR, _("Could not find requested hash: %s"), n);
    return 0;
}

static int get_algorithm_crypt(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = { 0x00 };
    int len = sizeof list;
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
            log_message(LOG_DEBUG, _("Found requested encryption algorithm: %s"), gcry_cipher_algo_name(list[i]));
            free(y);
            return list[i];
        }
        free(y);
    }
    log_message(LOG_ERROR, _("Could not find requested encryption algorithm: %s"), n);
    return 0;
}

static char *get_name_algorithm_hash(int a)
{
    const char *n = gcry_md_algo_name(a);
    if (strncasecmp(n, NAME_SHA1, strlen(NAME_SHA1) - 1))
        return strdup(n);
    return correct_sha1(n);
}

static char *get_name_algorithm_crypt(int a)
{
    const char *x = gcry_cipher_algo_name(a);
    if (!strncasecmp(x, NAME_AES, strlen(NAME_AES)))
        return correct_aes_rijndael(x);
    else if (!strcasecmp(x, NAME_BLOWFISH))
        return correct_blowfish128(x);
    else if (!strcasecmp(x, NAME_TWOFISH))
        return correct_twofish256(x);
    return strdup(x);
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
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(NAME_RIJNDAEL) + strlen(n) - strlen(NAME_AES));
    return x;
}

static char *correct_blowfish128(const char * const restrict n)
{
    (void)n;
    return strdup(NAME_BLOWFISH128);
}

static char *correct_twofish256(const char * const restrict n)
{
    (void)n;
    return strdup(NAME_TWOFISH256);
}

static bool algorithm_is_duplicate(const char * const restrict n)
{
    if (!strcmp(NAME_TIGER192, n))
        return true;
    return false;
}
