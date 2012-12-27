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

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <gcrypt.h>
#include <lzma.h>

#include "common/common.h"
#include "common/logging.h"
#include "common/error.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "io.h"
#include "crypto.h"

#define OFFSET_SLOTS 3

/*!
 * \brief  How to process the data
 *
 * How the data should be processed before writing or after reading.
 */
typedef enum
{
    IO_DEFAULT, /*!< No processing will be done */
    IO_ENCRYPT, /*!< Data will be encrypted/decrypted */
    IO_LZMA     /*!< Data will be compressed/decompressed prior to encryption/decryption */
}
io_e;

typedef enum
{
    EOF_NO,
    EOF_MAYBE,
    EOF_YES
}
eof_e;

typedef struct
{
    uint8_t *stream;
    size_t block;
    size_t offset[OFFSET_SLOTS];
}
buffer_t;

typedef struct
{
    int64_t fd;

    bool cipher_init;
    gcry_cipher_hd_t cipher_handle;

    bool hash_init;
    gcry_md_hd_t hash_handle;

    buffer_t *buffer;

    eof_e eof;
    uint8_t byte;

    bool lzma_init;
    lzma_stream lzma_handle;

    io_e operation;
}
io_private_t;

static ssize_t lzma_write(io_private_t *, const void *, size_t);
static ssize_t lzma_read(io_private_t *, void *, size_t);
static int lzma_sync(io_private_t *);

static ssize_t enc_write(io_private_t *, const void *, size_t);
static ssize_t enc_read(io_private_t *, void *, size_t);
static int enc_sync(io_private_t *);

static void io_do_compress(io_private_t *);
static void io_do_decompress(io_private_t *);

extern IO_HANDLE io_open(const char *n, int f, mode_t m)
{
    int64_t fd = open(n, f, m);
    if (fd < 0)
        return NULL;
    io_private_t *io_ptr = calloc(1, sizeof( io_private_t ));
    io_ptr->fd = fd;
    io_ptr->eof = EOF_NO;
    return io_ptr;
}

extern int io_close(IO_HANDLE ptr)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return -1;
    }
    int64_t fd = io_ptr->fd;

    if (io_ptr->buffer)
    {
        if (io_ptr->buffer->stream)
            free(io_ptr->buffer->stream);
        free(io_ptr->buffer);
    }

    if (io_ptr->cipher_init)
        gcry_cipher_close(io_ptr->cipher_handle);

    if (io_ptr->hash_init)
        gcry_md_close(io_ptr->hash_handle);

    if (io_ptr->lzma_init)
        lzma_end(&io_ptr->lzma_handle);

    free(io_ptr);
    io_ptr = NULL;

    return close(fd);
}

extern IO_HANDLE io_use_stdin(void)
{
    io_private_t *io_ptr = calloc(1, sizeof( io_private_t ));
    io_ptr->fd = STDIN_FILENO;
    return io_ptr;
}

extern IO_HANDLE io_use_stdout(void)
{
    io_private_t *io_ptr = calloc(1, sizeof( io_private_t ));
    io_ptr->fd = STDOUT_FILENO;
    return io_ptr;
}

extern bool io_is_stdin(IO_HANDLE ptr)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return false;
    }
    return io_ptr->fd == STDIN_FILENO;
}

extern bool io_is_stdout(IO_HANDLE ptr)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return false;
    }
    return io_ptr->fd == STDOUT_FILENO;
}

extern void io_encryption_init(IO_HANDLE ptr, const char *c, const char *h, const uint8_t *k, size_t l, bool g)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return;
    }

    /*
     * start setting up the encryption buffer
     */
    if (!(io_ptr->buffer = malloc(sizeof( buffer_t ))))
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( buffer_t ));

    gcry_md_open(&io_ptr->hash_handle, hash_id_from_name(h), GCRY_MD_FLAG_SECURE);
    gcry_cipher_open(&io_ptr->cipher_handle, cipher_id_from_name(c), GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    /*
     * generate a hash of the supplied key data
     */
    size_t hash_length = gcry_md_get_algo_dlen(gcry_md_get_algo(io_ptr->hash_handle));
    uint8_t *hash = malloc(hash_length);
    if (!hash)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, hash_length);
    gcry_md_hash_buffer(gcry_md_get_algo(io_ptr->hash_handle), hash, k, l);
    /*
     * set the key as the hash of supplied data
     */
    size_t key_length = 0;
    gcry_cipher_algo_info(cipher_id_from_name(c), GCRYCTL_GET_KEYLEN, NULL, &key_length);
    uint8_t *key = calloc(key_length, sizeof( byte_t ));
    if (!key)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, key_length);
    memcpy(key, hash, key_length < hash_length ? key_length : hash_length);
    gcry_cipher_setkey(io_ptr->cipher_handle, key, key_length);
    free(key);
    /*
     * set the IV as the hash of the hash
     */
    uint8_t *iv_hash = malloc(hash_length);
    if (!iv_hash)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, hash_length);
    gcry_md_hash_buffer(gcry_md_get_algo(io_ptr->hash_handle), iv_hash, hash, hash_length);
    free(hash);
    gcry_cipher_algo_info(cipher_id_from_name(c), GCRYCTL_GET_BLKLEN, NULL, &io_ptr->buffer->block);
    /* the 2011.* versions (incorrectly) used key length instead of block length */
    uint8_t *iv = calloc(g ? key_length : io_ptr->buffer->block, sizeof( byte_t ));
    if (!iv)
       die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, io_ptr->buffer->block);
    memcpy(iv, iv_hash, io_ptr->buffer->block < hash_length ? io_ptr->buffer->block : hash_length);
    free(iv_hash);
    gcry_cipher_setiv(io_ptr->cipher_handle, iv, io_ptr->buffer->block);
    free(iv);
    /*
     * set the rest of the buffer
     */
    if (!(io_ptr->buffer->stream = malloc(io_ptr->buffer->block)))
        die(_("Out of memyyory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, io_ptr->buffer->block);
    /*
     * when encrypting/writing data:
     *   0: length of data buffered so far (in stream); 1: length of data processed (from d)
     * when decrypting/reading data:
     *   0: length of available data in input buffer (stream); 1: available space in read buffer (d); 2: next available memory location for data (from d)
     */
    for (unsigned i = 0; i < OFFSET_SLOTS; i++)
        io_ptr->buffer->offset[i] = 0;

    io_ptr->cipher_init = true;
    io_ptr->hash_init = true;
    io_ptr->operation = IO_ENCRYPT;

    return;
}

extern void io_encryption_checksum_init(IO_HANDLE ptr, char *h)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return;
    }

    if (io_ptr->hash_init)
        gcry_md_reset(io_ptr->hash_handle);
    else
        gcry_md_open(&io_ptr->hash_handle, hash_id_from_name(h), GCRY_MD_FLAG_SECURE);

    return;
}

extern void io_encryption_checksum(IO_HANDLE ptr, uint8_t **b, size_t *l)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return;
    }

    if (!io_ptr->cipher_init)
    {
        *l = 0;
        return;
    }

    *l = gcry_md_get_algo_dlen(gcry_md_get_algo(io_ptr->hash_handle));
    uint8_t *x = realloc(*b, *l);
    if (!x)
        die(_("Out of memyyory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, *l);
    *b = x;
    memcpy(*b, gcry_md_read(io_ptr->hash_handle, gcry_md_get_algo(io_ptr->hash_handle)), *l);

    return;
}

extern void io_compression_init(IO_HANDLE ptr)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return;
    }

    io_ptr->operation = IO_LZMA;
    io_ptr->lzma_init = false;

    return;
}

extern ssize_t io_write(IO_HANDLE f, const void *d, size_t l)
{
    io_private_t *io_ptr = f;
    if (!io_ptr)
    {
        errno = EBADF;
        return -1;
    }

    if (io_ptr->cipher_init)
        gcry_md_write(io_ptr->hash_handle, d, l);

    switch (io_ptr->operation)
    {
        case IO_LZMA:
            if (!io_ptr->lzma_init)
                io_do_compress(io_ptr);
            return lzma_write(io_ptr, d, l);

        case IO_ENCRYPT:
            return enc_write(io_ptr, d, l);

        case IO_DEFAULT:
            return write(io_ptr->fd, d, l);

    }
    errno = EINVAL;
    return -1;
}

extern ssize_t io_read(IO_HANDLE f, void *d, size_t l)
{
    io_private_t *io_ptr = f;
    if (!io_ptr)
    {
        errno = EBADF;
        return -1;
    }

    ssize_t r = 0;
    switch (io_ptr->operation)
    {
        case IO_LZMA:
            if (!io_ptr->lzma_init)
                io_do_decompress(io_ptr);
            r = lzma_read(io_ptr, d, l);
            break;

        case IO_ENCRYPT:
            r = enc_read(io_ptr, d, l);
            break;

        case IO_DEFAULT:
            r = read(io_ptr->fd, d, l);
            break;

        default:
            errno = EINVAL;
            r = -1;
            break;
    }
    if (r >= 0 && io_ptr->cipher_init)
        gcry_md_write(io_ptr->hash_handle, d, r);

    return r;
}

extern int io_sync(IO_HANDLE ptr)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return -1;
    }

    switch (io_ptr->operation)
    {
        case IO_LZMA:
            return lzma_sync(io_ptr);

        case IO_ENCRYPT:
            return enc_sync(io_ptr);

        case IO_DEFAULT:
            return fsync(io_ptr->fd);
    }
    errno = EINVAL;
    return -1;
}

extern off_t io_seek(IO_HANDLE ptr, off_t o, int w)
{
    io_private_t *io_ptr = ptr;
    if (!io_ptr)
    {
        errno = EBADF;
        return -1;
    }

    return lseek(io_ptr->fd, o, w);
}

static ssize_t lzma_write(io_private_t *c, const void *d, size_t l)
{
    lzma_action x = LZMA_RUN;
    if (!d && !l)
        x = LZMA_FINISH;
    c->lzma_handle.next_in = d;
    c->lzma_handle.avail_in = l;

    uint8_t stream = 0x00;
    c->lzma_handle.next_out = &stream;
    c->lzma_handle.avail_out = sizeof stream;
    do
    {
        bool lzf = false;
        switch (lzma_code(&c->lzma_handle, x))
        {
            case LZMA_STREAM_END:
                lzf = true;
            case LZMA_OK:
                break;
            default:
                log_message(LOG_ERROR, _("Unexpected error during compression"));
                return -1;
        }
        if (c->lzma_handle.avail_out == 0)
        {
            enc_write(c, &stream, sizeof stream);
            c->lzma_handle.next_out = &stream;
            c->lzma_handle.avail_out = sizeof stream;
        }
        if (lzf && c->lzma_handle.avail_in == 0 && c->lzma_handle.avail_out == sizeof stream)
            return l;
    }
    while (x == LZMA_FINISH || c->lzma_handle.avail_in > 0);

    return l;
}

static ssize_t lzma_read(io_private_t *c, void *d, size_t l)
{
    lzma_action a = LZMA_RUN;

    c->lzma_handle.next_out = d;
    c->lzma_handle.avail_out = l;

    if (c->eof == EOF_YES)
        return 0;
    else if (c->eof == EOF_MAYBE)
    {
        a = LZMA_FINISH;
        goto proc_remain;
    }

    while (true)
    {
        if (c->lzma_handle.avail_in == 0)
        {
            c->lzma_handle.next_in = &c->byte;
            switch (enc_read(c, &c->byte, sizeof c->byte))
            {
                case 0:
                    a = LZMA_FINISH;
                    break;
                case 1:
                    c->lzma_handle.avail_in = 1;
                    break;
                default:
                    log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
                    return -1;
            }
        }
proc_remain:;
        lzma_ret e = lzma_code(&c->lzma_handle, a);
        switch (e)
        {
            case LZMA_STREAM_END:
                c->eof = EOF_MAYBE;
            case LZMA_OK:
                break;
            default:
                log_message(LOG_ERROR, _("Unexpected error during decompression : %d"), e);
                return -1;
        }

        if (c->lzma_handle.avail_out == 0 || c->eof != EOF_NO)
            return l - c->lzma_handle.avail_out;
    }
}

static int lzma_sync(io_private_t *c)
{
    lzma_write(c, NULL, 0);
    return enc_sync(c);
}

static ssize_t enc_write(io_private_t *f, const void *d, size_t l)
{
    size_t remainder[2] = { l, f->buffer->block - f->buffer->offset[0] }; /* 0: length of data yet to buffer (from d); 1: available space in output buffer (stream) */
    if (!d && !l)
    {
#ifdef __DEBUG__
        memset(f->buffer->stream + f->buffer->offset[0], 0x00, remainder[1]);
#else
        gcry_create_nonce(f->buffer->stream + f->buffer->offset[0], remainder[1]);
        gcry_cipher_encrypt(f->cipher_handle, f->buffer->stream, f->buffer->block, NULL, 0);
#endif
        ssize_t e = write(f->fd, f->buffer->stream, f->buffer->block);
        fsync(f->fd);
        f->buffer->block = 0;
        free(f->buffer->stream);
        f->buffer->stream = NULL;
        memset(f->buffer->offset, 0x00, sizeof f->buffer->offset);
        return e;
    }

    f->buffer->offset[1] = 0;
    while (remainder[0])
    {
        if (remainder[0] < remainder[1])
        {
            memcpy(f->buffer->stream + f->buffer->offset[0], d + f->buffer->offset[1], remainder[0]);
            f->buffer->offset[0] += remainder[0];
            return l;
        }
        memcpy(f->buffer->stream + f->buffer->offset[0], d + f->buffer->offset[1], remainder[1]);
#ifndef __DEBUG__
        gcry_cipher_encrypt(f->cipher_handle, f->buffer->stream, f->buffer->block, NULL, 0);
#endif
        ssize_t e = EXIT_SUCCESS;
        if ((e = write(f->fd, f->buffer->stream, f->buffer->block)) < 0)
            return e;
        f->buffer->offset[0] = 0;
        memset(f->buffer->stream, 0x00, f->buffer->block);
        f->buffer->offset[1] += remainder[1];
        remainder[0] -= remainder[1];
        remainder[1] = f->buffer->block - f->buffer->offset[0];
    }
    return l;
}

static ssize_t enc_read(io_private_t *f, void *d, size_t l)
{
    f->buffer->offset[1] = l;
    f->buffer->offset[2] = 0;
    while (true)
    {
        if (f->buffer->offset[0] >= f->buffer->offset[1])
        {
            memcpy(d + f->buffer->offset[2], f->buffer->stream, f->buffer->offset[1]);
            f->buffer->offset[0] -= f->buffer->offset[1];
            uint8_t *x = calloc(f->buffer->block, sizeof( uint8_t ));
            if (!x)
                die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, f->buffer->block * sizeof( uint8_t ));
            memcpy(x, f->buffer->stream + f->buffer->offset[1], f->buffer->offset[0]);
            memset(f->buffer->stream, 0x00, f->buffer->block);
            memcpy(f->buffer->stream, x, f->buffer->offset[0]);
            free(x);
            x = NULL;
            return l;
        }

        memcpy(d + f->buffer->offset[2], f->buffer->stream, f->buffer->offset[0]);
        f->buffer->offset[2] += f->buffer->offset[0];
        f->buffer->offset[1] -= f->buffer->offset[0];
        f->buffer->offset[0] = 0;

        ssize_t e = EXIT_SUCCESS;
        if ((e = read(f->fd, f->buffer->stream, f->buffer->block)) < 0)
            return e;
#ifndef __DEBUG__
        gcry_cipher_decrypt(f->cipher_handle, f->buffer->stream, f->buffer->block, NULL, 0);
#endif
        f->buffer->offset[0] = f->buffer->block;
    }
}

static int enc_sync(io_private_t *f)
{
    enc_write(f, NULL, 0);
    return 0;
}

static void io_do_compress(io_private_t *io_ptr)
{
    lzma_stream l = LZMA_STREAM_INIT;
    io_ptr->lzma_handle = l;

    lzma_filter lzf[2];
    lzma_options_lzma lzo;
    lzma_lzma_preset(&lzo, LZMA_PRESET_DEFAULT);
    lzf[0].id = LZMA_FILTER_LZMA2;
    lzf[0].options = &lzo;
    lzf[1].id = LZMA_VLI_UNKNOWN;
    if (lzma_stream_encoder(&io_ptr->lzma_handle, lzf, LZMA_CHECK_NONE) != LZMA_OK)
    {
        log_message(LOG_ERROR, "Could not setup liblzma for compression!");
        return;
    }

    io_ptr->lzma_init = true;
    return;
}

static void io_do_decompress(io_private_t *io_ptr)
{
    lzma_stream l = LZMA_STREAM_INIT;
    io_ptr->lzma_handle = l;

    if (lzma_stream_decoder(&io_ptr->lzma_handle, UINT64_MAX, 0/*LZMA_CONCATENATED*/) != LZMA_OK)
    {
        log_message(LOG_ERROR, "Could not setup liblzma for decompression!");
        return;
    }

    io_ptr->lzma_init = true;
    return;
}
