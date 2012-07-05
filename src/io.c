/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2012, albinoloverats ~ Software Development
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

#include <unistd.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <lzma.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "encrypt.h"
#include "io.h"

typedef enum eof_e
{
    EOF_NO,
    EOF_MAYBE,
    EOF_YES
}
eof_e;

extern int lzma_sync(int64_t f, io_params_t *c)
{
    lzma_write(f, NULL, 0, c);
    return 0;
}

extern int lzma_write(int64_t f, const void * const restrict d, size_t l, io_params_t *c)
{
    static uint8_t *stream = NULL;
    if (!stream)
    {
        if (!(stream = calloc(BLOCK_SIZE, sizeof( uint8_t ))))
            die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, BLOCK_SIZE);
        c->lzma->next_out = stream;
        c->lzma->avail_out = BLOCK_SIZE;
    }

    lzma_action x = LZMA_RUN;
    do
    {
        bool lzf = false;
        if (!d && !l)
        {
            c->lzma->next_in = (void *)"";
            c->lzma->avail_in = 0;
            x = LZMA_FINISH;
        }
        else
        {
            c->lzma->next_in = d;
            c->lzma->avail_in = l;
        }
        switch (lzma_code(c->lzma, x))
        {
            case LZMA_STREAM_END:
                lzf = true;
            case LZMA_OK:
                break;
            default:
                die("unexpected error during compression");
        }
        if (c->lzma->avail_out == 0)
        {
            enc_write(f, stream, BLOCK_SIZE, c);
            c->lzma->next_out = stream;
            c->lzma->avail_out = BLOCK_SIZE;
        }
        if (lzf)
        {
            enc_write(f, stream, BLOCK_SIZE - c->lzma->avail_out, c);
            enc_sync(f, c);
            return BLOCK_SIZE - c->lzma->avail_out;
        }
    }
    while (x == LZMA_FINISH);

    return l;
}

extern int lzma_read(int64_t f, void * const d, size_t l, io_params_t *c)
{
    static eof_e eof = EOF_NO;
    if (eof == EOF_YES)
        return 0;
    else if (eof == EOF_MAYBE)
        goto proc_remain;

    static uint8_t *stream = NULL;
    static size_t sz = 0;
    lzma_action a = LZMA_RUN;

    while (true)
    {
        while (!stream || sz < l)
        {
            sz += BLOCK_SIZE;
            uint8_t *x = realloc(stream, sz);
            if (!x)
                die("out of memory @ %s:%d:%s [%zu]", __FILE__, __LINE__, __func__, sz);
            c->lzma->next_out = (stream = x);
            c->lzma->avail_out += sz;
        }
        uint8_t chr = 0x00;
        if (c->lzma->avail_in == 0)
        {
            c->lzma->next_in = &chr;
            if ((c->lzma->avail_in = enc_read(f, &chr, sizeof chr, c)) < sizeof chr)
                a = LZMA_FINISH;
        }
proc_remain:
        ;
        lzma_ret x = lzma_code(c->lzma, a);
        switch (x)
        {
            case LZMA_STREAM_END:
                eof = EOF_MAYBE;
            case LZMA_OK:
                break;
            default:
                die("unexpected error during decompression : %d", x);
        }

        if (c->lzma->avail_out == 0 || eof)
        {
            l = (c->lzma->avail_out > 0 && c->lzma->avail_out < l) ? (eof = EOF_YES, sz - c->lzma->avail_out) : l;
            memcpy(d, stream, l);
            memmove(stream, stream + l, sz - l);
            c->lzma->next_out = stream + (sz - l);
            c->lzma->avail_out += l;
            return l;
        }
    }
}

extern int enc_sync(int64_t f, io_params_t *c)
{
    enc_write(f, NULL, 0, c);
    return 0;
}

extern int enc_write(int64_t f, const void * const restrict d, size_t l, io_params_t *c)
{
    static uint8_t *stream = NULL;
    static size_t block = 0;
    static off_t offset[2] = { 0, 0 };
    if (!block)
        gcry_cipher_algo_info(c->algorithm, GCRYCTL_GET_BLKLEN, NULL, &block);
    if (!stream)
        if (!(stream = calloc(block, sizeof( uint8_t ))))
            die("out of memory @ %s:%d:%s [%zu]", __FILE__, __LINE__, __func__, block * sizeof( uint8_t ));

    size_t remainder[2] = { l, block - offset[0] };
    if (!d && !l)
    {
        gcry_create_nonce(stream + offset[0], remainder[1]);
#ifndef __DEBUG__
        gcry_cipher_encrypt(c->cipher, stream, block, NULL, 0);
#endif
        int e = write(f, stream, block);
        fsync(f);
        block = 0;
        free(stream);
        stream = NULL;
        memset(offset, 0x00, sizeof offset );
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
#ifndef __DEBUG__
        gcry_cipher_encrypt(c->cipher, stream, block, NULL, 0);
#endif
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

extern int enc_read(int64_t f, void * const d, size_t l, io_params_t *c)
{
    static uint8_t *stream = NULL;
    static size_t block = 0;
    static size_t offset[3] = { 0, 0, 0 };
    if (!block)
        gcry_cipher_algo_info(c->algorithm, GCRYCTL_GET_BLKLEN, NULL, &block);
    if (!stream)
        if (!(stream = calloc(block, sizeof( uint8_t ))))
            die("out of memory @ %s:%d:%s [%zu]", __FILE__, __LINE__, __func__, block * sizeof( uint8_t ));

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
#ifndef __DEBUG__
        gcry_cipher_decrypt(c->cipher, stream, block, NULL, 0);
#endif
        offset[0] = block;
    }
}
