/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2021, albinoloverats ~ Software Development
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

#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <gcrypt.h>
#include <lzma.h>

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/ecc.h"

#include "crypt_io.h"
#include "crypt.h"

#define IO_DUMMY_FD 0x42145c91
#define OFFSET_SLOTS 3

/*!
 * \brief  How to process the data
 *
 * How the data should be processed before writing or after reading.
 */
typedef enum
{
	IO_DEFAULT, /*!< No processing will be done; only used when reading/writing the header */
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
	uint8_t *stream;             /*!< Buffer data   */
	size_t block;                /*!< Size of steam */
	size_t offset[OFFSET_SLOTS]; /*!< 0: length of data in buffer, yet to write; 1: available space in output buffer (stream); 2: offset of where to read new data to */
}
buffer_t;

typedef struct
{
	int64_t fd;

	lzma_stream lzma_handle;

	gcry_cipher_hd_t cipher_handle;
	gcry_md_hd_t hash_handle;
	gcry_mac_hd_t mac_handle;

	buffer_t *buffer_crypt;
	buffer_t *buffer_ecc;

	eof_e eof:2;
	io_e operation:2;

	uint8_t byte;

	bool lzma_init:1;
	bool cipher_init:1;
	bool hash_init:1;
	bool mac_init:1;
	bool ecc_init:1;
}
io_private_t;

static ssize_t lzma_write(io_private_t *, const void *, size_t);
static ssize_t lzma_read(io_private_t *, void *, size_t);
static int lzma_sync(io_private_t *);

static ssize_t enc_write(io_private_t *, const void *, size_t);
static ssize_t enc_read(io_private_t *, void *, size_t);
static int enc_sync(io_private_t *);

static ssize_t ecc_write(io_private_t *, const void *, size_t);
static ssize_t ecc_read(io_private_t *, void *, size_t);
static int ecc_sync(io_private_t *);

static void io_do_compress(io_private_t *);
static void io_do_decompress(io_private_t *);

extern IO_HANDLE io_open(const char *n, int f, mode_t m)
{
#ifndef _WIN32
	int64_t fd = open(n, f, m);
#else
	int64_t fd = open(n, f);
	(void)m;
#endif
	if (fd < 0)
		return NULL;
	io_private_t *io_ptr = gcry_calloc_secure(1, sizeof( io_private_t ));
	io_ptr->fd = fd;
	io_ptr->eof = EOF_NO;
	return io_ptr;
}

extern int io_close(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || (io_ptr->fd < 0 && io_ptr->fd != -IO_DUMMY_FD))
		return (errno = EBADF , -1);
	int64_t fd = io_ptr->fd;
	io_release(ptr);
	return fd == -IO_DUMMY_FD ? 0 : close(fd);
}

extern IO_HANDLE io_dummy_handle(void)
{

	io_private_t *io_ptr = gcry_calloc_secure(1, sizeof( io_private_t ));
	io_ptr->fd = -IO_DUMMY_FD;
	return io_ptr;
}

extern void io_release(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr)
		return (errno = EBADF , (void)NULL);
	if (io_ptr->buffer_crypt)
	{
		if (io_ptr->buffer_crypt->stream)
			gcry_free(io_ptr->buffer_crypt->stream);
		gcry_free(io_ptr->buffer_crypt);
	}
	if (io_ptr->buffer_ecc)
	{
		if (io_ptr->buffer_ecc->stream)
			free(io_ptr->buffer_ecc->stream);
		free(io_ptr->buffer_ecc);
	}
	if (io_ptr->cipher_init)
		gcry_cipher_close(io_ptr->cipher_handle);
	if (io_ptr->hash_init)
		gcry_md_close(io_ptr->hash_handle);
	if (io_ptr->mac_init)
		gcry_mac_close(io_ptr->mac_handle);
	if (io_ptr->lzma_init)
		lzma_end(&io_ptr->lzma_handle);
	gcry_free(io_ptr);
	io_ptr = NULL;
	return;
}

extern IO_HANDLE io_use_stdin(void)
{
	io_private_t *io_ptr = gcry_calloc_secure(1, sizeof( io_private_t ));
	io_ptr->fd = STDIN_FILENO;
	return io_ptr;
}

extern IO_HANDLE io_use_stdout(void)
{
	io_private_t *io_ptr = gcry_calloc_secure(1, sizeof( io_private_t ));
	io_ptr->fd = STDOUT_FILENO;
	return io_ptr;
}

extern bool io_is_initialised(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	return io_ptr && io_ptr->fd >= 0;
}

extern bool io_is_stdin(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return (errno = EBADF , false);
	return io_ptr->fd == STDIN_FILENO;
}

extern bool io_is_stdout(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return (errno = EBADF , false);
	return io_ptr->fd == STDOUT_FILENO;
}

extern void io_encryption_init(IO_HANDLE ptr, enum gcry_cipher_algos c, enum gcry_md_algos h, enum gcry_cipher_modes m, enum gcry_mac_algos a, uint64_t i, const uint8_t *k, size_t l, io_extra_t x)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	uint64_t key_iterations = i;
	/*
	 * start setting up the encryption buffer
	 */
	if (!(io_ptr->buffer_crypt = gcry_malloc_secure(sizeof( buffer_t ))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( buffer_t ));

	gcry_md_open(&io_ptr->hash_handle, h, GCRY_MD_FLAG_SECURE);
	gcry_cipher_open(&io_ptr->cipher_handle, c, m, GCRY_CIPHER_SECURE);
	if (a != GCRY_MAC_NONE)
		gcry_mac_open(&io_ptr->mac_handle, a, GCRY_MAC_FLAG_SECURE, NULL);
	/*
	 * generate a hash of the supplied key data
	 */
	size_t hash_length = gcry_md_get_algo_dlen(h);
	uint8_t *hash = gcry_malloc_secure(hash_length);
	if (!hash)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, hash_length);
	gcry_md_hash_buffer(gcry_md_get_algo(io_ptr->hash_handle), hash, k, l);
	/*
	 * set the key as the hash of supplied data
	 */
	size_t key_length = gcry_cipher_get_algo_keylen(c);
	uint8_t *key = gcry_calloc_secure(key_length, sizeof( byte_t ));
	if (!key)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, key_length);
	size_t salt_length = key_length;
	uint8_t *salt = gcry_calloc_secure(salt_length, sizeof( byte_t ));
	if (key_iterations)
	{
		if (!salt)
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, salt_length);
		if (x.x_encrypt)
		{
			gcry_create_nonce(salt, salt_length);
			io_write(ptr, salt, salt_length);
		}
		else
			io_read(ptr, salt, salt_length);
		gcry_kdf_derive(hash, hash_length, GCRY_KDF_PBKDF2, h, salt, salt_length, key_iterations, key_length, key);
	}
	else
	{
		/*
		 * versions previous to 2017.09 didn't use a proper key
		 * derivation function and instead just used a hash of
		 * the passphrase
		 */
		memcpy(key, hash, key_length < hash_length ? key_length : hash_length);
	}
	gcry_cipher_setkey(io_ptr->cipher_handle, key, key_length);
	gcry_free(key);

	/*
	 * initialise the MAC (not used on version before 2017.09 and so
	 * the default salt of { 0x00 } can be used/ignored)
	 */
	if (a != GCRY_MAC_NONE)
	{
		size_t mac_length = gcry_mac_get_algo_keylen(a);
		uint8_t *mac = gcry_calloc_secure(mac_length, sizeof( byte_t ));
		gcry_kdf_derive(hash, hash_length, GCRY_KDF_PBKDF2, h, salt, salt_length, key_iterations, mac_length, mac);
		gcry_mac_setkey(io_ptr->mac_handle, mac, mac_length);
		gcry_free(mac);
		io_ptr->mac_init = true;
	}
	gcry_free(salt);

	/*
	 * the 2011.* versions (incorrectly) used key length instead of block
	 * length; versions after 2014.06 randomly generate the IV instead
	 */
	io_ptr->buffer_crypt->block = gcry_cipher_get_algo_blklen(c);
	uint8_t *iv = gcry_calloc_secure(x.x_iv == IV_BROKEN ? key_length : io_ptr->buffer_crypt->block, sizeof( byte_t ));
	if (!iv)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, io_ptr->buffer_crypt->block);
	if (x.x_iv == IV_RANDOM)
	{
		if (x.x_encrypt)
		{
			gcry_create_nonce(iv, io_ptr->buffer_crypt->block);
			io_write(ptr, iv, io_ptr->buffer_crypt->block);
		}
		else
			io_read(ptr, iv, io_ptr->buffer_crypt->block);
	}
	else
	{
		uint8_t *iv_hash = gcry_malloc_secure(hash_length);
		if (!iv_hash)
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, hash_length);
		/*
		 * set the IV as the hash of the hash
		 */
		gcry_md_hash_buffer(gcry_md_get_algo(io_ptr->hash_handle), iv_hash, hash, hash_length);
		memcpy(iv, iv_hash, io_ptr->buffer_crypt->block < hash_length ? io_ptr->buffer_crypt->block : hash_length);
		gcry_free(iv_hash);
	}
	gcry_free(hash);

	if (m == GCRY_CIPHER_MODE_CTR)
		gcry_cipher_setctr(io_ptr->cipher_handle, iv, io_ptr->buffer_crypt->block);
	else
		gcry_cipher_setiv(io_ptr->cipher_handle, iv, io_ptr->buffer_crypt->block);

	if (io_ptr->mac_init)
	{
		gcry_mac_reset(io_ptr->mac_handle);
		const char *mac_name = mac_name_from_id(a);
		if (io_ptr->mac_init && (!strncmp("GMAC", mac_name, strlen("GMAC")) || !strncmp("POLY1305", mac_name, strlen("POLY1305"))))
			gcry_mac_setiv(io_ptr->mac_handle, iv, io_ptr->buffer_crypt->block);
		gcry_free(iv);
	}

	/*
	 * set the rest of the buffer
	 */
	if (!(io_ptr->buffer_crypt->stream = gcry_malloc_secure(io_ptr->buffer_crypt->block)))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, io_ptr->buffer_crypt->block);
	/*
	 * when encrypting/writing data:
	 *   0: length of data buffered so far (in stream)
	 *   1: length of data processed (from d)
	 * when decrypting/reading data:
	 *   0: length of available data in input buffer (stream)
	 *   1: available space in read buffer (d)
	 *   2: next available memory location for data (from d)
	 */
	for (unsigned i = 0; i < OFFSET_SLOTS; i++)
		io_ptr->buffer_crypt->offset[i] = 0;
	io_ptr->cipher_init = true;
	io_ptr->hash_init = true;
	io_ptr->operation = IO_ENCRYPT;

	return;
}

extern void io_encryption_checksum_init(IO_HANDLE ptr, enum gcry_md_algos h)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	io_ptr->hash_init ? gcry_md_reset(io_ptr->hash_handle) : gcry_md_open(&io_ptr->hash_handle, h, GCRY_MD_FLAG_SECURE);
	io_ptr->hash_init = true;
	return;
}

extern void io_encryption_checksum(IO_HANDLE ptr, uint8_t **b, size_t *l)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	if (!io_ptr->hash_init)
		return *l = 0 , (void)NULL;
	*l = gcry_md_get_algo_dlen(gcry_md_get_algo(io_ptr->hash_handle));
	uint8_t *x = gcry_realloc(*b, *l);
	if (!x)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, *l);
	*b = x;
	memcpy(*b, gcry_md_read(io_ptr->hash_handle, gcry_md_get_algo(io_ptr->hash_handle)), *l);
	return;
}

extern void io_encryption_mac(IO_HANDLE ptr, uint8_t **b, size_t *l)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	if (!io_ptr->mac_init)
		return *l = 0 , (void)NULL;
	if (!io_ptr->mac_init)
		return;
	*l = gcry_mac_get_algo_maclen(gcry_mac_get_algo(io_ptr->mac_handle));
	uint8_t *x = gcry_realloc(*b, *l);
	if (!x)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, *l);
	*b = x;
	gcry_mac_read(io_ptr->mac_handle, *b, l);
	return;
}

extern void io_compression_init(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	io_ptr->operation = IO_LZMA;
	io_ptr->lzma_init = false;
	return;
}

extern void io_correction_init(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , (void)NULL;
	io_ptr->ecc_init = true;
	io_ptr->buffer_ecc = malloc(sizeof( buffer_t ));
	io_ptr->buffer_ecc->block = ECC_PAYLOAD;
	io_ptr->buffer_ecc->stream = calloc(ECC_CAPACITY, sizeof( uint8_t ));
	for (unsigned i = 0; i < OFFSET_SLOTS; i++)
		io_ptr->buffer_ecc->offset[i] = 0;
	return;
}

extern ssize_t io_write(IO_HANDLE f, const void *d, size_t l)
{
	io_private_t *io_ptr = f;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , -1;

	if (io_ptr->hash_init)
		gcry_md_write(io_ptr->hash_handle, d, l);
	if (io_ptr->mac_init)
		gcry_mac_write(io_ptr->mac_handle, d, l);

	switch (io_ptr->operation)
	{
		case IO_LZMA:
			if (!io_ptr->lzma_init)
				io_do_compress(io_ptr);
			return lzma_write(io_ptr, d, l);
		case IO_ENCRYPT:
			return enc_write(io_ptr, d, l);
		case IO_DEFAULT:
			return ecc_write(io_ptr, d, l);
	}
	errno = EINVAL;
	return -1;
}

extern ssize_t io_read(IO_HANDLE f, void *d, size_t l)
{
	io_private_t *io_ptr = f;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , -1;

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
			r = ecc_read(io_ptr, d, l);
			break;
		default:
			errno = EINVAL;
			r = -1;
			break;
	}
	if (r >= 0 && io_ptr->hash_init)
		gcry_md_write(io_ptr->hash_handle, d, r);
	if (r >= 0 && io_ptr->mac_init)
		gcry_mac_write(io_ptr->mac_handle, d, r);
	return r;
}

extern int io_sync(IO_HANDLE ptr)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , -1;

	switch (io_ptr->operation)
	{
		case IO_LZMA:
			return lzma_sync(io_ptr);
		case IO_ENCRYPT:
			return enc_sync(io_ptr);
		case IO_DEFAULT:
			return ecc_sync(io_ptr);
	}
	return errno = EINVAL , -1;
}

extern off_t io_seek(IO_HANDLE ptr, off_t o, int w)
{
	io_private_t *io_ptr = ptr;
	if (!io_ptr || io_ptr->fd < 0)
		return errno = EBADF , -1;
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
		lzma_ret lr;
		switch ((lr = lzma_code(&c->lzma_handle, x)))
		{
			case LZMA_STREAM_END:
				lzf = true;
			case LZMA_OK:
				break;
			default:
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
					return -1;
			}
		}
proc_remain:;
		lzma_ret lr;
		switch ((lr = lzma_code(&c->lzma_handle, a)))
		{
			case LZMA_STREAM_END:
				c->eof = EOF_MAYBE;
			case LZMA_OK:
				break;
			default:
				return (ssize_t)-lr;
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
	size_t remainder[2] = { l, f->buffer_crypt->block - f->buffer_crypt->offset[0] }; /* 0: length of data yet to buffer (from d); 1: available space in output buffer (stream) */
	if (!d && !l)
	{
#if defined __DEBUG__ && !defined __DEBUG_WITH_ENCRYPTION__
		memset(f->buffer_crypt->stream + f->buffer_crypt->offset[0], 0x00, remainder[1]);
#else
		gcry_create_nonce(f->buffer_crypt->stream + f->buffer_crypt->offset[0], remainder[1]);
		gcry_cipher_encrypt(f->cipher_handle, f->buffer_crypt->stream, f->buffer_crypt->block, NULL, 0);
#endif
		ssize_t e = ecc_write(f, f->buffer_crypt->stream, f->buffer_crypt->block);
		ecc_sync(f);
		f->buffer_crypt->block = 0;
		gcry_free(f->buffer_crypt->stream);
		f->buffer_crypt->stream = NULL;
		memset(f->buffer_crypt->offset, 0x00, sizeof f->buffer_crypt->offset);
		return e;
	}

	f->buffer_crypt->offset[1] = 0;
	while (remainder[0])
	{
		if (remainder[0] < remainder[1])
		{
			memcpy(f->buffer_crypt->stream + f->buffer_crypt->offset[0], d + f->buffer_crypt->offset[1], remainder[0]);
			f->buffer_crypt->offset[0] += remainder[0];
			return l;
		}
		memcpy(f->buffer_crypt->stream + f->buffer_crypt->offset[0], d + f->buffer_crypt->offset[1], remainder[1]);
#if !defined __DEBUG__ || defined __DEBUG_WITH_ENCRYPTION__
		gcry_cipher_encrypt(f->cipher_handle, f->buffer_crypt->stream, f->buffer_crypt->block, NULL, 0);
#endif
		ssize_t e = EXIT_SUCCESS;
		if ((e = ecc_write(f, f->buffer_crypt->stream, f->buffer_crypt->block)) < 0)
			return e;
		f->buffer_crypt->offset[0] = 0;
		memset(f->buffer_crypt->stream, 0x00, f->buffer_crypt->block);
		f->buffer_crypt->offset[1] += remainder[1];
		remainder[0] -= remainder[1];
		remainder[1] = f->buffer_crypt->block - f->buffer_crypt->offset[0];
	}
	return l;
}

static ssize_t enc_read(io_private_t *f, void *d, size_t l)
{
	f->buffer_crypt->offset[1] = l;
	f->buffer_crypt->offset[2] = 0;
	while (true)
	{
		if (f->buffer_crypt->offset[0] >= f->buffer_crypt->offset[1])
		{
			memcpy(d + f->buffer_crypt->offset[2], f->buffer_crypt->stream, f->buffer_crypt->offset[1]);
			f->buffer_crypt->offset[0] -= f->buffer_crypt->offset[1];
			uint8_t *x = gcry_calloc_secure(f->buffer_crypt->block, sizeof( uint8_t ));
			if (!x)
				die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, f->buffer_crypt->block * sizeof( uint8_t ));
			memcpy(x, f->buffer_crypt->stream + f->buffer_crypt->offset[1], f->buffer_crypt->offset[0]);
			memset(f->buffer_crypt->stream, 0x00, f->buffer_crypt->block);
			memcpy(f->buffer_crypt->stream, x, f->buffer_crypt->offset[0]);
			gcry_free(x);
			return l;
		}

		memcpy(d + f->buffer_crypt->offset[2], f->buffer_crypt->stream, f->buffer_crypt->offset[0]);
		f->buffer_crypt->offset[2] += f->buffer_crypt->offset[0];
		f->buffer_crypt->offset[1] -= f->buffer_crypt->offset[0];
		f->buffer_crypt->offset[0] = 0;

		ssize_t e = EXIT_SUCCESS;
		if ((e = ecc_read(f, f->buffer_crypt->stream, f->buffer_crypt->block)) < 0)
			return e;
#if !defined __DEBUG__ || defined __DEBUG_WITH_ENCRYPTION__
		gcry_cipher_decrypt(f->cipher_handle, f->buffer_crypt->stream, f->buffer_crypt->block, NULL, 0);
#endif
		f->buffer_crypt->offset[0] = f->buffer_crypt->block;
	}
}

static int enc_sync(io_private_t *f)
{
	enc_write(f, NULL, 0);
	return 0;
}

static ssize_t ecc_write(io_private_t *f, const void *d, size_t l)
{
	if (!f->ecc_init)
	{
		if (!d && !l)
			return fsync(f->fd) , 0;
		else
			return write(f->fd, d, l);
	}

	size_t remainder[2] = { l, f->buffer_ecc->block - f->buffer_ecc->offset[0] }; /* 0: length of data yet to buffer (from d); 1: available space in output buffer (stream) */
	if (!d && !l)
	{
		uint8_t tmp[ECC_CAPACITY] = { 0x0 };
		ecc_encode(f->buffer_ecc->stream, tmp);
		memcpy(f->buffer_ecc->stream, tmp, sizeof tmp);

		uint8_t z = (uint8_t)f->buffer_ecc->offset[0];
		write(f->fd, &z, sizeof z);
		write(f->fd, f->buffer_ecc->stream, ECC_OFFSET);
		ssize_t e = write(f->fd, f->buffer_ecc->stream + ECC_OFFSET, ECC_PAYLOAD);

		fsync(f->fd);
		f->buffer_ecc->block = 0;
		free(f->buffer_ecc->stream);
		f->buffer_ecc->stream = NULL;
		memset(f->buffer_ecc->offset, 0x00, sizeof f->buffer_ecc->offset);
		return e;
	}

	f->buffer_ecc->offset[1] = 0;
	while (remainder[0])
	{
		if (remainder[0] < remainder[1])
		{
			memcpy(f->buffer_ecc->stream + f->buffer_ecc->offset[0], d + f->buffer_ecc->offset[1], remainder[0]);
			f->buffer_ecc->offset[0] += remainder[0];
			return l;
		}
		memcpy(f->buffer_ecc->stream + f->buffer_ecc->offset[0], d + f->buffer_ecc->offset[1], remainder[1]);

		uint8_t tmp[ECC_CAPACITY] = { 0x0 };
		ecc_encode(f->buffer_ecc->stream, tmp);
		memcpy(f->buffer_ecc->stream, tmp, sizeof tmp);

		uint8_t z = ECC_PAYLOAD;
		write(f->fd, &z, sizeof z);
		ssize_t e = EXIT_SUCCESS;
		if ((e = write(f->fd, f->buffer_ecc->stream, ECC_CAPACITY)) < 0)
			return e;

		f->buffer_ecc->offset[0] = 0;
		memset(f->buffer_ecc->stream, 0x00, f->buffer_ecc->block);
		f->buffer_ecc->offset[1] += remainder[1];
		remainder[0] -= remainder[1];
		remainder[1] = f->buffer_ecc->block - f->buffer_ecc->offset[0];
	}
	return l;
}

static ssize_t ecc_read(io_private_t *f, void *d, size_t l)
{
	if (!f->ecc_init)
		return read(f->fd, d, l);

	f->buffer_ecc->offset[1] = l;
	f->buffer_ecc->offset[2] = 0;
	while (true)
	{
		if (f->buffer_ecc->offset[0] >= f->buffer_ecc->offset[1])
		{
			memcpy(d + f->buffer_ecc->offset[2], f->buffer_ecc->stream, f->buffer_ecc->offset[1]);
			f->buffer_ecc->offset[0] -= f->buffer_ecc->offset[1];
			uint8_t *x = calloc(f->buffer_ecc->block, sizeof( uint8_t ));
			if (!x)
				die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, f->buffer_ecc->block * sizeof( uint8_t ));
			memcpy(x, f->buffer_ecc->stream + f->buffer_ecc->offset[1], f->buffer_ecc->offset[0]);
			memset(f->buffer_ecc->stream, 0x00, f->buffer_ecc->block);
			memcpy(f->buffer_ecc->stream, x, f->buffer_ecc->offset[0]);
			free(x);
			return l;
		}

		memcpy(d + f->buffer_ecc->offset[2], f->buffer_ecc->stream, f->buffer_ecc->offset[0]);
		f->buffer_ecc->offset[2] += f->buffer_ecc->offset[0];
		f->buffer_ecc->offset[1] -= f->buffer_ecc->offset[0];
		f->buffer_ecc->offset[0] = 0;
		memset(f->buffer_ecc->stream, 0x00, ECC_CAPACITY);

		ssize_t e = EXIT_SUCCESS;
		uint8_t z;
		read(f->fd, &z, sizeof z);
		if ((e = read(f->fd, f->buffer_ecc->stream, ECC_CAPACITY)) <= 0)
			return e;

		uint8_t tmp[ECC_CAPACITY] = { 0x0 };
		int bo;
		ecc_decode(f->buffer_ecc->stream, tmp, &bo);
		if (bo >= 4)
			return errno = EIO , -1;
		memcpy(f->buffer_ecc->stream, tmp, z);

		f->buffer_ecc->offset[0] = z;
	}
}

static int ecc_sync(io_private_t *f)
{
	ecc_write(f, NULL, 0);
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
		return;
	io_ptr->lzma_init = true;
	return;
}

static void io_do_decompress(io_private_t *io_ptr)
{
	lzma_stream l = LZMA_STREAM_INIT;
	io_ptr->lzma_handle = l;

	if (lzma_stream_decoder(&io_ptr->lzma_handle, UINT64_MAX, 0/*LZMA_CONCATENATED*/) != LZMA_OK)
		return;

	io_ptr->lzma_init = true;
	return;
}
