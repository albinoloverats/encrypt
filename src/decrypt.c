/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2024, albinoloverats ~ Software Development
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
#include <sys/stat.h>
#include <dirent.h>

#include <pthread.h>

#include <inttypes.h> /* used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself) */
#include <stdbool.h>
#include <string.h>

#ifndef _WIN32
	#include <netinet/in.h>
#endif

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/tlv.h"
#include "common/dir.h"

#include "crypt.h"
#include "decrypt.h"
#include "crypt_io.h"

static void *process(void *);

static uint64_t read_version(crypto_t *);
static bool read_verification_sum(crypto_t *);
static bool read_metadata(crypto_t *);
static void skip_random_data(crypto_t *);

static void decrypt_directory(crypto_t *, const char *);
static void decrypt_stream(crypto_t *);
static void decrypt_file(crypto_t *);

extern crypto_t *decrypt_init(const char * const restrict i,
                              const char * const restrict o,
                              const char * const restrict c,
                              const char * const restrict h,
                              const char * const restrict m,
                              const char * const restrict a,
                              const void * const restrict k,
                              size_t l, uint64_t n, bool r)
{
	init_crypto();

	crypto_t *z = gcry_calloc_secure(1, sizeof( crypto_t ));
	if (!z)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( crypto_t ));

	z->status = STATUS_INIT;

	z->name = NULL;
	if (i)
	{
		z->name = dir_get_name(i);
		if (!(z->source = io_open(i, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR)))
			return z->status = STATUS_FAILED_IO , z;
	}
	else
		z->source = IO_STDIN_FILENO;

	z->path = NULL;
	z->compressed = false;
	z->directory = false;

	if (o)
	{
		struct stat s;
		errno = 0;
		if (stat(o, &s) < 0)
		{
			if (errno != ENOENT)
				return z->status = STATUS_FAILED_IO , z;
			/*
			 * we’ve got a name, but don’t yet know if it will be a file
			 * or a directory
			 */
			z->output = IO_UNINITIALISED;
			z->path = strdup(o);
		}
		else
		{
			if (S_ISDIR(s.st_mode))
			{
				z->output = IO_UNINITIALISED;
				z->path = strdup(o);
				z->directory = true;
			}
			else if (S_ISREG(s.st_mode))
			{
				if (!(z->output = io_open(o, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK | O_BINARY, S_IRUSR | S_IWUSR)))
					return z->status = STATUS_FAILED_IO , z;
			}
			else
				return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
		}
	}
	else
		z->output = IO_STDOUT_FILENO;

	if (z->path)
	{
		char *sl = z->path + strlen(z->path) - 1;
		if (*sl == '/')
			*sl = '\0';
	}

	if (l)
	{
		if (!(z->key = gcry_malloc_secure(l)))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, l);
		memcpy(z->key, k, l);
		z->length = l;
	}
	else
	{
		int64_t kf = open(k, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
		if (kf < 0)
			return z->status = STATUS_FAILED_IO , z;
		z->length = lseek(kf, 0, SEEK_END);
		lseek(kf, 0, SEEK_SET);
		if (!(z->key = gcry_malloc_secure(z->length)))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, z->length);
		read(kf, z->key, z->length);
		close(kf);
	}

	z->kdf_iterations = n;

	if ((z->raw = r))
	{
		if ((z->cipher = cipher_id_from_name(c)) == GCRY_CIPHER_NONE)
			return z->status = STATUS_FAILED_UNKNOWN_CIPHER_ALGORITHM , z;
		if ((z->hash = hash_id_from_name(h)) == GCRY_MD_NONE)
			return z->status = STATUS_FAILED_UNKNOWN_HASH_ALGORITHM , z;
		if ((z->mode = mode_id_from_name(m)) == GCRY_CIPHER_MODE_NONE)
			return z->status = STATUS_FAILED_UNKNOWN_CIPHER_MODE , z;
		if ((z->mac = mac_id_from_name(a)) == GCRY_MAC_NONE)
			return z->status = STATUS_FAILED_UNKNOWN_MAC_ALGORITHM, z;
	}

	z->process = process;
	return z;
}

static void *process(void *ptr)
{
	crypto_t *c = (crypto_t *)ptr;

	if (!c || c->status != STATUS_INIT)
		return NULL;

	/*
	 * read encrypt file header
	 */
	c->version = c->raw ? VERSION_CURRENT : read_version(c);
	/*
	 * version_read() already handles setting the status and displaying
	 * an error
	 */
	if (!c->version)
		return c->status = STATUS_FAILED_UNKNOWN_VERSION , (void *)c->status;

	bool skip_some_random = false;
	x_iv_e iv_type = IV_RANDOM;
	switch (c->version)
	{
			/*
			 * these versions only had random data after the verification
			 * sum
			 */
		case VERSION_2011_08:
		case VERSION_2011_10:
			iv_type = IV_BROKEN;
			__attribute__((fallthrough)); /* allow fall-through for broken IV compatibility */
		case VERSION_2012_11:
			skip_some_random = true;
			break;

		case VERSION_2013_02:
		case VERSION_2013_11:
		case VERSION_2014_06:
			iv_type = IV_SIMPLE;
			__attribute__((fallthrough)); /* allow fall-through for broken key derivation */
		case VERSION_2015_01:
		case VERSION_2015_10:
			break;

		case VERSION_2017_09:
			c->kdf_iterations = KEY_ITERATIONS_201709;
			break;

		case VERSION_2020_01:
		case VERSION_2022_01:
		case VERSION_2024_01:
			//c->kdf_iterations = KEY_ITERATIONS_DEFAULT;
			break;
		default:
			/* this will catch the all more recent versions (unknown is detected above) */
			break;
	}
	/*
	 * the 2011.* versions (incorrectly) used key length instead of block
	 * length; and up until 2017.XX a kdf was not used; from 2020.01 the
	 * kdf iterations can be user defined
	 */
	io_extra_t iox = { iv_type, false };
	if (!io_encryption_init(c->source, c->cipher, c->hash, c->mode, c->mac, c->kdf_iterations, c->key, c->length, iox))
		return (c->status = STATUS_FAILED_GCRYPT_INIT , (void *)c->status);

	c->status = STATUS_RUNNING;
	gcry_free(c->key);
	c->key = NULL;

	if (!c->raw)
	{
		if (!skip_some_random)
			skip_random_data(c);

		if (!read_verification_sum(c))
			return (void *)c->status;

		skip_random_data(c);
	}

	if (!read_metadata(c))
		return (void *)c->status;

	if (!skip_some_random && !c->raw)
		skip_random_data(c);

	/*
	 * main decryption loop
	 */
	if (c->compressed)
		io_compression_init(c->source);

	/*
	 * The ever-expanding decrypt function!
	 *
	 * Scenarios:
	 *  1. Original, 2011.08, single file, not split into blocks
	 *  2. Version 2011.10, had data in blocks
	 *  3. Most recent release, 2012.11, data could/might be compressed
	 *  4. Next version: it might be a single file or stream, it might
	 *     be a directory hierarchy, this is where it gets complicated
	 *
	 * NB Newer versions didn’t require the data be split into blocks;
	 *    it was only to allow pipe to give us data where we didn’t know
	 *    ahead of time the total size
	 */
	io_encryption_checksum_init(c->source, c->hash);

	if (c->directory)
	{
		decrypt_directory(c, c->path);
		c->current.display = FINISHING_UP;
	}
	else
	{
		c->current.size = c->total.size;
		c->total.size = 1;
		c->blocksize ? decrypt_stream(c) : decrypt_file(c);
	}

	if (c->status != STATUS_RUNNING)
		return (void *)c->status;

	c->current.offset = c->current.size;
	c->total.offset = c->total.size;

	if (c->version != VERSION_2011_08 && !c->raw)
	{
		/*
		 * verify checksum (on versions which calculated it correctly)
		 */
		uint8_t *cs = NULL;
		size_t cl = 0;
		io_encryption_checksum(c->source, &cs, &cl);
		uint8_t *b = gcry_malloc_secure(cl);
		io_read(c->source, b, cl);
		if (memcmp(b, cs, cl))
			c->status = STATUS_WARNING_CHECKSUM;
		gcry_free(cs);
		gcry_free(b);
	}

	if (!c->raw)
		skip_random_data(c);

	if (c->kdf_iterations && c->version >= VERSION_2020_01)
	{
		uint8_t *mac = NULL;
		size_t mac_length = 0;
		io_encryption_mac(c->source, &mac, &mac_length);
		uint8_t *b = gcry_malloc_secure(mac_length);
		io_read(c->source, b, mac_length);
		if (memcmp(b, mac, mac_length))
			c->status = STATUS_WARNING_CHECKSUM;
		gcry_free(mac);
		gcry_free(b);
	}

	/*
	 * done
	 */
	if (c->output)
		io_sync(c->output);
	if (c->status == STATUS_RUNNING)
		c->status = STATUS_SUCCESS;

#ifndef __DEBUG__
	pthread_exit((void *)c->status);
#endif

#if defined _WIN32 || defined __sun || defined __clang__ || defined __DEBUG__
	return (void *)c->status;
#endif
}

static uint64_t read_version(crypto_t *c)
{
	uint64_t head[3] = { 0x0 };
	if ((io_read(c->source, head, sizeof head)) < 0)
		return 0;
	if (head[0] != htonll(HEADER_0) || head[1] != htonll(HEADER_1))
		return 0;

	version_e v = check_version(ntohll(head[2]));
	if (v >= VERSION_2015_10 && !c->raw)
		io_correction_init(c->source);

	uint8_t l;
	io_read(c->source, &l, sizeof l);
	char *z = gcry_calloc_secure(l + sizeof( char ), sizeof( char ));
	io_read(c->source, z, l);
	char *h = strchr(z, '/');
	*h = '\0';
	h++;
	char *m = strchr(h, '/');
	char *a = NULL;
	char *k = NULL;
	/* see if there's a cipher mode */
	if (m)
	{
		*m = '\0';
		m++;
		/* see if there's a MAC */
		if ((a = strchr(m, '/')))
		{
			*a = '\0';
			a++;
			/* see if there's a KDF iterations value */
			if ((k = strchr(a, '/')))
			{
				*k = '\0';
				k++;
			}
		}
	}
	else
		m = "CBC";
	c->cipher = cipher_id_from_name(z);
	c->hash = hash_id_from_name(h);
	c->mode = mode_id_from_name(m);
	if (v >= VERSION_2017_09)
		c->mac = mac_id_from_name(a);
	if (v >= VERSION_2020_01 && k)
		c->kdf_iterations = strtoull(k, NULL, 0x10);
	gcry_free(z);
	return v;
}

static bool read_verification_sum(crypto_t *c)
{
	/*
	 * read three 64bit signed integers and assert that x ^ y = z
	 */
	uint64_t x = 0;
	uint64_t y = 0;
	uint64_t z = 0;
	io_read(c->source, &x, sizeof x);
	io_read(c->source, &y, sizeof y);
	io_read(c->source, &z, sizeof z);
	x = ntohll(x);
	y = ntohll(y);
	z = ntohll(z);
	if ((x ^ y) != z)
		return c->status = STATUS_FAILED_DECRYPTION, false;
	return true;
}

static bool read_metadata(crypto_t *c)
{
	/*
	 * read the original file metadata - skip any unknown tag values
	 */
	uint8_t h = 0;
	TLV tlv = tlv_init();
	io_read(c->source, &h, sizeof h);
	for (int i = 0; i < h; i++)
	{
		tlv_t t;
		io_read(c->source, &t.tag, sizeof( byte_t ));
		io_read(c->source, &t.length, sizeof t.length);
		t.length = ntohs(t.length);
		if (!(t.value = gcry_malloc_secure(t.length)))
			die(_("Out of memory @ %s:%d:%s [%d]"), __FILE__, __LINE__, __func__, t.length);
		io_read(c->source, t.value, t.length);
		tlv_append(tlv, t);
		gcry_free(t.value);
	}

	if (tlv_has_tag(tlv, TAG_SIZE))
	{
		memcpy(&c->total.size, tlv_value_of(tlv, TAG_SIZE), sizeof c->total.size);
		c->total.size = ntohll(c->total.size);
		c->blocksize = 0;
	}

	if (tlv_has_tag(tlv, TAG_BLOCKED))
	{
		memcpy(&c->blocksize, tlv_value_of(tlv, TAG_BLOCKED), sizeof c->blocksize);
		c->blocksize = ntohll(c->blocksize);
	}
	else
		c->blocksize = 0;

	c->compressed = tlv_has_tag(tlv, TAG_COMPRESSED) ? tlv_value_of(tlv, TAG_COMPRESSED)[0] : false;
	c->directory = tlv_has_tag(tlv, TAG_DIRECTORY) ? tlv_value_of(tlv, TAG_DIRECTORY)[0] : false;
	if (c->directory)
	{
		struct stat s;
		stat(c->path, &s);
		if ((errno == ENOENT || S_ISDIR(s.st_mode)) && !io_is_initialised(c->output))
			dir_mk_recursive(c->path, S_IRUSR | S_IWUSR | S_IXUSR);
		else
			c->status = STATUS_FAILED_OUTPUT_MISMATCH;
	}
	else
	{
		if (!io_is_initialised(c->output))
		{
			/* directory was specified, but we're not decrypting a directory */
			if (tlv_has_tag(tlv, TAG_FILENAME))
			{
				/* use what's in the metadata (if it's there) */
				if (c->name)
					free(c->name);
				c->name = strndup((char *)tlv_value_of(tlv, TAG_FILENAME), tlv_length_of(tlv, TAG_FILENAME));
			}
			io_release(c->output);
			struct stat s;
			stat(c->path, &s);
			if (errno == ENOENT || S_ISREG(s.st_mode))
				;
			else if (S_ISDIR(s.st_mode))
			{
				char *ptr = NULL;
				asprintf(&ptr, "%s/%s", c->path, c->name ? : "decrypted");
				free(c->path);
				c->path = ptr;
			}
			else
				c->status = STATUS_FAILED_OUTPUT_MISMATCH;
			if (!(c->output = io_open(c->path, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK | O_BINARY, S_IRUSR | S_IWUSR)))
				c->status = STATUS_FAILED_IO;
		}
	}

	tlv_deinit(tlv);
	return c->status == STATUS_RUNNING;
}

static void skip_random_data(crypto_t *c)
{
	uint8_t l;
	io_read(c->source, &l, sizeof l);
	uint8_t *b = gcry_malloc_secure(l);
	if (l)
	{
		if (!b)
			die(_("Out of memory @ %s:%d:%s [%hhu]"), __FILE__, __LINE__, __func__, l);
		io_read(c->source, b, l);
		gcry_free(b);
	}
	return;
}

static void decrypt_directory(crypto_t *c, const char *dir)
{
	bool lnerr = false;
	for (c->total.offset = 0; c->total.offset < c->total.size && c->status == STATUS_RUNNING; c->total.offset++)
	{
		file_type_e tp = 0x0;
		io_read(c->source, &tp, sizeof( byte_t ));
		uint64_t l;
		io_read(c->source, &l, sizeof l);
		l = ntohll(l);
		char *filename = NULL;
		if (!(filename = gcry_calloc_secure(l + sizeof( byte_t ), sizeof( char ))))
			die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, l + sizeof( byte_t ));
		io_read(c->source, filename, l);
		char *fullpath = NULL;
		if (!asprintf(&fullpath, "%s/%s", dir, filename))
			die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2 * sizeof( byte_t ));
		c->current.display = fullpath;
		switch (tp)
		{
			case FILE_DIRECTORY:
				dir_mk_recursive(fullpath, S_IRUSR | S_IWUSR | S_IXUSR);
				break;
			case FILE_SYMLINK:
			case FILE_LINK:
				io_read(c->source, &l, sizeof l);
				l = ntohll(l);
				char *lnk = gcry_calloc_secure(l + sizeof( byte_t ), sizeof( byte_t ));
				if (!lnk)
					die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, l + sizeof( byte_t ));
				io_read(c->source, lnk, l);
				if (tp == FILE_SYMLINK)
				{
#ifndef _WIN32
					symlink(lnk, fullpath);
#else
					lnerr = true;
#endif
				}
				else
				{
					char *hl = NULL;
					if (!asprintf(&hl, "%s/%s", dir, lnk))
						die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(dir) + strlen(lnk) + 2);
					/* NB: on Windows this is just a copy not a link */
					link(hl, fullpath);
					free(hl);
				}
				break;
			case FILE_REGULAR:
				c->current.offset = 0;
				io_read(c->source, &c->current.size, sizeof c->current.size);
				c->current.size = ntohll(c->current.size);
				if (c->output)
					io_close(c->output);
				c->output = io_open(fullpath, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK | O_BINARY, S_IRUSR | S_IWUSR);
				decrypt_file(c);
				io_close(c->output);
				c->output = NULL;
				c->current.offset = c->total.size;
				break;
		}
		c->current.display = NULL;
		gcry_free(filename);
		gcry_free(fullpath);
	}
	if (lnerr)
		c->status = STATUS_WARNING_LINK;
	return;
}

static void decrypt_stream(crypto_t *c)
{
	bool b = true;
	uint8_t *buffer;
	if (!(buffer = gcry_malloc_secure(c->blocksize + sizeof b)))
		die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->blocksize + sizeof b);
	while (b && c->status == STATUS_RUNNING)
	{
		errno = EXIT_SUCCESS;
		int64_t r = io_read(c->source, buffer, c->blocksize + sizeof b);
		if (r < 0)
		{
			c->status = r < -1 ? STATUS_FAILED_LZMA : STATUS_FAILED_IO;
			break;
		}
		memcpy(&b, buffer, sizeof b);
		r -= sizeof b;
		memmove(buffer, buffer + sizeof b, r);
		if (!b)
		{
			io_read(c->source, &r, sizeof r);
			r = ntohll(r);
		}
		io_write(c->output, buffer, r);
		c->current.offset += r;
	}
	gcry_free(buffer);
	return;
}

static void decrypt_file(crypto_t *c)
{
	uint8_t buffer[BLOCK_SIZE];
	for (c->current.offset = 0; c->current.offset < c->current.size && c->status == STATUS_RUNNING; c->current.offset += BLOCK_SIZE)
	{
		errno = EXIT_SUCCESS;
		size_t l = BLOCK_SIZE;
		if (c->current.offset + BLOCK_SIZE > c->current.size)
			l = BLOCK_SIZE - (c->current.offset + BLOCK_SIZE - c->current.size);
		int64_t r = io_read(c->source, buffer, l);
		if (r < 0)
		{
			c->status = r < -1 ? STATUS_FAILED_LZMA : STATUS_FAILED_IO;
			break;
		}
		io_write(c->output, buffer, r);
	}
	return;
}
