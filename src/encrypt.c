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
#include <sys/stat.h>
#include <dirent.h>

#include <pthread.h>

#include <ctype.h>
#include <inttypes.h> /* used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself) */
#include <stdbool.h>
#include <string.h>

#ifndef _WIN32
	#include <netinet/in.h>
#endif

#include <gcrypt.h>

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/tlv.h"
#include "common/dir.h"

#include "crypt.h"
#include "encrypt.h"
#include "crypt_io.h"

static void *process(void *);

static inline void write_header(crypto_t *);
static inline void write_verification_sum(crypto_t *);
static inline void write_metadata(crypto_t *);
static inline void write_random_data(crypto_t *);

static int64_t count_entries(crypto_t *, const char *);

static void encrypt_directory(crypto_t *, const char *);
static char *encrypt_link(crypto_t *, char *, struct stat);
static void encrypt_stream(crypto_t *);
static void encrypt_file(crypto_t *);

typedef struct
{
	dev_t dev;
	ino_t inode;
	char *path;
}
link_count_t;

extern crypto_t *encrypt_init(const char * const restrict i,
                              const char * const restrict o,
                              const char * const restrict c,
                              const char * const restrict h,
                              const char * const restrict m,
                              const char * const restrict a,
                              const void * const restrict k,
                              size_t l, uint64_t n, bool r, bool x, bool f, version_e v)
{
	init_crypto();

	crypto_t *z = gcry_calloc_secure(1, sizeof( crypto_t ));
	if (!z)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( crypto_t ));

	z->status = STATUS_INIT;

	z->path = NULL;
	z->directory = false;
	if (i)
	{
		struct stat s;
		stat(i, &s);
		z->name = dir_get_name(i);
		if (S_ISDIR(s.st_mode))
		{
			z->source = IO_UNINITIALISED;
			z->path = strdup(i);
			z->directory = true;
		}
		else
		{
			if (!(z->source = io_open(i, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR)))
				return z->status = STATUS_FAILED_IO , z;
		}
	}
	else
		z->source = IO_STDIN_FILENO;

	if (o)
	{
		struct stat s;
		stat(o, &s);
		char *op = NULL;
		if (errno == ENOENT || S_ISREG(s.st_mode))
			op = strdup(o);
		else if (S_ISDIR(s.st_mode))
		{
			char *p = dir_get_path(i);
			if (!strcmp(p, i))
				asprintf(&op, "%s.X", z->name);
			else
				asprintf(&op, "%s%s%s.X", o, o[strlen(o) - 1] == DIR_SEPARATOR_CHAR ? "" : DIR_SEPARATOR, z->name);
			gcry_free(p);
		}
		else
			return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
#ifdef _WIN32
		long fa = GetFileAttributes(op);
		switch (fa)
		{
			case FILE_ATTRIBUTE_DIRECTORY:
				return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
			case INVALID_FILE_ATTRIBUTES:
				break; /* file doesn’t exist; that’s okay */
			default:
				chmod(op, 0600); /* this seems to work */
		}
#endif
		z->output = io_open(op, O_CREAT | O_TRUNC |  O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
		gcry_free(op);
		if (!z->output)
			return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
	}
	else
		z->output = IO_STDOUT_FILENO;

	if (l)
	{
		if (!(z->key = gcry_malloc_secure(l)))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, l);
		memcpy(z->key, k, l);
		z->length = l;
	}
	else
	{
		int64_t kf = open(k, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR);
		if (kf < 0)
			return z->status = STATUS_FAILED_IO , z;
		z->length = lseek(kf, 0, SEEK_END);
		lseek(kf, 0, SEEK_SET);
		if (!(z->key = gcry_malloc_secure(z->length)))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, z->length);
		read(kf, z->key, z->length);
		close(kf);
	}

	z->process = process;

	if ((z->cipher = cipher_id_from_name(c)) == GCRY_CIPHER_NONE)
		return z->status = STATUS_FAILED_UNKNOWN_CIPHER_ALGORITHM , z;
	if ((z->hash = hash_id_from_name(h)) == GCRY_MD_NONE)
		return z->status = STATUS_FAILED_UNKNOWN_HASH_ALGORITHM , z;
	if ((z->mode = mode_id_from_name(m)) == GCRY_CIPHER_MODE_NONE)
		return z->status = STATUS_FAILED_UNKNOWN_CIPHER_MODE , z;
	if ((z->mac = mac_id_from_name(a)) == GCRY_MAC_NONE)
		return z->status = STATUS_FAILED_UNKNOWN_MAC_ALGORITHM , z;

	z->blocksize = BLOCK_SIZE;
	z->compressed = x;
	z->follow_links = f;

	/* if the user wants to skip the header information then they either
	 * know what they’re doing, or they’re an idiot; either way it will
	 * override almost everything else
	 */
	if ((z->raw = r))
		v = VERSION_CURRENT;

	z->version = v ? : VERSION_CURRENT;
	/*
	 * determine which settings are valid for the given version
	 */
	switch (z->version)
	{
		case VERSION_2011_08:
		case VERSION_2011_10:
			/*
			 * single file only; if we don’t split the plaintext into
			 * blocks or compress it then both versions are identical
			 */
			z->version = VERSION_2011_08;
			z->compressed = false;
			__attribute__((fallthrough)); /* allow fall-through to check for directories */
		case VERSION_2012_11:
			/* allow compression, but not directories */
			if (z->source == IO_UNINITIALISED)
				return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
				//die(_("Compatibility with version %s does not allow encrypting directories"), get_version_string(z->version));
			/* if not compressing, fallback even more */
			if (!z->compressed)
				z->version = VERSION_2011_08;
			z->mode = mode_id_from_name("CBC");
			break;
		case VERSION_2013_02:
			z->follow_links = true;
			__attribute__((fallthrough)); /* allow fall-through to force CBC mode */
		case VERSION_2013_11:
			z->mode = mode_id_from_name("CBC");
			break;
		case VERSION_2014_06:
			/* fall back if using CBC */
			if (z->mode == GCRY_CIPHER_MODE_CBC)
				z->version = VERSION_2013_11;
			break;
		case VERSION_2015_01:
		case VERSION_2015_10:
			break;
		case VERSION_2017_09:
			z->kdf_iterations = KEY_ITERATIONS_201709;
			break;
		case VERSION_2020_01:
		case VERSION_2022_01:
			z->kdf_iterations = n ? : KEY_ITERATIONS_DEFAULT;
		// case VERSION_CURRENT:
			/*
			 * do nothing, all options are available; not falling back
			 * allows extra padding at beginning of file
			 */
			break;
		default:
			die(_("We’ve reached an unreachable location in the code @ %s:%d:%s"), __FILE__, __LINE__, __func__);
	}
	return z;
}

static void *process(void *ptr)
{
	crypto_t *c = (crypto_t *)ptr;

	if (!c || c->status != STATUS_INIT)
		return NULL;

	if (!c->raw)
		write_header(c);

	bool pre_random = true;
	x_iv_e iv_type = IV_RANDOM;
	switch (c->version)
	{
		case VERSION_2011_08:
		case VERSION_2011_10:
			iv_type = IV_BROKEN;
			__attribute__((fallthrough)); /* allow fall-through for broken IV compatibility */
		case VERSION_2012_11:
			pre_random = false;
			break;
		case VERSION_2013_02:
		case VERSION_2013_11:
		case VERSION_2014_06:
			iv_type = IV_SIMPLE;
			__attribute__((fallthrough)); /* allow fall-through for broken key derivation */
		case VERSION_2015_01:
		case VERSION_2015_10:
		case VERSION_2017_09:
		case VERSION_2020_01:
		case VERSION_2022_01:
		default:
			/* no changes */
			break;
	}

	/*
	 * all data written from here on is encrypted (with the exception
	 * of the IV and salt, both of which are auto-generated during
	 * the encryption initialisation)
	 */
	io_extra_t iox = { iv_type, true };
	io_encryption_init(c->output, c->cipher, c->hash, c->mode, c->mac, c->kdf_iterations, c->key, c->length, iox);
	c->status = STATUS_RUNNING;
	gcry_free(c->key);
	c->key = NULL;

	if (!c->raw)
	{
		if (pre_random)
			write_random_data(c);
		write_verification_sum(c);
		write_random_data(c);
	}
	write_metadata(c);

	if (pre_random && !c->raw)
		write_random_data(c);

	/*
	 * main encryption loop; if we’re compressing the output then
	 * everything from here will be compressed (if necessary)
	 */
	if (c->compressed)
		io_compression_init(c->output);

	io_encryption_checksum_init(c->output, c->hash);

	if (c->directory)
	{
		file_type_e tp = FILE_DIRECTORY;
		io_write(c->output, &tp, sizeof( byte_t ));
		/*
		 * strip leading directories and trailing /
		 */
		char *ps = c->path + (strlen(c->path) - 1);
		if (*ps == '/')
			*ps = '\0';
		char *cwd = NULL;
#ifndef _WIN32
		char *dir = strrchr(c->path, '/');
#else
		char *dir = strrchr(c->path, '\\');
#endif
		if (dir)
		{
			*dir = '\0';
			dir++;
			cwd = getcwd(NULL, 0);
			chdir(c->path);
			free(c->path);
			if (!(c->path = strdup(dir)))
				die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(dir));
		}
		uint64_t l = htonll(strlen(c->path));
		io_write(c->output, &l, sizeof l);
		io_write(c->output, c->path, strlen(c->path));
		c->total.offset = 1;
		if (!(c->misc = gcry_calloc_secure(c->total.size, sizeof( link_count_t ))))
			die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->total.size * sizeof( link_count_t ));
		encrypt_directory(c, c->path);
		c->current.display = FINISHING_UP;
		for (uint64_t i = 0; i < c->total.size; i++)
			if (((link_count_t *)c->misc)[i].path)
				gcry_free(((link_count_t *)c->misc)[i].path);
		gcry_free(c->misc);
		c->misc = NULL;
		if (cwd)
		{
			chdir(cwd);
			gcry_free(cwd);
		}
	}
	else
	{
		c->current.size = c->total.size;
		c->total.size = 1;
		c->blocksize ? encrypt_stream(c) : encrypt_file(c);
	}

	if (c->status != STATUS_RUNNING)
		return (void *)c->status;

	c->current.offset = c->current.size;
	c->total.offset = c->total.size;

	/*
	 * write checksum
	 */
	if (!c->raw)
	{
		uint8_t *cs = NULL;
		size_t cl = 0;
		io_encryption_checksum(c->output, &cs, &cl);
		io_write(c->output, cs, cl);
		gcry_free(cs);

		write_random_data(c);
	}

	if (c->kdf_iterations)
	{
		/*
		 * using a key derivation function also gives a MAC
		 */
		uint8_t *mac = NULL;
		size_t mac_length = 0;
		io_encryption_mac(c->output, &mac, &mac_length);
		io_write(c->output, mac, mac_length);
		gcry_free(mac);
	}

	/*
	 * done
	 */
	io_sync(c->output);
	c->status = STATUS_SUCCESS;

#ifndef __DEBUG__
	pthread_exit((void *)c->status);
#endif

#if defined _WIN32 || defined __sun || defined __clang__ || defined __DEBUG__
	return (void *)c->status;
#endif
}

static inline void write_header(crypto_t *c)
{
	uint64_t head[3] = { htonll(HEADER_0), htonll(HEADER_1), htonll(get_version(c->version)) };
	io_write(c->output, head, sizeof head);
	if (c->version >= VERSION_2015_10 && !c->raw) /* only since 2015_10 do we support ecc (and only when not in raw mode) */
		io_correction_init(c->output);
	char *algos = NULL;
	const char *u_cipher = cipher_name_from_id(c->cipher);
	const char *u_hash = hash_name_from_id(c->hash);
	const char *u_mode = mode_name_from_id(c->mode);
	const char *u_mac = mac_name_from_id(c->mac);
	if (c->version >= VERSION_2020_01)
	{
		/*
		 * NB KDF iters doesn't need htonll because it's displayed
		 * as a string (albeit in hex)
		 */
		if (!asprintf(&algos, "%s/%s/%s/%s/%016" PRIX64, u_cipher, u_hash, u_mode, u_mac, c->kdf_iterations))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(u_cipher) + strlen(u_hash) + strlen(u_mode) + strlen(u_mac) + 4);
	}
	else if (c->version >= VERSION_2017_09)
	{
		if (!asprintf(&algos, "%s/%s/%s/%s", u_cipher, u_hash, u_mode, u_mac))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(u_cipher) + strlen(u_hash) + strlen(u_mode) + strlen(u_mac) + 4);
	}
	else if (c->version >= VERSION_2014_06)
	{
		if (!asprintf(&algos, "%s/%s/%s", u_cipher, u_hash, u_mode))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(u_cipher) + strlen(u_hash) + strlen(u_mode) + 3);
	}
	else
		if (!asprintf(&algos, "%s/%s", u_cipher, u_hash))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(u_cipher) + strlen(u_hash) + 2);
	uint8_t h = (uint8_t)strlen(algos);
	io_write(c->output, &h, sizeof h);
	io_write(c->output, algos, h);
	gcry_free(algos);
	return;
}

static inline void write_verification_sum(crypto_t *c)
{
	/*
	 * write simple addition (x ^ y = z) where x, y are random 64 bit
	 * signed integers
	 */
	uint64_t x;
	uint64_t y;
	gcry_create_nonce(&x, sizeof x);
	gcry_create_nonce(&y, sizeof y);
	uint64_t z = x ^ y;
	x = htonll(x);
	y = htonll(y);
	z = htonll(z);
	io_write(c->output, &x, sizeof x);
	io_write(c->output, &y, sizeof y);
	io_write(c->output, &z, sizeof z);
	return;
}

static inline void write_metadata(crypto_t *c)
{
	if (c->directory)
		c->total.size = count_entries(c, c->path);
	else
	{
		c->total.size = io_seek(c->source, 0, SEEK_END);
		io_seek(c->source, 0, SEEK_SET);
	}

	TLV_HANDLE tlv = tlv_init();
	if (io_is_stdin(c->source))
	{
		uint64_t i = htonll(c->blocksize);
		tlv_t t = { TAG_BLOCKED, sizeof i, &i };
		tlv_append(&tlv, t);
	}
	else
	{
		c->blocksize = 0;
		uint64_t i = htonll(c->total.size);
		tlv_t t = { TAG_SIZE, sizeof i, &i };
		tlv_append(&tlv, t);
	}
	if (c->compressed)
	{
		bool b = c->compressed;
		tlv_t t = { TAG_COMPRESSED, sizeof b, &b };
		tlv_append(&tlv, t);
	}
	if (c->directory)
	{
		bool b = c->directory;
		tlv_t t = { TAG_DIRECTORY, sizeof b, &b };
		tlv_append(&tlv, t);
	}
	if (!c->directory && c->name && c->version >= VERSION_2015_01)
	{   /* after 2012.11 unknown tags are ignored, and this tag doesn't impact anything */
		tlv_t t = { TAG_FILENAME, strlen(c->name), c->name };
		tlv_append(&tlv, t);
	}
	uint8_t h = tlv_count(tlv);
	io_write(c->output, &h, sizeof h);
	io_write(c->output, tlv_export(tlv), tlv_size(tlv));
	tlv_deinit(&tlv);
	return;
}

static inline void write_random_data(crypto_t *c)
{
	uint8_t l;
#ifndef __DEBUG__
	do
	{
		gcry_create_nonce(&l, sizeof l);
	}
	while (!l);
#else
	l = 1; /* keep the same structure (include this junk) but limit it */
#endif
	uint8_t *b = gcry_malloc_secure(l);
	if (!b)
		die(_("Out of memory @ %s:%d:%s [%hhu]"), __FILE__, __LINE__, __func__, l);
	gcry_create_nonce(b, l);
	io_write(c->output, &l, sizeof l);
	io_write(c->output, b, l);
	gcry_free(b);
	return (void)c;
}

static int64_t count_entries(crypto_t *c, const char *dir)
{
	struct dirent **eps = NULL;
	int n = 0;
	int64_t e = 1;
	errno = 0;
	if ((n = scandir(dir, &eps, NULL, NULL)))
	{
		for (int i = 0; i < n; ++i)
		{
			if (!strcmp(".", eps[i]->d_name) || !strcmp("..", eps[i]->d_name))
				continue;
			size_t l = strlen(eps[i]->d_name);
			char *filename = NULL;
			if (!asprintf(&filename, "%s/%s", dir, eps[i]->d_name))
				die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
			struct stat s;
			c->follow_links ? stat(filename, &s) : lstat(filename, &s);
			if (S_ISDIR(s.st_mode))
				e += count_entries(c, filename);
			else if (S_ISREG(s.st_mode))
				e++;
#ifndef _WIN32
			else if (!c->follow_links && S_ISLNK(s.st_mode))
				e++;
#endif
			gcry_free(filename);
		}
	}
	for (int i = 0; i < n; ++i)
		gcry_free(eps[i]);
	gcry_free(eps);
	return e;
}

static void encrypt_directory(crypto_t *c, const char *dir)
{
	struct dirent **eps = NULL;
	int n = 0;
	if ((n = scandir(dir, &eps, NULL, NULL)))
	{
		for (int i = 0; i < n && c->status == STATUS_RUNNING; ++i)
		{
			if (!strcmp(".", eps[i]->d_name) || !strcmp("..", eps[i]->d_name))
				continue;
			uint64_t l = strlen(eps[i]->d_name);
			char *filename = NULL;
			if (!asprintf(&filename, "%s/%s", dir, eps[i]->d_name))
				die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
			c->current.display = filename;
			file_type_e tp;
			struct stat s;
			c->follow_links ? stat(filename, &s) : lstat(filename, &s);
			char *ln = NULL;
			switch (s.st_mode & S_IFMT)
			{
				case S_IFDIR:
					tp = FILE_DIRECTORY;
					break;
#ifndef _WIN32
				case S_IFLNK:
					tp = (ln = encrypt_link(c, filename, s)) ? FILE_LINK : FILE_SYMLINK;
					break;
#endif
				case S_IFREG:
					tp = (ln = encrypt_link(c, filename, s)) ? FILE_LINK : FILE_REGULAR;
					break;
				default:
					gcry_free(filename);
					continue;
			}
			io_write(c->output, &tp, sizeof( byte_t ));
			l = htonll(strlen(filename));
			io_write(c->output, &l, sizeof l);
			io_write(c->output, filename, strlen(filename));
			switch (tp)
			{
				case FILE_DIRECTORY:
					/*
					 * recurse into each directory as necessary
					 */
					encrypt_directory(c, filename);
					break;
				case FILE_SYMLINK:
#ifndef _WIN32
					{
						/*
						 * store the link instead of the file/directory
						 * it points to
						 */
						char *sl = gcry_malloc_secure(sizeof( byte_t ));
						for (l = BLOCK_SIZE; ; l += BLOCK_SIZE)
						{
							char *x = gcry_realloc(sl, l + sizeof( byte_t ));
							if (!x)
								die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, l + sizeof( byte_t ) );
							sl = x;
							if (readlink(filename, sl, BLOCK_SIZE + l) < (int64_t)l)
								break;
						}
						l = htonll(strlen(sl));
						io_write(c->output, &l, sizeof l);
						io_write(c->output, sl, strlen(sl));
					}
#endif
					break;
				case FILE_LINK:
#ifndef _WIN32
					/*
					 * store a hard link; it’s basically the same as a
					 * symlink at this point, but will be handled
					 * differently upon decryption
					 */
					l = htonll(strlen(ln));
					io_write(c->output, &l, sizeof l);
					io_write(c->output, ln, strlen(ln));
#endif
					break;
				case FILE_REGULAR:
					/*
					 * when we have a file:
					 */
					if (c->source)
						io_close(c->source);
					c->source = io_open(filename, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR);
					c->current.offset = 0;
					c->current.size = io_seek(c->source, 0, SEEK_END);
					uint64_t z = htonll(c->current.size);
					io_write(c->output, &z, sizeof z);
					io_seek(c->source, 0, SEEK_SET);
					encrypt_file(c);
					c->current.offset = c->current.size;
					io_close(c->source);
					c->source = NULL;
					break;
			}
			gcry_free(filename);
			c->total.offset++;
			c->current.display = NULL;
		}
		/*
		 * no more files in this directory
		 */
	}
	for (int i = 0; i < n; ++i)
		gcry_free(eps[i]);
	gcry_free(eps);
	return;
}

static char *encrypt_link(crypto_t *c, char *filename, struct stat s)
{
	link_count_t *ln = (link_count_t *)c->misc;
#ifndef _WIN32
	for (uint64_t i = 0; i < c->total.offset; i++)
		if (ln[i].dev == s.st_dev && ln[i].inode == s.st_ino)
			return ln[i].path;
#endif
	ln[c->total.offset].dev = s.st_dev;
	ln[c->total.offset].inode = s.st_ino;
	ln[c->total.offset].path = strdup(filename);
	return NULL;
}

static void encrypt_stream(crypto_t *c)
{
	bool b = true;
	uint8_t *buffer;
	if (!(buffer = gcry_malloc_secure(c->blocksize + sizeof b)))
		die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->blocksize + sizeof b);
	do
	{
		errno = EXIT_SUCCESS;
		/*
		 * read plaintext file, write encrypted data
		 */
		memset(buffer, 0x00, c->blocksize);
		int64_t r = io_read(c->source, buffer + sizeof b, c->blocksize);
		if (r < 0)
		{
			c->status = STATUS_FAILED_IO;
			break;
		}
		else if ((uint64_t)r != c->blocksize)
			b = false;
		memcpy(buffer, &b, sizeof b);
		io_write(c->output, buffer, c->blocksize + sizeof b);
		if (!b)
		{
			r = htonll(r);
			io_write(c->output, &r, sizeof r);
		}
		c->current.offset += c->blocksize;
	}
	while (b && c->status == STATUS_RUNNING);
	gcry_free(buffer);
	return;
}

static void encrypt_file(crypto_t *c)
{
	uint8_t buffer[BLOCK_SIZE];
	for (c->current.offset = 0; c->current.offset < c->current.size && c->status == STATUS_RUNNING; c->current.offset += BLOCK_SIZE)
	{
		errno = EXIT_SUCCESS;
		/*
		 * read plaintext file, write encrypted data
		 */
		int64_t r = io_read(c->source, buffer, BLOCK_SIZE);
		if (r < 0)
		{
			c->status = STATUS_FAILED_IO;
			break;
		}
		io_write(c->output, buffer, r);
	}
	return;
}
