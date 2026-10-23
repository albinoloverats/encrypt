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

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#include <pthread.h>

#include <inttypes.h> /* used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself) */
#include <stdbool.h>
#include <string.h>

#ifndef _WIN32
	#include <netinet/in.h>
#endif

/* submodule includes */

#include "src/common.h"
#include "src/non-gnu.h"
#include "src/error.h"
#include "src/mem.h"
#include "src/ccrypt.h"
#include "src/tlv.h"
#include "src/dir.h"

/* project includes */

#include "crypt.h"
#include "decrypt.h"
#include "crypt_io.h"

static void *process(void *);

static uint64_t read_version(crypto_s *);
static bool read_verification_sum(crypto_s *);
static bool read_metadata(crypto_s *);
static char *validate_archive_path(const uint8_t *, uint64_t);
static void skip_random_data(crypto_s *);

static void decrypt_directory(crypto_s *, const char *);
static void decrypt_stream(crypto_s *);
static void decrypt_file(crypto_s *);

extern crypto_s *decrypt_init(const char * const restrict i,
                              const char * const restrict o,
                              const char * const restrict c,
                              const char * const restrict h,
                              const char * const restrict m,
                              const char * const restrict a,
                              const void * const restrict k,
                              size_t l, uint64_t n, bool r)
{
	init_crypto();

	crypto_s *z = m_gcry_calloc_secure(1, sizeof( crypto_s ));

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
				if (io_same_file(z->source, o))
					return z->status = STATUS_FAILED_OUTPUT_MISMATCH , z;
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
		z->key = m_gcry_malloc_secure(l);
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
		z->key = m_gcry_malloc_secure(z->length);
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
	crypto_s *c = (crypto_s *)ptr;

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
		case VERSION_2025_05:
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
	io_extra_s iox = { iv_type, false };
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
		uint8_t *b = m_gcry_malloc_secure(cl);
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
		uint8_t *b = m_gcry_malloc_secure(mac_length);
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

static uint64_t read_version(crypto_s *c)
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
	char *z = m_gcry_calloc_secure(l + sizeof( char ), sizeof( char ));
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

static bool read_verification_sum(crypto_s *c)
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

static bool read_metadata(crypto_s *c)
{
	/*
	 * read the original file metadata - skip any unknown tag values
	 */
	uint8_t h = 0;
	tlv_t tlv = tlv_init();
	io_read(c->source, &h, sizeof h);
	for (int i = 0; i < h; i++)
	{
		tlv_entry_s t;
		io_read(c->source, &t.tag, sizeof( byte_t ));
		io_read(c->source, &t.length, sizeof t.length);
		t.length = ntohs(t.length);
		t.value = m_gcry_malloc_secure(t.length);
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
		errno = 0;
		int output_stat = c->path ? stat(c->path, &s) : -1;
		if (!c->path)
			c->status = STATUS_FAILED_OUTPUT_MISMATCH;
		else if (output_stat < 0 && errno != ENOENT)
			c->status = STATUS_FAILED_IO;
		else if (!io_is_initialised(c->output) &&
		         (output_stat < 0 || S_ISDIR(s.st_mode)))
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
				c->name = NULL;
				char *name = validate_archive_path(tlv_value_of(tlv, TAG_FILENAME), tlv_length_of(tlv, TAG_FILENAME));
				if (!name || strchr(name, '/'))
				{
					if (name)
						gcry_free(name);
					c->status = STATUS_FAILED_OUTPUT_MISMATCH;
				}
				else
					c->name = name;
			}
			io_release(c->output);
			c->output = NULL;
			if (c->status == STATUS_RUNNING)
			{
				struct stat s;
				if (stat(c->path, &s) < 0)
				{
					if (errno != ENOENT)
						c->status = STATUS_FAILED_IO;
				}
				else if (S_ISDIR(s.st_mode))
				{
					char *ptr = NULL;
					m_asprintf(&ptr, "%s/%s", c->path, c->name ? : "decrypted");
					free(c->path);
					c->path = ptr;
				}
				else if (!S_ISREG(s.st_mode))
					c->status = STATUS_FAILED_OUTPUT_MISMATCH;
			}
			if (c->status == STATUS_RUNNING && io_same_file(c->source, c->path))
				c->status = STATUS_FAILED_OUTPUT_MISMATCH;
			if (c->status == STATUS_RUNNING && !(c->output = io_open(c->path, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK | O_BINARY, S_IRUSR | S_IWUSR)))
				c->status = STATUS_FAILED_IO;
		}
	}

	tlv_deinit(tlv);
	return c->status == STATUS_RUNNING;
}

static void skip_random_data(crypto_s *c)
{
	uint8_t l;
	io_read(c->source, &l, sizeof l);
	uint8_t *b = m_gcry_malloc_secure(l);
	if (l)
	{
		io_read(c->source, b, l);
		gcry_free(b);
	}
	return;
}

static char *validate_archive_path(const uint8_t *path, uint64_t length)
{
	if (!length || length > SIZE_MAX - 1 || memchr(path, '\0', (size_t)length))
		return NULL;
	if (path[0] == '/' || path[0] == '\\')
		return NULL;

	char *result = m_gcry_malloc_secure((size_t)length + 1);
	memcpy(result, path, (size_t)length);
	result[length] = '\0';
	for (size_t i = 0; i < (size_t)length; i++)
	{
		if (result[i] == '\\')
			result[i] = '/';
		if (result[i] == ':')
		{
			gcry_free(result);
			return NULL;
		}
	}

	char *component = result;
	for (char *p = result; ; p++)
	{
		if (*p != '/' && *p != '\0')
			continue;
		if (p == component || (p - component == 1 && component[0] == '.') ||
		    (p - component == 2 && component[0] == '.' && component[1] == '.'))
		{
			gcry_free(result);
			return NULL;
		}
		if (!*p)
			break;
		component = p + 1;
	}
	return result;
}

static bool validate_symlink_target(const uint8_t *target, uint64_t length, const char *link_path)
{
	if (!length || length > SIZE_MAX - 1 || memchr(target, '\0', (size_t)length))
		return false;
	if (target[0] == '/' || target[0] == '\\')
		return false;

	size_t depth = 0;
	for (const char *p = link_path; *p; p++)
		if (*p == '/')
			depth++;

	size_t component_start = 0;
	for (size_t i = 0; i <= (size_t)length; i++)
	{
		if (i < (size_t)length && target[i] != '/' && target[i] != '\\')
		{
			if (target[i] == ':')
				return false;
			continue;
		}
		size_t component_length = i - component_start;
		if (!component_length)
			return false;
		if (component_length == 1 && target[component_start] == '.')
			;
		else if (component_length == 2 && target[component_start] == '.' && target[component_start + 1] == '.')
		{
			if (!depth)
				return false;
			depth--;
		}
		else
			depth++;
		component_start = i + 1;
	}
	return true;
}

#ifndef _WIN32
static int open_extract_parent(int root, char *path, bool create, char **leaf)
{
	int parent = dup(root);
	if (parent < 0)
		return -1;

	char *component = path;
	char *separator;
	while ((separator = strchr(component, '/')))
	{
		*separator = '\0';
		int next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (next < 0 && create && errno == ENOENT)
		{
			if (mkdirat(parent, component, S_IRWXU) < 0 && errno != EEXIST)
			{
				close(parent);
				return -1;
			}
			next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		}
		*separator = '/';
		if (next < 0)
		{
			close(parent);
			return -1;
		}
		close(parent);
		parent = next;
		component = separator + 1;
	}
	*leaf = component;
	return parent;
}

static bool ensure_extract_directory(int root, char *path)
{
	char *leaf = NULL;
	int parent = open_extract_parent(root, path, true, &leaf);
	if (parent < 0)
		return false;
	if (mkdirat(parent, leaf, S_IRWXU) == 0)
	{
		close(parent);
		return true;
	}
	if (errno != EEXIST)
	{
		close(parent);
		return false;
	}
	int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	close(parent);
	if (directory < 0)
		return false;
	close(directory);
	return true;
}

static int open_extract_file(int root, char *path)
{
	char *leaf = NULL;
	int parent = open_extract_parent(root, path, true, &leaf);
	if (parent < 0)
		return -1;
	int fd = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
	close(parent);
	return fd;
}

static bool create_extract_symlink(int root, const char *target, char *path)
{
	char *leaf = NULL;
	int parent = open_extract_parent(root, path, true, &leaf);
	if (parent < 0)
		return false;
	bool okay = symlinkat(target, parent, leaf) == 0;
	close(parent);
	return okay;
}

static bool symlink_target_uses_no_existing_links(int root, char *link_path, const char *target)
{
	char *leaf = NULL;
	int current = open_extract_parent(root, link_path, true, &leaf);
	if (current < 0)
		return false;

	size_t depth = 0;
	for (const char *p = link_path; *p; p++)
		if (*p == '/')
			depth++;

	char *copy = strdup(target);
	char *component = copy;
	for (char *p = copy; ; p++)
	{
		if (*p == '\\')
			*p = '/';
		if (*p != '/' && *p != '\0')
			continue;

		char saved = *p;
		*p = '\0';
		if (!strcmp(component, "."))
			;
		else if (!strcmp(component, ".."))
		{
			if (!depth)
			{
				free(copy);
				close(current);
				return false;
			}
			int parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (parent < 0)
			{
				free(copy);
				close(current);
				return false;
			}
			close(current);
			current = parent;
			depth--;
		}
		else
		{
			struct stat s;
			if (fstatat(current, component, &s, AT_SYMLINK_NOFOLLOW) < 0)
			{
				if (errno != ENOENT)
				{
					free(copy);
					close(current);
					return false;
				}
				free(copy);
				close(current);
				return true;
			}
			if (S_ISLNK(s.st_mode))
			{
				free(copy);
				close(current);
				return false;
			}
			if (S_ISDIR(s.st_mode))
			{
				int next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
				if (next < 0)
				{
					free(copy);
					close(current);
					return false;
				}
				close(current);
				current = next;
				depth++;
			}
			else
			{
				free(copy);
				close(current);
				return true;
			}
		}
		if (!saved)
			break;
		component = p + 1;
	}

	free(copy);
	close(current);
	return true;
}

static bool create_extract_hardlink(int root, char *target, char *path)
{
	char *target_leaf = NULL;
	char *link_leaf = NULL;
	int target_parent = open_extract_parent(root, target, false, &target_leaf);
	if (target_parent < 0)
		return false;
	int link_parent = open_extract_parent(root, path, true, &link_leaf);
	if (link_parent < 0)
	{
		close(target_parent);
		return false;
	}
	bool okay = linkat(target_parent, target_leaf, link_parent, link_leaf, 0) == 0;
	close(target_parent);
	close(link_parent);
	return okay;
}
#else
static char *join_extract_path(const char *root, const char *path)
{
	char *native = strdup(path);
	for (char *p = native; *p; p++)
		if (*p == '/')
			*p = DIR_SEPARATOR_CHAR;
	char *result = m_strdupf("%s%s%s", root,
	                         root[strlen(root) - 1] == DIR_SEPARATOR_CHAR ? "" : DIR_SEPARATOR,
	                         native);
	free(native);
	return result;
}

static bool windows_path_has_no_reparse_component(const char *root, const char *path)
{
	char *full = join_extract_path(root, path);
	for (char *p = full + strlen(root) + 1; *p; p++)
	{
		if (*p != DIR_SEPARATOR_CHAR)
			continue;
		char saved = *p;
		*p = '\0';
		DWORD attributes = GetFileAttributesA(full);
		*p = saved;
		if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
		{
			gcry_free(full);
			return false;
		}
	}
	DWORD attributes = GetFileAttributesA(full);
	gcry_free(full);
	return attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
#endif

static void decrypt_directory(crypto_s *c, const char *dir)
{
#ifndef _WIN32
	int root = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root < 0)
	{
		c->status = STATUS_FAILED_IO;
		return;
	}
	typedef struct
	{
		char *target;
		char *path;
	}
	deferred_symlink_s;
	deferred_symlink_s *symlinks = NULL;
	size_t symlink_count = 0;
#endif
	char **regular_paths = NULL;
	size_t regular_count = 0;
	bool lnerr = false;
	for (c->total.offset = 0; c->total.offset < c->total.size && c->status == STATUS_RUNNING; c->total.offset++)
	{
		file_type_e tp = 0x0;
		uint64_t l = 0;
		if (io_read(c->source, &tp, sizeof( byte_t )) != sizeof( byte_t ) ||
		    io_read(c->source, &l, sizeof l) != sizeof l)
		{
			c->status = STATUS_FAILED_IO;
			break;
		}
		l = ntohll(l);
		char *filename = l <= SIZE_MAX - 1 && l <= SSIZE_MAX ? m_gcry_malloc_secure((size_t)l + 1) : NULL;
		if (!filename || io_read(c->source, filename, (size_t)l) != (ssize_t)l)
		{
			if (filename)
				gcry_free(filename);
			c->status = STATUS_FAILED_IO;
			break;
		}
		char *path = validate_archive_path((uint8_t *)filename, l);
		gcry_free(filename);
		if (!path)
		{
			c->status = STATUS_FAILED_OUTPUT_MISMATCH;
			break;
		}
		char *fullpath = NULL;
#ifdef _WIN32
		fullpath = join_extract_path(dir, path);
		if (!windows_path_has_no_reparse_component(dir, path))
			c->status = STATUS_FAILED_OUTPUT_MISMATCH;
#endif
		if (c->status != STATUS_RUNNING)
		{
			gcry_free(path);
			if (fullpath)
				gcry_free(fullpath);
			break;
		}
		c->current.display = fullpath;
		switch (tp)
		{
			case FILE_DIRECTORY:
#ifndef _WIN32
				if (!ensure_extract_directory(root, path))
					c->status = STATUS_FAILED_OUTPUT_MISMATCH;
#else
				dir_mk_recursive(fullpath, S_IRUSR | S_IWUSR | S_IXUSR);
#endif
				break;
			case FILE_SYMLINK:
			case FILE_LINK:
				if (io_read(c->source, &l, sizeof l) != sizeof l)
				{
					c->status = STATUS_FAILED_IO;
					break;
				}
				l = ntohll(l);
				char *link_data = l <= SIZE_MAX - 1 && l <= SSIZE_MAX ? m_gcry_malloc_secure((size_t)l + 1) : NULL;
				if (!link_data || io_read(c->source, link_data, (size_t)l) != (ssize_t)l)
				{
					if (link_data)
						gcry_free(link_data);
					c->status = STATUS_FAILED_IO;
					break;
				}
				link_data[l] = '\0';
				if (tp == FILE_SYMLINK)
				{
					if (!validate_symlink_target((uint8_t *)link_data, l, path))
					{
						gcry_free(link_data);
						c->status = STATUS_FAILED_OUTPUT_MISMATCH;
						break;
					}
#ifndef _WIN32
					if (!symlink_target_uses_no_existing_links(root, path, link_data))
						c->status = STATUS_FAILED_OUTPUT_MISMATCH;
					else
					{
						symlinks = m_realloc(symlinks, (symlink_count + 1) * sizeof *symlinks);
						symlinks[symlink_count++] = (deferred_symlink_s){ m_strdup(link_data), m_strdup(path) };
					}
#else
					lnerr = true;
#endif
				}
				else
				{
					char *link_path = validate_archive_path((uint8_t *)link_data, l);
					if (!link_path)
						c->status = STATUS_FAILED_OUTPUT_MISMATCH;
					else
					{
						bool found = false;
						for (size_t i = 0; i < regular_count; i++)
							if (!strcmp(regular_paths[i], link_path))
								found = true;
						if (!found)
							c->status = STATUS_FAILED_OUTPUT_MISMATCH;
					}
#ifndef _WIN32
					if (link_path && c->status == STATUS_RUNNING && !create_extract_hardlink(root, link_path, path))
						c->status = STATUS_FAILED_OUTPUT_MISMATCH;
#else
					if (link_path && c->status == STATUS_RUNNING)
					{
						char *hardlink = join_extract_path(dir, link_path);
						if (!windows_path_has_no_reparse_component(dir, link_path) ||
						    link(hardlink, fullpath) < 0)
							c->status = STATUS_FAILED_OUTPUT_MISMATCH;
						gcry_free(hardlink);
					}
#endif
					if (link_path && c->status == STATUS_RUNNING)
					{
						regular_paths = m_realloc(regular_paths, (regular_count + 1) * sizeof *regular_paths);
						regular_paths[regular_count++] = m_strdup(path);
					}
					if (link_path)
						gcry_free(link_path);
				}
				gcry_free(link_data);
				break;
			case FILE_REGULAR:
				c->current.offset = 0;
				if (io_read(c->source, &c->current.size, sizeof c->current.size) != sizeof c->current.size)
				{
					c->status = STATUS_FAILED_IO;
					break;
				}
				c->current.size = ntohll(c->current.size);
#ifndef _WIN32
				{
					int fd = open_extract_file(root, path);
					if (fd < 0)
					{
						c->status = STATUS_FAILED_OUTPUT_MISMATCH;
						break;
					}
					if (c->output)
						io_close(c->output);
					c->output = io_wrap_fd(fd);
				}
#else
				if (c->output)
					io_close(c->output);
				c->output = io_open(fullpath, O_CREAT | O_EXCL | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
				if (!c->output)
				{
					c->status = STATUS_FAILED_OUTPUT_MISMATCH;
					break;
				}
#endif
				regular_paths = m_realloc(regular_paths, (regular_count + 1) * sizeof *regular_paths);
				regular_paths[regular_count++] = m_strdup(path);
				decrypt_file(c);
				if (c->output)
					io_close(c->output);
				c->output = NULL;
				c->current.offset = c->total.size;
				break;
			default:
				c->status = STATUS_FAILED_OUTPUT_MISMATCH;
				break;
		}
		c->current.display = NULL;
		gcry_free(path);
		if (fullpath)
			gcry_free(fullpath);
	}
#ifndef _WIN32
	if (c->status == STATUS_RUNNING)
	{
		for (size_t i = 0; i < symlink_count; i++)
		{
			for (char *p = symlinks[i].target; *p; p++)
				if (*p == '\\')
					*p = '/';
			if (!create_extract_symlink(root, symlinks[i].target, symlinks[i].path))
			{
				c->status = STATUS_FAILED_OUTPUT_MISMATCH;
				break;
			}
		}
	}
	for (size_t i = 0; i < symlink_count; i++)
	{
		free(symlinks[i].target);
		free(symlinks[i].path);
	}
	free(symlinks);
	close(root);
#endif
	for (size_t i = 0; i < regular_count; i++)
		free(regular_paths[i]);
	free(regular_paths);
	if (lnerr && c->status == STATUS_RUNNING)
		c->status = STATUS_WARNING_LINK;
	return;
}

static void decrypt_stream(crypto_s *c)
{
	bool b = true;
	uint8_t *buffer = m_gcry_malloc_secure(c->blocksize + sizeof b);
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

static void decrypt_file(crypto_s *c)
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
