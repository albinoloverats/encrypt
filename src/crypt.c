/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2017, albinoloverats ~ Software Development
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

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/stat.h>

#include <gcrypt.h>

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"

#include "crypt.h"
#include "crypt_io.h"

static const char *STATUS_MESSAGE[] =
{
	/* TODO Add translation support for these */
	/* success and running states */
	"Success",
	"Initialisation",
	"Running",
	"Cancelled",
	/* failures - decryption did not complete */
	"Failed: Invalid initialisation parameters!",
	"Failed: Unsupported version!",
	"Failed: Unsupported cipher algorithm!",
	"Failed: Unsupported hash algorithm!",
	"Failed: Unsupported cipher mode!",
	"Failed: Unsupported MAC algorithm!",
	"Failed: Decryption failure! (Invalid password)",
	"Failed: Unsupported feature!",
	"Failed: Read/Write error!",
	"Failed: Key generation error!",
	"Failed: Invalid target file type!",
	"Failed: An unknown error has occurred!",
	/* warnings - decryption finished but with possible errors */
	"Warning: Bad checksum! (Possible data corruption)",
	"Warning: Could not extract all files! (Links are unsupported)"
};

typedef struct
{
	const char string[8];
	uint64_t id;
}
version_t;

static const version_t VERSIONS[] =
{
	{ "Unknown", 0 },
	{ "2011.08", 0x72761df3e497c983llu },
	{ "2011.10", 0xbb116f7d00201110llu },
	{ "2012.11", 0x51d28245e1216c45llu },
	{ "2013.02", 0x5b7132ab5abb3c47llu },
	{ "2013.11", 0xf1f68e5f2a43aa5fllu },
	{ "2014.06", 0x8819d19069fae6b4llu },
	{ "2015.01", 0x63e7d49566e31bfbllu },
	{ "2015.10", 0x0dae4a923e4ae71dllu },
	{ "2017.09", 0x323031372e303921llu },
	{ "current", 0x323031372e303921llu }
};

extern void execute(crypto_t *c)
{
	pthread_t *t = gcry_calloc_secure(1, sizeof( pthread_t ));
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setdetachstate(&a, PTHREAD_CREATE_JOINABLE);
	pthread_create(t, &a, c->process, c);
	c->thread = t;
	pthread_attr_destroy(&a);
	return;
}

extern const char *status(const crypto_t * const restrict c)
{
	return STATUS_MESSAGE[c->status];
}

extern void deinit(crypto_t **c)
{
	crypto_t *z = *c;

	z->status = STATUS_CANCELLED;
	if (z->thread)
	{
		pthread_join(*z->thread, NULL);
		gcry_free(z->thread);
	}
	if (z->path)
		gcry_free(z->path);
	if (z->name)
		gcry_free(z->name);
	if (z->source)
		io_close(z->source);
	if (z->output)
		io_close(z->output);
	gcry_free(z);
	z = NULL;
	*c = NULL;
	return;
}

#if 0
extern void key_gcry_free(raw_key_t **key)
{
	memset((*key)->data, 0x00, (*key)->length);
	gcry_free((*key)->data);
	(*key)->length = 0;
	gcry_free(*key);
	key = NULL;
	return;
}
#endif

extern version_e is_encrypted_aux(bool b, const char *n, char **c, char **h, char **m, char **a)
{
	struct stat s;
	stat(n, &s);
	if (S_ISDIR(s.st_mode))
		return VERSION_UNKNOWN;
	int64_t f = open(n, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR);
	if (f < 0)
		return VERSION_UNKNOWN;
	uint64_t head[3] = { 0x0 };
	if ((read(f, head, sizeof head)) < 0)
		return close(f) , VERSION_UNKNOWN;
	if (head[0] != htonll(HEADER_0) && head[1] != htonll(HEADER_1))
		return close(f) , VERSION_UNKNOWN;

	version_e version = check_version(ntohll(head[2]));
	if (b)
	{
		if (version >= VERSION_2015_10)
		{
			/* skips past ECC length byte */
			uint8_t b;
			read(f, &b, sizeof b);
		}
		uint8_t l;
		read(f, &l, sizeof l);
		char *z = gcry_calloc_secure(l + sizeof( char ), sizeof( char ));
		read(f, z, l);
		char *s = strchr(z, '/');
		*s = '\0';
		s++;
		char *d = strchr(s, '/');
		char *g = NULL;
		if (d)
		{
			*d = '\0';
			d++;
			if ((g = strchr(d, '/')))
			{
				*g = '\0';
				g++;
			}
			else
				g = DEFAULT_MAC;
		}
		else
		{
			d = "CBC";
			g = DEFAULT_MAC;
		}
		if (*c)
			*c = strdup(z);
		if (*h)
			*h = strdup(s);
		if (*m)
			*m = strdup(d);
		if (*a)
			*a = strdup(g);
		gcry_free(z);
	}
	close(f);

	return version;
}

extern version_e check_version(uint64_t m)
{
	for (version_e v = VERSION_CURRENT; v > VERSION_UNKNOWN; v--)
		if (m == VERSIONS[v].id)
			return v;
	return VERSION_UNKNOWN;
}

extern uint64_t get_version(version_e v)
{
	return VERSIONS[v].id;
}

extern const char *get_version_string(version_e v)
{
	return VERSIONS[v].string;
}

extern version_e parse_version(const char *v)
{
	if (!v)
		return VERSION_CURRENT;
	for (version_e i = VERSION_CURRENT; i > VERSION_UNKNOWN; i--)
		if (!strcmp(v, VERSIONS[i].string))
			return i;
	return VERSION_CURRENT;
}
