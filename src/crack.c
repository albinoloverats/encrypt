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

/*
 * ${CC} ${CLI_LIBS} -lgmp ${CLI_CFLAGS} ${DEBUG_CFLAGS} ${CLI_CPPFLAGS} ${COMMON_SRC} src/crypt_io.c src/crypt.c src/thpool.c src/crack.c -o crack
 */

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include <inttypes.h> /* used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself) */
#include <string.h>
#include <stdbool.h>

#include <sys/sysinfo.h>

#include <pthread.h>
#include <gmp.h>

#include "common/common.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/config.h"

#include "crypt.h"
#include "thpool.h"


#define LENGTH_MIN 4
#define LENGTH_MAX 12

// TODO Make user configurable
#define CHARACTERS " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


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
	{ "2020.01", 0x323032302e30312ellu },
	{ "current", 0x323032302e30312ellu }
};


static void crack(size_t o, char *p);
static void attack(void *ptr);


static threadpool thpool;

static uint8_t *salt;
static size_t salt_length;
static uint8_t *iv;
static size_t iv_length;
static uint8_t *data;//[280] = { 0x00 };
static size_t data_length;

static enum gcry_cipher_algos cipher;
static enum gcry_md_algos hash;
static enum gcry_cipher_modes mode;
static enum gcry_mac_algos mac;
static uint64_t kdf_iterations;

static bool skip = false;
static bool success = false;

int main(int argc, char **argv)
{
	char **extra = NULL;
	extra = calloc(2, sizeof (char *));
	extra[0] = strdup("+file");

	config_arg_t args[] =
	{
		{ 'm', "min", "#", "Minimum number of characters to check; default is 4",  CONFIG_ARG_REQ_NUMBER, { 0x0 }, false, false, false },
		{ 'x', "max", "#", "Maximum number of characters to check; default is 12", CONFIG_ARG_REQ_NUMBER, { 0x0 }, false, false, false },
		{ 0x0, NULL, NULL, NULL, CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false }
	};

	config_about_t about =
	{
		"encrypt-crack",
		ENCRYPT_VERSION,
		PROJECT_URL,
		NULL
	};
	config_init(about);

	int e = config_parse(argc, argv, args, &extra, NULL);
	if (!e)
	{
		char *x[] = { "+file", NULL };
		config_show_usage(args, x);
	}
	uint64_t min = args[0].response_value.number ? : LENGTH_MIN;
	uint64_t max = args[1].response_value.number ? : LENGTH_MAX;

	if (min > max)
		max = min;

	/*
	 * read file header
	 */

	int64_t source;

	if (!(source = open(extra[0], O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR)))
	{
		perror(NULL);
		return errno;
	}
	uint64_t head[3] = { 0x0 };
	if ((read(source, head, sizeof head)) < 0)
		return 0;
	if (head[0] != htonll(HEADER_0) || head[1] != htonll(HEADER_1))
		return 0;

	version_e version = VERSION_UNKNOWN;
	for (version_e v = VERSION_CURRENT; v > VERSION_UNKNOWN; v--)
		if (ntohll(head[2]) == VERSIONS[v].id)
		{
			version = v;
			break;
		}

	if (version >= VERSION_2015_10)
	{
		uint8_t e;
		read(source, &e, sizeof e);
		if (e != 0xF9)
		{
			fprintf(stderr, "Missing ECC marker.");
			return EXIT_FAILURE;
		}
	}

	uint8_t l;
	read(source, &l, sizeof l);
	char *z = calloc(l + sizeof( char ), sizeof( char ));
	read(source, z, l);
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
	cipher = cipher_id_from_name(z);
	hash = hash_id_from_name(h);
	mode = mode_id_from_name(m);
	if (version >= VERSION_2017_09)
		mac = mac_id_from_name(a);
	if (version >= VERSION_2020_01 && k)
		kdf_iterations = strtoull(k, NULL, 0x10);
	free(z);

	x_iv_e iv_type = IV_RANDOM;
	switch (version)
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
			skip = true;
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
			kdf_iterations = KEY_ITERATIONS_201709;
			break;

		case VERSION_2020_01:
			break;

		default:
			/* this will catch the all more recent versions (unknown is detected above) */
			break;
	}

	/*
	 * read salt, IV, and then upto 280 bytes of encrypted data
	 */

	salt_length = gcry_cipher_get_algo_keylen(cipher);
	if (kdf_iterations)
	{
		salt = calloc(salt_length, sizeof (byte_t));
		if (!salt)
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, salt_length);
		read(source, salt, salt_length);
	}
	iv_length = iv_type == IV_BROKEN ? gcry_cipher_get_algo_keylen(cipher) : gcry_cipher_get_algo_blklen(cipher);
	if (iv_type == IV_RANDOM)
	{
		iv = gcry_calloc_secure(iv_length, sizeof (byte_t));
		if (!iv)
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, iv_length);
		read(source, iv, iv_length);
	}

	/*
	 * dump whatever info was found
	 */

	printf("File     %s\n", extra[0]);
	printf("Version  %s\n", VERSIONS[version].string);
	printf("Cipher   %s\n", cipher_name_from_id(cipher));
	printf("Hash     %s\n", hash_name_from_id(hash));
	printf("Mode     %s\n", mode_name_from_id(mode));
	printf("MAC      %s\n", mac_name_from_id(mac));
	printf("KDF      %" PRIu64 "\n", kdf_iterations);
	mpz_t c;
	mpz_init_set_ui(c, strlen(CHARACTERS));
	mpz_t g;
	mpz_init(g);
	for (uint64_t i = min; i <= max; i++)
	{
		mpz_t r;
		mpz_init(r);
		mpz_pow_ui(r, c, i);
		mpz_add(g, g, r);
		mpz_clear(r);
	}
	gmp_printf("Guesses  %'Zd\n", g);
	mpz_clears(c, g, NULL);
	if (salt)
	{
		printf("Salt\n");
		cli_printx(salt, salt_length);
	}
	if (iv)
	{
		printf("IV\n");
		cli_printx(iv, iv_length);
	}

	data_length = (1 + (280 / iv_length)) * iv_length;
	data = malloc(data_length);
	read(source, data, data_length);
	close(source);

	thpool = thpool_init(get_nprocs() / 2);

	for (uint64_t i = min; !success && i <= max; i++)
	{
		char *password = calloc(i + 1, sizeof (char));
		memset(password, CHARACTERS[0], i);
		crack(0, password);
		//free(password);
	}

	thpool_wait(thpool);
	thpool_destroy(thpool);

	for (int i = 0; extra[i]; i++)
		free(extra[i]);
	free(extra);

	return EXIT_SUCCESS;
}

/*
 * Single threaded search only:
 *  - crack -m6 -x6 p.x               1807.15s user 172.35s system  98% cpu 33:26.30  total
 *
 * Single threaded crack:
 *  - crack -m6 -x6 p.x ??
 *  - crack -m3 -x3 p.x (ABC) (250047) 158.32s user   0.06s system  99% cpu  2:38.62  total
 *
 * Multi-threaded crack:
 *  - crack -m3 -x3 p.x (ABC) (250047) 177.29s user   1.87s system 771% cpu    23.209 total
 *
 */

static void crack(size_t o, char *p)
{
	if (success)
		return;
	if (o >= strlen(p))
	{
#if 1
		thpool_add_work(thpool, attack, strdup(p));
#else
		attack(strdup(p));
#endif
		return;
	}
	for (size_t i = 0; !success && i < strlen(CHARACTERS); i++)
	{
		p[o] = CHARACTERS[i];
		crack(o + 1, p);
	}
	return;
}

static void attack(void *ptr)
{
	if (success)
		return;

	char *password = (char *)ptr;

	fprintf(stderr, "\r%s", password);

	gcry_cipher_hd_t cipher_handle;
	gcry_mac_hd_t mac_handle;

	gcry_cipher_open(&cipher_handle, cipher, mode, GCRY_CIPHER_SECURE);
	gcry_mac_open(&mac_handle, mac, GCRY_MAC_FLAG_SECURE, NULL);

	size_t hl = gcry_md_get_algo_dlen(hash);
	uint8_t h[0xFF] = { 0x00 };
	gcry_md_hash_buffer(hash, h, password, strlen(password));

	size_t key_length = gcry_cipher_get_algo_keylen(cipher);
	uint8_t key[0xFF] = { 0x00 };

	if (kdf_iterations)
		gcry_kdf_derive(h, hl, GCRY_KDF_PBKDF2, hash, salt, salt_length, kdf_iterations, key_length, key);
	else
		memcpy(key, h, key_length < hl ? key_length : hl);
	gcry_cipher_setkey(cipher_handle, key, key_length);

	size_t block_length = gcry_cipher_get_algo_blklen(cipher);

	bool mi = false;
	if (mac != GCRY_MAC_NONE)
	{
		size_t ml = gcry_mac_get_algo_keylen(mac);
		uint8_t m[0xFF] = { 0x00 };
		gcry_kdf_derive(h, hl, GCRY_KDF_PBKDF2, hash, salt, salt_length, kdf_iterations, ml, m);
		gcry_mac_setkey(mac_handle, m, ml);
		mi = true;
	}

	if (mode == GCRY_CIPHER_MODE_CTR)
		gcry_cipher_setctr(cipher_handle, iv, block_length);
	else
		gcry_cipher_setiv(cipher_handle, iv, block_length);

	gcry_mac_reset(mac_handle);
	const char *mac_name = mac_name_from_id(mac);
	if (mi && (!strncmp("GMAC", mac_name, strlen("GMAC")) || !strncmp("POLY1305", mac_name, strlen("POLY1305"))))
		gcry_mac_setiv(mac_handle, iv, block_length);

	uint8_t dec[0xFFFF] = { 0x00 };
	gcry_cipher_decrypt(cipher_handle, dec, sizeof dec, data, data_length);


	off_t off = 0;
	if (!skip)
		off += dec[0] + 1;

	/*
	 * read three 64bit signed integers and assert that x ^ y = z
	 */

	uint64_t x = 0;
	uint64_t y = 0;
	uint64_t z = 0;

	memcpy(&x, dec + off, sizeof x);
	memcpy(&y, dec + off + sizeof x, sizeof y);
	memcpy(&z, dec + off + sizeof x + sizeof y, sizeof z);

	x = ntohll(x);
	y = ntohll(y);
	z = ntohll(z);
	if ((x ^ y) == z)
	{
		success = true;
		printf("\nSuccess!\n  %s\n", password);
	}

	gcry_cipher_close(cipher_handle);
	gcry_mac_close(mac_handle);

	free(password);

	return;
}
