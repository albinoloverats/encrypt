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
#include <locale.h>
#include <pthread.h>
#include <gmp.h>
#include <stdatomic.h>

#include "common/common.h"
#include "common/error.h"
#include "common/mem.h"
#include "common/ccrypt.h"
#include "common/config.h"

#include "thpool.h"

#include "crypt.h"

#define LENGTH_MIN 4
#define LENGTH_MAX 12
#define PREFIX_LEN 2

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
	{ "2022.01", 0x323032312e30312ellu },
	{ "2024.01", 0x2e4155524f52412ellu },
	{ "2025.05", 0x323032352e30352ellu },
	{ "current", 0x323032352e30352ellu }
};


static void crack(void *);
static bool next_combination(char *, size_t);
static void try_password(char *);

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
static volatile bool success = false;
static atomic_ulong attempts = 0;

typedef struct
{
	char *prefix;
	uint64_t min;
	uint64_t max;
}
crack_s;

int main(int argc, char **argv)
{
	setlocale(LC_NUMERIC, "");

	long threads = get_nprocs() / 2;

	list_t args = list_init(config_named_compare, false, false);
	list_add(args, &((config_named_s){ 'm', "min",     "#", "Minimum number of characters to check", { CONFIG_ARG_REQ_INTEGER, { .integer = LENGTH_MIN } }, false, false, false, false }));
	list_add(args, &((config_named_s){ 'x', "max",     "#", "Maximum number of characters to check", { CONFIG_ARG_REQ_INTEGER, { .integer = LENGTH_MAX } }, false, false, false, false }));
	list_add(args, &((config_named_s){ 't', "threads", "#", "Maximum number of threads to us",       { CONFIG_ARG_REQ_INTEGER, { .integer = threads    } }, false, false, false, false }));
	list_add(args, &((config_named_s){ 'p', "prefix",  "#", "Prefix length",                         { CONFIG_ARG_REQ_INTEGER, { .integer = PREFIX_LEN } }, false, false, false, false }));

	config_about_s about =
	{
		"encrypt-crack",
		ENCRYPT_VERSION,
		PROJECT_URL,
		NULL
	};
	config_init(about);

	list_t extra = list_default();
	list_add(extra, &((config_unnamed_s){ "file", { CONFIG_ARG_STRING,  { .string = NULL } }, true, false }));

	config_parse(argc, argv, args, extra, NULL);

	uint64_t min   = ((config_named_s *)list_get(args, 0))->response.value.integer ? : LENGTH_MIN;
	uint64_t max   = ((config_named_s *)list_get(args, 1))->response.value.integer ? : LENGTH_MAX;
	threads        = ((config_named_s *)list_get(args, 2))->response.value.integer ? : threads;
	uint64_t prefix_len = ((config_named_s *)list_get(args, 3))->response.value.integer ? : PREFIX_LEN;

	char *file = ((config_unnamed_s *)list_get(extra, 0))->response.value.string;

	if (min > max)
		max = min;
	if (prefix_len > min)
		prefix_len = min;

	/*
	 * read file header
	 */

	int64_t source;

	if (!(source = open(file, O_RDONLY | F_RDLCK | O_BINARY, S_IRUSR | S_IWUSR)))
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
	char *z = m_calloc(l + sizeof( char ), sizeof( char ));
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
		case VERSION_2022_01:
		case VERSION_2024_01:
		case VERSION_2025_05:
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
		salt = m_calloc(salt_length, sizeof (byte_t));
		read(source, salt, salt_length);
	}
	iv_length = iv_type == IV_BROKEN ? gcry_cipher_get_algo_keylen(cipher) : gcry_cipher_get_algo_blklen(cipher);
	if (iv_type == IV_RANDOM)
	{
		iv = m_gcry_calloc_secure(iv_length, sizeof (byte_t));
		read(source, iv, iv_length);
	}

	/*
	 * dump whatever info was found
	 */

	printf("File     %s\n", file);
	printf("Version  %s\n", VERSIONS[version].string);
	printf("Cipher   %s\n", cipher_name_from_id(cipher));
	printf("Hash     %s\n", hash_name_from_id(hash));
	printf("Mode     %s\n", mode_name_from_id(mode));
	printf("MAC      %s\n", mac_name_from_id(mac));
	printf("KDF      %'" PRIu64 "\n", kdf_iterations);
	mpz_t cc;
	mpz_init_set_ui(cc, strlen(CHARACTERS));
	mpz_t total_guesses;
	mpz_init(total_guesses);
	for (uint64_t i = min; i <= max; i++)
	{
		mpz_t r;
		mpz_init(r);
		mpz_pow_ui(r, cc, i);
		mpz_add(total_guesses, total_guesses, r);
		mpz_clear(r);
	}
	gmp_printf("Guesses  %'Zd\n", total_guesses);
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
	data = m_malloc(data_length);
	read(source, data, data_length);
	close(source);

	thpool = thpool_init(threads);

	char *prefix = m_calloc(prefix_len + 1, sizeof(char));
	memset(prefix, CHARACTERS[0], prefix_len);

	time_t start_time = time(NULL);
	uint64_t r = 0;
	do
	{
		crack_s *c = m_malloc(sizeof (crack_s));
		c->prefix = strdup(prefix);
		c->min = min;
		c->max = max;
		thpool_add_work(thpool, crack, c);
		r++;
	}
	while (next_combination(prefix, prefix_len));

	printf("Runners  %'" PRIu64 " / %'ld\n", r, threads);

	free(prefix);

	// now just wait
	while (!success)
	{
		mpz_t current;
		mpz_init_set_ui(current, atomic_load(&attempts));

		mpf_t percent, total;
		mpf_init(percent);
		mpf_init(total);
		mpf_set_z(percent, current);
		mpf_set_z(total, total_guesses);
		mpf_mul_ui(percent, percent, 100);
		mpf_div(percent, percent, total);

		time_t now = time(NULL);
		double elapsed = difftime(now, start_time);
		double rate = elapsed > 0 ? mpz_get_d(current) / elapsed : 0.0;
		double remaining = rate > 0 ? (mpz_get_d(total_guesses) - mpz_get_d(current)) / rate : 0;

		uint64_t rem_d = (uint64_t) (remaining / 86400);
		uint64_t rem_h = (uint64_t)((remaining - rem_d * 86400) / 3600);
		uint64_t rem_m = (uint64_t)((remaining - rem_d * 86400 - rem_h * 3600) / 60);
		uint64_t rem_s = (uint64_t) (remaining - rem_d * 86400 - rem_h * 3600 - rem_m * 60);

		gmp_printf("\rTried    %Zd / %Zd (%.2Ff%%) | %.1f/s | ETA: %'d %02d:%02d:%02d",
				current,
				total_guesses,
				percent,
				rate, rem_d, rem_h, rem_m, rem_s);

		if (!mpz_cmp(current, total_guesses))
			break;

		usleep(10000);
	}
	printf("\n");

	thpool_wait(thpool);
	thpool_destroy(thpool);

	list_deinit(args);
	list_deinit(extra);

	return EXIT_SUCCESS;
}

static bool next_combination(char *s, size_t len)
{
	size_t i = len;
	while (i-- > 0 && !success)
	{
		char *p = strchr(CHARACTERS, s[i]);
		if (p && p[1])
		{
			s[i] = p[1];
			for (size_t j = i + 1; j < len && !success; j++)
				s[j] = CHARACTERS[0];
			return true;
		}
	}
	return false;
}

static void crack(void *ptr)
{
	if (success)
		return;

	crack_s *c = (crack_s *)ptr;
	size_t prefix_len = strlen(c->prefix);

	for (size_t len = c->min; len <= c->max && !success; len++)
	{
		if (len < prefix_len)
			continue;

		size_t suffix_len = len - prefix_len;
		if (suffix_len == 0)
		{
			// Only the prefix is needed
			try_password(c->prefix);
			if (success)
				break;
			continue;
		}

		// Allocate buffer for full candidate password
		char *candidate = m_malloc(len + 1);
		memcpy(candidate, c->prefix, prefix_len);

		// Suffix buffer
		char *suffix = m_malloc(suffix_len + 1);
		memset(suffix, CHARACTERS[0], suffix_len);
		suffix[suffix_len] = '\0';

		do
		{
			if (success)
				break;

			memcpy(candidate + prefix_len, suffix, suffix_len);
			candidate[len] = '\0';

			try_password(candidate);
		}
		while (next_combination(suffix, suffix_len));

		free(suffix);
		free(candidate);
	}

	free(c->prefix);
	free(c);
}

static void try_password(char *password)
{
	atomic_fetch_add(&attempts, 1);

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

	return;
}
