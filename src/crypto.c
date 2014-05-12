/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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
#include "common/error.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "crypto.h"
#include "io.h"

#define NAME_SHA1 "SHA1"
#define NAME_SHA160 "SHA160"
#define NAME_TIGER "TIGER"
#define NAME_TIGER192 "TIGER192"

#define NAME_AES "AES"
#define NAME_RIJNDAEL "RIJNDAEL"
#define NAME_BLOWFISH "BLOWFISH"
#define NAME_BLOWFISH128 "BLOWFISH128"
#define NAME_TWOFISH "TWOFISH"
#define NAME_TWOFISH256 "TWOFISH256"

static int algorithm_compare(const void *, const void *);

static const char *correct_sha1(const char * const restrict);
static const char *correct_aes_rijndael(const char * const restrict);
static const char *correct_blowfish128(const char * const restrict);
static const char *correct_twofish256(const char * const restrict);

static bool algorithm_is_duplicate(const char * const restrict);

static const char *STATUS_MESSAGE[] =
{
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
    { "2014.00", 0x8819d19069fae6b4llu },
    { "current", 0x8819d19069fae6b4llu } /* same as above */
};

typedef struct
{
    enum gcry_cipher_modes id;
    const char name[4];
}
block_mode_t;

static const block_mode_t MODES[] =
{
    { GCRY_CIPHER_MODE_ECB, "ECB" },
    { GCRY_CIPHER_MODE_CBC, "CBC" },
    { GCRY_CIPHER_MODE_CFB, "CFB" },
    { GCRY_CIPHER_MODE_OFB, "OFB" },
    { GCRY_CIPHER_MODE_CTR, "CTR" },
};

extern void init_crypto(void)
{
    static bool done = false;
    if (done)
        return;
    /*
     * initialise GNU Crypt library
     */
    if (!gcry_check_version(GCRYPT_VERSION))
        die(_("Could not find GNU Crypt library"));
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    errno = 0; /* need to reset errno after gcry_check_version() */
    done = true;
}

extern void execute(crypto_t *c)
{
    if (!c || c->status != STATUS_INIT)
        return;
    pthread_t *t = calloc(1, sizeof( pthread_t ));
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
    return c ? STATUS_MESSAGE[c->status] : NULL;
}

extern void deinit(crypto_t **c)
{
    if (!c)
        return;
    crypto_t *z = *c;

    z->status = STATUS_CANCELLED;
    if (z->thread)
    {
        pthread_join(*z->thread, NULL);
        free(z->thread);
    }
    if (z->path)
        free(z->path);
    if (z->source)
        io_close(z->source);
    if (z->output)
        io_close(z->output);
    free(z);
    z = NULL;
    *c = NULL;
    return;
}

extern const char **list_of_ciphers(void)
{
    init_crypto();

    enum gcry_cipher_algos lid[0xff] = { GCRY_CIPHER_NONE };
    int len = 0;
    enum gcry_cipher_algos id = GCRY_CIPHER_NONE;
    for (unsigned i = 0; i < sizeof lid; i++)
    {
        if (gcry_cipher_algo_info(id, GCRYCTL_TEST_ALGO, NULL, NULL) == 0)
        {
            lid[len] = id;
            len++;
        }
        id++;
    }
    static const char **l = NULL;
    if (!l)
    {
        if (!(l = calloc(len + 1, sizeof( char * ))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( char * ));
        int j = 0;
        for (int i = 0; i < len; i++)
        {
            const char *n = cipher_name_from_id(lid[i]);
            if (!n)
                continue;
            l[j] = strdup(n);
            j++;
        }
        //l[j] = NULL;
        qsort(l, j, sizeof( char * ), algorithm_compare);
    }
    return (const char **)l;
}

extern const char **list_of_hashes(void)
{
    init_crypto();

    enum gcry_md_algos lid[0xff] = { GCRY_MD_NONE };
    int len = 0;
    enum gcry_md_algos id = GCRY_MD_NONE;
    for (unsigned i = 0; i < sizeof lid; i++)
    {
        if (gcry_md_test_algo(id) == 0)
        {
            lid[len] = id;
            len++;
        }
        id++;
    }
    static const char **l = NULL;
    if (!l)
    {
        if (!(l = calloc(len + 1, sizeof( char * ))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( char * ));
        int j = 0;
        for (int i = 0; i < len; i++)
        {
            const char *n = hash_name_from_id(lid[i]);
            if (!n)
                continue;
            l[j] = strdup(n);
            j++;
        }
        //l[j] = NULL;
        qsort(l, j, sizeof( char * ), algorithm_compare);
    }
    return (const char **)l;
}

extern const char **list_of_modes(void)
{
    static const char **l = NULL;
    if (!l)
    {
        unsigned m = sizeof MODES / sizeof( block_mode_t );
        if (!(l = calloc(m + 1, sizeof( char * ))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( char * ));
        for (unsigned i = 0; i < m; i++)
            l[i] = MODES[i].name;
    }
    return (const char **)l;
}

extern enum gcry_cipher_algos cipher_id_from_name(const char * const restrict n)
{
    if (n)
    {
        int list[0xff] = { 0x00 };
        int len = 0;
        enum gcry_cipher_algos id = GCRY_CIPHER_NONE;
        for (unsigned i = 0; i < sizeof list; i++)
        {
            if (gcry_cipher_algo_info(id, GCRYCTL_TEST_ALGO, NULL, NULL) == 0)
            {
                list[len] = id;
                len++;
            }
            id++;
        }
        for (int i = 0; i < len; i++)
        {
            const char *x = cipher_name_from_id(list[i]);
            if (!x)
                continue;
            if (!strcasecmp(x, n))
                return list[i];
        }
    }
    return GCRY_CIPHER_NONE;
}

extern enum gcry_md_algos hash_id_from_name(const char * const restrict n)
{
    if (n)
    {
        int list[0xff] = { 0x00 };
        int len = 0;
        enum gcry_md_algos id = GCRY_MD_NONE;
        for (unsigned i = 0; i < sizeof list; i++)
        {
            if (gcry_md_test_algo(id) == 0)
            {
                list[len] = id;
                len++;
            }
            id++;
        }
        for (int i = 0; i < len; i++)
        {
            const char *x = hash_name_from_id(list[i]);
            if (!x)
                continue;
            if (!strcasecmp(x, n))
                return list[i];
        }
    }
    return GCRY_MD_NONE;
}

extern enum gcry_cipher_modes mode_id_from_name(const char * const restrict n)
{
    if (n)
        for (unsigned i = 0; i < sizeof MODES / sizeof( block_mode_t ); i++)
            if (!strcasecmp(n, MODES[i].name))
                return MODES[i].id;
    return GCRY_CIPHER_MODE_NONE;
}

extern const char *cipher_name_from_id(enum gcry_cipher_algos c)
{
    const char *n = gcry_cipher_algo_name(c);
    if (!strncasecmp(NAME_AES, n, strlen(NAME_AES)))
        return correct_aes_rijndael(n);
    else if (!strcasecmp(NAME_BLOWFISH, n))
        return correct_blowfish128(n);
    else if (!strcasecmp(NAME_TWOFISH, n))
        return correct_twofish256(n);
    return n;
}

extern const char *hash_name_from_id(enum gcry_md_algos h)
{
    const char *n = gcry_md_algo_name(h);
    if (algorithm_is_duplicate(n))
        return NULL;
    else if (!strncasecmp(NAME_SHA1, n, strlen(NAME_SHA1) - 1))
        return correct_sha1(n);
    return n;
}

extern const char *mode_name_from_id(enum gcry_cipher_modes m)
{
    for (unsigned i = 0; i < sizeof MODES / sizeof( block_mode_t ); i++)
        if (MODES[i].id == m)
            return MODES[i].name;
    return NULL;
}

extern version_e is_encrypted_aux(bool b, const char *n, char **c, char **h, char **m)
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

    if (b)
    {
        uint8_t l;
        read(f, &l, sizeof l);
        char *a = calloc(l + sizeof( char ), sizeof( char ));
        read(f, a, l);
        char *s = strchr(a, '/');
        *s = '\0';
        s++;
        char *d = strrchr(s, '/');
        if (d)
        {
            *d = '\0';
            d++;
        }
        else
            d = "CBC";
        asprintf(c, "%s", a);
        asprintf(h, "%s", s);
        asprintf(m ,"%s", d);
        free(a);
    }
    close(f);

    return check_version(ntohll(head[2]));
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

static int algorithm_compare(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}

static const char *correct_sha1(const char * const restrict n)
{
    return strcasecmp(n, NAME_SHA1) ? n : NAME_SHA160;
}

static const char *correct_aes_rijndael(const char * const restrict n)
{
    if (!strcasecmp(NAME_AES, n))
        return n; /* use AES (bits/blocks/etc) */
    /*
     * use rijndael instead of AES as that's the actual cipher name
     */
    static char *x = NULL;
    if (!x)
        if (!(asprintf(&x, "%s%s", NAME_RIJNDAEL, n + strlen(NAME_AES))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(NAME_RIJNDAEL) + strlen(n) - strlen(NAME_AES));
    return x;
}

static const char *correct_blowfish128(const char * const restrict n)
{
    return (void)n , NAME_BLOWFISH128;
}

static const char *correct_twofish256(const char * const restrict n)
{
    return (void)n , NAME_TWOFISH256;
}

static bool algorithm_is_duplicate(const char * const restrict n)
{
    return !strcmp(NAME_TIGER192, n);
}
