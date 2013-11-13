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

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/stat.h>

#include <gcrypt.h>

#include "common/common.h"
#include "common/logging.h"
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

static char *correct_sha1(const char * const restrict);
static char *correct_aes_rijndael(const char * const restrict);
static char *correct_blowfish128(const char * const restrict);
static char *correct_twofish256(const char * const restrict);

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
    "Failed: Unsupported algorithm!",
    "Failed: Decryption failure!",
    "Failed: Unsupported feature!",
    "Failed: Read/Write error!",
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
    { "2013.09", 0xf1f68e5f2a43aa5fllu },
    { "current", 0xf1f68e5f2a43aa5fllu } /* same as above */
};

extern void init_crypto(void)
{
    static bool done = false;
    if (done)
        return;
    /*
     * initialise GNU Crypt library
     */
    log_message(LOG_VERBOSE, _("Initialising GNU Crypt library"));
    if (!gcry_check_version(GCRYPT_VERSION))
        die(_("Could not find GNU Crypt library"));
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    errno = 0; /* need to reset errno after gcry_check_version() */
    done = true;
}

extern void execute(crypto_t *c)
{
    if (!c || c->status != STATUS_INIT)
        return (log_message(LOG_ERROR, _("Invalid cryptographic object!")) , (void)NULL);
    log_message(LOG_VERBOSE, _("Executing crypto instance %p in background"), c);
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
    if (!c)
        return NULL;
    log_message(LOG_INFO, _("Status [%d] : %s"), c->status, STATUS_MESSAGE[c->status]);
    return STATUS_MESSAGE[c->status];
}

extern void deinit(crypto_t **c)
{
    if (!c)
        return;
    crypto_t *z = *c;
    log_message(LOG_VERBOSE, _("Deleting crypto instance %p, and freeing resources"), z);

    z->status = STATUS_CANCELLED;
    pthread_join(*z->thread, NULL);

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

    int lid[0xff] = { 0x00 };
    int len = sizeof lid;
    gcry_cipher_list(lid, &len);
    static char **l = NULL;
    if (!l)
    {
        if (!(l = malloc(sizeof( char * ))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( char * ));
        int j = 0;
        for (int i = 0; i < len; i++)
        {
            const char *n = gcry_cipher_algo_name(lid[i]);
            if (!n)
                continue;
            else if (!strncasecmp(n, NAME_AES, strlen(NAME_AES)))
                l[j] = correct_aes_rijndael(n);
            else if (!strcasecmp(n, NAME_BLOWFISH))
                l[j] = correct_blowfish128(n);
            else if (!strcasecmp(n, NAME_TWOFISH))
                l[j] = correct_twofish256(n);
            else
                l[j] = strdup(n);
            j++;
            char **x = realloc(l, (j + 1) * sizeof( char * ));
            if (!x)
                die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, (j + 1) * sizeof( char * ));
            l = x;
        }
        l[j] = NULL;
        qsort(l, j, sizeof( char * ), algorithm_compare);
    }
    return (const char **)l;
}

extern const char **list_of_hashes(void)
{
    init_crypto();

    int lid[0xff] = { 0x00 };
    int len = sizeof lid;
    gcry_md_list(lid, &len);
    static char **l = NULL;
    if (!l)
    {
        if (!(l = malloc(sizeof( char * ))))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( char * ));
        int j = 0;
        for (int i = 0; i < len; i++)
        {
            const char *n = gcry_md_algo_name(lid[i]);
            if (!n || algorithm_is_duplicate(n))
                continue;
            else if (!strncasecmp(n, NAME_SHA1, strlen(NAME_SHA1) - 1))
                l[j] = correct_sha1(n);
            else
                l[j] = strdup(n);
            j++;
            char **x = realloc(l, (j + 1) * sizeof( char * ));
            if (!x)
                die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, (j + 1) * sizeof( char * ));
            l = x;
        }
        l[j] = NULL;
        qsort(l, j, sizeof( char * ), algorithm_compare);
    }
    return (const char **)l;
}

extern int cipher_id_from_name(const char * const restrict n)
{
    if (n)
    {
        int list[0xff] = { 0x00 };
        int len = sizeof list;
        gcry_cipher_list(list, &len);
        for (int i = 0; i < len; i++)
        {
            const char *x = gcry_cipher_algo_name(list[i]);
            char *y = NULL;
            if (!x)
                continue;
            else if (!strncasecmp(x, NAME_AES, strlen(NAME_AES)))
                y = correct_aes_rijndael(x);
            else if (!strcasecmp(x, NAME_BLOWFISH))
                y = correct_blowfish128(x);
            else if (!strcasecmp(x, NAME_TWOFISH))
                y = correct_twofish256(x);
            else
                y = strdup(x);
            if (!strcasecmp(y, n))
            {
                log_message(LOG_DEBUG, _("Found requested encryption algorithm: %s"), gcry_cipher_algo_name(list[i]));
                free(y);
                return list[i];
            }
            free(y);
        }
    }
    log_message(LOG_ERROR, _("Could not find requested encryption algorithm: %s"), n);
    return 0;
}

extern int hash_id_from_name(const char * const restrict n)
{
    if (!n)
        return 0;
    int list[0xff] = { 0x00 };
    int len = sizeof list;
    gcry_md_list(list, &len);
    for (int i = 0; i < len; i++)
    {
        const char *x = gcry_md_algo_name(list[i]);
        if (!x || algorithm_is_duplicate(x))
            continue;
        char *y = !strncasecmp(x, NAME_SHA1, strlen(NAME_SHA1) - 1) ? correct_sha1(x) : strdup(x);
        if (!strcasecmp(y, n))
        {
            free(y);
            log_message(LOG_DEBUG, _("Found requested hash: %s"), gcry_md_algo_name(list[i]));
            return list[i];
        }
        free(y);
    }
    log_message(LOG_ERROR, _("Could not find requested hash: %s"), n);
    return 0;
}

extern version_e is_encrypted_aux(bool b, const char *n, char **c, char **h)
{
    struct stat s;
    stat(n, &s);
    if (S_ISDIR(s.st_mode))
        return VERSION_UNKNOWN;
    int64_t f = open(n, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
    if (f < 0)
        return (log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno)) , VERSION_UNKNOWN);
    uint64_t head[3] = { 0x0 };
    if ((read(f, head, sizeof head)) < 0)
    {
        log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
        close(f);
        return VERSION_UNKNOWN;
    }
    if (head[0] != htonll(HEADER_0) && head[1] != htonll(HEADER_1))
        return (close(f) , VERSION_UNKNOWN);

    if (b)
    {
        uint8_t l;
        read(f, &l, sizeof l);
        char *a = calloc(l + sizeof( char ), sizeof( char ));
        read(f, a, l);
        char *s = strchr(a, '/');
        *s = '\0';
        s++;
        asprintf(c, "%s", a);
        asprintf(h, "%s", s);
        free(a);
    }
    close(f);

    return check_version(ntohll(head[2]));
}

extern version_e check_version(uint64_t m)
{
    for (version_e v = VERSION_CURRENT; v > VERSION_UNKNOWN; v--)
        if (m == VERSIONS[v].id)
            return (log_message(LOG_INFO, _("File encrypted with version %s"), VERSIONS[v].string) , v);
    log_message(LOG_ERROR, _("File encrypted with unknown, or more recent release of encrypt"));
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
    log_message(LOG_ERROR, _("Unknown version, defaulting to current : %s"), VERSIONS[VERSION_CURRENT].string);
    return VERSION_CURRENT;
}

static int algorithm_compare(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}

static char *correct_sha1(const char * const restrict n)
{
    return strcasecmp(n, NAME_SHA1) ? strdup(n) : strdup(NAME_SHA160);
}

static char *correct_aes_rijndael(const char * const restrict n)
{
    if (!strcasecmp(NAME_AES, n))
        return strdup(n); /* use AES (bits/blocks/etc) */
    /*
     * use rijndael instead of AES as that's the actual cipher name
     */
    char *x = NULL;
    if (!(asprintf(&x, "%s%s", NAME_RIJNDAEL, n + strlen(NAME_AES))))
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(NAME_RIJNDAEL) + strlen(n) - strlen(NAME_AES));
    return x;
}

static char *correct_blowfish128(const char * const restrict n)
{
    return ((void)n , strdup(NAME_BLOWFISH128));
}

static char *correct_twofish256(const char * const restrict n)
{
    return ((void)n , strdup(NAME_TWOFISH256));
}

static bool algorithm_is_duplicate(const char * const restrict n)
{
    return !strcmp(NAME_TIGER192, n);
}
