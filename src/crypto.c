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
    "Success",
    "Initialisation",
    "Running",
    "Cancelled",
    "Failed: Invalid initialisation parameters!",
    "Failed: Unsupported Version!",
    "Failed: Unsupported Algorithm!",
    "Failed: Decryption Failure!",
    "Failed: Unknown Tag!",
    "Failed: Bad Checksum! (Possible data corruption.)",
    "Failed: Read/Write Error!",
    "Failed: Target file type mismatch!",
    "Failed: Unknown Problem!"
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
    {
        log_message(LOG_ERROR, _("Invalid cryptographic object!"));
        return;
    }
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
    log_message(LOG_VERBOSE, _("Deleting crypto instance %p, and freeing resources "), z);

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
        char *y = NULL;
        if (!strncasecmp(x, NAME_SHA1, strlen(NAME_SHA1) - 1))
            y = correct_sha1(x);
        else
            y = strdup(x);
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

extern uint64_t file_encrypted_aux(bool b, const char *n, char **c, char **h)
{
    struct stat s;
    stat(n, &s);
    if (S_ISDIR(s.st_mode))
        return 0;
    int64_t f = open(n, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
    if (f < 0)
    {
        log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
        return 0;
    }
    uint64_t head[3] = { 0x0 };
    if ((read(f, head, sizeof head)) < 0)
    {
        log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
        close(f);
        return 0;
    }
    if (head[0] != htonll(HEADER_0) && head[1] != htonll(HEADER_1))
    {
        close(f);
        return 0;
    }

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

    return file_encrypted_version(ntohll(head[2]));
}

extern uint64_t file_encrypted_version(uint64_t m)
{
    switch (m)
    {
        case HEADER_VERSION_201108: /* original release 2011.08 */
            log_message(LOG_INFO, _("File encrypted with version 2011.08"));
            return HEADER_VERSION_201108;

        case HEADER_VERSION_201110:
            log_message(LOG_INFO, _("File encrypted with version 2011.10"));
            return HEADER_VERSION_201110;

        case HEADER_VERSION_201211:
            log_message(LOG_INFO, _("File encrypted with version 2012.11"));
            return HEADER_VERSION_201211;

        case HEADER_VERSION_201302:
            log_message(LOG_INFO, _("File encrypted with version 2013.02"));
            return HEADER_VERSION_201302;

        case HEADER_VERSION_LATEST:
            log_message(LOG_INFO, _("File encrypted with development version of encrypt"));
            return HEADER_VERSION_LATEST;

        default:
            log_message(LOG_ERROR, _("File encrypted with unknown, or more recent release of encrypt"));
            return 0;
    }
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
    (void)n;
    return strdup(NAME_BLOWFISH128);
}

static char *correct_twofish256(const char * const restrict n)
{
    (void)n;
    return strdup(NAME_TWOFISH256);
}

static bool algorithm_is_duplicate(const char * const restrict n)
{
    return !strcmp(NAME_TIGER192, n);
}
