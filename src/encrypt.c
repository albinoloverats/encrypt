/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#include <ctype.h>
#include <inttypes.h> // used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself)
#include <stdbool.h>
#include <string.h>

#include <time.h>
#include <netinet/in.h>

#include <gcrypt.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#include "common/tlv.h"

#include "crypto.h"
#include "encrypt.h"
#include "io.h"

static void *process(void *);

static inline void write_header(crypto_t *);
static inline void write_verification_sum(crypto_t *);
static inline void write_metadata(crypto_t *);
static inline void write_random_data(crypto_t *);

static int64_t count_entries(const char *);

static void encrypt_directory(crypto_t *, const char *);
static void encrypt_stream(crypto_t *);
static void encrypt_file(crypto_t *);

extern crypto_t *encrypt_init(const char * const restrict i, const char * const restrict o, const char * const restrict c, const char * const restrict h, const void * const restrict k, size_t l, bool x)
{
    init_crypto();

    crypto_t *z = malloc(sizeof( crypto_t ));
    if (!z)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( crypto_t ));

    z->status = INIT;

    z->path = NULL;
    z->directory = false;
    if (i)
    {
        struct stat s;
        stat(i, &s);
        if (S_ISDIR(s.st_mode))
        {
            log_message(LOG_VERBOSE, _("Encrypting directory tree : %s"), i);
            z->source = NULL;
            z->path = strdup(i);
            z->directory = true;
        }
        else
        {
            log_message(LOG_VERBOSE, _("Encrypting file : %s"), i);
            if (!(z->source = io_open(i, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR)))
            {
                log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
                z->status = FAILED_IO;
                goto end;
            }
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Encrypting stream from stdin"));
        z->source = io_use_stdin();
    }

    if (o)
    {
        log_message(LOG_VERBOSE, _("Encrypting to file : %s"), o);
        if (!(z->output = io_open(o, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK, S_IRUSR | S_IWUSR)))
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            z->status = FAILED_IO;
            goto end;
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Encrypting to stdout"));
        z->output = io_use_stdout();
    }

    z->process = process;

    z->cipher = strdup(c);
    z->hash = strdup(h);

    if (l)
    {
        if (!(z->key = malloc(l)))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, l);
        memcpy(z->key, k, l);
        z->length = l;
    }
    else
    {
        int64_t kf = open(k, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (kf < 0)
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            z->status = FAILED_IO;
            goto end;
        }
        z->length = lseek(kf, 0, SEEK_END);
        lseek(kf, 0, SEEK_SET);
        if (!(z->key = malloc(z->length)))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, z->length);
        read(kf, z->key, z->length);
        close(kf);
    }

    z->blocksize = BLOCK_SIZE;
    z->compressed = x;

end:
    return z;
}

static void *process(void *ptr)
{
    crypto_t *c = (crypto_t *)ptr;

    if (!c || c->status != INIT)
    {
        log_message(LOG_ERROR, _("Invalid cryptographic object!"));
        return NULL;
    }

    c->status = RUNNING;
    time(&c->total.started);
    write_header(c);
    /*
     * all data written from here on is encrypted
     */
    io_encryption_init(c->output, c->cipher, c->hash, c->key, c->length);
    free(c->cipher);
    free(c->hash);
    free(c->key);

    write_random_data(c);
    write_verification_sum(c);
    write_random_data(c);
    write_metadata(c);
    write_random_data(c);

    /*
     * main encryption loop; if we're compressing the output then everything
     * from here will be compressed (if necessary)
     */
    if (c->compressed)
        io_compression_init(c->output);
    log_message(LOG_INFO, _("Starting encryption process"));

    io_encryption_checksum_init(c->output);

    if (c->directory)
    {
        log_message(LOG_INFO, _("Directory tree contains %" PRIi64 " entries"), c->total.size);
        file_type_e tp = FILE_DIRECTORY;
        io_write(c->output, &tp, sizeof( byte_t ));
        uint64_t l = htonll(strlen(c->path));
        io_write(c->output, &l, sizeof l);
        io_write(c->output, c->path, strlen(c->path));
        c->total.offset = 1;
        encrypt_directory(c, c->path);
    }
    else
    {
        c->current.size = c->total.size;
        c->total.size = 1;
        if (c->blocksize)
            encrypt_stream(c);
        else
            encrypt_file(c);
    }

    if (c->status != RUNNING)
        goto end;

    c->current.offset = c->current.size;
    c->total.offset = c->total.size;

    /*
     * write checksum
     */
    uint8_t *cs = NULL;
    size_t cl = 0;
    io_encryption_checksum(c->output, &cs, &cl);
    io_write(c->output, cs, cl);

    write_random_data(c);

    /*
     * done
     */
    io_sync(c->output);
    c->status = SUCCESS;
end:
    return c;
}

static inline void write_header(crypto_t *c)
{
    log_message(LOG_INFO, _("Writing standard header"));
    uint64_t head[3] = { htonll(HEADER_0), htonll(HEADER_1), htonll(HEADER_2) };
    io_write(c->output, head, sizeof head);
    char *algos = NULL;
    char *u_cipher = strdup(c->cipher);
    if (!u_cipher)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(c->cipher) + sizeof( byte_t ));
    char *u_hash = strdup(c->hash);
    if (!u_hash)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(c->hash) + sizeof( byte_t ));
    for (size_t i = 0; i < strlen(u_cipher); i++)
        u_cipher[i] = toupper(u_cipher[i]);
    for (size_t i = 0; i < strlen(u_hash); i++)
        u_hash[i] = toupper(u_hash[i]);
    if (!asprintf(&algos, "%s/%s", u_cipher, u_hash))
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(c->cipher) + strlen(c->hash) + 2);
    free(u_cipher);
    free(u_hash);
    uint8_t h = (uint8_t)strlen(algos);
    io_write(c->output, &h, sizeof h);
    io_write(c->output, algos, h);
    free(algos);
    return;
}

static inline void write_verification_sum(crypto_t *c)
{
    log_message(LOG_INFO, _("Writing verification sum"));
    /*
     * write simple addition (x ^ y = z) where x, y are random
     * 64bit signed integers
     */
    int64_t x;
    gcry_create_nonce(&x, sizeof x);
    uint64_t y;
    gcry_create_nonce(&y, sizeof y);
    uint64_t z = x ^ y;
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    x = htonll(x);
    y = htonll(y);
    z = htonll(z);
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    io_write(c->output, &x, sizeof x);
    io_write(c->output, &y, sizeof y);
    io_write(c->output, &z, sizeof z);
    return;
}

static inline void write_metadata(crypto_t *c)
{
    log_message(LOG_INFO, _("Writing metadata"));
    if (c->directory)
        c->total.size = count_entries(c->path);
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
    uint8_t h = tlv_count(tlv);
    io_write(c->output, &h, sizeof h);
    io_write(c->output, tlv_export(tlv), tlv_size(tlv));
    tlv_deinit(&tlv);
    return;
}

static inline void write_random_data(crypto_t *c)
{
    uint8_t l;
    gcry_create_nonce(&l, sizeof l);
    uint8_t *b = malloc(l);
    if (!b)
        die(_("Out of memory @ %s:%d:%s [%hhu]"), __FILE__, __LINE__, __func__, l);
    gcry_create_nonce(b, l);
    io_write(c->output, &l, sizeof l);
    io_write(c->output, b, l);
    free(b);
    return;
}

static int64_t count_entries(const char *dir)
{
    struct dirent **eps = NULL;
    int n = 0;
    int64_t e = 1;
    log_message(LOG_EVERYTHING, _("Scanning directory : %s"), dir);
    errno = 0;
    if ((n = scandir(dir, &eps, NULL, alphasort)))
    {
        for (int i = 0; i < n; ++i)
        {
            char *nm = strdup(eps[i]->d_name);
            if (!strcmp(".", nm) || !strcmp("..", nm))
            {
                free(nm);
                continue;
            }
            size_t l = strlen(nm);
            if (!asprintf(&nm, "%s/%s", dir, nm))
                die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
            struct stat s;
            stat(nm, &s);
            if (S_ISDIR(s.st_mode))
                e += count_entries(nm);
            else if (S_ISREG(s.st_mode))
                e++;
            free(nm);
        }
    }
    free(eps);
    return e;
}

static void encrypt_directory(crypto_t *c, const char *dir)
{
    struct dirent **eps = NULL;
    int n = 0;
    if ((n = scandir(dir, &eps, NULL, alphasort)))
    {
        log_message(LOG_DEBUG, _("Found %i entries in %s"), n - 2, dir); /* subtract 2 for . and .. */

        for (int i = 0; i < n; ++i)
        {
            if (c->status != RUNNING)
                break;

            char *nm = strdup(eps[i]->d_name);
            if (!strcmp(".", nm) || !strcmp("..", nm))
            {
                free(nm);
                continue;
            }
            uint64_t l = strlen(nm);
            if (!asprintf(&nm, "%s/%s", dir, nm))
                die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
            file_type_e tp;
            struct stat s;
            stat(nm, &s);
            if (S_ISDIR(s.st_mode))
                tp = FILE_DIRECTORY;
            else if (S_ISREG(s.st_mode))
                tp = FILE_REGULAR;
            else
            {
                log_message(LOG_EVERYTHING, _("Ignoring unsupported file type [%d] : %s"), eps[i]->d_type, nm);
                free(nm);
                continue;
            }
            io_write(c->output, &tp, sizeof( byte_t ));
            l = htonll(strlen(nm));
            io_write(c->output, &l, sizeof l);
            io_write(c->output, nm, strlen(nm));

            switch (tp)
            {
                case FILE_DIRECTORY:
                    /*
                     * recurse into each directory as necessary
                     */
                    log_message(LOG_VERBOSE, _("Storing directory : %s"), nm);
                    encrypt_directory(c, nm);
                    break;
                case FILE_REGULAR:
                    /*
                     * when we have a file:
                     */
                    log_message(LOG_VERBOSE, _("Encrypting file : %s"), nm);
                    c->source = io_open(nm, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
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
            free(nm);
            c->total.offset++;
        }
        /*
         * no more files in this directory
         */
    }
    free(eps);
    return;
}

static void encrypt_stream(crypto_t *c)
{
    time(&c->current.started);
    bool b = true;
    uint8_t *buffer;
    if (!(buffer = malloc(c->blocksize + sizeof b)))
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->blocksize + sizeof b);
    do
    {
        if (c->status == CANCELLED)
            break;
        errno = EXIT_SUCCESS;
        /*
         * read plaintext file, write encrypted data
         */
        memset(buffer, 0x00, c->blocksize);
        int64_t r = io_read(c->source, buffer + sizeof b, c->blocksize);
        if (r < 0)
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = FAILED_IO;
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
    while (b);
    free(buffer);
    c->total.total += c->current.size;
    return;
}

static void encrypt_file(crypto_t *c)
{
    time(&c->current.started);
    uint8_t buffer[BLOCK_SIZE];
    for (c->current.offset = 0; c->current.offset < c->current.size; c->current.offset += BLOCK_SIZE)
    {
        if (c->status == CANCELLED)
            break;
        errno = EXIT_SUCCESS;
        /*
         * read plaintext file, write encrypted data
         */
        int64_t r = io_read(c->source, buffer, BLOCK_SIZE);
        if (r < 0)
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = FAILED_IO;
            break;
        }
        io_write(c->output, buffer, r);
    }
    c->total.total += c->current.size;
    return;
}
