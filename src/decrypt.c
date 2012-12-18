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

#include <inttypes.h> // used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself)
#include <stdbool.h>
#include <string.h>

#include <time.h>
#include <netinet/in.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#include "common/tlv.h"

#include "crypto.h"
#include "decrypt.h"
#include "io.h"

static void *process(void *);

static uint64_t read_version(crypto_t *);
static bool read_verification_sum(crypto_t *);
static bool read_metadata(crypto_t *);
static void skip_random_data(crypto_t *);

static void decrypt_directory(crypto_t *, const char *);
static void decrypt_stream(crypto_t *);
static void decrypt_file(crypto_t *);

extern crypto_t *decrypt_init(const char * const restrict i, const char * const restrict o, const void * const restrict k, size_t l)
{
    init_crypto();

    crypto_t *c = calloc(1, sizeof( crypto_t ));
    if (!c)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( crypto_t ));

    c->status = INIT;

    if (i)
    {
        log_message(LOG_VERBOSE, _("Decrypting file : %s"), i);
        if (!(c->source = io_open(i, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR)))
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = FAILED_IO;
            goto end;
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Decrypting stream from stdin"));
        c->source = io_use_stdin();
    }

    c->path = NULL;
    c->compressed = false;
    c->directory = false;

    if (o)
    {
        struct stat s;
        errno = 0;
        if (stat(o, &s) < 0)
        {
            if (errno != ENOENT)
            {
                log_message(LOG_ERROR, _("Unexpected error looking up destination"));
                c->status = FAILED_IO;
                goto end;
            }
            log_message(LOG_VERBOSE, _("Not sure whether %s will be a file or directory"), o);
            /*
             * we've got a name, but don't yet know if it will be a file
             * or a directory
             */
            c->output = NULL;
            c->path = strdup(o);
        }
        else
        {
            if (S_ISDIR(s.st_mode))
            {
                log_message(LOG_VERBOSE, _("Decrypting to directory : %s"), o);
                c->output = NULL;
                c->path = strdup(o);
                c->directory = true;
            }
            else if (S_ISREG(s.st_mode))
            {
                log_message(LOG_VERBOSE, _("Decrypting to file : %s"), o);
                if (!(c->output = io_open(o, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK, S_IRUSR | S_IWUSR)))
                {
                    log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
                    c->status = FAILED_IO;
                    goto end;
                }
            }
            else
            {
                log_message(LOG_ERROR, _("Unsupported destination file type"));
                c->output = NULL;
                c->status = FAILED_IO;
                goto end;
            }
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Decrypting to stdout"));
        c->output = io_use_stdout();
    }

    if (l)
    {
        if (!(c->key = malloc(l)))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, l);
        memcpy(c->key, k, l);
        c->length = l;
    }
    else
    {
        int64_t kf = open(k, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (kf < 0)
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = FAILED_IO;
            goto end;
        }
        c->length = lseek(kf, 0, SEEK_END);
        lseek(kf, 0, SEEK_SET);
        if (!(c->key = malloc(c->length)))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, c->length);
        read(kf, c->key, c->length);
        close(kf);
    }

    c->process = process;

end:
    return c;
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
    /*
     * read encrypt file header
     */
    uint64_t version = read_version(c);
    if (!version)
        return NULL;

    io_encryption_init(c->source, c->cipher, c->hash, c->key, c->length);
    free(c->cipher);
    free(c->hash);
    free(c->key);

    bool skip_some_random = false;
    switch (version)
    {
        case HEADER_VERSION_201108:
        case HEADER_VERSION_201110:
        case HEADER_VERSION_201211:
            /*
             * these versions only had random data after the verification sum
             */
            skip_some_random = true;
            break;
    }
    if (!skip_some_random)
        skip_random_data(c);
    if (!read_verification_sum(c))
        return NULL;
    skip_random_data(c);
    if (!read_metadata(c))
        return NULL;
    if (!skip_some_random)
        skip_random_data(c);

    /*
     * main decryption loop
     */
    if (c->compressed)
        io_compression_init(c->source);
    log_message(LOG_INFO, _("Starting decryption process"));

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
     * NB Newer versions didn't require the data be split into blocks;
     *    it was only to allow pipe to give us data where we didn't know
     *    ahead of time the total size
     */
    io_encryption_checksum_init(c->source);

    if (c->directory)
        decrypt_directory(c, c->path);
    else
    {
        c->current.size = c->total.size;
        c->total.size = 1;
        if (c->blocksize)
            decrypt_stream(c);
        else
            decrypt_file(c);
    }

    if (c->status != RUNNING)
        goto end;

    c->current.offset = c->current.size;
    c->total.offset = c->total.size;

    if (version != HEADER_VERSION_201108)
    {
        /*
         * verify checksum (on versions which calculated it correctly)
         */
        uint8_t *cs = NULL;
        size_t cl = 0;
        io_encryption_checksum(c->source, &cs, &cl);
        uint8_t *b = malloc(cl);
        io_read(c->source, b, cl);
        if (memcmp(b, cs, cl))
        {
            log_message(LOG_ERROR, _("Checksum verification failed"));
            c->status = FAILED_CHECKSUM;
        }
        free(b);
    }

    skip_random_data(c); /* not entirely necessary as we already know we've reached the end of the file */

    /*
     * done
     */
    io_sync(c->output);
    c->status = SUCCESS;
end:
    return c;
}

static uint64_t read_version(crypto_t *c)
{
    log_message(LOG_INFO, _("Checking for file header"));

    uint64_t head[3] = { 0x0 };
    if ((io_read(c->source, head, sizeof head)) < 0)
    {
        log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
        return 0;
    }
    if (head[0] != htonll(HEADER_0) || head[1] != htonll(HEADER_1))
    {
        log_message(LOG_ERROR, _("Data not encrypted"));
        return 0;
    }
    uint8_t l;
    io_read(c->source, &l, sizeof l);
    char *a = calloc(l + sizeof( char ), sizeof( char ));
    io_read(c->source, a, l);
    char *h = strchr(a, '/');
    *h = '\0';
    h++;
    c->cipher = strdup(a);
    c->hash = strdup(h);
    h--;
    *h = '/'; /* probably not necessary, but doesn't harm anyone */
    h = NULL;
    free(a);

    switch (ntohll(head[2]))
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

        case HEADER_VERSION_NEXT:
            log_message(LOG_INFO, _("File encrypted with development version"));
            return HEADER_VERSION_NEXT;

        default:
            log_message(LOG_ERROR, _("File encrypted with unknown, or more recent release of encrypt"));
            return 0;
    }
}

static bool read_verification_sum(crypto_t *c)
{
    log_message(LOG_INFO, _("Reading verification sum"));
    /*
     * read three 64bit signed integers and assert that x ^ y = z
     */
    uint64_t x = 0;
    uint64_t y = 0;
    uint64_t z = 0;
    io_read(c->source, &x, sizeof x);
    io_read(c->source, &y, sizeof y);
    io_read(c->source, &z, sizeof z);
    log_message(LOG_DEBUG, _("Verifying x ^ y = z"));
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    x = ntohll(x);
    y = ntohll(y);
    z = ntohll(z);
    log_message(LOG_VERBOSE, "x = %" PRIx64 " ; y = %" PRIx64 " ; z = %" PRIx64, x, y, z);
    if ((x ^ y) != z)
    {
        log_message(LOG_ERROR, _("Failed decryption verification"));
        c->status = FAILED_DECRYPTION;
        return false;
    }
    return true;
}

static bool read_metadata(crypto_t *c)
{
    log_message(LOG_INFO, _("Reading metadata"));
    /*
     * read the original file metadata - skip any unknown tag values
     */
    uint8_t h = 0;
    TLV_HANDLE tlv = tlv_init();
    io_read(c->source, &h, sizeof h);
    for (int i = 0; i < h; i++)
    {
        tlv_t t;
        io_read(c->source, &t.tag, sizeof( byte_t ));
        io_read(c->source, &t.length, sizeof t.length);
        t.length = ntohs(t.length);
        if (!(t.value = malloc(t.length)))
            die(_("Out of memory @ %s:%d:%s [%d]"), __FILE__, __LINE__, __func__, t.length);
        io_read(c->source, t.value, t.length);
        tlv_append(&tlv, t);
        free(t.value);
    }

    if (tlv_has_tag(tlv, TAG_SIZE))
    {
        memcpy(&c->total.size, tlv_value_of(tlv, TAG_SIZE), sizeof c->total.size);
        c->total.size = ntohll(c->total.size);
        log_message(LOG_DEBUG, _("Encrypted stream has size of %" PRIu64), c->total.size);
        c->blocksize = 0;
    }

    if (tlv_has_tag(tlv, TAG_BLOCKED))
    {
        memcpy(&c->blocksize, tlv_value_of(tlv, TAG_BLOCKED), sizeof c->blocksize);
        c->blocksize = ntohll(c->blocksize);
    }
    else
        c->blocksize = 0;
    log_message(LOG_DEBUG, _("Encrypted stream is %sblock delimited"), c->blocksize ? "" : "not ");

    if (tlv_has_tag(tlv, TAG_COMPRESSED))
        c->compressed = *tlv_value_of(tlv, TAG_COMPRESSED);
    else
        c->compressed = false;
    log_message(LOG_DEBUG, _("Encrypted stream is %scompressed"), c->compressed ? "" : "not ");

    if (tlv_has_tag(tlv, TAG_DIRECTORY))
        c->directory = *tlv_value_of(tlv, TAG_DIRECTORY);
    if (c->directory && !c->output)
    {
        log_message(LOG_DEBUG, _("Output is to a directory"));
        mkdir(c->path, S_IRUSR | S_IWUSR | S_IXUSR);
    }
    else if (!c->directory)
    {
        log_message(LOG_DEBUG, _("Output is to a file"));
        if (!c->output)
            c->output = io_open(c->path, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK, S_IRUSR | S_IWUSR);
    }
    else
    {
        log_message(LOG_ERROR, _("Output requires a directory, not a file"));
        c->status = FAILED_OUTPUT_MISMATCH;
    }

    tlv_deinit(&tlv);
    return c->status == RUNNING;
}

static void skip_random_data(crypto_t *c)
{
    uint8_t l;
    io_read(c->source, &l, sizeof l);
    uint8_t *b = malloc(l);
    if (!b)
        die(_("Out of memory @ %s:%d:%s [%hhu]"), __FILE__, __LINE__, __func__, l);
    io_read(c->source, b, l);
    free(b);
    return;
}

static void decrypt_directory(crypto_t *c, const char *dir)
{
    log_message(LOG_INFO, _("Decrypting %" PRIu64 " entries into %s"), c->total.size, dir);
    for (c->total.offset = 0; c->total.offset < c->total.size; c->total.offset++)
    {
        if (c->status != RUNNING)
            break;

        file_type_e tp;
        io_read(c->source, &tp, sizeof( byte_t ));

        char *nm;
        uint64_t l;
        io_read(c->source, &l, sizeof l);
        l = ntohll(l);
        if (!(nm = calloc(l + sizeof( byte_t ), sizeof( char ))))
            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, l + sizeof( byte_t ));
        io_read(c->source, nm, l);
        if (!asprintf(&nm, "%s/%s", dir, nm))
            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2 * sizeof( byte_t ));
        switch (tp)
        {
            case FILE_DIRECTORY:
                log_message(LOG_VERBOSE, _("Creating directory : %s"), nm);
                mkdir(nm, S_IRUSR | S_IWUSR | S_IXUSR);
                break;

            case FILE_REGULAR:
                c->current.offset = 0;
                io_read(c->source, &c->current.size, sizeof c->current.size);
                c->current.size = ntohll(c->current.size);
                log_message(LOG_VERBOSE, _("Decrypting file : %s"), nm);
                c->output = io_open(nm, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK, S_IRUSR | S_IWUSR);
                decrypt_file(c);
                io_close(c->output);
                c->output = NULL;
                c->current.offset = c->total.size;
                break;
        }
        free(nm);
    }
    return;
}

static void decrypt_stream(crypto_t *c)
{
    time(&c->current.started);
    bool b = true;
    uint8_t *buffer;
    if (!(buffer = malloc(c->blocksize + sizeof b)))
        die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->blocksize + sizeof b);
    while (b)
    {
        if (c->status == CANCELLED)
            break;
        errno = EXIT_SUCCESS;
        int64_t r = io_read(c->source, buffer, c->blocksize + sizeof b);
        if (r < 0)
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = FAILED_IO;
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
    free(buffer);
    c->total.total += c->current.size;
    return;
}

static void decrypt_file(crypto_t *c)
{
    time(&c->current.started);
    uint8_t buffer[BLOCK_SIZE];
    for (c->current.offset = 0; c->current.offset < c->current.size; c->current.offset += BLOCK_SIZE)
    {
        if (c->status == CANCELLED)
            break;
        errno = EXIT_SUCCESS;
        size_t l = BLOCK_SIZE;
        if (c->current.offset + BLOCK_SIZE > c->current.size)
            l = BLOCK_SIZE - (c->current.offset + BLOCK_SIZE - c->current.size);
        int64_t r = io_read(c->source, buffer, l);
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