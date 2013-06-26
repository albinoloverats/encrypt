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
#include <sys/stat.h>
#include <dirent.h>

#include <ctype.h>
#include <inttypes.h> // used instead of stdint as this defines the PRI… format placeholders (include <stdint.h> itself)
#include <stdbool.h>
#include <string.h>

#ifndef _WIN32
    #include <netinet/in.h>
#endif

#include <gcrypt.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#include "common/tlv.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "crypto.h"
#include "encrypt.h"
#include "io.h"

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

extern crypto_t *encrypt_init(const char * const restrict i, const char * const restrict o, const char * const restrict c, const char * const restrict h, const void * const restrict k, size_t l, bool x, bool f, version_e v)
{
    init_crypto();

    crypto_t *z = calloc(1, sizeof( crypto_t ));
    if (!z)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, sizeof( crypto_t ));

    z->status = STATUS_INIT;

    z->path = NULL;
    z->directory = false;
    if (i)
    {
        struct stat s;
        stat(i, &s);
        if (S_ISDIR(s.st_mode))
        {
            log_message(LOG_VERBOSE, _("Encrypting directory tree : %s"), i);
            z->source = IO_UNINITIALISED;
            z->path = strdup(i);
            z->directory = true;
        }
        else
        {
            log_message(LOG_VERBOSE, _("Encrypting file : %s"), i);
            if (!(z->source = io_open(i, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR)))
            {
                log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
                z->status = STATUS_FAILED_IO;
                return z;
            }
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Encrypting stream from stdin"));
        z->source = IO_STDIN_FILENO;
    }

    if (o)
    {
        log_message(LOG_VERBOSE, _("Encrypting to file : %s"), o);
        if (!(z->output = io_open(o, O_CREAT | O_TRUNC | O_WRONLY | F_WRLCK, S_IRUSR | S_IWUSR)))
        {
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            z->status = STATUS_FAILED_OUTPUT_MISMATCH;
            return z;
        }
    }
    else
    {
        log_message(LOG_VERBOSE, _("Encrypting to stdout"));
        z->output = IO_STDOUT_FILENO;
    }

    if (!k)
    {
        log_message(LOG_ERROR, _("Invalid key data"));
        z->status = STATUS_FAILED_INIT;
        return z;
    }
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
            z->status = STATUS_FAILED_IO;
            return z;
        }
        z->length = lseek(kf, 0, SEEK_END);
        lseek(kf, 0, SEEK_SET);
        if (!(z->key = malloc(z->length)))
            die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, z->length);
        read(kf, z->key, z->length);
        close(kf);
    }

    z->process = process;

    z->cipher = strdup(c);
    z->hash = strdup(h);

    z->blocksize = BLOCK_SIZE;
    z->compressed = x;
    z->follow_links = f;

    z->version = v ? : VERSION_CURRENT;
    /*
     * determine which settings are valid for the given version
     */
    switch (z->version)
    {
        case VERSION_2011_08:
        case VERSION_2011_10:
            /*
             * single file only; if we don't split the plaintext into
             * then both versions are identical :)
             */
            z->version = VERSION_2011_08;
            z->compressed = false;
            /* allow fall-through to check for directories */
        case VERSION_2012_11:
            /* allow compression, but not directories */
            if (z->source == IO_UNINITIALISED)
                die(_("Compatibility with version %s does not allow encrypting directories"), get_version(z->version));
            /* if not compressing, fallback even more */
            if (!z->compressed)
                z->version = VERSION_2011_08;
            break;

        case VERSION_2013_02:
            z->follow_links = true;
        case VERSION_CURRENT:
            /*
             * do nothing, all options are available; not falling back
             * allows extra padding at beginning of file
             */
            break;

        default:
            die(_("We've reached an unreachable location in the code @ %s:%d:%s"), __FILE__, __LINE__, __func__);
    }
    log_message(LOG_VERBOSE, _("Encrypted file compatible with versions %s and later"), get_version(z->version));
    return z;
}

static void *process(void *ptr)
{
    crypto_t *c = (crypto_t *)ptr;

    if (!c || c->status != STATUS_INIT)
        return log_message(LOG_ERROR, _("Invalid cryptographic object!")) , NULL;

    c->status = STATUS_RUNNING;
    write_header(c);
    /*
     * all data written from here on is encrypted
     */
    io_extra_t iox = { false, 1 };
    io_encryption_init(c->output, c->cipher, c->hash, c->key, c->length, iox);
    free(c->cipher);
    free(c->key);

    bool pre_random = true;
    switch (c->version)
    {
        case VERSION_2011_08:
        case VERSION_2011_10:
        case VERSION_2012_11:
            /*
             * these versions didn't have random data preceeding the verification sum
             */
            pre_random = false;
            break;

        default:
            /* all subsequent versions */
            break;
    }
    if (pre_random)
        write_random_data(c);

    write_verification_sum(c);
    write_random_data(c);
    write_metadata(c);

    if (pre_random)
        write_random_data(c);

    /*
     * main encryption loop; if we're compressing the output then everything
     * from here will be compressed (if necessary)
     */
    if (c->compressed)
        io_compression_init(c->output);
    log_message(LOG_INFO, _("Starting encryption process"));

    io_encryption_checksum_init(c->output, c->hash);
    free(c->hash);

    if (c->directory)
    {
        log_message(LOG_INFO, _("Directory tree contains %" PRIi64 " entries"), c->total.size);
        file_type_e tp = FILE_DIRECTORY;
        io_write(c->output, &tp, sizeof( byte_t ));
        uint64_t l = htonll(strlen(c->path));
        io_write(c->output, &l, sizeof l);
        io_write(c->output, c->path, strlen(c->path));
        c->total.offset = 1;
        if (!(c->misc = calloc(c->total.size, sizeof( link_count_t ))))
            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, c->total.size * sizeof( link_count_t ));
        encrypt_directory(c, c->path);
        for (uint64_t i = 0; i < c->total.size; i++)
            if (((link_count_t *)c->misc)[i].path)
                free(((link_count_t *)c->misc)[i].path);
        free(c->misc);
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
    uint8_t *cs = NULL;
    size_t cl = 0;
    io_encryption_checksum(c->output, &cs, &cl);
    io_write(c->output, cs, cl);
    free(cs);

    write_random_data(c);

    /*
     * done
     */
    io_sync(c->output);
    c->status = STATUS_SUCCESS;

    return (void *)c->status;
}

static inline void write_header(crypto_t *c)
{
    log_message(LOG_INFO, _("Writing standard header"));
    uint64_t head[3] = { htonll(HEADER_0), htonll(HEADER_1), htonll(c->version) };
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
    uint8_t h = tlv_count(tlv);
    io_write(c->output, &h, sizeof h);
    io_write(c->output, tlv_export(tlv), tlv_size(tlv));
    tlv_deinit(&tlv);
    return;
}

static inline void write_random_data(crypto_t *c)
{
#ifndef __DEBUG__
    uint8_t l;
    gcry_create_nonce(&l, sizeof l);
    uint8_t *b = malloc(l);
    if (!b)
        die(_("Out of memory @ %s:%d:%s [%hhu]"), __FILE__, __LINE__, __func__, l);
    gcry_create_nonce(b, l);
    io_write(c->output, &l, sizeof l);
    io_write(c->output, b, l);
    free(b);
#endif
    return;
}

static int64_t count_entries(crypto_t *c, const char *dir)
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
            char *filename = strdup(eps[i]->d_name);
            if (!strcmp(".", filename) || !strcmp("..", filename))
            {
                free(filename);
                continue;
            }
            size_t l = strlen(filename);
            if (!asprintf(&filename, "%s/%s", dir, filename))
                die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
            struct stat s;
            c->follow_links ? stat(filename, &s) : lstat(filename, &s);
            if (S_ISDIR(s.st_mode))
                e += count_entries(c, filename);
            else if (S_ISREG(s.st_mode))
                e++;
            else if (!c->follow_links && S_ISLNK(s.st_mode))
                e++;
            free(filename);
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
        for (int i = 0; i < n && c->status == STATUS_RUNNING; ++i)
        {
            char *filename = strdup(eps[i]->d_name);
            if (!strcmp(".", filename) || !strcmp("..", filename))
            {
                free(filename);
                continue;
            }
            uint64_t l = strlen(filename);
            if (!asprintf(&filename, "%s/%s", dir, filename))
                die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, strlen(dir) + l + 2);
            file_type_e tp;
            struct stat s;
            c->follow_links ? stat(filename, &s) : lstat(filename, &s);
            char *hl = NULL;
            switch (s.st_mode & S_IFMT)
            {
                case S_IFDIR:
                    tp = FILE_DIRECTORY;
                    break;
                case S_IFLNK:
                    tp = (hl = encrypt_link(c, filename, s)) ? FILE_LINK : FILE_SYMLINK;
                    break;
                case S_IFREG:
                    tp = (hl = encrypt_link(c, filename, s)) ? FILE_LINK : FILE_REGULAR;
                    break;
                default:
                    log_message(LOG_EVERYTHING, _("Ignoring unsupported file type for : %s"), filename);
                    free(filename);
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
                    log_message(LOG_VERBOSE, _("Storing directory : %s"), filename);
                    encrypt_directory(c, filename);
                    break;
                case FILE_SYMLINK:
                    /*
                     * store the link instead of the file/directory it points to
                     */
                    log_message(LOG_VERBOSE, _("Storing soft link : %s"), filename);
                    char *lnk = NULL;
                    for (l = BLOCK_SIZE; ; l += BLOCK_SIZE)
                    {
                        char *x = realloc(lnk, l + sizeof( byte_t ));
                        if (!x)
                            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, l + sizeof( byte_t ) );
                        lnk = x;
                        if (readlink(filename, lnk, BLOCK_SIZE + l) < (int64_t)l)
                            break;
                    }
                    l = htonl(strlen(lnk));
                    io_write(c->output, &l, sizeof l);
                    io_write(c->output, lnk, strlen(lnk));
                    break;
                case FILE_LINK:
                    /*
                     * store a hard link; it's basically the same as a symlink
                     * at this point, but will be handled differently upon
                     * decryption
                     */
                    log_message(LOG_VERBOSE, _("Storing link : %s"), filename);
                    l = htonl(strlen(hl));
                    io_write(c->output, &l, sizeof l);
                    // FIXME store the link, not itself :-p
                    io_write(c->output, hl, strlen(hl));
                    break;
                case FILE_REGULAR:
                    /*
                     * when we have a file:
                     */
                    log_message(LOG_VERBOSE, _("Encrypting file : %s"), filename);
                    c->source = io_open(filename, O_RDONLY | F_RDLCK, S_IRUSR | S_IWUSR);
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
            free(filename);
            c->total.offset++;
        }
        /*
         * no more files in this directory
         */
    }
    free(eps);
    return;
}

static char *encrypt_link(crypto_t *c, char *filename, struct stat s)
{
    link_count_t *ln = (link_count_t *)c->misc;
    for (uint64_t i = 0; i < c->total.offset; i++)
        if (ln[i].dev == s.st_dev && ln[i].inode == s.st_ino)
            return log_message(LOG_EVERYTHING, _("File %s is a duplicate of %ju:%ju"), filename, s.st_dev, s.st_ino) , ln[i].path;
    ln[c->total.offset].dev = s.st_dev;
    ln[c->total.offset].inode = s.st_ino;
    ln[c->total.offset].path = strdup(filename);
    return NULL;
}

static void encrypt_stream(crypto_t *c)
{
    bool b = true;
    uint8_t *buffer;
    if (!(buffer = malloc(c->blocksize + sizeof b)))
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
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
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
    free(buffer);
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
            log_message(LOG_ERROR, _("IO error [%d] @ %s:%d:%s : %s"), errno, __FILE__, __LINE__, __func__, strerror(errno));
            c->status = STATUS_FAILED_IO;
            break;
        }
        io_write(c->output, buffer, r);
    }
    return;
}
