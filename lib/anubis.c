/*
 *	This anubis module is an algorithm plugin for encrypt
 *	Copyright (c) 2005-2008, Ashley Anderson
 *	email: amanderson@albinoloverats.net
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "anubis.h"
#include "plugins.h"
#include "rmd160.h"

extern struct about_info about(void)
{
    struct about_info anubis;
    anubis.a_name = strdup(A_NAME);
    anubis.a_authors = strdup(A_AUTHORS);
    anubis.a_copyright = strdup(A_COPYRIGHT);
    anubis.a_licence = strdup(A_LICENCE);
    anubis.a_year = strdup(A_YEAR);
    anubis.a_block = strdup(A_BLOCK);
    anubis.k_name = strdup(K_NAME);
    anubis.k_authors = strdup(K_AUTHORS);
    anubis.k_copyright = strdup(K_COPYRIGHT);
    anubis.k_licence = strdup(K_LICENCE);
    anubis.k_year = strdup(K_YEAR);
    anubis.k_size = strdup(K_SIZE);
    anubis.m_authors = strdup(M_AUTHORS);
    anubis.m_copyright = strdup(M_COPYRIGHT);
    anubis.m_licence = strdup(M_LICENCE);
    anubis.m_version = strdup(M_VERSION);
    anubis.o_comment = strdup(O_COMMENT);
    return anubis;
}

extern int enc_main(int in, int out, void *key)
{
    errno = 0;
    ssize_t len = 0, size = (off_t) lseek(in, 0, SEEK_END);
    lseek(in, 0, SEEK_SET);
    struct NESSIEstruct subkeys;
    unsigned char plain[BLOCKSIZEB], cipher[BLOCKSIZEB];
    NESSIEkeysetup(key, &subkeys);
    write(out, HEADER, strlen(HEADER));
    memcpy(plain, &size, sizeof (ssize_t));
    NESSIEencrypt(&subkeys, plain, cipher);
    write(out, cipher, BLOCKSIZEB);
    while ((len = read(in, plain, BLOCKSIZEB)) > 0)
    {
        NESSIEencrypt(&subkeys, plain, cipher);
        write(out, cipher, BLOCKSIZEB);
    }
    if (len != 0)
        return errno;
    return EXIT_SUCCESS;
}

extern int dec_main(int in, int out, void *key)
{
    errno = 0;
    ssize_t len = 0, size = 0;
    struct NESSIEstruct subkeys;
    unsigned char cipher[BLOCKSIZEB], plain[BLOCKSIZEB];
    NESSIEkeysetup(key, &subkeys);

    char *tmp = calloc(strlen(HEADER), sizeof (char));
    read(in, tmp, strlen(HEADER));
    if (strncmp(tmp, HEADER, strcspn(HEADER, "/")))
        return EFTYPE;
    free(tmp);

    lseek(in, strlen(HEADER), SEEK_SET);
    len = read(in, &cipher, BLOCKSIZEB);
    NESSIEdecrypt(&subkeys, cipher, plain);
    memcpy(&size, plain, sizeof (size_t));
    for (int i = 0; i < size / (BLOCKSIZEB); i++)
    {
        if ((len = read(in, cipher, BLOCKSIZEB)) != BLOCKSIZEB)
            return errno;
        NESSIEdecrypt(&subkeys, cipher, plain);
        write(out, plain, BLOCKSIZEB);
    }
    if ((len = read(in, cipher, BLOCKSIZEB)) != BLOCKSIZEB)
        return errno;
    NESSIEdecrypt(&subkeys, cipher, plain);
    write(out, plain, ((size * 8) % (BLOCKSIZE)) / 8);
    return EXIT_SUCCESS;
}

extern void *gen_file(int file)
{
    char *data = NULL;
    size_t size = (off_t) lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    if ((data = malloc(size + 1)) == NULL)
        return NULL;
    read(file, data, size);
    data[size] = '\0';
    return gen_text(data, (long unsigned) size);
}

extern void *gen_text(void *msg, long unsigned length)
{
    byte *message;
    message = calloc(length, sizeof (char));
    memmove(message, msg, length);
    dword MDbuf[RMDsize / 32], X[16], nbytes;
    static byte hashcode[RMDsize / 8];
    MDinit(MDbuf);
    for (nbytes = length; nbytes > 63; nbytes -= 64)
    {
        for (int i = 0; i < 16; i++)
        {
            X[i] = BYTES_TO_DWORD(message);
            message += 4;
        }
        MDcompress(MDbuf, X);
    }
    MDfinish(MDbuf, message, length, 0);
    for (int i = 0; i < RMDsize / 8; i += 4)
    {
        hashcode[i] = MDbuf[i >> 2];
        hashcode[i + 1] = (MDbuf[i >> 2] >> 8);
        hashcode[i + 2] = (MDbuf[i >> 2] >> 16);
        hashcode[i + 3] = (MDbuf[i >> 2] >> 24);
    }
    message = realloc(message, RMDsize / 8);
    return memmove(message, hashcode, RMDsize / 8);
}

extern void *key_read(int file)
{
    char data[2];
    static byte *key;
    size_t size = (off_t) lseek(file, 0, SEEK_END);
    if (size < RMDsize / 8)
        return NULL;
    lseek(file, 0, SEEK_SET);
    if ((key = malloc(RMDsize / 8)) == NULL)
        return NULL;
    for (int i = 0; i < RMDsize / 8; i++) {
        read(file, &data, 2 * sizeof (char));
        key[i] = strtol(data, NULL, 16);
    }
    return key;
}
