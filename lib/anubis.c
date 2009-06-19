/*
 * This anubis module is an algorithm plugin for encrypt
 * Copyright (c) 2005-2009, Ashley Anderson
 * email: amanderson@albinoloverats.net
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "anubis.h"
#include "plugins.h"
#include "rmd160.h"

extern info_t *plugin_info(void)
{
    info_t *anubis = calloc(1, sizeof( info_t ));
    if (!anubis)
        return NULL;
    anubis->algorithm_name      = strdup(A_NAME);
    anubis->algorithm_authors   = strdup(A_AUTHORS);
    anubis->algorithm_copyright = strdup(A_COPYRIGHT);
    anubis->algorithm_licence   = strdup(A_LICENCE);
    anubis->algorithm_year      = strdup(A_YEAR);
    anubis->algorithm_block     = strdup(A_BLOCK);
    anubis->key_name            = strdup(K_NAME);
    anubis->key_authors         = strdup(K_AUTHORS);
    anubis->key_copyright       = strdup(K_COPYRIGHT);
    anubis->key_licence         = strdup(K_LICENCE);
    anubis->key_year            = strdup(K_YEAR);
    anubis->key_size            = strdup(K_SIZE);
    anubis->module_authors      = strdup(M_AUTHORS);
    anubis->module_copyright    = strdup(M_COPYRIGHT);
    anubis->module_licence      = strdup(M_LICENCE);
    anubis->module_version      = strdup(M_VERSION);
    anubis->module_comment      = strdup(O_COMMENT);
    return anubis;
}

extern int64_t plugin_encrypt(int64_t in, int64_t out, uint8_t *key)
{
    errno = EXIT_SUCCESS;
    ssize_t len = 0, size = (off_t)lseek(in, 0, SEEK_END);
    lseek(in, 0, SEEK_SET);
    struct NESSIEstruct subkeys;
    unsigned char plain[BLOCKSIZEB], cipher[BLOCKSIZEB];
    NESSIEkeysetup(key, &subkeys);
    if (write(out, HEADER, strlen(HEADER)) != strlen(HEADER))
        return errno;
    memcpy(plain, &size, sizeof( ssize_t ));
    NESSIEencrypt(&subkeys, plain, cipher);
    if (write(out, cipher, BLOCKSIZEB) != BLOCKSIZEB)
        return errno;
    while ((len = read(in, plain, BLOCKSIZEB)) > 0)
    {
        NESSIEencrypt(&subkeys, plain, cipher);
        if (write(out, cipher, BLOCKSIZEB) != BLOCKSIZEB)
            return errno;
    }
    if (len != 0)
        return errno;
    return EXIT_SUCCESS;
}

extern int64_t plugin_decrypt(int64_t in, int64_t out, uint8_t *key)
{
    errno = EXIT_SUCCESS;
    ssize_t len = 0, size = 0;
    struct NESSIEstruct subkeys;
    unsigned char cipher[BLOCKSIZEB], plain[BLOCKSIZEB];
    NESSIEkeysetup(key, &subkeys);

    char *tmp = calloc(strlen(HEADER), sizeof( char ));
    if (!tmp)
        return ENOMEM;
    if (read(in, tmp, strlen(HEADER)) != strlen(HEADER))
        return errno;
    if (strncmp(tmp, HEADER, strcspn(HEADER, "/")))
        return EFTYPE;
    free(tmp);

    lseek(in, strlen(HEADER), SEEK_SET);
    len = read(in, &cipher, BLOCKSIZEB);
    NESSIEdecrypt(&subkeys, cipher, plain);
    memcpy(&size, plain, sizeof( size_t ));
    for (int i = 0; i < size / (BLOCKSIZEB); i++)
    {
        if ((len = read(in, cipher, BLOCKSIZEB)) != BLOCKSIZEB)
            return errno;
        NESSIEdecrypt(&subkeys, cipher, plain);
        if (write(out, plain, BLOCKSIZEB) != BLOCKSIZEB)
            return errno;
    }
    if ((len = read(in, cipher, BLOCKSIZEB)) != BLOCKSIZEB)
        return errno;
    NESSIEdecrypt(&subkeys, cipher, plain);
    if (write(out, plain, ((size * 8) % (BLOCKSIZE)) / 8) != ((size * 8) % (BLOCKSIZE)))
        return errno;
    return EXIT_SUCCESS;
}

extern uint8_t *plugin_key(uint8_t *d, size_t l)
//extern void *gen_text(void *msg, long unsigned length)
{
    uint8_t *m = calloc(l, sizeof( char ));
    if (!m)
        return NULL;
    memmove(m, d, l);
    uint32_t MDbuf[RMDsize / 32] = { 0x00000000 };
    uint32_t X[16] = { 0x00000000 };
    uint32_t b = 0;
    static uint8_t hashcode[RMDsize / 8] = { 0x00 };
    MDinit(MDbuf);
    for (b = l; b > 63; b -= 64)
    {
        for (uint8_t i = 0; i < 16; i++)
        {
            X[i] = BYTES_TO_DWORD(m);
            m += 4;
        }
        MDcompress(MDbuf, X);
    }
    MDfinish(MDbuf, m, l, 0);
    for (uint64_t i = 0; i < RMDsize / 8; i += 4)
    {
        hashcode[i] = MDbuf[i >> 2];
        hashcode[i + 1] = (MDbuf[i >> 2] >> 8);
        hashcode[i + 2] = (MDbuf[i >> 2] >> 16);
        hashcode[i + 3] = (MDbuf[i >> 2] >> 24);
    }
    m = realloc(m, RMDsize / 8);
    if (!m)
        return NULL;
    return memmove(m, hashcode, RMDsize / 8);
}
