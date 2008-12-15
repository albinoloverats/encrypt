/*
 *	xtea is a plugin for encrypt
 *	Copyright (c) 2007-2008, Ashley Anderson
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
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "md5.h"
#include "plugins.h"

#define A_NAME "eXtended Tiny Encryption Algorithm"
#define A_AUTHORS "Roger Needham and David Wheeler"
#define A_COPYRIGHT "Copyright (c) 1997, R Needham and D Wheeler"
#define A_LICNECE "Public Domain"
#define A_YEAR "1997"
#define A_BLOCK "64 bits"
#define K_NAME "MD5"
#define K_AUTHORS "Ronald Rivest (Code by Aladdin Enterprises)"
#define K_COPYRIGHT "Copyright (c) 1999, 2000, 2002 Aladdin Enterprises"
#define K_LICENCE "Public Domain - RFC1321 (GPL)"
#define K_YEAR "1992"
#define K_SIZE "128 bits"
#define M_AUTHORS "Ashley Anderson"
#define M_COPYRIGHT "Copyright (c) 2007-2008, Ashley Anderson"
#define M_VERSION "3.0"
#define M_LICENCE "GPL"
#define O_COMMENT "The XTEA algorithm was originally designed to correct a\n  weaknesses in TEA.  This implementation uses a free MD5\n  library, which is based on RFC1321, and as such is RSA-\n  free. From: http://sourceforge.net/projects/libmd5-rfc/"

#define BYTE    8
#define CYCLES  64
#define DATA    2 * sizeof (uint32_t)
#define DELTA   0x9E3779B9
#define KEY     128
#define BLOCK   64

#define HEADER "XTEA\2553.0\255"

void hex2bin(uint32_t *, char *);

extern struct about_info about(void) {
    struct about_info xtea;

    xtea.a_name = strdup(A_NAME);
    xtea.a_authors = strdup(A_AUTHORS);
    xtea.a_copyright = strdup(A_COPYRIGHT);
    xtea.a_licence = strdup(A_LICNECE);
    xtea.a_year = strdup(A_YEAR);
    xtea.a_block = strdup(A_BLOCK);
    xtea.k_name = strdup(K_NAME);
    xtea.k_authors = strdup(K_AUTHORS);
    xtea.k_copyright = strdup(K_COPYRIGHT);
    xtea.k_licence = strdup(K_LICENCE);
    xtea.k_year = strdup(K_YEAR);
    xtea.k_size = strdup(K_SIZE);
    xtea.m_authors = strdup(M_AUTHORS);
    xtea.m_copyright = strdup(M_COPYRIGHT);
    xtea.m_version = strdup(M_VERSION);
    xtea.m_licence = strdup(M_LICENCE);
    xtea.o_comment = strdup(O_COMMENT);
    return xtea;
}

extern int enc_main(int in, int out, void *key) {
    uint32_t *data = NULL, *k = NULL;
    uint32_t v0 = 0, v1 = 0, sum = 0;
    ssize_t len = 0, size = 0;
    errno = 0;
    if ((data = calloc(1, DATA)) == NULL)
        return errno;
    if ((k = calloc(2, DATA)) == NULL)
        return errno;
    hex2bin(k, key);
    /*
     * write header
     */
    size = lseek(in, 0, SEEK_END);
    write(out, HEADER, strlen(HEADER));
    memcpy(data, &size, sizeof (ssize_t));
    v0 = data[0];
    v1 = data[1];
    for (uint32_t i = 0; i < CYCLES; i++) {
        v0  += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += DELTA;
        v1  += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    data[0] = v0;
    data[1] = v1;
    write(out, data, DATA);
    /*
     * main loop
     */
    size = lseek(in, 0, SEEK_SET);
    while ((len = read(in, data, DATA)) > 0) {
        if (len == DATA) {
            v0 = data[0];
            v1 = data[1];
            sum = 0;
            for (uint32_t i = 0; i < CYCLES; i++) {
                v0  += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
                sum += DELTA;
                v1  += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
            }
            data[0] = v0;
            data[1] = v1;
        }
        write(out, data, len);
    }
    /*
     * done
     */
    if (len != 0)
        return errno;
    free(data);
    free(k);
    return EXIT_SUCCESS;
}

extern int dec_main(int in, int out, void *key) {
    uint32_t *data = NULL, *k = NULL;
    uint32_t v0 = 0, v1 = 0, sum = 0;
    ssize_t len = 0, size = 0;
    errno = 0;
    if ((data = calloc(1, DATA)) == NULL)
        return errno;
    if ((k = calloc(2, DATA)) == NULL)
        return errno;
    hex2bin(k, key);
    /*
     * skip past header
     */
    lseek(in, strlen(HEADER), SEEK_SET);
    len = read(in, &data, DATA);
    v0 = data[0], v1 = data[1];
    sum = DELTA * CYCLES;
    for (uint32_t i = 0; i < CYCLES; i++) {
        v1  -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= DELTA;
        v0  -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    data[0] = v0;
    data[1] = v1;
    memcpy(&size, data, sizeof (size_t));
    /*
     * main loop
     */
    for (int i = 0; i < size / (BLOCK / BYTE); i++) {
        if ((len = read(in, data, DATA)) != DATA)
            return errno;
    //while ((len = read(in, data, DATA)) > 0) {
        if (len == DATA) {
            v0 = data[0], v1 = data[1];
            sum = DELTA * CYCLES;
            for (uint32_t i = 0; i < CYCLES; i++) {
                v1  -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
                sum -= DELTA;
                v0  -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
            }
            data[0] = v0;
            data[1] = v1;
        }
        write(out, data, len);
    }
    /*
     * write final block
     */
    if ((len = read(in, data, DATA)) != DATA)
        return errno;
    v0 = data[0], v1 = data[1];
    sum = DELTA * CYCLES;
    for (uint32_t i = 0; i < CYCLES; i++) {
        v1  -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= DELTA;
        v0  -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    data[0] = v0;
    data[1] = v1;
    write(out, data, ((size * BYTE) % (BLOCK)) / BYTE);
    /*
     * done
     */
    if (len != 0)
        return errno;
    free(data);
    free(k);
    return EXIT_SUCCESS;
}

extern void *gen_file(int file) {
    char *data = NULL;
    size_t size = (off_t)lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    if ((data = malloc(size)) == NULL)
        return NULL;
    read(file, data, size);
    return gen_text(data, (uint32_t)size);
}

extern void *gen_text(void *data, long unsigned size) {
    md5_state_t state;
    md5_byte_t *digest;
    if ((digest = malloc(KEY / 8)) == NULL)
        return NULL;
    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)data, size);
    md5_finish(&state, digest);
    return digest;
}

extern void *key_read(int file) {
    char data[2];
    md5_byte_t *key;
    size_t size = (off_t)lseek(file, 0, SEEK_END);

    if (size < KEY / 8)
        return NULL;
    lseek(file, 0, SEEK_SET);
    if ((key = malloc(KEY / 8)) == NULL)
        return NULL;
    int i;

    for (i = 0; i < KEY / 8; i++) {
        read(file, &data, 2 * sizeof (char));
        key[i] = strtol(data, NULL, 16);
    }
    return key;
}

void hex2bin(uint32_t *k, char *c) {
    k[0] = ((c[ 0] & 0xFF) << 24) | ((c[ 1] & 0xFF) << 16) | ((c[ 2] & 0xFF) << 8) | (c[ 3] & 0xFF);
    k[1] = ((c[ 4] & 0xFF) << 24) | ((c[ 5] & 0xFF) << 16) | ((c[ 6] & 0xFF) << 8) | (c[ 7] & 0xFF);
    k[2] = ((c[ 8] & 0xFF) << 24) | ((c[ 9] & 0xFF) << 16) | ((c[10] & 0xFF) << 8) | (c[11] & 0xFF);
    k[3] = ((c[12] & 0xFF) << 24) | ((c[13] & 0xFF) << 16) | ((c[14] & 0xFF) << 8) | (c[15] & 0xFF);
}
