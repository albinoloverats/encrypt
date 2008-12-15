/*
 *	encrypt ~ a simple, modular, (multi-OS,) encryption utility
 *	Copyright (c) 2005-2007, albinoloverats ~ Software Development
 *	email: encrypt@albinoloverats.net
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

#include "plugins.h"

#define A_NAME "Hello World Example - Boo!" /* algorithm name - duh */
#define A_AUTHORS "albinoloverats ~ Software Development"   /* algorithm
                                                             * authors - who
                                                             * wrote/designed 
                                                             * it */
#define A_COPYRIGHT "Copyright (c) 2004-2007, albinoloverats.net"   /* algorithm 
                                                                     * copyright 
                                                                     * - who
                                                                     * owns
                                                                     * it
                                                                     * (usually 
                                                                     * the
                                                                     * authors) 
                                                                     */
#define A_LICNECE "GPL"         /* algorithm licence */
#define A_YEAR "2007"           /* algorithm year - when was it introduced */
#define A_BLOCK "N/A"           /* algorithm block size */
#define K_NAME "N/A"            /* key name */
#define K_AUTHORS "albinoloverats ~ Software Development"   /* key authors */
#define K_COPYRIGHT "Copyright (c) 2004-2007, albinoloverats.net"   /* key
                                                                     * copyright 
                                                                     */
#define K_LICENCE "GPL"         /* key licence */
#define K_YEAR "2007"           /* key year */
#define K_SIZE "N/A"            /* key size */
#define M_AUTHORS "albinoloverats ~ Software Development"   /* module authors 
                                                             * - who coded
                                                             * the module */
#define M_COPYRIGHT "Copyright (c) 2004-2007, albinoloverats.net"   /* module 
                                                                     * copyright 
                                                                     * - who
                                                                     * owns
                                                                     * it
                                                                     * (again, 
                                                                     * usually 
                                                                     * the
                                                                     * authors) 
                                                                     */
#define M_LICENCE "GPL"         /* module licence */
#define M_VERSION "2.0"         /* module version */
#define O_COMMENT "Use this as a template for building plugins;\ngiving everybody a variety of algorithms to use :-)"   /* comments 
                                                                                                                         */

extern struct about_info about(void) {
    /* 
     * this function returns some basic information about this plugin
     */
    struct about_info hello;

    hello.a_name = strdup(A_NAME);
    hello.a_authors = strdup(A_AUTHORS);
    hello.a_copyright = strdup(A_COPYRIGHT);
    hello.a_licence = strdup(A_LICNECE);
    hello.a_year = strdup(A_YEAR);
    hello.a_block = strdup(A_BLOCK);
    hello.k_name = strdup(K_NAME);
    hello.k_authors = strdup(K_AUTHORS);
    hello.k_copyright = strdup(K_COPYRIGHT);
    hello.k_licence = strdup(K_LICENCE);
    hello.k_year = strdup(K_YEAR);
    hello.k_size = strdup(K_SIZE);
    hello.m_authors = strdup(M_AUTHORS);
    hello.m_copyright = strdup(M_COPYRIGHT);
    hello.m_licence = strdup(M_LICENCE);
    hello.m_version = strdup(M_VERSION);
    hello.o_comment = strdup(O_COMMENT);
    return hello;
}

extern int enc_main(int in, int out, void *key) {
    /* 
     * the encryption function
     */
    char *data = NULL;
    key = NULL;
    ssize_t len = 0;
    size_t size = 64;

    if ((data = malloc(size)) == NULL)
        return errno;
    while ((len = read(in, data, size)) > 0)
        write(out, data, len);
    if (len != 0)
        return errno;
    free(data);
    return EXIT_SUCCESS;
}

extern int dec_main(int in, int out, void *key) {
    /* 
     * this would be the decryption function, but as this doesn't do anything it just calls the encryption function
     */
    return enc_main(in, out, key);
}

extern void *gen_file(int file) {
    /* 
     * here we read data from the file to help us generate a key
     */
    void *data = NULL;
    size_t size = (off_t) lseek(file, 0, SEEK_END);

    lseek(file, 0, SEEK_SET);
    if ((data = malloc(size)) == NULL)
        return NULL;
    read(file, data, size);
    return gen_text(data, (long unsigned) size);
}

extern void *gen_text(void *data, long unsigned size) {
    /* 
     * this function uses the data given to generate the key - not necessarily called from above
     */
    size = 0;
    return data;
}

extern void *key_read(int file) {
    /* 
     * this function differs from above: it reads an already generated key from a file - no processing, etc
     */
    void *data = NULL;

    if ((data = malloc(8)) == NULL)
        return NULL;
    read(file, data, 8);
    return data;
}
