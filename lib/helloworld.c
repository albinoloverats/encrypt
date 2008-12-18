/*
 *	encrypt ~ a simple, modular, (multi-OS,) encryption utility
 *	Copyright (c) 2005-2008, albinoloverats ~ Software Development
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
#include <inttypes.h>

#ifdef _WIN32
  #include <windows.h>
#endif /* _WIN32 */

#include "plugins.h"

#define A_NAME      "Hello World Example - Boo!"                  /* algorithm name - duh */
#define A_AUTHORS   "albinoloverats ~ Software Development"       /* algorithm authors - who wrote/designed it */
#define A_COPYRIGHT "Copyright (c) 2004-2008, albinoloverats.net" /* algorithm copyright - who owns it (usually the authors) */
#define A_LICNECE   "GPL"                                         /* algorithm licence */
#define A_YEAR      "2007"                                        /* algorithm year - when was it introduced */
#define A_BLOCK     "N/A"                                         /* algorithm block size */
#define K_NAME      "N/A"                                         /* key name */
#define K_AUTHORS   "albinoloverats ~ Software Development"       /* key authors */
#define K_COPYRIGHT "Copyright (c) 2004-2008, albinoloverats.net" /* key copyright */
#define K_LICENCE   "GPL"                                         /* key licence */
#define K_YEAR      "2007"                                        /* key year */
#define K_SIZE      "N/A"                                         /* key size */
#define M_AUTHORS   "albinoloverats ~ Software Development"       /* module authors - who coded the module */
#define M_COPYRIGHT "Copyright (c) 2004-2008, albinoloverats.net" /* module copyright - who owns it (again, usually the authors) */
#define M_LICENCE   "GPL"                                         /* module licence */
#define M_VERSION   "3.0"                                         /* module version */
#define M_COMMENT   "Use this as a template for building plugins;\ngiving everybody a variety of algorithms to use :-)"

extern info_t *plugin_info(void) {
    /* 
     * this function returns some basic information about this plugin
     */
    info_t *hello = calloc(1, sizeof( info_t ));;
    if (!hello)
        return NULL;
    hello->algorithm_name      = strdup(A_NAME);
    hello->algorithm_authors   = strdup(A_AUTHORS);
    hello->algorithm_copyright = strdup(A_COPYRIGHT);
    hello->algorithm_licence   = strdup(A_LICNECE);
    hello->algorithm_year      = strdup(A_YEAR);
    hello->algorithm_block     = strdup(A_BLOCK);
    hello->key_name            = strdup(K_NAME);
    hello->key_authors         = strdup(K_AUTHORS);
    hello->key_copyright       = strdup(K_COPYRIGHT);
    hello->key_licence         = strdup(K_LICENCE);
    hello->key_year            = strdup(K_YEAR);
    hello->key_size            = strdup(K_SIZE);
    hello->module_authors      = strdup(M_AUTHORS);
    hello->module_copyright    = strdup(M_COPYRIGHT);
    hello->module_licence      = strdup(M_LICENCE);
    hello->module_version      = strdup(M_VERSION);
    hello->module_comment      = strdup(M_COMMENT);
    return hello;
}

extern int64_t plugin_encrypt(int64_t file_in, int64_t file_out, uint8_t *key)
{
    /* 
     * the encryption function
     */
    uint8_t data[0xFF];
    ssize_t len = 0;
    key = key; // lib/helloworld.c:78: warning: unused parameter 'key'

    while ((len = read(file_in, data, sizeof( data ))) > 0)
        write(file_out, data, len);
    if (len != 0)
        return errno;

    return EXIT_SUCCESS;
}

extern int64_t plugin_decrypt(int64_t file_in, int64_t file_out, uint8_t *key)
{
    /* 
     * this would be the decryption function, but as this doesn't do anything it just calls the encryption function
     */
    return plugin_encrypt(file_in, file_out, key);
}

extern uint8_t *plugin_key(uint8_t *d, size_t l)
{
    /* 
     * this function uses the data given to generate the key
     */
    d = d;
    return calloc(l, sizeof( uint8_t));
}
