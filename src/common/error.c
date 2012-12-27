/*
 * Common code for error handling
 * Copyright © 2009-2013, albinoloverats ~ Software Development
 * email: webmaster@albinoloverats.net
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
#include <stdarg.h>

#if !defined _WIN32 && !defined __CYGWIN__ && !defined __FreeBSD__
    #include <execinfo.h>
#endif

#include <ctype.h>
#include <string.h>

#ifndef __APPLE__
    #include "common/error.h"
    #include "common/logging.h"
#else
    #include "error.h"
    #include "logging.h"
#endif

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

extern void die(const char * const restrict s, ...)
{
    int ex = errno;
    if (s)
    {
        char *d = NULL;
        va_list ap;
        va_start(ap, s);
#ifndef _WIN32
        vasprintf(&d, s, ap);
        log_message(LOG_FATAL, "%s", d);
#else
        uint8_t l = 0xFF;
        d = calloc(l, sizeof( uint8_t ));
        if (d)
            vsnprintf(d, l - 1, s, ap);
        log_message(LOG_FATAL, d);
        if (d)
            free(d);
#endif
        va_end(ap);
    }
    if (ex)
    {
        char * const restrict e = strdup(strerror(ex));
        for (uint32_t i = 0; i < strlen(e); i++)
            e[i] = tolower(e[i]);
        log_message(LOG_FATAL, "%s", e);
        free(e);
    }
#if !defined _WIN32 && !defined __CYGWIN__ && !defined __FreeBSD__
    void *bt[BACKTRACE_BUFFER_LIMIT];
    int c = backtrace(bt, BACKTRACE_BUFFER_LIMIT);
    char **sym = backtrace_symbols(bt, c);
    if (sym)
    {
        for (int i = 0; i < c; i++)
            log_message(LOG_DEBUG, "%s", sym[i]);
        free(sym);
    }
#endif
    /*
     * TODO if running a GUI don't necessarily exit without alerting the user first
     * Users seem to dislike applications just quitting for no apparent reason!
     */
    exit(ex);
}
