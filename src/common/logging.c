/*
 * Common code for logging messages
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#ifndef __APPLE__
    #include "common/common.h"
    #include "common/logging.h"
#else
    #include "common.h"
    #include "logging.h"
#endif

#ifdef _WIN32
    #include "common/win32_ext.h"
    extern char *program_invocation_short_name;
#endif

/*@null@*/static FILE *log_destination = NULL;
static log_e log_current_level = LOG_DEFAULT;

static const char *LOG_LEVELS[] =
{
    "EVERYTHING",
    "VERBOSE",
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "FATAL"
};

extern void log_redirect(const char * const restrict f)
{
    if (f)
        log_destination = fopen(f, "a");
}

extern log_e log_parse_level(const char * const restrict l)
{
    for (uint8_t i = 0; i < LOG_LEVEL_COUNT; i++)
        if (!strcasecmp(l, LOG_LEVELS[i]))
            return (log_e)i;
    return LOG_DEFAULT;
}

extern void log_relevel(log_e l)
{
    if (l < LOG_EVERYTHING)
        l = LOG_EVERYTHING;
    else if (l > LOG_FATAL)
        l = LOG_FATAL;
    log_current_level = l;
}

extern void log_binary(log_e l, const void * const restrict v, uint64_t s)
{
    if (s < 1)
        return;
    const uint8_t * const z = v;
    char b[LOG_BINARY_LINE_WIDTH] = { 0x00 };
    uint8_t c = 1;
    for (uint64_t i = 0; i < s; i++, c++)
    {
        if (c > LOG_BINARY_LINE_WRAP)
        {
            c = 1;
            log_message(l, "%s", b);
            memset(b, 0x00, sizeof b);
        }
        sprintf(b, "%s%02X%s", b, z[i], (c % sizeof( uint32_t )) ? "" : " ");
    }
    log_message(l, "%s", b);
}

extern void log_message(log_e l, const char * const restrict s, ...)
{
    if (!s)
    {
        /*
         * NULL value for s causes error message based on errno to be
         * displayed at log level error
         */
        if (errno)
        {
            char * const restrict e = strdup(strerror(errno));
            for (uint32_t i = 0; i < strlen(e); i++)
                e[i] = tolower(e[i]);
            log_message(LOG_ERROR, "%s", e);
            free(e);
        }
        return;
    }
    if (l < log_current_level)
        return;
    va_list ap;
    va_start(ap, s);
    FILE *f = log_destination ? : stderr;
    flockfile(f);
    if (f == stderr)
        fprintf(f, "\r%s: ", program_invocation_short_name);
    char dtm[20];
    time_t tm = time(NULL);
    strftime(dtm, sizeof dtm, "%Y-%m-%d %T", localtime(&tm));
    fprintf(f, "[%s] (%d) [%s] ", dtm, getpid(), l < LOG_LEVEL_COUNT ? LOG_LEVELS[l] : "(unknown)");
    vfprintf(f, s, ap);
    fprintf(f, "\n");
    fflush(f);
    funlockfile(f);
    va_end(ap);
    return;
}
