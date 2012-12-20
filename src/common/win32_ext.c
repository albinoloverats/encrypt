/*
 * Common code which is typically missing on MS Windows
 * Copyright Â© 2005-2012, albinoloverats ~ Software Development
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

#ifdef _WIN32

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <dirent.h>

#include "common/win32_ext.h"
#include "common/common.h"
#include "common/error.h"

char *program_invocation_short_name = NULL;

/*
 * Copyright (C) 2001 Federico Di Gregorio <fog@debian.org> 
 * Copyright (C) 1991, 1994-1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This code has been derived from an example in the glibc2 documentation.
 * This file is part of the psycopg module.
 */
extern int asprintf(char **buffer, char *fmt, ...)
{
    /* guess we need no more than 200 chars of space */
    int size = 200;
    int nchars;
    va_list ap;
    
    if (!(*buffer = (char *)malloc(size)))
        die(_("Out of memory @ %s:%d:%s [%d]"), __FILE__, __LINE__, __func__, size);
          
    va_start(ap, fmt);
    nchars = vsnprintf(*buffer, size, fmt, ap);
    va_end(ap);

    if (nchars >= size)
    {
        char *tmpbuff;
        size = nchars + 1;
        if (!(tmpbuff = (char *)realloc(*buffer, size)))
            die(_("Out of memory @ %s:%d:%s [%d]"), __FILE__, __LINE__, __func__, size);

        *buffer = tmpbuff;

        va_start(ap, fmt);
        nchars = vsnprintf(*buffer, size, fmt, ap);
        va_end(ap);
    }
    if (nchars < 0)
        return nchars;
    return size;
}

extern ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    bool e = false;
    size_t r = 0;
    uint32_t step = 0xFF;
    char *buffer = malloc(step);
    if (!buffer)
        die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, step);
    for (r = 0; ; r++)
    {
        int c = fgetc(stream);
        if (c == EOF)
        {
            e = true;
            break;
        }
        buffer[r] = c;
        if (c == '\n')
            break;
        if (r >= step - 0x10)
        {
            step += 0xFF;
            if (!(buffer = realloc(buffer, step)))
                die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, step);
        }
    }
    buffer[r + 1] = 0x00;
    if (*lineptr)
        free(*lineptr);
    *lineptr = buffer;
    *n = r;
    return e ? -1 : r;
}

/*
 * This code has been lifted from musl, and is available under the MIT License.
 * Copyright © 2005-2012 Rich Felker
 *   See: http://www.musl-libc.org/
 */
extern int scandir(const char *path, struct dirent ***res, int (*sel)(const struct dirent *), int (*cmp)(const struct dirent **, const struct dirent **))
{
    DIR *d = opendir(path);
    struct dirent *de, **names = 0, **tmp;
    size_t cnt = 0, len = 0;
    int old_errno = errno;

    if (!d)
        return -1;

    while ((errno = 0), (de = readdir(d)))
    {
        if (sel && !sel(de))
            continue;

        if (cnt >= len)
        {
            len = 2 * len + 1;
            if (len > SIZE_MAX / sizeof *names)
                break;

            if (!(tmp = realloc(names, len * sizeof *names)))
                die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, len * sizeof *names);
            names = tmp;
        }

        if (!(names[cnt] = malloc(sizeof( struct dirent ))))
            die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, sizeof *names);

        memcpy(names[cnt++], de, sizeof( struct dirent ));
    }

    closedir(d);

    if (errno)
    {
        if (names)
            while (cnt-- > 0)
                free(names[cnt]);
        free(names);
        return -1;
    }
    errno = old_errno;

    if (cmp)
        qsort(names, cnt, sizeof *names, (int (*)(const void *, const void *))cmp);

    *res = names;
    return cnt;
}

#endif
