/*
 * Common code which is typically missing on MS Windows
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/win32_ext.h"
#include "common/common.h"
#include "common/error.h"

char *program_invocation_short_name = NULL;

extern ssize_t pread(int filedes, void *buffer, size_t size, off_t offset)
{
    off_t o = lseek(filedes, 0, SEEK_CUR);
    lseek(filedes, offset, SEEK_SET);
    ssize_t s = read(filedes, buffer, size);
    lseek(filedes, o, SEEK_SET);
    return s;
}

extern ssize_t pwrite(int filedes, const void *buffer, size_t size, off_t offset)
{
    off_t o = lseek(filedes, 0, SEEK_CUR);
    lseek(filedes, offset, SEEK_SET);
    ssize_t s = write(filedes, buffer, size);
    lseek(filedes, o, SEEK_SET);
    return s;
}

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
        die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, size);
          
    va_start(ap, fmt);
    nchars = vsnprintf(*buffer, size, fmt, ap);
    va_end(ap);

    if (nchars >= size)
    {
        char *tmpbuff;
        size = nchars + 1;
        if (!(tmpbuff = (char *)realloc(*buffer, size)))
            die("out of memory @ %s:%d:%s [%d]", __FILE__, __LINE__, __func__, size);

        *buffer = tmpbuff;

        va_start(ap, fmt);
        nchars = vsnprintf(*buffer, size, fmt, ap);
        va_end(ap);
    }
    if (nchars < 0)
        return nchars;
    return size;
}

#endif
