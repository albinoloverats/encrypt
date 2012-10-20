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

#include <windows.h>

#ifndef _WIN32_EXT_H_
#define _WIN32_EXT_H_

#include <sys/stat.h>
#include <stdio.h>

#ifndef vsnprintf
    #define vsnprintf _vsnprintf
#endif

#define fsync(fd) _commit(fd)
#define ftruncate(fd, sz) _chsize(fd, sz)

extern int asprintf(char **buffer, char *fmt, ...);

extern ssize_t getline(char **lineptr, size_t *n, FILE *stream);

#endif /* _WIN32_EXT_H_ */

#endif
