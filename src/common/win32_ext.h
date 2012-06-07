/*
 * Common code which is typically missing on MS Windows
 * Copyright (c) 2005-2012, albinoloverats ~ Software Development
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

#ifndef _WIN32_EXT_H_
#define _WIN32_EXT_H_

#include <sys/stat.h>

#ifndef vsnprintf
    #define vsnprintf _vsnprintf
#endif

#define fsync(fd) _commit(fd)

extern ssize_t pread(int filedes, void *buffer, size_t size, off_t offset);

extern ssize_t pwrite(int filedes, const void *buffer, size_t size, off_t offset);

extern int asprintf(char **buffer, char *fmt, ...);

#endif /* _WIN32_EXT_H_ */

#endif
