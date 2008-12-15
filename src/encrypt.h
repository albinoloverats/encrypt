/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2007, albinoloverats ~ Software Development
 * email: encrypt@albinoloverats.net
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

#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define AUTHOR "albinoloverats ~ Software Development"
#define LICENCE "GPL"
#define NAME "encrypt"
/*
 * version number now comes from SVN revision
 */
#ifndef VERSION
#define VERSION "TBA"
#endif

int main(int, char **);
int algorithm_info(char *);
int generate_key(char *, char *);
void list_modules(void);
int option_error(char *);
void show_help(void);
void show_licence(void);
void show_usage(void);
void show_version(void);

#ifdef _WIN32
#define dlerror() ""
#define _BUILD_GUI_ 1
#define F_RDLCK 0
#define F_WRLCK 0
#endif

#ifndef _WIN32
#define O_BINARY 0
#endif

#endif /* _ENCRYPT_H_ */
