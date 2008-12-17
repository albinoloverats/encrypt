/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2008, albinoloverats ~ Software Development
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

  #define AUTHOR "albinoloverats ~ Software Development"
  #define LICENCE "GPL"
  #define NAME "encrypt"

  //#ifndef VERSION
  //#define VERSION "TBA"
  //#endif

  #define NOTSET 0

  enum key { KEYFILE = 1, PASSFILE, PASSWORD };
  enum func { ENCRYPT = 1, DECRYPT };

  int main(int, char **);
  void die(const char *, ...);

  void *open_mod(char *);
  int64_t algorithm_info(char *);
  int64_t list_modules(void);

  int64_t  key_generate(char *, char *);
  uint8_t *key_calculate(void *, char *, uint8_t);

  int64_t show_help(void);
  int64_t show_licence(void);
  int64_t show_usage(void);
  int64_t show_version(void);

  #ifdef _WIN32
    #define srand48 srand
    #define lrand48 rand
    #define _BUILD_GUI_ 1
    #define F_RDLCK 0
    #define F_WRLCK 0
  #else  /*   _WIN32 */
    #define O_BINARY 0
  #endif /* ! _WIN32 */

#endif /* _ENCRYPT_H_ */
