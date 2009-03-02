/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2009, albinoloverats ~ Software Development
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

  #define NAME "encrypt"
  #define VERSION "200903-"

  enum key { KEYFILE = 1, PASSFILE, PASSWORD };
  enum func { ENCRYPT = 1, DECRYPT };

  void *open_mod(char *);
  int64_t algorithm_info(char *);
  int64_t list_modules(void);

  int64_t  key_generate(char *, char *);
  uint8_t *key_calculate(void *, char *, uint8_t);

  int64_t show_help(void);

#endif /* _ENCRYPT_H_ */
