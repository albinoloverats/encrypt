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
  #define VERSION "200905-"

  #define TEXT_HELP \
    "If -i or -o are omitted then stdin/stdout are used.  Either -e or -d must be\n" \
    "present if you intend to do something, as well as -k -f or -p. Using -g will\n" \
    "generate a random key and echo it to stdout unless -g is preceded by -k; the\n" \
    "key can be used later with the -k option. However -a -m -h -l -v may be used\n" \
    "on their own or not at all.\n"



  enum key { KEYFILE = 1, PASSFILE, PASSWORD };
  enum func { ENCRYPT = 1, DECRYPT };

  void *open_mod(char *);
  int64_t algorithm_info(char *);
  int64_t list_modules(void);

  int64_t  key_generate(char *, char *);
  uint8_t *key_calculate(void *, char *, uint8_t);

#endif /* _ENCRYPT_H_ */
