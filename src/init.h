/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#ifndef _INIT_H_
#define _INIT_H_

#define TEXT_NAME "encrypt"
#define ALT_NAME "decrypt"

#define TEXT_USAGE "[-c algorithm] [-s algorithm] [-k key/-p password] [-x] [input] [output]"

#define ENCRYPTRC ".encryptrc"
#define CONF_COMPRESS "compress"

/*!
 * \brief  Structure of expected options
 *
 * Structure returned from init() with values for any expected
 * options.
 */
typedef struct args_t
{
    char *cipher;    /*!< The cryptoraphic cipher selected by the user */
    char *hash;      /*!< The hash function selected by the user */
    char *key;       /*!< The key file for key generation */
    char *password;  /*!< The password for key generation */
    char *source;    /*!< The input file/stream */
    char *output;    /*!< The output file/stream */
    bool compress:1; /*!< Compress the file (with xz) before encrypting */
}
args_t;

/*!
 * \brief         Application init function
 * \return        Any command line options that were set
 *
 * Provide simple command line argument parsing, and pass back whatever
 * options where set. Removes a lot of the cruft from the legacy common
 * code that used to exist here.
 */
extern args_t init(int argc, char **argv);

/*!
 * \brief         Show list of command line options
 *
 * Show list of command line options, and ways to invoke the application.
 * Usually when --help is given as a command line argument.
 */
extern void show_help(void) __attribute__((noreturn));

/*!
  * \brief        Show brief GPL licence text
  *
  * Display a brief overview of the GNU GPL v3 licence, such as when the
  * command line argument is --licence.
  */
extern void show_licence(void) __attribute__((noreturn));

/*!
 * \brief         Show simple usage instructions
 *
 * Display simple application usage instruction.
 */
extern void show_usage(void) __attribute__((noreturn));

/*!
 * \brief         Show application version
 *
 * Display the version of the application.
 */
extern void show_version(void) __attribute__((noreturn));

#endif /* _INIT_H_ */
