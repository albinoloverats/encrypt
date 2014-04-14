/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_INIT_H_
#define _ENCRYPT_INIT_H_

#define APP_NAME "encrypt"
#define ALT_NAME "decrypt"

#define APP_USAGE "[source] [destination] [-c algorithm] [-s algorithm] [-m mode] [-k key/-p password] [-x] [-f] [-b version]"
#define ALT_USAGE "[-k key/-p password] [input] [output]"

#ifndef _WIN32
    #define ENCRYPTRC ".encryptrc"
#else
    #define ENCRYPTRC "etc\\_encryptrc"
#endif

#define CONF_COMPRESS "compress"
#define CONF_FOLLOW   "follow"
#define CONF_KEY      "key"
#define CONF_CIPHER   "cipher"
#define CONF_HASH     "hash"
#define CONF_MODE     "mode"
#define CONF_VERSION  "version"

#define CONF_TRUE     "true"
#define CONF_ON       "on"
#define CONF_ENABLED  "enabled"
#define CONF_FALSE    "false"
#define CONF_OFF      "off"
#define CONF_DISABLED "disabled"

/*!
 * \brief  Enum of available key sources
 *
 * Simple enum which indicates the source of the key material.
 */
typedef enum
{
    KEY_SOURCE_FILE,    /*!< Key data comes from a file */
    KEY_SOURCE_PASSWORD /*!< Key data comes from a password */
}
key_source_e;

extern char *KEY_SOURCE[];

/*!
 * \brief  Structure of expected options
 *
 * Structure returned from init() with values for any expected
 * options.
 */
typedef struct
{
    char *cipher;            /*!< The cryptoraphic cipher selected by the user */
    char *hash;              /*!< The hash function selected by the user */
    char *mode;              /*!< The encryption mode selected by the user */
    char *key;               /*!< The key file for key generation */
    char *password;          /*!< The password for key generation */
    char *source;            /*!< The input file/stream */
    char *output;            /*!< The output file/stream */
    char *version;           /*!< The container version to use */
    key_source_e key_source; /*!< The expected key source (GUI only) */
    bool compress:1;         /*!< Compress the file (with xz) before encrypting */
    bool follow:1;           /*!< Follow symlinks or not */
    bool nogui:1;            /*!< Skip the GUI (if it's available) */
}
args_t;

/*!
 * \brief           Application init function
 * \param[in]  argc Number of command line arguments
 * \param[out] argv Command line arguments
 * \return          Any command line options that were set
 *
 * Provide simple command line argument parsing, and pass back whatever
 * options where set. Removes a lot of the cruft from the legacy common
 * code that used to exist here.
 */
extern args_t init(int argc, char **argv);

extern void init_deinit(args_t args);

/*!
 * \brief         Update configuration file
 * \param[in]  o  Option to update
 * \param[out] v  New value
 *
 * Set or update the given configuration option with the given value.
 */
extern void update_config(const char * const restrict o, const char * const restrict v) __attribute__((nonnull(1, 2)));

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

#endif /* ! _INIT_H_ */
