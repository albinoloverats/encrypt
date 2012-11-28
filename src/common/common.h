/*
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

#ifndef _COMMON_H_
#define _COMMON_H_

/*!
 * \file    common.h
 * \author  albinoloverats ~ Software Development
 * \date    2009-2012
 * \brief   Mostly common macros, useful when dealing with different OS's
 *
 * Various macros which help with the transition from one OS to another.
 * There were originlly part of the main common library until it was
 * torn apart to reduce complexity.
 */

#define NOTSET 0 /*!< Value to use when nothing else is available */

#ifndef O_BINARY
    #define O_BINARY NOTSET /*!< Value is only relevant on MS systems (and is required), pretend it exists elsewhere */
#endif

#if defined __APPLE__ || defined __FreeBSD__
    #define program_invocation_short_name getprogname() /*!< This is the best/closest we have */
    #undef F_RDLCK         /*!< Undefine value on Mac OS X as it causes runtime issues */
    #define F_RDLCK NOTSET /*!< Set value to NOTSET */
    #undef F_WRLCK         /*!< Undefine value on Mac OS X as it causes runtime issues */
    #define F_WRLCK NOTSET /*!< Set value to NOTSET */
#endif

#ifdef __FreeBSD__
    #define S_IRUSR NOTSET
    #define S_IWUSR NOTSET
#endif

#ifndef __bswap_64
    #define __bswap_64(x) /*!< Define ourselves a 8-byte swap macro */ \
        ((((x) & 0xff00000000000000ull) >> 56) \
       | (((x) & 0x00ff000000000000ull) >> 40) \
       | (((x) & 0x0000ff0000000000ull) >> 24) \
       | (((x) & 0x000000ff00000000ull) >> 8)  \
       | (((x) & 0x00000000ff000000ull) << 8)  \
       | (((x) & 0x0000000000ff0000ull) << 24) \
       | (((x) & 0x000000000000ff00ull) << 40) \
       | (((x) & 0x00000000000000ffull) << 56))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN && !defined __APPLE__ && !defined __FreeBSD__
    #define ntohll(x) (x) /*!< No need to swap bytes from network byte order */
    #define htonll(x) (x) /*!< No need to swap bytes to network byte order */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    #define ntohll(x) __bswap_64(x) /*!< Do need to swap bytes (mostly on Mac OS X) */
    #define htonll(x) __bswap_64(x) /*!< Do need to swap bytes (mostly on Mac OS X) */
#endif

#if !defined _WIN32 && !defined __CYGWIN__ && !defined __APPLE__
    #include <libintl.h>
    #define _(s) gettext(s) /*!< Allow use of _() to refer to gettext() */
#else
    #define _(s) s /*!< Don't yet support translations on MS Windows */
#endif

#define CONCAT(A, B) CONCAT2(A, B) /*!< Function overloading argument concatination (part 1) */
#define CONCAT2(A, B) A ## B       /*!< Function overloading argument concatination (part 2) */

#define ARGS_COUNT(...) ARGS_COUNT2(__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1) /*!< Function overloading argument count (part 1) */
#define ARGS_COUNT2(_1, _2, _3, _4, _5, _6, _7, _, ...) _             /*!< Function overloading argument count (part 2) */

/*! Brief overview of the GNU General Public License (version 3) */
#define TEXT_LICENCE \
    "This program is free software: you can redistribute it and/or modify\n"  \
    "it under the terms of the GNU General Public License as published by\n"  \
    "the Free Software Foundation, either version 3 of the License, or\n"     \
    "(at your option) any later version.\n\n"                                 \
    "This program is distributed in the hope that it will be useful,\n"       \
    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"        \
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"         \
    "GNU General Public License for more details.\n\n"                        \
    "You should have received a copy of the GNU General Public License\n"     \
    "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"

#define ONE_MILLION 1000000 /*!< Integer value for 1 million */
#define TEN_MILLION 10000000 /*!< Integer value for 10 million */

#define RANDOM_SEED_SIZE 3 /*!< Size of random seed value in bytes */

#endif /* _COMMON_H_ */
