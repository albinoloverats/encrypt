/*
 *	encrypt ~ a simple, modular, (multi-OS,) encryption utility
 *	Copyright (c) 2005-2007, albinoloverats ~ Software Development
 *	email: encrypt@albinoloverats.net
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _PLUGINS_H_
#define _PLUGINS_H_

typedef struct about_info {
    /* 
     * simple data structure for information about the plugin
     */
    char *a_name;
    char *a_authors;
    char *a_copyright;
    char *a_licence;
    char *a_year;
    char *a_block;
    char *k_name;
    char *k_authors;
    char *k_copyright;
    char *k_licence;
    char *k_year;
    char *k_size;
    char *m_authors;
    char *m_copyright;
    char *m_licence;
    char *m_version;
    char *o_comment;
} about_info;

extern struct about_info info(void);
extern int enc_main(int, int, void *);
extern int dec_main(int, int, void *);
extern void *gen_file(int);
extern void *gen_text(void *, long unsigned);
extern void *key_read(int);

#ifdef _WIN32
#if BUILDING_DLL
#define extern __declspec (dllexport)
#else
#define extern __declspec (dllimport)
#endif
#endif
#endif /* _PLUGINS_H_ */
