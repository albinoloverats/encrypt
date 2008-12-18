/*
 *	encrypt ~ a simple, modular, (multi-OS,) encryption utility
 *	Copyright (c) 2005-2008, albinoloverats ~ Software Development
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

  /* 
   * simple data structure for information about the plugin
   */
  typedef struct info_t
  {
      char *algorithm_name;
      char *algorithm_authors;
      char *algorithm_copyright;
      char *algorithm_licence;
      char *algorithm_year;
      char *algorithm_block;
      char *key_name;
      char *key_authors;
      char *key_copyright;
      char *key_licence;
      char *key_year;
      char *key_size;
      char *module_authors;
      char *module_copyright;
      char *module_licence;
      char *module_version;
      char *module_comment;
  } info_t;

  extern info_t  *plugin_info(void);
  extern int64_t plugin_encrypt(int64_t, int64_t, uint8_t *);
  extern int64_t plugin_decrypt(int64_t, int64_t, uint8_t *);
  extern uint8_t *plugin_key(uint8_t *, size_t);

  //extern void *gen_file(int);
  //extern void *gen_text(void *, long unsigned);
  //extern void *key_read(int);

  #ifdef _WIN32
    #if BUILDING_DLL
      #define extern __declspec (dllexport)
    #else  /*   BUILDING_DLL */
      #define extern __declspec (dllimport)
    #endif /* ! BUILDING_DLL */
  #endif /* _WIN32 */

#endif /* _PLUGINS_H_ */
