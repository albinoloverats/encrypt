/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2020, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_GUI_H_
#define _ENCRYPT_GUI_H_

#define STATUS_BAR_READY "Ready"

#define LABEL_ENCRYPT "Encrypt"
#define LABEL_DECRYPT "Decrypt"

#define SELECT_CIPHER "Select Cipher Algorithm"
#define SELECT_HASH "Select Hash Algorithm"
#define SELECT_MODE "Select Cipher Mode"
#define SELECT_MAC "Select MAC Algorithm"

extern char *gui_file_hack_source;
extern char *gui_file_hack_output;

#endif /* _ENCRYPT_GUI_H_ */
