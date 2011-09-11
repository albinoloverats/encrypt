/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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

#ifndef _MAIN_H_
#define _MAIN_H_

#include "common/common.h"
#include "common/list.h"

#define USAGE_STRING "[-c algorithm] [-s algorithm] [-k/-p password source] [source file] [destination file]"

#define ui_thread_initialise1(A) ui_thread_initialise2(A, NULL)
#define ui_thread_initialise(...) COMMON_CONCAT(ui_thread_initialise, COMMON_ARGS_COUNT(__VA_ARGS__))(__VA_ARGS__)

extern pthread_t ui_thread_initialise2(void *(fn)(void *), void *n);

#endif /* _MAIN_H_ */
