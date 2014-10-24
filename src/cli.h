/*
 * encrypt ~ a simple, multi-OS encryption utility
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

#ifndef _ENCRYPT_CLI_H_
#define _ENCRYPT_CLI_H_

#include "crypt.h"

#define BPS 128

typedef struct
{
    uint64_t time;
    uint64_t bytes;
}
bps_t;

extern void cli_display(crypto_t *) __attribute__((nonnull(1)));
extern float cli_calc_bps(bps_t *) __attribute__((nonnull(1)));

#endif /* _ENCRYPT_CLI_H_ */
