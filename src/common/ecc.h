/*
 * Copyright © 2005-2015, albinoloverats ~ Software Development
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

#ifndef _ECC_H_
#define _ECC_H_

#include <inttypes.h>

/*
 * ecc Version 1.2 by Paul Flaherty (paulf@stanford.edu)
 * Copyright (C) 1993 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Basic Software Tool for Encoding and Decoding Files.
 *
 * This is a simple stream encoder which uses the rslib routines to
 * do something practical. It reads data from stdin in 248(encode) or
 * 256(decode) blocks, and writes the corresponding encoded/decoded
 * block onto stdout. An encoded block contains 248 data bytes, one
 * length byte, six redundancy bytes, and a capital G byte as a sync
 * marker to round it out to 256 bytes.
 */

#define ECC_CAPACITY     255
#define ECC_PAYLOAD      249
#define ECC_OFFSET      (ECC_CAPACITY - ECC_PAYLOAD)
#define ECC_BLOCK_START 0xFF

extern void ecc_encode(uint8_t m[ECC_PAYLOAD], uint8_t c[ECC_CAPACITY]);
extern void ecc_decode(uint8_t code[ECC_CAPACITY], uint8_t mesg[ECC_CAPACITY], int *errcode);

#endif /* _ECC_H_ */
