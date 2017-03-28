/*
 * Common code for ECC calculations
 * Copyright © 2005-2017, albinoloverats ~ Software Development
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

/*
 * ecc Version 1.2 by Paul Flaherty (paulf@stanford.edu)
 * Copyright (C) 1993 Free Software Foundation, Inc.
 *
 * Basic Software Tool for Encoding and Decoding Files.
 *
 * This is a simple stream encoder. It takes a buffer of data 249 bytes
 * (encode) - or 255 bytes (decode) - and copies the corresponding
 * encoded/decoded block to the output buffer. An encoded block contains
 * 249 data bytes and 6 redundancy bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "ecc.h"


/* Multiply two field elements */
#define GF_MUL(A, B) ((A) == 0 || (B) == 0 ? 0 : e2v[(v2e[A] + v2e[B]) % ECC_CAPACITY])
/* Add two field elements. Subtraction and addition are equivalent */
#define GF_ADD(A, B) ((A) ^ (B))
/* Invert a field element, for division */
#define GF_INV(A) (e2v[ECC_CAPACITY - v2e[A]])
/* Exponentiation. Convert to exponential notation, mod ECC_CAPACITY */
#define GF_EXP(A, B) ((A) == 0 ? 0 : e2v[(v2e[A] * (B)) % ECC_CAPACITY])

#define REVERSE(A, L)                                                   \
	for (int i = 0, j = (L) - 1; i < (L) / 2; i++, j--)             \
	{                                                               \
		A[i] ^= A[j];                                           \
		A[j] ^= A[i];                                           \
		A[i] ^= A[j];                                           \
	}


static const uint8_t g[ECC_OFFSET] = { 0x75, 0x31, 0x3A, 0x9E, 0x04, 0x7E };

static const uint8_t e2v[ECC_CAPACITY + 1] =
{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74, 0xE8, 0xCD, 0x87, 0x13, 0x26,
	0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75, 0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0,
	0x9D, 0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77, 0xEE, 0xC1, 0x9F, 0x23,
	0x46, 0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1,
	0x5F, 0xBE, 0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E, 0x3C, 0x78, 0xF0,
	0xFD, 0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F, 0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2,
	0xD9, 0xAF, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD, 0x67, 0xCE,
	0x81, 0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B, 0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC,
	0x85, 0x17, 0x2E, 0x5C, 0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A, 0x54,
	0xA8, 0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92, 0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73,
	0xE6, 0xD1, 0xBF, 0x63, 0xC6, 0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF,
	0xE3, 0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E, 0xDC, 0xA5, 0x57, 0xAE, 0x41,
	0x82, 0x19, 0x32, 0x64, 0xC8, 0x8D, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6,
	0x51, 0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56, 0xAC, 0x45, 0x8A, 0x09,
	0x12, 0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4, 0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16,
	0x2C, 0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E, 0x01
};

static const uint8_t v2e[ECC_CAPACITY + 1] =
{
	0xFF, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1A, 0xC6, 0x03, 0xDF, 0x33, 0xEE, 0x1B, 0x68, 0xC7, 0x4B,
	0x04, 0x64, 0xE0, 0x0E, 0x34, 0x8D, 0xEF, 0x81, 0x1C, 0xC1, 0x69, 0xF8, 0xC8, 0x08, 0x4C, 0x71,
	0x05, 0x8A, 0x65, 0x2F, 0xE1, 0x24, 0x0F, 0x21, 0x35, 0x93, 0x8E, 0xDA, 0xF0, 0x12, 0x82, 0x45,
	0x1D, 0xB5, 0xC2, 0x7D, 0x6A, 0x27, 0xF9, 0xB9, 0xC9, 0x9A, 0x09, 0x78, 0x4D, 0xE4, 0x72, 0xA6,
	0x06, 0xBF, 0x8B, 0x62, 0x66, 0xDD, 0x30, 0xFD, 0xE2, 0x98, 0x25, 0xB3, 0x10, 0x91, 0x22, 0x88,
	0x36, 0xD0, 0x94, 0xCE, 0x8F, 0x96, 0xDB, 0xBD, 0xF1, 0xD2, 0x13, 0x5C, 0x83, 0x38, 0x46, 0x40,
	0x1E, 0x42, 0xB6, 0xA3, 0xC3, 0x48, 0x7E, 0x6E, 0x6B, 0x3A, 0x28, 0x54, 0xFA, 0x85, 0xBA, 0x3D,
	0xCA, 0x5E, 0x9B, 0x9F, 0x0A, 0x15, 0x79, 0x2B, 0x4E, 0xD4, 0xE5, 0xAC, 0x73, 0xF3, 0xA7, 0x57,
	0x07, 0x70, 0xC0, 0xF7, 0x8C, 0x80, 0x63, 0x0D, 0x67, 0x4A, 0xDE, 0xED, 0x31, 0xC5, 0xFE, 0x18,
	0xE3, 0xA5, 0x99, 0x77, 0x26, 0xB8, 0xB4, 0x7C, 0x11, 0x44, 0x92, 0xD9, 0x23, 0x20, 0x89, 0x2E,
	0x37, 0x3F, 0xD1, 0x5B, 0x95, 0xBC, 0xCF, 0xCD, 0x90, 0x87, 0x97, 0xB2, 0xDC, 0xFC, 0xBE, 0x61,
	0xF2, 0x56, 0xD3, 0xAB, 0x14, 0x2A, 0x5D, 0x9E, 0x84, 0x3C, 0x39, 0x53, 0x47, 0x6D, 0x41, 0xA2,
	0x1F, 0x2D, 0x43, 0xD8, 0xB7, 0x7B, 0xA4, 0x76, 0xC4, 0x17, 0x49, 0xEC, 0x7F, 0x0C, 0x6F, 0xF6,
	0x6C, 0xA1, 0x3B, 0x52, 0x29, 0x9D, 0x55, 0xAA, 0xFB, 0x60, 0x86, 0xB1, 0xBB, 0xCC, 0x3E, 0x5A,
	0xCB, 0x59, 0x5F, 0xB0, 0x9C, 0xA9, 0xA0, 0x51, 0x0B, 0xF5, 0x16, 0xEB, 0x7A, 0x75, 0x2C, 0xD7,
	0x4F, 0xAE, 0xD5, 0xE9, 0xE6, 0xE7, 0xAD, 0xE8, 0x74, 0xD6, 0xF4, 0xEA, 0xA8, 0x50, 0x58, 0xAF
};


/*
 * Polynomial Evaluator, used to determine the Syndrome Vector. This is
 * relatively straightforward, and there are faster algorithms.
 */
static uint8_t evalpoly(uint8_t p[ECC_CAPACITY], uint8_t x)
{
	uint8_t y = 0;
	for (int i = 0; i < ECC_CAPACITY; i++)
		y = GF_ADD(y, GF_MUL(p[i], GF_EXP(x, i)));
	return y;
}

/*
 * Determine the Syndrome Vector. Note that in s[0] we return the OR of
 * all of the syndromes; this allows for an easy check for the no - error
 * condition.
 */
static void syndrome(uint8_t c[ECC_CAPACITY], uint8_t s[7])
{
	s[0] = 0;
	for (int i = 1; i < ECC_OFFSET + 1; i++)
	{
		s[i] = evalpoly(c, e2v[i]);
		s[0] |= s[i];
	}
}

/*
 * Determine the number of errors in a block. Since we have to find the
 * determinant of the S[] matrix in order to determine singularity, we
 * also return the determinant to be used by the Cramer's Rule correction
 * algorithm.
 */
static void errnum(uint8_t s[ECC_OFFSET + 1], uint8_t *det, int *errs)
{
	*det = GF_MUL(s[2], GF_MUL(s[4], s[6]));
	*det = GF_ADD(*det, GF_MUL(s[2], GF_MUL(s[5], s[5])));
	*det = GF_ADD(*det, GF_MUL(s[6], GF_MUL(s[3], s[3])));
	*det = GF_ADD(*det, GF_MUL(s[4], GF_MUL(s[4], s[4])));
	*errs = 3;

	if (*det != 0)
		return;

	*det = GF_ADD(GF_MUL(s[2], s[4]), GF_EXP(s[3], 2));
	*errs = 2;
	if (*det != 0)
		return;

	*det = s[1];
	*errs = 1;
	if (*det != 0)
		return;

	*errs = 4;
}

/*
 * Polynomial Solver. Simple exhaustive search, as solving polynomials is
 * generally NP - Complete anyway.
 */
static void polysolve(uint8_t polynom[4], uint8_t roots[3], int *numsol)
{
	*numsol = 0;

	for (int i = 0; i < ECC_CAPACITY; i++)
	{
		uint8_t y = 0;
		for (int j = 0; j < 4; j++)
			y = GF_ADD(y, GF_MUL(polynom[j], GF_EXP(e2v[i], j)));
		if (y == 0)
			roots[(*numsol)++] = e2v[i];
	}
}


/*
 * Full implementation of the three error correcting Peterson decoder. For
 * t<6, it is faster than Massey - Berlekamp. It is also somewhat more
 * intuitive.
 */
extern void ecc_decode(uint8_t code[ECC_CAPACITY], uint8_t mesg[ECC_CAPACITY], int *errcode)
{
	REVERSE(code, ECC_CAPACITY);

	uint8_t syn[ECC_OFFSET + 1], deter, z[4], e0, e1, e2, n0, n1, n2, w0, w1, w2, x0, x[3];
	int sols;

	*errcode = 0;

	/*
	 * First, get the message out of the code, so that even if we can't correct
	 * it, we return an estimate.
	 */
	for (int i = 0; i < ECC_PAYLOAD; i++)
		mesg[i] = code[(ECC_CAPACITY - 1) - i];

	syndrome(code, syn);

	if (syn[0] == 0)
		return;

	/*
	 * We now know we have at least one error. If there are no errors detected,
	 * we assume that something funny is going on, and so return with errcode 4,
	 * else pass the number of errors back via errcode.
	 */
	errnum(syn, &deter, errcode);

	if (*errcode == 4)
		return;

	/* Having obtained the syndrome, the number of errors, and the determinant,
	 * we now proceed to correct the block.	If we do not find exactly the
	 * number of solutions equal to the number of errors, we have exceeded our
	 * error capacity, and return with the block uncorrected, and errcode 4.
	 */

	switch (*errcode)
	{
		case 1:
			x0 = GF_MUL(syn[2], GF_INV(syn[1]));
			w0 = GF_MUL(GF_EXP(syn[1], 2), GF_INV(syn[2]));
			if (v2e[x0] > 5)
				mesg[(ECC_CAPACITY - 1) - v2e[x0]] = GF_ADD(mesg[(ECC_CAPACITY - 1) - v2e[x0]], w0);
			return;

		case 2:
			z[0] = GF_MUL(GF_ADD(GF_MUL(syn[1], syn[3]), GF_EXP(syn[2], 2)), GF_INV(deter));
			z[1] = GF_MUL(GF_ADD(GF_MUL(syn[2], syn[3]), GF_MUL(syn[1], syn[4])), GF_INV(deter));
			z[2] = 1;
			z[3] = 0;
			polysolve(z, x, &sols);
			if (sols != 2)
			{
				*errcode = 4;
				return;
			}
			w0 = GF_MUL(z[0], syn[1]);
			w1 = GF_ADD(GF_MUL(z[0], syn[2]), GF_MUL(z[1], syn[1]));
			n0 = (ECC_CAPACITY - 1) - v2e[GF_INV(x[0])];
			n1 = (ECC_CAPACITY - 1) - v2e[GF_INV(x[1])];
			e0 = GF_MUL(GF_ADD(w0, GF_MUL(w1, x[0])), GF_INV(z[1]));
			e1 = GF_MUL(GF_ADD(w0, GF_MUL(w1, x[1])), GF_INV(z[1]));
			if (n0 < ECC_PAYLOAD)
				mesg[n0] = GF_ADD(mesg[n0], e0);
			if (n1 < ECC_PAYLOAD)
				mesg[n1] = GF_ADD(mesg[n1], e1);
			return;

		case 3:
			z[3] = 1;
			z[2] = GF_MUL(syn[1], GF_MUL(syn[4], syn[6]));
			z[2] = GF_ADD(z[2], GF_MUL(syn[1], GF_MUL(syn[5], syn[5])));
			z[2] = GF_ADD(z[2], GF_MUL(syn[5], GF_MUL(syn[3], syn[3])));
			z[2] = GF_ADD(z[2], GF_MUL(syn[3], GF_MUL(syn[4], syn[4])));
			z[2] = GF_ADD(z[2], GF_MUL(syn[2], GF_MUL(syn[5], syn[4])));
			z[2] = GF_ADD(z[2], GF_MUL(syn[2], GF_MUL(syn[3], syn[6])));
			z[2] = GF_MUL(z[2], GF_INV(deter));

			z[1] = GF_MUL(syn[1], GF_MUL(syn[3], syn[6]));
			z[1] = GF_ADD(z[1], GF_MUL(syn[1], GF_MUL(syn[5], syn[4])));
			z[1] = GF_ADD(z[1], GF_MUL(syn[4], GF_MUL(syn[3], syn[3])));
			z[1] = GF_ADD(z[1], GF_MUL(syn[2], GF_MUL(syn[4], syn[4])));
			z[1] = GF_ADD(z[1], GF_MUL(syn[2], GF_MUL(syn[3], syn[5])));
			z[1] = GF_ADD(z[1], GF_MUL(syn[2], GF_MUL(syn[2], syn[6])));
			z[1] = GF_MUL(z[1], GF_INV(deter));

			z[0] = GF_MUL(syn[2], GF_MUL(syn[3], syn[4]));
			z[0] = GF_ADD(z[0], GF_MUL(syn[3], GF_MUL(syn[2], syn[4])));
			z[0] = GF_ADD(z[0], GF_MUL(syn[3], GF_MUL(syn[5], syn[1])));
			z[0] = GF_ADD(z[0], GF_MUL(syn[4], GF_MUL(syn[4], syn[1])));
			z[0] = GF_ADD(z[0], GF_MUL(syn[3], GF_MUL(syn[3], syn[3])));
			z[0] = GF_ADD(z[0], GF_MUL(syn[2], GF_MUL(syn[2], syn[5])));
			z[0] = GF_MUL(z[0], GF_INV(deter));

			polysolve (z, x, &sols);
			if (sols != 3)
			{
				*errcode = 4;
				return;
			}

			w0 = GF_MUL(z[0], syn[1]);
			w1 = GF_ADD(GF_MUL(z[0], syn[2]), GF_MUL(z[1], syn[1]));
			w2 = GF_ADD(GF_MUL(z[0], syn[3]), GF_ADD(GF_MUL(z[1], syn[2]), GF_MUL(z[2], syn[1])));

			n0 = (ECC_CAPACITY - 1) - v2e[GF_INV(x[0])];
			n1 = (ECC_CAPACITY - 1) - v2e[GF_INV(x[1])];
			n2 = (ECC_CAPACITY - 1) - v2e[GF_INV(x[2])];

			e0 = GF_ADD(w0, GF_ADD(GF_MUL(w1, x[0]), GF_MUL(w2, GF_EXP(x[0], 2))));
			e0 = GF_MUL(e0, GF_INV(GF_ADD(z[1], GF_EXP(x[0], 2))));
			e1 = GF_ADD(w0, GF_ADD(GF_MUL(w1, x[1]), GF_MUL(w2, GF_EXP(x[1], 2))));
			e1 = GF_MUL(e1, GF_INV(GF_ADD(z[1], GF_EXP(x[1], 2))));
			e2 = GF_ADD(w0, GF_ADD(GF_MUL(w1, x[2]), GF_MUL(w2, GF_EXP(x[2], 2))));
			e2 = GF_MUL(e2, GF_INV(GF_ADD(z[1], GF_EXP(x[2], 2))));

			if (n0 < ECC_PAYLOAD)
				mesg[n0] = GF_ADD(mesg[n0], e0);
			if (n1 < ECC_PAYLOAD)
				mesg[n1] = GF_ADD(mesg[n1], e1);
			if (n2 < ECC_PAYLOAD)
				mesg[n2] = GF_ADD(mesg[n2], e2);
			return;
	}
}

/*
 * Reed - Solomon Encoder. The Encoder uses a shift register algorithm,
 * as detailed in _Applied Modern Algebra_ by Dornhoff and Hohn (p.446).
 * Note that the message is reversed in the code array; this was done to
 * allow for (emergency) recovery of the message directly from the
 * data stream.
 */
extern void ecc_encode(uint8_t m[ECC_PAYLOAD], uint8_t c[ECC_CAPACITY])
{
	uint8_t r[ECC_OFFSET] = { 0x0 };

	for (int i = 0; i < ECC_PAYLOAD; i++)
	{
		c[(ECC_CAPACITY - 1) - i] = m[i];
		uint8_t rtmp = GF_ADD(m[i], r[5]);
		for (int j = ECC_OFFSET - 1; j > 0; j--)
			r[j] = GF_ADD(GF_MUL(rtmp, g[j]), r[j - 1]);
		r[0] = GF_MUL(rtmp, g[0]);
	}
	for (int i = 0; i < ECC_OFFSET; i++)
		c[i] = r[i];

	REVERSE(c, ECC_CAPACITY);
}
