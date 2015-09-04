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


static const uint8_t g[ECC_OFFSET] = { 117, 49, 58, 158, 4, 126 };

static const uint8_t e2v[ECC_CAPACITY + 1] =
{
	  1,   2,   4,   8,  16,  32,  64, 128,  29,  58, 116, 232, 205, 135,  19,  38,
	 76, 152,  45,  90, 180, 117, 234, 201, 143,   3,   6,  12,  24,  48,  96, 192,
	157,  39,  78, 156,  37,  74, 148,  53, 106, 212, 181, 119, 238, 193, 159,  35,
	 70, 140,   5,  10,  20,  40,  80, 160,  93, 186, 105, 210, 185, 111, 222, 161,
	 95, 190,  97, 194, 153,  47,  94, 188, 101, 202, 137,  15,  30,  60, 120, 240,
	253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163,  91, 182, 113, 226,
	217, 175,  67, 134,  17,  34,  68, 136,  13,  26,  52, 104, 208, 189, 103, 206,
	129,  31,  62, 124, 248, 237, 199, 147,  59, 118, 236, 197, 151,  51, 102, 204,
	133,  23,  46,  92, 184, 109, 218, 169,  79, 158,  33,  66, 132,  21,  42,  84,
	168,  77, 154,  41,  82, 164,  85, 170,  73, 146,  57, 114, 228, 213, 183, 115,
	230, 209, 191,  99, 198, 145,  63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
	227, 219, 171,  75, 150,  49,  98, 196, 149,  55, 110, 220, 165,  87, 174,  65,
	130,  25,  50, 100, 200, 141,   7,  14,  28,  56, 112, 224, 221, 167,  83, 166,
	 81, 162,  89, 178, 121, 242, 249, 239, 195, 155,  43,  86, 172,  69, 138,   9,
	 18,  36,  72, 144,  61, 122, 244, 245, 247, 243, 251, 235, 203, 139,  11,  22,
	 44,  88, 176, 125, 250, 233, 207, 131,  27,  54, 108, 216, 173,  71, 142,   1
};

static const uint8_t v2e[ECC_CAPACITY + 1] =
{
	255,   0,   1,  25,   2,  50,  26, 198,   3, 223,  51, 238,  27, 104, 199,  75,
	  4, 100, 224,  14,  52, 141, 239, 129,  28, 193, 105, 248, 200,   8,  76, 113,
	  5, 138, 101,  47, 225,  36,  15,  33,  53, 147, 142, 218, 240,  18, 130,  69,
	 29, 181, 194, 125, 106,  39, 249, 185, 201, 154,   9, 120,  77, 228, 114, 166,
	  6, 191, 139,  98, 102, 221,  48, 253, 226, 152,  37, 179,  16, 145,  34, 136,
	 54, 208, 148, 206, 143, 150, 219, 189, 241, 210,  19,  92, 131,  56,  70,  64,
	 30,  66, 182, 163, 195,  72, 126, 110, 107,  58,  40,  84, 250, 133, 186,  61,
	202,  94, 155, 159,  10,  21, 121,  43,  78, 212, 229, 172, 115, 243, 167,  87,
	  7, 112, 192, 247, 140, 128,  99,  13, 103,  74, 222, 237,  49, 197, 254,  24,
	227, 165, 153, 119,  38, 184, 180, 124,  17,  68, 146, 217,  35,  32, 137,  46,
	 55,  63, 209,  91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190,  97,
	242,  86, 211, 171,  20,  42,  93, 158, 132,  60,  57,  83,  71, 109,  65, 162,
	 31,  45,  67, 216, 183, 123, 164, 118, 196,  23,  73, 236, 127,  12, 111, 246,
	108, 161,  59,  82,  41, 157,  85, 170, 251,  96, 134, 177, 187, 204,  62,  90,
	203,  89,  95, 176, 156, 169, 160,  81,  11, 245,  22, 235, 122, 117,  44, 215,
	 79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168,  80,  88, 175
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
	for (int i = 1; i < 7; i++)
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
static void errnum(uint8_t s[7], uint8_t *det, int *errs)
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

	uint8_t syn[7], deter, z[4], e0, e1, e2, n0, n1, n2, w0, w1, w2, x0, x[3];
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

		default:
			*errcode = 4;
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
		for (int j = 5; j > 0; j--)
			r[j] = GF_ADD(GF_MUL(rtmp, g[j]), r[j - 1]);
		r[0] = GF_MUL(rtmp, g[0]);
	}
	for (int i = 0; i < ECC_OFFSET; i++)
		c[i] = r[i];

	REVERSE(c, ECC_CAPACITY);
}
