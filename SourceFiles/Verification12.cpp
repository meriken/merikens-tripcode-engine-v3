// Meriken's Tripcode Engine
// Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
//
// The initial versions of this software were based on:
// CUDA SHA-1 Tripper 0.2.1
// Copyright (c) 2009 Horo/.IBXjcg
// 
// The code that deals with DES decryption is partially adopted from:
// John the Ripper password cracker
// Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
// DeepLearningJohnDoe's fork of Meriken's Tripcode Engine
// Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
//
// The code that deals with SHA-1 hash generation is partially adopted from:
// sha_digest-2.2
// Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
// VecTripper 
// Copyright (C) 2011 tmkk <tmkk@smoug.net>
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// SHA-1 HASH GENERATION WITH CPU                                            //
///////////////////////////////////////////////////////////////////////////////

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
#define ROTL(bits, val) (((val) << (bits)) | ((val) >> (32 - (bits))))

// Central routine for calculating the hash value. See the FIPS
// 180-3 standard p. 17f for a detailed explanation.
#define f1 ((B & C) ^ ((~B) & D))
#define f2 (B ^ C ^ D)
#define f3 ((B & C) ^ (B & D) ^ (C & D))
#define f4 f2

// Initial hash values (see p. 14 of FIPS 180-3)
#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

// Constants required for hash calculation (see p. 11 of FIPS 180-3)
#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define ROUND_00_TO_15_W(t, w)                       \
		{                                            \
			W[t] = (w);                              \
			tmp = (ROTL(5, A) + f1 + E + W[t] + K0); \
			E = D;                                   \
			D = C;                                   \
			C = ROTL(30, B);                         \
			B = A;                                   \
			A = tmp;                                 \
		}                                            \

#define ROUND_00_TO_15_ZERO(t)                       \
		{                                            \
			W[t] = 0;                                \
			tmp = (ROTL(5, A) + f1 + E + K0);        \
			E = D;                                   \
			D = C;                                   \
			C = ROTL( 30, B );                       \
			B = A;                                   \
			A = tmp;                                 \
		}                                            \

#define ROUND_16_TO_19(t)                                                        \
		{                                                                        \
			W[t] = ROTL(1, W[(t) - 3] ^ W[(t) - 8] ^ W[(t) - 14] ^ W[(t) - 16]); \
			tmp = (ROTL(5, A) + f1 + E + W[t] + K0);                             \
			E = D;                                                               \
			D = C;                                                               \
			C = ROTL( 30, B );                                                   \
			B = A;                                                               \
			A = tmp;                                                             \
		}                                                                        \

#define ROUND_20_TO_39(t)                                                        \
		{                                                                        \
			W[t] = ROTL(1, W[(t) - 3] ^ W[(t) - 8] ^ W[(t) - 14] ^ W[(t) - 16]); \
			tmp = (ROTL(5, A) + f2 + E + W[t] + K1);                             \
			E = D;                                                               \
			D = C;                                                               \
			C = ROTL(30, B);                                                     \
			B = A;                                                               \
			A = tmp;                                                             \
		}                                                                        \

#define ROUND_40_TO_59(t)                                                        \
		{                                                                        \
			W[t] = ROTL(1, W[(t) - 3] ^ W[(t) - 8] ^ W[(t) - 14] ^ W[(t) - 16]); \
			tmp = (ROTL(5, A) + f3 + E + W[t] + K2);                             \
			E = D;                                                               \
			D = C;                                                               \
			C = ROTL(30, B);                                                     \
			B = A;                                                               \
			A = tmp;                                                             \
		}                                                                        \

#define	ROUND_60_TO_79(t)                                                        \
		{                                                                        \
			W[t] = ROTL(1, W[(t) - 3] ^ W[(t) - 8] ^ W[(t) - 14] ^ W[(t) - 16]); \
			tmp = (ROTL(5, A) + f4 + E + W[t] + K3);                             \
			E = D;                                                               \
			D = C;                                                               \
			C = ROTL(30, B);                                                     \
			B = A;                                                               \
			A = tmp;                                                             \
		}                                                                        \

BOOL VerifySHA1Tripcode(unsigned char *tripcode, unsigned char *key)
{
	if (strlen((char *)tripcode) != lenTripcode || strlen((char *)key) != lenTripcodeKey)
		return FALSE;

	uint32_t W[80];
    uint32_t A = H0, B = H1, C = H2, D = H3, E = H4, tmp;

	ROUND_00_TO_15_W(0, (key[ 0] << 24) | (key[ 1] << 16) | (key[ 2] << 8) | key[ 3]);
	ROUND_00_TO_15_W(1, (key[ 4] << 24) | (key[ 5] << 16) | (key[ 6] << 8) | key[ 7]);
	ROUND_00_TO_15_W(2, (key[ 8] << 24) | (key[ 9] << 16) | (key[10] << 8) | key[11]);
	ROUND_00_TO_15_W(3, 0x80000000);

	ROUND_00_TO_15_ZERO( 4); ROUND_00_TO_15_ZERO( 5); ROUND_00_TO_15_ZERO( 6); ROUND_00_TO_15_ZERO(7);
	ROUND_00_TO_15_ZERO( 8); ROUND_00_TO_15_ZERO( 9); ROUND_00_TO_15_ZERO(10); ROUND_00_TO_15_ZERO(11);
	ROUND_00_TO_15_ZERO(12); ROUND_00_TO_15_ZERO(13); ROUND_00_TO_15_ZERO(14); ROUND_00_TO_15_W(15, 12 * 8);

    ROUND_16_TO_19(16); ROUND_16_TO_19(17); ROUND_16_TO_19(18); ROUND_16_TO_19(19);
	
	ROUND_20_TO_39(20);	ROUND_20_TO_39(21);	ROUND_20_TO_39(22);	ROUND_20_TO_39(23);	ROUND_20_TO_39(24);
	ROUND_20_TO_39(25);	ROUND_20_TO_39(26);	ROUND_20_TO_39(27);	ROUND_20_TO_39(28);	ROUND_20_TO_39(29);
	ROUND_20_TO_39(30);	ROUND_20_TO_39(31);	ROUND_20_TO_39(32); ROUND_20_TO_39(33);	ROUND_20_TO_39(34);
	ROUND_20_TO_39(35);	ROUND_20_TO_39(36);	ROUND_20_TO_39(37); ROUND_20_TO_39(38);	ROUND_20_TO_39(39);

    ROUND_40_TO_59(40); ROUND_40_TO_59(41); ROUND_40_TO_59(42); ROUND_40_TO_59(43); ROUND_40_TO_59(44);
    ROUND_40_TO_59(45); ROUND_40_TO_59(46); ROUND_40_TO_59(47); ROUND_40_TO_59(48); ROUND_40_TO_59(49);
    ROUND_40_TO_59(50); ROUND_40_TO_59(51); ROUND_40_TO_59(52); ROUND_40_TO_59(53); ROUND_40_TO_59(54);
    ROUND_40_TO_59(55); ROUND_40_TO_59(56); ROUND_40_TO_59(57); ROUND_40_TO_59(58); ROUND_40_TO_59(59);

    ROUND_60_TO_79(60); ROUND_60_TO_79(61); ROUND_60_TO_79(62); ROUND_60_TO_79(63); ROUND_60_TO_79(64);
    ROUND_60_TO_79(65); ROUND_60_TO_79(66); ROUND_60_TO_79(67); ROUND_60_TO_79(68); ROUND_60_TO_79(69);
    ROUND_60_TO_79(70); ROUND_60_TO_79(71); ROUND_60_TO_79(72); ROUND_60_TO_79(73); ROUND_60_TO_79(74);
    ROUND_60_TO_79(75); ROUND_60_TO_79(76); ROUND_60_TO_79(77); ROUND_60_TO_79(78); ROUND_60_TO_79(79);
    
	A += H0;
	B += H1;
	C += H2;

	BOOL result =    (tripcode[ 0] == base64CharTable[ A >> 26                  ])
	              && (tripcode[ 1] == base64CharTable[(A >> 20          ) & 0x3f])
	              && (tripcode[ 2] == base64CharTable[(A >> 14          ) & 0x3f])
	              && (tripcode[ 3] == base64CharTable[(A >>  8          ) & 0x3f])
	              && (tripcode[ 4] == base64CharTable[(A >>  2          ) & 0x3f])
	              && (tripcode[ 5] == base64CharTable[(B >> 28 | A <<  4) & 0x3f])
	              && (tripcode[ 6] == base64CharTable[(B >> 22          ) & 0x3f])
	              && (tripcode[ 7] == base64CharTable[(B >> 16          ) & 0x3f])
	              && (tripcode[ 8] == base64CharTable[(B >> 10          ) & 0x3f])
	              && (tripcode[ 9] == base64CharTable[(B >>  4          ) & 0x3f])
	              && (tripcode[10] == base64CharTable[(B <<  2 | C >> 30) & 0x3f])
	              && (tripcode[11] == base64CharTable[(C >> 24          ) & 0x3f]);

#if TRUE
	if (!result) {
		printf("key:      `%s'\n", key);
		printf("tripcode: `%s'\n", tripcode);
	}
	fflush(stdout);
#endif

	return result;
}
