// Meriken's Tripcode Engine 1.0
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

// This file is not included in the build. I kept this file FYI.
// --Meriken



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES, CONSTANTS, AND MACROS FOR WIN32 AND CUDA                //
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// SHA-1 HASH GENERATION WITH CPU                                            //
///////////////////////////////////////////////////////////////////////////////

#define VECTOR_SIZE 16
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(16))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (16))) 
#endif

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
#define ROTL(bits, val) _mm_or_si128(_mm_slli_epi32((val), (bits)), _mm_srli_epi32((val), 32 - (bits)))

// Central routine for calculating the hash value. See the FIPS
// 180-3 standard p. 17f for a detailed explanation.
// #define f1 	( ( B & C ) ^ ( ( ~ B ) & D ) )
#define f1 _mm_xor_si128(_mm_and_si128(B, C), _mm_and_si128(_mm_andnot_si128((B), _mm_set1_epi8(0xff)), D))
// #define f2  ( B ^ C ^ D )
#define f2 _mm_xor_si128(_mm_xor_si128(B, C), D)
// #define f3  ( ( B & C ) ^ ( B & D ) ^ ( C & D ) )
#define f3 _mm_xor_si128(_mm_xor_si128(_mm_and_si128(B, C), _mm_and_si128(B, D)), _mm_and_si128(C, D))
#define f4  f2

// Initial hash values (see p. 14 of FIPS 180-3)
VECTOR_ALIGNMENT __m128i H0 = _mm_set1_epi32(0x67452301);
VECTOR_ALIGNMENT __m128i H1 = _mm_set1_epi32(0xefcdab89);
VECTOR_ALIGNMENT __m128i H2 = _mm_set1_epi32(0x98badcfe);
VECTOR_ALIGNMENT __m128i H3 = _mm_set1_epi32(0x10325476);
VECTOR_ALIGNMENT __m128i H4 = _mm_set1_epi32(0xc3d2e1f0);

// Constants required for hash calculation (see p. 11 of FIPS 180-3)
VECTOR_ALIGNMENT __m128i K0 = _mm_set1_epi32(0x5a827999);
VECTOR_ALIGNMENT __m128i K1 = _mm_set1_epi32(0x6ed9eba1);
VECTOR_ALIGNMENT __m128i K2 = _mm_set1_epi32(0x8f1bbcdc);
VECTOR_ALIGNMENT __m128i K3 = _mm_set1_epi32(0xca62c1d6);



///////////////////////////////////////////////////////////////////////////////
// CPU SEARCH THREAD FOR 12 CHARACTER TRIPCODES                              //
///////////////////////////////////////////////////////////////////////////////

inline void ConvertRaw12CharTripcodeIntoDisplayFormat(uint32_t *rawTripcodeArray, unsigned char *tripcode)
{
	tripcode[0]  = base64CharTable[ rawTripcodeArray[0] >> 26                                    ];
	tripcode[1]  = base64CharTable[(rawTripcodeArray[0] >> 20                            ) & 0x3f];
	tripcode[2]  = base64CharTable[(rawTripcodeArray[0] >> 14                            ) & 0x3f];
	tripcode[3]  = base64CharTable[(rawTripcodeArray[0] >>  8                            ) & 0x3f];
	tripcode[4]  = base64CharTable[(rawTripcodeArray[0] >>  2                            ) & 0x3f];
	tripcode[5]  = base64CharTable[(rawTripcodeArray[1] >> 28 | rawTripcodeArray[0] <<  4) & 0x3f];
	tripcode[6]  = base64CharTable[(rawTripcodeArray[1] >> 22                            ) & 0x3f];
	tripcode[7]  = base64CharTable[(rawTripcodeArray[1] >> 16                            ) & 0x3f];
	tripcode[8]  = base64CharTable[(rawTripcodeArray[1] >> 10                            ) & 0x3f];
	tripcode[9]  = base64CharTable[(rawTripcodeArray[1] >>  4                            ) & 0x3f];
	tripcode[10] = base64CharTable[(rawTripcodeArray[1] <<  2 | rawTripcodeArray[2] >> 30) & 0x3f];
	tripcode[11] = base64CharTable[(rawTripcodeArray[2] >> 24                            ) & 0x3f];
}

#define LOOK_FOR_POSSIBLE_MATCH                                                                                                                             \
	for (int32_t wordIndex = 0; wordIndex < 4; ++wordIndex) {                                                                                                   \
		BOOL found = FALSE;                                                                                                                                 \
		                                                                                                                                                    \
		key[0] = ((key[0] & 0xfc) | wordIndex);                                                                                                             \
		                                                                                                                                                    \
		if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {                                                                                                   \
			generatedTripcodeChunkArray[0] =   rawTripcodeArray[wordIndex][0] >>  2;                                                                        \
		} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {                                                                                           \
			generatedTripcodeChunkArray[0] = ((rawTripcodeArray[wordIndex][1] <<  8) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][2] >> 24) & 0x000000ff); \
		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {                                                                               \
			generatedTripcodeChunkArray[0] =   rawTripcodeArray[wordIndex][0] >>  2;                                                                        \
			generatedTripcodeChunkArray[1] = ((rawTripcodeArray[wordIndex][1] <<  8) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][2] >> 24) & 0x000000ff); \
		} else /* if (searchMode == SEARCH_MODE_FLEXIBLE) */ {                                                                                              \
			generatedTripcodeChunkArray[0] =   rawTripcodeArray[wordIndex][0] >>  2;                                                                        \
			generatedTripcodeChunkArray[1] = ((rawTripcodeArray[wordIndex][0] <<  4) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][1] >> 28) & 0x0000000f); \
			generatedTripcodeChunkArray[2] = ((rawTripcodeArray[wordIndex][0] << 10) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][1] >> 22) & 0x000003ff); \
			generatedTripcodeChunkArray[3] = ((rawTripcodeArray[wordIndex][0] << 16) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][1] >> 16) & 0x0000ffff); \
			generatedTripcodeChunkArray[4] = ((rawTripcodeArray[wordIndex][0] << 22) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][1] >> 10) & 0x003fffff); \
			generatedTripcodeChunkArray[5] = ((rawTripcodeArray[wordIndex][0] << 28) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][1] >>  4) & 0x0fffffff); \
			generatedTripcodeChunkArray[6] = ((rawTripcodeArray[wordIndex][1] <<  2) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][2] >> 30) & 0x00000003); \
			generatedTripcodeChunkArray[7] = ((rawTripcodeArray[wordIndex][1] <<  8) & 0x3fffffff) | ((rawTripcodeArray[wordIndex][2] >> 24) & 0x000000ff); \
		}                                                                                                                                                   \
		                                                                                                                                                    \
		if ((searchMode == SEARCH_MODE_FORWARD_MATCHING || searchMode == SEARCH_MODE_BACKWARD_MATCHING) && numTripcodeChunk == 1) {                         \
			if (generatedTripcodeChunkArray[0] == tripcodeChunkArray[0]) {                                                                                  \
				ConvertRaw12CharTripcodeIntoDisplayFormat(rawTripcodeArray[wordIndex], tripcode);                                                           \
				ProcessPossibleMatch(tripcode, key);                                                                                                        \
			}                                                                                                                                               \
		} else if (searchMode == SEARCH_MODE_FORWARD_MATCHING || searchMode == SEARCH_MODE_BACKWARD_MATCHING) {                                             \
			BINARY_SEARCH_FOR_TRIPCODE_CHUNK(0)                                                                                                             \
		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {                                                                               \
			BINARY_SEARCH_FOR_TRIPCODE_CHUNK(0)                                                                                                             \
			BINARY_SEARCH_FOR_TRIPCODE_CHUNK(1)                                                                                                             \
		} else {                                                                                                                                            \
			int32_t maxPos = (searchMode == SEARCH_MODE_FLEXIBLE || searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING)                                    \
						        ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN)                                                                                  \
						        : (0);                                                                                                                      \
			for (int32_t pos = 0; pos <= maxPos; ++pos)                                                                                                         \
				BINARY_SEARCH_FOR_TRIPCODE_CHUNK(pos)                                                                                                       \
		}                                                                                                                                                   \
		                                                                                                                                                    \
		if (!found && searchForSpecialPatternsOnCPU) {                                                                                                      \
			ConvertRaw12CharTripcodeIntoDisplayFormat(rawTripcodeArray[wordIndex], tripcode);                                                               \
			if (   options.searchForKaibunOnCPU                                                                                                             \
				&& tripcode[0] == tripcode[11]                                                                                                              \
				&& tripcode[1] == tripcode[10]                                                                                                              \
				&& tripcode[2] == tripcode[ 9]                                                                                                              \
				&& tripcode[3] == tripcode[ 8]                                                                                                              \
				&& tripcode[4] == tripcode[ 7]                                                                                                              \
				&& tripcode[5] == tripcode[ 6] ) {                                                                                                          \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForKagamiOnCPU                                                                                                      \
						&& charTableForKagami[tripcode[0]] == tripcode[11]                                                                                  \
						&& charTableForKagami[tripcode[1]] == tripcode[10]                                                                                  \
						&& charTableForKagami[tripcode[2]] == tripcode[ 9]                                                                                  \
						&& charTableForKagami[tripcode[3]] == tripcode[ 8]                                                                                  \
						&& charTableForKagami[tripcode[4]] == tripcode[ 7]                                                                                  \
						&& charTableForKagami[tripcode[5]] == tripcode[ 6] ) {                                                                              \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForYamabikoOnCPU                                                                                                    \
						&& tripcode[0] == tripcode[ 6]                                                                                                      \
						&& tripcode[1] == tripcode[ 7]                                                                                                      \
						&& tripcode[2] == tripcode[ 8]                                                                                                      \
						&& tripcode[3] == tripcode[ 9]                                                                                                      \
						&& tripcode[4] == tripcode[10]                                                                                                      \
						&& tripcode[5] == tripcode[11] ) {                                                                                                  \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForSourenOnCPU                                                                                                      \
						&& tripcode[ 0] == tripcode[ 1]                                                                                                     \
						&& tripcode[ 2] == tripcode[ 3]                                                                                                     \
						&& tripcode[ 4] == tripcode[ 5]                                                                                                     \
						&& tripcode[ 6] == tripcode[ 7]                                                                                                     \
						&& tripcode[ 8] == tripcode[ 9]                                                                                                     \
						&& tripcode[10] == tripcode[11] ) {                                                                                                 \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForHisekiOnCPU                                                                                                      \
						&& tripcode[ 0] == '.'                                                                                                              \
						&& tripcode[ 2] == '.'                                                                                                              \
						&& tripcode[ 4] == '.'                                                                                                              \
						&& tripcode[ 6] == '.'                                                                                                              \
						&& tripcode[ 8] == '.'                                                                                                              \
						&& tripcode[10] == '.') {                                                                                                           \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForHisekiOnCPU                                                                                                      \
						&& tripcode[ 1] == '.'                                                                                                              \
						&& tripcode[ 3] == '.'                                                                                                              \
						&& tripcode[ 5] == '.'                                                                                                              \
						&& tripcode[ 7] == '.'                                                                                                              \
						&& tripcode[ 9] == '.'                                                                                                              \
						&& tripcode[11] == '.') {                                                                                                           \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForHisekiOnCPU                                                                                                      \
						&& tripcode[ 0] == '/'                                                                                                              \
						&& tripcode[ 2] == '/'                                                                                                              \
						&& tripcode[ 4] == '/'                                                                                                              \
						&& tripcode[ 6] == '/'                                                                                                              \
						&& tripcode[ 8] == '/'                                                                                                              \
						&& tripcode[10] == '/') {                                                                                                           \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForHisekiOnCPU                                                                                                      \
						&& tripcode[ 1] == '/'                                                                                                              \
						&& tripcode[ 3] == '/'                                                                                                              \
						&& tripcode[ 5] == '/'                                                                                                              \
						&& tripcode[ 7] == '/'                                                                                                              \
						&& tripcode[ 9] == '/'                                                                                                              \
						&& tripcode[11] == '/') {                                                                                                           \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForKakuhiOnCPU                                                                                                      \
						&& tripcode[ 2] == tripcode[0]                                                                                                      \
						&& tripcode[ 4] == tripcode[0]                                                                                                      \
						&& tripcode[ 6] == tripcode[0]                                                                                                      \
						&& tripcode[ 8] == tripcode[0]                                                                                                      \
						&& tripcode[10] == tripcode[0]) {                                                                                                   \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			} else if (   options.searchForKakuhiOnCPU                                                                                                      \
						&& tripcode[ 3] == tripcode[1]                                                                                                      \
						&& tripcode[ 5] == tripcode[1]                                                                                                      \
						&& tripcode[ 7] == tripcode[1]                                                                                                      \
						&& tripcode[ 9] == tripcode[1]                                                                                                      \
						&& tripcode[11] == tripcode[1]) {                                                                                                   \
				ProcessMatch(tripcode, key);                                                                                                                \
				found = TRUE;                                                                                                                               \
			}                                                                                                                                               \
		}                                                                                                                                                   \
	}                                                                                                                                                       \

#define BINARY_SEARCH_FOR_TRIPCODE_CHUNK(p)                                                                     \
	if (!found && !smallChunkBitmap[generatedTripcodeChunkArray[p] >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;                                            \
		while (lower <= upper) {                                                                                \
			middle = (lower + upper) >> 1;                                                                      \
			if (generatedTripcodeChunkArray[p] > tripcodeChunkArray[middle]) {                                  \
				lower = middle + 1;                                                                             \
			} else if (generatedTripcodeChunkArray[p] < tripcodeChunkArray[middle]) {                           \
				upper = middle - 1;                                                                             \
			} else {                                                                                            \
				ConvertRaw12CharTripcodeIntoDisplayFormat(rawTripcodeArray[wordIndex], tripcode);               \
				ProcessPossibleMatch(tripcode, key);                                                            \
				found = TRUE;                                                                                   \
				break;                                                                                          \
			}                                                                                                   \
		}                                                                                                       \
	}                                                                                                           \

#define XOR(x, y) (_mm_xor_si128((x), (y)))

#define ROUND_00_TO_19(t, w)                                                                               \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f1), E), (w)), K0);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL(30, B);                                                                               \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define ROUND_20_TO_39(t, w)                                                                               \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f2), E), (w)), K1);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define ROUND_40_TO_59(t, w)                                                                               \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f3), E), (w)), K2);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define	ROUND_60_TO_79(t, w)                                                                               \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f4), E), (w)), K3);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

static uint32_t SearchForTripcodesWithMaximumOptimization()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	int32_t            pos, maxPos = (searchMode == SEARCH_MODE_FLEXIBLE) ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN) : (0);
	uint32_t   rawTripcodeArray[4][3];
	
 	tripcode[lenTripcode]    = '\0';
	key     [lenTripcodeKey] = '\0';

	SetCharactersInTripcodeKeyForSHA1Tripcode(key);
	while (TRUE) {
		key[0] = ((key[0] & 0xfc) | 0x00); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x01); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x02); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x03); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		break;
	}

	VECTOR_ALIGNMENT __m128i PW[80];
	PW[0]  = _mm_set1_epi32(0);
	PW[1]  = _mm_set1_epi32((key[4] << 24) | (key[5] << 16) | (key[ 6] << 8) | key[ 7]);
	PW[2]  = _mm_set1_epi32((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]);
	PW[3]  = _mm_set1_epi32(0x80000000);
	PW[4]  = _mm_set1_epi32(0);
	PW[5]  = _mm_set1_epi32(0);
	PW[6]  = _mm_set1_epi32(0);
	PW[7]  = _mm_set1_epi32(0);
	PW[8]  = _mm_set1_epi32(0);
	PW[9]  = _mm_set1_epi32(0);
	PW[10] = _mm_set1_epi32(0);
	PW[11] = _mm_set1_epi32(0);
	PW[12] = _mm_set1_epi32(0);
	PW[13] = _mm_set1_epi32(0);
	PW[14] = _mm_set1_epi32(0);
	PW[15] = _mm_set1_epi32(12 * 8);
	PW[16] = ROTL(1, _mm_xor_si128(_mm_xor_si128(PW[16 - 3], PW[16 - 8]), PW[16 - 14]));
	for (int32_t t = 17; t < 80; ++t)
		PW[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[(t) - 3], PW[(t) - 8]), PW[(t) - 14]), PW[(t) - 16]));

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte[indexKey3];
				
				VECTOR_ALIGNMENT __m128i A = H0;
				VECTOR_ALIGNMENT __m128i B = H1;
				VECTOR_ALIGNMENT __m128i C = H2;
				VECTOR_ALIGNMENT __m128i D = H3;
				VECTOR_ALIGNMENT __m128i E = H4;
				VECTOR_ALIGNMENT __m128i tmp;
				VECTOR_ALIGNMENT __m128i W0;

				union {
					__m128i v;
					int a[4];
				} converter;

				converter.a[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0 = converter.v;

				VECTOR_ALIGNMENT __m128i W0_1 = ROTL(1, W0);
				VECTOR_ALIGNMENT __m128i W0_2 = ROTL(2,  W0);
				VECTOR_ALIGNMENT __m128i W0_3 = ROTL(3,  W0);
				VECTOR_ALIGNMENT __m128i W0_4 = ROTL(4,  W0);
				VECTOR_ALIGNMENT __m128i W0_5 = ROTL(5,  W0);
				VECTOR_ALIGNMENT __m128i W0_6 = ROTL(6,  W0);
				VECTOR_ALIGNMENT __m128i W0_7 = ROTL(7,  W0);
				VECTOR_ALIGNMENT __m128i W0_8 = ROTL(8,  W0);
				VECTOR_ALIGNMENT __m128i W0_9 = ROTL(9,  W0);
				VECTOR_ALIGNMENT __m128i W010 = ROTL(10, W0);
				VECTOR_ALIGNMENT __m128i W011 = ROTL(11, W0);
				VECTOR_ALIGNMENT __m128i W012 = ROTL(12, W0);
				VECTOR_ALIGNMENT __m128i W013 = ROTL(13, W0);
				VECTOR_ALIGNMENT __m128i W014 = ROTL(14, W0);
				VECTOR_ALIGNMENT __m128i W015 = ROTL(15, W0);
				VECTOR_ALIGNMENT __m128i W016 = ROTL(16, W0);
				VECTOR_ALIGNMENT __m128i W017 = ROTL(17, W0);
				VECTOR_ALIGNMENT __m128i W018 = ROTL(18, W0);
				VECTOR_ALIGNMENT __m128i W019 = ROTL(19, W0);
				VECTOR_ALIGNMENT __m128i W020 = ROTL(20, W0);
				VECTOR_ALIGNMENT __m128i W021 = ROTL(21, W0);
				VECTOR_ALIGNMENT __m128i W022 = ROTL(22, W0);
				VECTOR_ALIGNMENT __m128i W0_6___W0_4        = XOR(W0_6,        W0_4);
				VECTOR_ALIGNMENT __m128i W0_6___W0_4___W0_7 = XOR(W0_6___W0_4, W0_7);
				VECTOR_ALIGNMENT __m128i W0_8___W0_4        = XOR(W0_8,        W0_4);
				VECTOR_ALIGNMENT __m128i W0_8___W012        = XOR(W0_8,        W012);

				ROUND_00_TO_19(0,  W0);
				ROUND_00_TO_19(1,  PW[1]);
				ROUND_00_TO_19(2,  PW[2]);
				ROUND_00_TO_19(3,  PW[3]);
				ROUND_00_TO_19(4,  PW[4]);
				ROUND_00_TO_19(5,  PW[5]);
				ROUND_00_TO_19(6,  PW[6]);
				ROUND_00_TO_19(7,  PW[7]);
				ROUND_00_TO_19(8,  PW[8]);
				ROUND_00_TO_19(9,  PW[9]);
				ROUND_00_TO_19(10, PW[10]);
				ROUND_00_TO_19(11, PW[11]);
				ROUND_00_TO_19(12, PW[12]);
				ROUND_00_TO_19(13, PW[13]);
				ROUND_00_TO_19(14, PW[14]);
				ROUND_00_TO_19(15, PW[15]);

				ROUND_00_TO_19(16, XOR(PW[16], W0_1));
				ROUND_00_TO_19(17, PW[17]);
				ROUND_00_TO_19(18, PW[18]);
				ROUND_00_TO_19(19, XOR(PW[19], W0_2));

				ROUND_20_TO_39(20, PW[20]);
				ROUND_20_TO_39(21, PW[21]);
				ROUND_20_TO_39(22, XOR(PW[22], W0_3));
				ROUND_20_TO_39(23, PW[23]);
				ROUND_20_TO_39(24, XOR(PW[24], W0_2));
				ROUND_20_TO_39(25, XOR(PW[25], W0_4));
				ROUND_20_TO_39(26, PW[26]);
				ROUND_20_TO_39(27, PW[27]);
				ROUND_20_TO_39(28, XOR(PW[28], W0_5));
				ROUND_20_TO_39(29, PW[29]);
				ROUND_20_TO_39(30, XOR(XOR(PW[30], W0_4), W0_2));
				ROUND_20_TO_39(31, XOR(PW[31], W0_6));
				ROUND_20_TO_39(32, XOR(XOR(PW[32], W0_3), W0_2));
				ROUND_20_TO_39(33, PW[33]);
				ROUND_20_TO_39(34, XOR(PW[34], W0_7));
				ROUND_20_TO_39(35, XOR(PW[35], W0_4));
				ROUND_20_TO_39(36, XOR(PW[36], W0_6___W0_4));
				ROUND_20_TO_39(37, XOR(PW[37], W0_8));
				ROUND_20_TO_39(38, XOR(PW[38], W0_4));
				ROUND_20_TO_39(39, PW[39]);
	
				ROUND_40_TO_59(40, XOR(XOR(PW[40], W0_4), W0_9));
				ROUND_40_TO_59(41, PW[41]); 
				ROUND_40_TO_59(42, XOR(XOR(PW[42], W0_6), W0_8));
				ROUND_40_TO_59(43, XOR(PW[43], W010));
				ROUND_40_TO_59(44, XOR(XOR(XOR(PW[44], W0_6), W0_3), W0_7));
				ROUND_40_TO_59(45, PW[45]);
				ROUND_40_TO_59(46, XOR(XOR(PW[46], W0_4), W011));
				ROUND_40_TO_59(47, XOR(PW[47], W0_8___W0_4));
				ROUND_40_TO_59(48, XOR(XOR(XOR(XOR(PW[48], W0_8___W0_4), W0_3), W010), W0_5));
				ROUND_40_TO_59(49, XOR(PW[49], W012));
				ROUND_40_TO_59(50, XOR(PW[50], W0_8));
				ROUND_40_TO_59(51, XOR(PW[51], W0_6___W0_4));
				ROUND_40_TO_59(52, XOR(XOR(PW[52], W0_8___W0_4), W013));
				ROUND_40_TO_59(53, PW[53]);
				ROUND_40_TO_59(54, XOR(XOR(XOR(PW[54], W0_7), W010), W012));
				ROUND_40_TO_59(55, XOR(PW[55], W014));
				ROUND_40_TO_59(56, XOR(XOR(XOR(PW[56], W0_6___W0_4___W0_7), W011), W010));
				ROUND_40_TO_59(57, XOR(PW[57], W0_8));
				ROUND_40_TO_59(58, XOR(XOR(PW[58], W0_8___W0_4), W015));
				ROUND_40_TO_59(59, XOR(PW[59], W0_8___W012));
	
				ROUND_60_TO_79(60, XOR(XOR(XOR(XOR(PW[60], W0_8___W012), W0_4), W0_7), W014));
				ROUND_60_TO_79(61, XOR(PW[61], W016));
				ROUND_60_TO_79(62, XOR(XOR(PW[62], W0_6___W0_4), W0_8___W012));
				ROUND_60_TO_79(63, XOR(PW[63], W0_8));
				ROUND_60_TO_79(64, XOR(XOR(XOR(PW[64], W0_6___W0_4___W0_7), W0_8___W012), W017));
				ROUND_60_TO_79(65, PW[65]);
				ROUND_60_TO_79(66, XOR(XOR(PW[66], W014), W016));
				ROUND_60_TO_79(67, XOR(XOR(PW[67], W0_8), W018));
				ROUND_60_TO_79(68, XOR(XOR(XOR(PW[68], W011), W014), W015));
				ROUND_60_TO_79(69, PW[69]);
				ROUND_60_TO_79(70, XOR(XOR(PW[70], W012), W019));
				ROUND_60_TO_79(71, XOR(XOR(PW[71], W012), W016));
				ROUND_60_TO_79(72, XOR(XOR(XOR(XOR(XOR(XOR(PW[72], W011), W012), W018), W013), W016), W0_5));
				ROUND_60_TO_79(73, XOR(PW[73], W020));
				ROUND_60_TO_79(74, XOR(XOR(PW[74], W0_8), W016));
				ROUND_60_TO_79(75, XOR(XOR(XOR(PW[75], W0_6), W012), W014));
				ROUND_60_TO_79(76, XOR(XOR(XOR(XOR(XOR(PW[76], W0_7), W0_8), W012), W016), W021));
				ROUND_60_TO_79(77, PW[77]);
				ROUND_60_TO_79(78, XOR(XOR(XOR(XOR(XOR(PW[78], W0_7), W0_8), W015), W018), W020));
				ROUND_60_TO_79(79, XOR(XOR(PW[79], W0_8), W022));
	
				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[0][0] = converter.a[0];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[0][1] = converter.a[0];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[0][2] = converter.a[0];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[1][0] = converter.a[1];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[1][1] = converter.a[1];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[1][2] = converter.a[1];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[2][0] = converter.a[2];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[2][1] = converter.a[2];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[2][2] = converter.a[2];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[3][0] = converter.a[3];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[3][1] = converter.a[3];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[3][2] = converter.a[3];

				numGeneratedTripcodes += 4;
			
				LOOK_FOR_POSSIBLE_MATCH
			}
		}
	}

	return numGeneratedTripcodes;
}

#if 0

#undef  ROUND_00_TO_15
#define ROUND_00_TO_15(t)                                                                                  \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f1), E), W[t]), K0); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL(30, B);                                                                               \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_16_TO_19
#define ROUND_16_TO_19(t)                                                                                  \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f1), E), W[t]), K0); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_20_TO_39
#define ROUND_20_TO_39(t)                                                                                  \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f2), E), W[t]), K1); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_40_TO_59
#define ROUND_40_TO_59(t)                                                                                  \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f3), E), W[t]), K2); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_60_TO_79
#define	ROUND_60_TO_79(t)                                                                                  \
		{                                                                                                  \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f4), E), W[t]), K3); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

static uint32_t SearchForTripcodesWithOptimization()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	uint32_t   rawTripcodeArray[4][3];
	
 	tripcode[lenTripcode] = '\0';
	key     [lenTripcodeKey] = '\0';

	SetCharactersInTripcodeKeyForSHA1Tripcode(key);
	while (TRUE) {
		key[0] = ((key[0] & 0xfc) | 0x00); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x01); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x02); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x03); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		break;
	}

	VECTOR_ALIGNMENT __m128i PW[80];
	PW[0]  = _mm_set1_epi32(0);
	PW[1]  = _mm_set1_epi32((key[4] << 24) | (key[5] << 16) | (key[ 6] << 8) | key[ 7]);
	PW[2]  = _mm_set1_epi32((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]);
	PW[3]  = _mm_set1_epi32(0x80000000);
	PW[4]  = _mm_set1_epi32(0);
	PW[5]  = _mm_set1_epi32(0);
	PW[6]  = _mm_set1_epi32(0);
	PW[7]  = _mm_set1_epi32(0);
	PW[8]  = _mm_set1_epi32(0);
	PW[9]  = _mm_set1_epi32(0);
	PW[10] = _mm_set1_epi32(0);
	PW[11] = _mm_set1_epi32(0);
	PW[12] = _mm_set1_epi32(0);
	PW[13] = _mm_set1_epi32(0);
	PW[14] = _mm_set1_epi32(0);
	PW[15] = _mm_set1_epi32(12 * 8);
	PW[16] = ROTL(1, _mm_xor_si128(_mm_xor_si128(PW[16 - 3], PW[16 - 8]), PW[16 - 14]));
	for (int32_t t = 17; t < 80; ++t)
		PW[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[(t) - 3], PW[(t) - 8]), PW[(t) - 14]), PW[(t) - 16]));

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte[indexKey3];
				
				VECTOR_ALIGNMENT __m128i A = H0;
				VECTOR_ALIGNMENT __m128i B = H1;
				VECTOR_ALIGNMENT __m128i C = H2;
				VECTOR_ALIGNMENT __m128i D = H3;
				VECTOR_ALIGNMENT __m128i E = H4;
				VECTOR_ALIGNMENT __m128i tmp;
				VECTOR_ALIGNMENT __m128i W[80];
	
				union {
					__m128i v;
					int a[4];
				} converter;

				converter.a[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				converter.a[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W[0] = converter.v;
				W[1]  = PW[1];
				W[2]  = PW[2];
				W[3]  = PW[3];
				W[4]  = _mm_set1_epi32(0);
				W[5]  = _mm_set1_epi32(0);
				W[6]  = _mm_set1_epi32(0);
				W[7]  = _mm_set1_epi32(0);
				W[8]  = _mm_set1_epi32(0);
				W[9]  = _mm_set1_epi32(0);
				W[10] = _mm_set1_epi32(0);
				W[11] = _mm_set1_epi32(0);
				W[12] = _mm_set1_epi32(0);
				W[13] = _mm_set1_epi32(0);
				W[14] = _mm_set1_epi32(0);
				W[15] = PW[15];

				VECTOR_ALIGNMENT __m128i W0_1 = ROTL(1,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_2 = ROTL(2,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_3 = ROTL(3,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_4 = ROTL(4,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_5 = ROTL(5,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_6 = ROTL(6,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_7 = ROTL(7,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_8 = ROTL(8,  W[0]);
				VECTOR_ALIGNMENT __m128i W0_9 = ROTL(9,  W[0]);
				VECTOR_ALIGNMENT __m128i W010 = ROTL(10, W[0]);
				VECTOR_ALIGNMENT __m128i W011 = ROTL(11, W[0]);
				VECTOR_ALIGNMENT __m128i W012 = ROTL(12, W[0]);
				VECTOR_ALIGNMENT __m128i W013 = ROTL(13, W[0]);
				VECTOR_ALIGNMENT __m128i W014 = ROTL(14, W[0]);
				VECTOR_ALIGNMENT __m128i W015 = ROTL(15, W[0]);
				VECTOR_ALIGNMENT __m128i W016 = ROTL(16, W[0]);
				VECTOR_ALIGNMENT __m128i W017 = ROTL(17, W[0]);
				VECTOR_ALIGNMENT __m128i W018 = ROTL(18, W[0]);
				VECTOR_ALIGNMENT __m128i W019 = ROTL(19, W[0]);
				VECTOR_ALIGNMENT __m128i W020 = ROTL(20, W[0]);
				VECTOR_ALIGNMENT __m128i W021 = ROTL(21, W[0]);
				VECTOR_ALIGNMENT __m128i W022 = ROTL(22, W[0]);
				VECTOR_ALIGNMENT __m128i W0_6___W0_4        = _mm_xor_si128(W0_6,        W0_4);
				VECTOR_ALIGNMENT __m128i W0_6___W0_4___W0_7 = _mm_xor_si128(W0_6___W0_4, W0_7);
				VECTOR_ALIGNMENT __m128i W0_8___W0_4        = _mm_xor_si128(W0_8,        W0_4);
				VECTOR_ALIGNMENT __m128i W0_8___W012        = _mm_xor_si128(W0_8,        W012);

				W[16] = _mm_xor_si128(PW[16], W0_1);
				W[17] = PW[17];
				W[18] = PW[18];
				W[19] = _mm_xor_si128(PW[19], W0_2);
				W[20] = PW[20];
				W[21] = PW[21];
				W[22] = _mm_xor_si128(PW[22], W0_3);
				W[23] = PW[23];
				W[24] = _mm_xor_si128(PW[24], W0_2);
				W[25] = _mm_xor_si128(PW[25], W0_4);
				W[26] = PW[26];
				W[27] = PW[27];
				W[28] = _mm_xor_si128(PW[28], W0_5);
				W[29] = PW[29];
				W[30] = _mm_xor_si128(_mm_xor_si128(PW[30], W0_4), W0_2);
				W[31] = _mm_xor_si128(PW[31], W0_6);
				W[32] = _mm_xor_si128(_mm_xor_si128(PW[32], W0_3), W0_2);
				W[33] = PW[33];
				W[34] = _mm_xor_si128(PW[34], W0_7);
				W[35] = _mm_xor_si128(PW[35], W0_4);
				W[36] = _mm_xor_si128(PW[36], W0_6___W0_4);
				W[37] = _mm_xor_si128(PW[37], W0_8);
				W[38] = _mm_xor_si128(PW[38], W0_4);
				W[39] = PW[39];
				W[40] = _mm_xor_si128(_mm_xor_si128(PW[40], W0_4), W0_9);
				W[41] = PW[41];
				W[42] = _mm_xor_si128(_mm_xor_si128(PW[42], W0_6), W0_8);
				W[43] = _mm_xor_si128(PW[43], W010);
				W[44] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[44], W0_6), W0_3), W0_7);
				W[45] = PW[45];
				W[46] = _mm_xor_si128(_mm_xor_si128(PW[46], W0_4), W011);
				W[47] = _mm_xor_si128(PW[47], W0_8___W0_4);
				W[48] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[48], W0_8___W0_4), W0_3), W010), W0_5);
				W[49] = _mm_xor_si128(PW[49], W012);
				W[50] = _mm_xor_si128(PW[50], W0_8);
				W[51] = _mm_xor_si128(PW[51], W0_6___W0_4);
				W[52] = _mm_xor_si128(_mm_xor_si128(PW[52], W0_8___W0_4), W013);
				W[53] = PW[53];
				W[54] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[54], W0_7), W010), W012);
				W[55] = _mm_xor_si128(PW[55], W014);
				W[56] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[56], W0_6___W0_4___W0_7), W011), W010);
				W[57] = _mm_xor_si128(PW[57], W0_8);
				W[58] = _mm_xor_si128(_mm_xor_si128(PW[58], W0_8___W0_4), W015);
				W[59] = _mm_xor_si128(PW[59], W0_8___W012);
				W[60] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[60], W0_8___W012), W0_4), W0_7), W014);
				W[61] = _mm_xor_si128(PW[61], W016);
				W[62] = _mm_xor_si128(_mm_xor_si128(PW[62], W0_6___W0_4), W0_8___W012);
				W[63] = _mm_xor_si128(PW[63], W0_8);
				W[64] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[64], W0_6___W0_4___W0_7), W0_8___W012), W017);
				W[65] = PW[65];
				W[66] = _mm_xor_si128(_mm_xor_si128(PW[66], W014), W016);
				W[67] = _mm_xor_si128(_mm_xor_si128(PW[67], W0_8), W018);
				W[68] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[68], W011), W014), W015);
				W[69] = PW[69];
				W[70] = _mm_xor_si128(_mm_xor_si128(PW[70], W012), W019);
				W[71] = _mm_xor_si128(_mm_xor_si128(PW[71], W012), W016);
				W[72] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[72], W011), W012), W018), W013), W016), W0_5);
				W[73] = _mm_xor_si128(PW[73], W020);
				W[74] = _mm_xor_si128(_mm_xor_si128(PW[74], W0_8), W016);
				W[75] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[75], W0_6), W012), W014);
				W[76] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[76], W0_7), W0_8), W012), W016), W021);
				W[77] = PW[77];
				W[78] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[78], W0_7), W0_8), W015), W018), W020);
				W[79] = _mm_xor_si128(_mm_xor_si128(PW[79], W0_8), W022);

				ROUND_00_TO_15(0);  ROUND_00_TO_15(1);  ROUND_00_TO_15(2);  ROUND_00_TO_15(3);  ROUND_00_TO_15(4);
				ROUND_00_TO_15(5);  ROUND_00_TO_15(6);  ROUND_00_TO_15(7);  ROUND_00_TO_15(8);  ROUND_00_TO_15(9);
				ROUND_00_TO_15(10); ROUND_00_TO_15(11); ROUND_00_TO_15(12); ROUND_00_TO_15(13); ROUND_00_TO_15(14);
				ROUND_00_TO_15(15);
	
				ROUND_16_TO_19(16); ROUND_16_TO_19(17); ROUND_16_TO_19(18); ROUND_16_TO_19(19);
	
				ROUND_20_TO_39(20); ROUND_20_TO_39(21); ROUND_20_TO_39(22); ROUND_20_TO_39(23); ROUND_20_TO_39(24);
				ROUND_20_TO_39(25); ROUND_20_TO_39(26); ROUND_20_TO_39(27); ROUND_20_TO_39(28);	ROUND_20_TO_39(29);
				ROUND_20_TO_39(30); ROUND_20_TO_39(31);	ROUND_20_TO_39(32); ROUND_20_TO_39(33); ROUND_20_TO_39(34);
				ROUND_20_TO_39(35);	ROUND_20_TO_39(36); ROUND_20_TO_39(37); ROUND_20_TO_39(38);	ROUND_20_TO_39(39);
	
				ROUND_40_TO_59(40); ROUND_40_TO_59(41); ROUND_40_TO_59(42); ROUND_40_TO_59(43); ROUND_40_TO_59(44);
				ROUND_40_TO_59(45); ROUND_40_TO_59(46); ROUND_40_TO_59(47); ROUND_40_TO_59(48); ROUND_40_TO_59(49);
				ROUND_40_TO_59(50); ROUND_40_TO_59(51); ROUND_40_TO_59(52); ROUND_40_TO_59(53); ROUND_40_TO_59(54);
				ROUND_40_TO_59(55); ROUND_40_TO_59(56); ROUND_40_TO_59(57); ROUND_40_TO_59(58); ROUND_40_TO_59(59);
	
				ROUND_60_TO_79(60); ROUND_60_TO_79(61); ROUND_60_TO_79(62); ROUND_60_TO_79(63); ROUND_60_TO_79(64);
				ROUND_60_TO_79(65); ROUND_60_TO_79(66); ROUND_60_TO_79(67); ROUND_60_TO_79(68); ROUND_60_TO_79(69);
				ROUND_60_TO_79(70); ROUND_60_TO_79(71); ROUND_60_TO_79(72); ROUND_60_TO_79(73); ROUND_60_TO_79(74);
				ROUND_60_TO_79(75); ROUND_60_TO_79(76); ROUND_60_TO_79(77); ROUND_60_TO_79(78); ROUND_60_TO_79(79);

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[0][0] = converter.a[0];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[0][1] = converter.a[0];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[0][2] = converter.a[0];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[1][0] = converter.a[1];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[1][1] = converter.a[1];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[1][2] = converter.a[1];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[2][0] = converter.a[2];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[2][1] = converter.a[2];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[2][2] = converter.a[2];

				converter.v = _mm_add_epi32(A, H0); rawTripcodeArray[3][0] = converter.a[3];
				converter.v = _mm_add_epi32(B, H1); rawTripcodeArray[3][1] = converter.a[3];
				converter.v = _mm_add_epi32(C, H2); rawTripcodeArray[3][2] = converter.a[3];

				numGeneratedTripcodes += 4;
			
				LOOK_FOR_POSSIBLE_MATCH
			}
		}
	}

	return numGeneratedTripcodes;
}

#undef  ROUND_16_TO_19
#define ROUND_16_TO_19(t)                                                                                  \
		{                                                                                                  \
			W[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(W[(t) - 3], W[(t) - 8]), W[(t) - 14]), W[(t) - 16])); \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f1), E), W[t]), K0); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_20_TO_39
#define ROUND_20_TO_39(t)                                                                                  \
		{                                                                                                  \
			W[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(W[(t) - 3], W[(t) - 8]), W[(t) - 14]), W[(t) - 16])); \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f2), E), W[t]), K1); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_40_TO_59
#define ROUND_40_TO_59(t)                                                                                  \
		{                                                                                                  \
			W[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(W[(t) - 3], W[(t) - 8]), W[(t) - 14]), W[(t) - 16])); \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f3), E), W[t]), K2); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#undef  ROUND_60_TO_79
#define	ROUND_60_TO_79(t)                                                                                  \
		{                                                                                                  \
			W[t] = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(W[(t) - 3], W[(t) - 8]), W[(t) - 14]), W[(t) - 16])); \
			tmp = _mm_add_epi32(_mm_add_epi32(_mm_add_epi32(_mm_add_epi32(ROTL(5, A), f4), E), W[t]), K3); \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

static uint32_t SearchForTripcodesWithoutOptimization()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	int32_t            pos, maxPos = (searchMode == SEARCH_MODE_FLEXIBLE) ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN) : (0);
	uint32_t   rawTripcodeArray[4][3];
	
 	tripcode[lenTripcode]    = '\0';
	key     [lenTripcodeKey] = '\0';

	SetCharactersInTripcodeKeyForSHA1Tripcode(key);
	while (TRUE) {
		key[0] = ((key[0] & 0xfc) | 0x00); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x01); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x02); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x03); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		break;
	}

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte[indexKey3];
				
				VECTOR_ALIGNMENT __m128i A = H0;
				VECTOR_ALIGNMENT __m128i B = H1;
				VECTOR_ALIGNMENT __m128i C = H2;
				VECTOR_ALIGNMENT __m128i D = H3;
				VECTOR_ALIGNMENT __m128i E = H4;
				VECTOR_ALIGNMENT __m128i tmp;
				VECTOR_ALIGNMENT __m128i W[80];
	
				W[0].m128i_u32[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[1]  = _mm_set1_epi32((key[4] << 24) | (key[5] << 16) | (key[ 6] << 8) | key[ 7]);
				W[2]  = _mm_set1_epi32((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]);
				W[3]  = _mm_set1_epi32(0x80000000);;
				W[4]  = _mm_set1_epi32(0);
				W[5]  = _mm_set1_epi32(0);
				W[6]  = _mm_set1_epi32(0);
				W[7]  = _mm_set1_epi32(0);
				W[8]  = _mm_set1_epi32(0);
				W[9]  = _mm_set1_epi32(0);
				W[10] = _mm_set1_epi32(0);
				W[11] = _mm_set1_epi32(0);
				W[12] = _mm_set1_epi32(0);
				W[13] = _mm_set1_epi32(0);
				W[14] = _mm_set1_epi32(0);
				W[15] = _mm_set1_epi32(12 * 8);

				ROUND_00_TO_15(0); ROUND_00_TO_15(1); ROUND_00_TO_15(2);  ROUND_00_TO_15(3); ROUND_00_TO_15(4);
				ROUND_00_TO_15(5);  ROUND_00_TO_15(6);  ROUND_00_TO_15(7);  ROUND_00_TO_15(8); ROUND_00_TO_15(9);
				ROUND_00_TO_15(10); ROUND_00_TO_15(11); ROUND_00_TO_15(12); ROUND_00_TO_15(13); ROUND_00_TO_15(14); 
				ROUND_00_TO_15(15);
	
				ROUND_16_TO_19(16); ROUND_16_TO_19(17); ROUND_16_TO_19(18); ROUND_16_TO_19(19);
				
				ROUND_20_TO_39(20); ROUND_20_TO_39(21); ROUND_20_TO_39(22); ROUND_20_TO_39(23); ROUND_20_TO_39(24);
				ROUND_20_TO_39(25); ROUND_20_TO_39(26); ROUND_20_TO_39(27); ROUND_20_TO_39(28); ROUND_20_TO_39(29);
				ROUND_20_TO_39(30); ROUND_20_TO_39(31);	ROUND_20_TO_39(32); ROUND_20_TO_39(33); ROUND_20_TO_39(34);
				ROUND_20_TO_39(35);	ROUND_20_TO_39(36); ROUND_20_TO_39(37); ROUND_20_TO_39(38);	ROUND_20_TO_39(39);

				ROUND_40_TO_59(40); ROUND_40_TO_59(41); ROUND_40_TO_59(42); ROUND_40_TO_59(43); ROUND_40_TO_59(44);
				ROUND_40_TO_59(45); ROUND_40_TO_59(46); ROUND_40_TO_59(47); ROUND_40_TO_59(48); ROUND_40_TO_59(49);
				ROUND_40_TO_59(50); ROUND_40_TO_59(51); ROUND_40_TO_59(52); ROUND_40_TO_59(53); ROUND_40_TO_59(54);
				ROUND_40_TO_59(55); ROUND_40_TO_59(56); ROUND_40_TO_59(57); ROUND_40_TO_59(58); ROUND_40_TO_59(59);
	
				ROUND_60_TO_79(60); ROUND_60_TO_79(61); ROUND_60_TO_79(62); ROUND_60_TO_79(63); ROUND_60_TO_79(64);
				ROUND_60_TO_79(65); ROUND_60_TO_79(66); ROUND_60_TO_79(67); ROUND_60_TO_79(68); ROUND_60_TO_79(69);
				ROUND_60_TO_79(70); ROUND_60_TO_79(71); ROUND_60_TO_79(72); ROUND_60_TO_79(73); ROUND_60_TO_79(74);
				ROUND_60_TO_79(75); ROUND_60_TO_79(76); ROUND_60_TO_79(77); ROUND_60_TO_79(78); ROUND_60_TO_79(79);
	
				rawTripcodeArray[0][0] = _mm_add_epi32(A, H0).m128i_u32[0];
				rawTripcodeArray[0][1] = _mm_add_epi32(B, H1).m128i_u32[0];
				rawTripcodeArray[0][2] = _mm_add_epi32(C, H2).m128i_u32[0];

				rawTripcodeArray[1][0] = _mm_add_epi32(A, H0).m128i_u32[1];
				rawTripcodeArray[1][1] = _mm_add_epi32(B, H1).m128i_u32[1];
				rawTripcodeArray[1][2] = _mm_add_epi32(C, H2).m128i_u32[1];

				rawTripcodeArray[2][0] = _mm_add_epi32(A, H0).m128i_u32[2];
				rawTripcodeArray[2][1] = _mm_add_epi32(B, H1).m128i_u32[2];
				rawTripcodeArray[2][2] = _mm_add_epi32(C, H2).m128i_u32[2];

				rawTripcodeArray[3][0] = _mm_add_epi32(A, H0).m128i_u32[3];
				rawTripcodeArray[3][1] = _mm_add_epi32(B, H1).m128i_u32[3];
				rawTripcodeArray[3][2] = _mm_add_epi32(C, H2).m128i_u32[3];

				numGeneratedTripcodes += 4;
			
				LOOK_FOR_POSSIBLE_MATCH
			}
		}
	}

	return numGeneratedTripcodes;
}

#endif

void Thread_SearchForSHA1TripcodesOnCPU()
{
	while (!GetTerminationState()) {
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);

		uint32_t numGeneratedTripcodes;
		numGeneratedTripcodes = SearchForTripcodesWithMaximumOptimization();
		AddToNumGeneratedTripcodesByCPU(numGeneratedTripcodes);
	}
}
