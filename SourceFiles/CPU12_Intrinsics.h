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



// Central routine for calculating the hash value. See the FIPS
// 180-3 standard p. 17f for a detailed explanation.
// #define f1 	( ( B & C ) ^ ( ( ~ B ) & D ) )
// #define f1 _mm_xor_si128(_mm_and_si128(B, C), _mm_and_si128(_mm_andnot_si128((B), _mm_set1_epi8(0xff)), D))
#define f1 f1_func(B, C, D)
inline sha1_vector f1_func(const sha1_vector &B, const sha1_vector &C, const sha1_vector &D) 
{
	return vxor_func(vand_func(B, C), vand_func(vnot_func(B), D));
}

// #define f2  ( B ^ C ^ D )
// #define f2 _mm_xor_si128(_mm_xor_si128(B, C), D)
#define f2 f2_func(B, C, D)
inline sha1_vector f2_func(const sha1_vector &B, const sha1_vector &C, const sha1_vector &D) 
{
	return vxor_func(vxor_func(B, C), D);
}

// #define f3  ( ( B & C ) ^ ( B & D ) ^ ( C & D ) )
// #define f3 _mm_xor_si128(_mm_xor_si128(_mm_and_si128(B, C), _mm_and_si128(B, D)), _mm_and_si128(C, D))
#define f3 f3_func(B, C, D)
inline sha1_vector f3_func(const sha1_vector &B, const sha1_vector &C, const sha1_vector &D) 
{
	return vxor_func(vxor_func(vand_func(B, C), vand_func(B, D)), vand_func(C, D));
}

#define f4  f2



inline void ConvertRaw12CharTripcodeIntoDisplayFormat(uint32_t A, uint32_t B, uint32_t C, unsigned char *tripcode)
{
	tripcode[0]  = base64CharTable[ A >> 26                                    ];
	tripcode[1]  = base64CharTable[(A >> 20                            ) & 0x3f];
	tripcode[2]  = base64CharTable[(A >> 14                            ) & 0x3f];
	tripcode[3]  = base64CharTable[(A >>  8                            ) & 0x3f];
	tripcode[4]  = base64CharTable[(A >>  2                            ) & 0x3f];
	tripcode[5]  = base64CharTable[(B >> 28 | A <<  4) & 0x3f];
	tripcode[6]  = base64CharTable[(B >> 22                            ) & 0x3f];
	tripcode[7]  = base64CharTable[(B >> 16                            ) & 0x3f];
	tripcode[8]  = base64CharTable[(B >> 10                            ) & 0x3f];
	tripcode[9]  = base64CharTable[(B >>  4                            ) & 0x3f];
	tripcode[10] = base64CharTable[(B <<  2 | C >> 30) & 0x3f];
	tripcode[11] = base64CharTable[(C >> 24                            ) & 0x3f];
}

#if VECTOR_SIZE == 16
#define KEY0_MASK 0xfc
#else
#define KEY0_MASK 0xf8
#endif

#define LOOK_FOR_POSSIBLE_MATCH                                                                                                                             \
	for (int32_t wordIndex = 0; wordIndex < VECTOR_SIZE / 4; ++wordIndex) {                                                                                                   \
		BOOL found = FALSE;                                                                                                                                 \
		                                                                                                                                                    \
		key[0] = ((key[0] & KEY0_MASK) | wordIndex);                                                                                                             \
		                                                                                                                                                    \
		if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {                                                                                                   \
			generatedTripcodeChunkArray[0] =   A.VECTOR_ELEMENTS[wordIndex] >>  2;                                                                        \
		} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {                                                                                           \
			generatedTripcodeChunkArray[0] = ((B.VECTOR_ELEMENTS[wordIndex] <<  8) & 0x3fffffff) | ((C.VECTOR_ELEMENTS[wordIndex] >> 24) & 0x000000ff); \
		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {                                                                               \
			generatedTripcodeChunkArray[0] =   A.VECTOR_ELEMENTS[wordIndex] >>  2;                                                                        \
			generatedTripcodeChunkArray[1] = ((B.VECTOR_ELEMENTS[wordIndex] <<  8) & 0x3fffffff) | ((C.VECTOR_ELEMENTS[wordIndex] >> 24) & 0x000000ff); \
		} else /* if (searchMode == SEARCH_MODE_FLEXIBLE) */ {                                                                                              \
			generatedTripcodeChunkArray[0] =   A.VECTOR_ELEMENTS[wordIndex] >>  2;                                                                        \
			generatedTripcodeChunkArray[1] = ((A.VECTOR_ELEMENTS[wordIndex] <<  4) & 0x3fffffff) | ((B.VECTOR_ELEMENTS[wordIndex] >> 28) & 0x0000000f); \
			generatedTripcodeChunkArray[2] = ((A.VECTOR_ELEMENTS[wordIndex] << 10) & 0x3fffffff) | ((B.VECTOR_ELEMENTS[wordIndex] >> 22) & 0x000003ff); \
			generatedTripcodeChunkArray[3] = ((A.VECTOR_ELEMENTS[wordIndex] << 16) & 0x3fffffff) | ((B.VECTOR_ELEMENTS[wordIndex] >> 16) & 0x0000ffff); \
			generatedTripcodeChunkArray[4] = ((A.VECTOR_ELEMENTS[wordIndex] << 22) & 0x3fffffff) | ((B.VECTOR_ELEMENTS[wordIndex] >> 10) & 0x003fffff); \
			generatedTripcodeChunkArray[5] = ((A.VECTOR_ELEMENTS[wordIndex] << 28) & 0x3fffffff) | ((B.VECTOR_ELEMENTS[wordIndex] >>  4) & 0x0fffffff); \
			generatedTripcodeChunkArray[6] = ((B.VECTOR_ELEMENTS[wordIndex] <<  2) & 0x3fffffff) | ((C.VECTOR_ELEMENTS[wordIndex] >> 30) & 0x00000003); \
			generatedTripcodeChunkArray[7] = ((B.VECTOR_ELEMENTS[wordIndex] <<  8) & 0x3fffffff) | ((C.VECTOR_ELEMENTS[wordIndex] >> 24) & 0x000000ff); \
		}                                                                                                                                                   \
		                                                                                                                                                    \
		if ((searchMode == SEARCH_MODE_FORWARD_MATCHING || searchMode == SEARCH_MODE_BACKWARD_MATCHING) && numTripcodeChunk == 1) {                         \
			if (generatedTripcodeChunkArray[0] == tripcodeChunkArray[0]) {                                                                                  \
				ConvertRaw12CharTripcodeIntoDisplayFormat(A.VECTOR_ELEMENTS[wordIndex], B.VECTOR_ELEMENTS[wordIndex], C.VECTOR_ELEMENTS[wordIndex], tripcode);                                                           \
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
			ConvertRaw12CharTripcodeIntoDisplayFormat(A.VECTOR_ELEMENTS[wordIndex], B.VECTOR_ELEMENTS[wordIndex], C.VECTOR_ELEMENTS[wordIndex], tripcode);                                                               \
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
				ConvertRaw12CharTripcodeIntoDisplayFormat(A.VECTOR_ELEMENTS[wordIndex], B.VECTOR_ELEMENTS[wordIndex], C.VECTOR_ELEMENTS[wordIndex], tripcode);               \
				ProcessPossibleMatch(tripcode, key);                                                            \
				found = TRUE;                                                                                   \
				break;                                                                                          \
			}                                                                                                   \
		}                                                                                                       \
	}                                                                                                           \

#define ROUND_00_TO_19(t, w)                                                                               \
		{                                                                                                  \
			tmp = vadd_func(vadd_func(vadd_func(vadd_func(ROTL(5, A), f1), E), (w)), K0);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL(30, B);                                                                               \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define ROUND_20_TO_39(t, w)                                                                               \
		{                                                                                                  \
			tmp = vadd_func(vadd_func(vadd_func(vadd_func(ROTL(5, A), f2), E), (w)), K1);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define ROUND_40_TO_59(t, w)                                                                               \
		{                                                                                                  \
			tmp = vadd_func(vadd_func(vadd_func(vadd_func(ROTL(5, A), f3), E), (w)), K2);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

#define	ROUND_60_TO_79(t, w)                                                                               \
		{                                                                                                  \
			tmp = vadd_func(vadd_func(vadd_func(vadd_func(ROTL(5, A), f4), E), (w)), K3);  \
			E = D;                                                                                         \
			D = C;                                                                                         \
			C = ROTL( 30, B );                                                                             \
			B = A;                                                                                         \
			A = tmp;                                                                                       \
		}                                                                                                  \

uint32_t CPU12_SHA1_MAIN_LOOP()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	int32_t            pos, maxPos = (searchMode == SEARCH_MODE_FLEXIBLE) ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN) : (0);
	uint32_t   rawTripcodeArray[4][3];
	
 	tripcode[lenTripcode]    = '\0';
	key     [lenTripcodeKey] = '\0';

#if VECTOR_SIZE == 16
	SetCharactersInTripcodeKeyForSHA1Tripcode(key);
	while (TRUE) {
		key[0] = ((key[0] & 0xfc) | 0x00); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x01); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x02); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xfc) | 0x03); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		break;
	}
	VECTOR_ALIGNMENT sha1_vector PW[80] = {
		{0, 0, 0, 0},
#define KEY (uint32_t)((unsigned char  *)key)
		{(KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7]},
        {(KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11]},
#undef KEY
		 {0x80000000, 0x80000000, 0x80000000, 0x80000000},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{12 * 8, 12 * 8, 12 * 8, 12 * 8},
	};
#else
	SetCharactersInTripcodeKeyForSHA1Tripcode(key);
	while (TRUE) {
		key[0] = ((key[0] & 0xf8) | 0x00); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x01); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x02); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x03); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x04); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x05); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x06); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		key[0] = ((key[0] & 0xf8) | 0x07); if (!IsValidKey(key)) { SetCharactersInTripcodeKeyForSHA1Tripcode(key); continue; }
		break;
	}
	VECTOR_ALIGNMENT sha1_vector PW[80] = {
		{0, 0, 0, 0, 0, 0, 0, 0},
#define KEY (uint32_t)((unsigned char  *)key)
		{(KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
	     (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7],
         (KEY[4] << 24) | (KEY[5] << 16) | (KEY[ 6] << 8) | KEY[ 7]},
        {(KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11],
         (KEY[8] << 24) | (KEY[9] << 16) | (KEY[10] << 8) | KEY[11]},
#undef KEY
		{0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{12 * 8, 12 * 8, 12 * 8, 12 * 8, 12 * 8, 12 * 8, 12 * 8, 12 * 8},
	};
#endif

	PW[16] = ROTL(1, vxor_func(vxor_func(PW[16 - 3], PW[16 - 8]), PW[16 - 14]));
	for (int32_t t = 17; t < 80; ++t)
		PW[t] = ROTL(1, vxor_func(vxor_func(vxor_func(PW[(t) - 3], PW[(t) - 8]), PW[(t) - 14]), PW[(t) - 16]));

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte[indexKey3];
				
				VECTOR_ALIGNMENT sha1_vector A = H0;
				VECTOR_ALIGNMENT sha1_vector B = H1;
				VECTOR_ALIGNMENT sha1_vector C = H2;
				VECTOR_ALIGNMENT sha1_vector D = H3;
				VECTOR_ALIGNMENT sha1_vector E = H4;
				VECTOR_ALIGNMENT sha1_vector tmp;
				VECTOR_ALIGNMENT sha1_vector W0;
				
#if VECTOR_SIZE == 16
				W0.VECTOR_ELEMENTS[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
#else
				W0.VECTOR_ELEMENTS[0] = (((key[0] & 0xf8) | 0x00) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[1] = (((key[0] & 0xf8) | 0x01) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[2] = (((key[0] & 0xf8) | 0x02) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[3] = (((key[0] & 0xf8) | 0x03) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[4] = (((key[0] & 0xf8) | 0x04) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[5] = (((key[0] & 0xf8) | 0x05) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[6] = (((key[0] & 0xf8) | 0x06) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
				W0.VECTOR_ELEMENTS[7] = (((key[0] & 0xf8) | 0x07) << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
#endif

				VECTOR_ALIGNMENT sha1_vector W0_1 = ROTL(1, W0);
				VECTOR_ALIGNMENT sha1_vector W0_2 = ROTL(2,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_3 = ROTL(3,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_4 = ROTL(4,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_5 = ROTL(5,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_6 = ROTL(6,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_7 = ROTL(7,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_8 = ROTL(8,  W0);
				VECTOR_ALIGNMENT sha1_vector W0_9 = ROTL(9,  W0);
				VECTOR_ALIGNMENT sha1_vector W010 = ROTL(10, W0);
				VECTOR_ALIGNMENT sha1_vector W011 = ROTL(11, W0);
				VECTOR_ALIGNMENT sha1_vector W012 = ROTL(12, W0);
				VECTOR_ALIGNMENT sha1_vector W013 = ROTL(13, W0);
				VECTOR_ALIGNMENT sha1_vector W014 = ROTL(14, W0);
				VECTOR_ALIGNMENT sha1_vector W015 = ROTL(15, W0);
				VECTOR_ALIGNMENT sha1_vector W016 = ROTL(16, W0);
				VECTOR_ALIGNMENT sha1_vector W017 = ROTL(17, W0);
				VECTOR_ALIGNMENT sha1_vector W018 = ROTL(18, W0);
				VECTOR_ALIGNMENT sha1_vector W019 = ROTL(19, W0);
				VECTOR_ALIGNMENT sha1_vector W020 = ROTL(20, W0);
				VECTOR_ALIGNMENT sha1_vector W021 = ROTL(21, W0);
				VECTOR_ALIGNMENT sha1_vector W022 = ROTL(22, W0);
				VECTOR_ALIGNMENT sha1_vector W0_6___W0_4        = vxor_func(W0_6,        W0_4);
				VECTOR_ALIGNMENT sha1_vector W0_6___W0_4___W0_7 = vxor_func(W0_6___W0_4, W0_7);
				VECTOR_ALIGNMENT sha1_vector W0_8___W0_4        = vxor_func(W0_8,        W0_4);
				VECTOR_ALIGNMENT sha1_vector W0_8___W012        = vxor_func(W0_8,        W012);

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

				ROUND_00_TO_19(16, vxor_func(PW[16], W0_1));
				ROUND_00_TO_19(17, PW[17]);
				ROUND_00_TO_19(18, PW[18]);
				ROUND_00_TO_19(19, vxor_func(PW[19], W0_2));

				ROUND_20_TO_39(20, PW[20]);
				ROUND_20_TO_39(21, PW[21]);
				ROUND_20_TO_39(22, vxor_func(PW[22], W0_3));
				ROUND_20_TO_39(23, PW[23]);
				ROUND_20_TO_39(24, vxor_func(PW[24], W0_2));
				ROUND_20_TO_39(25, vxor_func(PW[25], W0_4));
				ROUND_20_TO_39(26, PW[26]);
				ROUND_20_TO_39(27, PW[27]);
				ROUND_20_TO_39(28, vxor_func(PW[28], W0_5));
				ROUND_20_TO_39(29, PW[29]);
				ROUND_20_TO_39(30, vxor_func(vxor_func(PW[30], W0_4), W0_2));
				ROUND_20_TO_39(31, vxor_func(PW[31], W0_6));
				ROUND_20_TO_39(32, vxor_func(vxor_func(PW[32], W0_3), W0_2));
				ROUND_20_TO_39(33, PW[33]);
				ROUND_20_TO_39(34, vxor_func(PW[34], W0_7));
				ROUND_20_TO_39(35, vxor_func(PW[35], W0_4));
				ROUND_20_TO_39(36, vxor_func(PW[36], W0_6___W0_4));
				ROUND_20_TO_39(37, vxor_func(PW[37], W0_8));
				ROUND_20_TO_39(38, vxor_func(PW[38], W0_4));
				ROUND_20_TO_39(39, PW[39]);
	
				ROUND_40_TO_59(40, vxor_func(vxor_func(PW[40], W0_4), W0_9));
				ROUND_40_TO_59(41, PW[41]); 
				ROUND_40_TO_59(42, vxor_func(vxor_func(PW[42], W0_6), W0_8));
				ROUND_40_TO_59(43, vxor_func(PW[43], W010));
				ROUND_40_TO_59(44, vxor_func(vxor_func(vxor_func(PW[44], W0_6), W0_3), W0_7));
				ROUND_40_TO_59(45, PW[45]);
				ROUND_40_TO_59(46, vxor_func(vxor_func(PW[46], W0_4), W011));
				ROUND_40_TO_59(47, vxor_func(PW[47], W0_8___W0_4));
				ROUND_40_TO_59(48, vxor_func(vxor_func(vxor_func(vxor_func(PW[48], W0_8___W0_4), W0_3), W010), W0_5));
				ROUND_40_TO_59(49, vxor_func(PW[49], W012));
				ROUND_40_TO_59(50, vxor_func(PW[50], W0_8));
				ROUND_40_TO_59(51, vxor_func(PW[51], W0_6___W0_4));
				ROUND_40_TO_59(52, vxor_func(vxor_func(PW[52], W0_8___W0_4), W013));
				ROUND_40_TO_59(53, PW[53]);
				ROUND_40_TO_59(54, vxor_func(vxor_func(vxor_func(PW[54], W0_7), W010), W012));
				ROUND_40_TO_59(55, vxor_func(PW[55], W014));
				ROUND_40_TO_59(56, vxor_func(vxor_func(vxor_func(PW[56], W0_6___W0_4___W0_7), W011), W010));
				ROUND_40_TO_59(57, vxor_func(PW[57], W0_8));
				ROUND_40_TO_59(58, vxor_func(vxor_func(PW[58], W0_8___W0_4), W015));
				ROUND_40_TO_59(59, vxor_func(PW[59], W0_8___W012));
	
				ROUND_60_TO_79(60, vxor_func(vxor_func(vxor_func(vxor_func(PW[60], W0_8___W012), W0_4), W0_7), W014));
				ROUND_60_TO_79(61, vxor_func(PW[61], W016));
				ROUND_60_TO_79(62, vxor_func(vxor_func(PW[62], W0_6___W0_4), W0_8___W012));
				ROUND_60_TO_79(63, vxor_func(PW[63], W0_8));
				ROUND_60_TO_79(64, vxor_func(vxor_func(vxor_func(PW[64], W0_6___W0_4___W0_7), W0_8___W012), W017));
				ROUND_60_TO_79(65, PW[65]);
				ROUND_60_TO_79(66, vxor_func(vxor_func(PW[66], W014), W016));
				ROUND_60_TO_79(67, vxor_func(vxor_func(PW[67], W0_8), W018));
				ROUND_60_TO_79(68, vxor_func(vxor_func(vxor_func(PW[68], W011), W014), W015));
				ROUND_60_TO_79(69, PW[69]);
				ROUND_60_TO_79(70, vxor_func(vxor_func(PW[70], W012), W019));
				ROUND_60_TO_79(71, vxor_func(vxor_func(PW[71], W012), W016));
				ROUND_60_TO_79(72, vxor_func(vxor_func(vxor_func(vxor_func(vxor_func(vxor_func(PW[72], W011), W012), W018), W013), W016), W0_5));
				ROUND_60_TO_79(73, vxor_func(PW[73], W020));
				ROUND_60_TO_79(74, vxor_func(vxor_func(PW[74], W0_8), W016));
				ROUND_60_TO_79(75, vxor_func(vxor_func(vxor_func(PW[75], W0_6), W012), W014));
				ROUND_60_TO_79(76, vxor_func(vxor_func(vxor_func(vxor_func(vxor_func(PW[76], W0_7), W0_8), W012), W016), W021));
				ROUND_60_TO_79(77, PW[77]);
				ROUND_60_TO_79(78, vxor_func(vxor_func(vxor_func(vxor_func(vxor_func(PW[78], W0_7), W0_8), W015), W018), W020));
				ROUND_60_TO_79(79, vxor_func(vxor_func(PW[79], W0_8), W022));
				
				A = vadd_func(A, H0);
				B = vadd_func(B, H1);
				C = vadd_func(C, H2);

				numGeneratedTripcodes += VECTOR_SIZE / 4;
			
				LOOK_FOR_POSSIBLE_MATCH
			}
		}
	}

	return numGeneratedTripcodes;
}

