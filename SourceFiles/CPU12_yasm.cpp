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



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// CPU SEARCH THREAD FOR 12 CHARACTER TRIPCODES                              //
///////////////////////////////////////////////////////////////////////////////

#define VECTOR_SIZE 16
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(16))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (16))) 
#endif
typedef union VECTOR_ALIGNMENT __sha1_vector {
	__m128i m128i;
	__int8 m128i_i8[16];
	__int16 m128i_i16[8];
	int32_t m128i_i32[4];
	int64_t m128i_i64[2];
	uint8_t m128i_u8[16];
	uint16_t m128i_u16[8];
	uint32_t m128i_u32[4];
	uint64_t m128i_u64[2];
} sha1_vector;
#define VECTOR_ELEMENTS m128i_i32

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
#define ROTL(bits, val) _mm_or_si128(_mm_slli_epi32((val), (bits)), _mm_srli_epi32((val), 32 - (bits)))

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

#define LOOK_FOR_POSSIBLE_MATCH(numWordsInVector)                                                                                                           \
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];                                                            \
	int32_t            pos, maxPos = (searchMode == SEARCH_MODE_FLEXIBLE) ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN) : (0);                                     \
                                                                                                                                                            \
	for (int32_t wordIndex = 0; wordIndex < (numWordsInVector); ++wordIndex) {                                                                                  \
		BOOL found = FALSE;                                                                                                                                 \
		                                                                                                                                                    \
		key[0] = (numWordsInVector == 4)                                                                                                                    \
                   ? ((key[0] & 0xfc) | wordIndex)                                                                                                          \
				   : ((key[0] & 0xf8) | wordIndex);                                                                                                         \
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



#ifdef _M_X64
extern "C" void SHA1_GenerateTripcodesWithOptimization_x64_AVX         (void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x64_SSE2        (void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x64_SSE2_Nehalem(void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x64_AVX2        (void *W0, void *PW, void *W0Shifted, void *ABC);
#else
extern "C" void SHA1_GenerateTripcodesWithOptimization_x86_AVX         (void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x86_SSE2        (void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x86_SSE2_Nehalem(void *W0, void *PW, void *W0Shifted, void *ABC);
extern "C" void SHA1_GenerateTripcodesWithOptimization_x86_AVX2        (void *W0, void *PW, void *W0Shifted, void *ABC);
#endif

BOOL IsCPUBasedOnNehalemMicroarchitecture()
{
	int32_t results[4];
	int32_t processorInfoArray[] = {
		// 0x306a0, // For testing

		// See: http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
		0x20650,
		0x206c0,
		0x206f0,
		0x106e0,
		0x106a0,
		0x206e0,
		0
	};
	int32_t mask = 0xfffffff0;
	
	__cpuid(results, 1);
	for (int32_t i = 0; processorInfoArray[i]; ++i) {
		if ((results[0] & mask) == processorInfoArray[i])
			return TRUE;
	}

	return FALSE;
}

static uint32_t SearchForTripcodesWithOptimization()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   numGeneratedTripcodes = 0;
	uint32_t   rawTripcodeArray[4][3];

#ifdef _M_X64
	void           (*SHA1_GenerateTripcodesWithOptimization)(void *, void *, void *, void *) = 
		(options.isAVXEnabled && IsAVXSupported()) ? SHA1_GenerateTripcodesWithOptimization_x64_AVX          :
		(IsCPUBasedOnNehalemMicroarchitecture()  ) ? SHA1_GenerateTripcodesWithOptimization_x64_SSE2_Nehalem :
		                                             SHA1_GenerateTripcodesWithOptimization_x64_SSE2;
#else
	void           (*SHA1_GenerateTripcodesWithOptimization)(void *, void *, void *, void *) = 
		(options.isAVXEnabled && IsAVXSupported()) ? SHA1_GenerateTripcodesWithOptimization_x86_AVX          :
		(IsCPUBasedOnNehalemMicroarchitecture()  ) ? SHA1_GenerateTripcodesWithOptimization_x86_SSE2_Nehalem :
		                                             SHA1_GenerateTripcodesWithOptimization_x86_SSE2;
#endif

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

	sha1_vector PW[80], W0Shifted[23];
	unsigned char keyCharTable_FirstByte_local           [SIZE_KEY_CHAR_TABLE];
	unsigned char keyCharTable_SecondByteAndOneByte_local[SIZE_KEY_CHAR_TABLE];

	for (int32_t i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
		keyCharTable_FirstByte_local[i]            = keyCharTable_FirstByte[i];
		keyCharTable_SecondByteAndOneByte_local[i] = keyCharTable_SecondByteAndOneByte[i];
	}

	PW[0].m128i = _mm_set1_epi32(0);
	PW[1].m128i = _mm_set1_epi32((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]);
	PW[2].m128i = _mm_set1_epi32((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]);
	PW[3].m128i = _mm_set1_epi32(0x80000000);
	PW[4].m128i = _mm_set1_epi32(0);
	PW[5].m128i = _mm_set1_epi32(0);
	PW[6].m128i = _mm_set1_epi32(0);
	PW[7].m128i = _mm_set1_epi32(0);
	PW[8].m128i = _mm_set1_epi32(0);
	PW[9].m128i = _mm_set1_epi32(0);
	PW[10].m128i = _mm_set1_epi32(0);
	PW[11].m128i = _mm_set1_epi32(0);
	PW[12].m128i = _mm_set1_epi32(0);
	PW[13].m128i = _mm_set1_epi32(0);
	PW[14].m128i = _mm_set1_epi32(0);
	PW[15].m128i = _mm_set1_epi32(12 * 8);
	PW[16].m128i = ROTL(1, _mm_xor_si128(_mm_xor_si128(PW[16 - 3].m128i, PW[16 - 8].m128i), PW[16 - 14].m128i));
	for (int32_t t = 17; t < 80; ++t)
		PW[t].m128i = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[(t)-3].m128i, PW[(t)-8].m128i), PW[(t)-14].m128i), PW[(t)-16].m128i));

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte_local[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte_local[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte_local[indexKey3];

				sha1_vector W0, ABC[3];
				W0.m128i_u32[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.m128i_u32[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.m128i_u32[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.m128i_u32[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];

				(*SHA1_GenerateTripcodesWithOptimization)(&W0, PW, W0Shifted, ABC);

				rawTripcodeArray[0][0] = ABC[0].m128i_u32[0];
				rawTripcodeArray[0][1] = ABC[1].m128i_u32[0];
				rawTripcodeArray[0][2] = ABC[2].m128i_u32[0];

				rawTripcodeArray[1][0] = ABC[0].m128i_u32[1];
				rawTripcodeArray[1][1] = ABC[1].m128i_u32[1];
				rawTripcodeArray[1][2] = ABC[2].m128i_u32[1];

				rawTripcodeArray[2][0] = ABC[0].m128i_u32[2];
				rawTripcodeArray[2][1] = ABC[1].m128i_u32[2];
				rawTripcodeArray[2][2] = ABC[2].m128i_u32[2];

				rawTripcodeArray[3][0] = ABC[0].m128i_u32[3];
				rawTripcodeArray[3][1] = ABC[1].m128i_u32[3];
				rawTripcodeArray[3][2] = ABC[2].m128i_u32[3];

				numGeneratedTripcodes += 4;
			
				LOOK_FOR_POSSIBLE_MATCH(4)
			}
		}
	}

	return numGeneratedTripcodes;
}

static uint32_t SearchForTripcodesWithOptimization_AVX2()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   numGeneratedTripcodes = 0;
	uint32_t   rawTripcodeArray[8][3];

	tripcode[lenTripcode]    = '\0';
	key     [lenTripcodeKey] = '\0';

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

	VECTOR_ALIGNMENT struct {
		__sha1_vector lower, upper;
	} PW[80], W0Shifted[23], W0, ABC[3];
	unsigned char keyCharTable_FirstByte_local           [SIZE_KEY_CHAR_TABLE];
	unsigned char keyCharTable_SecondByteAndOneByte_local[SIZE_KEY_CHAR_TABLE];

	for (int32_t i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
		keyCharTable_FirstByte_local[i]            = keyCharTable_FirstByte[i];
		keyCharTable_SecondByteAndOneByte_local[i] = keyCharTable_SecondByteAndOneByte[i];
	}

	PW[0].lower.m128i = PW[0].upper.m128i = _mm_set1_epi32(0);
	PW[1].lower.m128i = PW[1].upper.m128i = _mm_set1_epi32((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]);
	PW[2].lower.m128i = PW[2].upper.m128i = _mm_set1_epi32((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]);
	PW[3].lower.m128i = PW[3].upper.m128i = _mm_set1_epi32(0x80000000);
	PW[4].lower.m128i = PW[4].upper.m128i = _mm_set1_epi32(0);
	PW[5].lower.m128i = PW[5].upper.m128i = _mm_set1_epi32(0);
	PW[6].lower.m128i = PW[6].upper.m128i = _mm_set1_epi32(0);
	PW[7].lower.m128i = PW[7].upper.m128i = _mm_set1_epi32(0);
	PW[8].lower.m128i = PW[8].upper.m128i = _mm_set1_epi32(0);
	PW[9].lower.m128i = PW[9].upper.m128i = _mm_set1_epi32(0);
	PW[10].lower.m128i = PW[10].upper.m128i = _mm_set1_epi32(0);
	PW[11].lower.m128i = PW[11].upper.m128i = _mm_set1_epi32(0);
	PW[12].lower.m128i = PW[12].upper.m128i = _mm_set1_epi32(0);
	PW[13].lower.m128i = PW[13].upper.m128i = _mm_set1_epi32(0);
	PW[14].lower.m128i = PW[14].upper.m128i = _mm_set1_epi32(0);
	PW[15].lower.m128i = PW[15].upper.m128i = _mm_set1_epi32(12 * 8);
	PW[16].lower.m128i = PW[16].upper.m128i = ROTL(1, _mm_xor_si128(_mm_xor_si128(PW[16 - 3].lower.m128i, PW[16 - 8].lower.m128i), PW[16 - 14].lower.m128i));
	for (int32_t t = 17; t < 80; ++t)
		PW[t].lower.m128i = PW[t].upper.m128i = ROTL(1, _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(PW[(t)-3].lower.m128i, PW[(t)-8].lower.m128i), PW[(t)-14].lower.m128i), PW[(t)-16].lower.m128i));

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte_local[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte_local[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte_local[indexKey3];
				
				W0.lower.m128i_u32[0] = (((key[0] & 0xf8) | 0x00) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.lower.m128i_u32[1] = (((key[0] & 0xf8) | 0x01) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.lower.m128i_u32[2] = (((key[0] & 0xf8) | 0x02) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.lower.m128i_u32[3] = (((key[0] & 0xf8) | 0x03) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];

				W0.upper.m128i_u32[0] = (((key[0] & 0xf8) | 0x04) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.upper.m128i_u32[1] = (((key[0] & 0xf8) | 0x05) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.upper.m128i_u32[2] = (((key[0] & 0xf8) | 0x06) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W0.upper.m128i_u32[3] = (((key[0] & 0xf8) | 0x07) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];

#ifdef _M_X64
				SHA1_GenerateTripcodesWithOptimization_x64_AVX2(&W0, PW, W0Shifted, ABC);
#else
				SHA1_GenerateTripcodesWithOptimization_x86_AVX2(&W0, PW, W0Shifted, ABC);
#endif

				rawTripcodeArray[0][0] = ABC[0].lower.m128i_u32[0];
				rawTripcodeArray[0][1] = ABC[1].lower.m128i_u32[0];
				rawTripcodeArray[0][2] = ABC[2].lower.m128i_u32[0];

				rawTripcodeArray[1][0] = ABC[0].lower.m128i_u32[1];
				rawTripcodeArray[1][1] = ABC[1].lower.m128i_u32[1];
				rawTripcodeArray[1][2] = ABC[2].lower.m128i_u32[1];

				rawTripcodeArray[2][0] = ABC[0].lower.m128i_u32[2];
				rawTripcodeArray[2][1] = ABC[1].lower.m128i_u32[2];
				rawTripcodeArray[2][2] = ABC[2].lower.m128i_u32[2];

				rawTripcodeArray[3][0] = ABC[0].lower.m128i_u32[3];
				rawTripcodeArray[3][1] = ABC[1].lower.m128i_u32[3];
				rawTripcodeArray[3][2] = ABC[2].lower.m128i_u32[3];

				rawTripcodeArray[4][0] = ABC[0].upper.m128i_u32[0];
				rawTripcodeArray[4][1] = ABC[1].upper.m128i_u32[0];
				rawTripcodeArray[4][2] = ABC[2].upper.m128i_u32[0];

				rawTripcodeArray[5][0] = ABC[0].upper.m128i_u32[1];
				rawTripcodeArray[5][1] = ABC[1].upper.m128i_u32[1];
				rawTripcodeArray[5][2] = ABC[2].upper.m128i_u32[1];

				rawTripcodeArray[6][0] = ABC[0].upper.m128i_u32[2];
				rawTripcodeArray[6][1] = ABC[1].upper.m128i_u32[2];
				rawTripcodeArray[6][2] = ABC[2].upper.m128i_u32[2];

				rawTripcodeArray[7][0] = ABC[0].upper.m128i_u32[3];
				rawTripcodeArray[7][1] = ABC[1].upper.m128i_u32[3];
				rawTripcodeArray[7][2] = ABC[2].upper.m128i_u32[3];

				numGeneratedTripcodes += 8;
			
				LOOK_FOR_POSSIBLE_MATCH(8)
			}
		}
	}

	return numGeneratedTripcodes;
}

#if FALSE

extern "C" void SHA1_GenerateTripcodes_x86_SSE2(void *W, void *rawTripcodeArray, void *ABC);
extern "C" void SHA1_GenerateTripcodes_x86_AVX (void *W, void *rawTripcodeArray, void *ABC);

static uint32_t SearchForTripcodesWithoutOptimization()
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	int32_t            pos, maxPos = (searchMode == SEARCH_MODE_FLEXIBLE) ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN) : (0);
	uint32_t   rawTripcodeArray[4][3];
	sha1_vector W[80], ABC[3];
	
 	void           (*SHA1_GenerateTripcodes)(void *, void *, void *) = 
		(options.isAVXEnabled && IsAVXSupported())
#ifdef _M_X64
		    ? SHA1_GenerateTripcodes_x64_AVX : SHA1_GenerateTripcodes_x64_SSE2;
#else
		    ? SHA1_GenerateTripcodes_x86_AVX : SHA1_GenerateTripcodes_x86_SSE2;
#endif

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

	for (int32_t indexKey1 = 0; indexKey1 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey1) {
		key[1] = keyCharTable_SecondByteAndOneByte[indexKey1];

		for (int32_t indexKey2 = 0; indexKey2 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey2) {
			key[2] = keyCharTable_FirstByte[indexKey2];

			for (int32_t indexKey3 = 0; indexKey3 <= CPU_SHA1_MAX_INDEX_FOR_KEYS; ++indexKey3) {
				key[3] = keyCharTable_SecondByteAndOneByte[indexKey3];
				
				W[0].m128i_u32[0] = (((key[0] & 0xfc) | 0x00) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[1] = (((key[0] & 0xfc) | 0x01) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[2] = (((key[0] & 0xfc) | 0x02) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];
				W[0].m128i_u32[3] = (((key[0] & 0xfc) | 0x03) << 24) | (key[1] << 16) | (key[ 2] << 8) | key[ 3];

				(*SHA1_GenerateTripcodes)(W, rawTripcodeArray, ABC);

				rawTripcodeArray[0][0] = ABC[0].m128i_u32[0];
				rawTripcodeArray[0][1] = ABC[1].m128i_u32[0];
				rawTripcodeArray[0][2] = ABC[2].m128i_u32[0];

				rawTripcodeArray[1][0] = ABC[0].m128i_u32[1];
				rawTripcodeArray[1][1] = ABC[1].m128i_u32[1];
				rawTripcodeArray[1][2] = ABC[2].m128i_u32[1];

				rawTripcodeArray[2][0] = ABC[0].m128i_u32[2];
				rawTripcodeArray[2][1] = ABC[1].m128i_u32[2];
				rawTripcodeArray[2][2] = ABC[2].m128i_u32[2];

				rawTripcodeArray[3][0] = ABC[0].m128i_u32[3];
				rawTripcodeArray[3][1] = ABC[1].m128i_u32[3];
				rawTripcodeArray[3][2] = ABC[2].m128i_u32[3];

				numGeneratedTripcodes += 4;
			
				LOOK_FOR_POSSIBLE_MATCH
			}
		}
	}

	return numGeneratedTripcodes;
}

#endif

#if _MSC_VER

#include <stdint.h>
#include <intrin.h>

void run_cpuid(uint32_t eax, uint32_t ecx, int32_t *abcd)
{
    __cpuidex(abcd, eax, ecx);
}     

int32_t check_xcr0_ymm() 
{
    uint32_t xcr0;
    xcr0 = (uint32_t)_myxgetbv(0);
    return ((xcr0 & 6) == 6); /* checking if xmm and ymm state are enabled in XCR0 */
}

int32_t check_4th_gen_intel_core_features()
{
    int32_t abcd[4];
    uint32_t fma_movbe_osxsave_mask = ((1 << 12) | (1 << 22) | (1 << 27));
    uint32_t avx2_bmi12_mask = (1 << 5) | (1 << 3) | (1 << 8);
 
    /* CPUID.(EAX=01H, ECX=0H):ECX.FMA[bit 12]==1   && 
       CPUID.(EAX=01H, ECX=0H):ECX.MOVBE[bit 22]==1 && 
       CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1 */
    run_cpuid( 1, 0, abcd );
    if ( (abcd[2] & fma_movbe_osxsave_mask) != fma_movbe_osxsave_mask ) 
        return 0;
 
    if ( ! check_xcr0_ymm() )
        return 0;
 
    /*  CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1  &&
        CPUID.(EAX=07H, ECX=0H):EBX.BMI1[bit 3]==1  &&
        CPUID.(EAX=07H, ECX=0H):EBX.BMI2[bit 8]==1  */
    run_cpuid( 7, 0, abcd );
    if ( (abcd[1] & avx2_bmi12_mask) != avx2_bmi12_mask ) 
        return 0;
 
    /* CPUID.(EAX=80000001H):ECX.LZCNT[bit 5]==1 */
    run_cpuid( 0x80000001, 0, abcd );
    if ( (abcd[2] & (1 << 5)) == 0)
        return 0;
 
    return 1;
}

int32_t IsAVX2Supported()
{
    static int32_t the_4th_gen_features_available = -1;
    /* test is performed once */
    if (the_4th_gen_features_available < 0 )
        the_4th_gen_features_available = check_4th_gen_intel_core_features();
 
    return the_4th_gen_features_available;
}

#else

int32_t IsAVX2Supported()
{
	return __builtin_cpu_supports("avx2");
}

#endif

void Thread_SearchForSHA1TripcodesOnCPU()
{
	BOOL useAVX2 = options.isAVX2Enabled && IsAVX2Supported();

	while (!GetTerminationState()) {
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);

		uint32_t numGeneratedTripcodes = (useAVX2) ? SearchForTripcodesWithOptimization_AVX2()
			                                           : SearchForTripcodesWithOptimization();
		AddToNumGeneratedTripcodesByCPU(numGeneratedTripcodes);
	}
}
