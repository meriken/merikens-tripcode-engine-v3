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



#define CUDA_SHA1_MAX_PASS_COUNT            2048  // Be VERY CAREFUL when you change this constant.
#define CUDA_SHA1_NUM_THREADS_PER_BLOCK     128



///////////////////////////////////////////////////////////////////////////////
// VARIABLES FOR CUDA CODES                                                  //
///////////////////////////////////////////////////////////////////////////////

__device__ __constant__ unsigned char   cudaKeyCharTable_OneByte[SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char   cudaKeyCharTable_FirstByte  [SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char   cudaKeyCharTable_SecondByte [SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char   cudaKeyCharTable_SecondByteAndOneByte[SIZE_KEY_CHAR_TABLE];
__device__ __constant__ char            CUDA_base64CharTable[64];
__device__ __constant__ unsigned char   CUDA_smallChunkBitmap[SMALL_CHUNK_BITMAP_SIZE];



///////////////////////////////////////////////////////////////////////////////
// SHA-1 HASH GENERATION ON CUDA DEVICE                                      //
///////////////////////////////////////////////////////////////////////////////

// Macros are used extensively for the sake of optimization.
// Good luck deciphering!

// The following are marcos and constants for SHA-1 hash generation.

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
#define ROTL(bits, val) (((val) << (bits)) | ((val) >> (32 - (bits))))

// Central routine for calculating the hash value. See the FIPS
// 180-3 standard p. 17f for a detailed explanation.
#define f1 	( ( B & C ) ^ ( ( ~ B ) & D ) )
#define f2  ( B ^ C ^ D )
#define f3  ( ( B & C ) ^ ( B & D ) ^ ( C & D ) )
#define f4  f2

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

#define SET_KEY_CHAR(var, flag, table, value)             \
	if (!(flag)) {                                        \
		var = (table)[(value)];                           \
		isSecondByte = IS_FIRST_BYTE_SJIS(var);           \
	} else {                                              \
		var = cudaKeyCharTable_SecondByte[(value)];          \
		isSecondByte = FALSE;                             \
	}                                                     \

#define ROUND_00_TO_19(t, w)                              \
		{                                                 \
			tmp = (ROTL(5, A) + f1 + E + (w) + K0);       \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define ROUND_20_TO_39(t, w)                              \
		{                                                 \
			tmp = (ROTL(5, A) + f2 + E + (w) + K1);       \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define ROUND_40_TO_59(t, w)                              \
		{                                                 \
			tmp = (ROTL(5, A) + f3 + E + (w) + K2);       \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define	ROUND_60_TO_79(t, w)                              \
		{                                                 \
			tmp = (ROTL(5, A) + f4 + E + (w) + K3 );      \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define CUDA_SHA1_DEFINE_SEARCH_FUNCTION(functionName) \
__global__ void (functionName)(\
	GPUOutput     *outputArray,\
	unsigned char *chunkBitmap,\
	uint32_t  *tripcodeChunkArray,\
	uint32_t   numTripcodeChunk,\
	unsigned char *keyAndRandomBytes\
) {

#define CUDA_SHA1_BEFORE_SEARCHING                                                                         \
	uint32_t        A, B, C, D, E, tmp;                                                                \
	unsigned char       key0, key1, key2, key3, key11;                                                     \
	unsigned char       found = 0;                                                                         \
	BOOL                isSecondByte = FALSE;                                                              \
	unsigned char      *tableForKey2;                                                                      \
	GPUOutput          *output = &outputArray[blockIdx.x * CUDA_SHA1_NUM_THREADS_PER_BLOCK + threadIdx.x]; \
    int32_t                 passCount;                                                                         \
	int32_t                 randomByte2 = keyAndRandomBytes[2];                                                         \
	int32_t                 randomByte3 = keyAndRandomBytes[3];                                                         \
	                                                                                                       \
	output->numMatchingTripcodes = 0;                                                                      \
	SET_KEY_CHAR(key0, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[0] + (blockIdx.x >> 6));        \
	SET_KEY_CHAR(key1, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[1] + (threadIdx.x & 0x3f));     \
	tableForKey2 = (isSecondByte) ? (cudaKeyCharTable_SecondByte) : (cudaKeyCharTable_FirstByte);        \
	key11 = cudaKeyCharTable_SecondByteAndOneByte[keyAndRandomBytes[11] + (blockIdx.x & 0x3f)];                    \
	                                                                                                       \
	__shared__ uint32_t PW[80+1];                                                                        \
	__shared__ unsigned char smallChunkBitmap[SMALL_CHUNK_BITMAP_SIZE];                                        \
	if (threadIdx.x == 0) {                                                                                \
		PW[0]  = 0;                                                                                        \
		PW[1]  = (keyAndRandomBytes[4] << 24) | (keyAndRandomBytes[5] << 16) | (keyAndRandomBytes[ 6] << 8) | keyAndRandomBytes[ 7];           \
		PW[2]  = (keyAndRandomBytes[8] << 24) | (keyAndRandomBytes[9] << 16) | (keyAndRandomBytes[10] << 8) | key11;                  \
		PW[3]  = 0x80000000;                                                                               \
		PW[4]  = 0;                                                                                        \
		PW[5]  = 0;                                                                                        \
		PW[6]  = 0;                                                                                        \
		PW[7]  = 0;                                                                                        \
		PW[8]  = 0;                                                                                        \
		PW[9]  = 0;                                                                                        \
		PW[10] = 0;                                                                                        \
		PW[11] = 0;                                                                                        \
		PW[12] = 0;                                                                                        \
		PW[13] = 0;                                                                                        \
		PW[14] = 0;                                                                                        \
		PW[15] = 12 * 8;                                                                                   \
		PW[16] = ROTL(1, PW[16 - 3] ^ PW[16 - 8] ^ PW[16 - 14]);                                           \
		for (int32_t t = 17; t < 80; ++t)                                                                      \
			PW[t] = ROTL(1, PW[(t) - 3] ^ PW[(t) - 8] ^ PW[(t) - 14] ^ PW[(t) - 16]);                      \
			                                                                                               \
		for (int32_t i = 0; i < SMALL_CHUNK_BITMAP_SIZE; ++i)                                                    \
			smallChunkBitmap[i] = CUDA_smallChunkBitmap[i];                                                    \
	}                                                                                                      \
	__syncthreads();                                                                                       \
	randomByte2 += ((threadIdx.x & 0x40) >> 1);                                                            \
	                                                                                                       \
	for (passCount = 0; passCount < CUDA_SHA1_MAX_PASS_COUNT; passCount++){                                \
		__syncthreads();                                                                                   \
		                                                                                                   \
		key2 = tableForKey2[randomByte2 + (passCount >> 6)];                                               \
		key3 = cudaKeyCharTable_SecondByteAndOneByte[randomByte3 + (passCount & 63)];                     \
		                                                                                                   \
		A = H0;                                                                                            \
		B = H1;                                                                                            \
		C = H2;                                                                                            \
		D = H3;                                                                                            \
		E = H4;                                                                                            \
		                                                                                                   \
		uint32_t W0   = (key0 << 24) | (key1 << 16) | (key2 << 8) | key3;                              \
		uint32_t W0_1 = ROTL(1,  W0);                                                                  \
		uint32_t W0_2 = ROTL(2,  W0);                                                                  \
		uint32_t W0_3 = ROTL(3,  W0);                                                                  \
		uint32_t W0_4 = ROTL(4,  W0);                                                                  \
		uint32_t W0_5 = ROTL(5,  W0);                                                                  \
		uint32_t W0_6 = ROTL(6,  W0);                                                                  \
		uint32_t W0_7 = ROTL(7,  W0);                                                                  \
		uint32_t W0_8 = ROTL(8,  W0);                                                                  \
		uint32_t W0_9 = ROTL(9,  W0);                                                                  \
		uint32_t W010 = ROTL(10, W0);                                                                  \
		uint32_t W011 = ROTL(11, W0);                                                                  \
		uint32_t W012 = ROTL(12, W0);                                                                  \
		uint32_t W013 = ROTL(13, W0);                                                                  \
		uint32_t W014 = ROTL(14, W0);                                                                  \
		uint32_t W015 = ROTL(15, W0);                                                                  \
		uint32_t W016 = ROTL(16, W0);                                                                  \
		uint32_t W017 = ROTL(17, W0);                                                                  \
		uint32_t W018 = ROTL(18, W0);                                                                  \
		uint32_t W019 = ROTL(19, W0);                                                                  \
		uint32_t W020 = ROTL(20, W0);                                                                  \
		uint32_t W021 = ROTL(21, W0);                                                                  \
		uint32_t W022 = ROTL(22, W0);                                                                  \
		uint32_t W0_6___W0_4        = W0_6        ^ W0_4;                                              \
		uint32_t W0_6___W0_4___W0_7 = W0_6___W0_4 ^ W0_7;                                              \
		uint32_t W0_8___W0_4        = W0_8        ^ W0_4;                                              \
		uint32_t W0_8___W012        = W0_8        ^ W012;                                              \
		                                                                                                   \
		ROUND_00_TO_19(0,  W0);                                                                            \
		ROUND_00_TO_19(1,  PW[1]);                                                                         \
		ROUND_00_TO_19(2,  PW[2]);                                                                         \
		ROUND_00_TO_19(3,  PW[3]);                                                                         \
		ROUND_00_TO_19(4,  PW[4]);                                                                         \
		ROUND_00_TO_19(5,  PW[5]);                                                                         \
		ROUND_00_TO_19(6,  PW[6]);                                                                         \
		ROUND_00_TO_19(7,  PW[7]);                                                                         \
		ROUND_00_TO_19(8,  PW[8]);                                                                         \
		ROUND_00_TO_19(9,  PW[9]);                                                                         \
		ROUND_00_TO_19(10, PW[10]);                                                                        \
		ROUND_00_TO_19(11, PW[11]);                                                                        \
		ROUND_00_TO_19(12, PW[12]);                                                                        \
		ROUND_00_TO_19(13, PW[13]);                                                                        \
		ROUND_00_TO_19(14, PW[14]);                                                                        \
		ROUND_00_TO_19(15, PW[15]);                                                                        \
		                                                                                                   \
		ROUND_00_TO_19(16, PW[16] ^ W0_1                                   );                              \
		ROUND_00_TO_19(17, PW[17]                                          );                              \
		ROUND_00_TO_19(18, PW[18]                                          );                              \
		ROUND_00_TO_19(19, PW[19] ^ W0_2                                   );                              \
		                                                                                                   \
		ROUND_20_TO_39(20, PW[20]                                          );                              \
		ROUND_20_TO_39(21, PW[21]                                          );                              \
		ROUND_20_TO_39(22, PW[22] ^ W0_3                                   );                              \
		ROUND_20_TO_39(23, PW[23]                                          );                              \
		ROUND_20_TO_39(24, PW[24] ^ W0_2                                   );                              \
		ROUND_20_TO_39(25, PW[25] ^ W0_4                                   );                              \
		ROUND_20_TO_39(26, PW[26]                                          );                              \
		ROUND_20_TO_39(27, PW[27]                                          );                              \
		ROUND_20_TO_39(28, PW[28] ^ W0_5                                   );                              \
		ROUND_20_TO_39(29, PW[29]                                          );                              \
		ROUND_20_TO_39(30, PW[30] ^ W0_4 ^ W0_2                            );                              \
		ROUND_20_TO_39(31, PW[31] ^ W0_6                                   );                              \
		ROUND_20_TO_39(32, PW[32] ^ W0_3 ^ W0_2                            );                              \
		ROUND_20_TO_39(33, PW[33]                                          );                              \
		ROUND_20_TO_39(34, PW[34] ^ W0_7                                   );                              \
		ROUND_20_TO_39(35, PW[35] ^ W0_4                                   );                              \
		ROUND_20_TO_39(36, PW[36] ^ W0_6___W0_4                            );                              \
		ROUND_20_TO_39(37, PW[37] ^ W0_8                                   );                              \
		ROUND_20_TO_39(38, PW[38] ^ W0_4                                   );                              \
		ROUND_20_TO_39(39, PW[39]                                          );                              \
		                                                                                                   \
		ROUND_40_TO_59(40, PW[40] ^ W0_4 ^ W0_9                            );                              \
		ROUND_40_TO_59(41, PW[41]                                          );                              \
		ROUND_40_TO_59(42, PW[42] ^ W0_6 ^ W0_8                            );                              \
		ROUND_40_TO_59(43, PW[43] ^ W010                                   );                              \
		ROUND_40_TO_59(44, PW[44] ^ W0_6 ^ W0_3 ^ W0_7                     );                              \
		ROUND_40_TO_59(45, PW[45]                                          );                              \
		ROUND_40_TO_59(46, PW[46] ^ W0_4 ^ W011                            );                              \
		ROUND_40_TO_59(47, PW[47] ^ W0_8___W0_4                            );                              \
		ROUND_40_TO_59(48, PW[48] ^ W0_8___W0_4 ^ W0_3 ^ W010 ^ W0_5       );                              \
		ROUND_40_TO_59(49, PW[49] ^ W012                                   );                              \
		ROUND_40_TO_59(50, PW[50] ^ W0_8                                   );                              \
		ROUND_40_TO_59(51, PW[51] ^ W0_6___W0_4                            );                              \
		ROUND_40_TO_59(52, PW[52] ^ W0_8___W0_4 ^ W013                     );                              \
		ROUND_40_TO_59(53, PW[53]                                          );                              \
		ROUND_40_TO_59(54, PW[54] ^ W0_7 ^ W010 ^ W012                     );                              \
		ROUND_40_TO_59(55, PW[55] ^ W014                                   );                              \
		ROUND_40_TO_59(56, PW[56] ^ W0_6___W0_4___W0_7 ^ W011 ^ W010       );                              \
		ROUND_40_TO_59(57, PW[57] ^ W0_8                                   );                              \
		ROUND_40_TO_59(58, PW[58] ^ W0_8___W0_4 ^ W015                     );                              \
		ROUND_40_TO_59(59, PW[59] ^ W0_8___W012                            );                              \
		                                                                                                   \
		ROUND_60_TO_79(60, PW[60] ^ W0_8___W012 ^ W0_4 ^ W0_7 ^ W014       );                              \
		ROUND_60_TO_79(61, PW[61] ^ W016                                   );                              \
		ROUND_60_TO_79(62, PW[62] ^ W0_6___W0_4 ^ W0_8___W012              );                              \
		ROUND_60_TO_79(63, PW[63] ^ W0_8                                   );                              \
		ROUND_60_TO_79(64, PW[64] ^ W0_6___W0_4___W0_7 ^ W0_8___W012 ^ W017);                              \
		ROUND_60_TO_79(65, PW[65]                                          );                              \
		ROUND_60_TO_79(66, PW[66] ^ W014 ^ W016                            );                              \
		ROUND_60_TO_79(67, PW[67] ^ W0_8 ^ W018                            );                              \
		ROUND_60_TO_79(68, PW[68] ^ W011 ^ W014 ^ W015                     );                              \
		ROUND_60_TO_79(69, PW[69]                                          );                              \
		ROUND_60_TO_79(70, PW[70] ^ W012 ^ W019                            );                              \
		ROUND_60_TO_79(71, PW[71] ^ W012 ^ W016                            );                              \
		ROUND_60_TO_79(72, PW[72] ^ W011 ^ W012 ^ W018 ^ W013 ^ W016 ^ W0_5);                              \
		ROUND_60_TO_79(73, PW[73] ^ W020                                   );                              \
		ROUND_60_TO_79(74, PW[74] ^ W0_8 ^ W016                            );                              \
		ROUND_60_TO_79(75, PW[75] ^ W0_6 ^ W012 ^ W014                     );                              \
		ROUND_60_TO_79(76, PW[76] ^ W0_7 ^ W0_8 ^ W012 ^ W016 ^ W021       );                              \
		ROUND_60_TO_79(77, PW[77]                                          );                              \
		ROUND_60_TO_79(78, PW[78] ^ W0_7 ^ W0_8 ^ W015 ^ W018 ^ W020       );                              \
		ROUND_60_TO_79(79, PW[79] ^ W0_8 ^ W022                            );                              \
		                                                                                                   \
		A += H0;                                                                                           \
		B += H1;                                                                                           \
		C += H2;                                                                                           \
		                                                                                                   \
		uint32_t tripcodeChunk = A >> 2;                                                               \

#define CUDA_SHA1_USE_SMALL_CHUNK_BITMAP                                                     \
		if (smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) \
			continue;                                                                      \

#define CUDA_SHA1_USE_CHUNK_BITMAP \
		if (chunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]) \
			continue;

#define CUDA_SHA1_LINEAR_SEARCH \
	for (uint32_t i = 0; i < numTripcodeChunk; i++){ \
		if (tripcodeChunkArray[i] == tripcodeChunk) { \
			found = 1; \
			break; \
		} \
	} \
	if (found) \
		break;

#define CUDA_SHA1_BINARY_SEARCH \
		{\
			int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;         \
			while (tripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) { \
				middle = (lower + upper) >> 1;                                          \
				if (tripcodeChunk > tripcodeChunkArray[middle]) {                   \
					lower = middle + 1;                                                 \
				} else {                                                                \
					upper = middle - 1;                                                 \
				}                                                                       \
			}                                                                           \
			if (tripcodeChunk == tripcodeChunkArray[middle]) {                      \
				found = 1;                                                              \
				break;                                                                  \
			} \
		}

#define CUDA_SHA1_END_OF_SEAERCH_FUNCTION \
	}\
	if (!found) {\
		output->numGeneratedTripcodes = CUDA_SHA1_MAX_PASS_COUNT;  \
	} else {\
		TripcodeKeyPair *pair = &(output->pair);\
		pair->key.c[0]  = key0;\
		pair->key.c[1]  = key1;\
		pair->key.c[2]  = key2;\
		pair->key.c[3]  = key3;\
		pair->key.c[7]  = keyAndRandomBytes[7];\
		pair->key.c[11] = key11;\
		pair->tripcode.c[0]  = CUDA_base64CharTable[ A >> 26                  ];\
		pair->tripcode.c[1]  = CUDA_base64CharTable[(A >> 20          ) & 0x3f];\
		pair->tripcode.c[2]  = CUDA_base64CharTable[(A >> 14          ) & 0x3f];\
		pair->tripcode.c[3]  = CUDA_base64CharTable[(A >>  8          ) & 0x3f];\
		pair->tripcode.c[4]  = CUDA_base64CharTable[(A >>  2          ) & 0x3f];\
		pair->tripcode.c[5]  = CUDA_base64CharTable[(B >> 28 | A <<  4) & 0x3f];\
		pair->tripcode.c[6]  = CUDA_base64CharTable[(B >> 22          ) & 0x3f];\
		pair->tripcode.c[7]  = CUDA_base64CharTable[(B >> 16          ) & 0x3f];\
		pair->tripcode.c[8]  = CUDA_base64CharTable[(B >> 10          ) & 0x3f];\
		pair->tripcode.c[9]  = CUDA_base64CharTable[(B >>  4          ) & 0x3f];\
		pair->tripcode.c[10] = CUDA_base64CharTable[(B <<  2 | C >> 30) & 0x3f];\
		pair->tripcode.c[11] = CUDA_base64CharTable[(C >> 24          ) & 0x3f];\
		output->numMatchingTripcodes = 1;\
		output->numGeneratedTripcodes = passCount + 1;\
	}\
}

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_ForwardMatching_1Chunk)
	uint32_t      tripcodeChunk0 = tripcodeChunkArray[0];
CUDA_SHA1_BEFORE_SEARCHING
	if (tripcodeChunk == tripcodeChunk0) {
		found = 1;
		break;
	}
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_ForwardMatching_Simple)
CUDA_SHA1_BEFORE_SEARCHING
	CUDA_SHA1_USE_SMALL_CHUNK_BITMAP
	CUDA_SHA1_LINEAR_SEARCH
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_ForwardMatching)
CUDA_SHA1_BEFORE_SEARCHING
	CUDA_SHA1_USE_SMALL_CHUNK_BITMAP
	CUDA_SHA1_USE_CHUNK_BITMAP
	CUDA_SHA1_BINARY_SEARCH
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_BackwardMatching_Simple)
CUDA_SHA1_BEFORE_SEARCHING
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff);
	CUDA_SHA1_USE_SMALL_CHUNK_BITMAP
	CUDA_SHA1_LINEAR_SEARCH
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_BackwardMatching)
CUDA_SHA1_BEFORE_SEARCHING
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff);
	CUDA_SHA1_USE_SMALL_CHUNK_BITMAP
	CUDA_SHA1_USE_CHUNK_BITMAP
	CUDA_SHA1_BINARY_SEARCH
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_Flexible_Simple)
CUDA_SHA1_BEFORE_SEARCHING

#define PERFORM_LINEAR_SEARCH_IF_NECESSARY                                           \
	if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
		CUDA_SHA1_LINEAR_SEARCH                                                      \
	}                                                                                \

	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A <<  4) & 0x3fffffff) | ((B >> 28) & 0x0000000f); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 10) & 0x3fffffff) | ((B >> 22) & 0x000003ff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 16) & 0x3fffffff) | ((B >> 16) & 0x0000ffff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 22) & 0x3fffffff) | ((B >> 10) & 0x003fffff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 28) & 0x3fffffff) | ((B >>  4) & 0x0fffffff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  2) & 0x3fffffff) | ((C >> 30) & 0x00000003); PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_Flexible)
CUDA_SHA1_BEFORE_SEARCHING

#define PERFORM_BINARY_SEARCH_IF_NECESSARY                                              \
	if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]    \
	    && !chunkBitmap     [tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING      ) * 6)]) { \
		CUDA_SHA1_BINARY_SEARCH                                                         \
	}                                                                                   \

	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A <<  4) & 0x3fffffff) | ((B >> 28) & 0x0000000f); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 10) & 0x3fffffff) | ((B >> 22) & 0x000003ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 16) & 0x3fffffff) | ((B >> 16) & 0x0000ffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 22) & 0x3fffffff) | ((B >> 10) & 0x003fffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((A << 28) & 0x3fffffff) | ((B >>  4) & 0x0fffffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  2) & 0x3fffffff) | ((C >> 30) & 0x00000003); PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_ForwardAndBackwardMatching_Simple)
CUDA_SHA1_BEFORE_SEARCHING
	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
CUDA_SHA1_END_OF_SEAERCH_FUNCTION

CUDA_SHA1_DEFINE_SEARCH_FUNCTION(CUDA_SHA1_PerformSearching_ForwardAndBackwardMatching)
CUDA_SHA1_BEFORE_SEARCHING
	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
CUDA_SHA1_END_OF_SEAERCH_FUNCTION



///////////////////////////////////////////////////////////////////////////////
// CUDA SEARCH THREAD FOR 12 CHARACTER TRIPCODES                             //
///////////////////////////////////////////////////////////////////////////////

void Thread_SearchForSHA1TripcodesOnCUDADevice(CUDADeviceSearchThreadInfo *info)
{
	cudaDeviceProp CUDADeviceProperties;
	uint32_t         numBlocksPerSM;
	uint32_t         numBlocksPerGrid;
	GPUOutput *outputArray = NULL;
	GPUOutput *CUDA_outputArray = NULL;
	uint32_t     *CUDA_tripcodeChunkArray = NULL;
	unsigned char      *CUDA_chunkBitmap = NULL;
	unsigned char      *cudaKeyAndRandomBytes;
	uint32_t      sizeOutputArray;
	unsigned char       key[MAX_LEN_TRIPCODE + 1];
	char        status[LEN_LINE_BUFFER_FOR_SCREEN] = "";
	double      timeElapsed = 0;
	double      numGeneratedTripcodes = 0;
	double      speed = 0;
	uint64_t       startingTime;
	uint64_t       endingTime;
	double      deltaTime;

	key[lenTripcode] = '\0';
	
	CUDA_ERROR(cudaSetDevice(info->CUDADeviceIndex));
	CUDA_ERROR(cudaGetDeviceProperties(&CUDADeviceProperties, info->CUDADeviceIndex));
	if (CUDADeviceProperties.computeMode == cudaComputeModeProhibited) {
		sprintf(status, "[disabled]");
		UpdateCUDADeviceStatus(info, status);
		return;
	}

	numBlocksPerSM = options.CUDANumBlocksPerSM;
	numBlocksPerGrid = numBlocksPerSM * CUDADeviceProperties.multiProcessorCount;
	sizeOutputArray = CUDA_SHA1_NUM_THREADS_PER_BLOCK * numBlocksPerGrid;
	outputArray = (GPUOutput *)malloc(sizeof(GPUOutput) * sizeOutputArray);
	ERROR0(outputArray == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_outputArray, sizeof(GPUOutput) * sizeOutputArray));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_chunkBitmap, CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_tripcodeChunkArray, sizeof(uint32_t) * numTripcodeChunk)); 
	CUDA_ERROR(cudaMalloc((void **)&cudaKeyAndRandomBytes, sizeof(unsigned char) * 12)); 
 
	info->mutex.lock();
	CUDA_ERROR(cudaMemcpy(CUDA_tripcodeChunkArray, tripcodeChunkArray, sizeof(uint32_t) * numTripcodeChunk, cudaMemcpyHostToDevice));
	CUDA_ERROR(cudaMemcpy(CUDA_chunkBitmap, chunkBitmap, CHUNK_BITMAP_SIZE, cudaMemcpyHostToDevice));
	CUDA_ERROR(cudaMemcpyToSymbol(CUDA_base64CharTable,                   base64CharTable,                    sizeof(base64CharTable)));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_OneByte,              keyCharTable_OneByte,               SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,            keyCharTable_FirstByte,             SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,           keyCharTable_SecondByte,            SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByteAndOneByte, keyCharTable_SecondByteAndOneByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(CUDA_smallChunkBitmap,                    smallChunkBitmap,                     SMALL_CHUNK_BITMAP_SIZE));
	info->mutex.unlock();

	startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;

	while (!GetTerminationState()) {
		// Choose a random key.
		SetCharactersInTripcodeKeyForSHA1Tripcode(key);
		if (!IsValidKey(key))
			continue;
		for (int32_t i = 0; i < 4; ++i)
			key[i] = RandomByte();
		key[11] = RandomByte();
				
		// Call an appropriate CUDA function.
		CUDA_ERROR(cudaMemcpy(cudaKeyAndRandomBytes, key, 12, cudaMemcpyHostToDevice));
		dim3 dimBlock(CUDA_SHA1_NUM_THREADS_PER_BLOCK);
		dim3 dimGrid(numBlocksPerGrid);
		if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
			if (numTripcodeChunk == 1) {
				CUDA_SHA1_PerformSearching_ForwardMatching_1Chunk<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			} else if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_SHA1_PerformSearching_ForwardMatching_Simple<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			} else {
				CUDA_SHA1_PerformSearching_ForwardMatching<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			}
		
		} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
			if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_SHA1_PerformSearching_BackwardMatching_Simple<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			} else {
				CUDA_SHA1_PerformSearching_BackwardMatching<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			}

		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
			if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_SHA1_PerformSearching_ForwardAndBackwardMatching_Simple<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			} else {
				CUDA_SHA1_PerformSearching_ForwardAndBackwardMatching<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			}
		} else {
			// Flexible search
			if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_SHA1_PerformSearching_Flexible_Simple<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			} else {
				CUDA_SHA1_PerformSearching_Flexible<<<dimGrid, dimBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
				    cudaKeyAndRandomBytes);
			}
		}
		CUDA_ERROR(cudaGetLastError());

		// Process the output array.
		CUDA_ERROR(cudaMemcpy(outputArray, CUDA_outputArray, sizeOutputArray * sizeof(GPUOutput), cudaMemcpyDeviceToHost));
		numGeneratedTripcodes += ProcessGPUOutput(key, outputArray, sizeOutputArray, TRUE);

		//
		endingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		deltaTime = (endingTime - startingTime) * 0.001;
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);
		startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		timeElapsed += deltaTime;
		speed = numGeneratedTripcodes / timeElapsed;
		sprintf(status,
			    "%.1lfM TPS, %d blocks/SM",
				speed / 1000000,
				numBlocksPerSM);
		UpdateCUDADeviceStatus(info, status);
	}

	RELEASE_AND_SET_TO_NULL(CUDA_outputArray,        cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_tripcodeChunkArray, cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_chunkBitmap,        cudaFree);
	RELEASE_AND_SET_TO_NULL(cudaKeyAndRandomBytes,                 cudaFree);
	RELEASE_AND_SET_TO_NULL(outputArray,             free);
}


