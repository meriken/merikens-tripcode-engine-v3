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
// CONSTANTS AND TYPES                                                       //
///////////////////////////////////////////////////////////////////////////////

typedef int BOOL;
#define TRUE  (1)
#define FALSE (0)

#define MAX_LEN_TRIPCODE            12
#define MAX_LEN_TRIPCODE_KEY        12
#define MAX_LEN_EXPANDED_PATTERN    MAX_LEN_TRIPCODE
#define SMALL_CHUNK_BITMAP_LEN_STRING 2
#define SMALL_CHUNK_BITMAP_SIZE       (64 * 64)
#define CHUNK_BITMAP_LEN_STRING       4
#define OPENCL_SHA1_MAX_PASS_COUNT  2048

#define IS_FIRST_BYTE_SJIS_FULL(c)    \
	(   (0x81 <= (c) && (c) <= 0x84)  \
	 || (0x88 <= (c) && (c) <= 0x9f)  \
	 || (0xe0 <= (c) && (c) <= 0xea)) \

#define IS_FIRST_BYTE_SJIS_CONSERVATIVE(c) \
	(   (0x89 <= (c) && (c) <= 0x97)       \
	 || (0x99 <= (c) && (c) <= 0x9f)       \
	 || (0xe0 <= (c) && (c) <= 0xe9))      \

#ifdef MAXIMIZE_KEY_SPACE
#define IS_FIRST_BYTE_SJIS(c) IS_FIRST_BYTE_SJIS_FULL(c)
#else
#define IS_FIRST_BYTE_SJIS(c) IS_FIRST_BYTE_SJIS_CONSERVATIVE(c)
#endif

typedef struct {
	// unsigned int length;
	unsigned char c[MAX_LEN_TRIPCODE];
} Tripcode;

typedef struct {
	// unsigned int length;
	unsigned char c[MAX_LEN_TRIPCODE_KEY];
} TripcodeKey;

typedef struct {
	Tripcode    tripcode;
	TripcodeKey key;
} TripcodeKeyPair;

typedef struct {
	unsigned char pos;
	unsigned char c[MAX_LEN_EXPANDED_PATTERN + 1];
} ExpandedPattern;

typedef struct {
	unsigned int  numGeneratedTripcodes;
	unsigned char numMatchingTripcodes;
	TripcodeKeyPair pair;
} GPUOutput;



///////////////////////////////////////////////////////////////////////////////
// SHA-1                                                                     //
///////////////////////////////////////////////////////////////////////////////

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)

// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )

#define ROTL( bits, val ) rotate((val), (unsigned int)(bits))

// Central routine for calculating the hash value. See the FIPS
// 180-3 standard p. 17f for a detailed explanation.

// #define f1 	( ( B & C ) ^ ( ( ~ B ) & D ) )
// #define f2  ( B ^ C ^ D )
// #define f3  ( ( B & C ) ^ ( B & D ) ^ ( C & D ) )
// #define f4  f2

#define f1 	bitselect(D, C, B)
#define f2  ( B ^ C ^ D )
#define f3  (bitselect(B, C, D) ^ bitselect(B, 0U, C))
#define f4  f2

#define SET_KEY_CHAR(var, flag, table, value)             \
	if (!(flag)) {                                        \
		var = (table)[(value)];                           \
		isSecondByte = IS_FIRST_BYTE_SJIS(var);           \
	} else {                                              \
		var = keyCharTable_SecondByte[(value)];               \
		isSecondByte = FALSE;                             \
	}                                                     \

#define ROUND_00_TO_15_W(t, w)                            \
		{                                                 \
			W[ t ] = (w);                                 \
			tmp = ( ROTL( 5, A ) + f1 + E + W[ t ] + K0); \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define ROUND_00_TO_15_ZERO(t)                            \
		{                                                 \
			W[ t ] = 0;                                   \
			tmp = ( ROTL( 5, A ) + f1 + E + K0);          \
			E = D;                                        \
			D = C;                                        \
			C = ROTL( 30, B );                            \
			B = A;                                        \
			A = tmp;                                      \
		}                                                 \

#define ROUND_16_TO_19(t)                                        \
		{                                                        \
			W[ t ] = ROTL( 1,   W[ (t) -  3 ] ^ W[ (t) -  8 ]    \
							  ^ W[ (t) - 14 ] ^ W[ (t) - 16 ] ); \
			tmp = ( ROTL( 5, A ) + f1 + E + W[ t ] + K0);        \
			E = D;                                               \
			D = C;                                               \
			C = ROTL( 30, B );                                   \
			B = A;                                               \
			A = tmp;                                             \
		}                                                        \

#define ROUND_20_TO_39(t) \
		{ \
			W[ t ] = ROTL( 1,   W[ (t) -  3 ] ^ W[ (t) -  8 ] \
							  ^ W[ (t) - 14 ] ^ W[ (t) - 16 ] ); \
			tmp = ( ROTL( 5, A ) + f2 + E + W[ t ] + K1); \
			E = D; \
			D = C; \
			C = ROTL( 30, B ); \
			B = A; \
			A = tmp; \
		}

#define ROUND_40_TO_59(t) \
		{ \
			W[ t ] = ROTL( 1,   W[ (t) -  3 ] ^ W[ (t) -  8 ] \
							  ^ W[ (t) - 14 ] ^ W[ (t) - 16 ] ); \
			tmp = ( ROTL( 5, A ) + f3 + E + W[ t ] + K2); \
			E = D; \
			D = C; \
			C = ROTL( 30, B ); \
			B = A; \
			A = tmp; \
		}

#define	ROUND_60_TO_79(t) \
		{ \
			W[ t ] = ROTL( 1,   W[ (t) -  3 ] ^ W[ (t) -  8 ] \
							  ^ W[ (t) - 14 ] ^ W[ (t) - 16 ] ); \
			tmp = ( ROTL( 5, A ) + f4 + E + W[ t ] + K3 ); \
			E = D; \
			D = C; \
			C = ROTL( 30, B ); \
			B = A; \
			A = tmp; \
		}

__constant char base64CharTable[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '/',
};

#define OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(functionName)         \
__kernel void (functionName)(                                    \
	__global   GPUOutput           * const outputArray,          \
	__constant const unsigned char * const key,                  \
	__global   const unsigned int  * const tripcodeChunkArray,   \
	           const unsigned int          numTripcodeChunk,     \
	__constant const unsigned char * const keyCharTable_OneByte, \
	__constant const unsigned char * const keyCharTable_FirstByte,   \
	__constant const unsigned char * const keyCharTable_SecondByte,  \
	__constant const unsigned char * const keyCharTable_SecondByteAndOneByte,  \
 	__constant const unsigned char * const smallChunkBitmap_constant, \
 	__global   const unsigned char * const chunkBitmap             \
) {                                                              \

#define OPENCL_SHA1_BEFORE_SEARCHING                                                                       \
	uint4               W[80], initW0, initW1, initW2;                                                     \
	uint4               A, B, C, D, E, tmp;                                                                \
	unsigned int        A_matching, B_matching, C_matching;                                                \
	int                 vectorIndex;                                                                       \
	unsigned char       key0, key1, key2, key3, key11;                                                     \
	unsigned char       found = 0;                                                                         \
	BOOL                isSecondByte = FALSE;                                                              \
	__global GPUOutput *output = &outputArray[(int)get_global_id(0)];                                      \
    int                 passCount;                                                                         \
	unsigned char       randomByte2 = key[2] + ((get_local_id(0) & 0x40) >> 1);                            \
	unsigned char       randomByte3 = key[3];                                                              \
                                                                                                           \
	uint4 H0 = (0x67452301, 0x67452301, 0x67452301, 0x67452301);                                             \
	uint4 H1 = (0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89);                                             \
	uint4 H2 = (0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe);                                             \
	uint4 H3 = (0x10325476, 0x10325476, 0x10325476, 0x10325476);                                             \
	uint4 H4 = (0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0);                                             \
	                                                                                                       \
	uint4 K0 = (0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999);                                             \
	uint4 K1 = (0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1);                                             \
	uint4 K2 = (0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc);                                             \
	uint4 K3 = (0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6);                                             \
	                                                                                                       \
	output->numMatchingTripcodes = 0;                                                                      \
	key0  = keyCharTable_FirstByte           [key[0 ] + ((int)get_group_id(0) & 0x3f)];                    \
	key1  = keyCharTable_SecondByteAndOneByte[key[1 ] + ((int)get_local_id(0) & 0x3f)];                    \
	key11 = keyCharTable_SecondByteAndOneByte[key[11] + ((int)get_group_id(0) >> 6  )];                    \
	                                                                                                       \
	initW0.xyzw = (key0   << 24) | (key1   << 16);                                                         \
	initW1.xyzw = (key[4] << 24) | (key[5] << 16) | (key[ 6] << 8) | key[7];                               \
	initW2.xyzw = (key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key11;                                \
	                                                                                                       \
	initW1.x = (initW1.x & 0xfffffffc) | 0;                                                                \
	initW1.y = (initW1.y & 0xfffffffc) | 1;                                                                \
	initW1.z = (initW1.z & 0xfffffffc) | 2;                                                                \
	initW1.w = (initW1.w & 0xfffffffc) | 3;                                                                \
	                                                                                                       \
	__local unsigned char smallChunkBitmap[SMALL_CHUNK_BITMAP_SIZE];                                           \
	if (get_local_id(0) == 0) {                                                                            \
		for (int i = 0; i < SMALL_CHUNK_BITMAP_SIZE; ++i)                                                    \
			smallChunkBitmap[i] = smallChunkBitmap_constant[i];                                                \
	}                                                                                                      \
	barrier(CLK_LOCAL_MEM_FENCE);                                                   \
	                                                                                                       \
	for (passCount = 0; passCount < OPENCL_SHA1_MAX_PASS_COUNT; passCount++) {                             \
		key2 = keyCharTable_FirstByte           [randomByte2 + (passCount >> 6)];                          \
		key3 = keyCharTable_SecondByteAndOneByte[randomByte3 + (passCount & 63)];                          \
		                                                                                                   \
		A = H0;\
		B = H1;\
		C = H2;\
		D = H3;\
		E = H4;\
		\
		ROUND_00_TO_15_W(0, initW0 | (uint4)((key2 << 8) | key3, (key2 << 8) | key3, (key2 << 8) | key3, (key2 << 8) | key3));\
		ROUND_00_TO_15_W(1, initW1);\
		ROUND_00_TO_15_W(2, initW2);\
		ROUND_00_TO_15_W(3, (uint4)(0x80000000, 0x80000000, 0x80000000, 0x80000000));\
		ROUND_00_TO_15_ZERO(4);\
		ROUND_00_TO_15_ZERO(5);\
		ROUND_00_TO_15_ZERO(6);\
		ROUND_00_TO_15_ZERO(7);\
		ROUND_00_TO_15_ZERO(8);\
		ROUND_00_TO_15_ZERO(9);\
		ROUND_00_TO_15_ZERO(10);\
		ROUND_00_TO_15_ZERO(11);\
		ROUND_00_TO_15_ZERO(12);\
		ROUND_00_TO_15_ZERO(13);\
		ROUND_00_TO_15_ZERO(14);\
		ROUND_00_TO_15_W(15, (uint4)(12 * 8, 12 * 8, 12 * 8, 12 * 8));\
		\
		                    ROUND_16_TO_19(16); ROUND_16_TO_19(17); ROUND_16_TO_19(18); ROUND_16_TO_19(19);\
		\
		ROUND_20_TO_39(20); ROUND_20_TO_39(21);	ROUND_20_TO_39(22);	ROUND_20_TO_39(23);	ROUND_20_TO_39(24);\
		ROUND_20_TO_39(25);	ROUND_20_TO_39(26);	ROUND_20_TO_39(27);	ROUND_20_TO_39(28);	ROUND_20_TO_39(29);\
		ROUND_20_TO_39(30);	ROUND_20_TO_39(31);	ROUND_20_TO_39(32);	ROUND_20_TO_39(33);	ROUND_20_TO_39(34);\
		ROUND_20_TO_39(35);	ROUND_20_TO_39(36);	ROUND_20_TO_39(37);	ROUND_20_TO_39(38);	ROUND_20_TO_39(39);\
		\
		ROUND_40_TO_59(40);	ROUND_40_TO_59(41);	ROUND_40_TO_59(42);	ROUND_40_TO_59(43);	ROUND_40_TO_59(44);\
		ROUND_40_TO_59(45);	ROUND_40_TO_59(46);	ROUND_40_TO_59(47);	ROUND_40_TO_59(48);	ROUND_40_TO_59(49);\
		ROUND_40_TO_59(50);	ROUND_40_TO_59(51);	ROUND_40_TO_59(52);	ROUND_40_TO_59(53);	ROUND_40_TO_59(54);\
		ROUND_40_TO_59(55);	ROUND_40_TO_59(56);	ROUND_40_TO_59(57);	ROUND_40_TO_59(58);	ROUND_40_TO_59(59);\
		\
		ROUND_60_TO_79(60); ROUND_60_TO_79(61);	ROUND_60_TO_79(62); ROUND_60_TO_79(63); ROUND_60_TO_79(64);\
		ROUND_60_TO_79(65);	ROUND_60_TO_79(66); ROUND_60_TO_79(67);	ROUND_60_TO_79(68);	ROUND_60_TO_79(69);\
		ROUND_60_TO_79(70);	ROUND_60_TO_79(71); ROUND_60_TO_79(72); ROUND_60_TO_79(73); ROUND_60_TO_79(74);\
		ROUND_60_TO_79(75); ROUND_60_TO_79(76);	ROUND_60_TO_79(77); ROUND_60_TO_79(78); ROUND_60_TO_79(79);\
		\
		A += H0;\
		B += H1;\
		C += H2;\
		\
		uint4        tripcodeChunk = A >> 2;\

#define OPENCL_SHA1_USE_SMALL_CHUNK_BITMAP                                                   \
		if (   smallChunkBitmap[tripcodeChunk.x >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]  \
		    && smallChunkBitmap[tripcodeChunk.y >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]  \
		    && smallChunkBitmap[tripcodeChunk.z >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]  \
		    && smallChunkBitmap[tripcodeChunk.w >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) \
			continue;                                                                      \

#define OPENCL_SHA1_USE_CHUNK_BITMAP                                                         \
		if (   chunkBitmap[tripcodeChunk.x >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]             \
		    && chunkBitmap[tripcodeChunk.y >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]             \
		    && chunkBitmap[tripcodeChunk.z >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]             \
		    && chunkBitmap[tripcodeChunk.w >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])            \
			continue;                                                                      \
		
#define OPENCL_SHA1_LINEAR_SEARCH                                                   \
		for (unsigned int i = 0; i < numTripcodeChunk; i++){                        \
			if (tripcodeChunkArray[i] == tripcodeChunk.x) {                         \
				found = 1;                                                          \
				vectorIndex = 0;                                                    \
				A_matching = A.x;                                                   \
				B_matching = B.x;                                                   \
				C_matching = C.x;                                                   \
				break;                                                              \
			} else if (tripcodeChunkArray[i] == tripcodeChunk.y) {                  \
				found = 1;                                                          \
				vectorIndex = 1;                                                    \
				A_matching = A.y;                                                   \
				B_matching = B.y;                                                   \
				C_matching = C.y;                                                   \
				break;                                                              \
			} else if (tripcodeChunkArray[i] == tripcodeChunk.z) {                  \
				found = 1;                                                          \
				vectorIndex = 2;                                                    \
				A_matching = A.z;                                                   \
				B_matching = B.z;                                                   \
				C_matching = C.z;                                                   \
				break;                                                              \
			} else if (tripcodeChunkArray[i] == tripcodeChunk.w) {                  \
				found = 1;                                                          \
				vectorIndex = 3;                                                    \
				A_matching = A.w;                                                   \
				B_matching = B.w;                                                   \
				C_matching = C.w;                                                   \
				break;                                                              \
			}                                                                       \
		}                                                                           \
		if (found)                                                                  \
			break;                                                                  \

#define OPENCL_SHA1_BINARY_SEARCH                                               \
	{\
		int lower, upper, middle;                                               \
		                                                                        \
		lower  = 0;                                                             \
		upper  = numTripcodeChunk - 1;                                          \
		middle = lower;                                                         \
		while (tripcodeChunk.x != tripcodeChunkArray[middle] && lower <= upper) { \
			middle = (lower + upper) >> 1;                                      \
			if (tripcodeChunk.x > tripcodeChunkArray[middle]) {                   \
				lower = middle + 1;                                             \
			} else {                                                            \
				upper = middle - 1;                                             \
			}                                                                   \
		}                                                                       \
		if (tripcodeChunk.x == tripcodeChunkArray[middle]) {                      \
			found = 1;                                                          \
			vectorIndex = 0;                                                    \
			A_matching = A.x;                                                   \
			B_matching = B.x;                                                   \
			C_matching = C.x;                                                   \
			break;                                                              \
		}                                                                       \
		                                                                        \
		lower  = 0;                                                             \
		upper  = numTripcodeChunk - 1;                                          \
		middle = lower;                                                         \
		while (tripcodeChunk.y != tripcodeChunkArray[middle] && lower <= upper) { \
			middle = (lower + upper) >> 1;                                      \
			if (tripcodeChunk.y > tripcodeChunkArray[middle]) {                   \
				lower = middle + 1;                                             \
			} else {                                                            \
				upper = middle - 1;                                             \
			}                                                                   \
		}                                                                       \
		if (tripcodeChunk.y == tripcodeChunkArray[middle]) {                      \
			found = 1;                                                          \
			vectorIndex = 1;                                                    \
			A_matching = A.y;                                                   \
			B_matching = B.y;                                                   \
			C_matching = C.y;                                                   \
			break;                                                              \
		}                                                                       \
		                                                                        \
		lower  = 0;                                                             \
		upper  = numTripcodeChunk - 1;                                          \
		middle = lower;                                                         \
		while (tripcodeChunk.z != tripcodeChunkArray[middle] && lower <= upper) { \
			middle = (lower + upper) >> 1;                                      \
			if (tripcodeChunk.z > tripcodeChunkArray[middle]) {                   \
				lower = middle + 1;                                             \
			} else {                                                            \
				upper = middle - 1;                                             \
			}                                                                   \
		}                                                                       \
		if (tripcodeChunk.z == tripcodeChunkArray[middle]) {                      \
			found = 1;                                                          \
			vectorIndex = 2;                                                    \
			A_matching = A.z;                                                   \
			B_matching = B.z;                                                   \
			C_matching = C.z;                                                   \
			break;                                                              \
		}                                                                       \
		                                                                        \
		lower  = 0;                                                             \
		upper  = numTripcodeChunk - 1;                                          \
		middle = lower;                                                         \
		while (tripcodeChunk.w != tripcodeChunkArray[middle] && lower <= upper) { \
			middle = (lower + upper) >> 1;                                      \
			if (tripcodeChunk.w > tripcodeChunkArray[middle]) {                   \
				lower = middle + 1;                                             \
			} else {                                                            \
				upper = middle - 1;                                             \
			}                                                                   \
		}                                                                       \
		if (tripcodeChunk.w == tripcodeChunkArray[middle]) {                      \
			found = 1;                                                          \
			vectorIndex = 3;                                                    \
			A_matching = A.w;                                                   \
			B_matching = B.w;                                                   \
			C_matching = C.w;                                                   \
			break;                                                              \
		}                                                                       \
	}\

#define OPENCL_SHA1_END_OF_SEAERCH_FUNCTION \
	}\
	if (!found) {\
		output->numGeneratedTripcodes = OPENCL_SHA1_MAX_PASS_COUNT * 4;  \
	} else {\
		__global TripcodeKeyPair *pair = &(output->pair);\
		pair->key.c[0]  = key0;\
		pair->key.c[1]  = key1;\
		pair->key.c[2]  = key2;\
		pair->key.c[3]  = key3;\
		pair->key.c[7]  = (key[7] & 0xfc) | vectorIndex;\
		pair->key.c[11] = key11;\
		pair->tripcode.c[0]  = base64CharTable[ A_matching >> 26                           ];\
		pair->tripcode.c[1]  = base64CharTable[(A_matching >> 20                   ) & 0x3f];\
		pair->tripcode.c[2]  = base64CharTable[(A_matching >> 14                   ) & 0x3f];\
		pair->tripcode.c[3]  = base64CharTable[(A_matching >>  8                   ) & 0x3f];\
		pair->tripcode.c[4]  = base64CharTable[(A_matching >>  2                   ) & 0x3f];\
		pair->tripcode.c[5]  = base64CharTable[(B_matching >> 28 | A_matching <<  4) & 0x3f];\
		pair->tripcode.c[6]  = base64CharTable[(B_matching >> 22                   ) & 0x3f];\
		pair->tripcode.c[7]  = base64CharTable[(B_matching >> 16                   ) & 0x3f];\
		pair->tripcode.c[8]  = base64CharTable[(B_matching >> 10                   ) & 0x3f];\
		pair->tripcode.c[9]  = base64CharTable[(B_matching >>  4                   ) & 0x3f];\
		pair->tripcode.c[10] = base64CharTable[(B_matching <<  2 | C_matching >> 30) & 0x3f];\
		pair->tripcode.c[11] = base64CharTable[(C_matching >> 24                   ) & 0x3f];\
		output->numMatchingTripcodes = 1;\
		output->numGeneratedTripcodes = (passCount + 1) * 4;\
	}\
}\

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_ForwardMatching_1Chunk)
	unsigned int      tripcodeChunk0 = tripcodeChunkArray[0];
OPENCL_SHA1_BEFORE_SEARCHING
	if (tripcodeChunk.x == tripcodeChunk0) {
		found = 1;
		vectorIndex = 0;
		A_matching = A.x;
		B_matching = B.x;
		C_matching = C.x;
		break;
	} else if (tripcodeChunk.y == tripcodeChunk0) {
		found = 1;
		vectorIndex = 1;
		A_matching = A.y;
		B_matching = B.y;
		C_matching = C.y;
		break;
	} else if (tripcodeChunk.z == tripcodeChunk0) {
		found = 1;
		vectorIndex = 2;
		A_matching = A.z;
		B_matching = B.z;
		C_matching = C.z;
		break;
	} else if (tripcodeChunk.w == tripcodeChunk0) {
		found = 1;
		vectorIndex = 3;
		A_matching = A.w;
		B_matching = B.w;
		C_matching = C.w;
		break;
	}
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_ForwardMatching_Simple)
OPENCL_SHA1_BEFORE_SEARCHING
	OPENCL_SHA1_USE_SMALL_CHUNK_BITMAP
	OPENCL_SHA1_LINEAR_SEARCH
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_ForwardMatching)
OPENCL_SHA1_BEFORE_SEARCHING
	OPENCL_SHA1_USE_SMALL_CHUNK_BITMAP
	OPENCL_SHA1_USE_CHUNK_BITMAP
	OPENCL_SHA1_BINARY_SEARCH
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_BackwardMatching_Simple)
OPENCL_SHA1_BEFORE_SEARCHING
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff);
	OPENCL_SHA1_USE_SMALL_CHUNK_BITMAP
	OPENCL_SHA1_LINEAR_SEARCH
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_BackwardMatching)
OPENCL_SHA1_BEFORE_SEARCHING
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff);
	OPENCL_SHA1_USE_SMALL_CHUNK_BITMAP
	OPENCL_SHA1_USE_CHUNK_BITMAP
	OPENCL_SHA1_BINARY_SEARCH
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

// TO DO: Make the following two functions faster!
// These functions became slower with an optimization for AMD VLIW architectures.

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_Flexible_Simple)
OPENCL_SHA1_BEFORE_SEARCHING
	tripcodeChunk =  (A >>  2);                                          OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((A <<  4) & 0x3fffffff) | ((B >> 28) & 0x0000000f); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((A << 10) & 0x3fffffff) | ((B >> 22) & 0x000003ff); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((A << 16) & 0x3fffffff) | ((B >> 16) & 0x0000ffff); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((A << 22) & 0x3fffffff) | ((B >> 10) & 0x003fffff); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((A << 28) & 0x3fffffff) | ((B >>  4) & 0x0fffffff); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((B <<  2) & 0x3fffffff) | ((C >> 30) & 0x00000003); OPENCL_SHA1_LINEAR_SEARCH
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); OPENCL_SHA1_LINEAR_SEARCH
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_Flexible)
OPENCL_SHA1_BEFORE_SEARCHING

	#define PERFORM_BINARY_SEARCH_IF_NECESSARY                                                    \
		{                                                                                         \
			int lower, upper, middle;                                                             \
																								  \
			if (   !smallChunkBitmap[tripcodeChunk.x >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]    \
				&& !chunkBitmap     [tripcodeChunk.x >> ((5 - CHUNK_BITMAP_LEN_STRING      ) * 6)]) { \
				lower  = 0;                                                                       \
				upper  = numTripcodeChunk - 1;                                                    \
				middle = lower;                                                                   \
				while (tripcodeChunk.x != tripcodeChunkArray[middle] && lower <= upper) {         \
					middle = (lower + upper) >> 1;                                                \
					if (tripcodeChunk.x > tripcodeChunkArray[middle]) {                           \
						lower = middle + 1;                                                       \
					} else {                                                                      \
						upper = middle - 1;                                                       \
					}                                                                             \
				}                                                                                 \
				if (tripcodeChunk.x == tripcodeChunkArray[middle]) {                              \
					found = 1;                                                                    \
					vectorIndex = 0;                                                              \
					A_matching = A.x;                                                             \
					B_matching = B.x;                                                             \
					C_matching = C.x;                                                             \
					break;                                                                        \
				}                                                                                 \
			} 																		              \
			if (found)                                                                            \
				break;                                                                            \
																								  \
			if (   !smallChunkBitmap[tripcodeChunk.y >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]    \
				&& !chunkBitmap     [tripcodeChunk.y >> ((5 - CHUNK_BITMAP_LEN_STRING      ) * 6)]) { \
				lower  = 0;                                                                       \
				upper  = numTripcodeChunk - 1;                                                    \
				middle = lower;                                                                   \
				while (tripcodeChunk.y != tripcodeChunkArray[middle] && lower <= upper) {         \
					middle = (lower + upper) >> 1;                                                \
					if (tripcodeChunk.y > tripcodeChunkArray[middle]) {                           \
						lower = middle + 1;                                                       \
					} else {                                                                      \
						upper = middle - 1;                                                       \
					}                                                                             \
				}                                                                                 \
				if (tripcodeChunk.y == tripcodeChunkArray[middle]) {                              \
					found = 1;                                                                    \
					vectorIndex = 1;                                                              \
					A_matching = A.y;                                                             \
					B_matching = B.y;                                                             \
					C_matching = C.y;                                                             \
					break;                                                                        \
				}                                                                                 \
			} 																		              \
			if (found)                                                                            \
				break;                                                                            \
																								  \
			if (   !smallChunkBitmap[tripcodeChunk.z >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]    \
				&& !chunkBitmap     [tripcodeChunk.z >> ((5 - CHUNK_BITMAP_LEN_STRING      ) * 6)]) { \
				lower  = 0;                                                                       \
				upper  = numTripcodeChunk - 1;                                                    \
				middle = lower;                                                                   \
				while (tripcodeChunk.z != tripcodeChunkArray[middle] && lower <= upper) {         \
					middle = (lower + upper) >> 1;                                                \
					if (tripcodeChunk.z > tripcodeChunkArray[middle]) {                           \
						lower = middle + 1;                                                       \
					} else {                                                                      \
						upper = middle - 1;                                                       \
					}                                                                             \
				}                                                                                 \
				if (tripcodeChunk.z == tripcodeChunkArray[middle]) {                              \
					found = 1;                                                                    \
					vectorIndex = 2;                                                              \
					A_matching = A.z;                                                             \
					B_matching = B.z;                                                             \
					C_matching = C.z;                                                             \
					break;                                                                        \
				}                                                                                 \
			} 																		              \
			if (found)                                                                            \
				break;                                                                            \
																								  \
			if (   !smallChunkBitmap[tripcodeChunk.w >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]    \
				&& !chunkBitmap     [tripcodeChunk.w >> ((5 - CHUNK_BITMAP_LEN_STRING      ) * 6)]) { \
				lower  = 0;                                                                       \
				upper  = numTripcodeChunk - 1;                                                    \
				middle = lower;                                                                   \
				while (tripcodeChunk.w != tripcodeChunkArray[middle] && lower <= upper) {         \
					middle = (lower + upper) >> 1;                                                \
					if (tripcodeChunk.w > tripcodeChunkArray[middle]) {                           \
						lower = middle + 1;                                                       \
					} else {                                                                      \
						upper = middle - 1;                                                       \
					}                                                                             \
				}                                                                                 \
				if (tripcodeChunk.w == tripcodeChunkArray[middle]) {                              \
					found = 1;                                                                    \
					vectorIndex = 3;                                                              \
					A_matching = A.w;                                                             \
					B_matching = B.w;                                                             \
					C_matching = C.w;                                                             \
					break;                                                                        \
				}                                                                                 \
			} 																		              \
			if (found)                                                                            \
				break;                                                                            \
		}                                                                                         \

	tripcodeChunk =  (A >>  2);                                          PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((A <<  4) & 0x3fffffff) | ((B >> 28) & 0x0000000f); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((A << 10) & 0x3fffffff) | ((B >> 22) & 0x000003ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((A << 16) & 0x3fffffff) | ((B >> 16) & 0x0000ffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((A << 22) & 0x3fffffff) | ((B >> 10) & 0x003fffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((A << 28) & 0x3fffffff) | ((B >>  4) & 0x0fffffff); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((B <<  2) & 0x3fffffff) | ((C >> 30) & 0x00000003); PERFORM_BINARY_SEARCH_IF_NECESSARY
	tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_ForwardAndBackwardMatching_Simple)
OPENCL_SHA1_BEFORE_SEARCHING

	#define PERFORM_LINEAR_SEARCH_IF_NECESSARY                                             \
		if (!smallChunkBitmap[tripcodeChunk.x >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
			for (unsigned int i = 0; i < numTripcodeChunk; i++){                           \
				if (tripcodeChunkArray[i] == tripcodeChunk.x) {                            \
					found = 1;                                                             \
					vectorIndex = 0;                                                       \
					A_matching = A.x;                                                      \
					B_matching = B.x;                                                      \
					C_matching = C.x;                                                      \
					break;                                                                 \
				}                                                                          \
			}                                                                              \
		}                                                                                  \
		if (found)                                                                         \
			break;                                                                         \
		if (!smallChunkBitmap[tripcodeChunk.y >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
			for (unsigned int i = 0; i < numTripcodeChunk; i++){                           \
				if (tripcodeChunkArray[i] == tripcodeChunk.y) {                            \
					found = 1;                                                             \
					vectorIndex = 1;                                                       \
					A_matching = A.y;                                                      \
					B_matching = B.y;                                                      \
					C_matching = C.y;                                                      \
					break;                                                                 \
				}                                                                          \
			}                                                                              \
		}                                                                                  \
		if (found)                                                                         \
			break;                                                                         \
		if (!smallChunkBitmap[tripcodeChunk.z >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
			for (unsigned int i = 0; i < numTripcodeChunk; i++){                           \
				if (tripcodeChunkArray[i] == tripcodeChunk.z) {                            \
					found = 1;                                                             \
					vectorIndex = 2;                                                       \
					A_matching = A.z;                                                      \
					B_matching = B.z;                                                      \
					C_matching = C.z;                                                      \
					break;                                                                 \
				}                                                                          \
			}                                                                              \
		}                                                                                  \
		if (found)                                                                         \
			break;                                                                         \
		if (!smallChunkBitmap[tripcodeChunk.w >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
			for (unsigned int i = 0; i < numTripcodeChunk; i++){                           \
				if (tripcodeChunkArray[i] == tripcodeChunk.w) {                            \
					found = 1;                                                             \
					vectorIndex = 3;                                                       \
					A_matching = A.w;                                                      \
					B_matching = B.w;                                                      \
					C_matching = C.w;                                                      \
					break;                                                                 \
				}                                                                          \
			}                                                                              \
		}                                                                                  \
		if (found)                                                                         \
			break;                                                                         \
	
	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_LINEAR_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_LINEAR_SEARCH_IF_NECESSARY
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION

OPENCL_SHA1_DEFINE_SEARCH_FUNCTION(OpenCL_SHA1_PerformSearching_ForwardAndBackwardMatching)
OPENCL_SHA1_BEFORE_SEARCHING
	/* tripcodeChunk =  (A >>  2) */                                        PERFORM_BINARY_SEARCH_IF_NECESSARY
	   tripcodeChunk = ((B <<  8) & 0x3fffffff) | ((C >> 24) & 0x000000ff); PERFORM_BINARY_SEARCH_IF_NECESSARY
OPENCL_SHA1_END_OF_SEAERCH_FUNCTION
