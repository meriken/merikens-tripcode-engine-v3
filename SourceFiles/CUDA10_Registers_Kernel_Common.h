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
// VARIABLES FOR CUDA CODES                                                  //
///////////////////////////////////////////////////////////////////////////////

__device__ __constant__ unsigned char   cudaKeyCharTable_FirstByte[SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char   cudaKeyCharTable_SecondByte[SIZE_KEY_CHAR_TABLE];
__device__              unsigned char   cudaChunkBitmap[CHUNK_BITMAP_SIZE];
__device__              unsigned char   cudaCompactMediumChunkBitmap[COMPACT_MEDIUM_CHUNK_BITMAP_SIZE];
__device__ __shared__   unsigned char   cudaSharedCompactMediumChunkBitmap[COMPACT_MEDIUM_CHUNK_BITMAP_SIZE];



///////////////////////////////////////////////////////////////////////////////
// BITSLICE DES                                                              //
///////////////////////////////////////////////////////////////////////////////

typedef uint32_t DES_Vector;

#define CUDA_DES_BS_DEPTH                   32
#define CUDA_DES_MAX_PASS_COUNT             32
#define CUDA_DES_NUM_THREADS_PER_BLOCK      384 

#define DES_CONSTANT_QUALIFIERS      __device__ __constant__
#define DES_FUNCTION_QUALIFIERS      __device__ __forceinline__
#define DES_SBOX_FUNCTION_QUALIFIERS __device__ __forceinline__

#include "CUDA10_S-boxes.h"

#define GET_TRIPCODE_CHAR_INDEX(t, i0, i1, i2, i3, i4, i5, pos)  \
		(  ((((i0) & (0x01 << (t))) ? (0x1) : (0x0)) << (5 + ((pos) * 6)))  \
	 	 | ((((i1) & (0x01 << (t))) ? (0x1) : (0x0)) << (4 + ((pos) * 6)))  \
		 | ((((i2) & (0x01 << (t))) ? (0x1) : (0x0)) << (3 + ((pos) * 6)))  \
		 | ((((i3) & (0x01 << (t))) ? (0x1) : (0x0)) << (2 + ((pos) * 6)))  \
		 | ((((i4) & (0x01 << (t))) ? (0x1) : (0x0)) << (1 + ((pos) * 6)))  \
		 | ((((i5) & (0x01 << (t))) ? (0x1) : (0x0)) << (0 + ((pos) * 6)))) \

#define GET_TRIPCODE_CHAR_INDEX_LAST(t, i0, i1, i2, i3)     \
		(  ((((i0) & (0x01 << (t))) ? (0x1) : (0x0)) << 5)  \
	 	 | ((((i1) & (0x01 << (t))) ? (0x1) : (0x0)) << 4)  \
		 | ((((i2) & (0x01 << (t))) ? (0x1) : (0x0)) << 3)  \
		 | ((((i3) & (0x01 << (t))) ? (0x1) : (0x0)) << 2)) \

#define BINARY_SEARCH\
	{\
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;\
		while (tripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) {\
			middle = (lower + upper) >> 1;\
			if (tripcodeChunk > tripcodeChunkArray[middle]) {\
				lower = middle + 1;\
			} else {\
				upper = middle - 1;\
			}\
		}\
		if (tripcodeChunk == tripcodeChunkArray[middle]) {\
			goto quit_loops;\
		}\
	}\

#define CUDA_SET_KEY_CHAR(var, flag, table, value)             \
	if (!(flag)) {                                        \
		var = (table)[(value)];                           \
		isSecondByte = IS_FIRST_BYTE_SJIS(var);           \
	} else {                                              \
		var = cudaKeyCharTable_SecondByte[(value)];          \
		isSecondByte = FALSE;                             \
	}

#define SET_KEY_CHAR(var, flag, table, value)             \
	if (!(flag)) {                                        \
		var = (table)[(value)];                           \
		isSecondByte = IS_FIRST_BYTE_SJIS(var);           \
	} else {                                              \
		var = keyCharTable_SecondByte[(value)];          \
		isSecondByte = FALSE;                             \
	}

#define CUDA_DES_CRYPT_EIGHT_ROUNDS2(salt) CUDA_DES_CRYPT_EIGHT_ROUNDS_##salt
#define CUDA_DES_CRYPT_EIGHT_ROUNDS(salt) CUDA_DES_CRYPT_EIGHT_ROUNDS2(salt)

#define LAUNCH_KERNEL(seed) \
	CUDA_DES_PerformSearch_##seed<<<dimGrid, dimBlock, 0, currentStream>>>(\
			cudaPassCountArray,\
			cudaTripcodeIndexArray,\
			cudaTripcodeChunkArray,\
			numTripcodeChunk,\
			intSalt,\
			cudaKey0Array,\
			cudaKey7Array,\
			cudaKeyVectorsFrom49To55,\
			cudaKeyAndRandomBytes,\
			searchMode);\

