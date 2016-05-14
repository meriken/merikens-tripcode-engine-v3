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



// TO DO: Use smallChunkBitmap[]!



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// VARIABLES FOR CUDA CODES                                                  //
///////////////////////////////////////////////////////////////////////////////

__device__ __constant__ unsigned char cudaKeyCharTable_OneByte   [SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char cudaKeyCharTable_FirstByte [SIZE_KEY_CHAR_TABLE];
__device__ __constant__ unsigned char cudaKeyCharTable_SecondByte[SIZE_KEY_CHAR_TABLE];
__device__ __constant__ char          CUDA_base64CharTable[64];
__device__ __constant__ unsigned char CUDA_smallChunkBitmap[SMALL_CHUNK_BITMAP_SIZE];



///////////////////////////////////////////////////////////////////////////////
// BITSLICE DES                                                              //
///////////////////////////////////////////////////////////////////////////////

#define NUM_THREADS_PER_BITSICE_DES   4

// FOR DEVICE CODES ONLY
#if   __CUDA_ARCH__ == 200
#define CUDA_DES_NUM_THREADS_PER_BLOCK      768
#elif __CUDA_ARCH__ == 300
#define CUDA_DES_NUM_THREADS_PER_BLOCK      768
#elif __CUDA_ARCH__ == 320
#define CUDA_DES_NUM_THREADS_PER_BLOCK      768
#elif __CUDA_ARCH__ == 350
#define CUDA_DES_NUM_THREADS_PER_BLOCK      768
#elif __CUDA_ARCH__ == 370
#define CUDA_DES_NUM_THREADS_PER_BLOCK      448
#elif __CUDA_ARCH__ == 500
#define CUDA_DES_NUM_THREADS_PER_BLOCK      512
#elif __CUDA_ARCH__ == 520
#define CUDA_DES_NUM_THREADS_PER_BLOCK      512
#elif __CUDA_ARCH__ == 530
#define CUDA_DES_NUM_THREADS_PER_BLOCK      512
#else
#define CUDA_DES_NUM_THREADS_PER_BLOCK      512 // dummy value to make nvcc happy
#endif
#define CUDA_DES_NUM_BITSLICE_DES_CONTEXTS_PER_BLOCK (CUDA_DES_NUM_THREADS_PER_BLOCK / NUM_THREADS_PER_BITSICE_DES)
#define N CUDA_DES_NUM_BITSLICE_DES_CONTEXTS_PER_BLOCK

#define CUDA_DES_BS_DEPTH                   32
#define CUDA_DES_MAX_PASS_COUNT             16

typedef int32_t           DES_ARCH_WORD;
typedef int32_t           DES_ARCH_WORD_32;
#define DES_ARCH_SIZE 4
#define DES_ARCH_BITS 32

typedef int32_t           DES_Vector;
// #define CUDA_DES_BS_DEPTH  DES_ARCH_BITS
#define DES_VECTOR_ZERO               0
#define DES_VECTOR_ONES               ~(DES_Vector)0

#define DES_VECTOR_NOT(dst, a)        (dst) =  ~(a)
#define DES_VECTOR_AND(dst, a, b)     (dst) =   (a) &  (b)
#define DES_VECTOR_OR(dst, a, b)      (dst) =   (a) |  (b)
#define DES_VECTOR_AND_NOT(dst, a, b) (dst) =   (a) & ~(b)
#define DES_VECTOR_XOR_NOT(dst, a, b) (dst) = ~((a) ^  (b))
#define DES_VECTOR_NOT_OR(dst, a, b)  (dst) = ~((a) |  (b))
#define DES_VECTOR_SEL(dst, a, b, c)  (dst) = (((a) & ~(c)) ^ ((b) & (c)))
#define DES_VECTOR_XOR_FUNC(a, b)              ((a) ^  (b))
#define DES_VECTOR_XOR(dst, a, b)     (dst) = DES_VECTOR_XOR_FUNC((a), (b))
#define DES_VECTOR_SET(dst, ofs, src) *((DES_Vector *)((DES_Vector *)&(dst) + ((ofs) * N))) = (src)

#define DES_CONSTANT_QUALIFIERS      __device__ __constant__
#define DES_FUNCTION_QUALIFIERS      __device__ __forceinline__
#define DES_SBOX_FUNCTION_QUALIFIERS __device__ __forceinline__

extern __shared__ DES_Vector dataBlocks[];

DES_CONSTANT_QUALIFIERS char CUDA_DES_indexToCharTable[64] =
//	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
{
	/* 00 */ '.', '/',
	/* 02 */ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
	/* 12 */ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
	/* 28 */ 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	/* 38 */ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	/* 54 */ 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
};

DES_CONSTANT_QUALIFIERS unsigned char keySchedule[DES_SIZE_KEY_SCHEDULE] = {
	12, 46, 33, 52, 48, 20, 34, 55,  5, 13, 18, 40,  4, 32, 26, 27,
	38, 54, 53,  6, 31, 25, 19, 41, 15, 24, 28, 43, 30,  3, 35, 22,
	 2, 44, 14, 23, 51, 16, 29, 49,  7, 17, 37,  8,  9, 50, 42, 21,
	 5, 39, 26, 45, 41, 13, 27, 48, 53,  6, 11, 33, 52, 25, 19, 20,
	31, 47, 46, 54, 55, 18, 12, 34,  8, 17, 21, 36, 23, 49, 28, 15,
	24, 37,  7, 16, 44,  9, 22, 42,  0, 10, 30,  1,  2, 43, 35, 14,
	46, 25, 12, 31, 27, 54, 13, 34, 39, 47, 52, 19, 38, 11,  5,  6,
	48, 33, 32, 40, 41,  4, 53, 20, 51,  3,  7, 22,  9, 35, 14,  1,
	10, 23, 50,  2, 30, 24,  8, 28, 43, 49, 16, 44, 17, 29, 21,  0,
	32, 11, 53, 48, 13, 40, 54, 20, 25, 33, 38,  5, 55, 52, 46, 47,
	34, 19, 18, 26, 27, 45, 39,  6, 37, 42, 50,  8, 24, 21,  0, 44,
	49,  9, 36, 17, 16, 10, 51, 14, 29, 35,  2, 30,  3, 15,  7, 43,
	18, 52, 39, 34, 54, 26, 40,  6, 11, 19, 55, 46, 41, 38, 32, 33,
	20,  5,  4, 12, 13, 31, 25, 47, 23, 28, 36, 51, 10,  7, 43, 30,
	35, 24, 22,  3,  2, 49, 37,  0, 15, 21, 17, 16, 42,  1, 50, 29,
	 4, 38, 25, 20, 40, 12, 26, 47, 52,  5, 41, 32, 27, 55, 18, 19,
	 6, 46, 45, 53, 54, 48, 11, 33,  9, 14, 22, 37, 49, 50, 29, 16,
	21, 10,  8, 42, 17, 35, 23, 43,  1,  7,  3,  2, 28, 44, 36, 15,
	45, 55, 11,  6, 26, 53, 12, 33, 38, 46, 27, 18, 13, 41,  4,  5,
	47, 32, 31, 39, 40, 34, 52, 19, 24,  0,  8, 23, 35, 36, 15,  2,
	 7, 49, 51, 28,  3, 21,  9, 29, 44, 50, 42, 17, 14, 30, 22,  1,
	31, 41, 52, 47, 12, 39, 53, 19, 55, 32, 13,  4, 54, 27, 45, 46,
	33, 18, 48, 25, 26, 20, 38,  5, 10, 43, 51,  9, 21, 22,  1, 17,
	50, 35, 37, 14, 42,  7, 24, 15, 30, 36, 28,  3,  0, 16,  8, 44,
	55, 34, 45, 40,  5, 32, 46, 12, 48, 25,  6, 52, 47, 20, 38, 39,
	26, 11, 41, 18, 19, 13, 31, 53,  3, 36, 44,  2, 14, 15, 51, 10,
	43, 28, 30,  7, 35,  0, 17,  8, 23, 29, 21, 49, 50,  9,  1, 37,
	41, 20, 31, 26, 46, 18, 32, 53, 34, 11, 47, 38, 33,  6, 55, 25,
	12, 52, 27,  4,  5, 54, 48, 39, 42, 22, 30, 17,  0,  1, 37, 49,
	29, 14, 16, 50, 21, 43,  3, 51,  9, 15,  7, 35, 36, 24, 44, 23,
	27,  6, 48, 12, 32,  4, 18, 39, 20, 52, 33, 55, 19, 47, 41, 11,
	53, 38, 13, 45, 46, 40, 34, 25, 28,  8, 16,  3, 43, 44, 23, 35,
	15,  0,  2, 36,  7, 29, 42, 37, 24,  1, 50, 21, 22, 10, 30,  9,
	13, 47, 34, 53, 18, 45,  4, 25,  6, 38, 19, 41,  5, 33, 27, 52,
	39, 55, 54, 31, 32, 26, 20, 11, 14, 51,  2, 42, 29, 30,  9, 21,
	 1, 43, 17, 22, 50, 15, 28, 23, 10, 44, 36,  7,  8, 49, 16, 24,
	54, 33, 20, 39,  4, 31, 45, 11, 47, 55,  5, 27, 46, 19, 13, 38,
	25, 41, 40, 48, 18, 12,  6, 52,  0, 37, 17, 28, 15, 16, 24,  7,
	44, 29,  3,  8, 36,  1, 14,  9, 49, 30, 22, 50, 51, 35,  2, 10,
	40, 19,  6, 25, 45, 48, 31, 52, 33, 41, 46, 13, 32,  5, 54, 55,
	11, 27, 26, 34,  4, 53, 47, 38, 43, 23,  3, 14,  1,  2, 10, 50,
	30, 15, 42, 51, 22, 44,  0, 24, 35, 16,  8, 36, 37, 21, 17, 49,
	26,  5, 47, 11, 31, 34, 48, 38, 19, 27, 32, 54, 18, 46, 40, 41,
	52, 13, 12, 20, 45, 39, 33, 55, 29,  9, 42,  0, 44, 17, 49, 36,
	16,  1, 28, 37,  8, 30, 43, 10, 21,  2, 51, 22, 23,  7,  3, 35,
	19, 53, 40,  4, 55, 27, 41, 31, 12, 20, 25, 47, 11, 39, 33, 34,
	45,  6,  5, 13, 38, 32, 26, 48, 22,  2, 35, 50, 37, 10, 42, 29,
	 9, 51, 21, 30,  1, 23, 36,  3, 14, 24, 44, 15, 16,  0, 49, 28,
};

#include "CUDA10_S-boxes.h"

#define CLEAR_BLOCK_8(i)                                                             \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 0, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 1, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 2, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 3, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 4, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 5, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 6, DES_VECTOR_ZERO); \
	DES_VECTOR_SET(dataBlocks[threadIdx.x + (i*N)] , 7, DES_VECTOR_ZERO); \

#define CLEAR_BLOCK()  \
	CLEAR_BLOCK_8(0);  \
	CLEAR_BLOCK_8(8);  \
	CLEAR_BLOCK_8(16); \
	CLEAR_BLOCK_8(24); \
	CLEAR_BLOCK_8(32); \
	CLEAR_BLOCK_8(40); \
	CLEAR_BLOCK_8(48); \
	CLEAR_BLOCK_8(56); \

DES_FUNCTION_QUALIFIERS
void DES_Crypt(volatile uint32_t keyFrom00To27, volatile uint32_t keyFrom28To48, unsigned char *CUDA_expansionFunction, DES_Vector *CUDA_keyFrom49To55Array)
{
	if (threadIdx.y == 0)
		CLEAR_BLOCK();
	
	DES_Vector *db = dataBlocks + threadIdx.x;
	int32_t E0, E1, E2, E3, E4, E5;

	switch (threadIdx.y) {
	case 0: 
		E0 = CUDA_expansionFunction[0]*N;
		E1 = CUDA_expansionFunction[1]*N;
		E2 = CUDA_expansionFunction[2]*N;
		E3 = CUDA_expansionFunction[3]*N;
		E4 = CUDA_expansionFunction[4]*N;
		E5 = CUDA_expansionFunction[5]*N;
		break;
	case 1: 
		E0 = CUDA_expansionFunction[6]*N;
		E1 = CUDA_expansionFunction[7]*N;
		E2 = CUDA_expansionFunction[8]*N;
		E3 = CUDA_expansionFunction[9]*N;
		E4 = CUDA_expansionFunction[10]*N;
		E5 = CUDA_expansionFunction[11]*N;
		break;
	case 2: 
		E0 = CUDA_expansionFunction[24]*N;
		E1 = CUDA_expansionFunction[25]*N;
		E2 = CUDA_expansionFunction[26]*N;
		E3 = CUDA_expansionFunction[27]*N;
		E4 = CUDA_expansionFunction[28]*N;
		E5 = CUDA_expansionFunction[29]*N;
		break;
	case 3: 
		E0 = CUDA_expansionFunction[30]*N;
		E1 = CUDA_expansionFunction[31]*N;
		E2 = CUDA_expansionFunction[32]*N;
		E3 = CUDA_expansionFunction[33]*N;
		E4 = CUDA_expansionFunction[34]*N;
		E5 = CUDA_expansionFunction[35]*N;
		break;
	}
	
#define K00 ((keyFrom00To27 & (0x1U << 0)) ? 0xffffffffU : 0x0)
#define K01 ((keyFrom00To27 & (0x1U << 1)) ? 0xffffffffU : 0x0)
#define K02 ((keyFrom00To27 & (0x1U << 2)) ? 0xffffffffU : 0x0)
#define K03 ((keyFrom00To27 & (0x1U << 3)) ? 0xffffffffU : 0x0)
#define K04 ((keyFrom00To27 & (0x1U << 4)) ? 0xffffffffU : 0x0)
#define K05 ((keyFrom00To27 & (0x1U << 5)) ? 0xffffffffU : 0x0)
#define K06 ((keyFrom00To27 & (0x1U << 6)) ? 0xffffffffU : 0x0)
#define K07 ((keyFrom00To27 & (0x1U << 7)) ? 0xffffffffU : 0x0)
#define K08 ((keyFrom00To27 & (0x1U << 8)) ? 0xffffffffU : 0x0)
#define K09 ((keyFrom00To27 & (0x1U << 9)) ? 0xffffffffU : 0x0)
#define K10 ((keyFrom00To27 & (0x1U << 10)) ? 0xffffffffU : 0x0)
#define K11 ((keyFrom00To27 & (0x1U << 11)) ? 0xffffffffU : 0x0)
#define K12 ((keyFrom00To27 & (0x1U << 12)) ? 0xffffffffU : 0x0)
#define K13 ((keyFrom00To27 & (0x1U << 13)) ? 0xffffffffU : 0x0)
#define K14 ((keyFrom00To27 & (0x1U << 14)) ? 0xffffffffU : 0x0)
#define K15 ((keyFrom00To27 & (0x1U << 15)) ? 0xffffffffU : 0x0)
#define K16 ((keyFrom00To27 & (0x1U << 16)) ? 0xffffffffU : 0x0)
#define K17 ((keyFrom00To27 & (0x1U << 17)) ? 0xffffffffU : 0x0)
#define K18 ((keyFrom00To27 & (0x1U << 18)) ? 0xffffffffU : 0x0)
#define K19 ((keyFrom00To27 & (0x1U << 19)) ? 0xffffffffU : 0x0)
#define K20 ((keyFrom00To27 & (0x1U << 20)) ? 0xffffffffU : 0x0)
#define K21 ((keyFrom00To27 & (0x1U << 21)) ? 0xffffffffU : 0x0)
#define K22 ((keyFrom00To27 & (0x1U << 22)) ? 0xffffffffU : 0x0)
#define K23 ((keyFrom00To27 & (0x1U << 23)) ? 0xffffffffU : 0x0)
#define K24 ((keyFrom00To27 & (0x1U << 24)) ? 0xffffffffU : 0x0)
#define K25 ((keyFrom00To27 & (0x1U << 25)) ? 0xffffffffU : 0x0)
#define K26 ((keyFrom00To27 & (0x1U << 26)) ? 0xffffffffU : 0x0)
#define K27 ((keyFrom00To27 & (0x1U << 27)) ? 0xffffffffU : 0x0)
#define K28 ((keyFrom28To48 & (0x1U << (28 - 28))) ? 0xffffffffU : 0x0)
#define K29 ((keyFrom28To48 & (0x1U << (29 - 28))) ? 0xffffffffU : 0x0)
#define K30 ((keyFrom28To48 & (0x1U << (30 - 28))) ? 0xffffffffU : 0x0)
#define K31 ((keyFrom28To48 & (0x1U << (31 - 28))) ? 0xffffffffU : 0x0)
#define K32 ((keyFrom28To48 & (0x1U << (32 - 28))) ? 0xffffffffU : 0x0)
#define K33 ((keyFrom28To48 & (0x1U << (33 - 28))) ? 0xffffffffU : 0x0)
#define K34 ((keyFrom28To48 & (0x1U << (34 - 28))) ? 0xffffffffU : 0x0)
#define K35 ((keyFrom28To48 & (0x1U << (35 - 28))) ? 0xffffffffU : 0x0)
#define K36 ((keyFrom28To48 & (0x1U << (36 - 28))) ? 0xffffffffU : 0x0)
#define K37 ((keyFrom28To48 & (0x1U << (37 - 28))) ? 0xffffffffU : 0x0)
#define K38 ((keyFrom28To48 & (0x1U << (38 - 28))) ? 0xffffffffU : 0x0)
#define K39 ((keyFrom28To48 & (0x1U << (39 - 28))) ? 0xffffffffU : 0x0)
#define K40 ((keyFrom28To48 & (0x1U << (40 - 28))) ? 0xffffffffU : 0x0)
#define K41 ((keyFrom28To48 & (0x1U << (41 - 28))) ? 0xffffffffU : 0x0)
#define K42 ((keyFrom28To48 & (0x1U << (42 - 28))) ? 0xffffffffU : 0x0)
#define K43 ((keyFrom28To48 & (0x1U << (43 - 28))) ? 0xffffffffU : 0x0)
#define K44 ((keyFrom28To48 & (0x1U << (44 - 28))) ? 0xffffffffU : 0x0)
#define K45 ((keyFrom28To48 & (0x1U << (45 - 28))) ? 0xffffffffU : 0x0)
#define K46 ((keyFrom28To48 & (0x1U << (46 - 28))) ? 0xffffffffU : 0x0)
#define K47 ((keyFrom28To48 & (0x1U << (47 - 28))) ? 0xffffffffU : 0x0)
#define K48 ((keyFrom28To48 & (0x1U << (48 - 28))) ? 0xffffffffU : 0x0)

#define K00XOR(val) ((keyFrom00To27 & (0x1U << 0)) ? ~(val) : (val))
#define K01XOR(val) ((keyFrom00To27 & (0x1U << 1)) ? ~(val) : (val))
#define K02XOR(val) ((keyFrom00To27 & (0x1U << 2)) ? ~(val) : (val))
#define K03XOR(val) ((keyFrom00To27 & (0x1U << 3)) ? ~(val) : (val))
#define K04XOR(val) ((keyFrom00To27 & (0x1U << 4)) ? ~(val) : (val))
#define K05XOR(val) ((keyFrom00To27 & (0x1U << 5)) ? ~(val) : (val))
#define K06XOR(val) ((keyFrom00To27 & (0x1U << 6)) ? ~(val) : (val))
#define K07XOR(val) ((keyFrom00To27 & (0x1U << 7)) ? ~(val) : (val))
#define K08XOR(val) ((keyFrom00To27 & (0x1U << 8)) ? ~(val) : (val))
#define K09XOR(val) ((keyFrom00To27 & (0x1U << 9)) ? ~(val) : (val))
#define K10XOR(val) ((keyFrom00To27 & (0x1U << 10)) ? ~(val) : (val))
#define K11XOR(val) ((keyFrom00To27 & (0x1U << 11)) ? ~(val) : (val))
#define K12XOR(val) ((keyFrom00To27 & (0x1U << 12)) ? ~(val) : (val))
#define K13XOR(val) ((keyFrom00To27 & (0x1U << 13)) ? ~(val) : (val))
#define K14XOR(val) ((keyFrom00To27 & (0x1U << 14)) ? ~(val) : (val))
#define K15XOR(val) ((keyFrom00To27 & (0x1U << 15)) ? ~(val) : (val))
#define K16XOR(val) ((keyFrom00To27 & (0x1U << 16)) ? ~(val) : (val))
#define K17XOR(val) ((keyFrom00To27 & (0x1U << 17)) ? ~(val) : (val))
#define K18XOR(val) ((keyFrom00To27 & (0x1U << 18)) ? ~(val) : (val))
#define K19XOR(val) ((keyFrom00To27 & (0x1U << 19)) ? ~(val) : (val))
#define K20XOR(val) ((keyFrom00To27 & (0x1U << 20)) ? ~(val) : (val))
#define K21XOR(val) ((keyFrom00To27 & (0x1U << 21)) ? ~(val) : (val))
#define K22XOR(val) ((keyFrom00To27 & (0x1U << 22)) ? ~(val) : (val))
#define K23XOR(val) ((keyFrom00To27 & (0x1U << 23)) ? ~(val) : (val))
#define K24XOR(val) ((keyFrom00To27 & (0x1U << 24)) ? ~(val) : (val))
#define K25XOR(val) ((keyFrom00To27 & (0x1U << 25)) ? ~(val) : (val))
#define K26XOR(val) ((keyFrom00To27 & (0x1U << 26)) ? ~(val) : (val))
#define K27XOR(val) ((keyFrom00To27 & (0x1U << 27)) ? ~(val) : (val))
#define K28XOR(val) ((keyFrom28To48 & (0x1U << (28 - 28))) ? ~(val) : (val))
#define K29XOR(val) ((keyFrom28To48 & (0x1U << (29 - 28))) ? ~(val) : (val))
#define K30XOR(val) ((keyFrom28To48 & (0x1U << (30 - 28))) ? ~(val) : (val))
#define K31XOR(val) ((keyFrom28To48 & (0x1U << (31 - 28))) ? ~(val) : (val))
#define K32XOR(val) ((keyFrom28To48 & (0x1U << (32 - 28))) ? ~(val) : (val))
#define K33XOR(val) ((keyFrom28To48 & (0x1U << (33 - 28))) ? ~(val) : (val))
#define K34XOR(val) ((keyFrom28To48 & (0x1U << (34 - 28))) ? ~(val) : (val))
#define K35XOR(val) ((keyFrom28To48 & (0x1U << (35 - 28))) ? ~(val) : (val))
#define K36XOR(val) ((keyFrom28To48 & (0x1U << (36 - 28))) ? ~(val) : (val))
#define K37XOR(val) ((keyFrom28To48 & (0x1U << (37 - 28))) ? ~(val) : (val))
#define K38XOR(val) ((keyFrom28To48 & (0x1U << (38 - 28))) ? ~(val) : (val))
#define K39XOR(val) ((keyFrom28To48 & (0x1U << (39 - 28))) ? ~(val) : (val))
#define K40XOR(val) ((keyFrom28To48 & (0x1U << (40 - 28))) ? ~(val) : (val))
#define K41XOR(val) ((keyFrom28To48 & (0x1U << (41 - 28))) ? ~(val) : (val))
#define K42XOR(val) ((keyFrom28To48 & (0x1U << (42 - 28))) ? ~(val) : (val))
#define K43XOR(val) ((keyFrom28To48 & (0x1U << (43 - 28))) ? ~(val) : (val))
#define K44XOR(val) ((keyFrom28To48 & (0x1U << (44 - 28))) ? ~(val) : (val))
#define K45XOR(val) ((keyFrom28To48 & (0x1U << (45 - 28))) ? ~(val) : (val))
#define K46XOR(val) ((keyFrom28To48 & (0x1U << (46 - 28))) ? ~(val) : (val))
#define K47XOR(val) ((keyFrom28To48 & (0x1U << (47 - 28))) ? ~(val) : (val))
#define K48XOR(val) ((keyFrom28To48 & (0x1U << (48 - 28))) ? ~(val) : (val))
	DES_Vector K49 = CUDA_keyFrom49To55Array[0];
	DES_Vector K50 = CUDA_keyFrom49To55Array[1];
	DES_Vector K51 = CUDA_keyFrom49To55Array[2];
	DES_Vector K52 = CUDA_keyFrom49To55Array[3];
	DES_Vector K53 = CUDA_keyFrom49To55Array[4];
	DES_Vector K54 = CUDA_keyFrom49To55Array[5];
	DES_Vector K55 = CUDA_keyFrom49To55Array[6];
#define K49XOR(val) ((val) ^ K49)
#define K50XOR(val) ((val) ^ K50)
#define K51XOR(val) ((val) ^ K51)
#define K52XOR(val) ((val) ^ K52)
#define K53XOR(val) ((val) ^ K53)
#define K54XOR(val) ((val) ^ K54)
#define K55XOR(val) ((val) ^ K55)

#if FALSE

#pragma unroll 1 // Do not unroll.
	for (int32_t i = 0; i < 13; ++i) {
		// ROUND_A(0);
		switch (threadIdx.y) {
		case 0: s1(K12XOR(db[E0]), K46XOR(db[E1]), K33XOR(db[E2]), K52XOR(db[E3]), K48XOR(db[E4]), K20XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K53XOR(db[11*N]), K06XOR(db[12*N]), K31XOR(db[13*N]), K25XOR(db[14*N]), K19XOR(db[15*N]), K41XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K04XOR(db[ 7*N]), K32XOR(db[ 8*N]), K26XOR(db[ 9*N]), K27XOR(db[10*N]), K38XOR(db[11*N]), K54XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K34XOR(db[E0]), K55XOR(db[E1]), K05XOR(db[E2]), K13XOR(db[E3]), K18XOR(db[E4]), K40XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K15XOR(db[E0]), K24XOR(db[E1]), K28XOR(db[E2]), K43XOR(db[E3]), K30XOR(db[E4]), K03XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K37XOR(db[27*N]), K08XOR(db[28*N]), K09XOR(db[29*N]), K50XOR(db[30*N]), K42XOR(db[31*N]), K21XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K51XOR(db[23*N]), K16XOR(db[24*N]), K29XOR(db[25*N]), K49XOR(db[26*N]), K07XOR(db[27*N]), K17XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K35XOR(db[E0]), K22XOR(db[E1]), K02XOR(db[E2]), K44XOR(db[E3]), K14XOR(db[E4]), K23XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(0);
		switch (threadIdx.y) {
		case 0: s1(K05XOR(db[(E0)+(32*N)]), K39XOR(db[(E1)+(32*N)]), K26XOR(db[(E2)+(32*N)]), K45XOR(db[(E3)+(32*N)]), K41XOR(db[(E4)+(32*N)]), K13XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K46XOR(db[43*N]), K54XOR(db[44*N]), K55XOR(db[45*N]), K18XOR(db[46*N]), K12XOR(db[47*N]), K34XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K52XOR(db[39*N]), K25XOR(db[40*N]), K19XOR(db[41*N]), K20XOR(db[42*N]), K31XOR(db[43*N]), K47XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K27XOR(db[(E0)+(32*N)]), K48XOR(db[(E1)+(32*N)]), K53XOR(db[(E2)+(32*N)]), K06XOR(db[(E3)+(32*N)]), K11XOR(db[(E4)+(32*N)]), K33XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K08XOR(db[(E0)+(32*N)]), K17XOR(db[(E1)+(32*N)]), K21XOR(db[(E2)+(32*N)]), K36XOR(db[(E3)+(32*N)]), K23XOR(db[(E4)+(32*N)]), K49XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K30XOR(db[59*N]), K01XOR(db[60*N]), K02XOR(db[61*N]), K43XOR(db[62*N]), K35XOR(db[63*N]), K14XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K44XOR(db[55*N]), K09XOR(db[56*N]), K22XOR(db[57*N]), K42XOR(db[58*N]), K00XOR(db[59*N]), K10XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K28XOR(db[(E0)+(32*N)]), K15XOR(db[(E1)+(32*N)]), K24XOR(db[(E2)+(32*N)]), K37XOR(db[(E3)+(32*N)]), K07XOR(db[(E4)+(32*N)]), K16XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(96);
		switch (threadIdx.y) {
		case 0: s1(K46XOR(db[E0]), K25XOR(db[E1]), K12XOR(db[E2]), K31XOR(db[E3]), K27XOR(db[E4]), K54XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K32XOR(db[11*N]), K40XOR(db[12*N]), K41XOR(db[13*N]), K04XOR(db[14*N]), K53XOR(db[15*N]), K20XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K38XOR(db[ 7*N]), K11XOR(db[ 8*N]), K05XOR(db[ 9*N]), K06XOR(db[10*N]), K48XOR(db[11*N]), K33XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K13XOR(db[E0]), K34XOR(db[E1]), K39XOR(db[E2]), K47XOR(db[E3]), K52XOR(db[E4]), K19XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K51XOR(db[E0]), K03XOR(db[E1]), K07XOR(db[E2]), K22XOR(db[E3]), K09XOR(db[E4]), K35XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K16XOR(db[27*N]), K44XOR(db[28*N]), K17XOR(db[29*N]), K29XOR(db[30*N]), K21XOR(db[31*N]), K00XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K30XOR(db[23*N]), K24XOR(db[24*N]), K08XOR(db[25*N]), K28XOR(db[26*N]), K43XOR(db[27*N]), K49XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K14XOR(db[E0]), K01XOR(db[E1]), K10XOR(db[E2]), K23XOR(db[E3]), K50XOR(db[E4]), K02XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(96);
		switch (threadIdx.y) {
		case 0: s1(K32XOR(db[(E0)+(32*N)]), K11XOR(db[(E1)+(32*N)]), K53XOR(db[(E2)+(32*N)]), K48XOR(db[(E3)+(32*N)]), K13XOR(db[(E4)+(32*N)]), K40XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K18XOR(db[43*N]), K26XOR(db[44*N]), K27XOR(db[45*N]), K45XOR(db[46*N]), K39XOR(db[47*N]), K06XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K55XOR(db[39*N]), K52XOR(db[40*N]), K46XOR(db[41*N]), K47XOR(db[42*N]), K34XOR(db[43*N]), K19XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K54XOR(db[(E0)+(32*N)]), K20XOR(db[(E1)+(32*N)]), K25XOR(db[(E2)+(32*N)]), K33XOR(db[(E3)+(32*N)]), K38XOR(db[(E4)+(32*N)]), K05XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K37XOR(db[(E0)+(32*N)]), K42XOR(db[(E1)+(32*N)]), K50XOR(db[(E2)+(32*N)]), K08XOR(db[(E3)+(32*N)]), K24XOR(db[(E4)+(32*N)]), K21XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K02XOR(db[59*N]), K30XOR(db[60*N]), K03XOR(db[61*N]), K15XOR(db[62*N]), K07XOR(db[63*N]), K43XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K16XOR(db[55*N]), K10XOR(db[56*N]), K51XOR(db[57*N]), K14XOR(db[58*N]), K29XOR(db[59*N]), K35XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K00XOR(db[(E0)+(32*N)]), K44XOR(db[(E1)+(32*N)]), K49XOR(db[(E2)+(32*N)]), K09XOR(db[(E3)+(32*N)]), K36XOR(db[(E4)+(32*N)]), K17XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(192);
		switch (threadIdx.y) {
		case 0: s1(K18XOR(db[E0]), K52XOR(db[E1]), K39XOR(db[E2]), K34XOR(db[E3]), K54XOR(db[E4]), K26XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K04XOR(db[11*N]), K12XOR(db[12*N]), K13XOR(db[13*N]), K31XOR(db[14*N]), K25XOR(db[15*N]), K47XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K41XOR(db[ 7*N]), K38XOR(db[ 8*N]), K32XOR(db[ 9*N]), K33XOR(db[10*N]), K20XOR(db[11*N]), K05XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K40XOR(db[E0]), K06XOR(db[E1]), K11XOR(db[E2]), K19XOR(db[E3]), K55XOR(db[E4]), K46XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K23XOR(db[E0]), K28XOR(db[E1]), K36XOR(db[E2]), K51XOR(db[E3]), K10XOR(db[E4]), K07XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K17XOR(db[27*N]), K16XOR(db[28*N]), K42XOR(db[29*N]), K01XOR(db[30*N]), K50XOR(db[31*N]), K29XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K02XOR(db[23*N]), K49XOR(db[24*N]), K37XOR(db[25*N]), K00XOR(db[26*N]), K15XOR(db[27*N]), K21XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K43XOR(db[E0]), K30XOR(db[E1]), K35XOR(db[E2]), K24XOR(db[E3]), K22XOR(db[E4]), K03XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(192);
		switch (threadIdx.y) {
		case 0: s1(K04XOR(db[(E0)+(32*N)]), K38XOR(db[(E1)+(32*N)]), K25XOR(db[(E2)+(32*N)]), K20XOR(db[(E3)+(32*N)]), K40XOR(db[(E4)+(32*N)]), K12XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K45XOR(db[43*N]), K53XOR(db[44*N]), K54XOR(db[45*N]), K48XOR(db[46*N]), K11XOR(db[47*N]), K33XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K27XOR(db[39*N]), K55XOR(db[40*N]), K18XOR(db[41*N]), K19XOR(db[42*N]), K06XOR(db[43*N]), K46XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K26XOR(db[(E0)+(32*N)]), K47XOR(db[(E1)+(32*N)]), K52XOR(db[(E2)+(32*N)]), K05XOR(db[(E3)+(32*N)]), K41XOR(db[(E4)+(32*N)]), K32XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K09XOR(db[(E0)+(32*N)]), K14XOR(db[(E1)+(32*N)]), K22XOR(db[(E2)+(32*N)]), K37XOR(db[(E3)+(32*N)]), K49XOR(db[(E4)+(32*N)]), K50XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K03XOR(db[59*N]), K02XOR(db[60*N]), K28XOR(db[61*N]), K44XOR(db[62*N]), K36XOR(db[63*N]), K15XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K17XOR(db[55*N]), K35XOR(db[56*N]), K23XOR(db[57*N]), K43XOR(db[58*N]), K01XOR(db[59*N]), K07XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K29XOR(db[(E0)+(32*N)]), K16XOR(db[(E1)+(32*N)]), K21XOR(db[(E2)+(32*N)]), K10XOR(db[(E3)+(32*N)]), K08XOR(db[(E4)+(32*N)]), K42XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(288);
		switch (threadIdx.y) {
		case 0: s1(K45XOR(db[E0]), K55XOR(db[E1]), K11XOR(db[E2]), K06XOR(db[E3]), K26XOR(db[E4]), K53XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K31XOR(db[11*N]), K39XOR(db[12*N]), K40XOR(db[13*N]), K34XOR(db[14*N]), K52XOR(db[15*N]), K19XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K13XOR(db[ 7*N]), K41XOR(db[ 8*N]), K04XOR(db[ 9*N]), K05XOR(db[10*N]), K47XOR(db[11*N]), K32XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K12XOR(db[E0]), K33XOR(db[E1]), K38XOR(db[E2]), K46XOR(db[E3]), K27XOR(db[E4]), K18XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K24XOR(db[E0]), K00XOR(db[E1]), K08XOR(db[E2]), K23XOR(db[E3]), K35XOR(db[E4]), K36XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K42XOR(db[27*N]), K17XOR(db[28*N]), K14XOR(db[29*N]), K30XOR(db[30*N]), K22XOR(db[31*N]), K01XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K03XOR(db[23*N]), K21XOR(db[24*N]), K09XOR(db[25*N]), K29XOR(db[26*N]), K44XOR(db[27*N]), K50XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K15XOR(db[E0]), K02XOR(db[E1]), K07XOR(db[E2]), K49XOR(db[E3]), K51XOR(db[E4]), K28XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(288);
		switch (threadIdx.y) {
		case 0: s1(K31XOR(db[(E0)+(32*N)]), K41XOR(db[(E1)+(32*N)]), K52XOR(db[(E2)+(32*N)]), K47XOR(db[(E3)+(32*N)]), K12XOR(db[(E4)+(32*N)]), K39XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K48XOR(db[43*N]), K25XOR(db[44*N]), K26XOR(db[45*N]), K20XOR(db[46*N]), K38XOR(db[47*N]), K05XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K54XOR(db[39*N]), K27XOR(db[40*N]), K45XOR(db[41*N]), K46XOR(db[42*N]), K33XOR(db[43*N]), K18XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K53XOR(db[(E0)+(32*N)]), K19XOR(db[(E1)+(32*N)]), K55XOR(db[(E2)+(32*N)]), K32XOR(db[(E3)+(32*N)]), K13XOR(db[(E4)+(32*N)]), K04XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K10XOR(db[(E0)+(32*N)]), K43XOR(db[(E1)+(32*N)]), K51XOR(db[(E2)+(32*N)]), K09XOR(db[(E3)+(32*N)]), K21XOR(db[(E4)+(32*N)]), K22XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K28XOR(db[59*N]), K03XOR(db[60*N]), K00XOR(db[61*N]), K16XOR(db[62*N]), K08XOR(db[63*N]), K44XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K42XOR(db[55*N]), K07XOR(db[56*N]), K24XOR(db[57*N]), K15XOR(db[58*N]), K30XOR(db[59*N]), K36XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K01XOR(db[(E0)+(32*N)]), K17XOR(db[(E1)+(32*N)]), K50XOR(db[(E2)+(32*N)]), K35XOR(db[(E3)+(32*N)]), K37XOR(db[(E4)+(32*N)]), K14XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(384);
		switch (threadIdx.y) {
		case 0: s1(K55XOR(db[E0]), K34XOR(db[E1]), K45XOR(db[E2]), K40XOR(db[E3]), K05XOR(db[E4]), K32XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K41XOR(db[11*N]), K18XOR(db[12*N]), K19XOR(db[13*N]), K13XOR(db[14*N]), K31XOR(db[15*N]), K53XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K47XOR(db[ 7*N]), K20XOR(db[ 8*N]), K38XOR(db[ 9*N]), K39XOR(db[10*N]), K26XOR(db[11*N]), K11XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K46XOR(db[E0]), K12XOR(db[E1]), K48XOR(db[E2]), K25XOR(db[E3]), K06XOR(db[E4]), K52XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K03XOR(db[E0]), K36XOR(db[E1]), K44XOR(db[E2]), K02XOR(db[E3]), K14XOR(db[E4]), K15XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K21XOR(db[27*N]), K49XOR(db[28*N]), K50XOR(db[29*N]), K09XOR(db[30*N]), K01XOR(db[31*N]), K37XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K35XOR(db[23*N]), K00XOR(db[24*N]), K17XOR(db[25*N]), K08XOR(db[26*N]), K23XOR(db[27*N]), K29XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K51XOR(db[E0]), K10XOR(db[E1]), K43XOR(db[E2]), K28XOR(db[E3]), K30XOR(db[E4]), K07XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(384);
		switch (threadIdx.y) {
		case 0: s1(K41XOR(db[(E0)+(32*N)]), K20XOR(db[(E1)+(32*N)]), K31XOR(db[(E2)+(32*N)]), K26XOR(db[(E3)+(32*N)]), K46XOR(db[(E4)+(32*N)]), K18XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K27XOR(db[43*N]), K04XOR(db[44*N]), K05XOR(db[45*N]), K54XOR(db[46*N]), K48XOR(db[47*N]), K39XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K33XOR(db[39*N]), K06XOR(db[40*N]), K55XOR(db[41*N]), K25XOR(db[42*N]), K12XOR(db[43*N]), K52XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K32XOR(db[(E0)+(32*N)]), K53XOR(db[(E1)+(32*N)]), K34XOR(db[(E2)+(32*N)]), K11XOR(db[(E3)+(32*N)]), K47XOR(db[(E4)+(32*N)]), K38XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K42XOR(db[(E0)+(32*N)]), K22XOR(db[(E1)+(32*N)]), K30XOR(db[(E2)+(32*N)]), K17XOR(db[(E3)+(32*N)]), K00XOR(db[(E4)+(32*N)]), K01XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K07XOR(db[59*N]), K35XOR(db[60*N]), K36XOR(db[61*N]), K24XOR(db[62*N]), K44XOR(db[63*N]), K23XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K21XOR(db[55*N]), K43XOR(db[56*N]), K03XOR(db[57*N]), K51XOR(db[58*N]), K09XOR(db[59*N]), K15XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K37XOR(db[(E0)+(32*N)]), K49XOR(db[(E1)+(32*N)]), K29XOR(db[(E2)+(32*N)]), K14XOR(db[(E3)+(32*N)]), K16XOR(db[(E4)+(32*N)]), K50XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(480);
		switch (threadIdx.y) {
		case 0: s1(K27XOR(db[E0]), K06XOR(db[E1]), K48XOR(db[E2]), K12XOR(db[E3]), K32XOR(db[E4]), K04XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K13XOR(db[11*N]), K45XOR(db[12*N]), K46XOR(db[13*N]), K40XOR(db[14*N]), K34XOR(db[15*N]), K25XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K19XOR(db[ 7*N]), K47XOR(db[ 8*N]), K41XOR(db[ 9*N]), K11XOR(db[10*N]), K53XOR(db[11*N]), K38XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K18XOR(db[E0]), K39XOR(db[E1]), K20XOR(db[E2]), K52XOR(db[E3]), K33XOR(db[E4]), K55XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K28XOR(db[E0]), K08XOR(db[E1]), K16XOR(db[E2]), K03XOR(db[E3]), K43XOR(db[E4]), K44XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K50XOR(db[27*N]), K21XOR(db[28*N]), K22XOR(db[29*N]), K10XOR(db[30*N]), K30XOR(db[31*N]), K09XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K07XOR(db[23*N]), K29XOR(db[24*N]), K42XOR(db[25*N]), K37XOR(db[26*N]), K24XOR(db[27*N]), K01XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K23XOR(db[E0]), K35XOR(db[E1]), K15XOR(db[E2]), K00XOR(db[E3]), K02XOR(db[E4]), K36XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(480);
		switch (threadIdx.y) {
		case 0: s1(K13XOR(db[(E0)+(32*N)]), K47XOR(db[(E1)+(32*N)]), K34XOR(db[(E2)+(32*N)]), K53XOR(db[(E3)+(32*N)]), K18XOR(db[(E4)+(32*N)]), K45XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K54XOR(db[43*N]), K31XOR(db[44*N]), K32XOR(db[45*N]), K26XOR(db[46*N]), K20XOR(db[47*N]), K11XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K05XOR(db[39*N]), K33XOR(db[40*N]), K27XOR(db[41*N]), K52XOR(db[42*N]), K39XOR(db[43*N]), K55XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K04XOR(db[(E0)+(32*N)]), K25XOR(db[(E1)+(32*N)]), K06XOR(db[(E2)+(32*N)]), K38XOR(db[(E3)+(32*N)]), K19XOR(db[(E4)+(32*N)]), K41XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K14XOR(db[(E0)+(32*N)]), K51XOR(db[(E1)+(32*N)]), K02XOR(db[(E2)+(32*N)]), K42XOR(db[(E3)+(32*N)]), K29XOR(db[(E4)+(32*N)]), K30XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K36XOR(db[59*N]), K07XOR(db[60*N]), K08XOR(db[61*N]), K49XOR(db[62*N]), K16XOR(db[63*N]), K24XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K50XOR(db[55*N]), K15XOR(db[56*N]), K28XOR(db[57*N]), K23XOR(db[58*N]), K10XOR(db[59*N]), K44XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K09XOR(db[(E0)+(32*N)]), K21XOR(db[(E1)+(32*N)]), K01XOR(db[(E2)+(32*N)]), K43XOR(db[(E3)+(32*N)]), K17XOR(db[(E4)+(32*N)]), K22XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(576);
		switch (threadIdx.y) {
		case 0: s1(K54XOR(db[E0]), K33XOR(db[E1]), K20XOR(db[E2]), K39XOR(db[E3]), K04XOR(db[E4]), K31XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K40XOR(db[11*N]), K48XOR(db[12*N]), K18XOR(db[13*N]), K12XOR(db[14*N]), K06XOR(db[15*N]), K52XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K46XOR(db[ 7*N]), K19XOR(db[ 8*N]), K13XOR(db[ 9*N]), K38XOR(db[10*N]), K25XOR(db[11*N]), K41XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K45XOR(db[E0]), K11XOR(db[E1]), K47XOR(db[E2]), K55XOR(db[E3]), K05XOR(db[E4]), K27XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K00XOR(db[E0]), K37XOR(db[E1]), K17XOR(db[E2]), K28XOR(db[E3]), K15XOR(db[E4]), K16XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K22XOR(db[27*N]), K50XOR(db[28*N]), K51XOR(db[29*N]), K35XOR(db[30*N]), K02XOR(db[31*N]), K10XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K36XOR(db[23*N]), K01XOR(db[24*N]), K14XOR(db[25*N]), K09XOR(db[26*N]), K49XOR(db[27*N]), K30XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K24XOR(db[E0]), K07XOR(db[E1]), K44XOR(db[E2]), K29XOR(db[E3]), K03XOR(db[E4]), K08XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(576);
		switch (threadIdx.y) {
		case 0: s1(K40XOR(db[(E0)+(32*N)]), K19XOR(db[(E1)+(32*N)]), K06XOR(db[(E2)+(32*N)]), K25XOR(db[(E3)+(32*N)]), K45XOR(db[(E4)+(32*N)]), K48XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K26XOR(db[43*N]), K34XOR(db[44*N]), K04XOR(db[45*N]), K53XOR(db[46*N]), K47XOR(db[47*N]), K38XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K32XOR(db[39*N]), K05XOR(db[40*N]), K54XOR(db[41*N]), K55XOR(db[42*N]), K11XOR(db[43*N]), K27XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K31XOR(db[(E0)+(32*N)]), K52XOR(db[(E1)+(32*N)]), K33XOR(db[(E2)+(32*N)]), K41XOR(db[(E3)+(32*N)]), K46XOR(db[(E4)+(32*N)]), K13XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K43XOR(db[(E0)+(32*N)]), K23XOR(db[(E1)+(32*N)]), K03XOR(db[(E2)+(32*N)]), K14XOR(db[(E3)+(32*N)]), K01XOR(db[(E4)+(32*N)]), K02XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K08XOR(db[59*N]), K36XOR(db[60*N]), K37XOR(db[61*N]), K21XOR(db[62*N]), K17XOR(db[63*N]), K49XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K22XOR(db[55*N]), K44XOR(db[56*N]), K00XOR(db[57*N]), K24XOR(db[58*N]), K35XOR(db[59*N]), K16XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K10XOR(db[(E0)+(32*N)]), K50XOR(db[(E1)+(32*N)]), K30XOR(db[(E2)+(32*N)]), K15XOR(db[(E3)+(32*N)]), K42XOR(db[(E4)+(32*N)]), K51XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(672);
		switch (threadIdx.y) {
		case 0: s1(K26XOR(db[E0]), K05XOR(db[E1]), K47XOR(db[E2]), K11XOR(db[E3]), K31XOR(db[E4]), K34XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K12XOR(db[11*N]), K20XOR(db[12*N]), K45XOR(db[13*N]), K39XOR(db[14*N]), K33XOR(db[15*N]), K55XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K18XOR(db[ 7*N]), K46XOR(db[ 8*N]), K40XOR(db[ 9*N]), K41XOR(db[10*N]), K52XOR(db[11*N]), K13XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K48XOR(db[E0]), K38XOR(db[E1]), K19XOR(db[E2]), K27XOR(db[E3]), K32XOR(db[E4]), K54XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K29XOR(db[E0]), K09XOR(db[E1]), K42XOR(db[E2]), K00XOR(db[E3]), K44XOR(db[E4]), K17XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K51XOR(db[27*N]), K22XOR(db[28*N]), K23XOR(db[29*N]), K07XOR(db[30*N]), K03XOR(db[31*N]), K35XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K08XOR(db[23*N]), K30XOR(db[24*N]), K43XOR(db[25*N]), K10XOR(db[26*N]), K21XOR(db[27*N]), K02XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K49XOR(db[E0]), K36XOR(db[E1]), K16XOR(db[E2]), K01XOR(db[E3]), K28XOR(db[E4]), K37XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(672);
		switch (threadIdx.y) {
		case 0: s1(K19XOR(db[(E0)+(32*N)]), K53XOR(db[(E1)+(32*N)]), K40XOR(db[(E2)+(32*N)]), K04XOR(db[(E3)+(32*N)]), K55XOR(db[(E4)+(32*N)]), K27XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K05XOR(db[43*N]), K13XOR(db[44*N]), K38XOR(db[45*N]), K32XOR(db[46*N]), K26XOR(db[47*N]), K48XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K11XOR(db[39*N]), K39XOR(db[40*N]), K33XOR(db[41*N]), K34XOR(db[42*N]), K45XOR(db[43*N]), K06XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K41XOR(db[(E0)+(32*N)]), K31XOR(db[(E1)+(32*N)]), K12XOR(db[(E2)+(32*N)]), K20XOR(db[(E3)+(32*N)]), K25XOR(db[(E4)+(32*N)]), K47XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K22XOR(db[(E0)+(32*N)]), K02XOR(db[(E1)+(32*N)]), K35XOR(db[(E2)+(32*N)]), K50XOR(db[(E3)+(32*N)]), K37XOR(db[(E4)+(32*N)]), K10XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K44XOR(db[59*N]), K15XOR(db[60*N]), K16XOR(db[61*N]), K00XOR(db[62*N]), K49XOR(db[63*N]), K28XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K01XOR(db[55*N]), K23XOR(db[56*N]), K36XOR(db[57*N]), K03XOR(db[58*N]), K14XOR(db[59*N]), K24XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K42XOR(db[(E0)+(32*N)]), K29XOR(db[(E1)+(32*N)]), K09XOR(db[(E2)+(32*N)]), K51XOR(db[(E3)+(32*N)]), K21XOR(db[(E4)+(32*N)]), K30XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		if (i >= 12)
			break;

		// ROUND_B(-48);
		switch (threadIdx.y) {
		case 0: s1(K12XOR(db[(E0)+(32*N)]), K46XOR(db[(E1)+(32*N)]), K33XOR(db[(E2)+(32*N)]), K52XOR(db[(E3)+(32*N)]), K48XOR(db[(E4)+(32*N)]), K20XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K53XOR(db[43*N]), K06XOR(db[44*N]), K31XOR(db[45*N]), K25XOR(db[46*N]), K19XOR(db[47*N]), K41XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K04XOR(db[39*N]), K32XOR(db[40*N]), K26XOR(db[41*N]), K27XOR(db[42*N]), K38XOR(db[43*N]), K54XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K34XOR(db[(E0)+(32*N)]), K55XOR(db[(E1)+(32*N)]), K05XOR(db[(E2)+(32*N)]), K13XOR(db[(E3)+(32*N)]), K18XOR(db[(E4)+(32*N)]), K40XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K15XOR(db[(E0)+(32*N)]), K24XOR(db[(E1)+(32*N)]), K28XOR(db[(E2)+(32*N)]), K43XOR(db[(E3)+(32*N)]), K30XOR(db[(E4)+(32*N)]), K03XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K37XOR(db[59*N]), K08XOR(db[60*N]), K09XOR(db[61*N]), K50XOR(db[62*N]), K42XOR(db[63*N]), K21XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K51XOR(db[55*N]), K16XOR(db[56*N]), K29XOR(db[57*N]), K49XOR(db[58*N]), K07XOR(db[59*N]), K17XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K35XOR(db[(E0)+(32*N)]), K22XOR(db[(E1)+(32*N)]), K02XOR(db[(E2)+(32*N)]), K44XOR(db[(E3)+(32*N)]), K14XOR(db[(E4)+(32*N)]), K23XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(48);
		switch (threadIdx.y) {
		case 0: s1(K05XOR(db[E0]), K39XOR(db[E1]), K26XOR(db[E2]), K45XOR(db[E3]), K41XOR(db[E4]), K13XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K46XOR(db[11*N]), K54XOR(db[12*N]), K55XOR(db[13*N]), K18XOR(db[14*N]), K12XOR(db[15*N]), K34XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K52XOR(db[ 7*N]), K25XOR(db[ 8*N]), K19XOR(db[ 9*N]), K20XOR(db[10*N]), K31XOR(db[11*N]), K47XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K27XOR(db[E0]), K48XOR(db[E1]), K53XOR(db[E2]), K06XOR(db[E3]), K11XOR(db[E4]), K33XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K08XOR(db[E0]), K17XOR(db[E1]), K21XOR(db[E2]), K36XOR(db[E3]), K23XOR(db[E4]), K49XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K30XOR(db[27*N]), K01XOR(db[28*N]), K02XOR(db[29*N]), K43XOR(db[30*N]), K35XOR(db[31*N]), K14XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K44XOR(db[23*N]), K09XOR(db[24*N]), K22XOR(db[25*N]), K42XOR(db[26*N]), K00XOR(db[27*N]), K10XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K28XOR(db[E0]), K15XOR(db[E1]), K24XOR(db[E2]), K37XOR(db[E3]), K07XOR(db[E4]), K16XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(48);
		switch (threadIdx.y) {
		case 0: s1(K46XOR(db[(E0)+(32*N)]), K25XOR(db[(E1)+(32*N)]), K12XOR(db[(E2)+(32*N)]), K31XOR(db[(E3)+(32*N)]), K27XOR(db[(E4)+(32*N)]), K54XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K32XOR(db[43*N]), K40XOR(db[44*N]), K41XOR(db[45*N]), K04XOR(db[46*N]), K53XOR(db[47*N]), K20XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K38XOR(db[39*N]), K11XOR(db[40*N]), K05XOR(db[41*N]), K06XOR(db[42*N]), K48XOR(db[43*N]), K33XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K13XOR(db[(E0)+(32*N)]), K34XOR(db[(E1)+(32*N)]), K39XOR(db[(E2)+(32*N)]), K47XOR(db[(E3)+(32*N)]), K52XOR(db[(E4)+(32*N)]), K19XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K51XOR(db[(E0)+(32*N)]), K03XOR(db[(E1)+(32*N)]), K07XOR(db[(E2)+(32*N)]), K22XOR(db[(E3)+(32*N)]), K09XOR(db[(E4)+(32*N)]), K35XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K16XOR(db[59*N]), K44XOR(db[60*N]), K17XOR(db[61*N]), K29XOR(db[62*N]), K21XOR(db[63*N]), K00XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K30XOR(db[55*N]), K24XOR(db[56*N]), K08XOR(db[57*N]), K28XOR(db[58*N]), K43XOR(db[59*N]), K49XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K14XOR(db[(E0)+(32*N)]), K01XOR(db[(E1)+(32*N)]), K10XOR(db[(E2)+(32*N)]), K23XOR(db[(E3)+(32*N)]), K50XOR(db[(E4)+(32*N)]), K02XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(144);
		switch (threadIdx.y) {
		case 0: s1(K32XOR(db[E0]), K11XOR(db[E1]), K53XOR(db[E2]), K48XOR(db[E3]), K13XOR(db[E4]), K40XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K18XOR(db[11*N]), K26XOR(db[12*N]), K27XOR(db[13*N]), K45XOR(db[14*N]), K39XOR(db[15*N]), K06XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K55XOR(db[ 7*N]), K52XOR(db[ 8*N]), K46XOR(db[ 9*N]), K47XOR(db[10*N]), K34XOR(db[11*N]), K19XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K54XOR(db[E0]), K20XOR(db[E1]), K25XOR(db[E2]), K33XOR(db[E3]), K38XOR(db[E4]), K05XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K37XOR(db[E0]), K42XOR(db[E1]), K50XOR(db[E2]), K08XOR(db[E3]), K24XOR(db[E4]), K21XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K02XOR(db[27*N]), K30XOR(db[28*N]), K03XOR(db[29*N]), K15XOR(db[30*N]), K07XOR(db[31*N]), K43XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K16XOR(db[23*N]), K10XOR(db[24*N]), K51XOR(db[25*N]), K14XOR(db[26*N]), K29XOR(db[27*N]), K35XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K00XOR(db[E0]), K44XOR(db[E1]), K49XOR(db[E2]), K09XOR(db[E3]), K36XOR(db[E4]), K17XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(144);
		switch (threadIdx.y) {
		case 0: s1(K18XOR(db[(E0)+(32*N)]), K52XOR(db[(E1)+(32*N)]), K39XOR(db[(E2)+(32*N)]), K34XOR(db[(E3)+(32*N)]), K54XOR(db[(E4)+(32*N)]), K26XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K04XOR(db[43*N]), K12XOR(db[44*N]), K13XOR(db[45*N]), K31XOR(db[46*N]), K25XOR(db[47*N]), K47XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K41XOR(db[39*N]), K38XOR(db[40*N]), K32XOR(db[41*N]), K33XOR(db[42*N]), K20XOR(db[43*N]), K05XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K40XOR(db[(E0)+(32*N)]), K06XOR(db[(E1)+(32*N)]), K11XOR(db[(E2)+(32*N)]), K19XOR(db[(E3)+(32*N)]), K55XOR(db[(E4)+(32*N)]), K46XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K23XOR(db[(E0)+(32*N)]), K28XOR(db[(E1)+(32*N)]), K36XOR(db[(E2)+(32*N)]), K51XOR(db[(E3)+(32*N)]), K10XOR(db[(E4)+(32*N)]), K07XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K17XOR(db[59*N]), K16XOR(db[60*N]), K42XOR(db[61*N]), K01XOR(db[62*N]), K50XOR(db[63*N]), K29XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K02XOR(db[55*N]), K49XOR(db[56*N]), K37XOR(db[57*N]), K00XOR(db[58*N]), K15XOR(db[59*N]), K21XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K43XOR(db[(E0)+(32*N)]), K30XOR(db[(E1)+(32*N)]), K35XOR(db[(E2)+(32*N)]), K24XOR(db[(E3)+(32*N)]), K22XOR(db[(E4)+(32*N)]), K03XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(240);
		switch (threadIdx.y) {
		case 0: s1(K04XOR(db[E0]), K38XOR(db[E1]), K25XOR(db[E2]), K20XOR(db[E3]), K40XOR(db[E4]), K12XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K45XOR(db[11*N]), K53XOR(db[12*N]), K54XOR(db[13*N]), K48XOR(db[14*N]), K11XOR(db[15*N]), K33XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K27XOR(db[ 7*N]), K55XOR(db[ 8*N]), K18XOR(db[ 9*N]), K19XOR(db[10*N]), K06XOR(db[11*N]), K46XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K26XOR(db[E0]), K47XOR(db[E1]), K52XOR(db[E2]), K05XOR(db[E3]), K41XOR(db[E4]), K32XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K09XOR(db[E0]), K14XOR(db[E1]), K22XOR(db[E2]), K37XOR(db[E3]), K49XOR(db[E4]), K50XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K03XOR(db[27*N]), K02XOR(db[28*N]), K28XOR(db[29*N]), K44XOR(db[30*N]), K36XOR(db[31*N]), K15XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K17XOR(db[23*N]), K35XOR(db[24*N]), K23XOR(db[25*N]), K43XOR(db[26*N]), K01XOR(db[27*N]), K07XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K29XOR(db[E0]), K16XOR(db[E1]), K21XOR(db[E2]), K10XOR(db[E3]), K08XOR(db[E4]), K42XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(240);
		switch (threadIdx.y) {
		case 0: s1(K45XOR(db[(E0)+(32*N)]), K55XOR(db[(E1)+(32*N)]), K11XOR(db[(E2)+(32*N)]), K06XOR(db[(E3)+(32*N)]), K26XOR(db[(E4)+(32*N)]), K53XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K31XOR(db[43*N]), K39XOR(db[44*N]), K40XOR(db[45*N]), K34XOR(db[46*N]), K52XOR(db[47*N]), K19XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K13XOR(db[39*N]), K41XOR(db[40*N]), K04XOR(db[41*N]), K05XOR(db[42*N]), K47XOR(db[43*N]), K32XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K12XOR(db[(E0)+(32*N)]), K33XOR(db[(E1)+(32*N)]), K38XOR(db[(E2)+(32*N)]), K46XOR(db[(E3)+(32*N)]), K27XOR(db[(E4)+(32*N)]), K18XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K24XOR(db[(E0)+(32*N)]), K00XOR(db[(E1)+(32*N)]), K08XOR(db[(E2)+(32*N)]), K23XOR(db[(E3)+(32*N)]), K35XOR(db[(E4)+(32*N)]), K36XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K42XOR(db[59*N]), K17XOR(db[60*N]), K14XOR(db[61*N]), K30XOR(db[62*N]), K22XOR(db[63*N]), K01XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K03XOR(db[55*N]), K21XOR(db[56*N]), K09XOR(db[57*N]), K29XOR(db[58*N]), K44XOR(db[59*N]), K50XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K15XOR(db[(E0)+(32*N)]), K02XOR(db[(E1)+(32*N)]), K07XOR(db[(E2)+(32*N)]), K49XOR(db[(E3)+(32*N)]), K51XOR(db[(E4)+(32*N)]), K28XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(336);
		switch (threadIdx.y) {
		case 0: s1(K31XOR(db[E0]), K41XOR(db[E1]), K52XOR(db[E2]), K47XOR(db[E3]), K12XOR(db[E4]), K39XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K48XOR(db[11*N]), K25XOR(db[12*N]), K26XOR(db[13*N]), K20XOR(db[14*N]), K38XOR(db[15*N]), K05XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K54XOR(db[ 7*N]), K27XOR(db[ 8*N]), K45XOR(db[ 9*N]), K46XOR(db[10*N]), K33XOR(db[11*N]), K18XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K53XOR(db[E0]), K19XOR(db[E1]), K55XOR(db[E2]), K32XOR(db[E3]), K13XOR(db[E4]), K04XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K10XOR(db[E0]), K43XOR(db[E1]), K51XOR(db[E2]), K09XOR(db[E3]), K21XOR(db[E4]), K22XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K28XOR(db[27*N]), K03XOR(db[28*N]), K00XOR(db[29*N]), K16XOR(db[30*N]), K08XOR(db[31*N]), K44XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K42XOR(db[23*N]), K07XOR(db[24*N]), K24XOR(db[25*N]), K15XOR(db[26*N]), K30XOR(db[27*N]), K36XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K01XOR(db[E0]), K17XOR(db[E1]), K50XOR(db[E2]), K35XOR(db[E3]), K37XOR(db[E4]), K14XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(336);
		switch (threadIdx.y) {
		case 0: s1(K55XOR(db[(E0)+(32*N)]), K34XOR(db[(E1)+(32*N)]), K45XOR(db[(E2)+(32*N)]), K40XOR(db[(E3)+(32*N)]), K05XOR(db[(E4)+(32*N)]), K32XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K41XOR(db[43*N]), K18XOR(db[44*N]), K19XOR(db[45*N]), K13XOR(db[46*N]), K31XOR(db[47*N]), K53XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K47XOR(db[39*N]), K20XOR(db[40*N]), K38XOR(db[41*N]), K39XOR(db[42*N]), K26XOR(db[43*N]), K11XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K46XOR(db[(E0)+(32*N)]), K12XOR(db[(E1)+(32*N)]), K48XOR(db[(E2)+(32*N)]), K25XOR(db[(E3)+(32*N)]), K06XOR(db[(E4)+(32*N)]), K52XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K03XOR(db[(E0)+(32*N)]), K36XOR(db[(E1)+(32*N)]), K44XOR(db[(E2)+(32*N)]), K02XOR(db[(E3)+(32*N)]), K14XOR(db[(E4)+(32*N)]), K15XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K21XOR(db[59*N]), K49XOR(db[60*N]), K50XOR(db[61*N]), K09XOR(db[62*N]), K01XOR(db[63*N]), K37XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K35XOR(db[55*N]), K00XOR(db[56*N]), K17XOR(db[57*N]), K08XOR(db[58*N]), K23XOR(db[59*N]), K29XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K51XOR(db[(E0)+(32*N)]), K10XOR(db[(E1)+(32*N)]), K43XOR(db[(E2)+(32*N)]), K28XOR(db[(E3)+(32*N)]), K30XOR(db[(E4)+(32*N)]), K07XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(432);
		switch (threadIdx.y) {
		case 0: s1(K41XOR(db[E0]), K20XOR(db[E1]), K31XOR(db[E2]), K26XOR(db[E3]), K46XOR(db[E4]), K18XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K27XOR(db[11*N]), K04XOR(db[12*N]), K05XOR(db[13*N]), K54XOR(db[14*N]), K48XOR(db[15*N]), K39XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K33XOR(db[ 7*N]), K06XOR(db[ 8*N]), K55XOR(db[ 9*N]), K25XOR(db[10*N]), K12XOR(db[11*N]), K52XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K32XOR(db[E0]), K53XOR(db[E1]), K34XOR(db[E2]), K11XOR(db[E3]), K47XOR(db[E4]), K38XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K42XOR(db[E0]), K22XOR(db[E1]), K30XOR(db[E2]), K17XOR(db[E3]), K00XOR(db[E4]), K01XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K07XOR(db[27*N]), K35XOR(db[28*N]), K36XOR(db[29*N]), K24XOR(db[30*N]), K44XOR(db[31*N]), K23XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K21XOR(db[23*N]), K43XOR(db[24*N]), K03XOR(db[25*N]), K51XOR(db[26*N]), K09XOR(db[27*N]), K15XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K37XOR(db[E0]), K49XOR(db[E1]), K29XOR(db[E2]), K14XOR(db[E3]), K16XOR(db[E4]), K50XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(432);
		switch (threadIdx.y) {
		case 0: s1(K27XOR(db[(E0)+(32*N)]), K06XOR(db[(E1)+(32*N)]), K48XOR(db[(E2)+(32*N)]), K12XOR(db[(E3)+(32*N)]), K32XOR(db[(E4)+(32*N)]), K04XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K13XOR(db[43*N]), K45XOR(db[44*N]), K46XOR(db[45*N]), K40XOR(db[46*N]), K34XOR(db[47*N]), K25XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K19XOR(db[39*N]), K47XOR(db[40*N]), K41XOR(db[41*N]), K11XOR(db[42*N]), K53XOR(db[43*N]), K38XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K18XOR(db[(E0)+(32*N)]), K39XOR(db[(E1)+(32*N)]), K20XOR(db[(E2)+(32*N)]), K52XOR(db[(E3)+(32*N)]), K33XOR(db[(E4)+(32*N)]), K55XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K28XOR(db[(E0)+(32*N)]), K08XOR(db[(E1)+(32*N)]), K16XOR(db[(E2)+(32*N)]), K03XOR(db[(E3)+(32*N)]), K43XOR(db[(E4)+(32*N)]), K44XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K50XOR(db[59*N]), K21XOR(db[60*N]), K22XOR(db[61*N]), K10XOR(db[62*N]), K30XOR(db[63*N]), K09XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K07XOR(db[55*N]), K29XOR(db[56*N]), K42XOR(db[57*N]), K37XOR(db[58*N]), K24XOR(db[59*N]), K01XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K23XOR(db[(E0)+(32*N)]), K35XOR(db[(E1)+(32*N)]), K15XOR(db[(E2)+(32*N)]), K00XOR(db[(E3)+(32*N)]), K02XOR(db[(E4)+(32*N)]), K36XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(528);
		switch (threadIdx.y) {
		case 0: s1(K13XOR(db[E0]), K47XOR(db[E1]), K34XOR(db[E2]), K53XOR(db[E3]), K18XOR(db[E4]), K45XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K54XOR(db[11*N]), K31XOR(db[12*N]), K32XOR(db[13*N]), K26XOR(db[14*N]), K20XOR(db[15*N]), K11XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K05XOR(db[ 7*N]), K33XOR(db[ 8*N]), K27XOR(db[ 9*N]), K52XOR(db[10*N]), K39XOR(db[11*N]), K55XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K04XOR(db[E0]), K25XOR(db[E1]), K06XOR(db[E2]), K38XOR(db[E3]), K19XOR(db[E4]), K41XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K14XOR(db[E0]), K51XOR(db[E1]), K02XOR(db[E2]), K42XOR(db[E3]), K29XOR(db[E4]), K30XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K36XOR(db[27*N]), K07XOR(db[28*N]), K08XOR(db[29*N]), K49XOR(db[30*N]), K16XOR(db[31*N]), K24XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K50XOR(db[23*N]), K15XOR(db[24*N]), K28XOR(db[25*N]), K23XOR(db[26*N]), K10XOR(db[27*N]), K44XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K09XOR(db[E0]), K21XOR(db[E1]), K01XOR(db[E2]), K43XOR(db[E3]), K17XOR(db[E4]), K22XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(528);
		switch (threadIdx.y) {
		case 0: s1(K54XOR(db[(E0)+(32*N)]), K33XOR(db[(E1)+(32*N)]), K20XOR(db[(E2)+(32*N)]), K39XOR(db[(E3)+(32*N)]), K04XOR(db[(E4)+(32*N)]), K31XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K40XOR(db[43*N]), K48XOR(db[44*N]), K18XOR(db[45*N]), K12XOR(db[46*N]), K06XOR(db[47*N]), K52XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K46XOR(db[39*N]), K19XOR(db[40*N]), K13XOR(db[41*N]), K38XOR(db[42*N]), K25XOR(db[43*N]), K41XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K45XOR(db[(E0)+(32*N)]), K11XOR(db[(E1)+(32*N)]), K47XOR(db[(E2)+(32*N)]), K55XOR(db[(E3)+(32*N)]), K05XOR(db[(E4)+(32*N)]), K27XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K00XOR(db[(E0)+(32*N)]), K37XOR(db[(E1)+(32*N)]), K17XOR(db[(E2)+(32*N)]), K28XOR(db[(E3)+(32*N)]), K15XOR(db[(E4)+(32*N)]), K16XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K22XOR(db[59*N]), K50XOR(db[60*N]), K51XOR(db[61*N]), K35XOR(db[62*N]), K02XOR(db[63*N]), K10XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K36XOR(db[55*N]), K01XOR(db[56*N]), K14XOR(db[57*N]), K09XOR(db[58*N]), K49XOR(db[59*N]), K30XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K24XOR(db[(E0)+(32*N)]), K07XOR(db[(E1)+(32*N)]), K44XOR(db[(E2)+(32*N)]), K29XOR(db[(E3)+(32*N)]), K03XOR(db[(E4)+(32*N)]), K08XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(624);
		switch (threadIdx.y) {
		case 0: s1(K40XOR(db[E0]), K19XOR(db[E1]), K06XOR(db[E2]), K25XOR(db[E3]), K45XOR(db[E4]), K48XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K26XOR(db[11*N]), K34XOR(db[12*N]), K04XOR(db[13*N]), K53XOR(db[14*N]), K47XOR(db[15*N]), K38XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K32XOR(db[ 7*N]), K05XOR(db[ 8*N]), K54XOR(db[ 9*N]), K55XOR(db[10*N]), K11XOR(db[11*N]), K27XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K31XOR(db[E0]), K52XOR(db[E1]), K33XOR(db[E2]), K41XOR(db[E3]), K46XOR(db[E4]), K13XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K43XOR(db[E0]), K23XOR(db[E1]), K03XOR(db[E2]), K14XOR(db[E3]), K01XOR(db[E4]), K02XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K08XOR(db[27*N]), K36XOR(db[28*N]), K37XOR(db[29*N]), K21XOR(db[30*N]), K17XOR(db[31*N]), K49XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K22XOR(db[23*N]), K44XOR(db[24*N]), K00XOR(db[25*N]), K24XOR(db[26*N]), K35XOR(db[27*N]), K16XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K10XOR(db[E0]), K50XOR(db[E1]), K30XOR(db[E2]), K15XOR(db[E3]), K42XOR(db[E4]), K51XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();

		// ROUND_B(624);
		switch (threadIdx.y) {
		case 0: s1(K26XOR(db[(E0)+(32*N)]), K05XOR(db[(E1)+(32*N)]), K47XOR(db[(E2)+(32*N)]), K11XOR(db[(E3)+(32*N)]), K31XOR(db[(E4)+(32*N)]), K34XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		        s4(K12XOR(db[43*N]), K20XOR(db[44*N]), K45XOR(db[45*N]), K39XOR(db[46*N]), K33XOR(db[47*N]), K55XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); break;
		case 1: s3(K18XOR(db[39*N]), K46XOR(db[40*N]), K40XOR(db[41*N]), K41XOR(db[42*N]), K52XOR(db[43*N]), K13XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		        s2(K48XOR(db[(E0)+(32*N)]), K38XOR(db[(E1)+(32*N)]), K19XOR(db[(E2)+(32*N)]), K27XOR(db[(E3)+(32*N)]), K32XOR(db[(E4)+(32*N)]), K54XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); break;
		case 2: s5(K29XOR(db[(E0)+(32*N)]), K09XOR(db[(E1)+(32*N)]), K42XOR(db[(E2)+(32*N)]), K00XOR(db[(E3)+(32*N)]), K44XOR(db[(E4)+(32*N)]), K17XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		        s8(K51XOR(db[59*N]), K22XOR(db[60*N]), K23XOR(db[61*N]), K07XOR(db[62*N]), K03XOR(db[63*N]), K35XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); break;
		case 3: s7(K08XOR(db[55*N]), K30XOR(db[56*N]), K43XOR(db[57*N]), K10XOR(db[58*N]), K21XOR(db[59*N]), K02XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
		        s6(K49XOR(db[(E0)+(32*N)]), K36XOR(db[(E1)+(32*N)]), K16XOR(db[(E2)+(32*N)]), K01XOR(db[(E3)+(32*N)]), K28XOR(db[(E4)+(32*N)]), K37XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); break;
		}
		__syncthreads();

		// ROUND_A(720);
		switch (threadIdx.y) {
		case 0: s1(K19XOR(db[E0]), K53XOR(db[E1]), K40XOR(db[E2]), K04XOR(db[E3]), K55XOR(db[E4]), K27XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		        s4(K05XOR(db[11*N]), K13XOR(db[12*N]), K38XOR(db[13*N]), K32XOR(db[14*N]), K26XOR(db[15*N]), K48XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); break;
		case 1: s3(K11XOR(db[ 7*N]), K39XOR(db[ 8*N]), K33XOR(db[ 9*N]), K34XOR(db[10*N]), K45XOR(db[11*N]), K06XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		        s2(K41XOR(db[E0]), K31XOR(db[E1]), K12XOR(db[E2]), K20XOR(db[E3]), K25XOR(db[E4]), K47XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); break;
		case 2: s5(K22XOR(db[E0]), K02XOR(db[E1]), K35XOR(db[E2]), K50XOR(db[E3]), K37XOR(db[E4]), K10XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		        s8(K44XOR(db[27*N]), K15XOR(db[28*N]), K16XOR(db[29*N]), K00XOR(db[30*N]), K49XOR(db[31*N]), K28XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); break;
		case 3: s7(K01XOR(db[23*N]), K23XOR(db[24*N]), K36XOR(db[25*N]), K03XOR(db[26*N]), K14XOR(db[27*N]), K24XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		        s6(K42XOR(db[E0]), K29XOR(db[E1]), K09XOR(db[E2]), K51XOR(db[E3]), K21XOR(db[E4]), K30XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); break;
		}
		__syncthreads();
	}

#else

	// For some reason, this routine works better on GTX580.
#pragma unroll 1 // Do not unroll.
	for (int32_t i = 0; i < 13; ++i) {
		switch (threadIdx.y) {
		case 0: 
			s1(K12XOR(db[E0]), K46XOR(db[E1]), K33XOR(db[E2]), K52XOR(db[E3]), K48XOR(db[E4]), K20XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		    s4(K53XOR(db[11*N]), K06XOR(db[12*N]), K31XOR(db[13*N]), K25XOR(db[14*N]), K19XOR(db[15*N]), K41XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K05XOR(db[(E0)+(32*N)]), K39XOR(db[(E1)+(32*N)]), K26XOR(db[(E2)+(32*N)]), K45XOR(db[(E3)+(32*N)]), K41XOR(db[(E4)+(32*N)]), K13XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		    s4(K46XOR(db[43*N]), K54XOR(db[44*N]), K55XOR(db[45*N]), K18XOR(db[46*N]), K12XOR(db[47*N]), K34XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]);
			__syncthreads();
			s1(K46XOR(db[E0]), K25XOR(db[E1]), K12XOR(db[E2]), K31XOR(db[E3]), K27XOR(db[E4]), K54XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
	        s4(K32XOR(db[11*N]), K40XOR(db[12*N]), K41XOR(db[13*N]), K04XOR(db[14*N]), K53XOR(db[15*N]), K20XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]);
			__syncthreads();
			s1(K32XOR(db[(E0)+(32*N)]), K11XOR(db[(E1)+(32*N)]), K53XOR(db[(E2)+(32*N)]), K48XOR(db[(E3)+(32*N)]), K13XOR(db[(E4)+(32*N)]), K40XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
		    s4(K18XOR(db[43*N]), K26XOR(db[44*N]), K27XOR(db[45*N]), K45XOR(db[46*N]), K39XOR(db[47*N]), K06XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]);
			__syncthreads();
			s1(K18XOR(db[E0]), K52XOR(db[E1]), K39XOR(db[E2]), K34XOR(db[E3]), K54XOR(db[E4]), K26XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
		    s4(K04XOR(db[11*N]), K12XOR(db[12*N]), K13XOR(db[13*N]), K31XOR(db[14*N]), K25XOR(db[15*N]), K47XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]);
			__syncthreads();
			s1(K04XOR(db[(E0)+(32*N)]), K38XOR(db[(E1)+(32*N)]), K25XOR(db[(E2)+(32*N)]), K20XOR(db[(E3)+(32*N)]), K40XOR(db[(E4)+(32*N)]), K12XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K45XOR(db[43*N]), K53XOR(db[44*N]), K54XOR(db[45*N]), K48XOR(db[46*N]), K11XOR(db[47*N]), K33XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K45XOR(db[E0]), K55XOR(db[E1]), K11XOR(db[E2]), K06XOR(db[E3]), K26XOR(db[E4]), K53XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K31XOR(db[11*N]), K39XOR(db[12*N]), K40XOR(db[13*N]), K34XOR(db[14*N]), K52XOR(db[15*N]), K19XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K31XOR(db[(E0)+(32*N)]), K41XOR(db[(E1)+(32*N)]), K52XOR(db[(E2)+(32*N)]), K47XOR(db[(E3)+(32*N)]), K12XOR(db[(E4)+(32*N)]), K39XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K48XOR(db[43*N]), K25XOR(db[44*N]), K26XOR(db[45*N]), K20XOR(db[46*N]), K38XOR(db[47*N]), K05XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K55XOR(db[E0]), K34XOR(db[E1]), K45XOR(db[E2]), K40XOR(db[E3]), K05XOR(db[E4]), K32XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K41XOR(db[11*N]), K18XOR(db[12*N]), K19XOR(db[13*N]), K13XOR(db[14*N]), K31XOR(db[15*N]), K53XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K41XOR(db[(E0)+(32*N)]), K20XOR(db[(E1)+(32*N)]), K31XOR(db[(E2)+(32*N)]), K26XOR(db[(E3)+(32*N)]), K46XOR(db[(E4)+(32*N)]), K18XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K27XOR(db[43*N]), K04XOR(db[44*N]), K05XOR(db[45*N]), K54XOR(db[46*N]), K48XOR(db[47*N]), K39XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K27XOR(db[E0]), K06XOR(db[E1]), K48XOR(db[E2]), K12XOR(db[E3]), K32XOR(db[E4]), K04XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K13XOR(db[11*N]), K45XOR(db[12*N]), K46XOR(db[13*N]), K40XOR(db[14*N]), K34XOR(db[15*N]), K25XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K13XOR(db[(E0)+(32*N)]), K47XOR(db[(E1)+(32*N)]), K34XOR(db[(E2)+(32*N)]), K53XOR(db[(E3)+(32*N)]), K18XOR(db[(E4)+(32*N)]), K45XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K54XOR(db[43*N]), K31XOR(db[44*N]), K32XOR(db[45*N]), K26XOR(db[46*N]), K20XOR(db[47*N]), K11XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K54XOR(db[E0]), K33XOR(db[E1]), K20XOR(db[E2]), K39XOR(db[E3]), K04XOR(db[E4]), K31XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K40XOR(db[11*N]), K48XOR(db[12*N]), K18XOR(db[13*N]), K12XOR(db[14*N]), K06XOR(db[15*N]), K52XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K40XOR(db[(E0)+(32*N)]), K19XOR(db[(E1)+(32*N)]), K06XOR(db[(E2)+(32*N)]), K25XOR(db[(E3)+(32*N)]), K45XOR(db[(E4)+(32*N)]), K48XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K26XOR(db[43*N]), K34XOR(db[44*N]), K04XOR(db[45*N]), K53XOR(db[46*N]), K47XOR(db[47*N]), K38XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K26XOR(db[E0]), K05XOR(db[E1]), K47XOR(db[E2]), K11XOR(db[E3]), K31XOR(db[E4]), K34XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K12XOR(db[11*N]), K20XOR(db[12*N]), K45XOR(db[13*N]), K39XOR(db[14*N]), K33XOR(db[15*N]), K55XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K19XOR(db[(E0)+(32*N)]), K53XOR(db[(E1)+(32*N)]), K40XOR(db[(E2)+(32*N)]), K04XOR(db[(E3)+(32*N)]), K55XOR(db[(E4)+(32*N)]), K27XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K05XOR(db[43*N]), K13XOR(db[44*N]), K38XOR(db[45*N]), K32XOR(db[46*N]), K26XOR(db[47*N]), K48XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			break;
		case 1: 
			s3(K04XOR(db[ 7*N]), K32XOR(db[ 8*N]), K26XOR(db[ 9*N]), K27XOR(db[10*N]), K38XOR(db[11*N]), K54XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		    s2(K34XOR(db[E0]), K55XOR(db[E1]), K05XOR(db[E2]), K13XOR(db[E3]), K18XOR(db[E4]), K40XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K52XOR(db[39*N]), K25XOR(db[40*N]), K19XOR(db[41*N]), K20XOR(db[42*N]), K31XOR(db[43*N]), K47XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		    s2(K27XOR(db[(E0)+(32*N)]), K48XOR(db[(E1)+(32*N)]), K53XOR(db[(E2)+(32*N)]), K06XOR(db[(E3)+(32*N)]), K11XOR(db[(E4)+(32*N)]), K33XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K38XOR(db[ 7*N]), K11XOR(db[ 8*N]), K05XOR(db[ 9*N]), K06XOR(db[10*N]), K48XOR(db[11*N]), K33XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
	        s2(K13XOR(db[E0]), K34XOR(db[E1]), K39XOR(db[E2]), K47XOR(db[E3]), K52XOR(db[E4]), K19XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]);
			__syncthreads();
			s3(K55XOR(db[39*N]), K52XOR(db[40*N]), K46XOR(db[41*N]), K47XOR(db[42*N]), K34XOR(db[43*N]), K19XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
		    s2(K54XOR(db[(E0)+(32*N)]), K20XOR(db[(E1)+(32*N)]), K25XOR(db[(E2)+(32*N)]), K33XOR(db[(E3)+(32*N)]), K38XOR(db[(E4)+(32*N)]), K05XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]);
			__syncthreads();
			s3(K41XOR(db[ 7*N]), K38XOR(db[ 8*N]), K32XOR(db[ 9*N]), K33XOR(db[10*N]), K20XOR(db[11*N]), K05XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
		    s2(K40XOR(db[E0]), K06XOR(db[E1]), K11XOR(db[E2]), K19XOR(db[E3]), K55XOR(db[E4]), K46XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]);
			__syncthreads();
			s3(K27XOR(db[39*N]), K55XOR(db[40*N]), K18XOR(db[41*N]), K19XOR(db[42*N]), K06XOR(db[43*N]), K46XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K26XOR(db[(E0)+(32*N)]), K47XOR(db[(E1)+(32*N)]), K52XOR(db[(E2)+(32*N)]), K05XOR(db[(E3)+(32*N)]), K41XOR(db[(E4)+(32*N)]), K32XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K13XOR(db[ 7*N]), K41XOR(db[ 8*N]), K04XOR(db[ 9*N]), K05XOR(db[10*N]), K47XOR(db[11*N]), K32XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K12XOR(db[E0]), K33XOR(db[E1]), K38XOR(db[E2]), K46XOR(db[E3]), K27XOR(db[E4]), K18XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K54XOR(db[39*N]), K27XOR(db[40*N]), K45XOR(db[41*N]), K46XOR(db[42*N]), K33XOR(db[43*N]), K18XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K53XOR(db[(E0)+(32*N)]), K19XOR(db[(E1)+(32*N)]), K55XOR(db[(E2)+(32*N)]), K32XOR(db[(E3)+(32*N)]), K13XOR(db[(E4)+(32*N)]), K04XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K47XOR(db[ 7*N]), K20XOR(db[ 8*N]), K38XOR(db[ 9*N]), K39XOR(db[10*N]), K26XOR(db[11*N]), K11XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K46XOR(db[E0]), K12XOR(db[E1]), K48XOR(db[E2]), K25XOR(db[E3]), K06XOR(db[E4]), K52XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K33XOR(db[39*N]), K06XOR(db[40*N]), K55XOR(db[41*N]), K25XOR(db[42*N]), K12XOR(db[43*N]), K52XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K32XOR(db[(E0)+(32*N)]), K53XOR(db[(E1)+(32*N)]), K34XOR(db[(E2)+(32*N)]), K11XOR(db[(E3)+(32*N)]), K47XOR(db[(E4)+(32*N)]), K38XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K19XOR(db[ 7*N]), K47XOR(db[ 8*N]), K41XOR(db[ 9*N]), K11XOR(db[10*N]), K53XOR(db[11*N]), K38XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K18XOR(db[E0]), K39XOR(db[E1]), K20XOR(db[E2]), K52XOR(db[E3]), K33XOR(db[E4]), K55XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K05XOR(db[39*N]), K33XOR(db[40*N]), K27XOR(db[41*N]), K52XOR(db[42*N]), K39XOR(db[43*N]), K55XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K04XOR(db[(E0)+(32*N)]), K25XOR(db[(E1)+(32*N)]), K06XOR(db[(E2)+(32*N)]), K38XOR(db[(E3)+(32*N)]), K19XOR(db[(E4)+(32*N)]), K41XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K46XOR(db[ 7*N]), K19XOR(db[ 8*N]), K13XOR(db[ 9*N]), K38XOR(db[10*N]), K25XOR(db[11*N]), K41XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K45XOR(db[E0]), K11XOR(db[E1]), K47XOR(db[E2]), K55XOR(db[E3]), K05XOR(db[E4]), K27XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K32XOR(db[39*N]), K05XOR(db[40*N]), K54XOR(db[41*N]), K55XOR(db[42*N]), K11XOR(db[43*N]), K27XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K31XOR(db[(E0)+(32*N)]), K52XOR(db[(E1)+(32*N)]), K33XOR(db[(E2)+(32*N)]), K41XOR(db[(E3)+(32*N)]), K46XOR(db[(E4)+(32*N)]), K13XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K18XOR(db[ 7*N]), K46XOR(db[ 8*N]), K40XOR(db[ 9*N]), K41XOR(db[10*N]), K52XOR(db[11*N]), K13XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K48XOR(db[E0]), K38XOR(db[E1]), K19XOR(db[E2]), K27XOR(db[E3]), K32XOR(db[E4]), K54XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K11XOR(db[39*N]), K39XOR(db[40*N]), K33XOR(db[41*N]), K34XOR(db[42*N]), K45XOR(db[43*N]), K06XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K41XOR(db[(E0)+(32*N)]), K31XOR(db[(E1)+(32*N)]), K12XOR(db[(E2)+(32*N)]), K20XOR(db[(E3)+(32*N)]), K25XOR(db[(E4)+(32*N)]), K47XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			break;
		case 2: 
			s5(K15XOR(db[E0]), K24XOR(db[E1]), K28XOR(db[E2]), K43XOR(db[E3]), K30XOR(db[E4]), K03XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K37XOR(db[27*N]), K08XOR(db[28*N]), K09XOR(db[29*N]), K50XOR(db[30*N]), K42XOR(db[31*N]), K21XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]);
			__syncthreads();
			s5(K08XOR(db[(E0)+(32*N)]), K17XOR(db[(E1)+(32*N)]), K21XOR(db[(E2)+(32*N)]), K36XOR(db[(E3)+(32*N)]), K23XOR(db[(E4)+(32*N)]), K49XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K30XOR(db[59*N]), K01XOR(db[60*N]), K02XOR(db[61*N]), K43XOR(db[62*N]), K35XOR(db[63*N]), K14XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]);
			__syncthreads();
			s5(K51XOR(db[E0]), K03XOR(db[E1]), K07XOR(db[E2]), K22XOR(db[E3]), K09XOR(db[E4]), K35XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
	        s8(K16XOR(db[27*N]), K44XOR(db[28*N]), K17XOR(db[29*N]), K29XOR(db[30*N]), K21XOR(db[31*N]), K00XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]);
			__syncthreads();
			s5(K37XOR(db[(E0)+(32*N)]), K42XOR(db[(E1)+(32*N)]), K50XOR(db[(E2)+(32*N)]), K08XOR(db[(E3)+(32*N)]), K24XOR(db[(E4)+(32*N)]), K21XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
		    s8(K02XOR(db[59*N]), K30XOR(db[60*N]), K03XOR(db[61*N]), K15XOR(db[62*N]), K07XOR(db[63*N]), K43XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]);
			__syncthreads();
			s5(K23XOR(db[E0]), K28XOR(db[E1]), K36XOR(db[E2]), K51XOR(db[E3]), K10XOR(db[E4]), K07XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
		    s8(K17XOR(db[27*N]), K16XOR(db[28*N]), K42XOR(db[29*N]), K01XOR(db[30*N]), K50XOR(db[31*N]), K29XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]);
			__syncthreads();
			s5(K09XOR(db[(E0)+(32*N)]), K14XOR(db[(E1)+(32*N)]), K22XOR(db[(E2)+(32*N)]), K37XOR(db[(E3)+(32*N)]), K49XOR(db[(E4)+(32*N)]), K50XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K03XOR(db[59*N]), K02XOR(db[60*N]), K28XOR(db[61*N]), K44XOR(db[62*N]), K36XOR(db[63*N]), K15XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K24XOR(db[E0]), K00XOR(db[E1]), K08XOR(db[E2]), K23XOR(db[E3]), K35XOR(db[E4]), K36XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K42XOR(db[27*N]), K17XOR(db[28*N]), K14XOR(db[29*N]), K30XOR(db[30*N]), K22XOR(db[31*N]), K01XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K10XOR(db[(E0)+(32*N)]), K43XOR(db[(E1)+(32*N)]), K51XOR(db[(E2)+(32*N)]), K09XOR(db[(E3)+(32*N)]), K21XOR(db[(E4)+(32*N)]), K22XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K28XOR(db[59*N]), K03XOR(db[60*N]), K00XOR(db[61*N]), K16XOR(db[62*N]), K08XOR(db[63*N]), K44XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K03XOR(db[E0]), K36XOR(db[E1]), K44XOR(db[E2]), K02XOR(db[E3]), K14XOR(db[E4]), K15XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K21XOR(db[27*N]), K49XOR(db[28*N]), K50XOR(db[29*N]), K09XOR(db[30*N]), K01XOR(db[31*N]), K37XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K42XOR(db[(E0)+(32*N)]), K22XOR(db[(E1)+(32*N)]), K30XOR(db[(E2)+(32*N)]), K17XOR(db[(E3)+(32*N)]), K00XOR(db[(E4)+(32*N)]), K01XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K07XOR(db[59*N]), K35XOR(db[60*N]), K36XOR(db[61*N]), K24XOR(db[62*N]), K44XOR(db[63*N]), K23XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K28XOR(db[E0]), K08XOR(db[E1]), K16XOR(db[E2]), K03XOR(db[E3]), K43XOR(db[E4]), K44XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K50XOR(db[27*N]), K21XOR(db[28*N]), K22XOR(db[29*N]), K10XOR(db[30*N]), K30XOR(db[31*N]), K09XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K14XOR(db[(E0)+(32*N)]), K51XOR(db[(E1)+(32*N)]), K02XOR(db[(E2)+(32*N)]), K42XOR(db[(E3)+(32*N)]), K29XOR(db[(E4)+(32*N)]), K30XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K36XOR(db[59*N]), K07XOR(db[60*N]), K08XOR(db[61*N]), K49XOR(db[62*N]), K16XOR(db[63*N]), K24XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K00XOR(db[E0]), K37XOR(db[E1]), K17XOR(db[E2]), K28XOR(db[E3]), K15XOR(db[E4]), K16XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K22XOR(db[27*N]), K50XOR(db[28*N]), K51XOR(db[29*N]), K35XOR(db[30*N]), K02XOR(db[31*N]), K10XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K43XOR(db[(E0)+(32*N)]), K23XOR(db[(E1)+(32*N)]), K03XOR(db[(E2)+(32*N)]), K14XOR(db[(E3)+(32*N)]), K01XOR(db[(E4)+(32*N)]), K02XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K08XOR(db[59*N]), K36XOR(db[60*N]), K37XOR(db[61*N]), K21XOR(db[62*N]), K17XOR(db[63*N]), K49XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K29XOR(db[E0]), K09XOR(db[E1]), K42XOR(db[E2]), K00XOR(db[E3]), K44XOR(db[E4]), K17XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K51XOR(db[27*N]), K22XOR(db[28*N]), K23XOR(db[29*N]), K07XOR(db[30*N]), K03XOR(db[31*N]), K35XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K22XOR(db[(E0)+(32*N)]), K02XOR(db[(E1)+(32*N)]), K35XOR(db[(E2)+(32*N)]), K50XOR(db[(E3)+(32*N)]), K37XOR(db[(E4)+(32*N)]), K10XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K44XOR(db[59*N]), K15XOR(db[60*N]), K16XOR(db[61*N]), K00XOR(db[62*N]), K49XOR(db[63*N]), K28XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			break;
		case 3: 
			s7(K51XOR(db[23*N]), K16XOR(db[24*N]), K29XOR(db[25*N]), K49XOR(db[26*N]), K07XOR(db[27*N]), K17XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K35XOR(db[E0]), K22XOR(db[E1]), K02XOR(db[E2]), K44XOR(db[E3]), K14XOR(db[E4]), K23XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K44XOR(db[55*N]), K09XOR(db[56*N]), K22XOR(db[57*N]), K42XOR(db[58*N]), K00XOR(db[59*N]), K10XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K28XOR(db[(E0)+(32*N)]), K15XOR(db[(E1)+(32*N)]), K24XOR(db[(E2)+(32*N)]), K37XOR(db[(E3)+(32*N)]), K07XOR(db[(E4)+(32*N)]), K16XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]);
			__syncthreads();
			s7(K30XOR(db[23*N]), K24XOR(db[24*N]), K08XOR(db[25*N]), K28XOR(db[26*N]), K43XOR(db[27*N]), K49XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
	        s6(K14XOR(db[E0]), K01XOR(db[E1]), K10XOR(db[E2]), K23XOR(db[E3]), K50XOR(db[E4]), K02XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]);
			__syncthreads();
			s7(K16XOR(db[55*N]), K10XOR(db[56*N]), K51XOR(db[57*N]), K14XOR(db[58*N]), K29XOR(db[59*N]), K35XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K00XOR(db[(E0)+(32*N)]), K44XOR(db[(E1)+(32*N)]), K49XOR(db[(E2)+(32*N)]), K09XOR(db[(E3)+(32*N)]), K36XOR(db[(E4)+(32*N)]), K17XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]);
			__syncthreads();
			s7(K02XOR(db[23*N]), K49XOR(db[24*N]), K37XOR(db[25*N]), K00XOR(db[26*N]), K15XOR(db[27*N]), K21XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
		    s6(K43XOR(db[E0]), K30XOR(db[E1]), K35XOR(db[E2]), K24XOR(db[E3]), K22XOR(db[E4]), K03XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]);
			__syncthreads();
			s7(K17XOR(db[55*N]), K35XOR(db[56*N]), K23XOR(db[57*N]), K43XOR(db[58*N]), K01XOR(db[59*N]), K07XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K29XOR(db[(E0)+(32*N)]), K16XOR(db[(E1)+(32*N)]), K21XOR(db[(E2)+(32*N)]), K10XOR(db[(E3)+(32*N)]), K08XOR(db[(E4)+(32*N)]), K42XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K03XOR(db[23*N]), K21XOR(db[24*N]), K09XOR(db[25*N]), K29XOR(db[26*N]), K44XOR(db[27*N]), K50XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K15XOR(db[E0]), K02XOR(db[E1]), K07XOR(db[E2]), K49XOR(db[E3]), K51XOR(db[E4]), K28XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K42XOR(db[55*N]), K07XOR(db[56*N]), K24XOR(db[57*N]), K15XOR(db[58*N]), K30XOR(db[59*N]), K36XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K01XOR(db[(E0)+(32*N)]), K17XOR(db[(E1)+(32*N)]), K50XOR(db[(E2)+(32*N)]), K35XOR(db[(E3)+(32*N)]), K37XOR(db[(E4)+(32*N)]), K14XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K35XOR(db[23*N]), K00XOR(db[24*N]), K17XOR(db[25*N]), K08XOR(db[26*N]), K23XOR(db[27*N]), K29XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K51XOR(db[E0]), K10XOR(db[E1]), K43XOR(db[E2]), K28XOR(db[E3]), K30XOR(db[E4]), K07XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K21XOR(db[55*N]), K43XOR(db[56*N]), K03XOR(db[57*N]), K51XOR(db[58*N]), K09XOR(db[59*N]), K15XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K37XOR(db[(E0)+(32*N)]), K49XOR(db[(E1)+(32*N)]), K29XOR(db[(E2)+(32*N)]), K14XOR(db[(E3)+(32*N)]), K16XOR(db[(E4)+(32*N)]), K50XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K07XOR(db[23*N]), K29XOR(db[24*N]), K42XOR(db[25*N]), K37XOR(db[26*N]), K24XOR(db[27*N]), K01XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K23XOR(db[E0]), K35XOR(db[E1]), K15XOR(db[E2]), K00XOR(db[E3]), K02XOR(db[E4]), K36XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K50XOR(db[55*N]), K15XOR(db[56*N]), K28XOR(db[57*N]), K23XOR(db[58*N]), K10XOR(db[59*N]), K44XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K09XOR(db[(E0)+(32*N)]), K21XOR(db[(E1)+(32*N)]), K01XOR(db[(E2)+(32*N)]), K43XOR(db[(E3)+(32*N)]), K17XOR(db[(E4)+(32*N)]), K22XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K36XOR(db[23*N]), K01XOR(db[24*N]), K14XOR(db[25*N]), K09XOR(db[26*N]), K49XOR(db[27*N]), K30XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K24XOR(db[E0]), K07XOR(db[E1]), K44XOR(db[E2]), K29XOR(db[E3]), K03XOR(db[E4]), K08XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K22XOR(db[55*N]), K44XOR(db[56*N]), K00XOR(db[57*N]), K24XOR(db[58*N]), K35XOR(db[59*N]), K16XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K10XOR(db[(E0)+(32*N)]), K50XOR(db[(E1)+(32*N)]), K30XOR(db[(E2)+(32*N)]), K15XOR(db[(E3)+(32*N)]), K42XOR(db[(E4)+(32*N)]), K51XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K08XOR(db[23*N]), K30XOR(db[24*N]), K43XOR(db[25*N]), K10XOR(db[26*N]), K21XOR(db[27*N]), K02XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K49XOR(db[E0]), K36XOR(db[E1]), K16XOR(db[E2]), K01XOR(db[E3]), K28XOR(db[E4]), K37XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K01XOR(db[55*N]), K23XOR(db[56*N]), K36XOR(db[57*N]), K03XOR(db[58*N]), K14XOR(db[59*N]), K24XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K42XOR(db[(E0)+(32*N)]), K29XOR(db[(E1)+(32*N)]), K09XOR(db[(E2)+(32*N)]), K51XOR(db[(E3)+(32*N)]), K21XOR(db[(E4)+(32*N)]), K30XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			break;
		}
		__syncthreads();

		if (i >= 12)
			break;

		// ROUND_B(-48);
		switch (threadIdx.y) {
		case 0:
			s1(K12XOR(db[(E0)+(32*N)]), K46XOR(db[(E1)+(32*N)]), K33XOR(db[(E2)+(32*N)]), K52XOR(db[(E3)+(32*N)]), K48XOR(db[(E4)+(32*N)]), K20XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K53XOR(db[43*N]), K06XOR(db[44*N]), K31XOR(db[45*N]), K25XOR(db[46*N]), K19XOR(db[47*N]), K41XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K05XOR(db[E0]), K39XOR(db[E1]), K26XOR(db[E2]), K45XOR(db[E3]), K41XOR(db[E4]), K13XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K46XOR(db[11*N]), K54XOR(db[12*N]), K55XOR(db[13*N]), K18XOR(db[14*N]), K12XOR(db[15*N]), K34XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K46XOR(db[(E0)+(32*N)]), K25XOR(db[(E1)+(32*N)]), K12XOR(db[(E2)+(32*N)]), K31XOR(db[(E3)+(32*N)]), K27XOR(db[(E4)+(32*N)]), K54XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K32XOR(db[43*N]), K40XOR(db[44*N]), K41XOR(db[45*N]), K04XOR(db[46*N]), K53XOR(db[47*N]), K20XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K32XOR(db[E0]), K11XOR(db[E1]), K53XOR(db[E2]), K48XOR(db[E3]), K13XOR(db[E4]), K40XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K18XOR(db[11*N]), K26XOR(db[12*N]), K27XOR(db[13*N]), K45XOR(db[14*N]), K39XOR(db[15*N]), K06XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K18XOR(db[(E0)+(32*N)]), K52XOR(db[(E1)+(32*N)]), K39XOR(db[(E2)+(32*N)]), K34XOR(db[(E3)+(32*N)]), K54XOR(db[(E4)+(32*N)]), K26XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K04XOR(db[43*N]), K12XOR(db[44*N]), K13XOR(db[45*N]), K31XOR(db[46*N]), K25XOR(db[47*N]), K47XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K04XOR(db[E0]), K38XOR(db[E1]), K25XOR(db[E2]), K20XOR(db[E3]), K40XOR(db[E4]), K12XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K45XOR(db[11*N]), K53XOR(db[12*N]), K54XOR(db[13*N]), K48XOR(db[14*N]), K11XOR(db[15*N]), K33XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K45XOR(db[(E0)+(32*N)]), K55XOR(db[(E1)+(32*N)]), K11XOR(db[(E2)+(32*N)]), K06XOR(db[(E3)+(32*N)]), K26XOR(db[(E4)+(32*N)]), K53XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K31XOR(db[43*N]), K39XOR(db[44*N]), K40XOR(db[45*N]), K34XOR(db[46*N]), K52XOR(db[47*N]), K19XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K31XOR(db[E0]), K41XOR(db[E1]), K52XOR(db[E2]), K47XOR(db[E3]), K12XOR(db[E4]), K39XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K48XOR(db[11*N]), K25XOR(db[12*N]), K26XOR(db[13*N]), K20XOR(db[14*N]), K38XOR(db[15*N]), K05XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K55XOR(db[(E0)+(32*N)]), K34XOR(db[(E1)+(32*N)]), K45XOR(db[(E2)+(32*N)]), K40XOR(db[(E3)+(32*N)]), K05XOR(db[(E4)+(32*N)]), K32XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K41XOR(db[43*N]), K18XOR(db[44*N]), K19XOR(db[45*N]), K13XOR(db[46*N]), K31XOR(db[47*N]), K53XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K41XOR(db[E0]), K20XOR(db[E1]), K31XOR(db[E2]), K26XOR(db[E3]), K46XOR(db[E4]), K18XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K27XOR(db[11*N]), K04XOR(db[12*N]), K05XOR(db[13*N]), K54XOR(db[14*N]), K48XOR(db[15*N]), K39XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K27XOR(db[(E0)+(32*N)]), K06XOR(db[(E1)+(32*N)]), K48XOR(db[(E2)+(32*N)]), K12XOR(db[(E3)+(32*N)]), K32XOR(db[(E4)+(32*N)]), K04XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K13XOR(db[43*N]), K45XOR(db[44*N]), K46XOR(db[45*N]), K40XOR(db[46*N]), K34XOR(db[47*N]), K25XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K13XOR(db[E0]), K47XOR(db[E1]), K34XOR(db[E2]), K53XOR(db[E3]), K18XOR(db[E4]), K45XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K54XOR(db[11*N]), K31XOR(db[12*N]), K32XOR(db[13*N]), K26XOR(db[14*N]), K20XOR(db[15*N]), K11XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K54XOR(db[(E0)+(32*N)]), K33XOR(db[(E1)+(32*N)]), K20XOR(db[(E2)+(32*N)]), K39XOR(db[(E3)+(32*N)]), K04XOR(db[(E4)+(32*N)]), K31XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K40XOR(db[43*N]), K48XOR(db[44*N]), K18XOR(db[45*N]), K12XOR(db[46*N]), K06XOR(db[47*N]), K52XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K40XOR(db[E0]), K19XOR(db[E1]), K06XOR(db[E2]), K25XOR(db[E3]), K45XOR(db[E4]), K48XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K26XOR(db[11*N]), K34XOR(db[12*N]), K04XOR(db[13*N]), K53XOR(db[14*N]), K47XOR(db[15*N]), K38XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			__syncthreads();
			s1(K26XOR(db[(E0)+(32*N)]), K05XOR(db[(E1)+(32*N)]), K47XOR(db[(E2)+(32*N)]), K11XOR(db[(E3)+(32*N)]), K31XOR(db[(E4)+(32*N)]), K34XOR(db[(E5)+(32*N)]), &db[ 8*N], &db[16*N], &db[22*N], &db[30*N]);
			s4(K12XOR(db[43*N]), K20XOR(db[44*N]), K45XOR(db[45*N]), K39XOR(db[46*N]), K33XOR(db[47*N]), K55XOR(db[48*N]), &db[25*N], &db[19*N], &db[ 9*N], &db[ 0*N]); 
			__syncthreads();
			s1(K19XOR(db[E0]), K53XOR(db[E1]), K40XOR(db[E2]), K04XOR(db[E3]), K55XOR(db[E4]), K27XOR(db[E5]), &db[40*N], &db[48*N], &db[54*N], &db[62*N]);
			s4(K05XOR(db[11*N]), K13XOR(db[12*N]), K38XOR(db[13*N]), K32XOR(db[14*N]), K26XOR(db[15*N]), K48XOR(db[16*N]), &db[57*N], &db[51*N], &db[41*N], &db[32*N]); 
			break;
		case 1:
			s3(K04XOR(db[39*N]), K32XOR(db[40*N]), K26XOR(db[41*N]), K27XOR(db[42*N]), K38XOR(db[43*N]), K54XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K34XOR(db[(E0)+(32*N)]), K55XOR(db[(E1)+(32*N)]), K05XOR(db[(E2)+(32*N)]), K13XOR(db[(E3)+(32*N)]), K18XOR(db[(E4)+(32*N)]), K40XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K52XOR(db[ 7*N]), K25XOR(db[ 8*N]), K19XOR(db[ 9*N]), K20XOR(db[10*N]), K31XOR(db[11*N]), K47XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K27XOR(db[E0]), K48XOR(db[E1]), K53XOR(db[E2]), K06XOR(db[E3]), K11XOR(db[E4]), K33XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K38XOR(db[39*N]), K11XOR(db[40*N]), K05XOR(db[41*N]), K06XOR(db[42*N]), K48XOR(db[43*N]), K33XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K13XOR(db[(E0)+(32*N)]), K34XOR(db[(E1)+(32*N)]), K39XOR(db[(E2)+(32*N)]), K47XOR(db[(E3)+(32*N)]), K52XOR(db[(E4)+(32*N)]), K19XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K55XOR(db[ 7*N]), K52XOR(db[ 8*N]), K46XOR(db[ 9*N]), K47XOR(db[10*N]), K34XOR(db[11*N]), K19XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K54XOR(db[E0]), K20XOR(db[E1]), K25XOR(db[E2]), K33XOR(db[E3]), K38XOR(db[E4]), K05XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K41XOR(db[39*N]), K38XOR(db[40*N]), K32XOR(db[41*N]), K33XOR(db[42*N]), K20XOR(db[43*N]), K05XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K40XOR(db[(E0)+(32*N)]), K06XOR(db[(E1)+(32*N)]), K11XOR(db[(E2)+(32*N)]), K19XOR(db[(E3)+(32*N)]), K55XOR(db[(E4)+(32*N)]), K46XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K27XOR(db[ 7*N]), K55XOR(db[ 8*N]), K18XOR(db[ 9*N]), K19XOR(db[10*N]), K06XOR(db[11*N]), K46XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K26XOR(db[E0]), K47XOR(db[E1]), K52XOR(db[E2]), K05XOR(db[E3]), K41XOR(db[E4]), K32XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K13XOR(db[39*N]), K41XOR(db[40*N]), K04XOR(db[41*N]), K05XOR(db[42*N]), K47XOR(db[43*N]), K32XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K12XOR(db[(E0)+(32*N)]), K33XOR(db[(E1)+(32*N)]), K38XOR(db[(E2)+(32*N)]), K46XOR(db[(E3)+(32*N)]), K27XOR(db[(E4)+(32*N)]), K18XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K54XOR(db[ 7*N]), K27XOR(db[ 8*N]), K45XOR(db[ 9*N]), K46XOR(db[10*N]), K33XOR(db[11*N]), K18XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K53XOR(db[E0]), K19XOR(db[E1]), K55XOR(db[E2]), K32XOR(db[E3]), K13XOR(db[E4]), K04XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K47XOR(db[39*N]), K20XOR(db[40*N]), K38XOR(db[41*N]), K39XOR(db[42*N]), K26XOR(db[43*N]), K11XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K46XOR(db[(E0)+(32*N)]), K12XOR(db[(E1)+(32*N)]), K48XOR(db[(E2)+(32*N)]), K25XOR(db[(E3)+(32*N)]), K06XOR(db[(E4)+(32*N)]), K52XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K33XOR(db[ 7*N]), K06XOR(db[ 8*N]), K55XOR(db[ 9*N]), K25XOR(db[10*N]), K12XOR(db[11*N]), K52XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K32XOR(db[E0]), K53XOR(db[E1]), K34XOR(db[E2]), K11XOR(db[E3]), K47XOR(db[E4]), K38XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K19XOR(db[39*N]), K47XOR(db[40*N]), K41XOR(db[41*N]), K11XOR(db[42*N]), K53XOR(db[43*N]), K38XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K18XOR(db[(E0)+(32*N)]), K39XOR(db[(E1)+(32*N)]), K20XOR(db[(E2)+(32*N)]), K52XOR(db[(E3)+(32*N)]), K33XOR(db[(E4)+(32*N)]), K55XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K05XOR(db[ 7*N]), K33XOR(db[ 8*N]), K27XOR(db[ 9*N]), K52XOR(db[10*N]), K39XOR(db[11*N]), K55XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K04XOR(db[E0]), K25XOR(db[E1]), K06XOR(db[E2]), K38XOR(db[E3]), K19XOR(db[E4]), K41XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K46XOR(db[39*N]), K19XOR(db[40*N]), K13XOR(db[41*N]), K38XOR(db[42*N]), K25XOR(db[43*N]), K41XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K45XOR(db[(E0)+(32*N)]), K11XOR(db[(E1)+(32*N)]), K47XOR(db[(E2)+(32*N)]), K55XOR(db[(E3)+(32*N)]), K05XOR(db[(E4)+(32*N)]), K27XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K32XOR(db[ 7*N]), K05XOR(db[ 8*N]), K54XOR(db[ 9*N]), K55XOR(db[10*N]), K11XOR(db[11*N]), K27XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K31XOR(db[E0]), K52XOR(db[E1]), K33XOR(db[E2]), K41XOR(db[E3]), K46XOR(db[E4]), K13XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			__syncthreads();
			s3(K18XOR(db[39*N]), K46XOR(db[40*N]), K40XOR(db[41*N]), K41XOR(db[42*N]), K52XOR(db[43*N]), K13XOR(db[44*N]), &db[23*N], &db[15*N], &db[29*N], &db[ 5*N]);
			s2(K48XOR(db[(E0)+(32*N)]), K38XOR(db[(E1)+(32*N)]), K19XOR(db[(E2)+(32*N)]), K27XOR(db[(E3)+(32*N)]), K32XOR(db[(E4)+(32*N)]), K54XOR(db[(E5)+(32*N)]), &db[12*N], &db[27*N], &db[ 1*N], &db[17*N]); 
			__syncthreads();
			s3(K11XOR(db[ 7*N]), K39XOR(db[ 8*N]), K33XOR(db[ 9*N]), K34XOR(db[10*N]), K45XOR(db[11*N]), K06XOR(db[12*N]), &db[55*N], &db[47*N], &db[61*N], &db[37*N]);
			s2(K41XOR(db[E0]), K31XOR(db[E1]), K12XOR(db[E2]), K20XOR(db[E3]), K25XOR(db[E4]), K47XOR(db[E5]), &db[44*N], &db[59*N], &db[33*N], &db[49*N]); 
			break;
		case 2:
			s5(K15XOR(db[(E0)+(32*N)]), K24XOR(db[(E1)+(32*N)]), K28XOR(db[(E2)+(32*N)]), K43XOR(db[(E3)+(32*N)]), K30XOR(db[(E4)+(32*N)]), K03XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K37XOR(db[59*N]), K08XOR(db[60*N]), K09XOR(db[61*N]), K50XOR(db[62*N]), K42XOR(db[63*N]), K21XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K08XOR(db[E0]), K17XOR(db[E1]), K21XOR(db[E2]), K36XOR(db[E3]), K23XOR(db[E4]), K49XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K30XOR(db[27*N]), K01XOR(db[28*N]), K02XOR(db[29*N]), K43XOR(db[30*N]), K35XOR(db[31*N]), K14XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K51XOR(db[(E0)+(32*N)]), K03XOR(db[(E1)+(32*N)]), K07XOR(db[(E2)+(32*N)]), K22XOR(db[(E3)+(32*N)]), K09XOR(db[(E4)+(32*N)]), K35XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K16XOR(db[59*N]), K44XOR(db[60*N]), K17XOR(db[61*N]), K29XOR(db[62*N]), K21XOR(db[63*N]), K00XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K37XOR(db[E0]), K42XOR(db[E1]), K50XOR(db[E2]), K08XOR(db[E3]), K24XOR(db[E4]), K21XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K02XOR(db[27*N]), K30XOR(db[28*N]), K03XOR(db[29*N]), K15XOR(db[30*N]), K07XOR(db[31*N]), K43XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K23XOR(db[(E0)+(32*N)]), K28XOR(db[(E1)+(32*N)]), K36XOR(db[(E2)+(32*N)]), K51XOR(db[(E3)+(32*N)]), K10XOR(db[(E4)+(32*N)]), K07XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K17XOR(db[59*N]), K16XOR(db[60*N]), K42XOR(db[61*N]), K01XOR(db[62*N]), K50XOR(db[63*N]), K29XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K09XOR(db[E0]), K14XOR(db[E1]), K22XOR(db[E2]), K37XOR(db[E3]), K49XOR(db[E4]), K50XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K03XOR(db[27*N]), K02XOR(db[28*N]), K28XOR(db[29*N]), K44XOR(db[30*N]), K36XOR(db[31*N]), K15XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K24XOR(db[(E0)+(32*N)]), K00XOR(db[(E1)+(32*N)]), K08XOR(db[(E2)+(32*N)]), K23XOR(db[(E3)+(32*N)]), K35XOR(db[(E4)+(32*N)]), K36XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K42XOR(db[59*N]), K17XOR(db[60*N]), K14XOR(db[61*N]), K30XOR(db[62*N]), K22XOR(db[63*N]), K01XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K10XOR(db[E0]), K43XOR(db[E1]), K51XOR(db[E2]), K09XOR(db[E3]), K21XOR(db[E4]), K22XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K28XOR(db[27*N]), K03XOR(db[28*N]), K00XOR(db[29*N]), K16XOR(db[30*N]), K08XOR(db[31*N]), K44XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K03XOR(db[(E0)+(32*N)]), K36XOR(db[(E1)+(32*N)]), K44XOR(db[(E2)+(32*N)]), K02XOR(db[(E3)+(32*N)]), K14XOR(db[(E4)+(32*N)]), K15XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K21XOR(db[59*N]), K49XOR(db[60*N]), K50XOR(db[61*N]), K09XOR(db[62*N]), K01XOR(db[63*N]), K37XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K42XOR(db[E0]), K22XOR(db[E1]), K30XOR(db[E2]), K17XOR(db[E3]), K00XOR(db[E4]), K01XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K07XOR(db[27*N]), K35XOR(db[28*N]), K36XOR(db[29*N]), K24XOR(db[30*N]), K44XOR(db[31*N]), K23XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K28XOR(db[(E0)+(32*N)]), K08XOR(db[(E1)+(32*N)]), K16XOR(db[(E2)+(32*N)]), K03XOR(db[(E3)+(32*N)]), K43XOR(db[(E4)+(32*N)]), K44XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K50XOR(db[59*N]), K21XOR(db[60*N]), K22XOR(db[61*N]), K10XOR(db[62*N]), K30XOR(db[63*N]), K09XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K14XOR(db[E0]), K51XOR(db[E1]), K02XOR(db[E2]), K42XOR(db[E3]), K29XOR(db[E4]), K30XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K36XOR(db[27*N]), K07XOR(db[28*N]), K08XOR(db[29*N]), K49XOR(db[30*N]), K16XOR(db[31*N]), K24XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K00XOR(db[(E0)+(32*N)]), K37XOR(db[(E1)+(32*N)]), K17XOR(db[(E2)+(32*N)]), K28XOR(db[(E3)+(32*N)]), K15XOR(db[(E4)+(32*N)]), K16XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K22XOR(db[59*N]), K50XOR(db[60*N]), K51XOR(db[61*N]), K35XOR(db[62*N]), K02XOR(db[63*N]), K10XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K43XOR(db[E0]), K23XOR(db[E1]), K03XOR(db[E2]), K14XOR(db[E3]), K01XOR(db[E4]), K02XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K08XOR(db[27*N]), K36XOR(db[28*N]), K37XOR(db[29*N]), K21XOR(db[30*N]), K17XOR(db[31*N]), K49XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			__syncthreads();
			s5(K29XOR(db[(E0)+(32*N)]), K09XOR(db[(E1)+(32*N)]), K42XOR(db[(E2)+(32*N)]), K00XOR(db[(E3)+(32*N)]), K44XOR(db[(E4)+(32*N)]), K17XOR(db[(E5)+(32*N)]), &db[ 7*N], &db[13*N], &db[24*N], &db[ 2*N]);
			s8(K51XOR(db[59*N]), K22XOR(db[60*N]), K23XOR(db[61*N]), K07XOR(db[62*N]), K03XOR(db[63*N]), K35XOR(db[32*N]), &db[ 4*N], &db[26*N], &db[14*N], &db[20*N]); 
			__syncthreads();
			s5(K22XOR(db[E0]), K02XOR(db[E1]), K35XOR(db[E2]), K50XOR(db[E3]), K37XOR(db[E4]), K10XOR(db[E5]), &db[39*N], &db[45*N], &db[56*N], &db[34*N]);
			s8(K44XOR(db[27*N]), K15XOR(db[28*N]), K16XOR(db[29*N]), K00XOR(db[30*N]), K49XOR(db[31*N]), K28XOR(db[ 0*N]), &db[36*N], &db[58*N], &db[46*N], &db[52*N]); 
			break;
		case 3: 
			s7(K51XOR(db[55*N]), K16XOR(db[56*N]), K29XOR(db[57*N]), K49XOR(db[58*N]), K07XOR(db[59*N]), K17XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K35XOR(db[(E0)+(32*N)]), K22XOR(db[(E1)+(32*N)]), K02XOR(db[(E2)+(32*N)]), K44XOR(db[(E3)+(32*N)]), K14XOR(db[(E4)+(32*N)]), K23XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K44XOR(db[23*N]), K09XOR(db[24*N]), K22XOR(db[25*N]), K42XOR(db[26*N]), K00XOR(db[27*N]), K10XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K28XOR(db[E0]), K15XOR(db[E1]), K24XOR(db[E2]), K37XOR(db[E3]), K07XOR(db[E4]), K16XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K30XOR(db[55*N]), K24XOR(db[56*N]), K08XOR(db[57*N]), K28XOR(db[58*N]), K43XOR(db[59*N]), K49XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K14XOR(db[(E0)+(32*N)]), K01XOR(db[(E1)+(32*N)]), K10XOR(db[(E2)+(32*N)]), K23XOR(db[(E3)+(32*N)]), K50XOR(db[(E4)+(32*N)]), K02XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K16XOR(db[23*N]), K10XOR(db[24*N]), K51XOR(db[25*N]), K14XOR(db[26*N]), K29XOR(db[27*N]), K35XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K00XOR(db[E0]), K44XOR(db[E1]), K49XOR(db[E2]), K09XOR(db[E3]), K36XOR(db[E4]), K17XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K02XOR(db[55*N]), K49XOR(db[56*N]), K37XOR(db[57*N]), K00XOR(db[58*N]), K15XOR(db[59*N]), K21XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K43XOR(db[(E0)+(32*N)]), K30XOR(db[(E1)+(32*N)]), K35XOR(db[(E2)+(32*N)]), K24XOR(db[(E3)+(32*N)]), K22XOR(db[(E4)+(32*N)]), K03XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K17XOR(db[23*N]), K35XOR(db[24*N]), K23XOR(db[25*N]), K43XOR(db[26*N]), K01XOR(db[27*N]), K07XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K29XOR(db[E0]), K16XOR(db[E1]), K21XOR(db[E2]), K10XOR(db[E3]), K08XOR(db[E4]), K42XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K03XOR(db[55*N]), K21XOR(db[56*N]), K09XOR(db[57*N]), K29XOR(db[58*N]), K44XOR(db[59*N]), K50XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K15XOR(db[(E0)+(32*N)]), K02XOR(db[(E1)+(32*N)]), K07XOR(db[(E2)+(32*N)]), K49XOR(db[(E3)+(32*N)]), K51XOR(db[(E4)+(32*N)]), K28XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K42XOR(db[23*N]), K07XOR(db[24*N]), K24XOR(db[25*N]), K15XOR(db[26*N]), K30XOR(db[27*N]), K36XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K01XOR(db[E0]), K17XOR(db[E1]), K50XOR(db[E2]), K35XOR(db[E3]), K37XOR(db[E4]), K14XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K35XOR(db[55*N]), K00XOR(db[56*N]), K17XOR(db[57*N]), K08XOR(db[58*N]), K23XOR(db[59*N]), K29XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K51XOR(db[(E0)+(32*N)]), K10XOR(db[(E1)+(32*N)]), K43XOR(db[(E2)+(32*N)]), K28XOR(db[(E3)+(32*N)]), K30XOR(db[(E4)+(32*N)]), K07XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K21XOR(db[23*N]), K43XOR(db[24*N]), K03XOR(db[25*N]), K51XOR(db[26*N]), K09XOR(db[27*N]), K15XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K37XOR(db[E0]), K49XOR(db[E1]), K29XOR(db[E2]), K14XOR(db[E3]), K16XOR(db[E4]), K50XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K07XOR(db[55*N]), K29XOR(db[56*N]), K42XOR(db[57*N]), K37XOR(db[58*N]), K24XOR(db[59*N]), K01XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K23XOR(db[(E0)+(32*N)]), K35XOR(db[(E1)+(32*N)]), K15XOR(db[(E2)+(32*N)]), K00XOR(db[(E3)+(32*N)]), K02XOR(db[(E4)+(32*N)]), K36XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K50XOR(db[23*N]), K15XOR(db[24*N]), K28XOR(db[25*N]), K23XOR(db[26*N]), K10XOR(db[27*N]), K44XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K09XOR(db[E0]), K21XOR(db[E1]), K01XOR(db[E2]), K43XOR(db[E3]), K17XOR(db[E4]), K22XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K36XOR(db[55*N]), K01XOR(db[56*N]), K14XOR(db[57*N]), K09XOR(db[58*N]), K49XOR(db[59*N]), K30XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K24XOR(db[(E0)+(32*N)]), K07XOR(db[(E1)+(32*N)]), K44XOR(db[(E2)+(32*N)]), K29XOR(db[(E3)+(32*N)]), K03XOR(db[(E4)+(32*N)]), K08XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K22XOR(db[23*N]), K44XOR(db[24*N]), K00XOR(db[25*N]), K24XOR(db[26*N]), K35XOR(db[27*N]), K16XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K10XOR(db[E0]), K50XOR(db[E1]), K30XOR(db[E2]), K15XOR(db[E3]), K42XOR(db[E4]), K51XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			__syncthreads();
			s7(K08XOR(db[55*N]), K30XOR(db[56*N]), K43XOR(db[57*N]), K10XOR(db[58*N]), K21XOR(db[59*N]), K02XOR(db[60*N]), &db[31*N], &db[11*N], &db[21*N], &db[ 6*N]);
			s6(K49XOR(db[(E0)+(32*N)]), K36XOR(db[(E1)+(32*N)]), K16XOR(db[(E2)+(32*N)]), K01XOR(db[(E3)+(32*N)]), K28XOR(db[(E4)+(32*N)]), K37XOR(db[(E5)+(32*N)]), &db[ 3*N], &db[28*N], &db[10*N], &db[18*N]); 
			__syncthreads();
			s7(K01XOR(db[23*N]), K23XOR(db[24*N]), K36XOR(db[25*N]), K03XOR(db[26*N]), K14XOR(db[27*N]), K24XOR(db[28*N]), &db[63*N], &db[43*N], &db[53*N], &db[38*N]);
			s6(K42XOR(db[E0]), K29XOR(db[E1]), K09XOR(db[E2]), K51XOR(db[E3]), K21XOR(db[E4]), K30XOR(db[E5]), &db[35*N], &db[60*N], &db[42*N], &db[50*N]); 
			break;
		}
		__syncthreads();
	}

#endif
}

#define GET_TRIPCODE_CHAR_INDEX(r, t, i0, i1, i2, i3, i4, i5, pos)  \
		(  ((((r)[threadIdx.x + (i0*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (5 + ((pos) * 6)))  \
	 	 | ((((r)[threadIdx.x + (i1*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (4 + ((pos) * 6)))  \
		 | ((((r)[threadIdx.x + (i2*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (3 + ((pos) * 6)))  \
		 | ((((r)[threadIdx.x + (i3*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (2 + ((pos) * 6)))  \
		 | ((((r)[threadIdx.x + (i4*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (1 + ((pos) * 6)))  \
		 | ((((r)[threadIdx.x + (i5*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << (0 + ((pos) * 6)))) \

#define GET_TRIPCODE_CHAR_INDEX_LAST(r, t, i0, i1, i2, i3)     \
		(  ((((r)[threadIdx.x + (i0*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << 5)  \
	 	 | ((((r)[threadIdx.x + (i1*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << 4)  \
		 | ((((r)[threadIdx.x + (i2*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << 3)  \
		 | ((((r)[threadIdx.x + (i3*N)] & (0x01 << (t))) ? (0x1) : (0x0)) << 2)) \

DES_FUNCTION_QUALIFIERS void
DES_GetTripcodeChunks(int32_t tripcodeIndex, uint32_t *tripcodeChunkArray, int32_t searchMode)
{
	// Perform the final permutation here.
	if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
	} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                        | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                        | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                        | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                        | GET_TRIPCODE_CHAR_INDEX_LAST(dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		tripcodeChunkArray[1] =   GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
								| GET_TRIPCODE_CHAR_INDEX_LAST(dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	} else {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		tripcodeChunkArray[1] = ((tripcodeChunkArray[0] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
		tripcodeChunkArray[2] = ((tripcodeChunkArray[1] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
		tripcodeChunkArray[3] = ((tripcodeChunkArray[2] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
		tripcodeChunkArray[4] = ((tripcodeChunkArray[3] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
		tripcodeChunkArray[5] = ((tripcodeChunkArray[4] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX_LAST(dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	}
}

DES_FUNCTION_QUALIFIERS
unsigned char *DES_GetTripcode(int32_t tripcodeIndex, unsigned char *tripcode)
{
	// Perform the final permutation as necessary.
  	tripcode[0] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0)];
  	tripcode[1] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0)];
  	tripcode[2] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0)];
  	tripcode[3] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0)];
  	tripcode[4] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0)];
  	tripcode[5] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0)];
  	tripcode[6] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0)];
  	tripcode[7] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0)];
  	tripcode[8] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0)];
	tripcode[9] = CUDA_DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX_LAST(dataBlocks, tripcodeIndex, 48, 16, 56, 24)];
 	tripcode[10] = '\0';

	return tripcode;
}

#define SET_KEY_CHAR(var, flag, table, value)             \
	if (!(flag)) {                                        \
		var = (table)[(value)];                           \
		isSecondByte = IS_FIRST_BYTE_SJIS(var);           \
	} else {                                              \
		var = cudaKeyCharTable_SecondByte[(value)];          \
		isSecondByte = FALSE;                             \
	}

#define CUDA_DES_DEFINE_SEARCH_FUNCTION(functionName) \
__global__ void functionName(\
	GPUOutput *outputArray,\
	unsigned char      *chunkBitmap,\
	uint32_t     *tripcodeChunkArray,\
	uint32_t      numTripcodeChunk,\
	unsigned char   *CUDA_key,\
	unsigned char   *CUDA_expansionFunction,\
	unsigned char   *CUDA_key0Array,\
	unsigned char   *CUDA_key7Array,\
	DES_Vector      *CUDA_keyFrom49To55Array,\
	int32_t         searchMode) {

#define CUDA_DES_BEFORE_SEARCHING \
	GPUOutput  *output = &outputArray[blockIdx.x * blockDim.x + threadIdx.x];\
	unsigned char        key[8];\
	BOOL         isSecondByte;\
	unsigned char        tripcodeIndex;\
	unsigned char        passCount = 0;\
	BOOL found = FALSE;\
	\
	if (threadIdx.y == 0) {\
		output->numMatchingTripcodes = 0;\
	}\
	key[1] = CUDA_key[1];\
	key[2] = CUDA_key[2];\
	\
	for (passCount = 0; passCount < CUDA_DES_MAX_PASS_COUNT; ++passCount) {\
		key[0] = CUDA_key0Array[passCount];\
		isSecondByte = IS_FIRST_BYTE_SJIS(CUDA_key[2]);\
		SET_KEY_CHAR(key[3], isSecondByte, cudaKeyCharTable_FirstByte, CUDA_key[3] + (((threadIdx.x >> 6) &  3) | ((blockIdx.x & (3 << 12)) >> (12 - 2))));\
		SET_KEY_CHAR(key[4], isSecondByte, cudaKeyCharTable_FirstByte, CUDA_key[4] + ( (blockIdx.x  >> 6) & 63));\
		SET_KEY_CHAR(key[5], isSecondByte, cudaKeyCharTable_FirstByte, CUDA_key[5] + (  blockIdx.x        & 63));\
		SET_KEY_CHAR(key[6], isSecondByte, cudaKeyCharTable_FirstByte, CUDA_key[6] + (  threadIdx.x       & 63));\
		uint32_t keyFrom00To27 = (((uint32_t)key[3] & 0x7f) << 21) | (((uint32_t)key[2] & 0x7f) << 14) | (((uint32_t)key[1] & 0x7f) <<  7) | (((uint32_t)key[0] & 0x7f) << 0); \
		uint32_t keyFrom28To48 = (((uint32_t)key[6] & 0x7f) << 14) | (((uint32_t)key[5] & 0x7f) <<  7) | (((uint32_t)key[4] & 0x7f) << 0); \
		__syncthreads();\
		DES_Crypt(keyFrom00To27, keyFrom28To48, CUDA_expansionFunction, CUDA_keyFrom49To55Array);\
		\
		__syncthreads();\
		if (threadIdx.y == 0) {\
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {

#define CUDA_DES_END_OF_SEAERCH_FUNCTION \
			}\
		}\
	}\
quit_loops:\
	if (found == TRUE) {\
		output->numMatchingTripcodes  = 1;\
		output->pair.key.c[0] = key[0];\
		output->pair.key.c[1] = key[1];\
		output->pair.key.c[2] = key[2];\
		output->pair.key.c[3] = key[3];\
		output->pair.key.c[4] = key[4];\
		output->pair.key.c[5] = key[5];\
		output->pair.key.c[6] = key[6];\
		output->pair.key.c[7] = CUDA_key7Array[tripcodeIndex];\
	}\
	if (threadIdx.y == 0)\
		output->numGeneratedTripcodes = CUDA_DES_BS_DEPTH * passCount;\
}

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_ForwardOrBackwardMatching_Simple)
	uint32_t tripcodeChunk;
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, &tripcodeChunk, searchMode);
	if (CUDA_smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)])
		continue;
	for (int32_t j = 0; j < numTripcodeChunk; ++j){
		if (tripcodeChunkArray[j] == tripcodeChunk) {
			found = TRUE;
			goto quit_loops;
		}
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_ForwardOrBackwardMatching)
	uint32_t tripcodeChunk;
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, &tripcodeChunk, searchMode);
	if (CUDA_smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)] || chunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
		continue;
	int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;
	while (tripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) {
		middle = (lower + upper) >> 1;
		if (tripcodeChunk > tripcodeChunkArray[middle]) {
			lower = middle + 1;
		} else {
			upper = middle - 1;
		}
	}
	if (tripcodeChunk == tripcodeChunkArray[middle]) {
		found = TRUE;
		goto quit_loops;
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_ForwardMatching_1Chunk)
	uint32_t tripcodeChunk0 = tripcodeChunkArray[0];
CUDA_DES_BEFORE_SEARCHING
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0) != ((tripcodeChunk0 >> (6 * 4)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0) != ((tripcodeChunk0 >> (6 * 3)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0) != ((tripcodeChunk0 >> (6 * 2)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0) != ((tripcodeChunk0 >> (6 * 1)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0) != ((tripcodeChunk0 >> (6 * 0)) & 0x3f))
		goto skip_final_permutation;
	found = TRUE;
	goto quit_loops;
skip_final_permutation:
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_BackwardMatching_1Chunk)
	uint32_t tripcodeChunk0 = tripcodeChunkArray[0];
CUDA_DES_BEFORE_SEARCHING
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0) != ((tripcodeChunk0 >> (6 * 4)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0) != ((tripcodeChunk0 >> (6 * 3)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0) != ((tripcodeChunk0 >> (6 * 2)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX(dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0) != ((tripcodeChunk0 >> (6 * 1)) & 0x3f))
		goto skip_final_permutation;
	if (GET_TRIPCODE_CHAR_INDEX_LAST(dataBlocks, tripcodeIndex, 48, 16, 56, 24) != ((tripcodeChunk0 >> (6 * 0)) & 0x3f))
		goto skip_final_permutation;
	found = TRUE;
	goto quit_loops;
skip_final_permutation:
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_Flexible_Simple)
	uint32_t generatedTripcodeChunkArray[6];
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, generatedTripcodeChunkArray, searchMode);
	for (int32_t pos = 0; pos < 6; ++pos) {
		if (CUDA_smallChunkBitmap[generatedTripcodeChunkArray[pos] >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)])
			continue;
		for (int32_t j = 0; j < numTripcodeChunk; ++j){
			if (tripcodeChunkArray[j] == generatedTripcodeChunkArray[pos]) {
				found = TRUE;
				goto quit_loops;
			}
		}
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_Flexible)
	uint32_t generatedTripcodeChunkArray[6];
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, generatedTripcodeChunkArray, searchMode);
	for (int32_t pos = 0; pos < 6; ++pos) {
		uint32_t generatedTripcodeChunk = generatedTripcodeChunkArray[pos];
		if (   CUDA_smallChunkBitmap[generatedTripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)] 
		    || chunkBitmap[generatedTripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
			continue;
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;
		while (generatedTripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) {
			middle = (lower + upper) >> 1;
			if (generatedTripcodeChunk > tripcodeChunkArray[middle]) {
				lower = middle + 1;
			} else {
				upper = middle - 1;
			}
		}
		if (generatedTripcodeChunk == tripcodeChunkArray[middle]) {
			found = TRUE;
			goto quit_loops;
		}
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_ForwardAndBackwardMatching_Simple)
	uint32_t generatedTripcodeChunkArray[6];
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, generatedTripcodeChunkArray, searchMode);
	//
	if (!CUDA_smallChunkBitmap[generatedTripcodeChunkArray[0] >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) {
		for (int32_t j = 0; j < numTripcodeChunk; ++j){
			if (tripcodeChunkArray[j] == generatedTripcodeChunkArray[0]) {
				found = TRUE;
				goto quit_loops;
			}
		}
	}
	//
	if (!CUDA_smallChunkBitmap[generatedTripcodeChunkArray[1] >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) {
		for (int32_t j = 0; j < numTripcodeChunk; ++j){
			if (tripcodeChunkArray[j] == generatedTripcodeChunkArray[1]) {
				found = TRUE;
				goto quit_loops;
			}
		}
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION

CUDA_DES_DEFINE_SEARCH_FUNCTION(CUDA_PerformSearching_DES_ForwardAndBackwardMatching)
	uint32_t generatedTripcodeChunkArray[6];
	uint32_t generatedTripcodeChunk;
CUDA_DES_BEFORE_SEARCHING
	DES_GetTripcodeChunks(tripcodeIndex, generatedTripcodeChunkArray, searchMode);
	//
	generatedTripcodeChunk = generatedTripcodeChunkArray[0];
	if (!CUDA_smallChunkBitmap[generatedTripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)] && !chunkBitmap[generatedTripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]) {
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;
		while (generatedTripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) {
			middle = (lower + upper) >> 1;
			if (generatedTripcodeChunk > tripcodeChunkArray[middle]) {
				lower = middle + 1;
			} else {
				upper = middle - 1;
			}
		}
		if (generatedTripcodeChunk == tripcodeChunkArray[middle]) {
			found = TRUE;
			goto quit_loops;
		}
	}
	//
	generatedTripcodeChunk = generatedTripcodeChunkArray[1];
	if (!CUDA_smallChunkBitmap[generatedTripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)] && !chunkBitmap[generatedTripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)]) {
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;
		while (generatedTripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) {
			middle = (lower + upper) >> 1;
			if (generatedTripcodeChunk > tripcodeChunkArray[middle]) {
				lower = middle + 1;
			} else {
				upper = middle - 1;
			}
		}
		if (generatedTripcodeChunk == tripcodeChunkArray[middle]) {
			found = TRUE;
			goto quit_loops;
		}
	}
CUDA_DES_END_OF_SEAERCH_FUNCTION



///////////////////////////////////////////////////////////////////////////////
// CUDA SEARCH THREAD FOR 10 CHARACTER TRIPCODES                             //
///////////////////////////////////////////////////////////////////////////////

#define SET_BIT_FOR_KEY7(var, k) if (key7 & (0x1 << (k))) (var) |= 0x1 << tripcodeIndex

void Thread_SearchForDESTripcodesOnCUDADevice(CUDADeviceSearchThreadInfo *info)
{
	cudaDeviceProp  CUDADeviceProperties;
	uint32_t    numBlocksPerSM;
	uint32_t    numBlocksPerGrid;
	GPUOutput      *outputArray = NULL;
	GPUOutput      *CUDA_outputArray = NULL;
	uint32_t   *CUDA_tripcodeChunkArray = NULL;
	unsigned char  *CUDA_chunkBitmap = NULL;
	uint32_t    sizeOutputArray;
	unsigned char   key[MAX_LEN_TRIPCODE + 1];
	unsigned char   expansionFunction[96];
	char            status[LEN_LINE_BUFFER_FOR_SCREEN] = "";
	double          timeElapsed = 0;
	double          numGeneratedTripcodes = 0;
	double          speed = 0;
	uint64_t           startingTime;
	uint64_t           endingTime;
	double          deltaTime;

	unsigned char   *CUDA_key; // [12];
	unsigned char   *CUDA_expansionFunction; // [96];
	unsigned char   *CUDA_key0Array; // [CUDA_DES_MAX_PASS_COUNT];
	unsigned char   *CUDA_key7Array; // [CUDA_DES_BS_DEPTH];
	DES_Vector      *CUDA_keyFrom49To55Array; // [7];

	key[lenTripcode] = '\0';
	
	CUDA_ERROR(cudaSetDevice(info->CUDADeviceIndex));
	CUDA_ERROR(cudaGetDeviceProperties(&CUDADeviceProperties, info->CUDADeviceIndex));
	if (CUDADeviceProperties.computeMode == cudaComputeModeProhibited) {
		sprintf(status, "[disabled]");
		UpdateCUDADeviceStatus(info, status);
		return;
	}
	int32_t numThreadsPerBlock = (CUDADeviceProperties.major == 3 && CUDADeviceProperties.minor == 7) ? 448 :
		                     (CUDADeviceProperties.major == 2                                   ) ? 768 :
		                     (CUDADeviceProperties.major == 3                                   ) ? 768 :
		                     (CUDADeviceProperties.major == 5                                   ) ? 512 :
		                                                                                            512;
	int32_t numBitsliceDESPerBlock = numThreadsPerBlock / NUM_THREADS_PER_BITSICE_DES;

	numBlocksPerSM = options.CUDANumBlocksPerSM;
	numBlocksPerGrid = numBlocksPerSM * CUDADeviceProperties.multiProcessorCount;
	sizeOutputArray = numBitsliceDESPerBlock * numBlocksPerGrid;
	outputArray = (GPUOutput *)malloc(sizeof(GPUOutput) * sizeOutputArray);
	ERROR0(outputArray == NULL, ERROR_NO_MEMORY, GetErrorMessage(ERROR_NO_MEMORY));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_outputArray,        sizeof(GPUOutput) * sizeOutputArray));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_chunkBitmap,        CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMalloc((void **)&CUDA_tripcodeChunkArray, sizeof(uint32_t) * numTripcodeChunk)); 
	CUDA_ERROR(cudaMalloc((void **)&CUDA_key,                sizeof(unsigned char) * 8)); 
	CUDA_ERROR(cudaMalloc((void **)&CUDA_expansionFunction,  sizeof(unsigned char) * 96)); 
	CUDA_ERROR(cudaMalloc((void **)&CUDA_key0Array,           sizeof(unsigned char) * CUDA_DES_MAX_PASS_COUNT)); 
	CUDA_ERROR(cudaMalloc((void **)&CUDA_key7Array,          sizeof(unsigned char) * CUDA_DES_BS_DEPTH)); 
	CUDA_ERROR(cudaMalloc((void **)&CUDA_keyFrom49To55Array, sizeof(DES_Vector)    * 7)); 

	info->mutex.lock();
	CUDA_ERROR(cudaMemcpy(CUDA_tripcodeChunkArray, tripcodeChunkArray, sizeof(uint32_t) * numTripcodeChunk, cudaMemcpyHostToDevice));
	CUDA_ERROR(cudaMemcpy(CUDA_chunkBitmap, chunkBitmap, CHUNK_BITMAP_SIZE, cudaMemcpyHostToDevice));
	CUDA_ERROR(cudaMemcpyToSymbol(CUDA_base64CharTable,      base64CharTable,      sizeof(base64CharTable)));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_OneByte, keyCharTable_OneByte, SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(CUDA_smallChunkBitmap, smallChunkBitmap, SMALL_CHUNK_BITMAP_SIZE));
	info->mutex.unlock();
	
	startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;

	while (!GetTerminationState()) {
		// Choose the first 3 characters of the key.
		SetCharactersInTripcodeKey(key, 3);
		unsigned char  salt[2];
		salt[0] = CONVERT_CHAR_FOR_SALT(key[1]);
		salt[1] = CONVERT_CHAR_FOR_SALT(key[2]);
		
		//
		unsigned char key0Array[CUDA_DES_MAX_PASS_COUNT];
		unsigned char randomByteForKey0 = RandomByte();
		int32_t j = 0;
		for (int32_t i = 3; i < lenTripcode; ++i)
			key[i] = 'A';
		for (int32_t i = 0; i < CUDA_DES_MAX_PASS_COUNT; ++i) {
			do {
				key[0] = keyCharTable_FirstByte[randomByteForKey0 + j++];
			} while(!IsValidKey(key));
			key0Array[i] = key[0];
		}

		// Generate random bytes for the key to ensure its randomness.
		for (int32_t i = 3; i < lenTripcode; ++i)
			key[i] = RandomByte();
		
		//
		unsigned char key7Array[CUDA_DES_BS_DEPTH];
		DES_Vector  keyFrom49To55Array[7] = {0, 0, 0, 0, 0, 0, 0};
		for (int32_t tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
			unsigned char key7 = key7Array[tripcodeIndex] = keyCharTable_SecondByteAndOneByte[key[7] + tripcodeIndex];
			SET_BIT_FOR_KEY7(keyFrom49To55Array[0], 0);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[1], 1);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[2], 2);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[3], 3);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[4], 4);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[5], 5);
			SET_BIT_FOR_KEY7(keyFrom49To55Array[6], 6);
		}

		// Create an expansion function based on the salt.
		salt[0] = CONVERT_CHAR_FOR_SALT(key[1]);
		salt[1] = CONVERT_CHAR_FOR_SALT(key[2]);
		DES_CreateExpansionFunction((char *)salt, expansionFunction);

		// Call an appropriate CUDA kernel.
		CUDA_ERROR(cudaMemcpy(CUDA_key,               key,               8, cudaMemcpyHostToDevice));
		CUDA_ERROR(cudaMemcpy(CUDA_expansionFunction, expansionFunction, sizeof(expansionFunction), cudaMemcpyHostToDevice));
		CUDA_ERROR(cudaMemcpy(CUDA_key0Array,         key0Array,         sizeof(key0Array), cudaMemcpyHostToDevice));
		CUDA_ERROR(cudaMemcpy(CUDA_key7Array,         key7Array,         sizeof(key7Array), cudaMemcpyHostToDevice));
		CUDA_ERROR(cudaMemcpy(CUDA_keyFrom49To55Array, keyFrom49To55Array, sizeof(keyFrom49To55Array), cudaMemcpyHostToDevice));
		dim3 dimBlock(numBitsliceDESPerBlock, NUM_THREADS_PER_BITSICE_DES);
		dim3 dimGrid(numBlocksPerGrid);
		if (searchMode == SEARCH_MODE_FLEXIBLE) {
			if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_PerformSearching_DES_Flexible_Simple<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			} else {
				CUDA_PerformSearching_DES_Flexible<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			}
		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
			if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_PerformSearching_DES_ForwardAndBackwardMatching_Simple<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			} else {
				CUDA_PerformSearching_DES_ForwardAndBackwardMatching<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			}
		} else {
			if (numTripcodeChunk == 1) {
				if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
					CUDA_PerformSearching_DES_ForwardMatching_1Chunk<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
						CUDA_outputArray,
						CUDA_chunkBitmap,
						CUDA_tripcodeChunkArray,
						numTripcodeChunk,
						CUDA_key,
						CUDA_expansionFunction,
						CUDA_key0Array,
						CUDA_key7Array,
						CUDA_keyFrom49To55Array,
						searchMode);
				} else {
					CUDA_PerformSearching_DES_BackwardMatching_1Chunk<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
						CUDA_outputArray,
						CUDA_chunkBitmap,
						CUDA_tripcodeChunkArray,
						numTripcodeChunk,
						CUDA_key,
						CUDA_expansionFunction,
						CUDA_key0Array,
						CUDA_key7Array,
						CUDA_keyFrom49To55Array,
						searchMode);
				}
			} else if (numTripcodeChunk <= CUDA_SIMPLE_SEARCH_THRESHOLD) {
				CUDA_PerformSearching_DES_ForwardOrBackwardMatching_Simple<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			} else {
				CUDA_PerformSearching_DES_ForwardOrBackwardMatching<<<dimGrid, dimBlock, CUDADeviceProperties.sharedMemPerBlock>>>(
					CUDA_outputArray,
					CUDA_chunkBitmap,
					CUDA_tripcodeChunkArray,
					numTripcodeChunk,
					CUDA_key,
					CUDA_expansionFunction,
					CUDA_key0Array,
					CUDA_key7Array,
					CUDA_keyFrom49To55Array,
					searchMode);
			}
		}
		CUDA_ERROR(cudaGetLastError());
		// CUDA_ERROR(cudaDeviceSynchronize()); // Check errors at kernel launch.

		// Process the output array.
		CUDA_ERROR(cudaMemcpy(outputArray, CUDA_outputArray, sizeof(GPUOutput) * sizeOutputArray, cudaMemcpyDeviceToHost));
		// We can save registers this way.
		for (uint32_t indexOutput = 0; indexOutput < sizeOutputArray; indexOutput++){
			GPUOutput *output = &outputArray[indexOutput];
			if (output->numMatchingTripcodes > 0)
				GenerateDESTripcode(output->pair.tripcode.c, output->pair.key.c);
		}
		numGeneratedTripcodes += ProcessGPUOutput(key, outputArray, sizeOutputArray, FALSE);
		
		//
		endingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		deltaTime = (endingTime - startingTime) * 0.001;
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);
		startingTime = TIME_SINCE_EPOCH_IN_MILLISECONDS;
		timeElapsed += deltaTime;
		speed = numGeneratedTripcodes / timeElapsed;
		//
		sprintf(status,
			    "%.1lfM TPS, %d blocks/SM",
				speed / 1000000,
				numBlocksPerSM);
		UpdateCUDADeviceStatus(info, status);
	}

	RELEASE_AND_SET_TO_NULL(CUDA_outputArray,        cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_tripcodeChunkArray, cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_chunkBitmap,        cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_key,                cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_expansionFunction,  cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_key0Array,          cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_key7Array,          cudaFree);
	RELEASE_AND_SET_TO_NULL(CUDA_keyFrom49To55Array, cudaFree);
	RELEASE_AND_SET_TO_NULL(outputArray,             free);
}
