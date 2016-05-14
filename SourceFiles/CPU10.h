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
// BITSLICE DES                                                              //
///////////////////////////////////////////////////////////////////////////////

#define NUM_ELEMENTS_IN_VECTOR (VECTOR_SIZE / 4)
#define BITSLICE_DES_DEPTH     (VECTOR_SIZE * 8)

// All bitslice DES parameters combined into one struct for more efficient
// cache usage and multi-threading.
#define DES_NUM_KEYS 56
#define NUM_DATA_BLOCKS 64
typedef struct {
	unsigned char expansionFunction[96];
	DES_Vector    expandedKeySchedule[0x300];
	DES_Vector    dataBlocks[NUM_DATA_BLOCKS];
	DES_Vector    temp[1 + 12];
	DES_Vector    keys[DES_NUM_KEYS];
	//
	void          (*crypt25)(void *);
	BOOL          useAVX;
	BOOL          useAVX2;
	unsigned char keyCharTable_FirstByte [SIZE_KEY_CHAR_TABLE];
	unsigned char keyCharTable_SecondByte[SIZE_KEY_CHAR_TABLE];
	unsigned char tripcodeChunkBitmap[5][0x40];
} DES_Context;

static unsigned char keySchedule[0x300] = {
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



///////////////////////////////////////////////////////////////////////////////
// TABLES                                                                    //
///////////////////////////////////////////////////////////////////////////////

static char DES_indexToCharTable[64] =
//	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
{
	/* 00 */ '.', '/',
	/* 02 */ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
	/* 12 */ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
	/* 28 */ 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	/* 38 */ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	/* 54 */ 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
};

static char DES_charToIndexTable[0x100] = {
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
	0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
	0x23, 0x24, 0x25, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
	0x3d, 0x3e, 0x3f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
};

/*
static unsigned char permutedChoice1Table[56] = {
	56, 48, 40, 32, 24, 16,  8,
	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,
	18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	 6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,
	20, 12,  4, 27, 19, 11,  3
};

static unsigned char leftShiftTable[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static unsigned char permutedChoice2Table[48] = {
	13, 16, 10, 23,  0,  4,
	 2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7,
	15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

static unsigned char finalPermutationTable[] = {
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25,
	32,  0, 40,  8, 48, 16, 56, 24,
};
*/



///////////////////////////////////////////////////////////////////////////////
// INITIALIZATION                                                            //
///////////////////////////////////////////////////////////////////////////////

#ifdef USE_YASM

static void DES_RewriteCrypt25(DES_Context *context)
{
	// Rewrite the assembly function.
#define SKIP 0x100
	int32_t rewriteTable[] = {
		0,    1,    2,    3,    4,    5,
		6,    7,    8,    9,    10,   11,
		SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
		SKIP, SKIP, SKIP, SKIP, SKIP,
		24,   25,   26,   27,   28,   29,
		30,   31,   32,   33,   34,   35,
		SKIP, SKIP, SKIP, SKIP, SKIP, 
		SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,

		48,   49,   50,   51,   52,   53,
		54,   55,   56,   57,   58,   59,
		SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,   
		SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
		72,   73,   74,   75,   76,   77,
		78,   79,   80,   81,   82,   83,
		-1
	};
	unsigned char *p = (unsigned char *)(context->crypt25);
	
	// Rewrite "movdqa/vmovdqa/movaps xmm*, [rbx + 0xffffffff]" based on context->ExpansionFunction[].
	for (int32_t i = 0; rewriteTable[i] >= 0; ++i) {
		if (context->useAVX) {
			// vmovdqa xmm*, [rbx + 0xffffffff]
			for (; 
					*(p + 0) != 0xc5
				 || *(p + 1) != 0xf9
				 || *(p + 2) != 0x6f
				 || (   *(p + 3) != 0x83
					 && *(p + 3) != 0x8b
					 && *(p + 3) != 0x93
					 && *(p + 3) != 0x9b
					 && *(p + 3) != 0xa3
					 && *(p + 3) != 0xab);
				 ++p)
				;
			p+= 4;
		} else if (IsCPUBasedOnNehalemMicroarchitecture()) {
			// movdqa xmm*, [rbx + 0xffffffff]
			for (; 
					*(p + 0) != 0x66
				 || *(p + 1) != 0x0f
				 || *(p + 2) != 0x6f
				 || (   *(p + 3) != 0x83
					 && *(p + 3) != 0x8b
					 && *(p + 3) != 0x93
					 && *(p + 3) != 0x9b
					 && *(p + 3) != 0xa3
					 && *(p + 3) != 0xab);
				 ++p)
				;
			p+= 4;
		} else {
			// movaps xmm*, [rbx + 0xffffffff]
			for (; 
					*(p + 0) != 0x0f
				 || *(p + 1) != 0x28
				 || (   *(p + 2) != 0x83
					 && *(p + 2) != 0x8b
					 && *(p + 2) != 0x93
					 && *(p + 2) != 0x9b
					 && *(p + 2) != 0xa3
					 && *(p + 2) != 0xab);
				 ++p)
				;
			p += 3;
		}
		// printf("offset = %d\n", (unsigned char *)p - (unsigned char *)(context->crypt25));
		if (rewriteTable[i] != SKIP)
			*(int32_t *)p = context->expansionFunction[rewriteTable[i]] * 8;
		p += 4;
	}
}

static void DES_RewriteCrypt25_x64_AVX2(DES_Context *context)
{
	// Rewrite the assembly function.
#define SKIP 0x100
	int32_t rewriteTable[] = {
		0,    1,    2,    3,    4,    5,
		6,    7,    8,    9,    10,   11,
		24,   25,   26,   27,   28,   29,
		30,   31,   32,   33,   34,   35,
		-1
	};
	unsigned char *p = (unsigned char *)(context->crypt25);
	unsigned char instructionBytes[3];

	// Rewrite "vpxor xmm*/ymm*, [rbx + 0xffffffff]" based on context->ExpansionFunction[].
	for (int32_t i = 0; rewriteTable[i] >= 0; ++i) {
		/*
			c5 f9 ef 83 ff ff ff ff 
			c5 f1 ef 8b ff ff ff ff 
			c5 e9 ef 93 ff ff ff ff 
			c5 e1 ef 9b ff ff ff ff 
			c5 d9 ef a3 ff ff ff ff 
			c5 d1 ef ab ff ff ff ff 

			c5 c9 ef b3 ff ff ff ff 
			c5 c1 ef bb ff ff ff ff 
			c5 39 ef 83 ff ff ff ff 
			c5 31 ef 8b ff ff ff ff 
			c5 29 ef 93 ff ff ff ff xmm10
			c5 21 ef 9b ff ff ff ff 
			c5 19 ef a3 ff ff ff ff 
			c5 11 ef ab ff ff ff ff 
			c5 09 ef b3 ff ff ff ff 
			c5 01 ef bb ff ff ff ff
		*/
		/*
			c5 fd ef 83 ff ff ff ff 
			c5 f5 ef 8b ff ff ff ff 
			c5 ed ef 93 ff ff ff ff 
			c5 e5 ef 9b ff ff ff ff 
			c5 dd ef a3 ff ff ff ff 
			c5 d5 ef ab ff ff ff ff 

			c5 cd ef b3 ff ff ff ff 
			c5 c5 ef bb ff ff ff ff 
			c5 3d ef 83 ff ff ff ff 
			c5 35 ef 8b ff ff ff ff 
			c5 2d ef 93 ff ff ff ff ymm10
			c5 25 ef 9b ff ff ff ff 
			c5 1d ef a3 ff ff ff ff 
			c5 15 ef ab ff ff ff ff 
			c5 0d ef b3 ff ff ff ff 
			c5 05 ef bb ff ff ff ff 
		*/
		for (; 
				   *(p + 0) != 0xc5
				|| *(p + 2) != 0xef
				|| !(   (*(p + 1) == 0xf9 && *(p + 3) == 0x83)
					 || (*(p + 1) == 0xf1 && *(p + 3) == 0x8b)
					 || (*(p + 1) == 0xe9 && *(p + 3) == 0x93)
					 || (*(p + 1) == 0xe1 && *(p + 3) == 0x9b)
					 || (*(p + 1) == 0xd9 && *(p + 3) == 0xa3)
					 || (*(p + 1) == 0xd1 && *(p + 3) == 0xab)
					 || (*(p + 1) == 0x29 && *(p + 3) == 0x93)
					 
					 || (*(p + 1) == 0xfd && *(p + 3) == 0x83)
					 || (*(p + 1) == 0xf5 && *(p + 3) == 0x8b)
					 || (*(p + 1) == 0xed && *(p + 3) == 0x93)
					 || (*(p + 1) == 0xe5 && *(p + 3) == 0x9b)
					 || (*(p + 1) == 0xdd && *(p + 3) == 0xa3)
					 || (*(p + 1) == 0xd5 && *(p + 3) == 0xab)
					 || (*(p + 1) == 0x2d && *(p + 3) == 0x93));
				++p)
			;
		p+= 4;

		if (rewriteTable[i] != SKIP)
			*(int32_t *)p = context->expansionFunction[rewriteTable[i]] * (VECTOR_SIZE / 2);
		p += 4;
	}
}

#endif

static void DES_SetSalt(DES_Context *context, int32_t salt)
{
	int32_t mask;
	int32_t src, dst;

	mask = 1;
	for (dst = 0; dst < 48; dst++) {
		if (dst == 24) mask = 1;

		if (salt & mask) {
			if (dst < 24) src = dst + 24; else src = dst - 24;
		} else src = dst;

		context->expansionFunction[dst     ] = expansionTable[src];
		context->expansionFunction[dst + 48] = expansionTable[src] + 32;

#ifdef USE_YASM
		// Multiply the values for the assembly version of DES_Crypt25().
		context->expansionFunction[dst     ] *= 2;
		context->expansionFunction[dst + 48] *= 2;
#endif

		mask <<= 1;
	}

#ifdef USE_YASM
	if (context->useAVX2) {
		DES_RewriteCrypt25_x64_AVX2(context);
	} else {
		DES_RewriteCrypt25(context);
	}
#endif

}



///////////////////////////////////////////////////////////////////////////////
// CRYPT                                                                     //
///////////////////////////////////////////////////////////////////////////////

#ifndef USE_YASM

static void DES_Crypt25_SSE2Intrinsics(DES_Context *context)
{
	int32_t iterations, roundsAndSwapped; 
	int32_t keyScheduleIndexBase = 0;

	roundsAndSwapped = 8;
	iterations = 25;

start:
	CPU_DES_SBoxes1_SSE2Intrinsics(context->expansionFunction, reinterpret_cast<__m128i *>(context->expandedKeySchedule), reinterpret_cast<__m128i *>(context->dataBlocks), keyScheduleIndexBase);

	if (roundsAndSwapped == 0x100)
		goto next;

swap:
	CPU_DES_SBoxes2_SSE2Intrinsics(context->expansionFunction, reinterpret_cast<__m128i *>(context->expandedKeySchedule), reinterpret_cast<__m128i *>(context->dataBlocks), keyScheduleIndexBase);

	keyScheduleIndexBase += 96;

	if (--roundsAndSwapped)
		goto start;
	keyScheduleIndexBase -= (0x300 + 48);
	roundsAndSwapped = 0x108;
	if (--iterations)
		goto swap;
	return;

next:
	keyScheduleIndexBase -= (0x300 - 48);
	roundsAndSwapped = 8;
	iterations--;
	goto start;
}

#endif

static void DES_Crypt(DES_Context *context)
{
	if (!context->useAVX2) {
		for (int32_t i = 0; i < 0x300; ++i)
			context->expandedKeySchedule[i] = context->keys[keySchedule[i]];
	}

	for (int32_t i = 0; i < NUM_DATA_BLOCKS; ++i) {
		for (int32_t j = 0; j < NUM_ELEMENTS_IN_VECTOR; ++j)
			context->dataBlocks[i].VECTOR_ELEMENTS[j] = 0;
	}

#ifdef USE_YASM
 	(*(context->crypt25))(context);
#else
	DES_Crypt25_SSE2Intrinsics(context);
#endif
}

#define GET_TRIPCODE_CHAR_INDEX(r, t, i0, i1, i2, i3, i4, i5, pos)  \
		(  ((( (r)[i0].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (5 + ((pos) * 6)))  \
	 	 | ((( (r)[i1].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (4 + ((pos) * 6)))  \
		 | ((( (r)[i2].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (3 + ((pos) * 6)))  \
		 | ((( (r)[i3].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (2 + ((pos) * 6)))  \
		 | ((( (r)[i4].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (1 + ((pos) * 6)))  \
		 | ((( (r)[i5].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (0 + ((pos) * 6)))) \

#define GET_TRIPCODE_CHAR_INDEX_LAST(r, t, i0, i1, i2, i3)     \
		(  ((((r)[i0].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 5)  \
	 	 | ((((r)[i1].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 4)  \
		 | ((((r)[i2].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 3)  \
		 | ((((r)[i3].VECTOR_ELEMENTS[(t) >> 5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 2)) \

#define GET_TRIPCODE_CHAR(r, t, i)   DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX((r), (t), (i))]

#define GET_TRIPCODE_CHAR_LAST(r, t) DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX_LAST((r), (t))]

static void DES_GetTripcodeChunks(DES_Context *context, int32_t tripcodeIndex, uint32_t *tripcodeChunkArray, int32_t searchMode)
{
	// Perform the final permutation here.
	if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
	} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                        | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                        | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                        | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                        | GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		tripcodeChunkArray[1] =   GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
								| GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	} else {
		tripcodeChunkArray[0] =   GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
								| GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		tripcodeChunkArray[1] = ((tripcodeChunkArray[0] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
		tripcodeChunkArray[2] = ((tripcodeChunkArray[1] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
		tripcodeChunkArray[3] = ((tripcodeChunkArray[2] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
		tripcodeChunkArray[4] = ((tripcodeChunkArray[3] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
		tripcodeChunkArray[5] = ((tripcodeChunkArray[4] << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24);
	}
}

static unsigned char *DES_GetTripcode(DES_Context *context, int32_t tripcodeIndex, unsigned char *tripcode)
{
	// Perform the final permutation as necessary.
  	tripcode[0] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0)];
  	tripcode[1] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0)];
  	tripcode[2] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0)];
  	tripcode[3] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0)];
  	tripcode[4] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0)];
  	tripcode[5] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0)];
  	tripcode[6] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0)];
  	tripcode[7] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0)];
  	tripcode[8] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0)];
	tripcode[9] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24)];
 	tripcode[10] = '\0';

	return tripcode;
}



///////////////////////////////////////////////////////////////////////////////
// SEARCH FOR TRIPCODES                                                      //
///////////////////////////////////////////////////////////////////////////////

#define QUICK_SEARCH_FOR_TRIPCODE_CHUNK(p)                                                                      \
	if (!found && !smallChunkBitmap[generatedTripcodeChunkArray[p] >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { \
		int32_t lower = 0, upper = numTripcodeChunk - 1, middle = lower;                                            \
		while (lower <= upper) {                                                                                \
			middle = (lower + upper) >> 1;                                                                      \
			if (generatedTripcodeChunkArray[p] > tripcodeChunkArray[middle]) {                                  \
				lower = middle + 1;                                                                             \
			} else if (generatedTripcodeChunkArray[p] < tripcodeChunkArray[middle]) {                           \
				upper = middle - 1;                                                                             \
			} else {                                                                                            \
				found = TRUE;                                                                                   \
				break;                                                                                          \
			}                                                                                                   \
		}                                                                                                       \
	}                                                                                                           \

#define CLEAR_KEYS(charIndex)                                          \
	for (int32_t i = 0; i < 7; ++i) {                                      \
		for (int32_t j = 0; j < NUM_ELEMENTS_IN_VECTOR; ++j)               \
			context->keys[(charIndex) * 7 + i].VECTOR_ELEMENTS[j] = 0; \
	}                                                                  \

#define SET_BIT_FOR_KEY(i, j, k)                                                          \
	if (key[j] & (0x1 << (k)))                                                            \
		context->keys[i].VECTOR_ELEMENTS[tripcodeIndex >> 5] |= (0x1 << (tripcodeIndex & 0x1f)); \

#define SET_ALL_BITS_FOR_KEY(i, j, k)                         \
	if (key[j] & (0x1 << (k))) {                              \
		for (int32_t l = 0; l < NUM_ELEMENTS_IN_VECTOR; ++l)      \
			context->keys[i].VECTOR_ELEMENTS[l] = 0xffffffff; \
	}                                                         \

static uint32_t SearchForTripcodes(DES_Context *context)
{
	unsigned char  tripcode[MAX_LEN_TRIPCODE + 1], key[MAX_LEN_TRIPCODE_KEY + 1];
	uint32_t   generatedTripcodeChunkArray[MAX_LEN_TRIPCODE - MIN_LEN_EXPANDED_PATTERN + 1];
	uint32_t   numGeneratedTripcodes = 0;
	uint32_t   indexKey4,     indexKey5;
	unsigned char *tableForKey4, *tableForKey5, *tableForKey6, *tableForKey7;
	uint32_t   tripcodeIndex;
	unsigned char  randomByteKey6, randomByteKey7, randomByteKey8, randomByteKey9;

	tripcode[lenTripcode] = '\0';
	key     [lenTripcode] = '\0';
	
	randomByteKey6 = RandomByte();
	randomByteKey7 = RandomByte();
	randomByteKey8 = RandomByte();
	randomByteKey9 = RandomByte();
		
	do {
		SetCharactersInTripcodeKey(key, 4);
		for (int32_t i = 4; i < lenTripcode; ++i)
			key[i] = 'A';
	} while (!IsValidKey(key));

	DES_SetSalt(context,
		            DES_charToIndexTable[CONVERT_CHAR_FOR_SALT(key[1])]
		        | (DES_charToIndexTable[CONVERT_CHAR_FOR_SALT(key[2])] << 6));	

	CLEAR_KEYS(0);
	SET_ALL_BITS_FOR_KEY( 0, 0, 0);
	SET_ALL_BITS_FOR_KEY( 1, 0, 1);
	SET_ALL_BITS_FOR_KEY( 2, 0, 2);
	SET_ALL_BITS_FOR_KEY( 3, 0, 3);
	SET_ALL_BITS_FOR_KEY( 4, 0, 4);
	SET_ALL_BITS_FOR_KEY( 5, 0, 5);
	SET_ALL_BITS_FOR_KEY( 6, 0, 6);

	CLEAR_KEYS(1);
	SET_ALL_BITS_FOR_KEY( 7, 1, 0);
	SET_ALL_BITS_FOR_KEY( 8, 1, 1);
	SET_ALL_BITS_FOR_KEY( 9, 1, 2);
	SET_ALL_BITS_FOR_KEY(10, 1, 3);
	SET_ALL_BITS_FOR_KEY(11, 1, 4);
	SET_ALL_BITS_FOR_KEY(12, 1, 5);
	SET_ALL_BITS_FOR_KEY(13, 1, 6);

	CLEAR_KEYS(2);
	SET_ALL_BITS_FOR_KEY(14, 2, 0);
	SET_ALL_BITS_FOR_KEY(15, 2, 1);
	SET_ALL_BITS_FOR_KEY(16, 2, 2);
	SET_ALL_BITS_FOR_KEY(17, 2, 3);
	SET_ALL_BITS_FOR_KEY(18, 2, 4);
	SET_ALL_BITS_FOR_KEY(19, 2, 5);
	SET_ALL_BITS_FOR_KEY(20, 2, 6);

	CLEAR_KEYS(3);
	SET_ALL_BITS_FOR_KEY(21, 3, 0);
	SET_ALL_BITS_FOR_KEY(22, 3, 1);
	SET_ALL_BITS_FOR_KEY(23, 3, 2);
	SET_ALL_BITS_FOR_KEY(24, 3, 3);
	SET_ALL_BITS_FOR_KEY(25, 3, 4);
	SET_ALL_BITS_FOR_KEY(26, 3, 5);
	SET_ALL_BITS_FOR_KEY(27, 3, 6);

	BOOL isSecondByte = FALSE;
	for (int32_t i = 0; i < 4; ++i) {
		if (!isSecondByte) {
			isSecondByte = IS_FIRST_BYTE_SJIS_FULL(key[i]);
		} else {
			isSecondByte = FALSE;
		}
	}
	BOOL isKey4SecondByte = isSecondByte;
	tableForKey4 = (isKey4SecondByte) ? context->keyCharTable_SecondByte : context->keyCharTable_FirstByte;	
				
	for (indexKey4 = 0; indexKey4 <= CPU_DES_MAX_INDEX_FOR_KEYS; ++indexKey4) {
		key[4] = tableForKey4[indexKey4];
		CLEAR_KEYS(4);
		SET_ALL_BITS_FOR_KEY(28, 4, 0);
		SET_ALL_BITS_FOR_KEY(29, 4, 1);
		SET_ALL_BITS_FOR_KEY(30, 4, 2);
		SET_ALL_BITS_FOR_KEY(31, 4, 3);
		SET_ALL_BITS_FOR_KEY(32, 4, 4);
		SET_ALL_BITS_FOR_KEY(33, 4, 5);
		SET_ALL_BITS_FOR_KEY(34, 4, 6);

		BOOL isKey5SecondByte = !isKey4SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[4]);
		tableForKey5 = (isKey5SecondByte) ? context->keyCharTable_SecondByte : context->keyCharTable_FirstByte;	

		for (indexKey5 = 0; indexKey5 <= CPU_DES_MAX_INDEX_FOR_KEYS; ++indexKey5) {
			BOOL isKey6SecondByte;
#if TRUE
			key[5] = tableForKey5[indexKey5];
			CLEAR_KEYS(5);
			SET_ALL_BITS_FOR_KEY(35, 5, 0);
			SET_ALL_BITS_FOR_KEY(36, 5, 1);
			SET_ALL_BITS_FOR_KEY(37, 5, 2);
			SET_ALL_BITS_FOR_KEY(38, 5, 3);
			SET_ALL_BITS_FOR_KEY(39, 5, 4);
			SET_ALL_BITS_FOR_KEY(40, 5, 5);
			SET_ALL_BITS_FOR_KEY(41, 5, 6);

			isKey6SecondByte = !isKey5SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[5]);
			tableForKey6 = (isKey6SecondByte) ? context->keyCharTable_SecondByte : context->keyCharTable_FirstByte;	

			CLEAR_KEYS(6);
			CLEAR_KEYS(7);

#if FALSE
			for (tripcodeIndex = 0; tripcodeIndex < BITSLICE_DES_DEPTH; ++tripcodeIndex) {
				key[6] = tableForKey6[(int32_t)randomByteKey6 + (tripcodeIndex >> 5)];
				tableForKey7 = (!isKey6SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[6])) ? (context->keyCharTable_SecondByte) : (context->keyCharTable_FirstByte);	
				SET_BIT_FOR_KEY(42, 6, 0);
				SET_BIT_FOR_KEY(43, 6, 1);
				SET_BIT_FOR_KEY(44, 6, 2);
				SET_BIT_FOR_KEY(45, 6, 3);
				SET_BIT_FOR_KEY(46, 6, 4);
				SET_BIT_FOR_KEY(47, 6, 5);
				SET_BIT_FOR_KEY(48, 6, 6);

				key[7] = tableForKey7[(int32_t)randomByteKey7 + (tripcodeIndex & 0x1f)];
				SET_BIT_FOR_KEY(49, 7, 0);
				SET_BIT_FOR_KEY(50, 7, 1);
				SET_BIT_FOR_KEY(51, 7, 2);
				SET_BIT_FOR_KEY(52, 7, 3);
				SET_BIT_FOR_KEY(53, 7, 4);
				SET_BIT_FOR_KEY(54, 7, 5);
				SET_BIT_FOR_KEY(55, 7, 6);
			}
#else
			for (int32_t tripcodeIndexUpper = 0; tripcodeIndexUpper < (BITSLICE_DES_DEPTH >> 5); ++tripcodeIndexUpper) {
				key[6] = tableForKey6[(int32_t)randomByteKey6 + tripcodeIndexUpper];
				tableForKey7 = (!isKey6SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[6])) ? (context->keyCharTable_SecondByte) : (context->keyCharTable_FirstByte);	
				if (key[6] & ((0x1 << 0))) context->keys[42].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 1))) context->keys[43].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 2))) context->keys[44].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 3))) context->keys[45].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 4))) context->keys[46].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 5))) context->keys[47].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;
				if (key[6] & ((0x1 << 6))) context->keys[48].VECTOR_ELEMENTS[tripcodeIndexUpper] = 0xffffffff;

				for (int32_t tripcodeIndexLower = 0; tripcodeIndexLower < 32; ++tripcodeIndexLower) {
					key[7] = tableForKey7[(int32_t)randomByteKey7 + tripcodeIndexLower];
					if (key[7] & ((0x1 << 0))) context->keys[49].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 1))) context->keys[50].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 2))) context->keys[51].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 3))) context->keys[52].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 4))) context->keys[53].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 5))) context->keys[54].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
					if (key[7] & ((0x1 << 6))) context->keys[55].VECTOR_ELEMENTS[tripcodeIndexUpper] |= (0x1 << tripcodeIndexLower);
				}
			}
#endif
#endif

		 	DES_Crypt(context);
			numGeneratedTripcodes += BITSLICE_DES_DEPTH;

			// continue;

			for (tripcodeIndex = 0; tripcodeIndex < BITSLICE_DES_DEPTH; ++tripcodeIndex) {
				// if (tripcodeIndex == 0) printf("tripcode[] = \"%s\"\n", DES_GetTripcode(context, tripcodeIndex, tripcode));

				// printf("[0x%08x, 0x%08x]\n", tripcodeChunkArray[0], generatedTripcodeChunkArray[0]);
				
				BOOL found = FALSE;
				if (searchMode == SEARCH_MODE_FORWARD_MATCHING && numTripcodeChunk == 1) {
					if (GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0) != ((tripcodeChunkArray[0] >> (6 * 4)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0) != ((tripcodeChunkArray[0] >> (6 * 3)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0) != ((tripcodeChunkArray[0] >> (6 * 2)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0) != ((tripcodeChunkArray[0] >> (6 * 1)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0) != ((tripcodeChunkArray[0] >> (6 * 0)) & 0x3f))
						goto skip_final_permutation;
					found = TRUE;
					
				} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING && numTripcodeChunk == 1) {
					if (GET_TRIPCODE_CHAR_INDEX     (context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0) != ((tripcodeChunkArray[0] >> (6 * 4)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX     (context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0) != ((tripcodeChunkArray[0] >> (6 * 3)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX     (context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0) != ((tripcodeChunkArray[0] >> (6 * 2)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX     (context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0) != ((tripcodeChunkArray[0] >> (6 * 1)) & 0x3f))
						goto skip_final_permutation;
					if (GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24) != ((tripcodeChunkArray[0] >> (6 * 0)) & 0x3f))
						goto skip_final_permutation;
					found = TRUE;

				} else if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
					generatedTripcodeChunkArray[0] = 0x00000000;

					uint32_t tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0);
					if (!context->tripcodeChunkBitmap[4][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 4);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0);
					if (!context->tripcodeChunkBitmap[3][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 3);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0);
					if (!context->tripcodeChunkBitmap[2][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 2);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0);
					if (!context->tripcodeChunkBitmap[1][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 1);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
					if (!context->tripcodeChunkBitmap[0][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 0);

					QUICK_SEARCH_FOR_TRIPCODE_CHUNK(0)

				} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
					generatedTripcodeChunkArray[0] = 0x00000000;

					uint32_t tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
					if (!context->tripcodeChunkBitmap[4][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 4);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
					if (!context->tripcodeChunkBitmap[3][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 3);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
					if (!context->tripcodeChunkBitmap[2][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 2);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
					if (!context->tripcodeChunkBitmap[1][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 1);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24);
					if (!context->tripcodeChunkBitmap[0][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 0);

					QUICK_SEARCH_FOR_TRIPCODE_CHUNK(0)

				} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
					generatedTripcodeChunkArray[0] = 0x00000000;

					uint32_t tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0);
					if (!context->tripcodeChunkBitmap[4][tripcodeCharIndex])
						goto second_part;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 4);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0);
					if (!context->tripcodeChunkBitmap[3][tripcodeCharIndex])
						goto second_part;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 3);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0);
					if (!context->tripcodeChunkBitmap[2][tripcodeCharIndex])
						goto second_part;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 2);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0);
					if (!context->tripcodeChunkBitmap[1][tripcodeCharIndex])
						goto second_part;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 1);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
					if (!context->tripcodeChunkBitmap[0][tripcodeCharIndex])
						goto second_part;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 0);

					QUICK_SEARCH_FOR_TRIPCODE_CHUNK(0)

second_part:
					generatedTripcodeChunkArray[0] = 0x00000000;

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
					if (!context->tripcodeChunkBitmap[4][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 4);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
					if (!context->tripcodeChunkBitmap[3][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 3);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
					if (!context->tripcodeChunkBitmap[2][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 2);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
					if (!context->tripcodeChunkBitmap[1][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 1);

					tripcodeCharIndex = GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24);
					if (!context->tripcodeChunkBitmap[0][tripcodeCharIndex])
						goto skip_final_permutation;
					generatedTripcodeChunkArray[0] |= tripcodeCharIndex << (6 * 0);

					QUICK_SEARCH_FOR_TRIPCODE_CHUNK(0)

				} else {
					DES_GetTripcodeChunks(context, tripcodeIndex, generatedTripcodeChunkArray, searchMode);
					int32_t maxPos = (searchMode == SEARCH_MODE_FLEXIBLE || searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING)
						                ? (lenTripcode - MIN_LEN_EXPANDED_PATTERN)
						                : (0);
					for (int32_t pos = 0; !found && pos <= maxPos; ++pos)
						QUICK_SEARCH_FOR_TRIPCODE_CHUNK(pos)
				}

skip_final_permutation:
				// Construct a valid 10 character key if necessary.
				if (found || searchForSpecialPatternsOnCPU) {
					key[6] = tableForKey6[(int32_t)randomByteKey6 + (tripcodeIndex >> 5)];
					BOOL isKey7SecondByte = !isKey6SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[6]);
					tableForKey7 = (isKey7SecondByte) ? (context->keyCharTable_SecondByte) : (context->keyCharTable_FirstByte);
					key[7] = tableForKey7[(int32_t)randomByteKey7 + (tripcodeIndex & 0x1f)];
					if (!isKey7SecondByte && IS_FIRST_BYTE_SJIS_FULL(key[7])) {
						key[8] = keyCharTable_SecondByte [randomByteKey8];
						key[9] = keyCharTable_OneByte[randomByteKey9];
					} else {
						key[8] = keyCharTable_FirstByte  [randomByteKey8];
						key[9] = (IsFirstByteSJIS(key[8]))
									? keyCharTable_SecondByte[randomByteKey9]
									: keyCharTable_OneByte[randomByteKey9];
					}
				}
				if (found) {
					ProcessPossibleMatch(DES_GetTripcode(context, tripcodeIndex, tripcode), key);
				} else if (!found && searchForSpecialPatternsOnCPU) {                                                                                                           \
					DES_GetTripcode(context, tripcodeIndex, tripcode);
					if (   options.searchForKaibunOnCPU
						&& tripcode[0] == tripcode[ 9]
						&& tripcode[1] == tripcode[ 8]
						&& tripcode[2] == tripcode[ 7]
						&& tripcode[3] == tripcode[ 6]
						&& tripcode[4] == tripcode[ 5] ) {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForKagamiOnCPU
								&& charTableForKagami[tripcode[0]] == tripcode[ 9]
 								&& charTableForKagami[tripcode[1]] == tripcode[ 8]
								&& charTableForKagami[tripcode[2]] == tripcode[ 7]
								&& charTableForKagami[tripcode[3]] == tripcode[ 6]
								&& charTableForKagami[tripcode[4]] == tripcode[ 5]
					) {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForYamabikoOnCPU
								&& tripcode[0] == tripcode[ 5]
								&& tripcode[1] == tripcode[ 6]
								&& tripcode[2] == tripcode[ 7]
								&& tripcode[3] == tripcode[ 8]
								&& tripcode[4] == tripcode[ 9] ) {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForSourenOnCPU
								&& tripcode[ 0] == tripcode[ 1]
								&& tripcode[ 2] == tripcode[ 3]
								&& tripcode[ 4] == tripcode[ 5]
								&& tripcode[ 6] == tripcode[ 7]
								&& tripcode[ 8] == tripcode[ 9] ) {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForHisekiOnCPU
								&& tripcode[ 0] == '.'
								&& tripcode[ 2] == '.'
								&& tripcode[ 4] == '.'
								&& tripcode[ 6] == '.'
								&& tripcode[ 8] == '.') {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForHisekiOnCPU
								&& tripcode[ 1] == '.'
								&& tripcode[ 3] == '.'
								&& tripcode[ 5] == '.'
								&& tripcode[ 7] == '.'
								&& tripcode[ 9] == '.') {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForHisekiOnCPU
								&& tripcode[ 0] == '/'
								&& tripcode[ 2] == '/'
								&& tripcode[ 4] == '/'
								&& tripcode[ 6] == '/'
								&& tripcode[ 8] == '/') {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForHisekiOnCPU
								&& tripcode[ 1] == '/'
								&& tripcode[ 3] == '/'
								&& tripcode[ 5] == '/'
								&& tripcode[ 7] == '/'
								&& tripcode[ 9] == '/') {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForKakuhiOnCPU
								&& tripcode[ 2] == tripcode[0]
								&& tripcode[ 4] == tripcode[0]
								&& tripcode[ 6] == tripcode[0]
								&& tripcode[ 8] == tripcode[0]) {
						ProcessMatch(tripcode, key);
					} else if (   options.searchForKakuhiOnCPU
								&& tripcode[ 3] == tripcode[1]
								&& tripcode[ 5] == tripcode[1]
								&& tripcode[ 7] == tripcode[1]
								&& tripcode[ 9] == tripcode[1]) {
						ProcessMatch(tripcode, key);
					}
				}
			}
		}
	}

	return numGeneratedTripcodes;
}

#ifdef USE_YASM
static char *GetCrypt25Address(DES_Context *context)
{
#ifdef _M_X64
	return (char *)(context->useAVX2                       ? DES_Crypt25_x64_AVX2         :
		            context->useAVX                        ? DES_Crypt25_x64_AVX          :
		            IsCPUBasedOnNehalemMicroarchitecture() ? DES_Crypt25_x64_SSE2_Nehalem :
					                                         DES_Crypt25_x64_SSE2          );
#else
	return (char *)(context->useAVX2                       ? DES_Crypt25_x86_AVX2         :
		            context->useAVX                        ? DES_Crypt25_x86_AVX          :
		            IsCPUBasedOnNehalemMicroarchitecture() ? DES_Crypt25_x86_SSE2_Nehalem :
				                                             DES_Crypt25_x86_SSE2          );
#endif
}
#endif

void CPU_DES_MAIN_LOOP()
{
	DES_Context context;

	for (int32_t i = 0; i < SIZE_KEY_CHAR_TABLE; ++i) {
		context.keyCharTable_FirstByte[i]  = keyCharTable_FirstByte[i];
		context.keyCharTable_SecondByte[i] = keyCharTable_SecondByte[i];
	}
	
#ifdef USE_YASM
	context.useAVX2 = options.isAVX2Enabled && IsAVX2Supported();
	context.useAVX  = !context.useAVX2 && options.isAVXEnabled && IsAVXSupported();
	// printf("context.useAVX = %d\n", context.useAVX);

	// Prepare a copy of DES_Crypt25_*() for thread-safe rewrites.
	char *base = GetCrypt25Address(&context);
	char *p;
	int32_t functionSize = 0;
	for (p = base; strcmp(p, "THIS_IS_THE_END_OF_THE_FUNCTION") != 0; ++p)
		++functionSize;
	context.crypt25 = (void (*)(void *))VirtualAllocEx(GetCurrentProcess(), 0, functionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	memcpy((void *)context.crypt25, base, functionSize);
#endif

	for (int32_t i = 0; i < 0x40; ++i)
		context.tripcodeChunkBitmap[0][i] = context.tripcodeChunkBitmap[1][i] = context.tripcodeChunkBitmap[2][i] = context.tripcodeChunkBitmap[3][i] = context.tripcodeChunkBitmap[4][i] = 0; 
	for (int32_t i = 0; i < numTripcodeChunk; ++i) {
		context.tripcodeChunkBitmap[4][(tripcodeChunkArray[i] >> (6 * 4)) & 0x3f] = 0x1;
		context.tripcodeChunkBitmap[3][(tripcodeChunkArray[i] >> (6 * 3)) & 0x3f] = 0x1;
		context.tripcodeChunkBitmap[2][(tripcodeChunkArray[i] >> (6 * 2)) & 0x3f] = 0x1;
		context.tripcodeChunkBitmap[1][(tripcodeChunkArray[i] >> (6 * 1)) & 0x3f] = 0x1;
		context.tripcodeChunkBitmap[0][(tripcodeChunkArray[i] >> (6 * 0)) & 0x3f] = 0x1;
	}

	while (!GetTerminationState()) {
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);

		uint32_t numGeneratedTripcodes = SearchForTripcodes(&context);
		AddToNumGeneratedTripcodesByCPU(numGeneratedTripcodes);
	}
}