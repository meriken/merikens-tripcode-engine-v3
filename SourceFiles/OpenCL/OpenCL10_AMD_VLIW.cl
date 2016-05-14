// Meriken's Tripcode Engine
// Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
//
// The initial versions of this software were based on:
// CUDA SHA-1 Tripper 0.2.1
// Copyright (c) 2009 Horo/.IBXjcg
// 
// A potion of the code that deals with DES decryption is adopted from:
// John the Ripper password cracker
// Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
//
// A potion of the code that deals with SHA-1 hash generation is adopted from:
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

typedef unsigned char BOOL;
#define TRUE  (1)
#define FALSE (0)

#define MAX_LEN_TRIPCODE            12
#define MAX_LEN_TRIPCODE_KEY        12
#define MAX_LEN_EXPANDED_PATTERN    MAX_LEN_TRIPCODE
#define SMALL_CHUNK_BITMAP_LEN_STRING 2
#define SMALL_CHUNK_BITMAP_SIZE       (64 * 64)
#define MEDIUM_CHUNK_BITMAP_LEN_STRING 3
#define CHUNK_BITMAP_LEN_STRING       4
#define DES_SIZE_EXPANSION_FUNCTION 96
#define OPENCL_DES_BS_DEPTH         32

#ifdef MAXIMIZE_KEY_SPACE

#define IS_FIRST_BYTE_SJIS(c)         \
	(   (0x81 <= (c) && (c) <= 0x84)  \
	 || (0x88 <= (c) && (c) <= 0x9f)  \
	 || (0xe0 <= (c) && (c) <= 0xea)) \

#else

#define IS_FIRST_BYTE_SJIS(c)         \
	(   (0x89 <= (c) && (c) <= 0x97)  \
	 || (0x99 <= (c) && (c) <= 0x9f)  \
 	 || (0xe0 <= (c) && (c) <= 0xe9)) \

#endif

#define IS_ONE_BYTE_KEY_CHAR(c)       \
	(   (0x21 <= (c) && (c) <= 0x24)  \
	 || (0x26 <= (c) && (c) <= 0x2a)  \
	 || (0x2d <= (c) && (c) <= 0x7e)  \
	 || (0xa1 <= (c) && (c) <= 0xdf)) \

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

typedef struct KeyInfo {
	unsigned char partialKeyAndRandomBytes[10];
	unsigned char expansioinFunction[DES_SIZE_EXPANSION_FUNCTION];
} KeyInfo;

typedef struct PartialKeyFrom3To6 {
	unsigned char partialKeyFrom3To6[4];
} PartialKeyFrom3To6;

__constant const char base64CharTable[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '/',
};

__constant const char indexToCharTable[64] =
//	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
{
	/* 00 */ '.', '/',
	/* 02 */ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
	/* 12 */ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
	/* 28 */ 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	/* 38 */ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	/* 54 */ 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
};

typedef unsigned int vtype;

#define vnot(dst, a)     (dst) =  (~(a))
#define vand(dst, a, b)  (dst) =  ((a) & (b))
#define vor(dst, a, b)   (dst) =  ((a) | (b))
#define vxor(dst, a, b)  (dst) =  ((a) ^ (b))
#define vandn(dst, a, b) (dst) =  (~(b) & (a))
#define vsel(x, y, z, w) (x) = bitselect((y), (z), (w))

#define DES_NUM_BITS_IN_KEY 56

#define DES_DATA_BLOCKS_SPACE __private
#define DES_KEYS_SPACE        __local



///////////////////////////////////////////////////////////////////////////////
// DES                                                                       //
///////////////////////////////////////////////////////////////////////////////

#define s1(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var2, var1, var4);\
	vxor(var7, var1, var2);\
	vor(var8, var0, var3);\
	vxor(var9, var7, var8);\
	vsel(var10, var4, var6, var9);\
	vxor(var11, var3, var10);\
	vxor(var12, var0, var11);\
	vsel(var0, var12, var8, var6);\
	vsel(var13, var7, var9, var4);\
	vxor(var14, var0, var13);\
	vsel(var0, var8, var12, var14);\
	vsel(var8, var11, var12, var4);\
	vsel(var15, var0, var14, var8);\
	vxor(var16, var6, var15);\
	vsel(var15, var9, var11, var0);\
	vsel(var0, var6, var9, var12);\
	vsel(var11, var4, var0, var16);\
	vxor(var4, var15, var11);\
	vsel(var15, var12, var0, var2);\
	vsel(var0, var3, var6, var16);\
	vsel(var6, var4, var15, var0);\
	vnot(var0, var6);\
	vsel(var6, var0, var4, var5);\
	vxor(out1, out1, var6);\
	vsel(var4, var0, var2, var11);\
	vsel(var0, var15, var1, var9);\
	vsel(var1, var4, var3, var0);\
	vxor(var3, var16, var1);\
	vsel(var4, var3, var12, var5);\
	vxor(out2, out2, var4);\
	vsel(var4, var8, var13, var1);\
	vsel(var6, var0, var12, var10);\
	vxor(var0, var4, var6);\
	vsel(var4, var0, var16, var5);\
	vxor(out4, out4, var4);\
	vxor(var0, var12, var3);\
	vsel(var3, var2, var0, var1);\
	vsel(var0, var3, var7, var6);\
	vsel(var1, var0, var14, var5);\
	vxor(out3, out3, var1);\

#define s2(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var0, var2, var5);\
	vsel(var7, var5, var6, var4);\
	vsel(var8, var2, var3, var7);\
	vxor(var9, var0, var8);\
	vxor(var8, var4, var5);\
	vxor(var10, var9, var8);\
	vsel(var11, var3, var9, var5);\
	vnot(var12, var11);\
	vxor(var13, var6, var12);\
	vxor(var6, var8, var13);\
	vsel(var14, var6, var10, var1);\
	vxor(out2, out2, var14);\
	vxor(var6, var3, var7);\
	vsel(var14, var9, var5, var8);\
	vsel(var15, var13, var6, var14);\
	vsel(var16, var13, var6, var4);\
	vxor(var17, var2, var6);\
	vsel(var6, var16, var17, var0);\
	vsel(var16, var9, var10, var13);\
	vsel(var9, var3, var6, var4);\
	vxor(var3, var16, var9);\
	vxor(var17, var12, var3);\
	vsel(var3, var17, var6, var1);\
	vxor(out1, out1, var3);\
	vsel(var3, var6, var17, var8);\
	vsel(var8, var10, var13, var0);\
	vsel(var0, var3, var8, var14);\
	vsel(var3, var16, var17, var6);\
	vsel(var6, var8, var2, var7);\
	vsel(var2, var3, var6, var4);\
	vsel(var3, var15, var2, var1);\
	vxor(out4, out4, var3);\
	vsel(var2, var8, var9, var5);\
	vsel(var3, var11, var0, var2);\
	vxor(var2, var6, var3);\
	vsel(var3, var0, var2, var1);\
	vxor(out3, out3, var3);\

#define s3(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var3, var2, var4);\
	vxor(var7, var5, var6);\
	vxor(var6, var1, var7);\
	vsel(var8, var2, var5, var6);\
	vsel(var9, var4, var2, var7);\
	vsel(var10, var4, var7, var1);\
	vsel(var11, var9, var3, var10);\
	vxor(var12, var8, var11);\
	vsel(var8, var6, var10, var3);\
	vsel(var13, var8, var12, var2);\
	vnot(var2, var13);\
	vsel(var14, var12, var2, var0);\
	vxor(out2, out2, var14);\
	vxor(var14, var9, var12);\
	vsel(var12, var1, var7, var11);\
	vsel(var11, var13, var1, var4);\
	vsel(var13, var14, var12, var11);\
	vxor(var14, var9, var2);\
	vsel(var2, var14, var8, var6);\
	vxor(var8, var12, var2);\
	vxor(var15, var11, var8);\
	vsel(var16, var3, var5, var7);\
	vsel(var7, var14, var16, var10);\
	vsel(var10, var8, var5, var14);\
	vsel(var14, var7, var11, var10);\
	vsel(var7, var14, var15, var0);\
	vxor(out1, out1, var7);\
	vsel(var7, var2, var8, var4);\
	vsel(var4, var16, var9, var3);\
	vsel(var3, var7, var14, var4);\
	vsel(var7, var6, var3, var0);\
	vxor(out4, out4, var7);\
	vsel(var3, var2, var1, var12);\
	vsel(var1, var3, var4, var5);\
	vxor(var2, var11, var1);\
	vsel(var1, var2, var13, var0);\
	vxor(out3, out3, var1);\

#define s4(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var4, var2, var0);\
	vsel(var7, var6, var0, var3);\
	vxor(var8, var2, var7);\
	vsel(var9, var0, var8, var1);\
	vsel(var8, var2, var4, var0);\
	vxor(var10, var3, var8);\
	vsel(var11, var10, var2, var4);\
	vxor(var2, var9, var11);\
	vnot(var4, var2);\
	vsel(var9, var3, var1, var7);\
	vxor(var7, var0, var6);\
	vsel(var0, var4, var9, var7);\
	vxor(var6, var8, var0);\
	vnot(var0, var6);\
	vsel(var12, var7, var0, var3);\
	vsel(var13, var11, var10, var8);\
	vsel(var8, var4, var13, var1);\
	vxor(var11, var12, var8);\
	vsel(var8, var11, var2, var5);\
	vxor(out3, out3, var8);\
	vsel(var2, var4, var11, var5);\
	vxor(out4, out4, var2);\
	vsel(var2, var1, var3, var10);\
	vsel(var1, var9, var2, var7);\
	vxor(var2, var0, var1);\
	vxor(var1, var11, var2);\
	vsel(var2, var0, var1, var5);\
	vxor(out1, out1, var2);\
	vsel(var0, var1, var6, var5);\
	vxor(out2, out2, var0);\

#define s5(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var0, var2, var4);\
	vnot(var7, var6);\
	vsel(var8, var7, var0, var2);\
	vxor(var9, var1, var8);\
	vxor(var10, var4, var5);\
	vxor(var11, var9, var10);\
	vsel(var12, var2, var7, var1);\
	vsel(var2, var1, var11, var9);\
	vsel(var13, var5, var6, var2);\
	vsel(var14, var13, var4, var0);\
	vxor(var15, var12, var14);\
	vsel(var16, var10, var15, var9);\
	vsel(var17, var5, var0, var16);\
	vsel(var18, var2, var5, var17);\
	vxor(var2, var15, var18);\
	vsel(var19, var2, var15, var3);\
	vxor(out3, out3, var19);\
	vsel(var15, var7, var13, var16);\
	vsel(var7, var18, var6, var0);\
	vxor(var0, var15, var7);\
	vsel(var6, var0, var11, var3);\
	vxor(out2, out2, var6);\
	vsel(var6, var0, var7, var5);\
	vsel(var13, var6, var14, var1);\
	vsel(var14, var12, var1, var11);\
	vsel(var1, var13, var14, var0);\
	vsel(var16, var4, var0, var11);\
	vsel(var0, var9, var2, var15);\
	vsel(var2, var16, var0, var13);\
	vsel(var0, var18, var13, var14);\
	vsel(var4, var7, var10, var16);\
	vxor(var7, var0, var4);\
	vsel(var0, var1, var7, var3);\
	vxor(out4, out4, var0);\
	vsel(var0, var12, var8, var5);\
	vsel(var1, var9, var11, var17);\
	vsel(var4, var0, var1, var6);\
	vsel(var0, var4, var2, var3);\
	vxor(out1, out1, var0);\

#define s6(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var0, var3, var4);\
	vxor(var7, var1, var6);\
	vsel(var8, var7, var3, var2);\
	vxor(var9, var0, var8);\
	vxor(var10, var4, var9);\
	vnot(var11, var10);\
	vsel(var12, var9, var10, var3);\
	vsel(var13, var2, var3, var12);\
	vxor(var14, var7, var13);\
	vxor(var7, var10, var14);\
	vsel(var15, var3, var9, var12);\
	vxor(var12, var2, var15);\
	vsel(var15, var3, var2, var10);\
	vsel(var2, var12, var15, var14);\
	vsel(var3, var11, var15, var14);\
	vsel(var14, var4, var12, var2);\
	vsel(var16, var3, var10, var14);\
	vsel(var14, var11, var16, var5);\
	vxor(out1, out1, var14);\
	vsel(var11, var9, var16, var1);\
	vsel(var1, var0, var3, var11);\
	vxor(var0, var7, var1);\
	vsel(var9, var7, var0, var5);\
	vxor(out4, out4, var9);\
	vsel(var7, var12, var8, var10);\
	vsel(var9, var7, var15, var13);\
	vxor(var10, var0, var9);\
	vxor(var9, var6, var10);\
	vsel(var6, var4, var16, var3);\
	vsel(var3, var9, var10, var6);\
	vnot(var4, var3);\
	vsel(var3, var4, var9, var5);\
	vxor(out2, out2, var3);\
	vsel(var3, var6, var0, var10);\
	vsel(var0, var1, var7, var8);\
	vxor(var1, var3, var0);\
	vsel(var0, var2, var1, var5);\
	vxor(out3, out3, var0);\

#define s7(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var1, var5, var2);\
	vxor(var7, var3, var6);\
	vsel(var6, var2, var4, var1);\
	vsel(var8, var5, var1, var3);\
	vsel(var9, var6, var8, var4);\
	vxor(var6, var7, var9);\
	vxor(var10, var4, var5);\
	vxor(var11, var1, var2);\
	vsel(var12, var2, var9, var3);\
	vsel(var9, var11, var12, var7);\
	vxor(var13, var10, var9);\
	vsel(var14, var13, var6, var0);\
	vxor(out1, out1, var14);\
	vxor(var14, var1, var13);\
	vsel(var15, var14, var4, var11);\
	vsel(var16, var13, var15, var5);\
	vsel(var15, var7, var14, var5);\
	vsel(var5, var15, var11, var10);\
	vxor(var10, var8, var5);\
	vsel(var5, var7, var10, var1);\
	vnot(var1, var4);\
	vsel(var4, var1, var14, var12);\
	vxor(var1, var5, var4);\
	vsel(var7, var1, var16, var0);\
	vxor(out2, out2, var7);\
	vxor(var7, var11, var1);\
	vsel(var1, var16, var7, var5);\
	vsel(var5, var1, var6, var4);\
	vsel(var1, var5, var10, var0);\
	vxor(out3, out3, var1);\
	vsel(var1, var14, var13, var9);\
	vxor(var4, var14, var7);\
	vsel(var5, var1, var4, var3);\
	vsel(var1, var16, var6, var13);\
	vsel(var3, var5, var2, var1);\
	vnot(var1, var3);\
	vsel(var2, var5, var1, var0);\
	vxor(out4, out4, var2);\

#define s8(arg1, arg2, arg3, arg4, arg5, arg6, out1, out2, out3, out4)\
	var0 = arg1;\
	var1 = arg2;\
	var2 = arg3;\
	var3 = arg4;\
	var4 = arg5;\
	var5 = arg6;\
	vsel(var6, var4, var0, var2);\
	vxor(var7, var3, var6);\
	vsel(var6, var2, var3, var4);\
	vsel(var8, var1, var4, var0);\
	vsel(var9, var7, var6, var8);\
	vxor(var6, var1, var9);\
	vsel(var8, var7, var3, var2);\
	vsel(var3, var4, var8, var1);\
	vsel(var10, var0, var6, var3);\
	vsel(var11, var2, var4, var1);\
	vxor(var2, var10, var11);\
	vsel(var12, var6, var4, var7);\
	vsel(var7, var12, var0, var8);\
	vxor(var8, var2, var7);\
	vsel(var12, var8, var2, var5);\
	vxor(out3, out3, var12);\
	vsel(var12, var11, var8, var4);\
	vxor(var4, var3, var12);\
	vxor(var3, var6, var4);\
	vnot(var8, var3);\
	vsel(var13, var9, var1, var12);\
	vsel(var12, var8, var13, var7);\
	vxor(var14, var4, var12);\
	vsel(var4, var14, var6, var5);\
	vxor(out2, out2, var4);\
	vsel(var4, var10, var11, var13);\
	vsel(var6, var9, var4, var2);\
	vxor(var4, var8, var6);\
	vsel(var6, var8, var4, var5);\
	vxor(out4, out4, var6);\
	vsel(var4, var9, var1, var2);\
	vor(var1, var0, var7);\
	vxor(var0, var4, var1);\
	vxor(var1, var12, var0);\
	vsel(var0, var1, var3, var5);\
	vxor(out1, out1, var0);\

#define K00XORV(val) ((keyFrom00To27 & (0x1U <<  0)) ? (~(val)) : (val))
#define K01XORV(val) ((keyFrom00To27 & (0x1U <<  1)) ? (~(val)) : (val))
#define K02XORV(val) ((keyFrom00To27 & (0x1U <<  2)) ? (~(val)) : (val))
#define K03XORV(val) ((keyFrom00To27 & (0x1U <<  3)) ? (~(val)) : (val))
#define K04XORV(val) ((keyFrom00To27 & (0x1U <<  4)) ? (~(val)) : (val))
#define K05XORV(val) ((keyFrom00To27 & (0x1U <<  5)) ? (~(val)) : (val))
#define K06XORV(val) ((keyFrom00To27 & (0x1U <<  6)) ? (~(val)) : (val))

/*
#define K07XORV(val) ((keyFrom00To27 & (0x1U <<  7)) ? (~(val)) : (val))
#define K08XORV(val) ((keyFrom00To27 & (0x1U <<  8)) ? (~(val)) : (val))
#define K09XORV(val) ((keyFrom00To27 & (0x1U <<  9)) ? (~(val)) : (val))
#define K10XORV(val) ((keyFrom00To27 & (0x1U << 10)) ? (~(val)) : (val))
#define K11XORV(val) ((keyFrom00To27 & (0x1U << 11)) ? (~(val)) : (val))
#define K12XORV(val) ((keyFrom00To27 & (0x1U << 12)) ? (~(val)) : (val))
#define K13XORV(val) ((keyFrom00To27 & (0x1U << 13)) ? (~(val)) : (val))

#define K14XORV(val) ((keyFrom00To27 & (0x1U << 14)) ? (~(val)) : (val))
#define K15XORV(val) ((keyFrom00To27 & (0x1U << 15)) ? (~(val)) : (val))
#define K16XORV(val) ((keyFrom00To27 & (0x1U << 16)) ? (~(val)) : (val))
#define K17XORV(val) ((keyFrom00To27 & (0x1U << 17)) ? (~(val)) : (val))
#define K18XORV(val) ((keyFrom00To27 & (0x1U << 18)) ? (~(val)) : (val))
#define K19XORV(val) ((keyFrom00To27 & (0x1U << 19)) ? (~(val)) : (val))
#define K20XORV(val) ((keyFrom00To27 & (0x1U << 20)) ? (~(val)) : (val))
*/

#define K21XORV(val) ((keyFrom00To27 & (0x1U << 21)) ? (~(val)) : (val))
#define K22XORV(val) ((keyFrom00To27 & (0x1U << 22)) ? (~(val)) : (val))
#define K23XORV(val) ((keyFrom00To27 & (0x1U << 23)) ? (~(val)) : (val))
#define K24XORV(val) ((keyFrom00To27 & (0x1U << 24)) ? (~(val)) : (val))
#define K25XORV(val) ((keyFrom00To27 & (0x1U << 25)) ? (~(val)) : (val))
#define K26XORV(val) ((keyFrom00To27 & (0x1U << 26)) ? (~(val)) : (val))
#define K27XORV(val) ((keyFrom00To27 & (0x1U << 27)) ? (~(val)) : (val))

#define K28XORV(val) ((keyFrom28To48 & (0x1U << (28 - 28))) ? (~(val)) : (val))
#define K29XORV(val) ((keyFrom28To48 & (0x1U << (29 - 28))) ? (~(val)) : (val))
#define K30XORV(val) ((keyFrom28To48 & (0x1U << (30 - 28))) ? (~(val)) : (val))
#define K31XORV(val) ((keyFrom28To48 & (0x1U << (31 - 28))) ? (~(val)) : (val))
#define K32XORV(val) ((keyFrom28To48 & (0x1U << (32 - 28))) ? (~(val)) : (val))
#define K33XORV(val) ((keyFrom28To48 & (0x1U << (33 - 28))) ? (~(val)) : (val))
#define K34XORV(val) ((keyFrom28To48 & (0x1U << (34 - 28))) ? (~(val)) : (val))

#define K35XORV(val) ((keyFrom28To48 & (0x1U << (35 - 28))) ? (~(val)) : (val))
#define K36XORV(val) ((keyFrom28To48 & (0x1U << (36 - 28))) ? (~(val)) : (val))
#define K37XORV(val) ((keyFrom28To48 & (0x1U << (37 - 28))) ? (~(val)) : (val))
#define K38XORV(val) ((keyFrom28To48 & (0x1U << (38 - 28))) ? (~(val)) : (val))
#define K39XORV(val) ((keyFrom28To48 & (0x1U << (39 - 28))) ? (~(val)) : (val))
#define K40XORV(val) ((keyFrom28To48 & (0x1U << (40 - 28))) ? (~(val)) : (val))
#define K41XORV(val) ((keyFrom28To48 & (0x1U << (41 - 28))) ? (~(val)) : (val))

#define K42XORV(val) ((keyFrom28To48 & (0x1U << (42 - 28))) ? (~(val)) : (val))
#define K43XORV(val) ((keyFrom28To48 & (0x1U << (43 - 28))) ? (~(val)) : (val))
#define K44XORV(val) ((keyFrom28To48 & (0x1U << (44 - 28))) ? (~(val)) : (val))
#define K45XORV(val) ((keyFrom28To48 & (0x1U << (45 - 28))) ? (~(val)) : (val))
#define K46XORV(val) ((keyFrom28To48 & (0x1U << (46 - 28))) ? (~(val)) : (val))
#define K47XORV(val) ((keyFrom28To48 & (0x1U << (47 - 28))) ? (~(val)) : (val))
#define K48XORV(val) ((keyFrom28To48 & (0x1U << (48 - 28))) ? (~(val)) : (val))

#define SWAP(a, b) var0 = (a); (a) = (b); (b) = var0;
#define DATASWAP \
	SWAP(db[ 0], db[32]); SWAP(db[ 1], db[33]);	SWAP(db[ 2], db[34]); SWAP(db[ 3], db[35]);	SWAP(db[ 4], db[36]); SWAP(db[ 5], db[37]);	SWAP(db[ 6], db[38]); SWAP(db[ 7], db[39]);	SWAP(db[ 8], db[40]); SWAP(db[ 9], db[41]); \
	SWAP(db[10], db[42]); SWAP(db[11], db[43]);	SWAP(db[12], db[44]); SWAP(db[13], db[45]);	SWAP(db[14], db[46]); SWAP(db[15], db[47]);	SWAP(db[16], db[48]); SWAP(db[17], db[49]);	SWAP(db[18], db[50]); SWAP(db[19], db[51]); \
	SWAP(db[20], db[52]); SWAP(db[21], db[53]);	SWAP(db[22], db[54]); SWAP(db[23], db[55]);	SWAP(db[24], db[56]); SWAP(db[25], db[57]);	SWAP(db[26], db[58]); SWAP(db[27], db[59]);	SWAP(db[28], db[60]); SWAP(db[29], db[61]); \
	SWAP(db[30], db[62]); SWAP(db[31], db[63]);

void DES_Crypt(DES_DATA_BLOCKS_SPACE vtype *db, const unsigned int keyFrom00To27, const unsigned int keyFrom28To48)
{
	vtype var0; 
	vtype var1; 
	vtype var2; 
	vtype var3; 
	vtype var4; 
	vtype var5; 
	vtype var6; 
	vtype var7; 
	vtype var8; 
	vtype var9; 
	vtype var10; 
	vtype var11; 
	vtype var12; 
	vtype var13; 
	vtype var14; 
	vtype var15; 
	vtype var16; 
	vtype var17; 
	vtype var18; 
	vtype var19;
	
	db[ 0] = 0, db[ 1] = 0, db[ 2] = 0, db[ 3] = 0, db[ 4] = 0, db[ 5] = 0, db[ 6] = 0, db[ 7] = 0, db[ 8] = 0, db[ 9] = 0;
	db[10] = 0, db[11] = 0, db[12] = 0, db[13] = 0, db[14] = 0, db[15] = 0, db[16] = 0, db[17] = 0, db[18] = 0, db[19] = 0;
	db[20] = 0, db[21] = 0, db[22] = 0, db[23] = 0, db[24] = 0, db[25] = 0, db[26] = 0, db[27] = 0, db[28] = 0, db[29] = 0;
	db[30] = 0, db[31] = 0, db[32] = 0, db[33] = 0, db[34] = 0, db[35] = 0, db[36] = 0, db[37] = 0, db[38] = 0, db[39] = 0;
	db[40] = 0, db[41] = 0, db[42] = 0, db[43] = 0, db[44] = 0, db[45] = 0, db[46] = 0, db[47] = 0, db[48] = 0, db[49] = 0;
	db[50] = 0, db[51] = 0, db[52] = 0, db[53] = 0, db[54] = 0, db[55] = 0, db[56] = 0, db[57] = 0, db[58] = 0, db[59] = 0;
	db[60] = 0, db[61] = 0, db[62] = 0, db[63] = 0; 

#pragma unroll 1
	for (int i = 0; i < 25; ++i) {
		DATASWAP;
		
		// ROUND_A(0);
		s1(K12XORV(db[EF00]), K46XORV(db[EF01]), K33XORV(db[EF02]), K52XORV(db[EF03]), K48XORV(db[EF04]), K20XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K34XORV(db[EF06]), K55XORV(db[EF07]), K05XORV(db[EF08]), K13XORV(db[EF09]), K18XORV(db[EF10]), K40XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K04XORV(db[   7]), K32XORV(db[   8]), K26XORV(db[   9]), K27XORV(db[  10]), K38XORV(db[  11]), K54XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K53XORV(db[  11]), K06XORV(db[  12]), K31XORV(db[  13]), K25XORV(db[  14]), K19XORV(db[  15]), K41XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K15XORV(db[EF24]), K24XORV(db[EF25]), K28XORV(db[EF26]), K43XORV(db[EF27]), K30XORV(db[EF28]), K03XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K35XORV(db[EF30]), K22XORV(db[EF31]), K02XORV(db[EF32]), K44XORV(db[EF33]), K14XORV(db[EF34]), K23XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K51XORV(db[  23]), K16XORV(db[  24]), K29XORV(db[  25]), K49XORV(db[  26]), K07XORV(db[  27]), K17XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K37XORV(db[  27]), K08XORV(db[  28]), K09XORV(db[  29]), K50XORV(db[  30]), K42XORV(db[  31]), K21XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(0);
		s1(K05XORV(db[EF48]), K39XORV(db[EF49]), K26XORV(db[EF50]), K45XORV(db[EF51]), K41XORV(db[EF52]), K13XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K27XORV(db[EF54]), K48XORV(db[EF55]), K53XORV(db[EF56]), K06XORV(db[EF57]), K11XORV(db[EF58]), K33XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K52XORV(db[  39]), K25XORV(db[  40]), K19XORV(db[  41]), K20XORV(db[  42]), K31XORV(db[  43]), K47XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K46XORV(db[  43]), K54XORV(db[  44]), K55XORV(db[  45]), K18XORV(db[  46]), K12XORV(db[  47]), K34XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K08XORV(db[EF72]), K17XORV(db[EF73]), K21XORV(db[EF74]), K36XORV(db[EF75]), K23XORV(db[EF76]), K49XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K28XORV(db[EF78]), K15XORV(db[EF79]), K24XORV(db[EF80]), K37XORV(db[EF81]), K07XORV(db[EF82]), K16XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K44XORV(db[  55]), K09XORV(db[  56]), K22XORV(db[  57]), K42XORV(db[  58]), K00XORV(db[  59]), K10XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K30XORV(db[  59]), K01XORV(db[  60]), K02XORV(db[  61]), K43XORV(db[  62]), K35XORV(db[  63]), K14XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(96);
		s1(K46XORV(db[EF00]), K25XORV(db[EF01]), K12XORV(db[EF02]), K31XORV(db[EF03]), K27XORV(db[EF04]), K54XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K13XORV(db[EF06]), K34XORV(db[EF07]), K39XORV(db[EF08]), K47XORV(db[EF09]), K52XORV(db[EF10]), K19XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K38XORV(db[   7]), K11XORV(db[   8]), K05XORV(db[   9]), K06XORV(db[  10]), K48XORV(db[  11]), K33XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K32XORV(db[  11]), K40XORV(db[  12]), K41XORV(db[  13]), K04XORV(db[  14]), K53XORV(db[  15]), K20XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K51XORV(db[EF24]), K03XORV(db[EF25]), K07XORV(db[EF26]), K22XORV(db[EF27]), K09XORV(db[EF28]), K35XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K14XORV(db[EF30]), K01XORV(db[EF31]), K10XORV(db[EF32]), K23XORV(db[EF33]), K50XORV(db[EF34]), K02XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K30XORV(db[  23]), K24XORV(db[  24]), K08XORV(db[  25]), K28XORV(db[  26]), K43XORV(db[  27]), K49XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K16XORV(db[  27]), K44XORV(db[  28]), K17XORV(db[  29]), K29XORV(db[  30]), K21XORV(db[  31]), K00XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(96);
		s1(K32XORV(db[EF48]), K11XORV(db[EF49]), K53XORV(db[EF50]), K48XORV(db[EF51]), K13XORV(db[EF52]), K40XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K54XORV(db[EF54]), K20XORV(db[EF55]), K25XORV(db[EF56]), K33XORV(db[EF57]), K38XORV(db[EF58]), K05XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K55XORV(db[  39]), K52XORV(db[  40]), K46XORV(db[  41]), K47XORV(db[  42]), K34XORV(db[  43]), K19XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K18XORV(db[  43]), K26XORV(db[  44]), K27XORV(db[  45]), K45XORV(db[  46]), K39XORV(db[  47]), K06XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K37XORV(db[EF72]), K42XORV(db[EF73]), K50XORV(db[EF74]), K08XORV(db[EF75]), K24XORV(db[EF76]), K21XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K00XORV(db[EF78]), K44XORV(db[EF79]), K49XORV(db[EF80]), K09XORV(db[EF81]), K36XORV(db[EF82]), K17XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K16XORV(db[  55]), K10XORV(db[  56]), K51XORV(db[  57]), K14XORV(db[  58]), K29XORV(db[  59]), K35XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K02XORV(db[  59]), K30XORV(db[  60]), K03XORV(db[  61]), K15XORV(db[  62]), K07XORV(db[  63]), K43XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(192);
		s1(K18XORV(db[EF00]), K52XORV(db[EF01]), K39XORV(db[EF02]), K34XORV(db[EF03]), K54XORV(db[EF04]), K26XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K40XORV(db[EF06]), K06XORV(db[EF07]), K11XORV(db[EF08]), K19XORV(db[EF09]), K55XORV(db[EF10]), K46XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K41XORV(db[   7]), K38XORV(db[   8]), K32XORV(db[   9]), K33XORV(db[  10]), K20XORV(db[  11]), K05XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K04XORV(db[  11]), K12XORV(db[  12]), K13XORV(db[  13]), K31XORV(db[  14]), K25XORV(db[  15]), K47XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K23XORV(db[EF24]), K28XORV(db[EF25]), K36XORV(db[EF26]), K51XORV(db[EF27]), K10XORV(db[EF28]), K07XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K43XORV(db[EF30]), K30XORV(db[EF31]), K35XORV(db[EF32]), K24XORV(db[EF33]), K22XORV(db[EF34]), K03XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K02XORV(db[  23]), K49XORV(db[  24]), K37XORV(db[  25]), K00XORV(db[  26]), K15XORV(db[  27]), K21XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K17XORV(db[  27]), K16XORV(db[  28]), K42XORV(db[  29]), K01XORV(db[  30]), K50XORV(db[  31]), K29XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(192);
		s1(K04XORV(db[EF48]), K38XORV(db[EF49]), K25XORV(db[EF50]), K20XORV(db[EF51]), K40XORV(db[EF52]), K12XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K26XORV(db[EF54]), K47XORV(db[EF55]), K52XORV(db[EF56]), K05XORV(db[EF57]), K41XORV(db[EF58]), K32XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K27XORV(db[  39]), K55XORV(db[  40]), K18XORV(db[  41]), K19XORV(db[  42]), K06XORV(db[  43]), K46XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K45XORV(db[  43]), K53XORV(db[  44]), K54XORV(db[  45]), K48XORV(db[  46]), K11XORV(db[  47]), K33XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K09XORV(db[EF72]), K14XORV(db[EF73]), K22XORV(db[EF74]), K37XORV(db[EF75]), K49XORV(db[EF76]), K50XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K29XORV(db[EF78]), K16XORV(db[EF79]), K21XORV(db[EF80]), K10XORV(db[EF81]), K08XORV(db[EF82]), K42XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K17XORV(db[  55]), K35XORV(db[  56]), K23XORV(db[  57]), K43XORV(db[  58]), K01XORV(db[  59]), K07XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K03XORV(db[  59]), K02XORV(db[  60]), K28XORV(db[  61]), K44XORV(db[  62]), K36XORV(db[  63]), K15XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(288);
		s1(K45XORV(db[EF00]), K55XORV(db[EF01]), K11XORV(db[EF02]), K06XORV(db[EF03]), K26XORV(db[EF04]), K53XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K12XORV(db[EF06]), K33XORV(db[EF07]), K38XORV(db[EF08]), K46XORV(db[EF09]), K27XORV(db[EF10]), K18XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K13XORV(db[   7]), K41XORV(db[   8]), K04XORV(db[   9]), K05XORV(db[  10]), K47XORV(db[  11]), K32XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K31XORV(db[  11]), K39XORV(db[  12]), K40XORV(db[  13]), K34XORV(db[  14]), K52XORV(db[  15]), K19XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K24XORV(db[EF24]), K00XORV(db[EF25]), K08XORV(db[EF26]), K23XORV(db[EF27]), K35XORV(db[EF28]), K36XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K15XORV(db[EF30]), K02XORV(db[EF31]), K07XORV(db[EF32]), K49XORV(db[EF33]), K51XORV(db[EF34]), K28XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K03XORV(db[  23]), K21XORV(db[  24]), K09XORV(db[  25]), K29XORV(db[  26]), K44XORV(db[  27]), K50XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K42XORV(db[  27]), K17XORV(db[  28]), K14XORV(db[  29]), K30XORV(db[  30]), K22XORV(db[  31]), K01XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(288);
		s1(K31XORV(db[EF48]), K41XORV(db[EF49]), K52XORV(db[EF50]), K47XORV(db[EF51]), K12XORV(db[EF52]), K39XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K53XORV(db[EF54]), K19XORV(db[EF55]), K55XORV(db[EF56]), K32XORV(db[EF57]), K13XORV(db[EF58]), K04XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K54XORV(db[  39]), K27XORV(db[  40]), K45XORV(db[  41]), K46XORV(db[  42]), K33XORV(db[  43]), K18XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K48XORV(db[  43]), K25XORV(db[  44]), K26XORV(db[  45]), K20XORV(db[  46]), K38XORV(db[  47]), K05XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K10XORV(db[EF72]), K43XORV(db[EF73]), K51XORV(db[EF74]), K09XORV(db[EF75]), K21XORV(db[EF76]), K22XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K01XORV(db[EF78]), K17XORV(db[EF79]), K50XORV(db[EF80]), K35XORV(db[EF81]), K37XORV(db[EF82]), K14XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K42XORV(db[  55]), K07XORV(db[  56]), K24XORV(db[  57]), K15XORV(db[  58]), K30XORV(db[  59]), K36XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K28XORV(db[  59]), K03XORV(db[  60]), K00XORV(db[  61]), K16XORV(db[  62]), K08XORV(db[  63]), K44XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(384);
		s1(K55XORV(db[EF00]), K34XORV(db[EF01]), K45XORV(db[EF02]), K40XORV(db[EF03]), K05XORV(db[EF04]), K32XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K46XORV(db[EF06]), K12XORV(db[EF07]), K48XORV(db[EF08]), K25XORV(db[EF09]), K06XORV(db[EF10]), K52XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K47XORV(db[   7]), K20XORV(db[   8]), K38XORV(db[   9]), K39XORV(db[  10]), K26XORV(db[  11]), K11XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K41XORV(db[  11]), K18XORV(db[  12]), K19XORV(db[  13]), K13XORV(db[  14]), K31XORV(db[  15]), K53XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K03XORV(db[EF24]), K36XORV(db[EF25]), K44XORV(db[EF26]), K02XORV(db[EF27]), K14XORV(db[EF28]), K15XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K51XORV(db[EF30]), K10XORV(db[EF31]), K43XORV(db[EF32]), K28XORV(db[EF33]), K30XORV(db[EF34]), K07XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K35XORV(db[  23]), K00XORV(db[  24]), K17XORV(db[  25]), K08XORV(db[  26]), K23XORV(db[  27]), K29XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K21XORV(db[  27]), K49XORV(db[  28]), K50XORV(db[  29]), K09XORV(db[  30]), K01XORV(db[  31]), K37XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(384);
		s1(K41XORV(db[EF48]), K20XORV(db[EF49]), K31XORV(db[EF50]), K26XORV(db[EF51]), K46XORV(db[EF52]), K18XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K32XORV(db[EF54]), K53XORV(db[EF55]), K34XORV(db[EF56]), K11XORV(db[EF57]), K47XORV(db[EF58]), K38XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K33XORV(db[  39]), K06XORV(db[  40]), K55XORV(db[  41]), K25XORV(db[  42]), K12XORV(db[  43]), K52XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K27XORV(db[  43]), K04XORV(db[  44]), K05XORV(db[  45]), K54XORV(db[  46]), K48XORV(db[  47]), K39XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K42XORV(db[EF72]), K22XORV(db[EF73]), K30XORV(db[EF74]), K17XORV(db[EF75]), K00XORV(db[EF76]), K01XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K37XORV(db[EF78]), K49XORV(db[EF79]), K29XORV(db[EF80]), K14XORV(db[EF81]), K16XORV(db[EF82]), K50XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K21XORV(db[  55]), K43XORV(db[  56]), K03XORV(db[  57]), K51XORV(db[  58]), K09XORV(db[  59]), K15XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K07XORV(db[  59]), K35XORV(db[  60]), K36XORV(db[  61]), K24XORV(db[  62]), K44XORV(db[  63]), K23XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(480);
		s1(K27XORV(db[EF00]), K06XORV(db[EF01]), K48XORV(db[EF02]), K12XORV(db[EF03]), K32XORV(db[EF04]), K04XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K18XORV(db[EF06]), K39XORV(db[EF07]), K20XORV(db[EF08]), K52XORV(db[EF09]), K33XORV(db[EF10]), K55XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K19XORV(db[   7]), K47XORV(db[   8]), K41XORV(db[   9]), K11XORV(db[  10]), K53XORV(db[  11]), K38XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K13XORV(db[  11]), K45XORV(db[  12]), K46XORV(db[  13]), K40XORV(db[  14]), K34XORV(db[  15]), K25XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K28XORV(db[EF24]), K08XORV(db[EF25]), K16XORV(db[EF26]), K03XORV(db[EF27]), K43XORV(db[EF28]), K44XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K23XORV(db[EF30]), K35XORV(db[EF31]), K15XORV(db[EF32]), K00XORV(db[EF33]), K02XORV(db[EF34]), K36XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K07XORV(db[  23]), K29XORV(db[  24]), K42XORV(db[  25]), K37XORV(db[  26]), K24XORV(db[  27]), K01XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K50XORV(db[  27]), K21XORV(db[  28]), K22XORV(db[  29]), K10XORV(db[  30]), K30XORV(db[  31]), K09XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(480);
		s1(K13XORV(db[EF48]), K47XORV(db[EF49]), K34XORV(db[EF50]), K53XORV(db[EF51]), K18XORV(db[EF52]), K45XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K04XORV(db[EF54]), K25XORV(db[EF55]), K06XORV(db[EF56]), K38XORV(db[EF57]), K19XORV(db[EF58]), K41XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K05XORV(db[  39]), K33XORV(db[  40]), K27XORV(db[  41]), K52XORV(db[  42]), K39XORV(db[  43]), K55XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K54XORV(db[  43]), K31XORV(db[  44]), K32XORV(db[  45]), K26XORV(db[  46]), K20XORV(db[  47]), K11XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K14XORV(db[EF72]), K51XORV(db[EF73]), K02XORV(db[EF74]), K42XORV(db[EF75]), K29XORV(db[EF76]), K30XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K09XORV(db[EF78]), K21XORV(db[EF79]), K01XORV(db[EF80]), K43XORV(db[EF81]), K17XORV(db[EF82]), K22XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K50XORV(db[  55]), K15XORV(db[  56]), K28XORV(db[  57]), K23XORV(db[  58]), K10XORV(db[  59]), K44XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K36XORV(db[  59]), K07XORV(db[  60]), K08XORV(db[  61]), K49XORV(db[  62]), K16XORV(db[  63]), K24XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(576);
		s1(K54XORV(db[EF00]), K33XORV(db[EF01]), K20XORV(db[EF02]), K39XORV(db[EF03]), K04XORV(db[EF04]), K31XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K45XORV(db[EF06]), K11XORV(db[EF07]), K47XORV(db[EF08]), K55XORV(db[EF09]), K05XORV(db[EF10]), K27XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K46XORV(db[   7]), K19XORV(db[   8]), K13XORV(db[   9]), K38XORV(db[  10]), K25XORV(db[  11]), K41XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K40XORV(db[  11]), K48XORV(db[  12]), K18XORV(db[  13]), K12XORV(db[  14]), K06XORV(db[  15]), K52XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K00XORV(db[EF24]), K37XORV(db[EF25]), K17XORV(db[EF26]), K28XORV(db[EF27]), K15XORV(db[EF28]), K16XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K24XORV(db[EF30]), K07XORV(db[EF31]), K44XORV(db[EF32]), K29XORV(db[EF33]), K03XORV(db[EF34]), K08XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K36XORV(db[  23]), K01XORV(db[  24]), K14XORV(db[  25]), K09XORV(db[  26]), K49XORV(db[  27]), K30XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K22XORV(db[  27]), K50XORV(db[  28]), K51XORV(db[  29]), K35XORV(db[  30]), K02XORV(db[  31]), K10XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(576);
		s1(K40XORV(db[EF48]), K19XORV(db[EF49]), K06XORV(db[EF50]), K25XORV(db[EF51]), K45XORV(db[EF52]), K48XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K31XORV(db[EF54]), K52XORV(db[EF55]), K33XORV(db[EF56]), K41XORV(db[EF57]), K46XORV(db[EF58]), K13XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K32XORV(db[  39]), K05XORV(db[  40]), K54XORV(db[  41]), K55XORV(db[  42]), K11XORV(db[  43]), K27XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K26XORV(db[  43]), K34XORV(db[  44]), K04XORV(db[  45]), K53XORV(db[  46]), K47XORV(db[  47]), K38XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K43XORV(db[EF72]), K23XORV(db[EF73]), K03XORV(db[EF74]), K14XORV(db[EF75]), K01XORV(db[EF76]), K02XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K10XORV(db[EF78]), K50XORV(db[EF79]), K30XORV(db[EF80]), K15XORV(db[EF81]), K42XORV(db[EF82]), K51XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K22XORV(db[  55]), K44XORV(db[  56]), K00XORV(db[  57]), K24XORV(db[  58]), K35XORV(db[  59]), K16XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K08XORV(db[  59]), K36XORV(db[  60]), K37XORV(db[  61]), K21XORV(db[  62]), K17XORV(db[  63]), K49XORV(db[  32]), db[ 4], db[26], db[14], db[20]);

		// ROUND_A(672);
		s1(K26XORV(db[EF00]), K05XORV(db[EF01]), K47XORV(db[EF02]), K11XORV(db[EF03]), K31XORV(db[EF04]), K34XORV(db[EF05]), db[40], db[48], db[54], db[62]);
		s2(K48XORV(db[EF06]), K38XORV(db[EF07]), K19XORV(db[EF08]), K27XORV(db[EF09]), K32XORV(db[EF10]), K54XORV(db[EF11]), db[44], db[59], db[33], db[49]);
		s3(K18XORV(db[   7]), K46XORV(db[   8]), K40XORV(db[   9]), K41XORV(db[  10]), K52XORV(db[  11]), K13XORV(db[  12]), db[55], db[47], db[61], db[37]);
		s4(K12XORV(db[  11]), K20XORV(db[  12]), K45XORV(db[  13]), K39XORV(db[  14]), K33XORV(db[  15]), K55XORV(db[  16]), db[57], db[51], db[41], db[32]);
		s5(K29XORV(db[EF24]), K09XORV(db[EF25]), K42XORV(db[EF26]), K00XORV(db[EF27]), K44XORV(db[EF28]), K17XORV(db[EF29]), db[39], db[45], db[56], db[34]);
		s6(K49XORV(db[EF30]), K36XORV(db[EF31]), K16XORV(db[EF32]), K01XORV(db[EF33]), K28XORV(db[EF34]), K37XORV(db[EF35]), db[35], db[60], db[42], db[50]);
		s7(K08XORV(db[  23]), K30XORV(db[  24]), K43XORV(db[  25]), K10XORV(db[  26]), K21XORV(db[  27]), K02XORV(db[  28]), db[63], db[43], db[53], db[38]);
		s8(K51XORV(db[  27]), K22XORV(db[  28]), K23XORV(db[  29]), K07XORV(db[  30]), K03XORV(db[  31]), K35XORV(db[   0]), db[36], db[58], db[46], db[52]);

		// ROUND_B(672);
		s1(K19XORV(db[EF48]), K53XORV(db[EF49]), K40XORV(db[EF50]), K04XORV(db[EF51]), K55XORV(db[EF52]), K27XORV(db[EF53]), db[ 8], db[16], db[22], db[30]);
		s2(K41XORV(db[EF54]), K31XORV(db[EF55]), K12XORV(db[EF56]), K20XORV(db[EF57]), K25XORV(db[EF58]), K47XORV(db[EF59]), db[12], db[27], db[ 1], db[17]);
		s3(K11XORV(db[  39]), K39XORV(db[  40]), K33XORV(db[  41]), K34XORV(db[  42]), K45XORV(db[  43]), K06XORV(db[  44]), db[23], db[15], db[29], db[ 5]);
		s4(K05XORV(db[  43]), K13XORV(db[  44]), K38XORV(db[  45]), K32XORV(db[  46]), K26XORV(db[  47]), K48XORV(db[  48]), db[25], db[19], db[ 9], db[ 0]);
		s5(K22XORV(db[EF72]), K02XORV(db[EF73]), K35XORV(db[EF74]), K50XORV(db[EF75]), K37XORV(db[EF76]), K10XORV(db[EF77]), db[ 7], db[13], db[24], db[ 2]);
		s6(K42XORV(db[EF78]), K29XORV(db[EF79]), K09XORV(db[EF80]), K51XORV(db[EF81]), K21XORV(db[EF82]), K30XORV(db[EF83]), db[ 3], db[28], db[10], db[18]);
		s7(K01XORV(db[  55]), K23XORV(db[  56]), K36XORV(db[  57]), K03XORV(db[  58]), K14XORV(db[  59]), K24XORV(db[  60]), db[31], db[11], db[21], db[ 6]);
		s8(K44XORV(db[  59]), K15XORV(db[  60]), K16XORV(db[  61]), K00XORV(db[  62]), K49XORV(db[  63]), K28XORV(db[  32]), db[ 4], db[26], db[14], db[20]);
	}
}

#define OPENCL_DES_DEFINE_SEARCH_FUNCTION                                                                  \
	\
	__kernel \
__attribute__((work_group_size_hint(OPENCL_DES_LOCAL_WORK_SIZE, 1, 1)))\
__attribute__((reqd_work_group_size(OPENCL_DES_LOCAL_WORK_SIZE, 1, 1)))\
	void OpenCL_DES_PerformSearching(                                                             \
				   const          int               searchMode,                                            \
		__global   GPUOutput                * const outputArray,                                           \
		__constant KeyInfo                  *       keyInfo,                                               \
		__global   const unsigned int       * const tripcodeChunkArray,                                    \
				   const unsigned int               numTripcodeChunk,                                      \
 		__constant const unsigned char      * const smallChunkBitmap,                                        \
  		__constant const unsigned int       * const compactMediumChunkBitmap,                                \
		__global   const unsigned char      * const chunkBitmap,                                             \
		__global   const PartialKeyFrom3To6 * const partialKeyFrom3To6Array,                               \
                   const unsigned int               keyFrom00To27                                          \
	) {                                                                                                    \
		__global              GPUOutput     *output = &outputArray[get_global_id(0)];                      \
							  int  tripcodeIndex;                                                          \
		DES_DATA_BLOCKS_SPACE vtype          DES_dataBlocks[64];                                           \
		__global unsigned char *partialKeyFrom3To6 = partialKeyFrom3To6Array[get_global_id(0)].partialKeyFrom3To6; \
		output->numMatchingTripcodes = 0;                                                                  \
		const unsigned int keyFrom28To48 = ((partialKeyFrom3To6[3] & 0x7f) << 14) | ((partialKeyFrom3To6[2] & 0x7f) << 7) | (partialKeyFrom3To6[1] & 0x7f); \
		                                                                                                   \
		DES_Crypt(DES_dataBlocks, keyFrom00To27, keyFrom28To48);                                           \
		                                                                                                   \
		BOOL found = FALSE;                                                                                \

#define OPENCL_DES_END_OF_SEAERCH_FUNCTION                                                                 \
	quit_loops:                                                                                            \
		if (found == TRUE) {                                                                               \
			output->numMatchingTripcodes = 1;                                                              \
			output->pair.key.c[7] = (tripcodeIndex == 0) ? KEY7_00 :\
                                    (tripcodeIndex == 1) ? KEY7_01 :\
                                    (tripcodeIndex == 2) ? KEY7_02 :\
                                    (tripcodeIndex == 3) ? KEY7_03 :\
                                    (tripcodeIndex == 4) ? KEY7_04 :\
                                    (tripcodeIndex == 5) ? KEY7_05 :\
                                    (tripcodeIndex == 6) ? KEY7_06 :\
                                    (tripcodeIndex == 7) ? KEY7_07 :\
                                    (tripcodeIndex == 8) ? KEY7_08 :\
                                    (tripcodeIndex == 9) ? KEY7_09 :\
									(tripcodeIndex == 10) ? KEY7_10 :\
                                    (tripcodeIndex == 11) ? KEY7_11 :\
                                    (tripcodeIndex == 12) ? KEY7_12 :\
                                    (tripcodeIndex == 13) ? KEY7_13 :\
                                    (tripcodeIndex == 14) ? KEY7_14 :\
                                    (tripcodeIndex == 15) ? KEY7_15 :\
                                    (tripcodeIndex == 16) ? KEY7_16 :\
                                    (tripcodeIndex == 17) ? KEY7_17 :\
                                    (tripcodeIndex == 18) ? KEY7_18 :\
                                    (tripcodeIndex == 19) ? KEY7_19 :\
									(tripcodeIndex == 20) ? KEY7_20 :\
                                    (tripcodeIndex == 21) ? KEY7_21 :\
                                    (tripcodeIndex == 22) ? KEY7_22 :\
                                    (tripcodeIndex == 23) ? KEY7_23 :\
                                    (tripcodeIndex == 24) ? KEY7_24 :\
                                    (tripcodeIndex == 25) ? KEY7_25 :\
                                    (tripcodeIndex == 26) ? KEY7_26 :\
                                    (tripcodeIndex == 27) ? KEY7_27 :\
                                    (tripcodeIndex == 28) ? KEY7_28 :\
                                    (tripcodeIndex == 29) ? KEY7_29 :\
									(tripcodeIndex == 30) ? KEY7_30 :\
                                                            KEY7_31;\
		}                                                                                                  \
		output->numGeneratedTripcodes = OPENCL_DES_BS_DEPTH;                                               \
	}                                                                                                      \

#define OPENCL_DES_USE_SMALL_CHUNK_BITMAP                                           \
	if (smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) \
		continue;                                                                 \

#define OPENCL_DES_USE_MEDIUM_CHUNK_BITMAP                                          \
	if (compactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 5)] & (0x1 << (tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6) & 0x1f))) \
		continue;                                                                 \

#define OPENCL_DES_USE_CHUNK_BITMAP                                                 \
	if (chunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])            \
		continue;                                                                 \

#define OPENCL_DES_PERFORM_LINEAR_SEARCH                                          \
	for (int j = 0; j < numTripcodeChunk; ++j) {                                  \
		if (tripcodeChunkArray[j] == tripcodeChunk) {                             \
			found = TRUE;                                                         \
			goto quit_loops;                                                      \
		}                                                                         \
	}                                                                             \

#define OPENCL_DES_PERFORM_BINARY_SEARCH                                    \
	int lower = 0, upper = numTripcodeChunk - 1, middle = lower;            \
	while (tripcodeChunk != tripcodeChunkArray[middle] && lower <= upper) { \
		middle = (lower + upper) >> 1;                                      \
		if (tripcodeChunk > tripcodeChunkArray[middle]) {                   \
			lower = middle + 1;                                             \
		} else {                                                            \
			upper = middle - 1;                                             \
		}                                                                   \
	}                                                                       \
	if (tripcodeChunk == tripcodeChunkArray[middle]) {                      \
		found = TRUE;                                                       \
		goto quit_loops;                                                    \
	}                                                                       \

#define GET_TRIPCODE_CHAR_INDEX(r, t, i0, i1, i2, i3, i4, i5, pos)         \
	(  ((((r)[i0] & (0x01U << (t))) ? (0x1) : (0x0)) << (5 + ((pos) * 6)))  \
	 | ((((r)[i1] & (0x01U << (t))) ? (0x1) : (0x0)) << (4 + ((pos) * 6)))  \
	 | ((((r)[i2] & (0x01U << (t))) ? (0x1) : (0x0)) << (3 + ((pos) * 6)))  \
	 | ((((r)[i3] & (0x01U << (t))) ? (0x1) : (0x0)) << (2 + ((pos) * 6)))  \
	 | ((((r)[i4] & (0x01U << (t))) ? (0x1) : (0x0)) << (1 + ((pos) * 6)))  \
	 | ((((r)[i5] & (0x01U << (t))) ? (0x1) : (0x0)) << (0 + ((pos) * 6)))) \

#define GET_TRIPCODE_CHAR_INDEX_LAST(r, t, i0, i1, i2, i3) \
	(  ((((r)[i0] & (0x01U << (t))) ? (0x1) : (0x0)) << 5)  \
	 | ((((r)[i1] & (0x01U << (t))) ? (0x1) : (0x0)) << 4)  \
	 | ((((r)[i2] & (0x01U << (t))) ? (0x1) : (0x0)) << 3)  \
	 | ((((r)[i3] & (0x01U << (t))) ? (0x1) : (0x0)) << 2)) \

#if defined(FORWARD_MATCHING_1CHUNK)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		if (GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0) != ((tripcodeChunkArray[0] >> (6 * 4)) & 0x3f)) continue;
		if (GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0) != ((tripcodeChunkArray[0] >> (6 * 3)) & 0x3f)) continue;
		if (GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0) != ((tripcodeChunkArray[0] >> (6 * 2)) & 0x3f)) continue;
		if (GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0) != ((tripcodeChunkArray[0] >> (6 * 1)) & 0x3f)) continue;
		if (GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0) != ((tripcodeChunkArray[0] >> (6 * 0)) & 0x3f)) continue;
		found = TRUE;
		goto quit_loops;
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FORWARD_MATCHING_SIMPLE)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_PERFORM_LINEAR_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FORWARD_MATCHING)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		// all:                                  2181M (10m)
		// w/o OPENCL_DES_USE_SMALL_CHUNK_BITMAP:  2160M (10m)
		// w/o OPENCL_DES_USE_MEDIUM_CHUNK_BITMAP: 2142M (10m)
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_USE_MEDIUM_CHUNK_BITMAP
		OPENCL_DES_USE_CHUNK_BITMAP
		OPENCL_DES_PERFORM_BINARY_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(BACKWARD_MATCHING_SIMPLE)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                             | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_PERFORM_LINEAR_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(BACKWARD_MATCHING)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                             | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_USE_CHUNK_BITMAP
		OPENCL_DES_PERFORM_BINARY_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FORWARD_AND_BACKWARD_MATCHING_SIMPLE)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_PERFORM_LINEAR_SEARCH
	}
	
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                             | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_PERFORM_LINEAR_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FORWARD_AND_BACKWARD_MATCHING)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_USE_CHUNK_BITMAP
		OPENCL_DES_PERFORM_BINARY_SEARCH
	}
	
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 4)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 3)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 2)
		                             | GET_TRIPCODE_CHAR_INDEX     (DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 1)
		                             | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		OPENCL_DES_USE_SMALL_CHUNK_BITMAP
		OPENCL_DES_USE_CHUNK_BITMAP
		OPENCL_DES_PERFORM_BINARY_SEARCH
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FLEXIBLE_SIMPLE)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		if (!smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]) { OPENCL_DES_PERFORM_LINEAR_SEARCH }
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#elif defined(FLEXIBLE)

OPENCL_DES_DEFINE_SEARCH_FUNCTION
	for (tripcodeIndex = 0; tripcodeIndex < OPENCL_DES_BS_DEPTH; ++tripcodeIndex) {
		unsigned int tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 4)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 3)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 2)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 1)
						             | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(DES_dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}

		tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX_LAST(DES_dataBlocks, tripcodeIndex, 48, 16, 56, 24);
		if (   !smallChunkBitmap[tripcodeChunk >> ((5 - SMALL_CHUNK_BITMAP_LEN_STRING) * 6)]
		    && !     chunkBitmap[tripcodeChunk >> ((5 -       CHUNK_BITMAP_LEN_STRING) * 6)]) {
			OPENCL_DES_PERFORM_BINARY_SEARCH
		}
	}
OPENCL_DES_END_OF_SEAERCH_FUNCTION

#endif