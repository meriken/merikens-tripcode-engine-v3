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
// BITSLICE DES                                                              //
///////////////////////////////////////////////////////////////////////////////

#define VECTOR_SIZE 16
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(16))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (16))) 
#endif
typedef union VECTOR_ALIGNMENT __DES_Vector {
	__m128i m128i;
	int8_t m128i_i8[16];
	int16_t m128i_i16[8];
	int32_t m128i_i32[4];
	int64_t m128i_i64[2];
	uint8_t m128i_u8[16];
	uint16_t m128i_u16[8];
	uint32_t m128i_u32[4];
	uint64_t m128i_u64[2];
} DES_Vector;
#define VECTOR_ELEMENTS m128i_i32

#define CPU_DES_MAIN_LOOP CPU_DES_MainLoop

// Bitslice DES S-boxes for x86 with MMX/SSE2/AVX and for typical RISC
// architectures.  These use AND, OR, XOR, NOT, and AND-NOT gates.
//
// Gate counts: 49 44 46 33 48 46 46 41
// Average: 44.125
//
// Several same-gate-count expressions for each S-box are included (for use on
// different CPUs/GPUs).
//
// These Boolean expressions corresponding to DES S-boxes have been generated
// by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
// John the Ripper password cracker: http://www.openwall.com/john/
// Being mathematical formulas, they are not copyrighted and are free for reuse
// by anyone.
//
// This file (a specific representation of the S-box expressions, surrounding
// logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.  (This is a heavily cut-down "BSD license".)
//
// The effort has been sponsored by Rapid7: http://www.rapid7.com

typedef VECTOR_ALIGNMENT __m128i vtype;

#define DES_VECTOR_XOR_FUNC           _mm_xor_si128

#define MOVDQA(op1, op2) (op2) = (op1)
#define POR(op1, op2)    (op2) = _mm_or_si128    ((op2), (op1))
#define PAND(op1, op2)   (op2) = _mm_and_si128   ((op2), (op1))
#define PXOR(op1, op2)   (op2) = _mm_xor_si128   ((op2), (op1))
#define PANDN(op1, op2)  (op2) = _mm_andnot_si128((op2), (op1))

#define vnot(dst, a)     (dst) =  _mm_andnot_si128((a), _mm_set1_epi8(0xff))
#define vand(dst, a, b)  (dst) =  _mm_and_si128((a), (b))
#define vor(dst, a, b)   (dst) =  _mm_or_si128((a), (b))
#define vxor(dst, a, b)  (dst) =  _mm_xor_si128((a), (b))
#define vandn(dst, a, b) (dst) =  _mm_andnot_si128((b), (a))

#define s1(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var0, var4); \
	vxor(var7, var3, var6); \
	vor(var8, var2, var5); \
	vxor(var9, var0, var2); \
	vand(var10, var8, var9); \
	vxor(var11, var3, var10); \
	vandn(var12, var11, var7); \
	vxor(var13, var4, var5); \
	vxor(var14, var2, var13); \
	vandn(var15, var7, var14); \
	vor(var14, var5, var10); \
	vxor(var10, var15, var14); \
	vandn(var14, var10, var12); \
	vor(var15, var0, var5); \
	vor(var5, var10, var15); \
	vandn(var16, var4, var11); \
	vxor(var11, var5, var16); \
	vandn(var17, var3, var15); \
	vxor(var3, var16, var17); \
	vandn(var15, var13, var9); \
	vor(var9, var3, var15); \
	vandn(var3, var2, var6); \
	vxor(var2, var7, var5); \
	vandn(var6, var2, var3); \
	vnot(var2, var6); \
	vand(var3, var8, var10); \
	vxor(var10, var2, var3); \
	vandn(var2, var11, var1); \
	vxor(var3, var2, var10); \
	vxor(out3, out3, var3); \
	vxor(var2, var13, var6); \
	vor(var3, var16, var2); \
	vxor(var2, var8, var3); \
	vxor(var3, var0, var2); \
	vxor(var0, var10, var3); \
	vor(var2, var12, var1); \
	vxor(var6, var2, var0); \
	vxor(out1, out1, var6); \
	vxor(var2, var8, var5); \
	vor(var5, var9, var2); \
	vxor(var2, var3, var5); \
	vor(var5, var13, var0); \
	vxor(var0, var2, var5); \
	vor(var5, var14, var1); \
	vxor(var6, var5, var0); \
	vxor(out2, out2, var6); \
	vor(var0, var4, var7); \
	vandn(var4, var0, var2); \
	vand(var0, var14, var3); \
	vxor(var2, var4, var0); \
	vor(var0, var2, var1); \
	vxor(var1, var0, var9); \
	vxor(out4, out4, var1); \
}                  \

#define s2(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor(var6, var1, var4); \
	vandn(var7, var0, var5); \
	vandn(var8, var4, var7); \
	vor(var7, var1, var8); \
	vandn(var9, var6, var5); \
	vand(var10, var0, var6); \
	vxor(var11, var4, var10); \
	vandn(var10, var11, var9); \
	vand(var12, var2, var5); \
	vxor(var13, var8, var9); \
	vand(var8, var7, var13); \
	vandn(var13, var8, var12); \
	vand(var14, var2, var8); \
	vnot(var8, var0); \
	vxor(var0, var14, var8); \
	vxor(var8, var5, var6); \
	vandn(var5, var8, var12); \
	vxor(var6, var0, var5); \
	vandn(var15, var3, var13); \
	vxor(var13, var15, var6); \
	vxor(out2, out2, var13); \
	vandn(var13, var1, var5); \
	vxor(var1, var11, var13); \
	vandn(var5, var0, var1); \
	vxor(var0, var2, var8); \
	vxor(var2, var5, var0); \
	vandn(var5, var7, var3); \
	vxor(var11, var5, var2); \
	vxor(out1, out1, var11); \
	vxor(var5, var14, var13); \
	vor(var11, var0, var5); \
	vxor(var0, var7, var6); \
	vor(var7, var12, var0); \
	vxor(var12, var11, var7); \
	vxor(var11, var2, var5); \
	vand(var2, var7, var11); \
	vxor(var5, var4, var2); \
	vandn(var2, var5, var9); \
	vxor(var4, var6, var2); \
	vor(var2, var4, var3); \
	vxor(var5, var2, var12); \
	vxor(out3, out3, var5); \
	vandn(var2, var4, var1); \
	vor(var1, var8, var0); \
	vxor(var0, var2, var1); \
	vor(var1, var10, var3); \
	vxor(var2, var1, var0); \
	vxor(out4, out4, var2); \
}                      \

#define s3(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var0, var1); \
	vxor(var7, var2, var5); \
	vor(var8, var6, var7); \
	vxor(var6, var3, var5); \
	vandn(var9, var6, var0); \
	vxor(var10, var8, var9); \
	vxor(var11, var1, var7); \
	vandn(var12, var11, var5); \
	vxor(var13, var8, var12); \
	vandn(var8, var10, var13); \
	vand(var12, var5, var10); \
	vor(var14, var3, var12); \
	vand(var12, var0, var14); \
	vxor(var14, var11, var12); \
	vandn(var12, var10, var4); \
	vxor(var15, var12, var14); \
	vxor(out4, out4, var15); \
	vand(var12, var7, var6); \
	vxor(var6, var0, var3); \
	vxor(var7, var13, var6); \
	vor(var13, var2, var7); \
	vandn(var7, var13, var12); \
	vor(var12, var9, var6); \
	vandn(var6, var14, var12); \
	vand(var9, var3, var5); \
	vandn(var3, var9, var1); \
	vxor(var5, var6, var3); \
	vandn(var3, var5, var2); \
	vor(var6, var11, var9); \
	vandn(var9, var6, var3); \
	vxor(var3, var0, var9); \
	vand(var6, var7, var4); \
	vxor(var9, var6, var3); \
	vxor(out2, out2, var9); \
	vor(var3, var1, var2); \
	vandn(var1, var10, var3); \
	vxor(var2, var11, var12); \
	vnot(var6, var2); \
	vxor(var2, var1, var6); \
	vandn(var1, var4, var8); \
	vxor(var8, var1, var2); \
	vxor(out1, out1, var8); \
	vxor(var1, var0, var7); \
	vor(var0, var6, var1); \
	vxor(var1, var10, var0); \
	vxor(var0, var14, var1); \
	vxor(var1, var3, var0); \
	vor(var0, var5, var4); \
	vxor(var2, var0, var1); \
	vxor(out3, out3, var2); \
}

#define s4(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{  \
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor (var6, var0, var2); \
	vxor (var0, var2, var4); \
	vor  (var2, var1, var3); \
	vxor (var7, var4, var2); \
	vandn(var2, var0, var7); \
	vandn(var7, var0, var1); \
	vxor (var8, var3, var7); \
	vor  (var9, var6, var8); \
	vandn(var10, var9, var2); \
	vxor (var9, var1, var10); \
	vand (var11, var8, var9); \
	vandn(var8, var0, var11); \
	vxor (var0, var6, var9); \
	vandn(var6, var0, var8); \
	vxor (var8, var2, var6); \
	vxor (var2, var1, var3); \
	vor  (var1, var4, var7); \
	vxor (var3, var0, var1); \
	vandn(var0, var3, var2); \
	vxor (var1, var10, var0); \
	vandn(var0, var5, var8); \
	vxor (var4, var0, var1); \
	vxor (var4, var4, out1); \
	out1 = var4; \
	vnot (var0, var1); \
	vandn(var1, var8, var5); \
	vxor (var4, var1, var0); \
	vxor (var4, var4, out2); \
	out2 = var4; \
	vxor (var1, var8, var0); \
	vandn(var0, var1, var2); \
	vor  (var1, var11, var0); \
	vxor (var0, var3, var1); \
	vor  (var1, var9, var5); \
	vxor (var2, var1, var0); \
 	vxor (var2, var2, out3); \
	out3 = var2; \
	vand (var1, var5, var9); \
	vxor (var2, var1, var0); \
	vxor (var2, var2, out4); \
	out4 = var2;  \
} \

#define s5(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vor(var6, var0, var2); \
	vandn(var7, var6, var5); \
	vxor(var8, var0, var7); \
	vxor(var9, var2, var8); \
	vor(var10, var3, var9); \
	vandn(var11, var7, var3); \
	vxor(var7, var2, var11); \
	vand(var2, var4, var7); \
	vor(var11, var0, var9); \
	vxor(var9, var2, var11); \
	vxor(var2, var3, var9); \
	vxor(var9, var5, var2); \
	vor(var5, var8, var9); \
	vand(var12, var4, var5); \
	vxor(var13, var8, var12); \
	vand(var14, var3, var11); \
	vxor(var15, var13, var14); \
	vandn(var13, var5, var0); \
	vxor(var5, var7, var13); \
	vxor(var14, var4, var10); \
	vandn(var4, var14, var5); \
	vnot(var5, var4); \
	vandn(var4, var5, var1); \
	vxor(var5, var4, var2); \
	vxor(out3, out3, var5); \
	vandn(var2, var7, var12); \
	vxor(var4, var13, var14); \
	vor(var5, var15, var4); \
	vandn(var4, var5, var2); \
	vandn(var2, var10, var4); \
	vand(var5, var9, var4); \
	vxor(var9, var14, var5); \
	vand(var5, var7, var11); \
	vor(var11, var9, var5); \
	vxor(var5, var12, var11); \
	vand(var11, var5, var1); \
	vxor(var5, var11, var15); \
	vxor(out4, out4, var5); \
	vxor(var5, var0, var6); \
	vxor(var0, var4, var5); \
	vand(var4, var3, var9); \
	vxor(var3, var0, var4); \
	vor(var0, var2, var1); \
	vxor(var2, var0, var3); \
	vxor(out1, out1, var2); \
	vxor(var0, var10, var7); \
	vandn(var2, var0, var3); \
	vxor(var0, var8, var9); \
	vxor(var3, var2, var0); \
	vand(var0, var10, var1); \
	vxor(var1, var0, var3); \
	vxor(out2, out2, var1); \
}

#define s6(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor(var6, var1, var4); \
	vor(var7, var1, var5); \
	vand(var8, var0, var7); \
	vxor(var7, var6, var8); \
	vxor(var6, var5, var7); \
	vandn(var9, var4, var6); \
	vand(var10, var0, var6); \
	vxor(var6, var1, var10); \
	vxor(var11, var0, var2); \
	vor(var12, var6, var11); \
	vxor(var13, var7, var12); \
	vand(var14, var2, var13); \
	vandn(var15, var14, var5); \
	vor(var16, var9, var6); \
	vxor(var6, var15, var16); \
	vand(var17, var6, var3); \
	vxor(var18, var17, var13); \
	vxor(out4, out4, var18); \
	vxor(var17, var1, var12); \
	vandn(var12, var5, var17); \
	vxor(var18, var2, var12); \
	vandn(var2, var4, var14); \
	vor(var12, var18, var2); \
	vor(var2, var0, var13); \
	vand(var13, var16, var2); \
	vxor(var2, var18, var13); \
	vandn(var13, var2, var15); \
	vor(var15, var9, var3); \
	vxor(var9, var15, var13); \
	vxor(out3, out3, var9); \
	vor(var9, var1, var11); \
	vxor(var1, var6, var9); \
	vor(var6, var8, var12); \
	vxor(var8, var1, var6); \
	vxor(var1, var7, var2); \
	vandn(var2, var4, var1); \
	vnot(var1, var17); \
	vxor(var4, var9, var1); \
	vxor(var1, var2, var4); \
	vandn(var2, var1, var3); \
	vxor(var1, var2, var8); \
	vxor(out2, out2, var1); \
	vxor(var1, var5, var10); \
	vxor(var2, var0, var18); \
	vand(var0, var1, var2); \
	vxor(var1, var14, var4); \
	vxor(var2, var0, var1); \
	vandn(var0, var12, var3); \
	vxor(var1, var0, var2); \
	vxor(out1, out1, var1); \
}                      \

#define s7(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var3, var4); \
	vxor(var7, var1, var6); \
	vor(var8, var2, var7); \
	vxor(var9, var0, var3); \
	vxor(var10, var4, var9); \
	vxor(var11, var8, var10); \
	vxor(var8, var2, var10); \
	vandn(var12, var0, var8); \
	vxor(var13, var6, var12); \
	vand(var12, var7, var13); \
	vxor(var7, var6, var12); \
	vandn(var6, var5, var7); \
	vxor(var14, var6, var11); \
	vxor(var14, var14, out4); \
	out4 = var14; \
	vor(var6, var1, var3); \
	vand(var3, var2, var6); \
	vor(var2, var0, var3); \
	vandn(var11, var2, var13); \
	vxor(var14, var8, var7); \
	vandn(var7, var13, var14); \
	vandn(var15, var6, var7); \
	vandn(var7, var9, var3); \
	vxor(var3, var15, var7); \
	vand(var9, var10, var2); \
	vxor(var2, var1, var14); \
	vor(var10, var9, var2); \
	vxor(var2, var15, var10); \
	vor(var14, var11, var5); \
	vxor(var15, var14, var2); \
	vxor(var15, var15, out1); \
	out1 = var15; \
	vand(var2, var8, var9); \
	vxor(var9, var1, var2); \
	vandn(var1, var9, var7); \
	vxor(var9, var13, var1); \
	vxor(var1, var10, var9); \
	vor(var10, var12, var2); \
	vandn(var2, var10, var4); \
	vxor(var10, var8, var2); \
	vxor(var2, var6, var10); \
	vand(var6, var1, var5); \
	vxor(var1, var6, var2); \
	vxor(var1, var1, out3); \
	out3 = var1; \
 	vandn(var1, var4, var7); \
	vxor(var2, var11, var1); \
	vor(var0, var0, var2); \
 	vnot(var1, var9); \
	vxor(var2, var0, var1); \
	vand(var0, var3, var5); \
	vxor(var1, var0, var2); \
	vxor(var1, var1, out2); \
	out2 = var1; \
}                     \

#define s8(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var2, var1); \
	vandn(var7, var4, var2); \
	vxor(var8, var3, var7); \
	vand(var7, var0, var8); \
	vandn(var9, var7, var6); \
	vandn(var10, var1, var8); \
	vor(var11, var0, var10); \
	vandn(var12, var1, var2); \
	vxor(var13, var4, var12); \
	vand(var12, var11, var13); \
	vor(var14, var7, var12); \
	vnot(var7, var8); \
	vxor(var8, var12, var7); \
	vandn(var7, var2, var11); \
	vxor(var2, var8, var7); \
	vxor(var7, var6, var2); \
	vor(var6, var9, var5); \
	vxor(var8, var6, var7); \
	vxor(out2, out2, var8); \
	vxor(var6, var0, var7); \
	vand(var7, var4, var6); \
	vxor(var8, var1, var2); \
	vxor(var2, var7, var8); \
	vxor(var7, var10, var2); \
	vxor(var10, var14, var2); \
	vor(var2, var1, var10); \
	vxor(var1, var4, var6); \
	vxor(var4, var2, var1); \
	vand(var1, var14, var5); \
	vxor(var2, var1, var4); \
	vxor(out3, out3, var2); \
	vxor(var1, var13, var7); \
	vor(var2, var3, var8); \
	vxor(var6, var1, var2); \
	vxor(var2, var0, var6); \
	vand(var0, var2, var5); \
	vxor(var2, var0, var7); \
	vxor(out4, out4, var2); \
	vandn(var0, var1, var3); \
	vand(var1, var4, var0); \
	vxor(var0, var9, var6); \
	vxor(var2, var1, var0); \
	vor(var0, var2, var5); \
	vxor(var1, var0, var7); \
	vxor(out1, out1, var1); \
}                      \



#define x(p)    DES_VECTOR_XOR_FUNC(dataBlocks[expansionFunction[p]], expandedKeySchedule[keyScheduleIndexBase + (p)])
#define y(p, q) DES_VECTOR_XOR_FUNC(dataBlocks[p],                    expandedKeySchedule[keyScheduleIndexBase + (q)])
#define z(r)    (dataBlocks[r])

void CPU_DES_SBoxes1_SSE2Intrinsics(unsigned char *expansionFunction, __m128i *expandedKeySchedule, __m128i *dataBlocks, int32_t keyScheduleIndexBase)
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
	vtype pnot = _mm_set1_epi8(0xff);

	s1(x(0), x(1), x(2), x(3), x(4), x(5), z(40), z(48), z(54), z(62));
	s2(x(6), x(7), x(8), x(9), x(10), x(11), z(44), z(59), z(33), z(49));
	s3(y(7, 12), y(8, 13), y(9, 14), y(10, 15), y(11, 16), y(12, 17), z(55), z(47), z(61), z(37));
	s4(y(11, 18), y(12, 19), y(13, 20), y(14, 21), y(15, 22), y(16, 23), z(57), z(51), z(41), z(32));
	s5(x(24), x(25), x(26), x(27), x(28), x(29), z(39), z(45), z(56), z(34));
	s6(x(30), x(31), x(32), x(33), x(34), x(35), z(35), z(60), z(42), z(50));
	s7(y(23, 36), y(24, 37), y(25, 38), y(26, 39), y(27, 40), y(28, 41), z(63), z(43), z(53), z(38));
	s8(y(27, 42), y(28, 43), y(29, 44), y(30, 45), y(31, 46), y(0, 47), z(36), z(58), z(46), z(52));
}

void CPU_DES_SBoxes2_SSE2Intrinsics(unsigned char *expansionFunction, __m128i *expandedKeySchedule, __m128i *dataBlocks, int32_t keyScheduleIndexBase)
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
	vtype pnot = _mm_set1_epi8(0xff);

	s1(x(48), x(49), x(50), x(51), x(52), x(53), z(8), z(16), z(22), z(30));
	s2(x(54), x(55), x(56), x(57), x(58), x(59), z(12), z(27), z(1), z(17));
	s3(y(39, 60), y(40, 61), y(41, 62), y(42, 63), y(43, 64), y(44, 65), z(23), z(15), z(29), z(5));
	s4(y(43, 66), y(44, 67), y(45, 68), y(46, 69), y(47, 70), y(48, 71), z(25), z(19), z(9), z(0));
	s5(x(72), x(73), x(74), x(75), x(76), x(77), z(7), z(13), z(24), z(2));
	s6(x(78), x(79), x(80), x(81), x(82), x(83), z(3), z(28), z(10), z(18));
	s7(y(55, 84), y(56, 85), y(57, 86), y(58, 87), y(59, 88), y(60, 89), z(31), z(11), z(21), z(6));
	s8(y(59, 90), y(60, 91), y(61, 92), y(62, 93), y(63, 94), y(32, 95), z(4), z(26), z(14), z(20));
}

#include "CPU10.h"



///////////////////////////////////////////////////////////////////////////////
// THREAD                                                                    //
///////////////////////////////////////////////////////////////////////////////

void Thread_SearchForDESTripcodesOnCPU()
{
	CPU_DES_MainLoop();
}
