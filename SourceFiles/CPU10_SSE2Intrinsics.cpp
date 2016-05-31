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
typedef union VECTOR_ALIGNMENT DES_Vector {
#ifdef ARCH_X86
	__m128i m128i;
#endif
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

typedef VECTOR_ALIGNMENT DES_Vector vtype;

#ifdef ARCH_X86

inline vtype vxor_func(vtype &a, vtype &b) 
{
    vtype ret;

    ret.m128i = _mm_xor_si128((a).m128i, (b).m128i);
    return ret;
}

#define vnot(dst, a)     (dst).m128i =  _mm_andnot_si128((a).m128i, _mm_set1_epi8(0xff))
#define vand(dst, a, b)  (dst).m128i =  _mm_and_si128((a).m128i, (b).m128i)
#define vor(dst, a, b)   (dst).m128i =  _mm_or_si128((a).m128i, (b).m128i)
#define vxor(dst, a, b)  (dst).m128i =  _mm_xor_si128((a).m128i, (b).m128i)
#define vandn(dst, a, b) (dst).m128i =  _mm_andnot_si128((b).m128i, (a).m128i)

#elif defined(ARCH_64BIT)

inline vtype vxor_func(vtype &a, vtype &b) 
{
    vtype ret;

    ret.m128i_u64[0] = (a).m128i_u64[0] ^ (b).m128i_u64[0];
    ret.m128i_u64[1] = (a).m128i_u64[1] ^ (b).m128i_u64[1];
    return ret;
}

inline void vnot(vtype &dst, vtype &a) 
{
    dst.m128i_u64[0] = ~(a).m128i_u64[0];
    dst.m128i_u64[1] = ~(a).m128i_u64[1];
}

inline void vand(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u64[0] = (a).m128i_u64[0] & (b).m128i_u64[0];
    dst.m128i_u64[1] = (a).m128i_u64[1] & (b).m128i_u64[1];
}

inline void vor(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u64[0] = (a).m128i_u64[0] | (b).m128i_u64[0];
    dst.m128i_u64[1] = (a).m128i_u64[1] | (b).m128i_u64[1];
}

inline void vxor(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u64[0] = (a).m128i_u64[0] ^ (b).m128i_u64[0];
    dst.m128i_u64[1] = (a).m128i_u64[1] ^ (b).m128i_u64[1];
}

inline void vandn(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u64[0] = (a).m128i_u64[0] & ~(b).m128i_u64[0];
    dst.m128i_u64[1] = (a).m128i_u64[1] & ~(b).m128i_u64[1];
}

#else

inline vtype vxor_func(vtype &a, vtype &b) 
{
    vtype ret;

    ret.m128i_u32[0] = (a).m128i_u32[0] ^ (b).m128i_u32[0];
    ret.m128i_u32[1] = (a).m128i_u32[1] ^ (b).m128i_u32[1];
    ret.m128i_u32[2] = (a).m128i_u32[2] ^ (b).m128i_u32[2];
    ret.m128i_u32[3] = (a).m128i_u32[3] ^ (b).m128i_u32[3];
    return ret;
}

inline void vnot(vtype &dst, vtype &a) 
{
    dst.m128i_u32[0] = ~(a).m128i_u32[0];
    dst.m128i_u32[1] = ~(a).m128i_u32[1];
    dst.m128i_u32[2] = ~(a).m128i_u32[2];
    dst.m128i_u32[3] = ~(a).m128i_u32[3];
}

inline void vand(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u32[0] = (a).m128i_u32[0] & (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] & (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] & (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] & (b).m128i_u32[3];
}

inline void vor(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u32[0] = (a).m128i_u32[0] | (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] | (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] | (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] | (b).m128i_u32[3];
}

inline void vxor(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u32[0] = (a).m128i_u32[0] ^ (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] ^ (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] ^ (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] ^ (b).m128i_u32[3];
}

inline void vandn(vtype &dst, vtype &a, vtype &b) 
{
    dst.m128i_u32[0] = (a).m128i_u32[0] & ~(b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] & ~(b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] & ~(b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] & ~(b).m128i_u32[3];
}

#endif

#include "CPU10.h"



///////////////////////////////////////////////////////////////////////////////
// THREAD                                                                    //
///////////////////////////////////////////////////////////////////////////////

#ifdef ARCH_X86

extern void CPU_DES_MainLoop_AVX2();
extern void CPU_DES_MainLoop_AVX();

void Thread_SearchForDESTripcodesOnCPU()
{
    if(__builtin_cpu_supports("avx2")) {
    	CPU_DES_MainLoop_AVX2();
    } else if(__builtin_cpu_supports("avx")) {
    	CPU_DES_MainLoop_AVX();
    } else {
    	CPU_DES_MainLoop();
    }
}

#else

void Thread_SearchForDESTripcodesOnCPU()
{
   	CPU_DES_MainLoop();
}

#endif

