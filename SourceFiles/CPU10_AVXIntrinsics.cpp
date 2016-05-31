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

#define CPU_DES_MAIN_LOOP CPU_DES_MainLoop_AVX

typedef VECTOR_ALIGNMENT DES_Vector vtype;

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

#include "CPU10.h"

