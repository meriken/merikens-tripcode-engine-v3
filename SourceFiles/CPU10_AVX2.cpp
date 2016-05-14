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

#define VECTOR_SIZE 32
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(32))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (32))) 
#endif
typedef union VECTOR_ALIGNMENT __DES_Vector {
	__int8 m128i_i8[32];
	__int16 m128i_i16[16];
	int32_t m128i_i32[8];
	int64_t m128i_i64[4];
	uint8_t m128i_u8[32];
	uint16_t m128i_u16[16];
	uint32_t m128i_u32[8];
	uint64_t m128i_u64[4];
} DES_Vector;
#define VECTOR_ELEMENTS m128i_i32

#define CPU_DES_MAIN_LOOP CPU_DES_MainLoop_AVX2

#include "CPU10.h"
