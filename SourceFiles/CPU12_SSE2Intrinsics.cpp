// Meriken's Tripcode Engine 1.0
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

// This file is not included in the build. I kept this file FYI.
// --Meriken



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES, CONSTANTS, AND MACROS FOR WIN32 AND CUDA                //
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// SHA-1 HASH GENERATION WITH CPU                                            //
///////////////////////////////////////////////////////////////////////////////

#define VECTOR_SIZE 16
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(16))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (16))) 
#endif
typedef union VECTOR_ALIGNMENT sha1_vector {
	uint32_t m128i_u32[4];
#ifdef ARCH_X86
	__m128i m128i;
#endif
	int8_t m128i_i8[16];
	int16_t m128i_i16[8];
	int32_t m128i_i32[4];
	int64_t m128i_i64[2];
	uint8_t m128i_u8[16];
	uint16_t m128i_u16[8];
	uint64_t m128i_u64[2];
} sha1_vector;
#define VECTOR_ELEMENTS m128i_u32

#ifdef ARCH_X86

inline sha1_vector vnot_func(const sha1_vector &a) 
{
    sha1_vector ret;

    ret.m128i = _mm_andnot_si128(a.m128i, _mm_set1_epi8(0xff));
    return ret;
}

inline sha1_vector vand_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m128i = _mm_and_si128((a).m128i, (b).m128i);
    return ret;
}

inline sha1_vector vor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m128i = _mm_or_si128((a).m128i, (b).m128i);
    return ret;
}

inline sha1_vector vxor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m128i = _mm_xor_si128((a).m128i, (b).m128i);
    return ret;
}

inline sha1_vector vadd_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m128i = _mm_add_epi32((a).m128i, (b).m128i);
    return ret;
}

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
// #define ROTL(bits, val) _mm_or_si128(_mm_slli_epi32((val), (bits)), _mm_srli_epi32((val), 32 - (bits)))
inline sha1_vector ROTL(unsigned int bits, const sha1_vector &val) 
{
	sha1_vector ret;

	ret.m128i = _mm_or_si128(_mm_slli_epi32((val).m128i, (bits)), _mm_srli_epi32((val).m128i, 32 - (bits)));
	return ret;
}

#else

inline sha1_vector vnot_func(const sha1_vector &a) 
{
    sha1_vector dst;

    dst.m128i_u32[0] = ~(a).m128i_u32[0];
    dst.m128i_u32[1] = ~(a).m128i_u32[1];
    dst.m128i_u32[2] = ~(a).m128i_u32[2];
    dst.m128i_u32[3] = ~(a).m128i_u32[3];
    return dst;
}

inline sha1_vector vand_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m128i_u32[0] = (a).m128i_u32[0] & (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] & (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] & (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] & (b).m128i_u32[3];
    return dst;
}

inline sha1_vector vor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m128i_u32[0] = (a).m128i_u32[0] | (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] | (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] | (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] | (b).m128i_u32[3];
    return dst;
}

inline sha1_vector vxor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m128i_u32[0] = (a).m128i_u32[0] ^ (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] ^ (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] ^ (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] ^ (b).m128i_u32[3];
    return dst;
}

inline sha1_vector vadd_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m128i_u32[0] = (a).m128i_u32[0] + (b).m128i_u32[0];
    dst.m128i_u32[1] = (a).m128i_u32[1] + (b).m128i_u32[1];
    dst.m128i_u32[2] = (a).m128i_u32[2] + (b).m128i_u32[2];
    dst.m128i_u32[3] = (a).m128i_u32[3] + (b).m128i_u32[3];
    return dst;
}

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
// #define ROTL(bits, val) _mm_or_si128(_mm_slli_epi32((val), (bits)), _mm_srli_epi32((val), 32 - (bits)))
inline sha1_vector ROTL(unsigned int bits, const sha1_vector &val) 
{
	sha1_vector dst;

    dst.m128i_u32[0] = (val.m128i_u32[0] << bits) + (val.m128i_u32[0] >> (32 - bits));
    dst.m128i_u32[1] = (val.m128i_u32[1] << bits) + (val.m128i_u32[1] >> (32 - bits));
    dst.m128i_u32[2] = (val.m128i_u32[2] << bits) + (val.m128i_u32[2] >> (32 - bits));
    dst.m128i_u32[3] = (val.m128i_u32[3] << bits) + (val.m128i_u32[3] >> (32 - bits));
	return dst;
}

#endif

// Initial hash values (see p. 14 of FIPS 180-3)
static VECTOR_ALIGNMENT sha1_vector H0 = {0x67452301, 0x67452301, 0x67452301, 0x67452301};
static VECTOR_ALIGNMENT sha1_vector H1 = {0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89};
static VECTOR_ALIGNMENT sha1_vector H2 = {0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe};
static VECTOR_ALIGNMENT sha1_vector H3 = {0x10325476, 0x10325476, 0x10325476, 0x10325476};
static VECTOR_ALIGNMENT sha1_vector H4 = {0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0};

// Constants required for hash calculation (see p. 11 of FIPS 180-3)
static VECTOR_ALIGNMENT sha1_vector K0 = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999};
static VECTOR_ALIGNMENT sha1_vector K1 = {0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1};
static VECTOR_ALIGNMENT sha1_vector K2 = {0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc};
static VECTOR_ALIGNMENT sha1_vector K3 = {0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6};

#define CPU12_SHA1_MAIN_LOOP SearchForSHA1Tripcodes
#include "CPU12_Intrinsics.h"



///////////////////////////////////////////////////////////////////////////////
// CPU SEARCH THREAD FOR 12 CHARACTER TRIPCODES                              //
///////////////////////////////////////////////////////////////////////////////


#ifdef ENABLE_AVX
extern uint32_t SearchForSHA1Tripcodes_AVX();
extern uint32_t SearchForSHA1Tripcodes_AVX2();
#endif

void Thread_SearchForSHA1TripcodesOnCPU()
{
	while (!GetTerminationState()) {
		while (GetPauseState() && !GetTerminationState())
			sleep_for_milliseconds(PAUSE_INTERVAL);

		uint32_t numGeneratedTripcodes;
#ifdef ENABLE_AVX
		if (IsAVX2Supported()) {
			numGeneratedTripcodes = SearchForSHA1Tripcodes_AVX2();
		} else if (IsAVXSupported()) {
			numGeneratedTripcodes = SearchForSHA1Tripcodes_AVX();
		} else {
			numGeneratedTripcodes = SearchForSHA1Tripcodes();
		}
#else
		numGeneratedTripcodes = SearchForSHA1Tripcodes();
#endif

		AddToNumGeneratedTripcodesByCPU(numGeneratedTripcodes);
	}
}

