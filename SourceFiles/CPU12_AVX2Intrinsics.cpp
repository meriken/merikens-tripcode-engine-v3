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



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"

#include <nmmintrin.h>
#include <smmintrin.h>



///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES, CONSTANTS, AND MACROS FOR WIN32 AND CUDA                //
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// SHA-1 HASH GENERATION WITH CPU                                            //
///////////////////////////////////////////////////////////////////////////////

#define VECTOR_SIZE 32
#if defined (_MSC_VER)
#define VECTOR_ALIGNMENT __declspec(align(32))
#else
#define VECTOR_ALIGNMENT __attribute__ ((aligned (32))) 
#endif
typedef union VECTOR_ALIGNMENT sha1_vector {
	uint32_t m256i_u32[8];
#ifdef ARCH_X86
	__m256i m256i;
#endif
	int8_t m256i_i8[32];
	int16_t m256i_i16[16];
	int32_t m256i_i32[8];
	int64_t m256i_i64[4];
	uint8_t m256i_u8[32];
	uint16_t m256i_u16[16];
	uint64_t m256i_u64[4];
} sha1_vector;
#define VECTOR_ELEMENTS m256i_u32

#ifdef ARCH_X86

inline sha1_vector vnot_func(const sha1_vector &a) 
{
    sha1_vector ret;

    ret.m256i = _mm256_andnot_si256(a.m256i, _mm256_set1_epi8(0xff));
    return ret;
}

inline sha1_vector vand_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m256i = _mm256_and_si256((a).m256i, (b).m256i);
    return ret;
}

inline sha1_vector vor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m256i = _mm256_or_si256((a).m256i, (b).m256i);
    return ret;
}

inline sha1_vector vxor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m256i = _mm256_xor_si256((a).m256i, (b).m256i);
    return ret;
}

inline sha1_vector vadd_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector ret;

    ret.m256i = _mm256_add_epi32((a).m256i, (b).m256i);
    return ret;
}

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
// #define ROTL(bits, val) _mm256_or_si256(_mm256_slli_epi32((val), (bits)), _mm256_srli_epi32((val), 32 - (bits)))
inline sha1_vector ROTL(unsigned int bits, const sha1_vector &val) 
{
	sha1_vector ret;

	ret.m256i = _mm256_or_si256(_mm256_slli_epi32((val).m256i, (bits)), _mm256_srli_epi32((val).m256i, 32 - (bits)));
	return ret;
}

#else

inline sha1_vector vnot_func(const sha1_vector &a) 
{
    sha1_vector dst;

    dst.m256i_u32[0] = ~(a).m256i_u32[0];
    dst.m256i_u32[1] = ~(a).m256i_u32[1];
    dst.m256i_u32[2] = ~(a).m256i_u32[2];
    dst.m256i_u32[3] = ~(a).m256i_u32[3];
    return dst;
}

inline sha1_vector vand_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m256i_u32[0] = (a).m256i_u32[0] & (b).m256i_u32[0];
    dst.m256i_u32[1] = (a).m256i_u32[1] & (b).m256i_u32[1];
    dst.m256i_u32[2] = (a).m256i_u32[2] & (b).m256i_u32[2];
    dst.m256i_u32[3] = (a).m256i_u32[3] & (b).m256i_u32[3];
    return dst;
}

inline sha1_vector vor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m256i_u32[0] = (a).m256i_u32[0] | (b).m256i_u32[0];
    dst.m256i_u32[1] = (a).m256i_u32[1] | (b).m256i_u32[1];
    dst.m256i_u32[2] = (a).m256i_u32[2] | (b).m256i_u32[2];
    dst.m256i_u32[3] = (a).m256i_u32[3] | (b).m256i_u32[3];
    return dst;
}

inline sha1_vector vxor_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m256i_u32[0] = (a).m256i_u32[0] ^ (b).m256i_u32[0];
    dst.m256i_u32[1] = (a).m256i_u32[1] ^ (b).m256i_u32[1];
    dst.m256i_u32[2] = (a).m256i_u32[2] ^ (b).m256i_u32[2];
    dst.m256i_u32[3] = (a).m256i_u32[3] ^ (b).m256i_u32[3];
    return dst;
}

inline sha1_vector vadd_func(const sha1_vector &a, const sha1_vector &b) 
{
    sha1_vector dst;

    dst.m256i_u32[0] = (a).m256i_u32[0] + (b).m256i_u32[0];
    dst.m256i_u32[1] = (a).m256i_u32[1] + (b).m256i_u32[1];
    dst.m256i_u32[2] = (a).m256i_u32[2] + (b).m256i_u32[2];
    dst.m256i_u32[3] = (a).m256i_u32[3] + (b).m256i_u32[3];
    return dst;
}

// Circular left rotation of 32-bit value 'val' left by 'bits' bits
// (assumes that 'bits' is always within range from 0 to 32)
// #define ROTL( bits, val ) \
//        ( ( ( val ) << ( bits ) ) | ( ( val ) >> ( 32 - ( bits ) ) ) )
// #define ROTL(bits, val) _mm256_or_si256(_mm256_slli_epi32((val), (bits)), _mm256_srli_epi32((val), 32 - (bits)))
inline sha1_vector ROTL(unsigned int bits, const sha1_vector &val) 
{
	sha1_vector dst;

    dst.m256i_u32[0] = (val.m256i_u32[0] << bits) + (val.m256i_u32[0] >> (32 - bits));
    dst.m256i_u32[1] = (val.m256i_u32[1] << bits) + (val.m256i_u32[1] >> (32 - bits));
    dst.m256i_u32[2] = (val.m256i_u32[2] << bits) + (val.m256i_u32[2] >> (32 - bits));
    dst.m256i_u32[3] = (val.m256i_u32[3] << bits) + (val.m256i_u32[3] >> (32 - bits));
	return dst;
}

#endif

// Initial hash values (see p. 14 of FIPS 180-3)
static VECTOR_ALIGNMENT sha1_vector H0 = {0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301};
static VECTOR_ALIGNMENT sha1_vector H1 = {0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89};
static VECTOR_ALIGNMENT sha1_vector H2 = {0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe};
static VECTOR_ALIGNMENT sha1_vector H3 = {0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476};
static VECTOR_ALIGNMENT sha1_vector H4 = {0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0};

// Constants required for hash calculation (see p. 11 of FIPS 180-3)
static VECTOR_ALIGNMENT sha1_vector K0 = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999};
static VECTOR_ALIGNMENT sha1_vector K1 = {0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1};
static VECTOR_ALIGNMENT sha1_vector K2 = {0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc};
static VECTOR_ALIGNMENT sha1_vector K3 = {0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6};

#define CPU12_SHA1_MAIN_LOOP SearchForSHA1Tripcodes_AVX2
#include "CPU12_Intrinsics.h"

