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



#define SWAP(a, b) asm("mov.u32 %2, %0; mov.u32 %0, %1; mov.u32 %1, %2;":"+r"(a),"+r"(b),"+r"(temp0));
#define CHAIN(a,b,c,d,e,f,g,h,i,j,k,l,m,n) a=b;b=c;c=d;d=e;e=f;f=g;g=h;h=i;i=j;j=k;k=l;l=m;m=n;
#define REVERSECHAIN(a,b,c,d,e,f,g,h,i,j,k,l,m,n) n=m;m=l;l=k;k=j;j=i;i=h;h=g;g=f;f=e;e=d;d=c;c=b;b=a;

#define DATASWAP \
	SWAP(DB00, DB32); SWAP(DB01, DB33);	SWAP(DB02, DB34); SWAP(DB03, DB35);	SWAP(DB04, DB36); SWAP(DB05, DB37);	SWAP(DB06, DB38); SWAP(DB07, DB39);	SWAP(DB08, DB40); SWAP(DB09, DB41); \
	SWAP(DB10, DB42); SWAP(DB11, DB43);	SWAP(DB12, DB44); SWAP(DB13, DB45);	SWAP(DB14, DB46); SWAP(DB15, DB47);	SWAP(DB16, DB48); SWAP(DB17, DB49);	SWAP(DB18, DB50); SWAP(DB19, DB51); \
	SWAP(DB20, DB52); SWAP(DB21, DB53);	SWAP(DB22, DB54); SWAP(DB23, DB55);	SWAP(DB24, DB56); SWAP(DB25, DB57);	SWAP(DB26, DB58); SWAP(DB27, DB59);	SWAP(DB28, DB60); SWAP(DB29, DB61); \
	SWAP(DB30, DB62); SWAP(DB31, DB63);

#define SWAP01 \
	SWAP(K12, K55); \
	SWAP(K46, K34); \
	SWAP(K05, K48); \
	SWAP(K20, K32); \
	SWAP(K35, K51); \
	SWAP(K06, K18); \
	SWAP(K03, K15); \
	SWAP(K23, K07); \
	SWAP(K40, K52); \
	SWAP(K14, K30); \
	SWAP(K43, K02); \
	SWAP(K44, K28); \
	SWAP(K08, K49); \
	SWAP(K19, K31); \
	SWAP(K17, K29); \
	SWAP(K26, K38); \
	SWAP(K41, K53); \
	SWAP(K21, K37); \
	SWAP(K09, K50); \
	SWAP(K33, K45); \
	SWAP(K13, K25); \
	SWAP(K04, K47); \
	SWAP(K27, K39); \
	SWAP(K54, K11); \
	SWAP(K24, K36); \
	SWAP(K22, K10); \
	SWAP(K16, K00); \
	SWAP(K42, K01); \

#define KEYSWAP12 \
	if (i) \
	{ \
		SWAP01; \
		temp0 = K19; temp1 = K31; \
		CHAIN(K19, K55, K05, K41, K46, K27, K32, K13, K18, K54, K04, K40, K45, K26); \
		CHAIN(K31, K12, K48, K53, K34, K39, K20, K25, K06, K11, K47, K52, K33, K38); \
		K26 = temp1; K38 = temp0; \
		temp0 = K10; temp1 = K22; \
		CHAIN(K10, K15, K49, K01, K35, K44, K21, K30, K07, K16, K50, K02, K36, K17); \
		CHAIN(K22, K03, K08, K42, K51, K28, K37, K14, K23, K00, K09, K43, K24, K29); \
		K17 = temp1; K29 = temp0; \
	}

#define KEYSWAP21 \
	if (i) \
	{ \
		temp0 = K26; temp1 = K38; \
		REVERSECHAIN(K19, K55, K05, K41, K46, K27, K32, K13, K18, K54, K04, K40, K45, K26); \
		REVERSECHAIN(K31, K12, K48, K53, K34, K39, K20, K25, K06, K11, K47, K52, K33, K38); \
		K19 = temp1; K31 = temp0; \
		temp0 = K17; temp1 = K29; \
		REVERSECHAIN(K10, K15, K49, K01, K35, K44, K21, K30, K07, K16, K50, K02, K36, K17); \
		REVERSECHAIN(K22, K03, K08, K42, K51, K28, K37, K14, K23, K00, K09, K43, K24, K29); \
		K10 = temp1; K22 = temp0; \
		SWAP01; \
	} \



#if defined(SALT) && __CUDA_ARCH__ >= 500
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_0.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_1.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_2.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_3.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_4.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_5.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_6.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_7.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_8.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_9.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_10.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_11.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_12.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_13.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_14.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_15.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_16.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_17.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_18.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_19.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_20.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_21.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_22.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_23.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_24.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_25.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_26.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_27.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_28.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_29.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_30.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_31.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_32.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_33.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_34.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_35.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_36.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_37.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_38.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_39.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_40.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_41.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_42.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_43.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_44.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_45.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_46.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_47.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_48.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_49.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_50.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_51.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_52.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_53.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_54.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_55.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_56.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_57.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_58.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_59.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_60.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_61.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_62.h"
#include "CUDA10_Registers_MultipleKernels\DES_Crypt_63.h"
#endif



#define KERNEL_FUNC2(salt) CUDA_DES_PerformSearch_##salt
#define KERNEL_FUNC(salt) KERNEL_FUNC2(salt)

#if !defined(SALT)
__global__ void CUDA_DES_PerformSearch(
#else
__global__ void KERNEL_FUNC(SALT)(
#endif
	unsigned char      *passCountArray,
	unsigned char      *tripcodeIndexArray,
	uint32_t       *tripcodeChunkArray,
	uint32_t        numTripcodeChunk,
	int32_t                 intSalt,
	unsigned char      *key0Array,
	unsigned char      *key7Array,
	DES_Vector         *keyVectorsFrom49To55,
	unsigned char      *keyAndRandomBytes,
	const int32_t           searchMode) {
	
	for (int32_t i = 0; i < COMPACT_MEDIUM_CHUNK_BITMAP_SIZE / CUDA_DES_NUM_THREADS_PER_BLOCK; ++i) \
	{ 
		int32_t index = i * CUDA_DES_NUM_THREADS_PER_BLOCK + threadIdx.x;
		cudaSharedCompactMediumChunkBitmap[index] = cudaCompactMediumChunkBitmap[index];
	}
	__syncthreads();

	unsigned char key = keyAndRandomBytes[1];
	DES_Vector K07 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K08 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K09 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K10 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K11 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K12 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K13 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	key = keyAndRandomBytes[2];
	DES_Vector K14 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K15 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K16 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K17 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K18 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K19 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K20 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	BOOL isSecondByte =    ( IS_FIRST_BYTE_SJIS_FULL(key0Array[0])                                                   && IS_FIRST_BYTE_SJIS_FULL(keyAndRandomBytes[2]))
		                || (!IS_FIRST_BYTE_SJIS_FULL(key0Array[0]) && !IS_FIRST_BYTE_SJIS_FULL(keyAndRandomBytes[1]) && IS_FIRST_BYTE_SJIS_FULL(keyAndRandomBytes[2]));
	CUDA_SET_KEY_CHAR(key, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[3] + (((threadIdx.x >> 6) &  7) | (((blockIdx.x  >> 12) & 7) << 3)));
	DES_Vector K21 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K22 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K23 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K24 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K25 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K26 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K27 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	CUDA_SET_KEY_CHAR(key, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[4] + ( (blockIdx.x  >> 6) & 63));
	DES_Vector K28 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K29 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K30 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K31 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K32 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K33 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K34 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	CUDA_SET_KEY_CHAR(key, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[5] + (  blockIdx.x        & 63));
	DES_Vector K35 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K36 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K37 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K38 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K39 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K40 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K41 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	CUDA_SET_KEY_CHAR(key, isSecondByte, cudaKeyCharTable_FirstByte, keyAndRandomBytes[6] + (  threadIdx.x       & 63));
	DES_Vector K42 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
	DES_Vector K43 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
	DES_Vector K44 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
	DES_Vector K45 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
	DES_Vector K46 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
	DES_Vector K47 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
	DES_Vector K48 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

	DES_Vector K49 =  keyVectorsFrom49To55[0 + (isSecondByte ? 7 : 0)];
	DES_Vector K50 =  keyVectorsFrom49To55[1 + (isSecondByte ? 7 : 0)];
	DES_Vector K51 =  keyVectorsFrom49To55[2 + (isSecondByte ? 7 : 0)];
	DES_Vector K52 =  keyVectorsFrom49To55[3 + (isSecondByte ? 7 : 0)];
	DES_Vector K53 =  keyVectorsFrom49To55[4 + (isSecondByte ? 7 : 0)];
	DES_Vector K54 =  keyVectorsFrom49To55[5 + (isSecondByte ? 7 : 0)];
	DES_Vector K55 =  keyVectorsFrom49To55[6 + (isSecondByte ? 7 : 0)];
	
	DES_Vector temp0, temp1;

	int32_t tripcodeIndex;
	int32_t passCount;
	for (passCount = 0; passCount < CUDA_DES_MAX_PASS_COUNT; ++passCount) {
		key = key0Array[passCount];
		DES_Vector K00 = ((key & (0x1U << 0)) ? 0xffffffffU : 0x0);
		DES_Vector K01 = ((key & (0x1U << 1)) ? 0xffffffffU : 0x0);
		DES_Vector K02 = ((key & (0x1U << 2)) ? 0xffffffffU : 0x0);
		DES_Vector K03 = ((key & (0x1U << 3)) ? 0xffffffffU : 0x0);
		DES_Vector K04 = ((key & (0x1U << 4)) ? 0xffffffffU : 0x0);
		DES_Vector K05 = ((key & (0x1U << 5)) ? 0xffffffffU : 0x0);
		DES_Vector K06 = ((key & (0x1U << 6)) ? 0xffffffffU : 0x0);

		DES_Vector DB00 = 0, DB01 = 0, DB02 = 0, DB03 = 0, DB04 = 0, DB05 = 0, DB06 = 0, DB07 = 0, DB08 = 0, DB09 = 0;
		DES_Vector DB10 = 0, DB11 = 0, DB12 = 0, DB13 = 0, DB14 = 0, DB15 = 0, DB16 = 0, DB17 = 0, DB18 = 0, DB19 = 0;
		DES_Vector DB20 = 0, DB21 = 0, DB22 = 0, DB23 = 0, DB24 = 0, DB25 = 0, DB26 = 0, DB27 = 0, DB28 = 0, DB29 = 0;
		DES_Vector DB30 = 0, DB31 = 0, DB32 = 0, DB33 = 0, DB34 = 0, DB35 = 0, DB36 = 0, DB37 = 0, DB38 = 0, DB39 = 0;
		DES_Vector DB40 = 0, DB41 = 0, DB42 = 0, DB43 = 0, DB44 = 0, DB45 = 0, DB46 = 0, DB47 = 0, DB48 = 0, DB49 = 0;
		DES_Vector DB50 = 0, DB51 = 0, DB52 = 0, DB53 = 0, DB54 = 0, DB55 = 0, DB56 = 0, DB57 = 0, DB58 = 0, DB59 = 0;
		DES_Vector DB60 = 0, DB61 = 0, DB62 = 0, DB63 = 0; 

		for (int32_t ii = 0; ii < 25; ++ii) {
			DATASWAP;
			for (int32_t i = 0; i < 2; ++i) {

#if !defined(SALT) || __CUDA_ARCH__ < 500
#if !defined(SALT)
#define SALT intSalt
#endif

				s1(((   1 & SALT) ? DB15 : DB31) ^ K12, ((   2 & SALT) ? DB16 : DB00) ^ K46, ((   4 & SALT) ? DB17 : DB01) ^ K33, ((   8 & SALT) ? DB18 : DB02) ^ K52, ((  16 & SALT) ? DB19 : DB03) ^ K48, ((  32 & SALT) ? DB20 : DB04) ^ K20, &DB40, &DB48, &DB54, &DB62);
				s2(((  64 & SALT) ? DB19 : DB03) ^ K34, (( 128 & SALT) ? DB20 : DB04) ^ K55, (( 256 & SALT) ? DB21 : DB05) ^ K05, (( 512 & SALT) ? DB22 : DB06) ^ K13, ((1024 & SALT) ? DB23 : DB07) ^ K18, ((2048 & SALT) ? DB24 : DB08) ^ K40, &DB44, &DB59, &DB33, &DB49);
				s3((                DB07       ) ^ K04, (                DB08       ) ^ K32, (                DB09       ) ^ K26, (                DB10       ) ^ K27, (                DB11       ) ^ K38, (                DB12       ) ^ K54, &DB55, &DB47, &DB61, &DB37);
				s4((                DB11       ) ^ K53, (                DB12       ) ^ K06, (                DB13       ) ^ K31, (                DB14       ) ^ K25, (                DB15       ) ^ K19, (                DB16       ) ^ K41, &DB57, &DB51, &DB41, &DB32);
				s5(((   1 & SALT) ? DB31 : DB15) ^ K15, ((   2 & SALT) ? DB00 : DB16) ^ K24, ((   4 & SALT) ? DB01 : DB17) ^ K28, ((   8 & SALT) ? DB02 : DB18) ^ K43, ((  16 & SALT) ? DB03 : DB19) ^ K30, ((  32 & SALT) ? DB04 : DB20) ^ K03, &DB39, &DB45, &DB56, &DB34);
				s6(((  64 & SALT) ? DB03 : DB19) ^ K35, (( 128 & SALT) ? DB04 : DB20) ^ K22, (( 256 & SALT) ? DB05 : DB21) ^ K02, (( 512 & SALT) ? DB06 : DB22) ^ K44, ((1024 & SALT) ? DB07 : DB23) ^ K14, ((2048 & SALT) ? DB08 : DB24) ^ K23, &DB35, &DB60, &DB42, &DB50);
				s7((                DB23       ) ^ K51, (                DB24       ) ^ K16, (                DB25       ) ^ K29, (                DB26       ) ^ K49, (                DB27       ) ^ K07, (                DB28       ) ^ K17, &DB63, &DB43, &DB53, &DB38);
				s8((                DB27       ) ^ K37, (                DB28       ) ^ K08, (                DB29       ) ^ K09, (                DB30       ) ^ K50, (                DB31       ) ^ K42, (                DB00       ) ^ K21, &DB36, &DB58, &DB46, &DB52);

				KEYSWAP12;
		
				s1(((   1 & SALT) ? DB47 : DB63) ^ K05, ((   2 & SALT) ? DB48 : DB32) ^ K39, ((   4 & SALT) ? DB49 : DB33) ^ K26, ((   8 & SALT) ? DB50 : DB34) ^ K45, ((  16 & SALT) ? DB51 : DB35) ^ K41, ((  32 & SALT) ? DB52 : DB36) ^ K13, &DB08, &DB16, &DB22, &DB30);
				s2(((  64 & SALT) ? DB51 : DB35) ^ K27, (( 128 & SALT) ? DB52 : DB36) ^ K48, (( 256 & SALT) ? DB53 : DB37) ^ K53, (( 512 & SALT) ? DB54 : DB38) ^ K06, ((1024 & SALT) ? DB55 : DB39) ^ K11, ((2048 & SALT) ? DB56 : DB40) ^ K33, &DB12, &DB27, &DB01, &DB17);
				s3((                DB39       ) ^ K52, (                DB40       ) ^ K25, (                DB41       ) ^ K19, (                DB42       ) ^ K20, (                DB43       ) ^ K31, (                DB44       ) ^ K47, &DB23, &DB15, &DB29, &DB05);
				s4((                DB43       ) ^ K46, (                DB44       ) ^ K54, (                DB45       ) ^ K55, (                DB46       ) ^ K18, (                DB47       ) ^ K12, (                DB48       ) ^ K34, &DB25, &DB19, &DB09, &DB00);
				s5(((   1 & SALT) ? DB63 : DB47) ^ K08, ((   2 & SALT) ? DB32 : DB48) ^ K17, ((   4 & SALT) ? DB33 : DB49) ^ K21, ((   8 & SALT) ? DB34 : DB50) ^ K36, ((  16 & SALT) ? DB35 : DB51) ^ K23, ((  32 & SALT) ? DB36 : DB52) ^ K49, &DB07, &DB13, &DB24, &DB02);
				s6(((  64 & SALT) ? DB35 : DB51) ^ K28, (( 128 & SALT) ? DB36 : DB52) ^ K15, (( 256 & SALT) ? DB37 : DB53) ^ K24, (( 512 & SALT) ? DB38 : DB54) ^ K37, ((1024 & SALT) ? DB39 : DB55) ^ K07, ((2048 & SALT) ? DB40 : DB56) ^ K16, &DB03, &DB28, &DB10, &DB18);
				s7((                DB55       ) ^ K44, (                DB56       ) ^ K09, (                DB57       ) ^ K22, (                DB58       ) ^ K42, (                DB59       ) ^ K00, (                DB60       ) ^ K10, &DB31, &DB11, &DB21, &DB06);
				s8((                DB59       ) ^ K30, (                DB60       ) ^ K01, (                DB61       ) ^ K02, (                DB62       ) ^ K43, (                DB63       ) ^ K35, (                DB32       ) ^ K14, &DB04, &DB26, &DB14, &DB20);

				s1(((   1 & SALT) ? DB15 : DB31) ^ K46, ((   2 & SALT) ? DB16 : DB00) ^ K25, ((   4 & SALT) ? DB17 : DB01) ^ K12, ((   8 & SALT) ? DB18 : DB02) ^ K31, ((  16 & SALT) ? DB19 : DB03) ^ K27, ((  32 & SALT) ? DB20 : DB04) ^ K54, &DB40, &DB48, &DB54, &DB62);
				s2(((  64 & SALT) ? DB19 : DB03) ^ K13, (( 128 & SALT) ? DB20 : DB04) ^ K34, (( 256 & SALT) ? DB21 : DB05) ^ K39, (( 512 & SALT) ? DB22 : DB06) ^ K47, ((1024 & SALT) ? DB23 : DB07) ^ K52, ((2048 & SALT) ? DB24 : DB08) ^ K19, &DB44, &DB59, &DB33, &DB49);
				s3((                DB07       ) ^ K38, (                DB08       ) ^ K11, (                DB09       ) ^ K05, (                DB10       ) ^ K06, (                DB11       ) ^ K48, (                DB12       ) ^ K33, &DB55, &DB47, &DB61, &DB37);
				s4((                DB11       ) ^ K32, (                DB12       ) ^ K40, (                DB13       ) ^ K41, (                DB14       ) ^ K04, (                DB15       ) ^ K53, (                DB16       ) ^ K20, &DB57, &DB51, &DB41, &DB32);
				s5(((   1 & SALT) ? DB31 : DB15) ^ K51, ((   2 & SALT) ? DB00 : DB16) ^ K03, ((   4 & SALT) ? DB01 : DB17) ^ K07, ((   8 & SALT) ? DB02 : DB18) ^ K22, ((  16 & SALT) ? DB03 : DB19) ^ K09, ((  32 & SALT) ? DB04 : DB20) ^ K35, &DB39, &DB45, &DB56, &DB34);
				s6(((  64 & SALT) ? DB03 : DB19) ^ K14, (( 128 & SALT) ? DB04 : DB20) ^ K01, (( 256 & SALT) ? DB05 : DB21) ^ K10, (( 512 & SALT) ? DB06 : DB22) ^ K23, ((1024 & SALT) ? DB07 : DB23) ^ K50, ((2048 & SALT) ? DB08 : DB24) ^ K02, &DB35, &DB60, &DB42, &DB50);
				s7((                DB23       ) ^ K30, (                DB24       ) ^ K24, (                DB25       ) ^ K08, (                DB26       ) ^ K28, (                DB27       ) ^ K43, (                DB28       ) ^ K49, &DB63, &DB43, &DB53, &DB38);
				s8((                DB27       ) ^ K16, (                DB28       ) ^ K44, (                DB29       ) ^ K17, (                DB30       ) ^ K29, (                DB31       ) ^ K21, (                DB00       ) ^ K00, &DB36, &DB58, &DB46, &DB52);
		
				s1(((   1 & SALT) ? DB47 : DB63) ^ K32, ((   2 & SALT) ? DB48 : DB32) ^ K11, ((   4 & SALT) ? DB49 : DB33) ^ K53, ((   8 & SALT) ? DB50 : DB34) ^ K48, ((  16 & SALT) ? DB51 : DB35) ^ K13, ((  32 & SALT) ? DB52 : DB36) ^ K40, &DB08, &DB16, &DB22, &DB30);
				s2(((  64 & SALT) ? DB51 : DB35) ^ K54, (( 128 & SALT) ? DB52 : DB36) ^ K20, (( 256 & SALT) ? DB53 : DB37) ^ K25, (( 512 & SALT) ? DB54 : DB38) ^ K33, ((1024 & SALT) ? DB55 : DB39) ^ K38, ((2048 & SALT) ? DB56 : DB40) ^ K05, &DB12, &DB27, &DB01, &DB17);
				s3((                DB39       ) ^ K55, (                DB40       ) ^ K52, (                DB41       ) ^ K46, (                DB42       ) ^ K47, (                DB43       ) ^ K34, (                DB44       ) ^ K19, &DB23, &DB15, &DB29, &DB05);
				s4((                DB43       ) ^ K18, (                DB44       ) ^ K26, (                DB45       ) ^ K27, (                DB46       ) ^ K45, (                DB47       ) ^ K39, (                DB48       ) ^ K06, &DB25, &DB19, &DB09, &DB00);
				s5(((   1 & SALT) ? DB63 : DB47) ^ K37, ((   2 & SALT) ? DB32 : DB48) ^ K42, ((   4 & SALT) ? DB33 : DB49) ^ K50, ((   8 & SALT) ? DB34 : DB50) ^ K08, ((  16 & SALT) ? DB35 : DB51) ^ K24, ((  32 & SALT) ? DB36 : DB52) ^ K21, &DB07, &DB13, &DB24, &DB02);
				s6(((  64 & SALT) ? DB35 : DB51) ^ K00, (( 128 & SALT) ? DB36 : DB52) ^ K44, (( 256 & SALT) ? DB37 : DB53) ^ K49, (( 512 & SALT) ? DB38 : DB54) ^ K09, ((1024 & SALT) ? DB39 : DB55) ^ K36, ((2048 & SALT) ? DB40 : DB56) ^ K17, &DB03, &DB28, &DB10, &DB18);
				s7((                DB55       ) ^ K16, (                DB56       ) ^ K10, (                DB57       ) ^ K51, (                DB58       ) ^ K14, (                DB59       ) ^ K29, (                DB60       ) ^ K35, &DB31, &DB11, &DB21, &DB06);
				s8((                DB59       ) ^ K02, (                DB60       ) ^ K30, (                DB61       ) ^ K03, (                DB62       ) ^ K15, (                DB63       ) ^ K07, (                DB32       ) ^ K43, &DB04, &DB26, &DB14, &DB20);

				s1(((   1 & SALT) ? DB15 : DB31) ^ K18, ((   2 & SALT) ? DB16 : DB00) ^ K52, ((   4 & SALT) ? DB17 : DB01) ^ K39, ((   8 & SALT) ? DB18 : DB02) ^ K34, ((  16 & SALT) ? DB19 : DB03) ^ K54, ((  32 & SALT) ? DB20 : DB04) ^ K26, &DB40, &DB48, &DB54, &DB62);
				s2(((  64 & SALT) ? DB19 : DB03) ^ K40, (( 128 & SALT) ? DB20 : DB04) ^ K06, (( 256 & SALT) ? DB21 : DB05) ^ K11, (( 512 & SALT) ? DB22 : DB06) ^ K19, ((1024 & SALT) ? DB23 : DB07) ^ K55, ((2048 & SALT) ? DB24 : DB08) ^ K46, &DB44, &DB59, &DB33, &DB49);
				s3((                DB07       ) ^ K41, (                DB08       ) ^ K38, (                DB09       ) ^ K32, (                DB10       ) ^ K33, (                DB11       ) ^ K20, (                DB12       ) ^ K05, &DB55, &DB47, &DB61, &DB37);
				s4((                DB11       ) ^ K04, (                DB12       ) ^ K12, (                DB13       ) ^ K13, (                DB14       ) ^ K31, (                DB15       ) ^ K25, (                DB16       ) ^ K47, &DB57, &DB51, &DB41, &DB32);
				s5(((   1 & SALT) ? DB31 : DB15) ^ K23, ((   2 & SALT) ? DB00 : DB16) ^ K28, ((   4 & SALT) ? DB01 : DB17) ^ K36, ((   8 & SALT) ? DB02 : DB18) ^ K51, ((  16 & SALT) ? DB03 : DB19) ^ K10, ((  32 & SALT) ? DB04 : DB20) ^ K07, &DB39, &DB45, &DB56, &DB34);
				s6(((  64 & SALT) ? DB03 : DB19) ^ K43, (( 128 & SALT) ? DB04 : DB20) ^ K30, (( 256 & SALT) ? DB05 : DB21) ^ K35, (( 512 & SALT) ? DB06 : DB22) ^ K24, ((1024 & SALT) ? DB07 : DB23) ^ K22, ((2048 & SALT) ? DB08 : DB24) ^ K03, &DB35, &DB60, &DB42, &DB50);
				s7((                DB23       ) ^ K02, (                DB24       ) ^ K49, (                DB25       ) ^ K37, (                DB26       ) ^ K00, (                DB27       ) ^ K15, (                DB28       ) ^ K21, &DB63, &DB43, &DB53, &DB38);
				s8((                DB27       ) ^ K17, (                DB28       ) ^ K16, (                DB29       ) ^ K42, (                DB30       ) ^ K01, (                DB31       ) ^ K50, (                DB00       ) ^ K29, &DB36, &DB58, &DB46, &DB52);
		
				s1(((   1 & SALT) ? DB47 : DB63) ^ K04, ((   2 & SALT) ? DB48 : DB32) ^ K38, ((   4 & SALT) ? DB49 : DB33) ^ K25, ((   8 & SALT) ? DB50 : DB34) ^ K20, ((  16 & SALT) ? DB51 : DB35) ^ K40, ((  32 & SALT) ? DB52 : DB36) ^ K12, &DB08, &DB16, &DB22, &DB30);
				s2(((  64 & SALT) ? DB51 : DB35) ^ K26, (( 128 & SALT) ? DB52 : DB36) ^ K47, (( 256 & SALT) ? DB53 : DB37) ^ K52, (( 512 & SALT) ? DB54 : DB38) ^ K05, ((1024 & SALT) ? DB55 : DB39) ^ K41, ((2048 & SALT) ? DB56 : DB40) ^ K32, &DB12, &DB27, &DB01, &DB17);
				s3((                DB39       ) ^ K27, (                DB40       ) ^ K55, (                DB41       ) ^ K18, (                DB42       ) ^ K19, (                DB43       ) ^ K06, (                DB44       ) ^ K46, &DB23, &DB15, &DB29, &DB05);
				s4((                DB43       ) ^ K45, (                DB44       ) ^ K53, (                DB45       ) ^ K54, (                DB46       ) ^ K48, (                DB47       ) ^ K11, (                DB48       ) ^ K33, &DB25, &DB19, &DB09, &DB00);
				s5(((   1 & SALT) ? DB63 : DB47) ^ K09, ((   2 & SALT) ? DB32 : DB48) ^ K14, ((   4 & SALT) ? DB33 : DB49) ^ K22, ((   8 & SALT) ? DB34 : DB50) ^ K37, ((  16 & SALT) ? DB35 : DB51) ^ K49, ((  32 & SALT) ? DB36 : DB52) ^ K50, &DB07, &DB13, &DB24, &DB02);
				s6(((  64 & SALT) ? DB35 : DB51) ^ K29, (( 128 & SALT) ? DB36 : DB52) ^ K16, (( 256 & SALT) ? DB37 : DB53) ^ K21, (( 512 & SALT) ? DB38 : DB54) ^ K10, ((1024 & SALT) ? DB39 : DB55) ^ K08, ((2048 & SALT) ? DB40 : DB56) ^ K42, &DB03, &DB28, &DB10, &DB18);
				s7((                DB55       ) ^ K17, (                DB56       ) ^ K35, (                DB57       ) ^ K23, (                DB58       ) ^ K43, (                DB59       ) ^ K01, (                DB60       ) ^ K07, &DB31, &DB11, &DB21, &DB06);
				s8((                DB59       ) ^ K03, (                DB60       ) ^ K02, (                DB61       ) ^ K28, (                DB62       ) ^ K44, (                DB63       ) ^ K36, (                DB32       ) ^ K15, &DB04, &DB26, &DB14, &DB20);
		
				s1(((   1 & SALT) ? DB15 : DB31) ^ K45, ((   2 & SALT) ? DB16 : DB00) ^ K55, ((   4 & SALT) ? DB17 : DB01) ^ K11, ((   8 & SALT) ? DB18 : DB02) ^ K06, ((  16 & SALT) ? DB19 : DB03) ^ K26, ((  32 & SALT) ? DB20 : DB04) ^ K53, &DB40, &DB48, &DB54, &DB62);
				s2(((  64 & SALT) ? DB19 : DB03) ^ K12, (( 128 & SALT) ? DB20 : DB04) ^ K33, (( 256 & SALT) ? DB21 : DB05) ^ K38, (( 512 & SALT) ? DB22 : DB06) ^ K46, ((1024 & SALT) ? DB23 : DB07) ^ K27, ((2048 & SALT) ? DB24 : DB08) ^ K18, &DB44, &DB59, &DB33, &DB49);
				s3((                DB07       ) ^ K13, (                DB08       ) ^ K41, (                DB09       ) ^ K04, (                DB10       ) ^ K05, (                DB11       ) ^ K47, (                DB12       ) ^ K32, &DB55, &DB47, &DB61, &DB37);
				s4((                DB11       ) ^ K31, (                DB12       ) ^ K39, (                DB13       ) ^ K40, (                DB14       ) ^ K34, (                DB15       ) ^ K52, (                DB16       ) ^ K19, &DB57, &DB51, &DB41, &DB32);
				s5(((   1 & SALT) ? DB31 : DB15) ^ K24, ((   2 & SALT) ? DB00 : DB16) ^ K00, ((   4 & SALT) ? DB01 : DB17) ^ K08, ((   8 & SALT) ? DB02 : DB18) ^ K23, ((  16 & SALT) ? DB03 : DB19) ^ K35, ((  32 & SALT) ? DB04 : DB20) ^ K36, &DB39, &DB45, &DB56, &DB34);
				s6(((  64 & SALT) ? DB03 : DB19) ^ K15, (( 128 & SALT) ? DB04 : DB20) ^ K02, (( 256 & SALT) ? DB05 : DB21) ^ K07, (( 512 & SALT) ? DB06 : DB22) ^ K49, ((1024 & SALT) ? DB07 : DB23) ^ K51, ((2048 & SALT) ? DB08 : DB24) ^ K28, &DB35, &DB60, &DB42, &DB50);
				s7((                DB23       ) ^ K03, (                DB24       ) ^ K21, (                DB25       ) ^ K09, (                DB26       ) ^ K29, (                DB27       ) ^ K44, (                DB28       ) ^ K50, &DB63, &DB43, &DB53, &DB38);
				s8((                DB27       ) ^ K42, (                DB28       ) ^ K17, (                DB29       ) ^ K14, (                DB30       ) ^ K30, (                DB31       ) ^ K22, (                DB00       ) ^ K01, &DB36, &DB58, &DB46, &DB52);

				KEYSWAP21;
		
				s1(((   1 & SALT) ? DB47 : DB63) ^ K31, ((   2 & SALT) ? DB48 : DB32) ^ K41, ((   4 & SALT) ? DB49 : DB33) ^ K52, ((   8 & SALT) ? DB50 : DB34) ^ K47, ((  16 & SALT) ? DB51 : DB35) ^ K12, ((  32 & SALT) ? DB52 : DB36) ^ K39, &DB08, &DB16, &DB22, &DB30);
				s2(((  64 & SALT) ? DB51 : DB35) ^ K53, (( 128 & SALT) ? DB52 : DB36) ^ K19, (( 256 & SALT) ? DB53 : DB37) ^ K55, (( 512 & SALT) ? DB54 : DB38) ^ K32, ((1024 & SALT) ? DB55 : DB39) ^ K13, ((2048 & SALT) ? DB56 : DB40) ^ K04, &DB12, &DB27, &DB01, &DB17);
				s3((                DB39       ) ^ K54, (                DB40       ) ^ K27, (                DB41       ) ^ K45, (                DB42       ) ^ K46, (                DB43       ) ^ K33, (                DB44       ) ^ K18, &DB23, &DB15, &DB29, &DB05);
				s4((                DB43       ) ^ K48, (                DB44       ) ^ K25, (                DB45       ) ^ K26, (                DB46       ) ^ K20, (                DB47       ) ^ K38, (                DB48       ) ^ K05, &DB25, &DB19, &DB09, &DB00);
				s5(((   1 & SALT) ? DB63 : DB47) ^ K10, ((   2 & SALT) ? DB32 : DB48) ^ K43, ((   4 & SALT) ? DB33 : DB49) ^ K51, ((   8 & SALT) ? DB34 : DB50) ^ K09, ((  16 & SALT) ? DB35 : DB51) ^ K21, ((  32 & SALT) ? DB36 : DB52) ^ K22, &DB07, &DB13, &DB24, &DB02);
				s6(((  64 & SALT) ? DB35 : DB51) ^ K01, (( 128 & SALT) ? DB36 : DB52) ^ K17, (( 256 & SALT) ? DB37 : DB53) ^ K50, (( 512 & SALT) ? DB38 : DB54) ^ K35, ((1024 & SALT) ? DB39 : DB55) ^ K37, ((2048 & SALT) ? DB40 : DB56) ^ K14, &DB03, &DB28, &DB10, &DB18);
				s7((                DB55       ) ^ K42, (                DB56       ) ^ K07, (                DB57       ) ^ K24, (                DB58       ) ^ K15, (                DB59       ) ^ K30, (                DB60       ) ^ K36, &DB31, &DB11, &DB21, &DB06);
				s8((                DB59       ) ^ K28, (                DB60       ) ^ K03, (                DB61       ) ^ K00, (                DB62       ) ^ K16, (                DB63       ) ^ K08, (                DB32       ) ^ K44, &DB04, &DB26, &DB14, &DB20);
		
				SWAP01;
#else
				CUDA_DES_CRYPT_EIGHT_ROUNDS(SALT);
#endif
			}
		}

		if (numTripcodeChunk == 1 && searchMode == SEARCH_MODE_FORWARD_MATCHING) {
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
				uint32_t tripcodeChunk = tripcodeChunkArray[0];
				if (GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB63, DB31, DB38, DB06, DB46, DB14, 0) != ((tripcodeChunk >> (6 * 4)) & 0x3f))
					continue;
				if (GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB54, DB22, DB62, DB30, DB37, DB05, 0) != ((tripcodeChunk >> (6 * 3)) & 0x3f))
					continue;
				if (GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB45, DB13, DB53, DB21, DB61, DB29, 0) != ((tripcodeChunk >> (6 * 2)) & 0x3f))
					continue;
				if (GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB36, DB04, DB44, DB12, DB52, DB20, 0) != ((tripcodeChunk >> (6 * 1)) & 0x3f))
					continue;
				if (GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB60, DB28, DB35, DB03, DB43, DB11, 0) != ((tripcodeChunk >> (6 * 0)) & 0x3f))
					continue;
				goto quit_loops;
			}
		} else if (searchMode == SEARCH_MODE_FORWARD_MATCHING) {
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
				uint32_t tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB63, DB31, DB38, DB06, DB46, DB14, 4)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB54, DB22, DB62, DB30, DB37, DB05, 3)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB45, DB13, DB53, DB21, DB61, DB29, 2)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB36, DB04, DB44, DB12, DB52, DB20, 1)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB60, DB28, DB35, DB03, DB43, DB11, 0);
				if (cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7)))
					continue;
				if (cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					continue;
				BINARY_SEARCH;
			}
		} else if (searchMode == SEARCH_MODE_BACKWARD_MATCHING) {
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
				uint32_t tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB51, DB19, DB59, DB27, DB34, DB02, 4)
							                 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB42, DB10, DB50, DB18, DB58, DB26, 3)
									         | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB33, DB01, DB41, DB09, DB49, DB17, 2)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB57, DB25, DB32, DB00, DB40, DB08, 1)
											 | GET_TRIPCODE_CHAR_INDEX_LAST(tripcodeIndex, DB48, DB16, DB56, DB24);
				if ((cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))))
					continue;
				if (cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					continue;
				BINARY_SEARCH;
			}
		} else if (searchMode == SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING) {
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
				uint32_t tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB63, DB31, DB38, DB06, DB46, DB14, 4)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB54, DB22, DB62, DB30, DB37, DB05, 3)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB45, DB13, DB53, DB21, DB61, DB29, 2)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB36, DB04, DB44, DB12, DB52, DB20, 1)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB60, DB28, DB35, DB03, DB43, DB11, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7)))
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB51, DB19, DB59, DB27, DB34, DB02, 4)
							                 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB42, DB10, DB50, DB18, DB58, DB26, 3)
									         | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB33, DB01, DB41, DB09, DB49, DB17, 2)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB57, DB25, DB32, DB00, DB40, DB08, 1)
											 | GET_TRIPCODE_CHAR_INDEX_LAST(tripcodeIndex, DB48, DB16, DB56, DB24);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
			}
		} else {
			for (tripcodeIndex = 0; tripcodeIndex < CUDA_DES_BS_DEPTH; ++tripcodeIndex) {
				uint32_t tripcodeChunk =   GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB63, DB31, DB38, DB06, DB46, DB14, 4)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB54, DB22, DB62, DB30, DB37, DB05, 3)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB45, DB13, DB53, DB21, DB61, DB29, 2)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB36, DB04, DB44, DB12, DB52, DB20, 1)
											 | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB60, DB28, DB35, DB03, DB43, DB11, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7)))
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB51, DB19, DB59, DB27, DB34, DB02, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB42, DB10, DB50, DB18, DB58, DB26, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB33, DB01, DB41, DB09, DB49, DB17, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX(tripcodeIndex, DB57, DB25, DB32, DB00, DB40, DB08, 0);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
				tripcodeChunk = ((tripcodeChunk << 6) & 0x3fffffff) | GET_TRIPCODE_CHAR_INDEX_LAST(tripcodeIndex, DB48, DB16, DB56, DB24);
				if (   !(cudaSharedCompactMediumChunkBitmap[tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6 + 3)] & (1 << ((tripcodeChunk >> ((5 - MEDIUM_CHUNK_BITMAP_LEN_STRING) * 6)) & 7))) 
				    && !cudaChunkBitmap[tripcodeChunk >> ((5 - CHUNK_BITMAP_LEN_STRING) * 6)])
					BINARY_SEARCH;
			}
		}
	}
quit_loops:
	tripcodeIndexArray[blockIdx.x * blockDim.x + threadIdx.x] = tripcodeIndex;
	passCountArray    [blockIdx.x * blockDim.x + threadIdx.x] = passCount;
}

#undef SALT
#undef KERNEL_FUNC
#undef KERNEL_FUNC2
