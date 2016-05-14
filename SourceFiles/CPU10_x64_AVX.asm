; Meriken's Tripcode Engine
; Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
;
; The initial versions of this software were based on:
; CUDA SHA-1 Tripper 0.2.1
; Copyright (c) 2009 Horo/.IBXjcg
; 
; The code that deals with DES decryption is partially adopted from:
; John the Ripper password cracker
; Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
; DeepLearningJohnDoe's fork of Meriken's Tripcode Engine
; Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
;
; The code that deals with SHA-1 hash generation is partially adopted from:
; sha_digest-2.2
; Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
; VecTripper 
; Copyright (C) 2011 tmkk <tmkk@smoug.net>
; 
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http:;www.gnu.org/licenses/>.

global DES_Crypt25_x64_AVX
global IsAVXSupported
global _myxgetbv
global TestASM



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define expanded_key_schedule_address (rcx + expanded_key_schedule_offset)
%define data_blocks_address           rbx
%define key_schedule_index_base_x2    rdx

%define iterations                    rsi
%define rounds_and_swapped            rdi

; typedef struct {
; 	unsigned char expansionFunction[96];
; 	DES_Vector    expandedKeySchedule[0x300];
; 	DES_Vector    dataBlocks[NUM_DATA_BLOCKS];
; 	DES_Vector    temp[1 + 12];
; 	DES_Vector    keys[DES_NUM_KEYS];
; 	void          (*crypt25)(void *);
; } DES_Context;

%define expansion_function_offset    0
%define expanded_key_schedule_offset 96
%define data_blocks_offset           12384
%define temp_offset                  13408

%define pnot                  [rcx + temp_offset + 0 * 16]
%define temp0                 [rcx + temp_offset + 1 * 16]
%define temp1                 [rcx + temp_offset + 2 * 16]
%define data_blocks(i)        [rcx + data_blocks_offset + (i) * 16]

; This is the original macro.
%macro prepare_args_for_sbox_x 6
	movzx   eax,  byte [rcx + %1]
	vmovdqa xmm0, [data_blocks_address + eax * 8]
	movzx   eax,  byte [rcx + %2]
	vmovdqa xmm1, [data_blocks_address + eax * 8]
	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]

	movzx   eax,  byte [rcx + %3]
	vmovdqa xmm2, [data_blocks_address + eax * 8]
	movzx   eax,  byte [rcx + %4]
	vmovdqa xmm3, [data_blocks_address + eax * 8]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]

	movzx   eax,  byte [rcx + %5]
	vmovdqa xmm4, [data_blocks_address + eax * 8]
	movzx   eax,  byte [rcx + %6]
	vmovdqa xmm5, [data_blocks_address + eax * 8]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

; "0xffffffff" will be rewritten in DES_SetSalt() based on context->expansionFunction[].
%macro prepare_args_for_sbox_x_with_rewrites 6
	vmovdqa xmm0, [data_blocks_address + 0xffffffff]
	vmovdqa xmm1, [data_blocks_address + 0xffffffff]
	vmovdqa xmm2, [data_blocks_address + 0xffffffff]
	vmovdqa xmm3, [data_blocks_address + 0xffffffff]
	vmovdqa xmm4, [data_blocks_address + 0xffffffff]
	vmovdqa xmm5, [data_blocks_address + 0xffffffff]

	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

%macro prepare_args_for_sbox_y 12
	vmovdqa xmm0, [data_blocks_address + %1 * 16]
	vmovdqa xmm1, [data_blocks_address + %3 * 16]
	vmovdqa xmm2, [data_blocks_address + %5 * 16]
	vmovdqa xmm3, [data_blocks_address + %7 * 16]
	vmovdqa xmm4, [data_blocks_address + %9 * 16]
	vmovdqa xmm5, [data_blocks_address + %11 * 16]

	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %8 * 16]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %10 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %12 * 16]
%endmacro

%macro sbox1 4
	; From STF
	vpandn  xmm12, xmm4, xmm0
    vpxor   xmm9, xmm12, xmm3
    vpor    xmm15, xmm2, xmm5
    vpxor   xmm6, xmm0, xmm2
    vpand   xmm11, xmm15, xmm6
    vpxor   xmm7, xmm11, xmm3
    vpandn  xmm13, xmm9, xmm7
    vpandn  xmm10, xmm7, xmm4
    vpxor   xmm14, xmm4, xmm5
    vpxor   xmm8, xmm14, xmm2
    vpandn  xmm8, xmm8, xmm9
    vpor    xmm7, xmm11, xmm5
    vpxor   xmm7, xmm8, xmm7
    vpandn  xmm11, xmm13, xmm7
    vpor    xmm8, xmm0, xmm5
    vpor    xmm5, xmm7, xmm8
    vpor    xmm4, xmm9, xmm4
    vpandn  xmm8, xmm8, xmm3
    vpxor   xmm8, xmm10, xmm8
    vpandn  xmm6, xmm6, xmm14
    vpor    xmm3, xmm8, xmm6
    vpandn  xmm8, xmm12, xmm2
    vpxor   xmm6, xmm9, xmm5
    vpandn  xmm9, xmm8, xmm6
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm8, xmm9, xmm6
    vpand   xmm7, xmm15, xmm7
    vpxor   xmm6, xmm8, xmm7
    vpxor   xmm7, xmm10, xmm5
    vpandn  xmm12, xmm1, xmm7
    vpxor   xmm12, xmm12, xmm6
    vpxor   xmm12, xmm12, %3
    vmovdqa %3, xmm12
    vpxor   xmm7, xmm14, xmm9
    vpor    xmm7, xmm10, xmm7
    vpxor   xmm7, xmm15, xmm7
    vpxor   xmm0, xmm7, xmm0
    vpxor   xmm2, xmm6, xmm0
    vpor    xmm13, xmm13, xmm1
    vpxor   xmm13, xmm13, xmm2
    vpxor   xmm13, xmm13, %1
    vmovdqa %1, xmm13
    vpxor   xmm15, xmm15, xmm5
    vpor    xmm15, xmm15, xmm3
    vpxor   xmm15, xmm15, xmm0
    vpor    xmm7, xmm14, xmm2
    vpxor   xmm7, xmm15, xmm7
    vpor    xmm14, xmm11, xmm1
    vpxor   xmm14, xmm14, xmm7
    vpxor   xmm14, xmm14, %2
    vmovdqa %2, xmm14
    vpandn  xmm15, xmm15, xmm4
    vpand   xmm7, xmm11, xmm0
    vpxor   xmm15, xmm15, xmm7
    vpor    xmm15, xmm15, xmm1
    vpxor   xmm15, xmm15, xmm3
    vpxor   xmm15, xmm15, %4
    vmovdqa %4, xmm15
%endmacro

%macro sbox2 4
	; From STF
    vpxor   xmm13, xmm1, xmm4
    vpandn  xmm12, xmm5, xmm0
    vpandn  xmm12, xmm12, xmm4
    vpor    xmm10, xmm12, xmm1
    vpandn  xmm6, xmm5, xmm13
    vpand   xmm7, xmm13, xmm0
    vpxor   xmm7, xmm7, xmm4
    vpxor   xmm12, xmm12, xmm6
    vpandn  xmm15, xmm6, xmm7
    vpand   xmm14, xmm2, xmm5
    vpand   xmm6, xmm10, xmm12
    vpandn  xmm12, xmm14, xmm6
    vpand   xmm8, xmm2, xmm6
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm0, xmm0, xmm6
    vpxor   xmm6, xmm8, xmm0
    vpxor   xmm4, xmm8, xmm4
    vpxor   xmm5, xmm13, xmm5
    vpandn  xmm8, xmm14, xmm5
    vpxor   xmm0, xmm8, xmm6
    vpandn  xmm12, xmm12, xmm3
    vpxor   xmm12, xmm12, xmm0
    vpxor   xmm12, xmm12, %2
    vmovdqa %2, xmm12
    vpandn  xmm8, xmm8, xmm1
    vpxor   xmm12, xmm8, xmm7
    vpandn  xmm7, xmm12, xmm6
    vpxor   xmm11, xmm2, xmm5
    vpxor   xmm7, xmm11, xmm7
    vpandn  xmm13, xmm3, xmm10
    vpxor   xmm13, xmm13, xmm7
    vpxor   xmm13, xmm13, %1
    vmovdqa %1, xmm13
    vpandn  xmm7, xmm11, xmm1
    vpxor   xmm13, xmm10, xmm0
    vpxor   xmm7, xmm13, xmm7
    vpor    xmm7, xmm14, xmm7
    vpxor   xmm1, xmm11, xmm7
    vpandn  xmm7, xmm1, xmm2
    vpxor   xmm7, xmm15, xmm7
    vpor    xmm7, xmm12, xmm7
    vpxor   xmm2, xmm7, xmm4
    vpor    xmm14, xmm2, xmm3
    vpxor   xmm14, xmm14, xmm1
    vpxor   xmm14, xmm14, %3
    vmovdqa %3, xmm14
    vpandn  xmm2, xmm12, xmm2
    vpor    xmm7, xmm13, xmm5
    vpxor   xmm2, xmm2, xmm7
    vpor    xmm15, xmm15, xmm3
    vpxor   xmm15, xmm15, xmm2
    vpxor   xmm15, xmm15, %4
    vmovdqa %4, xmm15
%endmacro

%macro sbox3 4
    vmovdqa xmm11, xmm1

	; From STF
    vpandn  xmm7, xmm11, xmm0
    vpxor   xmm15, xmm2, xmm5
    vpor    xmm12, xmm15, xmm7
    vpxor   xmm7, xmm3, xmm5
    vpandn  xmm6, xmm0, xmm7
    vpand   xmm13, xmm15, xmm7
    vpxor   xmm1, xmm12, xmm6
    vpxor   xmm9, xmm11, xmm15
    vpandn  xmm7, xmm5, xmm9
    vpxor   xmm14, xmm12, xmm7
    vpxor   xmm7, xmm0, xmm3
    vpor    xmm6, xmm6, xmm7
    vpxor   xmm7, xmm14, xmm7
    vpor    xmm7, xmm2, xmm7
    vpandn  xmm10, xmm13, xmm7
    vpand   xmm12, xmm5, xmm1
    vpor    xmm12, xmm12, xmm3
    vpand   xmm12, xmm12, xmm0
    vpxor   xmm7, xmm9, xmm12
    vpandn  xmm12, xmm4, xmm1
    vpxor   xmm12, xmm12, xmm7
    vpxor   xmm12, xmm12, %4
    vmovdqa %4, xmm12
    vpandn  xmm13, xmm14, xmm1
    vpandn  xmm14, xmm6, xmm7
    vpand   xmm3, xmm3, xmm5
    vpandn  xmm5, xmm11, xmm3
    vpxor   xmm14, xmm14, xmm5
    vpor    xmm11, xmm11, xmm2
    vpandn  xmm8, xmm2, xmm14
    vpor    xmm2, xmm9, xmm3
    vpandn  xmm8, xmm8, xmm2
    vpxor   xmm8, xmm8, xmm0
    vpand   xmm2, xmm10, xmm4
    vpxor   xmm2, xmm8, xmm2
    vpxor   xmm2, xmm2, %2
    vmovdqa %2, xmm2
    vpxor   xmm8, xmm9, xmm6
    vpcmpeqd    xmm3, xmm3, xmm3
    vpxor   xmm3, xmm8, xmm3
    vpandn  xmm8, xmm11, xmm1
    vpxor   xmm2, xmm8, xmm3
    vpandn  xmm8, xmm13, xmm4
    vpxor   xmm8, xmm8, xmm2
    vpxor   xmm8, xmm8, %1
    vmovdqa %1, xmm8
    vpxor   xmm0, xmm10, xmm0
    vpor    xmm0, xmm3, xmm0
    vpxor   xmm0, xmm1, xmm0
    vpxor   xmm0, xmm7, xmm0
    vpxor   xmm15, xmm11, xmm0
    vpor    xmm4, xmm14, xmm4
    vpxor   xmm15, xmm15, xmm4
    vpxor   xmm15, xmm15, %3
    vmovdqa %3, xmm15
%endmacro

%macro sbox4 4
	; From STF
    vpxor   xmm8, xmm0, xmm2
    vpxor   xmm2, xmm2, xmm4
    vpor    xmm9, xmm1, xmm3
    vpxor   xmm9, xmm9, xmm4
    vpandn  xmm9, xmm9, xmm2
    vpandn  xmm10, xmm1, xmm2
    vpxor   xmm7, xmm10, xmm3
    vpor    xmm6, xmm8, xmm7
    vpandn  xmm11, xmm9, xmm6
    vpxor   xmm0, xmm11, xmm1
    vpxor   xmm14, xmm1, xmm3
    vpand   xmm7, xmm0, xmm7
    vpandn  xmm6, xmm7, xmm2
    vpxor   xmm1, xmm8, xmm0
    vpandn  xmm6, xmm6, xmm1
    vpxor   xmm2, xmm9, xmm6
    vpor    xmm4, xmm10, xmm4
    vpxor   xmm3, xmm1, xmm4
    vpandn  xmm4, xmm14, xmm3
    vpxor   xmm4, xmm11, xmm4
    vpandn  xmm12, xmm2, xmm5
    vpxor   xmm12, xmm12, xmm4
    vpxor   xmm12, xmm12, %1
    vmovdqa %1, xmm12
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm4, xmm4, xmm6
    vpandn  xmm13, xmm5, xmm2
    vpxor   xmm13, xmm13, xmm4
    vpxor   xmm13, xmm13, %2
    vmovdqa %2, xmm13
    vpxor   xmm4, xmm2, xmm4
    vpandn  xmm4, xmm14, xmm4
    vpor    xmm4, xmm7, xmm4
    vpxor   xmm4, xmm3, xmm4
    vpor    xmm14, xmm0, xmm5
    vpxor   xmm14, xmm14, xmm4
    vpxor   xmm14, xmm14, %3
    vmovdqa %3, xmm14
    vpand   xmm5, xmm0, xmm5
    vpxor   xmm5, xmm4, xmm5
    vpxor   xmm5, xmm5, %4
    vmovdqa %4, xmm5
%endmacro

%macro sbox5 4
	vmovdqa xmm10, xmm0

	; From STF
    vpor    xmm0, xmm10, xmm2
    vpandn  xmm7, xmm5, xmm0
    vpxor   xmm15, xmm10, xmm7
    vpandn  xmm8, xmm3, xmm7
    vpxor   xmm7, xmm15, xmm2
    vpor    xmm13, xmm7, xmm3
    vpxor   xmm2, xmm8, xmm2
    vpor    xmm11, xmm10, xmm7
    vpand   xmm7, xmm4, xmm2
    vpxor   xmm8, xmm11, xmm7
    vpxor   xmm8, xmm8, xmm3
    vpxor   xmm5, xmm8, xmm5
    vpor    xmm7, xmm15, xmm5
    vpand   xmm6, xmm7, xmm4
    vpandn  xmm14, xmm10, xmm7
    vpxor   xmm12, xmm15, xmm6
    vpand   xmm7, xmm11, xmm3
    vpxor   xmm12, xmm12, xmm7
    vpxor   xmm9, xmm14, xmm2
    vpxor   xmm4, xmm13, xmm4
    vpandn  xmm9, xmm9, xmm4
    vpcmpeqd    xmm7, xmm7, xmm7
    vpxor   xmm7, xmm9, xmm7
    vpandn  xmm7, xmm1, xmm7
    vpxor   xmm7, xmm8, xmm7
    vpxor   xmm7, xmm7, %3
    vmovdqa %3, xmm7
    vpandn  xmm8, xmm6, xmm2
    vpxor   xmm7, xmm14, xmm4
    vpor    xmm7, xmm12, xmm7
    vpandn  xmm8, xmm8, xmm7
    vpxor   xmm0, xmm8, xmm0
    vpxor   xmm14, xmm10, xmm0
    vpand   xmm0, xmm8, xmm5
    vpandn  xmm8, xmm8, xmm13
    vpxor   xmm4, xmm0, xmm4
    vpand   xmm0, xmm11, xmm2
    vpor    xmm0, xmm4, xmm0
    vpxor   xmm0, xmm6, xmm0
    vpand   xmm0, xmm0, xmm1
    vpxor   xmm0, xmm12, xmm0
    vpxor   xmm0, xmm0, %4
    vmovdqa %4, xmm0
    vpand   xmm3, xmm3, xmm4
    vpxor   xmm14, xmm14, xmm3
    vpor    xmm3, xmm8, xmm1
    vpxor   xmm3, xmm14, xmm3
    vpxor   xmm3, xmm3, %1
    vmovdqa %1, xmm3
    vpxor   xmm3, xmm13, xmm2
    vpandn  xmm0, xmm14, xmm3
    vpxor   xmm3, xmm15, xmm4
    vpxor   xmm3, xmm0, xmm3
    vpand   xmm1, xmm13, xmm1
    vpxor   xmm1, xmm1, xmm3
    vpxor   xmm1, xmm1, %2
    vmovdqa %2, xmm1
%endmacro

%macro sbox6 4
	; From STF
    vpxor   xmm7, xmm1, xmm4
    vpor    xmm9, xmm1, xmm5
    vpand   xmm10, xmm9, xmm0
    vpxor   xmm8, xmm10, xmm7
    vpxor   xmm7, xmm8, xmm5
    vpandn  xmm12, xmm7, xmm4
    vpand   xmm7, xmm0, xmm7
    vpxor   xmm6, xmm1, xmm7
    vpxor   xmm9, xmm5, xmm7
    vpxor   xmm13, xmm0, xmm2
    vpor    xmm7, xmm13, xmm6
    vpxor   xmm11, xmm8, xmm7
    vpxor   xmm15, xmm1, xmm7
    vpor    xmm1, xmm13, xmm1
    vpandn  xmm13, xmm15, xmm5
    vpxor   xmm13, xmm13, xmm2
    vpxor   xmm7, xmm13, xmm0
    vpand   xmm9, xmm9, xmm7
    vpand   xmm7, xmm11, xmm2
    vpor    xmm2, xmm12, xmm6
    vpandn  xmm6, xmm5, xmm7
    vpxor   xmm14, xmm6, xmm2
    vpor    xmm0, xmm11, xmm0
    vpand   xmm0, xmm2, xmm0
    vpand   xmm2, xmm14, xmm3
    vpxor   xmm2, xmm11, xmm2
    vpxor   xmm2, xmm2, %4
    vmovdqa %4, xmm2
    vpxor   xmm9, xmm9, xmm7
    vpandn  xmm7, xmm7, xmm4
    vpor    xmm7, xmm13, xmm7
    vpxor   xmm0, xmm13, xmm0
    vpandn  xmm6, xmm6, xmm0
    vpor    xmm2, xmm12, xmm3
    vpxor   xmm2, xmm2, xmm6
    vpxor   xmm2, xmm2, %3
    vmovdqa %3, xmm2
    vpor    xmm10, xmm10, xmm7
    vpxor   xmm2, xmm10, xmm1
    vpxor   xmm10, xmm14, xmm2
    vpxor   xmm8, xmm8, xmm0
    vpandn  xmm8, xmm8, xmm4
    vpxor   xmm15, xmm15, xmm1
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm4, xmm15, xmm6
    vpxor   xmm2, xmm8, xmm4
    vpandn  xmm2, xmm3, xmm2
    vpxor   xmm2, xmm10, xmm2
    vpxor   xmm2, xmm2, %2
    vmovdqa %2, xmm2
    vpxor   xmm1, xmm9, xmm4
    vpandn  xmm3, xmm3, xmm7
    vpxor   xmm3, xmm3, xmm1
    vpxor   xmm3, xmm3, %1
    vmovdqa %1, xmm3
%endmacro

%macro sbox7 4
	vmovdqa xmm12, xmm2
	
	; From STF
    vpxor   xmm10, xmm3, xmm4
    vpand   xmm9, xmm10, xmm3
    vpxor   xmm8, xmm10, xmm5
    vpxor   xmm7, xmm10, xmm12
    vpandn  xmm15, xmm7, xmm4
    vpandn  xmm10, xmm8, xmm7
    vpand   xmm7, xmm5, xmm7
    vpxor   xmm2, xmm9, xmm1
    vpand   xmm13, xmm7, xmm2
    vpand   xmm6, xmm9, xmm5
    vpxor   xmm11, xmm12, xmm6
    vpor    xmm6, xmm11, xmm2
    vpxor   xmm6, xmm8, xmm6
    vpandn  xmm14, xmm13, xmm0
    vpxor   xmm14, xmm14, xmm6
    vpxor   xmm14, xmm14, %4
    vmovdqa %4, xmm14
    vpxor   xmm14, xmm8, xmm7
    vpandn  xmm14, xmm14, xmm3
    vpandn  xmm14, xmm14, xmm2
    vpor    xmm2, xmm15, xmm2
    vpxor   xmm11, xmm11, xmm7
    vpxor   xmm13, xmm2, xmm11
    vpxor   xmm11, xmm11, xmm4
    vpxor   xmm14, xmm14, xmm11
    vpor    xmm7, xmm9, xmm6
    vpand   xmm9, xmm14, xmm12
    vpor    xmm2, xmm7, xmm9
    vpxor   xmm7, xmm2, xmm10
    vpandn  xmm2, xmm0, xmm7
    vpxor   xmm2, xmm2, xmm13
    vpxor   xmm2, xmm2, %1
    vmovdqa %1, xmm2
    vpor    xmm10, xmm14, xmm7
    vpand   xmm5, xmm10, xmm5
    vpand   xmm1, xmm1, xmm5
    vpxor   xmm13, xmm13, xmm7
    vpxor   xmm1, xmm13, xmm1
    vpor    xmm9, xmm9, xmm1
    vpxor   xmm9, xmm9, xmm5
    vpxor   xmm4, xmm13, xmm4
    vpor    xmm9, xmm9, xmm4
    vpand   xmm4, xmm9, xmm0
    vpxor   xmm4, xmm14, xmm4
    vpxor   xmm4, xmm4, %3
    vmovdqa %3, xmm4
    vpxor   xmm5, xmm9, xmm5
    vpor    xmm9, xmm15, xmm5
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm2, xmm7, xmm6
    vpxor   xmm2, xmm9, xmm2
    vpandn  xmm0, xmm0, xmm2
    vpxor   xmm0, xmm0, xmm1
    vpxor   xmm0, xmm0, %2
    vmovdqa %2, xmm0
%endmacro

%macro sbox8 4
	; From STF
    vpandn  xmm15, xmm1, xmm2
    vpandn  xmm14, xmm2, xmm4
    vpxor   xmm14, xmm14, xmm3
    vpand   xmm7, xmm14, xmm0
    vpandn  xmm13, xmm15, xmm7
    vpandn  xmm9, xmm14, xmm1
    vpor    xmm12, xmm9, xmm0
    vpandn  xmm8, xmm2, xmm1
    vpxor   xmm10, xmm4, xmm8
    vpand   xmm8, xmm12, xmm10
    vpor    xmm11, xmm7, xmm8
    vpxor   xmm7, xmm14, xmm8
    vpcmpeqd    xmm6, xmm6, xmm6
    vpxor   xmm7, xmm7, xmm6
    vpandn  xmm12, xmm12, xmm2
    vpxor   xmm7, xmm7, xmm12
    vpxor   xmm15, xmm15, xmm7
    vpor    xmm2, xmm13, xmm5
    vpxor   xmm2, xmm2, xmm15
    vpxor   xmm2, xmm2, %2
    vmovdqa %2, xmm2
    vpxor   xmm12, xmm15, xmm0
    vpand   xmm2, xmm4, xmm12
    vpxor   xmm14, xmm7, xmm1
    vpxor   xmm2, xmm14, xmm2
    vpxor   xmm7, xmm11, xmm2
    vpxor   xmm15, xmm9, xmm2
    vpor    xmm1, xmm1, xmm7
    vpxor   xmm1, xmm12, xmm1
    vpor    xmm12, xmm12, xmm3
    vpor    xmm3, xmm3, xmm14
    vpxor   xmm14, xmm15, xmm3
    vpxor   xmm14, xmm10, xmm14
    vpxor   xmm3, xmm14, xmm0
    vpand   xmm3, xmm3, xmm5
    vpxor   xmm3, xmm15, xmm3
    vpxor   xmm3, xmm3, %4
    vmovdqa %4, xmm3
    vpxor   xmm4, xmm4, xmm1
    vpand   xmm3, xmm11, xmm5
    vpxor   xmm3, xmm3, xmm4
    vpxor   xmm3, xmm3, %3
    vmovdqa %3, xmm3
    vpandn  xmm4, xmm12, xmm4
    vpor    xmm4, xmm13, xmm4
    vpxor   xmm4, xmm14, xmm4
    vpor    xmm5, xmm4, xmm5
    vpxor   xmm5, xmm15, xmm5
    vpxor   xmm5, xmm5, %1
    vmovdqa %1, xmm5
%endmacro



section .text
	PROC_FRAME DES_Crypt25_x64_AVX
		alloc_stack 0xb8
		save_xmm128 xmm6,  0x00
		save_xmm128 xmm7,  0x10
		save_xmm128 xmm8,  0x20
		save_xmm128 xmm9,  0x30
		save_xmm128 xmm10, 0x40
		save_xmm128 xmm11, 0x50
		save_xmm128 xmm12, 0x60
		save_xmm128 xmm13, 0x70
		save_xmm128 xmm14, 0x80
		save_xmm128 xmm15, 0x90
		save_reg rbx, 0xa0
		save_reg rsi, 0xa8
		save_reg rdi, 0xb0
	END_PROLOGUE

		; ======================================

		; rcx: DES_Context *context

		pcmpeqd xmm0, xmm0
		vmovdqa pnot, xmm0

		lea data_blocks_address, [rcx + data_blocks_offset]

		mov key_schedule_index_base_x2, 0
		mov rounds_and_swapped, 8
		mov iterations, 25

	start:
		prepare_args_for_sbox_x_with_rewrites 0, 1, 2, 3, 4, 5
		sbox1 data_blocks(40), data_blocks(48), data_blocks(54), data_blocks(62)

		prepare_args_for_sbox_x_with_rewrites 6, 7, 8, 9, 10, 11
		sbox2 data_blocks(44), data_blocks(59), data_blocks(33), data_blocks(49)

		prepare_args_for_sbox_y 7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12, 17
		sbox3 data_blocks(55), data_blocks(47), data_blocks(61), data_blocks(37)

		prepare_args_for_sbox_y 11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16, 23
		sbox4 data_blocks(57), data_blocks(51), data_blocks(41), data_blocks(32)

		prepare_args_for_sbox_x_with_rewrites 24, 25, 26, 27, 28, 29
		sbox5 data_blocks(39), data_blocks(45), data_blocks(56), data_blocks(34)

		prepare_args_for_sbox_x_with_rewrites 30, 31, 32, 33, 34, 35
		sbox6 data_blocks(35), data_blocks(60), data_blocks(42), data_blocks(50)

		prepare_args_for_sbox_y 23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28, 41
		sbox7 data_blocks(63), data_blocks(43), data_blocks(53), data_blocks(38)

		prepare_args_for_sbox_y 27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0, 47
		sbox8 data_blocks(36), data_blocks(58), data_blocks(46), data_blocks(52)

		cmp rounds_and_swapped, 0x100
		je next

	swap:
		prepare_args_for_sbox_x_with_rewrites 48, 49, 50, 51, 52, 53
		sbox1 data_blocks(8), data_blocks(16), data_blocks(22), data_blocks(30)

		prepare_args_for_sbox_x_with_rewrites 54, 55, 56, 57, 58, 59
		sbox2 data_blocks(12), data_blocks(27), data_blocks(1), data_blocks(17)

		prepare_args_for_sbox_y 39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44, 65
		sbox3 data_blocks(23), data_blocks(15), data_blocks(29), data_blocks(5)

		prepare_args_for_sbox_y 43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48, 71
		sbox4 data_blocks(25), data_blocks(19), data_blocks(9), data_blocks(0)

		prepare_args_for_sbox_x_with_rewrites 72, 73, 74, 75, 76, 77
		sbox5 data_blocks(7), data_blocks(13), data_blocks(24), data_blocks(2)

		prepare_args_for_sbox_x_with_rewrites 78, 79, 80, 81, 82, 83
		sbox6 data_blocks(3), data_blocks(28), data_blocks(10), data_blocks(18)

		prepare_args_for_sbox_y 55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60, 89
		sbox7 data_blocks(31), data_blocks(11), data_blocks(21), data_blocks(6)

		prepare_args_for_sbox_y 59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32, 95
		sbox8 data_blocks(4), data_blocks(26), data_blocks(14), data_blocks(20)

		add key_schedule_index_base_x2, 96 * 2

		sub rounds_and_swapped, 1
		jnz start

		sub key_schedule_index_base_x2, (0x300 + 48) * 2
		mov rounds_and_swapped, 0x108

		sub iterations, 1
		jnz swap

		jmp exit

	next:
		sub key_schedule_index_base_x2, (0x300 - 48) * 2
		mov rounds_and_swapped, 8
		sub iterations, 1

		jnz start

		; ======================================

	exit:
		vmovdqa  xmm6,  [rsp+0x00]
		vmovdqa  xmm7,  [rsp+0x10]
		vmovdqa  xmm8,  [rsp+0x20]
		vmovdqa  xmm9,  [rsp+0x30]
		vmovdqa  xmm10, [rsp+0x40]
		vmovdqa  xmm11, [rsp+0x50]
		vmovdqa  xmm12, [rsp+0x60]
		vmovdqa  xmm13, [rsp+0x70]
		vmovdqa  xmm14, [rsp+0x80]
		vmovdqa  xmm15, [rsp+0x90]
		mov     rbx,   [rsp+0xa0]
		mov     rsi,   [rsp+0xa8]
		mov     rdi,   [rsp+0xb0]
		add     rsp, 0xb8
		ret

	ENDPROC_FRAME
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00



		; int IsAVXSupported();
	IsAVXSupported:
		mov r10, rbx
		xor eax, eax
		cpuid
		cmp eax, 1 ; does CPUID support eax = 1?
		jb AVX_not_supported
		mov eax, 1
		cpuid
		and ecx, 018000000h ;check 27 bit (OS uses XSAVE/XRSTOR)
		cmp ecx, 018000000h ; and 28 (AVX supported by CPU)
		jne AVX_not_supported
		xor ecx, ecx ; XFEATURE_ENABLED_MASK/XCR0 register number = 0
		xgetbv ; XFEATURE_ENABLED_MASK register is in edx:eax
		and eax, 110b
		cmp eax, 110b ; check the AVX registers restore at context switch
		jne AVX_not_supported
		mov eax, 1
		mov rbx, r10
		ret
	AVX_not_supported:
		xor eax, eax
		mov rbx, r10
		ret



	; int _myxgetbv(int ecx);
	_myxgetbv:
		xgetbv
		ret



	PROC_FRAME TestASM
		alloc_stack 0xe8
		save_xmm128 xmm6,  0x00
		save_xmm128 xmm7,  0x10
		save_xmm128 xmm8,  0x20
		save_xmm128 xmm9,  0x30
		save_xmm128 xmm10, 0x40
		save_xmm128 xmm11, 0x50
		save_xmm128 xmm12, 0x60
		save_xmm128 xmm13, 0x70
		save_xmm128 xmm14, 0x80
		save_xmm128 xmm15, 0x90

		%define pnot  [rsp+0xa0]
		%define temp0 [rsp+0xb0]
		%define temp1 [rsp+0xc0]

		save_reg rbx, 0xd0
		save_reg rsi, 0xd8
		save_reg rdi, 0xe0
	END_PROLOGUE
		


		; ======================================
		
		 	jmp skip
		 	vmovdqa xmm0, [data_blocks_address + 0xffff0000]
		 	vmovdqa xmm0, [data_blocks_address + 0xffff0000]
			vmovdqa xmm0, [data_blocks_address + 0xffff0000]
			vmovdqa xmm0, [data_blocks_address + 0xffff0000]
			vmovdqa xmm0, [data_blocks_address + 0xffff0000]
			vmovdqa xmm0, [data_blocks_address + 0xffff0000]
		skip:

		; ======================================


	exit_TestAVX:
		vmovdqa  xmm6,  [rsp+0x00]
		vmovdqa  xmm7,  [rsp+0x10]
		vmovdqa  xmm8,  [rsp+0x20]
		vmovdqa  xmm9,  [rsp+0x30]
		vmovdqa  xmm10, [rsp+0x40]
		vmovdqa  xmm11, [rsp+0x50]
		vmovdqa  xmm12, [rsp+0x60]
		vmovdqa  xmm13, [rsp+0x70]
		vmovdqa  xmm14, [rsp+0x80]
		vmovdqa  xmm15, [rsp+0x90]
		mov     rbx,   [rsp+0xd0]
		mov     rsi,   [rsp+0xd8]
		mov     rdi,   [rsp+0xe0]
		add     rsp, 0xe8
		ret

	ENDPROC_FRAME

		db "This is the end of DES_Crypt25_x64()",  0x00
