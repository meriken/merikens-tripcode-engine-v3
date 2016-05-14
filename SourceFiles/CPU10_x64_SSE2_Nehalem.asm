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

global DES_Crypt25_x64_SSE2_Nehalem



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
	movzx r10, byte [rcx + %1]
	movdqa xmm0, [data_blocks_address + r10 * 8]
	movzx r10, byte [rcx + %2]
	movdqa xmm1, [data_blocks_address + r10 * 8]
	pxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	pxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]

	movzx  r10, byte [rcx + %3]
	movdqa xmm2, [data_blocks_address + r10 * 8]
	movzx  r10, byte [rcx + %4]
	movdqa xmm3, [data_blocks_address + r10 * 8]
	pxor     xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	pxor     xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]

	movzx  r10, byte [rcx + %5]
	movdqa xmm4, [data_blocks_address + r10 * 8]
	movzx  r10, byte [rcx + %6]
	movdqa xmm5, [data_blocks_address + r10 * 8]
	pxor     xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	pxor     xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

; "0xffffffff" will be rewritten in DES_SetSalt() based on context->expansionFunction[].
%macro prepare_args_for_sbox_x_with_rewrites 6
	movdqa xmm0, [data_blocks_address + 0xffffffff]
	movdqa xmm1, [data_blocks_address + 0xffffffff]
	pxor     xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	movdqa xmm2, [data_blocks_address + 0xffffffff]
	pxor     xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	movdqa xmm3, [data_blocks_address + 0xffffffff]
	pxor     xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	movdqa xmm4, [data_blocks_address + 0xffffffff]
	pxor     xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	movdqa xmm5, [data_blocks_address + 0xffffffff]
	pxor     xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	pxor     xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

%macro prepare_args_for_sbox_y 12
	; 12 ops
	movdqa xmm0, [data_blocks_address + %1 * 16]
	movdqa xmm1, [data_blocks_address + %3 * 16]
	pxor     xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	movdqa xmm2, [data_blocks_address + %5 * 16]
	pxor     xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	movdqa xmm3, [data_blocks_address + %7 * 16]
	pxor     xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
	movdqa xmm4, [data_blocks_address + %9 * 16]
	pxor     xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %8 * 16]
	movdqa xmm5, [data_blocks_address + %11 * 16]
	pxor     xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %10 * 16]
	pxor     xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %12 * 16]
%endmacro

%macro sbox1 4
	movdqa xmm7, xmm4
	movdqa xmm10, xmm5
	pandn  xmm4, xmm0
	movdqa xmm13, xmm2
	movdqa xmm14, xmm4
	por    xmm10, xmm2
	movdqa xmm11, xmm5
	pxor   xmm13, xmm0
	pxor   xmm11, xmm7
	pxor   xmm14, xmm3
	movdqa xmm12, xmm13
	movdqa xmm15, xmm11
	pand   xmm13, xmm10
	movdqa xmm9, xmm14
	movdqa xmm8, xmm13
	pxor   xmm15, xmm2
	pxor   xmm8, xmm3
	pandn  xmm12, xmm11
	pandn  xmm9, xmm8
	por    xmm13, xmm5
	por    xmm5, xmm0
	pandn  xmm8, xmm7
	pandn  xmm15, xmm14
	movdqa xmm6, xmm5
	pxor   xmm13, xmm15
	movdqa xmm15, xmm9
	por    xmm6, xmm13
	pandn  xmm5, xmm3
	movdqa xmm3, xmm8
	pandn  xmm15, xmm13
	pxor   xmm8, xmm6
	pxor   xmm5, xmm3
	pand   xmm13, xmm10
	pandn  xmm4, xmm2
	movdqa xmm2, xmm6
	pxor   xmm6, xmm10
	pxor   xmm2, xmm14
	pandn  xmm4, xmm2
	movdqa xmm2, xmm4
	pxor   xmm2, pnot
	pxor   xmm4, xmm11
	pxor   xmm13, xmm2
	movdqa xmm2, xmm1
	por    xmm4, xmm3
	pandn  xmm2, xmm8
	por    xmm14, xmm7
	pxor   xmm4, xmm10
	por    xmm9, xmm1
	pxor   xmm2, xmm13
	pxor   xmm4, xmm0
	movdqa xmm0, xmm1
	pxor   xmm13, xmm4
	pxor   xmm9, xmm13
	por    xmm5, xmm12
	pxor   xmm9, %1
	por    xmm6, xmm5
	por    xmm13, xmm11
	pxor   xmm6, xmm4
	movdqa %1, xmm9
	por    xmm0, xmm15
	pxor   xmm13, xmm6
	pxor   xmm2, %3
	pxor   xmm13, %2
	pand   xmm4, xmm15
	pandn  xmm6, xmm14
	pxor   xmm13, xmm0
	pxor   xmm4, xmm6
	movdqa %3, xmm2
	por    xmm4, xmm1
	pxor   xmm4, xmm5
	movdqa %2, xmm13
	pxor   xmm4, %4
	movdqa %4, xmm4
%endmacro

%macro sbox2 4
	movdqa xmm13, xmm4
	movdqa xmm6, xmm5
	pxor   xmm13, xmm1
	movdqa xmm8, xmm5
	pandn  xmm6, xmm0
	movdqa xmm7, xmm13
	pandn  xmm6, xmm4
	movdqa xmm9, xmm5
	movdqa xmm14, xmm6
	pandn  xmm8, xmm13
	pand   xmm7, xmm0
	pxor   xmm0, pnot
	por    xmm14, xmm1
	movdqa xmm12, xmm8
	pxor   xmm7, xmm4
	pand   xmm9, xmm2
	pxor   xmm13, xmm5
	pxor   xmm6, xmm8
	movdqa xmm10, xmm9
	pand   xmm6, xmm14
	pandn  xmm10, xmm6
	pand   xmm6, xmm2
	pandn  xmm12, xmm7
	pxor   xmm0, xmm6
	movdqa xmm5, xmm9
	pandn  xmm10, xmm3
	pandn  xmm5, xmm13
	movdqa xmm11, xmm5
	pandn  xmm5, xmm1
	pxor   xmm11, xmm0
	pxor   xmm2, xmm13
	por    xmm12, xmm3
	pxor   xmm7, xmm5
	movdqa xmm1, xmm7
	pxor   xmm10, %2
	pandn  xmm1, xmm0
	movdqa xmm0, xmm3
	pxor   xmm1, xmm2
	pandn  xmm0, xmm14
	pxor   xmm14, xmm11
	pxor   xmm6, xmm5
	pxor   xmm0, xmm1
	por    xmm2, xmm6
	por    xmm9, xmm14
	pxor   xmm6, xmm1
	pxor   xmm10, xmm11
	pand   xmm6, xmm9
	pxor   xmm2, %3
	pxor   xmm6, xmm4
	pandn  xmm8, xmm6
	pxor   xmm2, xmm9
	pxor   xmm8, xmm11
	por    xmm3, xmm8
	por    xmm14, xmm13
	pxor   xmm2, xmm3
	pandn  xmm7, xmm8
	movdqa %3, xmm2
	pxor   xmm7, %4
	movdqa %2, xmm10
	pxor   xmm7, xmm14
	pxor   xmm0, %1
	pxor   xmm7, xmm12
	movdqa %1, xmm0
	movdqa %4, xmm7
%endmacro

%macro sbox3 4
	movdqa xmm6, xmm1
	movdqa xmm13, xmm5
	pandn  xmm6, xmm0
	movdqa xmm8, xmm5
	pxor   xmm13, xmm2
	movdqa xmm11, xmm0
	por    xmm6, xmm13
	movdqa xmm9, xmm13
	pxor   xmm8, xmm3
	movdqa xmm15, xmm3
	pandn  xmm11, xmm8
	pxor   xmm9, xmm1
	movdqa xmm10, xmm11
	movdqa xmm12, xmm4
	movdqa xmm14, xmm5
	pxor   xmm10, xmm6
	pandn  xmm14, xmm9
	movdqa xmm7, xmm10
	pxor   xmm6, xmm14
	movdqa xmm14, xmm6
	pand   xmm7, xmm5
	pand   xmm5, xmm3
	pandn  xmm14, xmm10
	por    xmm7, xmm3
	pandn  xmm12, xmm10
	pand   xmm7, xmm0
	pxor   xmm12, %4
	pxor   xmm7, xmm9
	pand   xmm8, xmm13
	pxor   xmm15, xmm0
	pxor   xmm12, xmm7
	pxor   xmm6, xmm15
	pand   xmm13, xmm3
	por    xmm6, xmm2
	por    xmm15, xmm11
	pandn  xmm8, xmm6
	movdqa xmm6, xmm15
	pand   xmm8, xmm4
	pandn  xmm6, xmm7
	movdqa xmm7, xmm1
	pandn  xmm1, xmm10
	pandn  xmm7, xmm5
	por    xmm5, xmm9
	pxor   xmm6, xmm7
	movdqa xmm7, xmm2
	pxor   xmm15, xmm9
	pandn  xmm7, xmm6
	pandn  xmm2, xmm1
	pandn  xmm7, xmm5
	pxor   xmm15, pnot
	pxor   xmm7, %2
	pxor   xmm15, xmm2
	pandn  xmm14, xmm4
	movdqa %4, xmm12
	por    xmm9, xmm15
	pxor   xmm7, xmm0
	pandn  xmm13, xmm9
	por    xmm1, xmm11
	pxor   xmm7, xmm8
	pxor   xmm13, xmm1
	por    xmm6, xmm4
	pxor   xmm14, %1
	pxor   xmm6, xmm13
	pxor   xmm14, xmm15
	pxor   xmm6, %3
	movdqa %2, xmm7
	movdqa %1, xmm14
	movdqa %3, xmm6
%endmacro

%macro sbox4 4
	movdqa xmm7, xmm3
	movdqa xmm8, xmm1
	pxor   xmm0, xmm2
	pxor   xmm2, xmm4
	por    xmm3, xmm1
	pandn  xmm1, xmm2
	pxor   xmm3, xmm4
	movdqa xmm10, xmm1
	pxor   xmm1, xmm7
	pandn  xmm3, xmm2
	movdqa xmm11, xmm1
	movdqa xmm6, xmm3
	pxor   xmm7, xmm8
	por    xmm1, xmm0
	pandn  xmm3, xmm1
	movdqa xmm1, xmm3
	movdqa xmm12, xmm5
	pxor   xmm3, xmm8
	pand   xmm11, xmm3
	movdqa xmm9, xmm11
	por    xmm10, xmm4
	pxor   xmm0, xmm3
	pandn  xmm11, xmm2
	pandn  xmm11, xmm0
	pxor   xmm10, xmm0
	movdqa xmm0, xmm7
	pxor   xmm6, xmm11
	movdqa xmm4, xmm6
	pandn  xmm6, xmm5
	pandn  xmm7, xmm10
	pxor   xmm6, %1
	pandn  xmm5, xmm4
	pxor   xmm7, xmm1
	pxor   xmm6, xmm7
	pxor   xmm7, pnot
	pxor   xmm5, xmm7
	pxor   xmm7, xmm4
	pxor   xmm5, %2
	movdqa %2, xmm5
	pandn  xmm0, xmm7
	movdqa xmm7, xmm12
	por    xmm0, xmm9
	movdqa %1, xmm6
	pxor   xmm0, xmm10
	por    xmm12, xmm3
	pxor   xmm12, xmm0
	pxor   xmm0, %4
	pand   xmm3, xmm7
	pxor   xmm12, %3
	movdqa %3, xmm12
	pxor   xmm0, xmm3
	movdqa %4, xmm0
%endmacro

%macro sbox5 4
	movdqa xmm6, xmm2
	por    xmm2, xmm0
	movdqa xmm7, xmm5
	pandn  xmm5, xmm2
	movdqa xmm14, xmm3
	pandn  xmm3, xmm5
	pxor   xmm5, xmm0
	pxor   xmm3, xmm6
	movdqa xmm15, xmm5
	pxor   xmm5, xmm6
	movdqa xmm10, xmm3
	pand   xmm3, xmm4
	movdqa xmm8, xmm5
	por    xmm5, xmm0
	pxor   xmm3, xmm14
	pxor   xmm3, xmm5
	movdqa xmm12, xmm5
	por    xmm8, xmm14
	pxor   xmm2, xmm0
	pxor   xmm7, xmm3
	pand   xmm12, xmm14
	movdqa xmm9, xmm7
	por    xmm7, xmm15
	pxor   xmm12, xmm15
	pandn  xmm0, xmm7
	pand   xmm7, xmm4
	pxor   xmm4, xmm8
	pxor   xmm12, xmm7
	movdqa xmm6, xmm0
	pxor   xmm0, xmm4
	pxor   xmm6, xmm10
	movdqa xmm13, xmm1
	pandn  xmm6, xmm4
	pand   xmm5, xmm10
	pxor   xmm6, pnot
	por    xmm0, xmm12
	pandn  xmm13, xmm6
	movdqa xmm6, xmm7
	pandn  xmm7, xmm10
	pxor   xmm10, xmm8
	pandn  xmm7, xmm0
	pxor   xmm3, xmm13
	pand   xmm9, xmm7
	movdqa xmm0, xmm7
	pxor   xmm9, xmm4
	pandn  xmm0, xmm8
	pand   xmm8, xmm1
	por    xmm0, xmm1
	pand   xmm14, xmm9
	pxor   xmm7, xmm2
	por    xmm5, xmm9
	pxor   xmm7, xmm14
	pxor   xmm5, xmm6
	pxor   xmm0, xmm7
	pxor   xmm9, xmm15
	pandn  xmm7, xmm10
	pand   xmm5, xmm1
	pxor   xmm7, xmm9
	pxor   xmm5, xmm12
	pxor   xmm7, xmm8
	pxor   xmm3, %3
	pxor   xmm5, %4
	pxor   xmm0, %1
	pxor   xmm7, %2
	movdqa %3, xmm3
	movdqa %4, xmm5
	movdqa %1, xmm0
	movdqa %2, xmm7
%endmacro

%macro sbox6 4
	movdqa xmm8, xmm5
	por    xmm5, xmm1
	movdqa xmm7, xmm4
	movdqa temp1, xmm4
	movdqa xmm11, xmm2
	pxor   xmm4, xmm1
	pand   xmm5, xmm0
	movdqa xmm15, xmm3
	pxor   xmm4, xmm5
	movdqa xmm9, xmm4
	pxor   xmm11, xmm0
	pxor   xmm4, xmm8
	movdqa temp0, xmm0
	movdqa xmm12, xmm4
	pand   xmm4, xmm0
	movdqa xmm0, xmm11
	pandn  xmm12, xmm7
	movdqa xmm10, xmm4
	pxor   xmm4, xmm1
	por    xmm11, xmm1
	por    xmm0, xmm4
	movdqa xmm6, xmm0
	por    xmm4, xmm12
	pxor   xmm0, xmm9
	pxor   xmm6, xmm1
	movdqa xmm14, xmm4
	movdqa xmm7, xmm6
	pandn  xmm6, xmm8
	pxor   xmm10, xmm8
	pxor   xmm6, xmm2
	pand   xmm2, xmm0
	movdqa xmm1, xmm3
	pandn  xmm8, xmm2
	movdqa xmm13, xmm2
	pxor   xmm14, xmm8
	pxor   xmm7, xmm11
	pand   xmm15, xmm14
	pandn  xmm2, temp1
	pxor   xmm15, xmm0
	por    xmm0, temp0
	pxor   xmm15, %4
	pand   xmm0, xmm4
	por    xmm2, xmm6
	pxor   xmm0, xmm6
	pxor   xmm7, pnot
	pandn  xmm8, xmm0
	pxor   xmm0, xmm9
	por    xmm12, xmm3
	pandn  xmm0, temp1
	por    xmm5, xmm2
	pxor   xmm0, xmm7
	pxor   xmm6, temp0
	pandn  xmm1, xmm0
	pandn  xmm3, xmm2
	pand   xmm6, xmm10
	pxor   xmm7, xmm3
	pxor   xmm8, %3
	pxor   xmm7, xmm6
	pxor   xmm8, xmm12
	pxor   xmm5, xmm1
	pxor   xmm7, xmm13
	pxor   xmm14, xmm11
	pxor   xmm5, %2
	pxor   xmm5, xmm14
	movdqa %4, xmm15
	pxor   xmm7, %1
	movdqa %3, xmm8
	movdqa %2, xmm5
	movdqa %1, xmm7
%endmacro

%macro sbox7 4
	movdqa xmm14, xmm4
	pxor   xmm4, xmm3
	movdqa xmm11, xmm3
	movdqa xmm12, xmm4
	pand   xmm11, xmm4
	pxor   xmm4, xmm2
	movdqa xmm6, xmm11
	movdqa xmm7, xmm4
	movdqa xmm15, xmm11
	pand   xmm6, xmm5
	pxor   xmm11, xmm1
	movdqa xmm13, xmm7
	pand   xmm4, xmm5
	movdqa xmm10, xmm11
	pxor   xmm12, xmm5
	pxor   xmm6, xmm2
	movdqa xmm8, xmm6
	por    xmm6, xmm10
	pand   xmm11, xmm4
	pandn  xmm11, xmm0
	pxor   xmm6, xmm12
	pxor   xmm8, xmm4
	pandn  xmm7, xmm14
	movdqa xmm9, xmm7
	pxor   xmm11, xmm6
	pxor   xmm4, xmm12
	por    xmm7, xmm10
	pxor   xmm7, xmm8
	pandn  xmm4, xmm3
	pxor   xmm8, xmm14
	pandn  xmm4, xmm10
	pxor   xmm8, xmm4
	pandn  xmm12, xmm13
	pand   xmm2, xmm8
	por    xmm6, xmm15
	por    xmm6, xmm2
	pxor   xmm6, xmm12
	movdqa xmm3, xmm0
	pandn  xmm0, xmm6
	movdqa xmm4, xmm6
	por    xmm6, xmm8
	pand   xmm6, xmm5
	pxor   xmm0, xmm7
	por    xmm2, xmm14
	pand   xmm1, xmm6
	pxor   xmm7, xmm4
	pxor   xmm2, xmm6
	pxor   xmm1, xmm7
	pxor   xmm7, xmm14
	movdqa xmm5, xmm3
	por    xmm7, xmm2
	pxor   xmm0, %1
	pand   xmm3, xmm7
	pxor   xmm4, pnot
	pxor   xmm7, xmm6
	por    xmm7, xmm9
	pxor   xmm11, %4
	pxor   xmm8, xmm3
	pxor   xmm7, xmm4
	pandn  xmm5, xmm7
	movdqa %4, xmm11
	pxor   xmm1, %2
	movdqa %1, xmm0
	pxor   xmm1, xmm5
	pxor   xmm8, %3
	movdqa %3, xmm8
	movdqa %2, xmm1
%endmacro

%macro sbox8 4
	movdqa xmm13, xmm1
	pandn  xmm1, xmm2
	movdqa xmm11, xmm2
	movdqa xmm8, xmm2
	pandn  xmm2, xmm4
	movdqa xmm6, xmm1
	pxor   xmm2, xmm3
	pandn  xmm11, xmm13
	movdqa xmm9, xmm2
	pand   xmm2, xmm0
	movdqa xmm7, xmm9
	pandn  xmm1, xmm2
	pandn  xmm9, xmm13
	pxor   xmm11, xmm4
	movdqa xmm12, xmm9
	por    xmm9, xmm0
	movdqa xmm10, xmm11
	pand   xmm11, xmm9
	pxor   xmm7, pnot
	por    xmm2, xmm11
	pxor   xmm7, xmm11
	pandn  xmm9, xmm8
	movdqa xmm15, xmm5
	pxor   xmm7, xmm9
	por    xmm5, xmm1
	pxor   xmm6, xmm7
	pxor   xmm5, xmm6
	pxor   xmm6, xmm0
	movdqa xmm14, xmm6
	pxor   xmm7, xmm13
	pand   xmm6, xmm4
	pxor   xmm5, %2
	pxor   xmm6, xmm7
	pxor   xmm12, xmm6
	movdqa %2, xmm5
	pxor   xmm6, xmm2
	pxor   xmm14, xmm4
	por    xmm6, xmm13
	pand   xmm2, xmm15
	por    xmm7, xmm3
	pxor   xmm10, xmm12
	pxor   xmm7, xmm10
	pxor   xmm6, xmm14
	pxor   xmm2, xmm6
	pxor   xmm0, xmm7
	pandn  xmm3, xmm10
	pand   xmm0, xmm15
	pand   xmm6, xmm3
	pxor   xmm2, %3
	pxor   xmm7, xmm6
	pxor   xmm7, xmm1
	pxor   xmm0, %4
	movdqa %3, xmm2
	por    xmm7, xmm15
	pxor   xmm7, %1
	pxor   xmm0, xmm12
	pxor   xmm7, xmm12
	movdqa %4, xmm0
	movdqa %1, xmm7
%endmacro



section .text
	PROC_FRAME DES_Crypt25_x64_SSE2_Nehalem
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
		movdqa  pnot, xmm0

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
		movdqa  xmm6,  [rsp+0x00]
		movdqa  xmm7,  [rsp+0x10]
		movdqa  xmm8,  [rsp+0x20]
		movdqa  xmm9,  [rsp+0x30]
		movdqa  xmm10, [rsp+0x40]
		movdqa  xmm11, [rsp+0x50]
		movdqa  xmm12, [rsp+0x60]
		movdqa  xmm13, [rsp+0x70]
		movdqa  xmm14, [rsp+0x80]
		movdqa  xmm15, [rsp+0x90]
		mov     rbx,   [rsp+0xa0]
		mov     rsi,   [rsp+0xa8]
		mov     rdi,   [rsp+0xb0]
		add     rsp,   0xb8
		ret

	ENDPROC_FRAME
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00

