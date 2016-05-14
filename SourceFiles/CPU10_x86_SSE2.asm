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

global _DES_Crypt25_x86_SSE2
global _TestASM



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define expanded_key_schedule_address   (ecx + expanded_key_schedule_offset)
%define data_blocks_address             ebx
%define key_schedule_index_base_x2      edx

%define iterations                      esi
%define rounds_and_swapped              edi

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

%define data_blocks(i)               [ecx + data_blocks_offset + (i) * 16]
%define pnot                         [ecx + temp_offset]
%define tmp_at(i)                    [ecx + temp_offset + (i) * 16]

; This is the original macro.
%macro prepare_args_for_sbox_x 6
	movzx  eax,  byte [ecx + %1]
	movaps xmm0, [data_blocks_address + eax * 8]
	movzx  eax,  byte [ecx + %2]
	movaps xmm1, [data_blocks_address + eax * 8]
	pxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	pxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]

	movzx  eax,  byte [ecx + %3]
	movaps xmm2, [data_blocks_address + eax * 8]
	movzx  eax,  byte [ecx + %4]
	movaps xmm3, [data_blocks_address + eax * 8]
	pxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	pxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]

	movzx  eax,  byte [ecx + %5]
	movaps xmm4, [data_blocks_address + eax * 8]
	movzx  eax,  byte [ecx + %6]
	movaps xmm5, [data_blocks_address + eax * 8]
	pxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	pxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

; "0xffffffff" will be rewritten in DES_SetSalt() based on context->expansionFunction[].
%macro prepare_args_for_sbox_x_with_rewrites 6
	movaps xmm0, [data_blocks_address + 0xffffffff]
	movaps xmm1, [data_blocks_address + 0xffffffff]
	pxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	movaps xmm2, [data_blocks_address + 0xffffffff]
	pxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	movaps xmm3, [data_blocks_address + 0xffffffff]
	pxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	movaps xmm4, [data_blocks_address + 0xffffffff]
	pxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	movaps xmm5, [data_blocks_address + 0xffffffff]
	pxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	pxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

%macro prepare_args_for_sbox_y 12
	; 12 ops
	movaps xmm0, [data_blocks_address + %1 * 16]
	movaps xmm1, [data_blocks_address + %3 * 16]
	pxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	movaps xmm2, [data_blocks_address + %5 * 16]
	pxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	movaps xmm3, [data_blocks_address + %7 * 16]
	pxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
	movaps xmm4, [data_blocks_address + %9 * 16]
	pxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %8 * 16]
	movaps xmm5, [data_blocks_address + %11 * 16]
	pxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %10 * 16]
	pxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %12 * 16]
%endmacro

%macro sbox1 4
	movaps tmp_at(1), xmm0
	movaps xmm7, xmm5
	movaps tmp_at(4), xmm4
	movaps xmm6, xmm2
	movaps tmp_at(2), xmm1
	por xmm7, xmm2
	movaps tmp_at(3), xmm3
	pxor xmm6, xmm0
	movaps tmp_at(5), xmm7
	movaps xmm1, xmm6
	pandn xmm4, xmm0
	pand xmm1, xmm7
	movaps xmm7, xmm1
	por xmm7, xmm5
	pxor xmm1, xmm3
	pxor xmm3, xmm4
	movaps tmp_at(6), xmm1
	movaps xmm1, xmm3
	pandn xmm3, tmp_at(6)
	movaps tmp_at(7), xmm3
	movaps xmm3, xmm5
	por xmm5, xmm0
	pxor xmm3, tmp_at(4)
	movaps tmp_at(8), xmm3
	movaps xmm0, xmm5
	pandn xmm6, xmm3
	pxor xmm3, xmm2
	pandn xmm4, xmm2
	pandn xmm3, xmm1
	pxor xmm7, xmm3
	movaps xmm3, tmp_at(7)
	pandn xmm5, tmp_at(3)
	por xmm0, xmm7
	pandn xmm3, xmm7
	movaps tmp_at(9), xmm3
	pand xmm7, tmp_at(5)
	movaps xmm3, tmp_at(6)
	movaps xmm2, xmm0
	pxor xmm2, xmm1
	pandn xmm3, tmp_at(4)
	pandn xmm4, xmm2
	movaps xmm2, tmp_at(2)
	pxor xmm7, xmm4
	pxor xmm4, tmp_at(8)
	pxor xmm5, xmm3
	por xmm4, xmm3
	pxor xmm4, tmp_at(1)
	pxor xmm3, xmm0
	pandn xmm2, xmm3
	pxor xmm0, tmp_at(5)
	movaps xmm3, tmp_at(7)
	por xmm3, tmp_at(2)
	pxor xmm7, pnot
	pxor xmm3, %1
	pxor xmm2, xmm7
	pxor xmm4, tmp_at(5)
	pxor xmm2, %3
	pxor xmm7, xmm4
	pxor xmm3, xmm7
	movaps %1, xmm3
	por xmm5, xmm6
	por xmm7, tmp_at(8)
	por xmm0, xmm5
	pxor xmm7, %2
	pxor xmm0, xmm4
	pxor xmm7, xmm0
	por xmm1, tmp_at(4)
	movaps xmm3, tmp_at(2)
	pand xmm4, tmp_at(9)
	pandn xmm0, xmm1
	pxor xmm4, xmm0
	por xmm3, tmp_at(9)
	por xmm4, tmp_at(2)
	movaps %3, xmm2
	pxor xmm7, xmm3
	pxor xmm4, xmm5
	pxor xmm4, %4
	movaps %2, xmm7
	movaps %4, xmm4
%endmacro

%macro sbox2 4
	movaps tmp_at(2), xmm2
	movaps tmp_at(1), xmm1
	movaps xmm2, xmm5
	movaps tmp_at(4), xmm4
	pandn xmm2, xmm0
	movaps tmp_at(3), xmm3
	pandn xmm2, xmm4
	movaps xmm6, xmm0
	movaps xmm7, xmm2
	pxor xmm0, pnot
	por xmm7, xmm1
	pxor xmm1, xmm4
	movaps tmp_at(5), xmm7
	pand xmm6, xmm1
	movaps xmm7, xmm5
	pxor xmm6, xmm4
	pandn xmm7, xmm1
	movaps xmm4, xmm3
	pxor xmm2, xmm7
	pandn xmm7, xmm6
	pxor xmm1, xmm5
	movaps tmp_at(7), xmm7
	movaps xmm7, xmm5
	pand xmm5, tmp_at(2)
	pand xmm2, tmp_at(5)
	movaps tmp_at(8), xmm5
	pandn xmm5, xmm2
	pand xmm2, tmp_at(2)
	movaps xmm7, tmp_at(8)
	pandn xmm5, tmp_at(3)
	pandn xmm7, xmm1
	pxor xmm0, xmm2
	movaps xmm3, xmm7
	pxor xmm3, xmm0
	pxor xmm5, %2
	pandn xmm7, tmp_at(1)
	pxor xmm7, xmm6
	pxor xmm5, xmm3
	movaps xmm6, xmm7
	movaps %2, xmm5
	movaps xmm5, tmp_at(7)
	pandn xmm4, tmp_at(5)
	pandn xmm6, xmm0
	pxor xmm3, tmp_at(5)
	movaps xmm0, xmm1
	pxor xmm6, xmm4
	pxor xmm0, tmp_at(2)
	pxor xmm6, xmm0
	movaps xmm4, xmm0
	pxor xmm6, %1
	pandn xmm0, tmp_at(1)
	pxor xmm2, tmp_at(4)
	pxor xmm0, xmm3
	movaps %1, xmm6
	por xmm3, xmm1
	por xmm0, tmp_at(8)
	pxor xmm0, xmm4
	movaps xmm4, xmm0
	pandn xmm0, tmp_at(2)
	movaps xmm6, tmp_at(3)
	pxor xmm0, tmp_at(7)
	por xmm0, xmm7
	por xmm5, xmm6
	pxor xmm2, xmm0
	pandn xmm7, xmm2
	por xmm6, xmm2
	pxor xmm7, %4
	pxor xmm6, xmm4
	pxor xmm6, %3
	pxor xmm7, xmm5
	pxor xmm7, xmm3
	movaps %3, xmm6
	movaps %4, xmm7
%endmacro

%macro sbox3 4
	movaps tmp_at(1), xmm0
	movaps tmp_at(2), xmm1
	movaps xmm7, xmm0
	pandn xmm1, xmm0
	movaps tmp_at(3), xmm2
	movaps xmm0, xmm5
	pxor xmm0, xmm2
	movaps tmp_at(4), xmm4
	movaps xmm2, xmm5
	por xmm1, xmm0
	pxor xmm2, xmm3
	movaps xmm4, xmm0
	movaps xmm6, xmm5
	pandn xmm7, xmm2
	pxor xmm4, tmp_at(2)
	movaps tmp_at(5), xmm7
	pxor xmm7, xmm1
	pandn xmm6, xmm4
	movaps tmp_at(6), xmm7
	pxor xmm1, xmm6
	pand xmm2, xmm0
	movaps xmm6, xmm1
	movaps xmm0, xmm3
	pandn xmm6, xmm7
	pand xmm7, xmm5
	pand xmm5, xmm3
	por xmm7, xmm3
	pand xmm7, tmp_at(1)
	movaps xmm3, tmp_at(4)
	pandn xmm3, tmp_at(6)
	pxor xmm7, xmm4
	pxor xmm0, tmp_at(1)
	movaps tmp_at(7), xmm7
	pxor xmm7, xmm3
	movaps xmm3, tmp_at(2)
	pxor xmm7, %4
	pxor xmm1, xmm0
	movaps %4, xmm7
	movaps xmm7, tmp_at(3)
	por xmm1, tmp_at(3)
	pandn xmm2, xmm1
	por xmm0, tmp_at(5)
	movaps xmm1, xmm0
	pandn xmm3, xmm5
	pandn xmm1, tmp_at(7)
	por xmm5, xmm4
	pxor xmm1, xmm3
	por xmm7, tmp_at(2)
	movaps xmm3, tmp_at(3)
	pandn xmm3, xmm1
	pxor xmm0, xmm4
	pandn xmm3, xmm5
	movaps xmm5, tmp_at(4)
	pxor xmm3, tmp_at(1)
	pand xmm5, xmm2
	pxor xmm0, pnot
	pxor xmm3, xmm5
	movaps xmm5, xmm7
	pxor xmm3, %2
	pandn xmm6, tmp_at(4)
	pandn xmm7, tmp_at(6)
	pxor xmm6, xmm0
	movaps %2, xmm3
	pxor xmm2, tmp_at(1)
	por xmm1, tmp_at(4)
	por xmm0, xmm2
	pxor xmm5, tmp_at(6)
	pxor xmm0, xmm1
	pxor xmm6, %1
	pxor xmm5, %3
	pxor xmm0, tmp_at(7)
	pxor xmm6, xmm7
	pxor xmm0, xmm5
	movaps %1, xmm6
	movaps %3, xmm0
%endmacro

%macro sbox4 4
	movaps xmm7, xmm1
	pxor xmm0, xmm2
	por xmm1, xmm3
	pxor xmm2, xmm4
	movaps tmp_at(2), xmm5
	pxor xmm1, xmm4
	movaps xmm6, xmm7
	movaps xmm5, xmm7
	pandn xmm7, xmm2
	pandn xmm1, xmm2
	por xmm4, xmm7
	pxor xmm7, xmm3
	movaps xmm6, xmm7
	por xmm7, xmm0
	pxor xmm3, xmm5
	movaps tmp_at(3), xmm1
	pandn xmm1, xmm7
	movaps xmm7, xmm1
	pxor xmm1, xmm5
	pand xmm6, xmm1
	movaps xmm5, xmm6
	pxor xmm0, xmm1
	pandn xmm6, xmm2
	pandn xmm6, xmm0
	pxor xmm4, xmm0
	movaps xmm0, xmm3
	pandn xmm3, xmm4
	movaps xmm2, tmp_at(2)
	pxor xmm3, xmm7
	pxor xmm6, tmp_at(3)
	movaps xmm7, xmm6
	pandn xmm6, xmm2
	pxor xmm6, %1
	pandn xmm2, xmm7
	pxor xmm2, %2
	pxor xmm6, xmm3
	pxor xmm3, pnot
	pxor xmm2, xmm3
	pxor xmm3, xmm7
	movaps %1, xmm6
	pandn xmm0, xmm3
	por xmm0, xmm5
	movaps %2, xmm2
	movaps xmm3, tmp_at(2)
	por xmm3, xmm1
	pand xmm1, tmp_at(2)
	pxor xmm0, xmm4
	pxor xmm3, xmm0
	pxor xmm3, %3
	pxor xmm0, xmm1
	movaps %3, xmm3
	pxor xmm0, %4
	movaps %4, xmm0
%endmacro

%macro sbox5 4
	movaps tmp_at(3), xmm2
	movaps tmp_at(1), xmm0
	por xmm2, xmm0
	movaps xmm6, xmm5
	movaps tmp_at(4), xmm2
	pandn xmm5, xmm2
	movaps xmm7, xmm2
	movaps xmm2, xmm5
	pxor xmm5, xmm0
	movaps xmm7, xmm3
	movaps tmp_at(5), xmm5
	pxor xmm5, tmp_at(3)
	movaps tmp_at(2), xmm1
	por xmm0, xmm5
	por xmm5, xmm3
	pandn xmm3, xmm2
	pxor xmm3, tmp_at(3)
	movaps tmp_at(6), xmm3
	movaps xmm1, xmm0
	pand xmm3, xmm4
	pxor xmm3, xmm0
	pand xmm0, xmm7
	pxor xmm3, xmm7
	movaps tmp_at(3), xmm3
	pxor xmm6, xmm3
	movaps xmm2, xmm6
	por xmm6, tmp_at(5)
	movaps xmm3, xmm6
	pand xmm6, xmm4
	movaps tmp_at(7), xmm6
	pxor xmm6, tmp_at(5)
	pxor xmm0, xmm6
	movaps xmm6, tmp_at(1)
	movaps tmp_at(8), xmm0
	pandn xmm6, xmm3
	movaps xmm0, tmp_at(2)
	movaps xmm3, xmm6
	pxor xmm6, tmp_at(6)
	pxor xmm4, xmm5
	pandn xmm6, xmm4
	pxor xmm6, pnot
	pandn xmm0, xmm6
	pxor xmm0, tmp_at(3)
	movaps xmm6, tmp_at(7)
	pandn xmm6, tmp_at(6)
	pxor xmm0, %3
	pxor xmm3, xmm4
	movaps %3, xmm0
	por xmm3, tmp_at(8)
	movaps xmm0, tmp_at(6)
	pandn xmm6, xmm3
	pand xmm1, tmp_at(6)
	pand xmm2, xmm6
	movaps xmm3, xmm6
	pandn xmm6, xmm5
	pxor xmm2, xmm4
	por xmm1, xmm2
	pxor xmm3, tmp_at(4)
	pxor xmm1, tmp_at(7)
	pand xmm7, xmm2
	pand xmm1, tmp_at(2)
	pxor xmm7, tmp_at(1)
	pxor xmm1, tmp_at(8)
	pxor xmm3, xmm7
	por xmm6, tmp_at(2)
	pxor xmm1, %4
	movaps %4, xmm1
	pxor xmm0, xmm5
	pxor xmm2, tmp_at(5)
	pxor xmm6, xmm3
	pandn xmm3, xmm0
	pand xmm5, tmp_at(2)
	pxor xmm3, xmm2
	pxor xmm5, %2
	pxor xmm3, xmm5
	pxor xmm6, %1
	movaps %2, xmm3
	movaps %1, xmm6
%endmacro

%macro sbox6 4
	movaps tmp_at(2), xmm4
	pxor xmm4, xmm1
	movaps tmp_at(3), xmm5
	por xmm5, xmm1
	movaps xmm7, xmm2
	pand xmm5, xmm0
	pxor xmm2, xmm0
	movaps tmp_at(1), xmm0
	pxor xmm4, xmm5
	movaps tmp_at(4), xmm4
	pxor xmm4, tmp_at(3)
	movaps xmm6, xmm4
	pandn xmm4, tmp_at(2)
	pand xmm6, xmm0
	movaps tmp_at(5), xmm6
	pxor xmm6, xmm1
	movaps tmp_at(6), xmm6
	por xmm6, xmm2
	movaps tmp_at(7), xmm6
	pxor xmm6, tmp_at(4)
	movaps xmm0, xmm6
	pand xmm6, xmm7
	movaps tmp_at(8), xmm6
	movaps xmm6, tmp_at(3)
	por xmm2, xmm1
	pandn xmm6, tmp_at(8)
	movaps tmp_at(9), xmm6
	movaps xmm6, tmp_at(6)
	por xmm6, xmm4
	movaps tmp_at(6), xmm6
	pxor xmm6, tmp_at(9)
	movaps tmp_at(10), xmm6
	pand xmm6, xmm3
	pxor xmm6, %4
	pxor xmm6, xmm0
	por xmm0, tmp_at(1)
	movaps %4, xmm6
	movaps xmm6, tmp_at(7)
	pxor xmm6, xmm1
	movaps xmm1, xmm3
	movaps tmp_at(7), xmm6
	pandn xmm6, tmp_at(3)
	pxor xmm6, xmm7
	movaps xmm7, tmp_at(8)
	movaps tmp_at(12), xmm6
	pandn xmm7, tmp_at(2)
	pand xmm0, tmp_at(6)
	por xmm7, xmm6
	pxor xmm0, xmm6
	movaps xmm6, tmp_at(9)
	por xmm4, xmm3
	pandn xmm6, xmm0
	por xmm5, xmm7
	pxor xmm6, xmm4
	pxor xmm0, tmp_at(4)
	pxor xmm6, %3
	pxor xmm5, xmm2
	movaps %3, xmm6
	movaps xmm6, tmp_at(5)
	pandn xmm0, tmp_at(2)
	pxor xmm2, pnot
	pxor xmm2, tmp_at(7)
	pxor xmm6, tmp_at(3)
	pxor xmm5, %2
	movaps xmm4, tmp_at(12)
	pxor xmm0, xmm2
	pxor xmm4, tmp_at(1)
	pxor xmm5, tmp_at(10)
	pand xmm4, xmm6
	pandn xmm3, xmm0
	pxor xmm4, %1
	pandn xmm1, xmm7
	pxor xmm4, tmp_at(8)
	pxor xmm1, xmm2
	pxor xmm5, xmm3
	movaps %2, xmm5
	pxor xmm4, xmm1
	movaps %1, xmm4
%endmacro

%macro sbox7 4
	movaps tmp_at(1), xmm0
	movaps tmp_at(3), xmm4
	movaps xmm0, xmm4
	pxor xmm4, xmm3
	movaps tmp_at(4), xmm5
	movaps xmm7, xmm4
	movaps tmp_at(2), xmm3
	pxor xmm4, xmm2
	movaps tmp_at(5), xmm4
	pand xmm4, xmm5
	movaps xmm5, xmm7
	pxor xmm5, tmp_at(4)
	pand xmm7, xmm3
	movaps tmp_at(6), xmm7
	movaps xmm6, xmm7
	pxor xmm7, xmm1
	pand xmm6, tmp_at(4)
	pxor xmm6, xmm2
	movaps tmp_at(7), xmm7
	movaps xmm3, tmp_at(1)
	movaps xmm0, xmm6
	por xmm6, xmm7
	pand xmm7, xmm4
	pxor xmm6, xmm5
	pandn xmm7, xmm3
	pxor xmm0, xmm4
	pxor xmm7, %4
	pxor xmm4, xmm5
	pxor xmm7, xmm6
	movaps %4, xmm7
	pandn xmm4, tmp_at(2)
	por xmm6, tmp_at(6)
	movaps xmm7, tmp_at(5)
	pandn xmm7, tmp_at(3)
	pandn xmm4, tmp_at(7)
	movaps tmp_at(9), xmm7
	por xmm7, tmp_at(7)
	pandn xmm5, tmp_at(5)
	pxor xmm7, xmm0
	pxor xmm0, tmp_at(3)
	pxor xmm0, xmm4
	movaps xmm4, tmp_at(1)
	pand xmm2, xmm0
	por xmm6, xmm2
	pxor xmm6, xmm5
	pandn xmm3, xmm6
	movaps xmm5, xmm6
	pxor xmm3, xmm7
	pxor xmm7, xmm6
	por xmm6, xmm0
	pxor xmm3, %1
	pand xmm6, tmp_at(4)
	pxor xmm5, pnot
	pand xmm1, xmm6
	pxor xmm0, %3
	pxor xmm1, xmm7
	movaps %1, xmm3
	movaps xmm3, xmm4
	pxor xmm7, tmp_at(3)
	por xmm2, xmm1
	pxor xmm2, xmm6
	por xmm7, xmm2
	pand xmm4, xmm7
	pxor xmm7, xmm6
	por xmm7, tmp_at(9)
	pxor xmm7, xmm5
	pxor xmm1, %2
	pandn xmm3, xmm7
	pxor xmm0, xmm4
	movaps %3, xmm0
	pxor xmm1, xmm3
	movaps %2, xmm1
%endmacro

%macro sbox8 4
	movaps xmm7, xmm2
	movaps tmp_at(1), xmm1
	pandn xmm1, xmm2
	movaps tmp_at(2), xmm2
	pandn xmm2, xmm4
	movaps tmp_at(5), xmm5
	pxor xmm2, xmm3
	movaps tmp_at(4), xmm4
	movaps xmm5, xmm1
	movaps tmp_at(3), xmm3
	movaps xmm4, xmm2
	movaps xmm3, xmm2
	pandn xmm4, tmp_at(1)
	pand xmm2, xmm0
	pandn xmm7, tmp_at(1)
	pandn xmm1, xmm2
	pxor xmm7, tmp_at(4)
	movaps xmm6, xmm4
	por xmm4, xmm0
	movaps tmp_at(6), xmm7
	pand xmm7, xmm4
	pxor xmm3, pnot
	por xmm2, xmm7
	pxor xmm3, xmm7
	pandn xmm4, tmp_at(2)
	movaps xmm7, tmp_at(5)
	pxor xmm3, xmm4
	por xmm7, xmm1
	pxor xmm5, xmm3
	pxor xmm7, xmm5
	pxor xmm5, xmm0
	pxor xmm7, %2
	movaps %2, xmm7
	pxor xmm3, tmp_at(1)
	movaps xmm4, xmm5
	pand xmm5, tmp_at(4)
	pxor xmm5, xmm3
	por xmm3, tmp_at(3)
	pxor xmm6, xmm5
	pxor xmm3, tmp_at(6)
	pxor xmm5, xmm2
	pxor xmm3, xmm6
	por xmm5, tmp_at(1)
	pxor xmm0, xmm3
	pxor xmm5, xmm4
	por xmm4, tmp_at(3)
	pxor xmm5, tmp_at(4)
	pand xmm2, tmp_at(5)
	pandn xmm4, xmm5
	pand xmm0, tmp_at(5)
	pxor xmm0, xmm6
	por xmm4, xmm1
	pxor xmm0, %4
	pxor xmm3, xmm4
	pxor xmm2, %3
	por xmm3, tmp_at(5)
	pxor xmm3, %1
	pxor xmm2, xmm5
	pxor xmm3, xmm6
	movaps %4, xmm0
	movaps %3, xmm2
	movaps %1, xmm3
%endmacro



section .text
	_DES_Crypt25_x86_SSE2:
		push ebp
		mov ebp, esp
		; sub  esp, 4
		push ebx
		push esi
		push edi

		mov ecx, [ebp + 8]
		lea data_blocks_address, [ecx + data_blocks_offset]

		pcmpeqd xmm0, xmm0
		movaps  pnot, xmm0

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
		pop edi
		pop esi
		pop ebx
		mov esp, ebp
		pop ebp
		ret
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00



	_TestASM:
		push ebp
		mov  ebp, esp
		; sub  esp, 4
		push ebx
		push esi
		push edi

		; ======================================
		
		jmp skip
		movaps xmm0, [data_blocks_address + 0xffffffff]
		movaps xmm1, [data_blocks_address + 0xffffffff]
		movaps xmm2, [data_blocks_address + 0xffffffff]
		movaps xmm3, [data_blocks_address + 0xffffffff]
		movaps xmm4, [data_blocks_address + 0xffffffff]
		movaps xmm0, [data_blocks_address + 0xffffffff]
	skip:

		; ======================================

		pop edi
		pop esi
		pop ebx
		mov esp, ebp
		pop ebp
		ret
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00
