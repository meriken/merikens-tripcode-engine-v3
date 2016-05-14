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

global _DES_Crypt25_x86_AVX
global _IsAVXSupported
global __myxgetbv



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
	movzx   eax,  byte [ecx + %1]
	vmovdqa xmm0, [data_blocks_address + eax * 8]
	movzx   eax,  byte [ecx + %2]
	vmovdqa xmm1, [data_blocks_address + eax * 8]
	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]

	movzx   eax,  byte [ecx + %3]
	vmovdqa xmm2, [data_blocks_address + eax * 8]
	movzx   eax,  byte [ecx + %4]
	vmovdqa xmm3, [data_blocks_address + eax * 8]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]

	movzx   eax,  byte [ecx + %5]
	vmovdqa xmm4, [data_blocks_address + eax * 8]
	movzx   eax,  byte [ecx + %6]
	vmovdqa xmm5, [data_blocks_address + eax * 8]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

; "0xffffffff" will be rewritten in DES_SetSalt() based on context->expansionFunction[].
%macro prepare_args_for_sbox_x_with_rewrites 6
	vmovdqa xmm0, [data_blocks_address + 0xffffffff]
	vmovdqa xmm1, [data_blocks_address + 0xffffffff]
	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %1 * 16]
	vmovdqa xmm2, [data_blocks_address + 0xffffffff]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	vmovdqa xmm3, [data_blocks_address + 0xffffffff]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %3 * 16]
	vmovdqa xmm4, [data_blocks_address + 0xffffffff]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	vmovdqa xmm5, [data_blocks_address + 0xffffffff]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %5 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
%endmacro

%macro prepare_args_for_sbox_y 12
	; 12 ops
	vmovdqa xmm0, [data_blocks_address + %1 * 16]
	vmovdqa xmm1, [data_blocks_address + %3 * 16]
	vpxor   xmm0, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %2 * 16]
	vmovdqa xmm2, [data_blocks_address + %5 * 16]
	vpxor   xmm1, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %4 * 16]
	vmovdqa xmm3, [data_blocks_address + %7 * 16]
	vpxor   xmm2, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %6 * 16]
	vmovdqa xmm4, [data_blocks_address + %9 * 16]
	vpxor   xmm3, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %8 * 16]
	vmovdqa xmm5, [data_blocks_address + %11 * 16]
	vpxor   xmm4, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %10 * 16]
	vpxor   xmm5, [expanded_key_schedule_address + key_schedule_index_base_x2 * 8 + %12 * 16]
%endmacro

%macro sbox1 4
	vmovdqa tmp_at(1), xmm0                 ; [X]
	vmovdqa tmp_at(4), xmm4                 ; [X]
	vmovdqa tmp_at(2), xmm1                 ; [X]
	vpor    xmm7,      xmm5,      xmm2
	vmovdqa tmp_at(3), xmm3                 ; [X]
	vpxor   xmm6,      xmm2,      xmm0
	vmovdqa tmp_at(5), xmm7                 ; [X]
	vpandn  xmm4,      xmm0
	vpand   xmm1,      xmm6,      xmm7
	vpor    xmm7,      xmm1,      xmm5
	vpxor   xmm1,      xmm3
	vpxor   xmm3,      xmm4
	vmovdqa tmp_at(6), xmm1                 ; [X]
	vmovdqa xmm1,      xmm3                 ; [X]
	vpandn  xmm3,      tmp_at(6)
	vmovdqa tmp_at(7), xmm3                 ; [X]
	vpxor   xmm3,      xmm5,      tmp_at(4)
	vpor    xmm5,      xmm0
	vmovdqa tmp_at(8), xmm3                 ; [X]
	vpandn  xmm6,      xmm3
	vpxor   xmm3,      xmm2
	vpandn  xmm4,      xmm2
	vpandn  xmm3,      xmm1
	vpxor   xmm7,      xmm3
	vpor    xmm0,      xmm5,      xmm7
	vmovdqa xmm3,      tmp_at(7)            ; [X]
	vpandn  xmm5,      tmp_at(3)
	vpandn  xmm3,      xmm7
	vmovdqa tmp_at(9), xmm3                 ; [X]
	vpand   xmm7,      tmp_at(5)
	vmovdqa xmm3,      tmp_at(6)            ; [X]
	vpxor   xmm2,      xmm0,      xmm1
	vpandn  xmm3,      tmp_at(4)
	vpandn  xmm4,      xmm2
	vpxor   xmm7,      xmm4
	vpxor   xmm4,      tmp_at(8)
	vpxor   xmm5,      xmm3
	vpor    xmm4,      xmm3
	vpxor   xmm4,      tmp_at(1)
	vpxor   xmm3,      xmm0
	vmovdqa xmm2,      tmp_at(2)            ; [X]
	vpandn  xmm2,      xmm3
	vpxor   xmm0,      tmp_at(5)
	vmovdqa xmm3,      tmp_at(7)            ; [X]
	vpor    xmm3,      tmp_at(2)
	vpxor   xmm7,      pnot
	vpxor   xmm3,      %1
	vpxor   xmm2,      xmm7
	vpxor   xmm4,      tmp_at(5)
	vpxor   xmm2,      %3
	vpxor   xmm7,      xmm4
	vpxor   xmm3,      xmm7
	vmovdqa %1,        xmm3                 ; [X]
	vpor    xmm5,      xmm6
	vpor    xmm7,      tmp_at(8)
	vpor    xmm0,      xmm5
	vpxor   xmm7,      %2
	vpxor   xmm0,      xmm4
	vpxor   xmm7,      xmm0
	vpor    xmm1,      tmp_at(4)
	vpand   xmm4,      tmp_at(9)
	vpandn  xmm0,      xmm1
	vpxor   xmm4,      xmm0
	vmovdqa xmm3,      tmp_at(2)            ; [X]
	vpor    xmm3,      tmp_at(9)
	vpor    xmm4,      tmp_at(2)
	vmovdqa %3,        xmm2                 ; [X]
	vpxor   xmm7,      xmm3
	vpxor   xmm4,      xmm5
	vpxor   xmm4,      %4
	vmovdqa %2,        xmm7                 ; [X]
	vmovdqa %4,        xmm4                 ; [X]
%endmacro

%macro sbox2 4
	vmovdqa tmp_at(2), xmm2                 ; [X]
	vmovdqa tmp_at(1), xmm1                 ; [X]
	vpandn  xmm2,      xmm5,      xmm0
	vmovdqa tmp_at(4), xmm4                 ; [X]
	vmovdqa tmp_at(3), xmm3                 ; [X]
	vpandn  xmm2,      xmm4
	vmovdqa xmm6,      xmm0                 ; [X]
	vpxor   xmm0,      pnot
	vpor    xmm7,      xmm2,      xmm1
	vpxor   xmm1,      xmm4
	vmovdqa tmp_at(5), xmm7                 ; [X]
	vpand   xmm6,      xmm1
	vpxor   xmm6,      xmm4
	vpandn  xmm7,      xmm5,      xmm1
	vpxor   xmm2,      xmm7
	vpandn  xmm7,      xmm6
	vpxor   xmm1,      xmm5
	vmovdqa tmp_at(7), xmm7                 ; [X]
	vmovdqa xmm7,      xmm5                 ; [X]
	vpand   xmm5,      tmp_at(2)            ; [X]
	vpandn  xmm7,      xmm5,      xmm1
	vmovdqa tmp_at(8), xmm5                 ; [X]
	vpand   xmm2,      tmp_at(5)
	vpandn  xmm5,      xmm2
	vpand   xmm2,      tmp_at(2)
	vpandn  xmm5,      tmp_at(3)
	vpxor   xmm0,      xmm2
	vpandn  xmm4,      xmm3,      tmp_at(5)
	vpxor   xmm3,      xmm7,      xmm0
	vpxor   xmm5,      %2
	vpandn  xmm7,      tmp_at(1)
	vpxor   xmm7,      xmm6
	vpxor   xmm5,      xmm3
	vmovdqa %2,        xmm5                 ; [X]
	vpandn  xmm6,      xmm7,      xmm0
	vpxor   xmm3,      tmp_at(5)
	vpxor   xmm6,      xmm4
	vpxor   xmm0,      xmm1,      tmp_at(2)
	vpxor   xmm6,      xmm0
	vmovdqa xmm4,      xmm0                 ; [X]
	vpxor   xmm6,      %1
	vpandn  xmm0,      tmp_at(1)
	vpxor   xmm2,      tmp_at(4)
	vpxor   xmm0,      xmm3
	vmovdqa %1,        xmm6                 ; [X]
	vpor    xmm3,      xmm1
	vpor    xmm0,      tmp_at(8)
	vpxor   xmm0,      xmm4
	vmovdqa xmm4,      xmm0                 ; [X]
	vpandn  xmm0,      tmp_at(2)
	vmovdqa xmm6,      tmp_at(3)            ; [X]
	vpxor   xmm0,      tmp_at(7)
	vpor    xmm0,      xmm7
	vpor    xmm5,      xmm6,      tmp_at(7)
	vpxor   xmm2,      xmm0
	vpandn  xmm7,      xmm2
	vpor    xmm6,      xmm2
	vpxor   xmm7,      %4
	vpxor   xmm6,      xmm4
	vpxor   xmm6,      %3
	vpxor   xmm7,      xmm5
	vpxor   xmm7,      xmm3
	vmovdqa %3,        xmm6                 ; [X]
	vmovdqa %4,        xmm7                 ; [X]
%endmacro

%macro sbox3 4
	vmovdqa tmp_at(1), xmm0                 ; [X]
	vmovdqa tmp_at(2), xmm1                 ; [X]
	vmovdqa xmm7,      xmm0                 ; [X]
	vpandn  xmm1,      xmm0
	vmovdqa tmp_at(3), xmm2                 ; [X]
	vpxor   xmm0,      xmm5,     xmm2
	vmovdqa tmp_at(4), xmm4                 ; [X]
	vpxor   xmm2,      xmm5,     xmm3
	vpor    xmm1,      xmm0
	vpxor   xmm4,      xmm0,     tmp_at(2)
	vpandn  xmm7,      xmm2
	vmovdqa tmp_at(5), xmm7                 ; [X]
	vpxor   xmm7,      xmm1
	vpandn  xmm6,      xmm5,     xmm4
	vmovdqa tmp_at(6), xmm7                 ; [X]
	vpxor   xmm1,      xmm6
	vpand   xmm2,      xmm0
	vpxor   xmm0,      xmm3,     tmp_at(1)
	vpandn  xmm6,      xmm1,     xmm7
	vpand   xmm7,      xmm5
	vpand   xmm5,      xmm3
	vpor    xmm7,      xmm3
	vpand   xmm7,      tmp_at(1)
	vmovdqa xmm3,      tmp_at(4)            ; [X]
	vpandn  xmm3,      tmp_at(6)
	vpxor   xmm7,      xmm4
	vmovdqa tmp_at(7), xmm7                 ; [X]
	vpxor   xmm7,      xmm3
	vmovdqa xmm3,      tmp_at(2)            ; [X]
	vpxor   xmm7,      %4
	vpxor   xmm1,      xmm0
	vmovdqa %4,        xmm7                 ; [X]
	vmovdqa xmm7,      tmp_at(3)            ; [X]
	vpor    xmm1,      tmp_at(3)
	vpandn  xmm2,      xmm1
	vpor    xmm0,      tmp_at(5)
	vpandn  xmm1,      xmm0,      tmp_at(7)
	vpandn  xmm3,      xmm5
	vpor    xmm5,      xmm4
	vpxor   xmm1,      xmm3
	vpor    xmm7,      tmp_at(2)
	vmovdqa xmm3,      tmp_at(3)            ; [X]
	vpandn  xmm3,      xmm1
	vpxor   xmm0,      xmm4
	vpandn  xmm3,      xmm5
	vpxor   xmm3,      tmp_at(1)
	vpand   xmm5,      xmm2,     tmp_at(4)
	vpxor   xmm0,      pnot
	vpxor   xmm3,      xmm5
	vpxor   xmm5,      xmm7,     tmp_at(6)
	vpxor   xmm3,      %2
	vpandn  xmm6,      tmp_at(4)
	vpandn  xmm7,      tmp_at(6)
	vpxor   xmm6,      xmm0
	vmovdqa %2,        xmm3                 ; [X]
	vpxor   xmm2,      tmp_at(1)
	vpor    xmm1,      tmp_at(4)
	vpor    xmm0,      xmm2
	vpxor   xmm0,      xmm1
	vpxor   xmm6,      %1
	vpxor   xmm5,      %3
	vpxor   xmm0,      tmp_at(7)
	vpxor   xmm6,      xmm7
	vpxor   xmm0,      xmm5
	vmovdqa %1,        xmm6                 ; [X]
	vmovdqa %3,        xmm0                 ; [X]
%endmacro

%macro sbox4 4
	vmovdqa xmm7,      xmm1                 ; [X]
	vpxor   xmm0,      xmm2
	vpor    xmm1,      xmm3
	vpxor   xmm2,      xmm4
	vmovdqa tmp_at(2), xmm5                 ; [X]
	vpxor   xmm1,      xmm4
	vmovdqa xmm6,      xmm7                 ; [X]
	vmovdqa xmm5,      xmm7                 ; [X]
	vpandn  xmm7,      xmm2
	vpandn  xmm1,      xmm2
	vpor    xmm4,      xmm7
	vpxor   xmm7,      xmm3
	vmovdqa xmm6,      xmm7                 ; [X]
	vpor    xmm7,      xmm0
	vpxor   xmm3,      xmm5
	vmovdqa tmp_at(3), xmm1                 ; [X]
	vpandn  xmm1,      xmm7
	vmovdqa xmm7,      xmm1                 ; [X]
	vpxor   xmm1,      xmm5
	vpand   xmm6,      xmm1
	vmovdqa xmm5,      xmm6                 ; [X]
	vpxor   xmm0,      xmm1
	vpandn  xmm6,      xmm2
	vpandn  xmm6,      xmm0
	vpxor   xmm4,      xmm0
	vmovdqa xmm0,      xmm3                 ; [X]
	vpandn  xmm3,      xmm4
	vmovdqa xmm2,      tmp_at(2)            ; [X]
	vpxor   xmm3,      xmm7
	vpxor   xmm6,      tmp_at(3)
	vmovdqa xmm7,      xmm6                 ; [X]
	vpandn  xmm6,      xmm2
	vpxor   xmm6,      %1
	vpandn  xmm2,      xmm7
	vpxor   xmm2,      %2
	vpxor   xmm6,      xmm3
	vpxor   xmm3,      pnot
	vpxor   xmm2,      xmm3
	vpxor   xmm3,      xmm7
	vmovdqa %1,        xmm6                 ; [X]
	vpandn  xmm0,      xmm3
	vpor    xmm0,      xmm5
	vmovdqa %2,        xmm2                 ; [X]
	vpor    xmm3,      xmm1,      tmp_at(2)
	vpand   xmm1,      tmp_at(2)
	vpxor   xmm0,      xmm4
	vpxor   xmm3,      xmm0
	vpxor   xmm3,      %3
	vpxor   xmm0,      xmm1
	vmovdqa %3,        xmm3                 ; [X]
	vpxor   xmm0,      %4
	vmovdqa %4,        xmm0                 ; [X]
%endmacro

%macro sbox5 4
	vmovdqa tmp_at(3), xmm2                 ; [X]
	vmovdqa tmp_at(1), xmm0                 ; [X]
	vpor    xmm2,      xmm0
	vmovdqa xmm6,      xmm5                 ; [X]
	vmovdqa tmp_at(4), xmm2                 ; [X]
	vpandn  xmm5,      xmm2
	vmovdqa xmm7,      xmm2                 ; [X]
	vmovdqa xmm2,      xmm5                 ; [X]
	vpxor   xmm5,      xmm0
	vmovdqa xmm7,      xmm3                 ; [X]
	vmovdqa tmp_at(5), xmm5                 ; [X]
	vpxor   xmm5,      tmp_at(3)
	vmovdqa tmp_at(2), xmm1                 ; [X]
	vpor    xmm0,      xmm5
	vpor    xmm5,      xmm3
	vpandn  xmm3,      xmm2
	vpxor   xmm3,      tmp_at(3)
	vmovdqa tmp_at(6), xmm3                 ; [X]
	vpand   xmm1,      xmm0,      tmp_at(6)
	vpand   xmm3,      xmm4
	vpxor   xmm3,      xmm0
	vpand   xmm0,      xmm7
	vpxor   xmm3,      xmm7
	vmovdqa tmp_at(3), xmm3                 ; [X]
	vpxor   xmm6,      xmm3
	vmovdqa xmm2,      xmm6                 ; [X]
	vpor    xmm6,      tmp_at(5)
	vmovdqa xmm3,      xmm6                 ; [X]
	vpand   xmm6,      xmm4
	vmovdqa tmp_at(7), xmm6                 ; [X]
	vpxor   xmm6,      tmp_at(5)
	vpxor   xmm0,      xmm6
	vmovdqa xmm6,      tmp_at(1)            ; [X]
	vmovdqa tmp_at(8), xmm0                 ; [X]
	vpandn  xmm6,      xmm3
	vmovdqa xmm0,      tmp_at(2)            ; [X]
	vpxor   xmm4,      xmm5
	vpxor   xmm3,      xmm6,      xmm4
	vpxor   xmm6,      tmp_at(6)
	vpandn  xmm6,      xmm4
	vpxor   xmm6,      pnot
	vpandn  xmm0,      xmm6
	vpxor   xmm0,      tmp_at(3)
	vmovdqa xmm6,      tmp_at(7)            ; [X]
	vpandn  xmm6,      tmp_at(6)
	vpxor   xmm0,      %3
	vmovdqa %3,        xmm0                 ; [X]
	vpor    xmm3,      tmp_at(8)
	vpxor   xmm0,      xmm5,      tmp_at(6)
	vpandn  xmm6,      xmm3
	vpand   xmm2,      xmm6
	vpxor   xmm3,      xmm6,      tmp_at(4)
	vpandn  xmm6,      xmm5
	vpxor   xmm2,      xmm4
	vpor    xmm1,      xmm2
	vpxor   xmm1,      tmp_at(7)
	vpand   xmm7,      xmm2
	vpand   xmm1,      tmp_at(2)
	vpxor   xmm7,      tmp_at(1)
	vpxor   xmm1,      tmp_at(8)
	vpxor   xmm3,      xmm7
	vpor    xmm6,      tmp_at(2)
	vpxor   xmm1,      %4
	vmovdqa %4,        xmm1                 ; [X]
	vpxor   xmm2,      tmp_at(5)
	vpxor   xmm6,      xmm3
	vpandn  xmm3,      xmm0
	vpand   xmm5,      tmp_at(2)
	vpxor   xmm3,      xmm2
	vpxor   xmm5,      %2
	vpxor   xmm3,      xmm5
	vpxor   xmm6,      %1
	vmovdqa %2,        xmm3                 ; [X]
	vmovdqa %1,        xmm6                 ; [X]
%endmacro

%macro sbox6 4
	vmovdqa tmp_at(2), xmm4                 ; [X]
	vpxor   xmm4,      xmm1
	vmovdqa tmp_at(3), xmm5                 ; [X]
	vpor    xmm5,      xmm1
	vmovdqa xmm7,      xmm2                 ; [X]
	vpand   xmm5,      xmm0
	vpxor   xmm2,      xmm0
	vmovdqa tmp_at(1), xmm0                 ; [X]
	vpxor   xmm4,      xmm5
	vmovdqa tmp_at(4), xmm4                 ; [X]
	vpxor   xmm4,      tmp_at(3)
	vpand   xmm6,      xmm4,      xmm0
	vpandn  xmm4,      tmp_at(2)
	vmovdqa tmp_at(5), xmm6                 ; [X]
	vpxor   xmm6,      xmm1
	vmovdqa tmp_at(6), xmm6                 ; [X]
	vpor    xmm6,      xmm2
	vmovdqa tmp_at(7), xmm6                 ; [X]
	vpxor   xmm6,      tmp_at(4)
	vmovdqa xmm0,      xmm6                 ; [X]
	vpand   xmm6,      xmm7
	vmovdqa tmp_at(8), xmm6                 ; [X]
	vmovdqa xmm6,      tmp_at(3)            ; [X]
	vpor    xmm2,      xmm1
	vpandn  xmm6,      tmp_at(8)
	vmovdqa tmp_at(9), xmm6                 ; [X]
	vpor    xmm6,      xmm4,      tmp_at(6)
	vmovdqa tmp_at(6), xmm6                 ; [X]
	vpxor   xmm6,      tmp_at(9)
	vmovdqa tmp_at(10),xmm6                 ; [X]
	vpand   xmm6,      xmm3
	vpxor   xmm6,      %4
	vpxor   xmm6,      xmm0
	vpor    xmm0,      tmp_at(1)
	vmovdqa %4,        xmm6                 ; [X]
	vpxor   xmm6,      xmm1,      tmp_at(7)
	vmovdqa tmp_at(7), xmm6                 ; [X]
	vpandn  xmm6,      tmp_at(3)
	vpxor   xmm6,      xmm7
	vmovdqa xmm7,      tmp_at(8)            ; [X]
	vmovdqa tmp_at(12),xmm6                 ; [X]
	vpandn  xmm7,      tmp_at(2)
	vpand   xmm0,      tmp_at(6)
	vpor    xmm7,      xmm6
	vpandn  xmm1,      xmm3,      xmm7
	vpxor   xmm0,      xmm6
	vmovdqa xmm6,      tmp_at(9)            ; [X]
	vpor    xmm4,      xmm3
	vpandn  xmm6,      xmm0
	vpor    xmm5,      xmm7
	vpxor   xmm6,      xmm4
	vpxor   xmm0,      tmp_at(4)
	vpxor   xmm6,      %3
	vpxor   xmm5,      xmm2
	vmovdqa %3,        xmm6                 ; [X]
	vmovdqa xmm6,      tmp_at(5)            ; [X]
	vpandn  xmm0,      tmp_at(2)
	vpxor   xmm2,      pnot
	vpxor   xmm2,      tmp_at(7)
	vpxor   xmm6,      tmp_at(3)
	vpxor   xmm5,      %2
	vmovdqa xmm4,      tmp_at(12)           ; [X]
	vpxor   xmm0,      xmm2
	vpxor   xmm4,      tmp_at(1)
	vpxor   xmm5,      tmp_at(10)
	vpand   xmm4,      xmm6
	vpandn  xmm3,      xmm0
	vpxor   xmm4,      %1
	vpxor   xmm4,      tmp_at(8)
	vpxor   xmm1,      xmm2
	vpxor   xmm5,      xmm3
	vmovdqa %2,        xmm5                 ; [X]
	vpxor   xmm4,      xmm1
	vmovdqa %1,        xmm4                 ; [X]
%endmacro

%macro sbox7 4
	vmovdqa tmp_at(1), xmm0                 ; [X]
	vmovdqa tmp_at(3), xmm4                 ; [X]
	vmovdqa xmm0,      xmm4                 ; [X]
	vpxor   xmm4,      xmm3
	vmovdqa tmp_at(4), xmm5                 ; [X]
	vmovdqa xmm7,      xmm4                 ; [X]
	vmovdqa tmp_at(2), xmm3                 ; [X]
	vpxor   xmm4,      xmm2
	vmovdqa tmp_at(5), xmm4                 ; [X]
	vpand   xmm4,      xmm5
	vpxor   xmm5,      xmm7,      tmp_at(4)
	vpand   xmm7,      xmm3
	vmovdqa tmp_at(6), xmm7                 ; [X]
	vpand   xmm6,      xmm7,      tmp_at(4)
	vpxor   xmm7,      xmm1
	vpxor   xmm6,      xmm2
	vmovdqa tmp_at(7), xmm7                 ; [X]
	vmovdqa xmm3,      tmp_at(1)            ; [X]
	vpxor   xmm0,      xmm6,      xmm4
	vpor    xmm6,      xmm7
	vpand   xmm7,      xmm4
	vpxor   xmm6,      xmm5
	vpandn  xmm7,      xmm3
	vpxor   xmm7,      %4
	vpxor   xmm4,      xmm5
	vpxor   xmm7,      xmm6
	vmovdqa %4,        xmm7                 ; [X]
	vpandn  xmm4,      tmp_at(2)
	vpor    xmm6,      tmp_at(6)
	vmovdqa xmm7,      tmp_at(5)            ; [X]
	vpandn  xmm7,      tmp_at(3)
	vpandn  xmm4,      tmp_at(7)
	vmovdqa tmp_at(9), xmm7                 ; [X]
	vpor    xmm7,      tmp_at(7)
	vpandn  xmm5,      tmp_at(5)
	vpxor   xmm7,      xmm0
	vpxor   xmm0,      tmp_at(3)
	vpxor   xmm0,      xmm4
	vmovdqa xmm4,      tmp_at(1)            ; [X]
	vpand   xmm2,      xmm0
	vpor    xmm6,      xmm2
	vpxor   xmm6,      xmm5
	vpandn  xmm3,      xmm6
	vmovdqa xmm5,      xmm6                 ; [X]
	vpxor   xmm3,      xmm7
	vpxor   xmm7,      xmm6
	vpor    xmm6,      xmm0
	vpxor   xmm3,      %1
	vpand   xmm6,      tmp_at(4)
	vpxor   xmm5,      pnot
	vpand   xmm1,      xmm6
	vpxor   xmm0,      %3
	vpxor   xmm1,      xmm7
	vmovdqa %1,        xmm3                 ; [X]
	vmovdqa xmm3,      xmm4                 ; [X]
	vpxor   xmm7,      tmp_at(3)
	vpor    xmm2,      xmm1
	vpxor   xmm2,      xmm6
	vpor    xmm7,      xmm2
	vpand   xmm4,      xmm7
	vpxor   xmm7,      xmm6
	vpor    xmm7,      tmp_at(9)
	vpxor   xmm7,      xmm5
	vpxor   xmm1,      %2
	vpandn  xmm3,      xmm7
	vpxor   xmm0,      xmm4
	vmovdqa %3,        xmm0                 ; [X]
	vpxor   xmm1,      xmm3
	vmovdqa %2,        xmm1                 ; [X]
%endmacro

%macro sbox8 4
	vpandn  xmm7,      xmm2,      xmm1
	vmovdqa tmp_at(1), xmm1                 ; [X]
	vpandn  xmm1,      xmm2
	vmovdqa tmp_at(2), xmm2                 ; [X]
	vpandn  xmm2,      xmm4
	vmovdqa tmp_at(5), xmm5                 ; [X]
	vpxor   xmm2,      xmm3
	vmovdqa tmp_at(4), xmm4                 ; [X]
	vmovdqa xmm5,      xmm1                 ; [X]
	vmovdqa tmp_at(3), xmm3                 ; [X]
	vpxor   xmm3,      xmm2,      pnot
	vpandn  xmm4,      xmm2,      tmp_at(1)  
	vpand   xmm2,      xmm0
	vpandn  xmm1,      xmm2
	vpxor   xmm7,      tmp_at(4)
	vmovdqa xmm6,      xmm4                 ; [X]
	vpor    xmm4,      xmm0
	vmovdqa tmp_at(6), xmm7                 ; [X]
	vpand   xmm7,      xmm4
	vpor    xmm2,      xmm7
	vpxor   xmm3,      xmm7
	vpandn  xmm4,      tmp_at(2)
	vpxor   xmm3,      xmm4
	vpor    xmm7,      xmm1,      tmp_at(5)
	vpxor   xmm5,      xmm3
	vpxor   xmm7,      xmm5
	vpxor   xmm5,      xmm0
	vpxor   xmm7,      %2
	vmovdqa %2,        xmm7                 ; [X]
	vpxor   xmm3,      tmp_at(1)
	vmovdqa xmm4,      xmm5                 ; [X]
	vpand   xmm5,      tmp_at(4)
	vpxor   xmm5,      xmm3
	vpor    xmm3,      tmp_at(3)
	vpxor   xmm6,      xmm5
	vpxor   xmm3,      tmp_at(6)
	vpxor   xmm5,      xmm2
	vpxor   xmm3,      xmm6
	vpor    xmm5,      tmp_at(1)
	vpxor   xmm0,      xmm3
	vpxor   xmm5,      xmm4
	vpor    xmm4,      tmp_at(3)
	vpxor   xmm5,      tmp_at(4)
	vpand   xmm2,      tmp_at(5)
	vpandn  xmm4,      xmm5
	vpand   xmm0,      tmp_at(5)
	vpxor   xmm0,      xmm6
	vpor    xmm4,      xmm1
	vpxor   xmm0,      %4
	vpxor   xmm3,      xmm4
	vpxor   xmm2,      %3
	vpor    xmm3,      tmp_at(5)
	vpxor   xmm3,      %1
	vpxor   xmm2,      xmm5
	vpxor   xmm3,      xmm6
	vmovdqa %4,        xmm0                 ; [X]
	vmovdqa %3,        xmm2                 ; [X]
	vmovdqa %1,        xmm3                 ; [X]
%endmacro



section .text
	_DES_Crypt25_x86_AVX:
		push ebp
		mov ebp, esp
		; sub  esp, 4
		push ebx
		push esi
		push edi

		mov ecx, [ebp + 8]
		lea data_blocks_address, [ecx + data_blocks_offset]

		pcmpeqd xmm0, xmm0
		vmovdqa pnot, xmm0

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



		; int IsAVXSupported();
	_IsAVXSupported:
		push ebx
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
		pop ebx
		ret
	AVX_not_supported:
		xor eax, eax
		pop ebx
		ret



	__myxgetbv:
		push ebp
		mov ebp, esp

		mov ecx, [ebp + 8]
		xgetbv

		mov esp, ebp
		pop ebp
		ret

