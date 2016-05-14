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
; The code that deals with SHA-1 hash generati8on is partially adopted from:
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

global DES_Crypt25_x64_AVX2



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define iterations                           rsi

%define data_blocks_source_address           rbx
%define data_blocks_destination_address      rdx

%define expanded_key_schedule_address        (rcx + expanded_key_schedule_offset)

%define vector_size 32

%define expansion_function_offset    0
%define expanded_key_schedule_offset (expansion_function_offset    + 96)
%define data_blocks_offset           (expanded_key_schedule_offset + 0x300 * vector_size)
%define temp_offset                  (data_blocks_offset           + 64    * vector_size)
%define keys_offset                  (temp_offset                  + 13    * vector_size)

%define data_blocks_destination(i) [data_blocks_destination_address + (i) * vector_size]
%define keys(i)                    [rcx + keys_offset               + (i) * vector_size]

%macro sbox1 4
	; From STF
	vpandn  ymm12, ymm4, ymm0
    vpxor   ymm9, ymm12, ymm3
    vpor    ymm15, ymm2, ymm5
    vpxor   ymm6, ymm0, ymm2
    vpand   ymm11, ymm15, ymm6
    vpxor   ymm7, ymm11, ymm3
    vpandn  ymm13, ymm9, ymm7
    vpandn  ymm10, ymm7, ymm4
    vpxor   ymm14, ymm4, ymm5
    vpxor   ymm8, ymm14, ymm2
    vpandn  ymm8, ymm8, ymm9
    vpor    ymm7, ymm11, ymm5
    vpxor   ymm7, ymm8, ymm7
    vpandn  ymm11, ymm13, ymm7
    vpor    ymm8, ymm0, ymm5
    vpor    ymm5, ymm7, ymm8
    vpor    ymm4, ymm9, ymm4
    vpandn  ymm8, ymm8, ymm3
    vpxor   ymm8, ymm10, ymm8
    vpandn  ymm6, ymm6, ymm14
    vpor    ymm3, ymm8, ymm6
    vpandn  ymm8, ymm12, ymm2
    vpxor   ymm6, ymm9, ymm5
    vpandn  ymm9, ymm8, ymm6
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm8, ymm9, ymm6
    vpand   ymm7, ymm15, ymm7
    vpxor   ymm6, ymm8, ymm7
    vpxor   ymm7, ymm10, ymm5
    vpandn  ymm12, ymm1, ymm7
    vpxor   ymm12, ymm12, ymm6
    vpxor   ymm12, ymm12, %3
    vmovdqa %3, ymm12
    vpxor   ymm7, ymm14, ymm9
    vpor    ymm7, ymm10, ymm7
    vpxor   ymm7, ymm15, ymm7
    vpxor   ymm0, ymm7, ymm0
    vpxor   ymm2, ymm6, ymm0
    vpor    ymm13, ymm13, ymm1
    vpxor   ymm13, ymm13, ymm2
    vpxor   ymm13, ymm13, %1
    vmovdqa %1, ymm13
    vpxor   ymm15, ymm15, ymm5
    vpor    ymm15, ymm15, ymm3
    vpxor   ymm15, ymm15, ymm0
    vpor    ymm7, ymm14, ymm2
    vpxor   ymm7, ymm15, ymm7
    vpor    ymm14, ymm11, ymm1
    vpxor   ymm14, ymm14, ymm7
    vpxor   ymm14, ymm14, %2
    vmovdqa %2, ymm14
    vpandn  ymm15, ymm15, ymm4
    vpand   ymm7, ymm11, ymm0
    vpxor   ymm15, ymm15, ymm7
    vpor    ymm15, ymm15, ymm1
    vpxor   ymm15, ymm15, ymm3
    vpxor   ymm15, ymm15, %4
    vmovdqa %4, ymm15
%endmacro

%macro sbox2 4
	; From STF
    vpxor   ymm13, ymm1, ymm4
    vpandn  ymm12, ymm5, ymm0
    vpandn  ymm12, ymm12, ymm4
    vpor    ymm10, ymm12, ymm1
    vpandn  ymm6, ymm5, ymm13
    vpand   ymm7, ymm13, ymm0
    vpxor   ymm7, ymm7, ymm4
    vpxor   ymm12, ymm12, ymm6
    vpandn  ymm15, ymm6, ymm7
    vpand   ymm14, ymm2, ymm5
    vpand   ymm6, ymm10, ymm12
    vpandn  ymm12, ymm14, ymm6
    vpand   ymm8, ymm2, ymm6
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm0, ymm0, ymm6
    vpxor   ymm6, ymm8, ymm0
    vpxor   ymm4, ymm8, ymm4
    vpxor   ymm5, ymm13, ymm5
    vpandn  ymm8, ymm14, ymm5
    vpxor   ymm0, ymm8, ymm6
    vpandn  ymm12, ymm12, ymm3
    vpxor   ymm12, ymm12, ymm0
    vpxor   ymm12, ymm12, %2
    vmovdqa %2, ymm12
    vpandn  ymm8, ymm8, ymm1
    vpxor   ymm12, ymm8, ymm7
    vpandn  ymm7, ymm12, ymm6
    vpxor   ymm11, ymm2, ymm5
    vpxor   ymm7, ymm11, ymm7
    vpandn  ymm13, ymm3, ymm10
    vpxor   ymm13, ymm13, ymm7
    vpxor   ymm13, ymm13, %1
    vmovdqa %1, ymm13
    vpandn  ymm7, ymm11, ymm1
    vpxor   ymm13, ymm10, ymm0
    vpxor   ymm7, ymm13, ymm7
    vpor    ymm7, ymm14, ymm7
    vpxor   ymm1, ymm11, ymm7
    vpandn  ymm7, ymm1, ymm2
    vpxor   ymm7, ymm15, ymm7
    vpor    ymm7, ymm12, ymm7
    vpxor   ymm2, ymm7, ymm4
    vpor    ymm14, ymm2, ymm3
    vpxor   ymm14, ymm14, ymm1
    vpxor   ymm14, ymm14, %3
    vmovdqa %3, ymm14
    vpandn  ymm2, ymm12, ymm2
    vpor    ymm7, ymm13, ymm5
    vpxor   ymm2, ymm2, ymm7
    vpor    ymm15, ymm15, ymm3
    vpxor   ymm15, ymm15, ymm2
    vpxor   ymm15, ymm15, %4
    vmovdqa %4, ymm15
%endmacro

%macro sbox3 4
	; From STF
    vpandn  ymm7, ymm11, ymm0
    vpxor   ymm15, ymm2, ymm5
    vpor    ymm12, ymm15, ymm7
    vpxor   ymm7, ymm3, ymm5
    vpandn  ymm6, ymm0, ymm7
    vpand   ymm13, ymm15, ymm7
    vpxor   ymm1, ymm12, ymm6
    vpxor   ymm9, ymm11, ymm15
    vpandn  ymm7, ymm5, ymm9
    vpxor   ymm14, ymm12, ymm7
    vpxor   ymm7, ymm0, ymm3
    vpor    ymm6, ymm6, ymm7
    vpxor   ymm7, ymm14, ymm7
    vpor    ymm7, ymm2, ymm7
    vpandn  ymm10, ymm13, ymm7
    vpand   ymm12, ymm5, ymm1
    vpor    ymm12, ymm12, ymm3
    vpand   ymm12, ymm12, ymm0
    vpxor   ymm7, ymm9, ymm12
    vpandn  ymm12, ymm4, ymm1
    vpxor   ymm12, ymm12, ymm7
    vpxor   ymm12, ymm12, %4
    vmovdqa %4, ymm12
    vpandn  ymm13, ymm14, ymm1
    vpandn  ymm14, ymm6, ymm7
    vpand   ymm3, ymm3, ymm5
    vpandn  ymm5, ymm11, ymm3
    vpxor   ymm14, ymm14, ymm5
    vpor    ymm11, ymm11, ymm2
    vpandn  ymm8, ymm2, ymm14
    vpor    ymm2, ymm9, ymm3
    vpandn  ymm8, ymm8, ymm2
    vpxor   ymm8, ymm8, ymm0
    vpand   ymm2, ymm10, ymm4
    vpxor   ymm2, ymm8, ymm2
    vpxor   ymm2, ymm2, %2
    vmovdqa %2, ymm2
    vpxor   ymm8, ymm9, ymm6
    vpcmpeqd    ymm3, ymm3, ymm3
    vpxor   ymm3, ymm8, ymm3
    vpandn  ymm8, ymm11, ymm1
    vpxor   ymm2, ymm8, ymm3
    vpandn  ymm8, ymm13, ymm4
    vpxor   ymm8, ymm8, ymm2
    vpxor   ymm8, ymm8, %1
    vmovdqa %1, ymm8
    vpxor   ymm0, ymm10, ymm0
    vpor    ymm0, ymm3, ymm0
    vpxor   ymm0, ymm1, ymm0
    vpxor   ymm0, ymm7, ymm0
    vpxor   ymm15, ymm11, ymm0
    vpor    ymm4, ymm14, ymm4
    vpxor   ymm15, ymm15, ymm4
    vpxor   ymm15, ymm15, %3
    vmovdqa %3, ymm15
%endmacro

%macro sbox4 4
	; From STF
    vpxor   ymm8, ymm0, ymm2
    vpxor   ymm2, ymm2, ymm4
    vpor    ymm9, ymm1, ymm3
    vpxor   ymm9, ymm9, ymm4
    vpandn  ymm9, ymm9, ymm2
    vpandn  ymm10, ymm1, ymm2
    vpxor   ymm7, ymm10, ymm3
    vpor    ymm6, ymm8, ymm7
    vpandn  ymm11, ymm9, ymm6
    vpxor   ymm0, ymm11, ymm1
    vpxor   ymm14, ymm1, ymm3
    vpand   ymm7, ymm0, ymm7
    vpandn  ymm6, ymm7, ymm2
    vpxor   ymm1, ymm8, ymm0
    vpandn  ymm6, ymm6, ymm1
    vpxor   ymm2, ymm9, ymm6
    vpor    ymm4, ymm10, ymm4
    vpxor   ymm3, ymm1, ymm4
    vpandn  ymm4, ymm14, ymm3
    vpxor   ymm4, ymm11, ymm4
    vpandn  ymm12, ymm2, ymm5
    vpxor   ymm12, ymm12, ymm4
    vpxor   ymm12, ymm12, %1
    vmovdqa %1, ymm12
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm4, ymm4, ymm6
    vpandn  ymm13, ymm5, ymm2
    vpxor   ymm13, ymm13, ymm4
    vpxor   ymm13, ymm13, %2
    vmovdqa %2, ymm13
    vpxor   ymm4, ymm2, ymm4
    vpandn  ymm4, ymm14, ymm4
    vpor    ymm4, ymm7, ymm4
    vpxor   ymm4, ymm3, ymm4
    vpor    ymm14, ymm0, ymm5
    vpxor   ymm14, ymm14, ymm4
    vpxor   ymm14, ymm14, %3
    vmovdqa %3, ymm14
    vpand   ymm5, ymm0, ymm5
    vpxor   ymm5, ymm4, ymm5
    vpxor   ymm5, ymm5, %4
    vmovdqa %4, ymm5
%endmacro

%macro sbox5 4
	; From STF
    vpor    ymm0, ymm10, ymm2
    vpandn  ymm7, ymm5, ymm0
    vpxor   ymm15, ymm10, ymm7
    vpandn  ymm8, ymm3, ymm7
    vpxor   ymm7, ymm15, ymm2
    vpor    ymm13, ymm7, ymm3
    vpxor   ymm2, ymm8, ymm2
    vpor    ymm11, ymm10, ymm7
    vpand   ymm7, ymm4, ymm2
    vpxor   ymm8, ymm11, ymm7
    vpxor   ymm8, ymm8, ymm3
    vpxor   ymm5, ymm8, ymm5
    vpor    ymm7, ymm15, ymm5
    vpand   ymm6, ymm7, ymm4
    vpandn  ymm14, ymm10, ymm7
    vpxor   ymm12, ymm15, ymm6
    vpand   ymm7, ymm11, ymm3
    vpxor   ymm12, ymm12, ymm7
    vpxor   ymm9, ymm14, ymm2
    vpxor   ymm4, ymm13, ymm4
    vpandn  ymm9, ymm9, ymm4
    vpcmpeqd    ymm7, ymm7, ymm7
    vpxor   ymm7, ymm9, ymm7
    vpandn  ymm7, ymm1, ymm7
    vpxor   ymm7, ymm8, ymm7
    vpxor   ymm7, ymm7, %3
    vmovdqa %3, ymm7
    vpandn  ymm8, ymm6, ymm2
    vpxor   ymm7, ymm14, ymm4
    vpor    ymm7, ymm12, ymm7
    vpandn  ymm8, ymm8, ymm7
    vpxor   ymm0, ymm8, ymm0
    vpxor   ymm14, ymm10, ymm0
    vpand   ymm0, ymm8, ymm5
    vpandn  ymm8, ymm8, ymm13
    vpxor   ymm4, ymm0, ymm4
    vpand   ymm0, ymm11, ymm2
    vpor    ymm0, ymm4, ymm0
    vpxor   ymm0, ymm6, ymm0
    vpand   ymm0, ymm0, ymm1
    vpxor   ymm0, ymm12, ymm0
    vpxor   ymm0, ymm0, %4
    vmovdqa %4, ymm0
    vpand   ymm3, ymm3, ymm4
    vpxor   ymm14, ymm14, ymm3
    vpor    ymm3, ymm8, ymm1
    vpxor   ymm3, ymm14, ymm3
    vpxor   ymm3, ymm3, %1
    vmovdqa %1, ymm3
    vpxor   ymm3, ymm13, ymm2
    vpandn  ymm0, ymm14, ymm3
    vpxor   ymm3, ymm15, ymm4
    vpxor   ymm3, ymm0, ymm3
    vpand   ymm1, ymm13, ymm1
    vpxor   ymm1, ymm1, ymm3
    vpxor   ymm1, ymm1, %2
    vmovdqa %2, ymm1
%endmacro

%macro sbox6 4
	; From STF
    vpxor   ymm7, ymm1, ymm4
    vpor    ymm9, ymm1, ymm5
    vpand   ymm10, ymm9, ymm0
    vpxor   ymm8, ymm10, ymm7
    vpxor   ymm7, ymm8, ymm5
    vpandn  ymm12, ymm7, ymm4
    vpand   ymm7, ymm0, ymm7
    vpxor   ymm6, ymm1, ymm7
    vpxor   ymm9, ymm5, ymm7
    vpxor   ymm13, ymm0, ymm2
    vpor    ymm7, ymm13, ymm6
    vpxor   ymm11, ymm8, ymm7
    vpxor   ymm15, ymm1, ymm7
    vpor    ymm1, ymm13, ymm1
    vpandn  ymm13, ymm15, ymm5
    vpxor   ymm13, ymm13, ymm2
    vpxor   ymm7, ymm13, ymm0
    vpand   ymm9, ymm9, ymm7
    vpand   ymm7, ymm11, ymm2
    vpor    ymm2, ymm12, ymm6
    vpandn  ymm6, ymm5, ymm7
    vpxor   ymm14, ymm6, ymm2
    vpor    ymm0, ymm11, ymm0
    vpand   ymm0, ymm2, ymm0
    vpand   ymm2, ymm14, ymm3
    vpxor   ymm2, ymm11, ymm2
    vpxor   ymm2, ymm2, %4
    vmovdqa %4, ymm2
    vpxor   ymm9, ymm9, ymm7
    vpandn  ymm7, ymm7, ymm4
    vpor    ymm7, ymm13, ymm7
    vpxor   ymm0, ymm13, ymm0
    vpandn  ymm6, ymm6, ymm0
    vpor    ymm2, ymm12, ymm3
    vpxor   ymm2, ymm2, ymm6
    vpxor   ymm2, ymm2, %3
    vmovdqa %3, ymm2
    vpor    ymm10, ymm10, ymm7
    vpxor   ymm2, ymm10, ymm1
    vpxor   ymm10, ymm14, ymm2
    vpxor   ymm8, ymm8, ymm0
    vpandn  ymm8, ymm8, ymm4
    vpxor   ymm15, ymm15, ymm1
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm4, ymm15, ymm6
    vpxor   ymm2, ymm8, ymm4
    vpandn  ymm2, ymm3, ymm2
    vpxor   ymm2, ymm10, ymm2
    vpxor   ymm2, ymm2, %2
    vmovdqa %2, ymm2
    vpxor   ymm1, ymm9, ymm4
    vpandn  ymm3, ymm3, ymm7
    vpxor   ymm3, ymm3, ymm1
    vpxor   ymm3, ymm3, %1
    vmovdqa %1, ymm3
%endmacro

%macro sbox7 4
	; From STF
    vpxor   ymm10, ymm3, ymm4
    vpand   ymm9, ymm10, ymm3
    vpxor   ymm8, ymm10, ymm5
    vpxor   ymm7, ymm10, ymm12
    vpandn  ymm15, ymm7, ymm4
    vpandn  ymm10, ymm8, ymm7
    vpand   ymm7, ymm5, ymm7
    vpxor   ymm2, ymm9, ymm1
    vpand   ymm13, ymm7, ymm2
    vpand   ymm6, ymm9, ymm5
    vpxor   ymm11, ymm12, ymm6
    vpor    ymm6, ymm11, ymm2
    vpxor   ymm6, ymm8, ymm6
    vpandn  ymm14, ymm13, ymm0
    vpxor   ymm14, ymm14, ymm6
    vpxor   ymm14, ymm14, %4
    vmovdqa %4, ymm14
    vpxor   ymm14, ymm8, ymm7
    vpandn  ymm14, ymm14, ymm3
    vpandn  ymm14, ymm14, ymm2
    vpor    ymm2, ymm15, ymm2
    vpxor   ymm11, ymm11, ymm7
    vpxor   ymm13, ymm2, ymm11
    vpxor   ymm11, ymm11, ymm4
    vpxor   ymm14, ymm14, ymm11
    vpor    ymm7, ymm9, ymm6
    vpand   ymm9, ymm14, ymm12
    vpor    ymm2, ymm7, ymm9
    vpxor   ymm7, ymm2, ymm10
    vpandn  ymm2, ymm0, ymm7
    vpxor   ymm2, ymm2, ymm13
    vpxor   ymm2, ymm2, %1
    vmovdqa %1, ymm2
    vpor    ymm10, ymm14, ymm7
    vpand   ymm5, ymm10, ymm5
    vpand   ymm1, ymm1, ymm5
    vpxor   ymm13, ymm13, ymm7
    vpxor   ymm1, ymm13, ymm1
    vpor    ymm9, ymm9, ymm1
    vpxor   ymm9, ymm9, ymm5
    vpxor   ymm4, ymm13, ymm4
    vpor    ymm9, ymm9, ymm4
    vpand   ymm4, ymm9, ymm0
    vpxor   ymm4, ymm14, ymm4
    vpxor   ymm4, ymm4, %3
    vmovdqa %3, ymm4
    vpxor   ymm5, ymm9, ymm5
    vpor    ymm9, ymm15, ymm5
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm2, ymm7, ymm6
    vpxor   ymm2, ymm9, ymm2
    vpandn  ymm0, ymm0, ymm2
    vpxor   ymm0, ymm0, ymm1
    vpxor   ymm0, ymm0, %2
    vmovdqa %2, ymm0
%endmacro

%macro sbox8 4
	; From STF
    vpandn  ymm15, ymm1, ymm2
    vpandn  ymm14, ymm2, ymm4
    vpxor   ymm14, ymm14, ymm3
    vpand   ymm7, ymm14, ymm0
    vpandn  ymm13, ymm15, ymm7
    vpandn  ymm9, ymm14, ymm1
    vpor    ymm12, ymm9, ymm0
    vpandn  ymm8, ymm2, ymm1
    vpxor   ymm10, ymm4, ymm8
    vpand   ymm8, ymm12, ymm10
    vpor    ymm11, ymm7, ymm8
    vpxor   ymm7, ymm14, ymm8
    vpcmpeqd    ymm6, ymm6, ymm6
    vpxor   ymm7, ymm7, ymm6
    vpandn  ymm12, ymm12, ymm2
    vpxor   ymm7, ymm7, ymm12
    vpxor   ymm15, ymm15, ymm7
    vpor    ymm2, ymm13, ymm5
    vpxor   ymm2, ymm2, ymm15
    vpxor   ymm2, ymm2, %2
    vmovdqa %2, ymm2
    vpxor   ymm12, ymm15, ymm0
    vpand   ymm2, ymm4, ymm12
    vpxor   ymm14, ymm7, ymm1
    vpxor   ymm2, ymm14, ymm2
    vpxor   ymm7, ymm11, ymm2
    vpxor   ymm15, ymm9, ymm2
    vpor    ymm1, ymm1, ymm7
    vpxor   ymm1, ymm12, ymm1
    vpor    ymm12, ymm12, ymm3
    vpor    ymm3, ymm3, ymm14
    vpxor   ymm14, ymm15, ymm3
    vpxor   ymm14, ymm10, ymm14
    vpxor   ymm3, ymm14, ymm0
    vpand   ymm3, ymm3, ymm5
    vpxor   ymm3, ymm15, ymm3
    vpxor   ymm3, ymm3, %4
    vmovdqa %4, ymm3
    vpxor   ymm4, ymm4, ymm1
    vpand   ymm3, ymm11, ymm5
    vpxor   ymm3, ymm3, ymm4
    vpxor   ymm3, ymm3, %3
    vmovdqa %3, ymm3
    vpandn  ymm4, ymm12, ymm4
    vpor    ymm4, ymm13, ymm4
    vpxor   ymm4, ymm14, ymm4
    vpor    ymm5, ymm4, ymm5
    vpxor   ymm5, ymm15, ymm5
    vpxor   ymm5, ymm5, %1
    vmovdqa %1, ymm5
%endmacro

%macro round 48
	vmovdqa ymm0, keys(%1)
	vmovdqa ymm1, keys(%2)
	vmovdqa ymm2, keys(%3)
	vmovdqa ymm3, keys(%4)
	vmovdqa ymm4, keys(%5)
	vmovdqa ymm5, keys(%6)
	call sbox1_func

	vmovdqa ymm0, keys(%7)
	vmovdqa ymm1, keys(%8)
	vmovdqa ymm2, keys(%9)
	vmovdqa ymm3, keys(%10)
	vmovdqa ymm4, keys(%11)
	vmovdqa ymm5, keys(%12)
	call sbox2_func

	vmovdqa ymm0, keys(%13)
	vmovdqa ymm11, keys(%14)
	vmovdqa ymm2, keys(%15)
	vmovdqa ymm3, keys(%16)
	vmovdqa ymm4, keys(%17)
	vmovdqa ymm5, keys(%18)
	call sbox3_func

	vmovdqa ymm0, keys(%19)
	vmovdqa ymm1, keys(%20)
	vmovdqa ymm2, keys(%21)
	vmovdqa ymm3, keys(%22)
	vmovdqa ymm4, keys(%23)
	vmovdqa ymm5, keys(%24)
	call sbox4_func

	vmovdqa ymm10, keys(%25)
	vmovdqa ymm1, keys(%26)
	vmovdqa ymm2, keys(%27)
	vmovdqa ymm3, keys(%28)
	vmovdqa ymm4, keys(%29)
	vmovdqa ymm5, keys(%30)
	call sbox5_func

	vmovdqa ymm0, keys(%31)
	vmovdqa ymm1, keys(%32)
	vmovdqa ymm2, keys(%33)
	vmovdqa ymm3, keys(%34)
	vmovdqa ymm4, keys(%35)
	vmovdqa ymm5, keys(%36)
	call sbox6_func

	vmovdqa ymm0,  keys(%37)
	vmovdqa ymm1,  keys(%38)
	vmovdqa ymm12, keys(%39)
	vmovdqa ymm3,  keys(%40)
	vmovdqa ymm4,  keys(%41)
	vmovdqa ymm5,  keys(%42)
	call sbox7_func

	vmovdqa ymm0, keys(%43)
	vmovdqa ymm1, keys(%44)
	vmovdqa ymm2, keys(%45)
	vmovdqa ymm3, keys(%46)
	vmovdqa ymm4, keys(%47)
	vmovdqa ymm5, keys(%48)
	call sbox8_func

	xchg data_blocks_source_address, data_blocks_destination_address
%endmacro



%macro save_xmm128_with_vmovdqa 2
	[savexmm128 %1, %2]
	vmovdqa [rsp + %2], %1
%endmacro



section .text
	PROC_FRAME DES_Crypt25_x64_AVX2
		alloc_stack 0xb8
		save_xmm128_with_vmovdqa xmm6,  0x00
		save_xmm128_with_vmovdqa xmm7,  0x10
		save_xmm128_with_vmovdqa xmm8,  0x20
		save_xmm128_with_vmovdqa xmm9,  0x30
		save_xmm128_with_vmovdqa xmm10, 0x40
		save_xmm128_with_vmovdqa xmm11, 0x50
		save_xmm128_with_vmovdqa xmm12, 0x60
		save_xmm128_with_vmovdqa xmm13, 0x70
		save_xmm128_with_vmovdqa xmm14, 0x80
		save_xmm128_with_vmovdqa xmm15, 0x90
		save_reg rbx, 0xa0
		save_reg rsi, 0xa8
		save_reg rdi, 0xb0
	END_PROLOGUE	

		; ======================================

		; rcx: DES_Context *context

		lea data_blocks_source_address,      [rcx + data_blocks_offset]
		lea data_blocks_destination_address, [rcx + data_blocks_offset + 32 * vector_size]

		mov iterations, 25

	start:
		round 12, 46, 33, 52, 48, 20, 34, 55,  5, 13, 18, 40,  4, 32, 26, 27, 38, 54, 53,  6, 31, 25, 19, 41, 15, 24, 28, 43, 30,  3, 35, 22,  2, 44, 14, 23, 51, 16, 29, 49,  7, 17, 37,  8,  9, 50, 42, 21
		round  5, 39, 26, 45, 41, 13, 27, 48, 53,  6, 11, 33, 52, 25, 19, 20, 31, 47, 46, 54, 55, 18, 12, 34,  8, 17, 21, 36, 23, 49, 28, 15, 24, 37,  7, 16, 44,  9, 22, 42,  0, 10, 30,  1,  2, 43, 35, 14
		round 46, 25, 12, 31, 27, 54, 13, 34, 39, 47, 52, 19, 38, 11,  5,  6, 48, 33, 32, 40, 41,  4, 53, 20, 51,  3,  7, 22,  9, 35, 14,  1, 10, 23, 50,  2, 30, 24,  8, 28, 43, 49, 16, 44, 17, 29, 21,  0
		round 32, 11, 53, 48, 13, 40, 54, 20, 25, 33, 38,  5, 55, 52, 46, 47, 34, 19, 18, 26, 27, 45, 39,  6, 37, 42, 50,  8, 24, 21,  0, 44, 49,  9, 36, 17, 16, 10, 51, 14, 29, 35,  2, 30,  3, 15,  7, 43
		round 18, 52, 39, 34, 54, 26, 40,  6, 11, 19, 55, 46, 41, 38, 32, 33, 20,  5,  4, 12, 13, 31, 25, 47, 23, 28, 36, 51, 10,  7, 43, 30, 35, 24, 22,  3,  2, 49, 37,  0, 15, 21, 17, 16, 42,  1, 50, 29
		round  4, 38, 25, 20, 40, 12, 26, 47, 52,  5, 41, 32, 27, 55, 18, 19,  6, 46, 45, 53, 54, 48, 11, 33,  9, 14, 22, 37, 49, 50, 29, 16, 21, 10,  8, 42, 17, 35, 23, 43,  1,  7,  3,  2, 28, 44, 36, 15
		round 45, 55, 11,  6, 26, 53, 12, 33, 38, 46, 27, 18, 13, 41,  4,  5, 47, 32, 31, 39, 40, 34, 52, 19, 24,  0,  8, 23, 35, 36, 15,  2,  7, 49, 51, 28,  3, 21,  9, 29, 44, 50, 42, 17, 14, 30, 22,  1
		round 31, 41, 52, 47, 12, 39, 53, 19, 55, 32, 13,  4, 54, 27, 45, 46, 33, 18, 48, 25, 26, 20, 38,  5, 10, 43, 51,  9, 21, 22,  1, 17, 50, 35, 37, 14, 42,  7, 24, 15, 30, 36, 28,  3,  0, 16,  8, 44
		round 55, 34, 45, 40,  5, 32, 46, 12, 48, 25,  6, 52, 47, 20, 38, 39, 26, 11, 41, 18, 19, 13, 31, 53,  3, 36, 44,  2, 14, 15, 51, 10, 43, 28, 30,  7, 35,  0, 17,  8, 23, 29, 21, 49, 50,  9,  1, 37
		round 41, 20, 31, 26, 46, 18, 32, 53, 34, 11, 47, 38, 33,  6, 55, 25, 12, 52, 27,  4,  5, 54, 48, 39, 42, 22, 30, 17,  0,  1, 37, 49, 29, 14, 16, 50, 21, 43,  3, 51,  9, 15,  7, 35, 36, 24, 44, 23
		round 27,  6, 48, 12, 32,  4, 18, 39, 20, 52, 33, 55, 19, 47, 41, 11, 53, 38, 13, 45, 46, 40, 34, 25, 28,  8, 16,  3, 43, 44, 23, 35, 15,  0,  2, 36,  7, 29, 42, 37, 24,  1, 50, 21, 22, 10, 30,  9
		round 13, 47, 34, 53, 18, 45,  4, 25,  6, 38, 19, 41,  5, 33, 27, 52, 39, 55, 54, 31, 32, 26, 20, 11, 14, 51,  2, 42, 29, 30,  9, 21,  1, 43, 17, 22, 50, 15, 28, 23, 10, 44, 36,  7,  8, 49, 16, 24
		round 54, 33, 20, 39,  4, 31, 45, 11, 47, 55,  5, 27, 46, 19, 13, 38, 25, 41, 40, 48, 18, 12,  6, 52,  0, 37, 17, 28, 15, 16, 24,  7, 44, 29,  3,  8, 36,  1, 14,  9, 49, 30, 22, 50, 51, 35,  2, 10
		round 40, 19,  6, 25, 45, 48, 31, 52, 33, 41, 46, 13, 32,  5, 54, 55, 11, 27, 26, 34,  4, 53, 47, 38, 43, 23,  3, 14,  1,  2, 10, 50, 30, 15, 42, 51, 22, 44,  0, 24, 35, 16,  8, 36, 37, 21, 17, 49
		round 26,  5, 47, 11, 31, 34, 48, 38, 19, 27, 32, 54, 18, 46, 40, 41, 52, 13, 12, 20, 45, 39, 33, 55, 29,  9, 42,  0, 44, 17, 49, 36, 16,  1, 28, 37,  8, 30, 43, 10, 21,  2, 51, 22, 23,  7,  3, 35
		round 19, 53, 40,  4, 55, 27, 41, 31, 12, 20, 25, 47, 11, 39, 33, 34, 45,  6,  5, 13, 38, 32, 26, 48, 22,  2, 35, 50, 37, 10, 42, 29,  9, 51, 21, 30,  1, 23, 36,  3, 14, 24, 44, 15, 16,  0, 49, 28

		xchg data_blocks_source_address, data_blocks_destination_address

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

	align 16
	sbox1_func:
		vpxor   ymm0, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm1, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm2, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm3, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm4, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm5, [data_blocks_source_address + 0xffffffff]
		sbox1 data_blocks_destination(8), data_blocks_destination(16), data_blocks_destination(22), data_blocks_destination(30)
		ret

	align 16
	sbox2_func:
		vpxor   ymm0, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm1, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm2, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm3, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm4, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm5, [data_blocks_source_address + 0xffffffff]
		sbox2 data_blocks_destination(12), data_blocks_destination(27), data_blocks_destination(1), data_blocks_destination(17)
		ret

	align 16
	sbox5_func:
		vpxor   ymm10, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm1, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm2, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm3, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm4, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm5, [data_blocks_source_address + 0xffffffff]
		sbox5 data_blocks_destination(7), data_blocks_destination(13), data_blocks_destination(24), data_blocks_destination(2)
		ret

	align 16
	sbox6_func:
		vpxor   ymm0, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm1, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm2, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm3, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm4, [data_blocks_source_address + 0xffffffff]
		vpxor   ymm5, [data_blocks_source_address + 0xffffffff]
		sbox6 data_blocks_destination(3), data_blocks_destination(28), data_blocks_destination(10), data_blocks_destination(18)
		ret

	align 16
	sbox3_func:
		vpxor   ymm0, [data_blocks_source_address + 7 * vector_size]
		vpxor   ymm11, [data_blocks_source_address + 8 * vector_size]
		vpxor   ymm2, [data_blocks_source_address + 9 * vector_size]
		vpxor   ymm3, [data_blocks_source_address + 10 * vector_size]
		vpxor   ymm4, [data_blocks_source_address + 11 * vector_size]
		vpxor   ymm5, [data_blocks_source_address + 12 * vector_size]
		sbox3 data_blocks_destination(23), data_blocks_destination(15), data_blocks_destination(29), data_blocks_destination(5)
		ret

	align 16
	sbox4_func:
		vpxor   ymm0, [data_blocks_source_address + 11 * vector_size]
		vpxor   ymm1, [data_blocks_source_address + 12 * vector_size]
		vpxor   ymm2, [data_blocks_source_address + 13 * vector_size]
		vpxor   ymm3, [data_blocks_source_address + 14 * vector_size]
		vpxor   ymm4, [data_blocks_source_address + 15 * vector_size]
		vpxor   ymm5, [data_blocks_source_address + 16 * vector_size]
		sbox4 data_blocks_destination(25), data_blocks_destination(19), data_blocks_destination(9), data_blocks_destination(0)
		ret

	align 16
	sbox7_func:
		vpxor   ymm0,  [data_blocks_source_address + 23 * vector_size]
		vpxor   ymm1,  [data_blocks_source_address + 24 * vector_size]
		vpxor   ymm12, [data_blocks_source_address + 25 * vector_size]
		vpxor   ymm3,  [data_blocks_source_address + 26 * vector_size]
		vpxor   ymm4,  [data_blocks_source_address + 27 * vector_size]
		vpxor   ymm5,  [data_blocks_source_address + 28 * vector_size]
		sbox7 data_blocks_destination(31), data_blocks_destination(11), data_blocks_destination(21), data_blocks_destination(6)
		ret

	align 16
	sbox8_func:
		vpxor   ymm0, [data_blocks_source_address + 27 * vector_size]
		vpxor   ymm1, [data_blocks_source_address + 28 * vector_size]
		vpxor   ymm2, [data_blocks_source_address + 29 * vector_size]
		vpxor   ymm3, [data_blocks_source_address + 30 * vector_size]
		vpxor   ymm4, [data_blocks_source_address + 31 * vector_size]
		vpxor   ymm5, [data_blocks_source_address +  0 * vector_size]
		sbox8 data_blocks_destination(4), data_blocks_destination(26), data_blocks_destination(14), data_blocks_destination(20)
		ret

	ENDPROC_FRAME
	
	align 16
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00
