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

global SHA1_GenerateTripcodesWithOptimization_x64_AVX2



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define A ymm0
%define B ymm1
%define C ymm2
%define D ymm3
%define E ymm4

%define W1 ymm10
%define W2 ymm11
%define W3 ymm12
%define W4 ymm13
%define W5 ymm14

%define W0_6___W0_4        ymm10
%define W0_8___W0_4        ymm11
%define W0_6___W0_4___W0_7 ymm12
%define W0_8___W012        ymm13

%define K ymm15

%macro round1 6
	vpaddd		%5, [rcx + %6 * 32]
	vpslld		ymm5, %1,  5
	vpsrld		ymm6, %1,  27
	vpxor		ymm7, %4,  %3
	vpand		ymm7, %2
	vpaddd		%5,   K,   %5
	vpor		ymm5, ymm6
	vpxor		ymm7, %4
	vpaddd		ymm5, ymm7
	vpslld		ymm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   ymm5
	vpor		%2,   ymm6
%endmacro

%macro round1_optimized 6
	vpaddd		%5, [rdx + %6 * 32]
	vpslld		ymm5, %1,  5
	vpsrld		ymm6, %1,  27
	vpxor		ymm7, %4,  %3
	vpand		ymm7, %2
	vpaddd		%5,   K,   %5
	vpor		ymm5, ymm6
	vpxor		ymm7, %4
	vpaddd		ymm5, ymm7
	vpslld		ymm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   ymm5
	vpor		%2,   ymm6
%endmacro

%macro round1_optimized_ymm5 6
	vpxor       ymm5, [rdx + %6 * 32]
	vpaddd		%5,   ymm5
	vpslld		ymm5, %1,  5
	vpsrld		ymm6, %1,  27
	vpxor		ymm7, %4,  %3
	vpand		ymm7, %2
	vpaddd		%5,   K,   %5
	vpor		ymm5, ymm6
	vpxor		ymm7, %4
	vpaddd		ymm5, ymm7
	vpslld		ymm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   ymm5
	vpor		%2,   ymm6
%endmacro

%macro round24_optimized 6
	vpaddd  %5, [rdx + %6 * 32]

	vpaddd	%5, K

	vpxor   ymm6, %2, %3
	vpxor   ymm6, %4
	vpaddd  %5, ymm6

	vpslld  ymm7, %1,   5
	vpsrld  ymm6, %1,   27
	vpor    ymm6, ymm7
	vpaddd  %5,   %5, ymm6

	vpslld  ymm7, %2,   30
	vpsrld  ymm6, %2,   2
	vpor    %2,   ymm6, ymm7
%endmacro

%macro round24_optimized_ymm5 6
	vpxor   ymm5, [rdx + %6 * 32]

	vpaddd  %5, ymm5

	vpaddd	%5, K

	vpxor   ymm6, %2, %3
	vpxor   ymm6, %4
	vpaddd  %5, ymm6

	vpslld  ymm7, %1,   5
	vpsrld  ymm6, %1,   27
	vpor    ymm6, ymm7
	vpaddd  %5,   %5, ymm6

	vpslld  ymm7, %2,   30
	vpsrld  ymm6, %2,   2
	vpor    %2,   ymm6, ymm7
%endmacro

%macro round3_optimized 6
	vpaddd  %5, [rdx + %6 * 32]

	vpaddd	%5, K

	vpand   ymm6, %2,   %3
	vpand   ymm7, %2,   %4
	vpand	ymm5, %3,   %4
	vpxor   ymm7, ymm5
	vpxor   ymm6, ymm7
	vpaddd  %5, ymm6

	vpslld  ymm7, %1,   5
	vpsrld  ymm6, %1,   27
	vpor    ymm6, ymm7
	vpaddd  %5, ymm6

	vpslld  ymm7, %2,   30
	vpsrld  ymm6, %2,   2
	vpor    %2,   ymm6, ymm7
%endmacro

%macro round3_optimized_ymm5 6
	vpxor   ymm5, [rdx + %6 * 32]

	vpaddd  %5, ymm5

	vpaddd	%5, K

	vpand   ymm6, %2,   %3
	vpand   ymm7, %2,   %4
	vpand	ymm5, %3,   %4
	vpxor   ymm7, ymm5
	vpxor   ymm6, ymm7
	vpaddd  %5, ymm6

	vpslld  ymm7, %1,   5
	vpsrld  ymm6, %1,   27
	vpor    ymm6, ymm7
	vpaddd  %5,   %5, ymm6

	vpslld  ymm7, %2,   30
	vpsrld  ymm6, %2,   2
	vpor    %2,   ymm6, ymm7
%endmacro

%macro set_W0_shifted 1
	vpslld  ymm1, ymm0, %1
	vpsrld  ymm2, ymm0, (32 - %1)
	vpor    ymm1, ymm2
	vmovdqa [r8 + %1 * 32], ymm1
%endmacro



section .data
	; Constants required for hash calculation (see p. 11 of FIPS 180-3)
	align 32
K0:	dd 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
K1: dd 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
K2:	dd 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
K3:	dd 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

	; Initial hash values (see p. 14 of FIPS 180-3)
	align 32
H0:	dd 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301, 0x67452301
H1: dd 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89
H2: dd 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe
H3: dd 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476, 0x10325476
H4: dd 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0



%macro save_xmm128_with_vmovdqa 2
	[savexmm128 %1, %2]
	vmovdqa [rsp + %2], %1
%endmacro



section .text
	PROC_FRAME SHA1_GenerateTripcodesWithOptimization_x64_AVX2
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

		mov     rsi, qword K0
		mov     rdi, qword H0

		vmovdqa ymm0, [rcx]
		set_W0_shifted 1
		set_W0_shifted 2
		set_W0_shifted 3
		set_W0_shifted 4
		set_W0_shifted 5
		set_W0_shifted 6
		set_W0_shifted 7
		set_W0_shifted 8
		set_W0_shifted 9
		set_W0_shifted 10
		set_W0_shifted 11
		set_W0_shifted 12
		set_W0_shifted 13
		set_W0_shifted 14
		set_W0_shifted 15
		set_W0_shifted 16
		set_W0_shifted 17
		set_W0_shifted 18
		set_W0_shifted 19
		set_W0_shifted 20
		set_W0_shifted 21
		set_W0_shifted 22

		vmovdqa K, [rsi]

		vmovdqa A, [rdi + 0 * 32]
		vmovdqa B, [rdi + 1 * 32]
		vmovdqa C, [rdi + 2 * 32]
		vmovdqa D, [rdi + 3 * 32]
		vmovdqa E, [rdi + 4 * 32]

		round1           A, B, C, D, E, 0
		round1_optimized E, A, B, C, D, 1
		round1_optimized D, E, A, B, C, 2
		round1_optimized C, D, E, A, B, 3
		round1_optimized B, C, D, E, A, 4

		round1_optimized A, B, C, D, E, 5
		round1_optimized E, A, B, C, D, 6
		round1_optimized D, E, A, B, C, 7
		round1_optimized C, D, E, A, B, 8
		round1_optimized B, C, D, E, A, 9

		round1_optimized A, B, C, D, E, 10
		round1_optimized E, A, B, C, D, 11
		round1_optimized D, E, A, B, C, 12
		round1_optimized C, D, E, A, B, 13
		round1_optimized B, C, D, E, A, 14

		round1_optimized      A, B, C, D, E, 15
		vmovdqa ymm5, [r8 + 1 * 32]
		round1_optimized_ymm5 E, A, B, C, D, 16
		round1_optimized      D, E, A, B, C, 17
		round1_optimized      C, D, E, A, B, 18
		vmovdqa ymm5, [r8 + 2 * 32]
		round1_optimized_ymm5 B, C, D, E, A, 19

		vmovdqa K, [rsi + 1 * 32]

		round24_optimized      A, B, C, D, E, 20
		round24_optimized      E, A, B, C, D, 21
		vmovdqa ymm5, [r8 + 3 * 32]
		round24_optimized_ymm5 D, E, A, B, C, 22
		round24_optimized      C, D, E, A, B, 23
		vmovdqa ymm5, [r8 + 2 * 32]
		round24_optimized_ymm5 B, C, D, E, A, 24

		vmovdqa ymm5, [r8 + 4 * 32]
		round24_optimized_ymm5 A, B, C, D, E, 25
		round24_optimized      E, A, B, C, D, 26
		round24_optimized      D, E, A, B, C, 27
		vmovdqa ymm5, [r8 + 5 * 32]
		round24_optimized_ymm5 C, D, E, A, B, 28
		round24_optimized      B, C, D, E, A, 29

		vmovdqa ymm5, [r8 + 4 * 32]
		vpxor   ymm5, [r8 + 2 * 32]
		round24_optimized_ymm5 A, B, C, D, E, 30
		vmovdqa ymm5, [r8 + 6 * 32]
		round24_optimized_ymm5 E, A, B, C, D, 31
		vmovdqa ymm5, [r8 + 3 * 32]
		vpxor   ymm5, [r8 + 2 * 32]
		round24_optimized_ymm5 D, E, A, B, C, 32
		round24_optimized      C, D, E, A, B, 33
		vmovdqa ymm5, [r8 + 7 * 32]
		round24_optimized_ymm5 B, C, D, E, A, 34

		vmovdqa ymm5, [r8 + 4 * 32]
		round24_optimized_ymm5 A, B, C, D, E, 35
		vmovdqa ymm5, [r8 + 6 * 32]
		vpxor   ymm5, [r8 + 4 * 32]
		vmovdqa W0_6___W0_4, ymm5
		round24_optimized_ymm5 E, A, B, C, D, 36
		vmovdqa ymm5, [r8 + 8 * 32]
		round24_optimized_ymm5 D, E, A, B, C, 37
		vmovdqa ymm5, [r8 + 4 * 32]
		round24_optimized_ymm5 C, D, E, A, B, 38
		round24_optimized      B, C, D, E, A, 39

		vmovdqa K, [rsi + 2 * 32]

		vmovdqa ymm5, [r8 + 4 * 32]
		vpxor   ymm5, [r8 + 9 * 32]
		round3_optimized_ymm5  A, B, C, D, E, 40
		round3_optimized       E, A, B, C, D, 41
		vmovdqa ymm5, [r8 + 6 * 32]
		vpxor   ymm5, [r8 + 8 * 32]
		round3_optimized_ymm5  D, E, A, B, C, 42
		vmovdqa ymm5, [r8 + 10 * 32]
		round3_optimized_ymm5  C, D, E, A, B, 43
		vmovdqa ymm5, [r8 + 6 * 32]
		vpxor   ymm5, [r8 + 3 * 32]
		vpxor   ymm5, [r8 + 7 * 32]
		round3_optimized_ymm5  B, C, D, E, A, 44

		round3_optimized       A, B, C, D, E, 45
		vmovdqa ymm5, [r8 + 4 * 32]
		vpxor   ymm5, [r8 + 11 * 32]
		round3_optimized_ymm5  E, A, B, C, D, 46
		vmovdqa ymm5, [r8 + 8 * 32]
		vpxor   ymm5, [r8 + 4 * 32]
		vmovdqa W0_8___W0_4, ymm5
		round3_optimized_ymm5  D, E, A, B, C, 47
		vmovdqa ymm5, W0_8___W0_4
		vpxor   ymm5, [r8 + 3 * 32]
		vpxor   ymm5, [r8 + 10 * 32]
		vpxor   ymm5, [r8 + 5 * 32]
		round3_optimized_ymm5  C, D, E, A, B, 48
		vmovdqa ymm5, [r8 + 12 * 32]
		round3_optimized_ymm5  B, C, D, E, A, 49

		vmovdqa ymm5, [r8 + 8 * 32]
		round3_optimized_ymm5  A, B, C, D, E, 50
		vmovdqa ymm5, W0_6___W0_4
		round3_optimized_ymm5  E, A, B, C, D, 51
		vmovdqa ymm5, W0_8___W0_4
		vpxor   ymm5, [r8 + 13 * 32]
		round3_optimized_ymm5  D, E, A, B, C, 52
		round3_optimized       C, D, E, A, B, 53
		vmovdqa ymm5, [r8 + 7  * 32]
		vpxor   ymm5, [r8 + 10 * 32]
		vpxor   ymm5, [r8 + 12 * 32]
		round3_optimized_ymm5  B, C, D, E, A, 54

		vmovdqa ymm5, [r8 + 14 * 32]
		round3_optimized_ymm5  A, B, C, D, E, 55
		vmovdqa ymm5, [r8 + 7  * 32]
		vpxor   ymm5, W0_6___W0_4
		vmovdqa W0_6___W0_4___W0_7, ymm5
		vpxor   ymm5, [r8 + 11 * 32]
		vpxor   ymm5, [r8 + 10 * 32]
		round3_optimized_ymm5  E, A, B, C, D, 56
		vmovdqa ymm5, [r8 + 8  * 32]
		round3_optimized_ymm5  D, E, A, B, C, 57
		vmovdqa ymm5, W0_8___W0_4
		vpxor   ymm5, [r8 + 15 * 32]
		round3_optimized_ymm5  C, D, E, A, B, 58
		vmovdqa ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 12 * 32]
		vmovdqa W0_8___W012, ymm5
		round3_optimized_ymm5  B, C, D, E, A, 59

		vmovdqa K, [rsi + 3 * 32]

		vmovdqa ymm5, W0_8___W012
		vpxor   ymm5, [r8 + 4  * 32]
		vpxor   ymm5, [r8 + 7  * 32]
		vpxor   ymm5, [r8 + 14 * 32]
		round24_optimized_ymm5  A, B, C, D, E, 60
		vmovdqa ymm5, [r8 + 16 * 32]
		round24_optimized_ymm5  E, A, B, C, D, 61
		vmovdqa ymm5, W0_6___W0_4
		vpxor   ymm5, W0_8___W012
		round24_optimized_ymm5  D, E, A, B, C, 62
		vmovdqa ymm5, [r8 + 8  * 32]
		round24_optimized_ymm5  C, D, E, A, B, 63
		vmovdqa ymm5, W0_6___W0_4___W0_7
		vpxor   ymm5, W0_8___W012
		vpxor   ymm5, [r8 + 17 * 32]
		round24_optimized_ymm5  B, C, D, E, A, 64

		round24_optimized       A, B, C, D, E, 65
		vmovdqa ymm5, [r8 + 14 * 32]
		vpxor   ymm5, [r8 + 16 * 32]
		round24_optimized_ymm5  E, A, B, C, D, 66
		vmovdqa ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 18 * 32]
		round24_optimized_ymm5  D, E, A, B, C, 67
		vmovdqa ymm5, [r8 + 11 * 32]
		vpxor   ymm5, [r8 + 14 * 32]
		vpxor   ymm5, [r8 + 15 * 32]
		round24_optimized_ymm5  C, D, E, A, B, 68
		round24_optimized       B, C, D, E, A, 69

		vmovdqa ymm5, [r8 + 12 * 32]
		vpxor   ymm5, [r8 + 19 * 32]
		round24_optimized_ymm5  A, B, C, D, E, 70
		vmovdqa ymm5, [r8 + 12 * 32]
		vpxor   ymm5, [r8 + 16 * 32]
		round24_optimized_ymm5  E, A, B, C, D, 71
		vmovdqa ymm5, [r8 + 11 * 32]
		vpxor   ymm5, [r8 + 12 * 32]
		vpxor   ymm5, [r8 + 18 * 32]
		vpxor   ymm5, [r8 + 13 * 32]
		vpxor   ymm5, [r8 + 16 * 32]
		vpxor   ymm5, [r8 + 5  * 32]
		round24_optimized_ymm5  D, E, A, B, C, 72
		vmovdqa ymm5, [r8 + 20 * 32]
		round24_optimized_ymm5  C, D, E, A, B, 73
		vmovdqa ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 16 * 32]
		round24_optimized_ymm5  B, C, D, E, A, 74

		vmovdqa ymm5, [r8 + 6  * 32]
		vpxor   ymm5, [r8 + 12 * 32]
		vpxor   ymm5, [r8 + 14 * 32]
		round24_optimized_ymm5  A, B, C, D, E, 75
		vmovdqa ymm5, [r8 + 7  * 32]
		vpxor   ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 12 * 32]
		vpxor   ymm5, [r8 + 16 * 32]
		vpxor   ymm5, [r8 + 21 * 32]
		round24_optimized_ymm5  E, A, B, C, D, 76
		round24_optimized       D, E, A, B, C, 77
		vmovdqa ymm5, [r8 + 7  * 32]
		vpxor   ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 15 * 32]
		vpxor   ymm5, [r8 + 18 * 32]
		vpxor   ymm5, [r8 + 20 * 32]
		round24_optimized_ymm5  C, D, E, A, B, 78
		vmovdqa ymm5, [r8 + 8  * 32]
		vpxor   ymm5, [r8 + 22 * 32]
		round24_optimized_ymm5  B, C, D, E, A, 79

		vpaddd A, [rdi + 0 * 32]
		vpaddd B, [rdi + 1 * 32]
		vpaddd C, [rdi + 2 * 32]

		vmovdqa [r9 + 0 * 32], A
		vmovdqa [r9 + 1 * 32], B
		vmovdqa [r9 + 2 * 32], C

		; ======================================

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
		