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

global SHA1_GenerateTripcodes_x64_AVX
global SHA1_GenerateTripcodesWithOptimization_x64_AVX



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define A xmm0
%define B xmm1
%define C xmm2
%define D xmm3
%define E xmm4

%define W1 xmm10
%define W2 xmm11
%define W3 xmm12
%define W4 xmm13
%define W5 xmm14

%define W0_6___W0_4        xmm10
%define W0_8___W0_4        xmm11
%define W0_6___W0_4___W0_7 xmm12
%define W0_8___W012        xmm13

%define K xmm15

; #define ROUND1(%1, %2, %3, %4, %5, stage)
%macro round1 6
	vpaddd		%5, [rcx + %6 * 16]
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K,   %5
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1a 6
	; paddd		%5, [rcx + %6 * 16]
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K,   %5
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1b 7
	; movaps		stage*16(%rdi), W;
	; vpaddd		%5, W, %5;

	vmovdqa     %6, [rcx + %7 * 16]
	vpaddd      %5, %6, %5

	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K,   %5
	vpor			xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1c 8
; #define ROUND1c(%1, %2, %3, %4, %5, W1, W2, stage)
	vmovdqa		%6,  [rcx + (%8 - 16) * 16]
	vmovdqa		%7,  [rcx + (%8 - 14) * 16]
	vpxor		%6,   %7
	vpaddd		%5,   K,    %5
	vpslld		xmm5, %1,   5
	vpsrld		xmm8, %1,   27 
	vpxor		xmm7, %4,   %3 
	vpand		xmm7, %2
	vpslld		xmm6, %6,   1  
	vpsrld		%6,   %6,   31
	vpor		%6,   %6,   xmm6 
	vpor		xmm5, xmm8, xmm5
	vpxor		xmm7, %4
	vpaddd		%5,   %6,   %5
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,   30 
	vpsrld		%2,   %2,   2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
	vmovdqa		[rcx + %8 * 16], %6
%endmacro

%macro round1d 8
	; vmovdqa		%6,  [rcx + (%8 - 16) * 16]
	; vmovdqa		%7,  [rcx + (%8 - 14) * 16]
	vpxor		%6,   %7
	vpaddd		%5,   K,    %5
	vpslld		xmm5, %1,   5
	vpsrld		xmm8, %1,   27 
	vpxor		xmm7, %4,   %3 
	vpand		xmm7, %2
	vpslld		xmm6, %6,   1  
	vpsrld		%6,   %6,   31
	vpor		%6,   %6,   xmm6 
	vpor		xmm5, xmm8, xmm5
	vpxor		xmm7, %4
	vpaddd		%5,   %6,   %5
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,   30 
	vpsrld		%2,   %2,   2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
	vmovdqa		[rcx + %8 * 16], %6
%endmacro

%macro round24 8
; #define ROUND24(%1, %2, %3, %4, %5, W1, W2, stage)
	vpxor	%6, %7
	vmovdqa	%7, [rcx + (%8 - 14) * 16]
	vpxor	%6, [rcx + (%8 -  8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	%6, %7
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	vpaddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	vpaddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %8 * 16], %6
%endmacro

%macro round24a 8
	vpxor	%6, %7
	vmovdqa	%7, [rcx + (%8 - 14) * 16]
	vpxor	%6, [rcx + (%8 -  8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	%6, %7
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	vpaddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	vpaddd	%5, xmm5
	vpor	%2, xmm6
%endmacro

%macro round24b 7
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	vpaddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	vpaddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %7 * 16], %6
%endmacro

%macro round24c 7
	vpxor	%6, [rcx + (%7 - 8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	vpaddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	vpaddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %7 * 16], %6
%endmacro

%macro round24d 7
	vpxor	%6, [rcx + (%7 - 14) * 16]
	vpxor	%6, [rcx + (%7 - 8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	vpaddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	vpaddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %7 * 16], %6
%endmacro

%macro round24e 7
; #define ROUND24e(%1, %2, %3, %4, %5, W, stage)
	vpxor	%6,   [rcx + (%7 - 16) * 16]
	vmovdqa	xmm7, [rcx + (%7 - 14) * 16]
	vpxor	%6,   [rcx + (%7 -  8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	%6, %6, xmm7
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	paddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	paddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %7 * 16], %6
%endmacro

%macro round24f 8
	vpxor	%6, [rcx + (%8 - 16) * 16]
	vmovdqa	%7, [rcx + (%8 - 14) * 16]
	vpxor	%6, [rcx + (%8 -  8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm8, %1, 27
	vpxor	%6, %7
	vpxor	xmm7, %3, %2
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm8, xmm5
	vpxor	xmm7, %4
	vpaddd	%5, %6, %5
	paddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	paddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %8 * 16], %6
%endmacro

%macro round3 8
	vpxor	%6, %7
	vmovdqa	%7, [rcx + (%8 - 14) * 16]
	vpxor	%6, [rcx + (%8 -  8) * 16]
	vpaddd	%5, K, %5
	vpslld	xmm5, %1, 5
	vpsrld	xmm9, %1, 27
	vpxor	%6, %7
	vpor	xmm7, %3, %4
	vpand	xmm8, %3, %4
	vpslld	xmm6, %6, 1
	vpsrld	%6, %6, 31
	vpor	%6, %6, xmm6
	vpor	xmm5, xmm9, xmm5
	pand	xmm7, %2
	vpor	xmm7, xmm8, xmm7
	vpaddd	%5, %6, %5
	paddd	xmm5, xmm7
	vpslld	xmm6, %2, 30
	vpsrld	%2, %2, 2
	paddd	%5, xmm5
	vpor	%2, xmm6
	vmovdqa	[rcx + %8 * 16], %6
%endmacro



%macro round1_optimized 6
	vpaddd		%5, [rdx + %6 * 16]
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K,   %5
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1_optimized_xmm5 6
	vpxor       xmm5, [rdx + %6 * 16]
	vpaddd		%5,   xmm5
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K,   %5
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round24_optimized 6
	vpaddd  %5, [rdx + %6 * 16]

	vpaddd	%5, K

	vpxor   xmm6, %2, %3
	vpxor   xmm6, %4
	vpaddd  %5, xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round24_optimized_xmm5 6
	vpxor   xmm5, [rdx + %6 * 16]

	vpaddd  %5, xmm5

	vpaddd	%5, K

	vpxor   xmm6, %2, %3
	vpxor   xmm6, %4
	vpaddd  %5, xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round3_optimized 6
	vpaddd  %5, [rdx + %6 * 16]

	vpaddd	%5, K

	vpand   xmm6, %2,   %3
	vpand   xmm7, %2,   %4
	vpand	xmm5, %3,   %4
	vpxor   xmm7, xmm5
	vpxor   xmm6, xmm7
	vpaddd  %5, xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round3_optimized_xmm5 6
	vpxor   xmm5, [rdx + %6 * 16]

	vpaddd  %5, xmm5

	vpaddd	%5, K

	vpand   xmm6, %2,   %3
	vpand   xmm7, %2,   %4
	vpand	xmm5, %3,   %4
	vpxor   xmm7, xmm5
	vpxor   xmm6, xmm7
	vpaddd  %5, xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro set_W0_shifted 1
	vpslld  xmm1, xmm0, %1
	vpsrld  xmm2, xmm0, (32 - %1)
	vpor    xmm1, xmm2
	vmovdqa [r8 + %1 * 16], xmm1
%endmacro



section .data
	; Constants required for hash calculation (see p. 11 of FIPS 180-3)
	align 16
K0:	dd 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
K1: dd 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
K2:	dd 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
K3:	dd 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

	; Initial hash values (see p. 14 of FIPS 180-3)
	align 16
H0:	dd 0x67452301, 0x67452301, 0x67452301, 0x67452301
H1: dd 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89
H2: dd 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe
H3: dd 0x10325476, 0x10325476, 0x10325476, 0x10325476
H4: dd 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0



section .text
	PROC_FRAME SHA1_GenerateTripcodes_x64_AVX
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

		mov     rsi, qword K0
		mov     rdi, qword H0

		vmovdqa K, [rsi]

		vmovdqa A, [rdi + 0 * 16]
		vmovdqa B, [rdi + 1 * 16]
		vmovdqa C, [rdi + 2 * 16]
		vmovdqa D, [rdi + 3 * 16]
		vmovdqa E, [rdi + 4 * 16]

		round1  A, B, C, D, E, 0
		round1  E, A, B, C, D, 1
		round1  D, E, A, B, C, 2
		round1  C, D, E, A, B, 3
		round1a B, C, D, E, A, 4
		round1a A, B, C, D, E, 5
		round1a E, A, B, C, D, 6
		round1a D, E, A, B, C, 7
		round1a C, D, E, A, B, 8
		round1a B, C, D, E, A, 9
		round1a A, B, C, D, E, 10
		round1a E, A, B, C, D, 11
		round1a D, E, A, B, C, 12
		round1a C, D, E, A, B, 13
		round1a B, C, D, E, A, 14
		round1b A, B, C, D, E, W3, 15
		round1c E, A, B, C, D, W1, W4, 16
		round1c D, E, A, B, C, W2, W5, 17
		round1d C, D, E, A, B, W3, W4, 18
		round1d B, C, D, E, A, W1, W5, 19

		vmovdqa K, [rsi + 1 * 16]

		round24b A, B, C, D, E, W2, 20
		round24b E, A, B, C, D, W3, 21
		round24b D, E, A, B, C, W1, 22
		round24c C, D, E, A, B, W2, 23
		round24c B, C, D, E, A, W3, 24
		round24c A, B, C, D, E, W1, 25
		round24c E, A, B, C, D, W2, 26
		round24c D, E, A, B, C, W3, 27
		round24c C, D, E, A, B, W1, 28
		round24d B, C, D, E, A, W2, 29
		round24d A, B, C, D, E, W3, 30
		round24e E, A, B, C, D, W1, 31
		round24f D, E, A, B, C, W2, W4, 32
		round24f C, D, E, A, B, W3, W5, 33
		round24  B, C, D, E, A, W1, W4, 34
		round24  A, B, C, D, E, W2, W5, 35
		round24  E, A, B, C, D, W3, W4, 36
		round24  D, E, A, B, C, W1, W5, 37
		round24  C, D, E, A, B, W2, W4, 38
		round24  B, C, D, E, A, W3, W5, 39

		vmovdqa K, [rsi + 2 * 16]

		round3 A, B, C, D, E, W1, W4, 40 
		round3 E, A, B, C, D, W2, W5, 41 
		round3 D, E, A, B, C, W3, W4, 42 
		round3 C, D, E, A, B, W1, W5, 43 
		round3 B, C, D, E, A, W2, W4, 44 
		round3 A, B, C, D, E, W3, W5, 45 
		round3 E, A, B, C, D, W1, W4, 46 
		round3 D, E, A, B, C, W2, W5, 47 
		round3 C, D, E, A, B, W3, W4, 48 
		round3 B, C, D, E, A, W1, W5, 49 
		round3 A, B, C, D, E, W2, W4, 50 
		round3 E, A, B, C, D, W3, W5, 51 
		round3 D, E, A, B, C, W1, W4, 52 
		round3 C, D, E, A, B, W2, W5, 53 
		round3 B, C, D, E, A, W3, W4, 54 
		round3 A, B, C, D, E, W1, W5, 55 
		round3 E, A, B, C, D, W2, W4, 56 
		round3 D, E, A, B, C, W3, W5, 57 
		round3 C, D, E, A, B, W1, W4, 58 
		round3 B, C, D, E, A, W2, W5, 59 

		vmovdqa K, [rsi + 3 * 16]

		round24 A, B, C, D, E, W3, W4, 60
		round24 E, A, B, C, D, W1, W5, 61
		round24 D, E, A, B, C, W2, W4, 62
		round24 C, D, E, A, B, W3, W5, 63
		round24 B, C, D, E, A, W1, W4, 64
		round24 A, B, C, D, E, W2, W5, 65
		round24 E, A, B, C, D, W3, W4, 66
		round24 D, E, A, B, C, W1, W5, 67
		round24 C, D, E, A, B, W2, W4, 68
		round24 B, C, D, E, A, W3, W5, 69
		round24 A, B, C, D, E, W1, W4, 70
		round24 E, A, B, C, D, W2, W5, 71
		round24 D, E, A, B, C, W3, W4, 72
		round24 C, D, E, A, B, W1, W5, 73
		round24a B, C, D, E, A, W2, W4, 74
		round24a A, B, C, D, E, W3, W5, 75
		round24a E, A, B, C, D, W1, W4, 76
		round24a D, E, A, B, C, W2, W5, 77
		round24a C, D, E, A, B, W3, W4, 78
		round24a B, C, D, E, A, W1, W5, 79

		vpaddd A, [rdi + 0 * 16]
		vpaddd B, [rdi + 1 * 16]
		vpaddd C, [rdi + 2 * 16]

		vmovdqa [r8 + 0 * 16], A
		vmovdqa [r8 + 1 * 16], B
		vmovdqa [r8 + 2 * 16], C

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



	PROC_FRAME SHA1_GenerateTripcodesWithOptimization_x64_AVX
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

		mov     rsi, qword K0
		mov     rdi, qword H0

		vmovdqa xmm0, [rcx]
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

		vmovdqa A, [rdi + 0 * 16]
		vmovdqa B, [rdi + 1 * 16]
		vmovdqa C, [rdi + 2 * 16]
		vmovdqa D, [rdi + 3 * 16]
		vmovdqa E, [rdi + 4 * 16]

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
		vmovdqa xmm5, [r8 + 1 * 16]
		round1_optimized_xmm5 E, A, B, C, D, 16
		round1_optimized      D, E, A, B, C, 17
		round1_optimized      C, D, E, A, B, 18
		vmovdqa xmm5, [r8 + 2 * 16]
		round1_optimized_xmm5 B, C, D, E, A, 19

		vmovdqa K, [rsi + 1 * 16]

		round24_optimized      A, B, C, D, E, 20
		round24_optimized      E, A, B, C, D, 21
		vmovdqa xmm5, [r8 + 3 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 22
		round24_optimized      C, D, E, A, B, 23
		vmovdqa xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 B, C, D, E, A, 24

		vmovdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 25
		round24_optimized      E, A, B, C, D, 26
		round24_optimized      D, E, A, B, C, 27
		vmovdqa xmm5, [r8 + 5 * 16]
		round24_optimized_xmm5 C, D, E, A, B, 28
		round24_optimized      B, C, D, E, A, 29

		vmovdqa xmm5, [r8 + 4 * 16]
		vpxor   xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 30
		vmovdqa xmm5, [r8 + 6 * 16]
		round24_optimized_xmm5 E, A, B, C, D, 31
		vmovdqa xmm5, [r8 + 3 * 16]
		vpxor   xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 32
		round24_optimized      C, D, E, A, B, 33
		vmovdqa xmm5, [r8 + 7 * 16]
		round24_optimized_xmm5 B, C, D, E, A, 34

		vmovdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 35
		vmovdqa xmm5, [r8 + 6 * 16]
		vpxor   xmm5, [r8 + 4 * 16]
		vmovdqa W0_6___W0_4, xmm5
		round24_optimized_xmm5 E, A, B, C, D, 36
		vmovdqa xmm5, [r8 + 8 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 37
		vmovdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 C, D, E, A, B, 38
		round24_optimized      B, C, D, E, A, 39

		vmovdqa K, [rsi + 2 * 16]

		vmovdqa xmm5, [r8 + 4 * 16]
		vpxor   xmm5, [r8 + 9 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 40
		round3_optimized       E, A, B, C, D, 41
		vmovdqa xmm5, [r8 + 6 * 16]
		vpxor   xmm5, [r8 + 8 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 42
		vmovdqa xmm5, [r8 + 10 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 43
		vmovdqa xmm5, [r8 + 6 * 16]
		vpxor   xmm5, [r8 + 3 * 16]
		vpxor   xmm5, [r8 + 7 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 44

		round3_optimized       A, B, C, D, E, 45
		vmovdqa xmm5, [r8 + 4 * 16]
		vpxor   xmm5, [r8 + 11 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 46
		vmovdqa xmm5, [r8 + 8 * 16]
		vpxor   xmm5, [r8 + 4 * 16]
		vmovdqa W0_8___W0_4, xmm5
		round3_optimized_xmm5  D, E, A, B, C, 47
		vmovdqa xmm5, W0_8___W0_4
		vpxor   xmm5, [r8 + 3 * 16]
		vpxor   xmm5, [r8 + 10 * 16]
		vpxor   xmm5, [r8 + 5 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 48
		vmovdqa xmm5, [r8 + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 49

		vmovdqa xmm5, [r8 + 8 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 50
		vmovdqa xmm5, W0_6___W0_4
		round3_optimized_xmm5  E, A, B, C, D, 51
		vmovdqa xmm5, W0_8___W0_4
		vpxor   xmm5, [r8 + 13 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 52
		round3_optimized       C, D, E, A, B, 53
		vmovdqa xmm5, [r8 + 7  * 16]
		vpxor   xmm5, [r8 + 10 * 16]
		vpxor   xmm5, [r8 + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 54

		vmovdqa xmm5, [r8 + 14 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 55
		vmovdqa xmm5, [r8 + 7  * 16]
		vpxor   xmm5, W0_6___W0_4
		vmovdqa W0_6___W0_4___W0_7, xmm5
		vpxor   xmm5, [r8 + 11 * 16]
		vpxor   xmm5, [r8 + 10 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 56
		vmovdqa xmm5, [r8 + 8  * 16]
		round3_optimized_xmm5  D, E, A, B, C, 57
		vmovdqa xmm5, W0_8___W0_4
		vpxor   xmm5, [r8 + 15 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 58
		vmovdqa xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 12 * 16]
		vmovdqa W0_8___W012, xmm5
		round3_optimized_xmm5  B, C, D, E, A, 59

		vmovdqa K, [rsi + 3 * 16]

		vmovdqa xmm5, W0_8___W012
		vpxor   xmm5, [r8 + 4  * 16]
		vpxor   xmm5, [r8 + 7  * 16]
		vpxor   xmm5, [r8 + 14 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 60
		vmovdqa xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 61
		vmovdqa xmm5, W0_6___W0_4
		vpxor   xmm5, W0_8___W012
		round24_optimized_xmm5  D, E, A, B, C, 62
		vmovdqa xmm5, [r8 + 8  * 16]
		round24_optimized_xmm5  C, D, E, A, B, 63
		vmovdqa xmm5, W0_6___W0_4___W0_7
		vpxor   xmm5, W0_8___W012
		vpxor   xmm5, [r8 + 17 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 64

		round24_optimized       A, B, C, D, E, 65
		vmovdqa xmm5, [r8 + 14 * 16]
		vpxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 66
		vmovdqa xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 18 * 16]
		round24_optimized_xmm5  D, E, A, B, C, 67
		vmovdqa xmm5, [r8 + 11 * 16]
		vpxor   xmm5, [r8 + 14 * 16]
		vpxor   xmm5, [r8 + 15 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 68
		round24_optimized       B, C, D, E, A, 69

		vmovdqa xmm5, [r8 + 12 * 16]
		vpxor   xmm5, [r8 + 19 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 70
		vmovdqa xmm5, [r8 + 12 * 16]
		vpxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 71
		vmovdqa xmm5, [r8 + 11 * 16]
		vpxor   xmm5, [r8 + 12 * 16]
		vpxor   xmm5, [r8 + 18 * 16]
		vpxor   xmm5, [r8 + 13 * 16]
		vpxor   xmm5, [r8 + 16 * 16]
		vpxor   xmm5, [r8 + 5  * 16]
		round24_optimized_xmm5  D, E, A, B, C, 72
		vmovdqa xmm5, [r8 + 20 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 73
		vmovdqa xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 74

		vmovdqa xmm5, [r8 + 6  * 16]
		vpxor   xmm5, [r8 + 12 * 16]
		vpxor   xmm5, [r8 + 14 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 75
		vmovdqa xmm5, [r8 + 7  * 16]
		vpxor   xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 12 * 16]
		vpxor   xmm5, [r8 + 16 * 16]
		vpxor   xmm5, [r8 + 21 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 76
		round24_optimized       D, E, A, B, C, 77
		vmovdqa xmm5, [r8 + 7  * 16]
		vpxor   xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 15 * 16]
		vpxor   xmm5, [r8 + 18 * 16]
		vpxor   xmm5, [r8 + 20 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 78
		vmovdqa xmm5, [r8 + 8  * 16]
		vpxor   xmm5, [r8 + 22 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 79

		vpaddd A, [rdi + 0 * 16]
		vpaddd B, [rdi + 1 * 16]
		vpaddd C, [rdi + 2 * 16]

		vmovdqa [r9 + 0 * 16], A
		vmovdqa [r9 + 1 * 16], B
		vmovdqa [r9 + 2 * 16], C

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
		