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

; global SHA1_GenerateTripcodes_x64_SSE2
global SHA1_GenerateTripcodesWithOptimization_x64_SSE2_Nehalem

; The only difference in this file is that movdqa is used instead of movaps.



;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define A xmm0
%define B xmm1
%define C xmm2
%define D xmm3
%define E xmm4

%define W0_6___W0_4        xmm10
%define W0_8___W0_4        xmm11
%define W0_6___W0_4___W0_7 xmm12
%define W0_8___W012        xmm13

%define K xmm15

%macro round1_optimized_0 5
	paddd		%5,  [rcx]
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K
	por		xmm5, xmm6
	pxor		xmm7, %4
	paddd		xmm5, xmm7
	movdqa     xmm6, %2
	pslld		xmm6, 30
	psrld		%2,   2
	paddd		%5,   xmm5
	por		%2,   xmm6
%endmacro

%macro round1_optimized 6
	paddd		%5,  [rdx + %6 * 16]
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K
	por		xmm5, xmm6
	pxor		xmm7, %4
	paddd		xmm5, xmm7
	movdqa     xmm6, %2
	pslld		xmm6, 30
	psrld		%2,   2
	paddd		%5,   xmm5
	por		%2,   xmm6
%endmacro

%macro round1_optimized_xmm5 6
	pxor       xmm5, [rdx + %6 * 16]
	paddd		%5,   xmm5
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K
	por		xmm5, xmm6
	pxor		xmm7, %4
	paddd		xmm5, xmm7
	movdqa     xmm6, %2
	pslld		xmm6, 30
	psrld		%2,   2
	paddd		%5,   xmm5
	por		%2,   xmm6
%endmacro

%macro round24_optimized 6
	paddd  %5, [rdx + %6 * 16]

	paddd	%5,   K

	movdqa xmm6, %2
	pxor   xmm6, %3
	pxor   xmm6, %4
	paddd  %5,   xmm6

	movdqa xmm7, %1
	pslld  xmm7, 5
	movdqa xmm6, %1
	psrld  xmm6, 27
	por    xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %2
	pslld  xmm7, 30
	movdqa xmm6, %2
	psrld  xmm6, 2
	por    xmm6, xmm7
	movdqa %2,   xmm6
%endmacro

%macro round24_optimized_xmm5 6
	pxor   xmm5, [rdx + %6 * 16]

	paddd  %5,   xmm5

	paddd	%5,   K

	movdqa xmm6, %2
	pxor   xmm6, %3
	pxor   xmm6, %4
	paddd  %5,   xmm6

	movdqa xmm7, %1
	pslld  xmm7, 5
	movdqa xmm6, %1
	psrld  xmm6, 27
	por    xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %2
	pslld  xmm7, 30
	movdqa xmm6, %2
	psrld  xmm6, 2
	por    xmm6, xmm7
	movdqa %2,   xmm6
%endmacro

%macro round3_optimized 6
	paddd  %5, [rdx + %6 * 16]

	paddd	%5, K

	movdqa xmm6, %2
	pand   xmm6, %3
	movdqa xmm7, %2
	pand   xmm7, %4
	movdqa xmm5, %3
	pand	xmm5, %4
	pxor   xmm7, xmm5
	pxor   xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %1
	pslld  xmm7, 5
	movdqa xmm6, %1
	psrld  xmm6, 27
	por    xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %2
	pslld  xmm7, 30
	movdqa xmm6, %2
	psrld  xmm6, 2
	por    xmm6, xmm7
	movdqa %2,   xmm6
%endmacro

%macro round3_optimized_xmm5 6
	pxor   xmm5, [rdx + %6 * 16]

	paddd  %5, xmm5

	paddd	%5, K

	movdqa xmm6, %2
	pand   xmm6, %3
	movdqa xmm7, %2
	pand   xmm7, %4
	movdqa xmm5, %3
	pand	xmm5, %4
	pxor   xmm7, xmm5
	pxor   xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %1
	pslld  xmm7, 5
	movdqa xmm6, %1
	psrld  xmm6, 27
	por    xmm6, xmm7
	paddd  %5,   xmm6

	movdqa xmm7, %2
	pslld  xmm7, 30
	movdqa xmm6, %2
	psrld  xmm6, 2
	por    xmm6, xmm7
	movdqa %2,   xmm6
%endmacro

%macro set_W0_shifted 1
	movdqa xmm1, xmm0
	pslld xmm1, %1
	movdqa xmm2, xmm0
	psrld xmm2, (32 - %1)
	por   xmm1, xmm2
	movdqa [r8 + %1 * 16], xmm1
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
	PROC_FRAME SHA1_GenerateTripcodesWithOptimization_x64_SSE2_Nehalem
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
		
		movdqa xmm0, [rcx]

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

		movdqa K, [rsi]

		movdqa A, [rdi + 0 * 16]
		movdqa B, [rdi + 1 * 16]
		movdqa C, [rdi + 2 * 16]
		movdqa D, [rdi + 3 * 16]
		movdqa E, [rdi + 4 * 16]

		round1_optimized_0 A, B, C, D, E
		round1_optimized   E, A, B, C, D, 1
		round1_optimized   D, E, A, B, C, 2
		round1_optimized   C, D, E, A, B, 3
		round1_optimized   B, C, D, E, A, 4

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
		movdqa xmm5, [r8 + 1 * 16]
		round1_optimized_xmm5 E, A, B, C, D, 16
		round1_optimized      D, E, A, B, C, 17
		round1_optimized      C, D, E, A, B, 18
		movdqa xmm5, [r8 + 2 * 16]
		round1_optimized_xmm5 B, C, D, E, A, 19

		movdqa K, [rsi + 1 * 16]

		round24_optimized      A, B, C, D, E, 20
		round24_optimized      E, A, B, C, D, 21
		movdqa xmm5, [r8 + 3 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 22
		round24_optimized      C, D, E, A, B, 23
		movdqa xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 B, C, D, E, A, 24

		movdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 25
		round24_optimized      E, A, B, C, D, 26
		round24_optimized      D, E, A, B, C, 27
		movdqa xmm5, [r8 + 5 * 16]
		round24_optimized_xmm5 C, D, E, A, B, 28
		round24_optimized      B, C, D, E, A, 29

		movdqa xmm5, [r8 + 4 * 16]
		pxor   xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 30
		movdqa xmm5, [r8 + 6 * 16]
		round24_optimized_xmm5 E, A, B, C, D, 31
		movdqa xmm5, [r8 + 3 * 16]
		pxor   xmm5, [r8 + 2 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 32
		round24_optimized      C, D, E, A, B, 33
		movdqa xmm5, [r8 + 7 * 16]
		round24_optimized_xmm5 B, C, D, E, A, 34

		movdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 A, B, C, D, E, 35
		movdqa xmm5, [r8 + 6 * 16]
		pxor   xmm5, [r8 + 4 * 16]
		movdqa W0_6___W0_4, xmm5
		round24_optimized_xmm5 E, A, B, C, D, 36
		movdqa xmm5, [r8 + 8 * 16]
		round24_optimized_xmm5 D, E, A, B, C, 37
		movdqa xmm5, [r8 + 4 * 16]
		round24_optimized_xmm5 C, D, E, A, B, 38
		round24_optimized      B, C, D, E, A, 39

		movdqa K, [rsi + 2 * 16]

		movdqa xmm5, [r8 + 4 * 16]
		pxor   xmm5, [r8 + 9 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 40
		round3_optimized       E, A, B, C, D, 41
		movdqa xmm5, [r8 + 6 * 16]
		pxor   xmm5, [r8 + 8 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 42
		movdqa xmm5, [r8 + 10 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 43
		movdqa xmm5, [r8 + 6 * 16]
		pxor   xmm5, [r8 + 3 * 16]
		pxor   xmm5, [r8 + 7 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 44

		round3_optimized       A, B, C, D, E, 45
		movdqa xmm5, [r8 + 4 * 16]
		pxor   xmm5, [r8 + 11 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 46
		movdqa xmm5, [r8 + 8 * 16]
		pxor   xmm5, [r8 + 4 * 16]
		movdqa W0_8___W0_4, xmm5
		round3_optimized_xmm5  D, E, A, B, C, 47
		movdqa xmm5, W0_8___W0_4
		pxor   xmm5, [r8 + 3 * 16]
		pxor   xmm5, [r8 + 10 * 16]
		pxor   xmm5, [r8 + 5 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 48
		movdqa xmm5, [r8 + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 49

		movdqa xmm5, [r8 + 8 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 50
		movdqa xmm5, W0_6___W0_4
		round3_optimized_xmm5  E, A, B, C, D, 51
		movdqa xmm5, W0_8___W0_4
		pxor   xmm5, [r8 + 13 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 52
		round3_optimized       C, D, E, A, B, 53
		movdqa xmm5, [r8 + 7  * 16]
		pxor   xmm5, [r8 + 10 * 16]
		pxor   xmm5, [r8 + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 54

		movdqa xmm5, [r8 + 14 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 55
		movdqa xmm5, [r8 + 7  * 16]
		pxor   xmm5, W0_6___W0_4
		movdqa W0_6___W0_4___W0_7, xmm5
		pxor   xmm5, [r8 + 11 * 16]
		pxor   xmm5, [r8 + 10 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 56
		movdqa xmm5, [r8 + 8  * 16]
		round3_optimized_xmm5  D, E, A, B, C, 57
		movdqa xmm5, W0_8___W0_4
		pxor   xmm5, [r8 + 15 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 58
		movdqa xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 12 * 16]
		movdqa W0_8___W012, xmm5
		round3_optimized_xmm5  B, C, D, E, A, 59

		movdqa K, [rsi + 3 * 16]

		movdqa xmm5, W0_8___W012
		pxor   xmm5, [r8 + 4  * 16]
		pxor   xmm5, [r8 + 7  * 16]
		pxor   xmm5, [r8 + 14 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 60
		movdqa xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 61
		movdqa xmm5, W0_6___W0_4
		pxor   xmm5, W0_8___W012
		round24_optimized_xmm5  D, E, A, B, C, 62
		movdqa xmm5, [r8 + 8  * 16]
		round24_optimized_xmm5  C, D, E, A, B, 63
		movdqa xmm5, W0_6___W0_4___W0_7
		pxor   xmm5, W0_8___W012
		pxor   xmm5, [r8 + 17 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 64

		round24_optimized       A, B, C, D, E, 65
		movdqa xmm5, [r8 + 14 * 16]
		pxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 66
		movdqa xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 18 * 16]
		round24_optimized_xmm5  D, E, A, B, C, 67
		movdqa xmm5, [r8 + 11 * 16]
		pxor   xmm5, [r8 + 14 * 16]
		pxor   xmm5, [r8 + 15 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 68
		round24_optimized       B, C, D, E, A, 69

		movdqa xmm5, [r8 + 12 * 16]
		pxor   xmm5, [r8 + 19 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 70
		movdqa xmm5, [r8 + 12 * 16]
		pxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 71
		movdqa xmm5, [r8 + 11 * 16]
		pxor   xmm5, [r8 + 12 * 16]
		pxor   xmm5, [r8 + 18 * 16]
		pxor   xmm5, [r8 + 13 * 16]
		pxor   xmm5, [r8 + 16 * 16]
		pxor   xmm5, [r8 + 5  * 16]
		round24_optimized_xmm5  D, E, A, B, C, 72
		movdqa xmm5, [r8 + 20 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 73
		movdqa xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 16 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 74

		movdqa xmm5, [r8 + 6  * 16]
		pxor   xmm5, [r8 + 12 * 16]
		pxor   xmm5, [r8 + 14 * 16]
		round24_optimized_xmm5  A, B, C, D, E, 75
		movdqa xmm5, [r8 + 7  * 16]
		pxor   xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 12 * 16]
		pxor   xmm5, [r8 + 16 * 16]
		pxor   xmm5, [r8 + 21 * 16]
		round24_optimized_xmm5  E, A, B, C, D, 76
		round24_optimized       D, E, A, B, C, 77
		movdqa xmm5, [r8 + 7  * 16]
		pxor   xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 15 * 16]
		pxor   xmm5, [r8 + 18 * 16]
		pxor   xmm5, [r8 + 20 * 16]
		round24_optimized_xmm5  C, D, E, A, B, 78
		movdqa xmm5, [r8 + 8  * 16]
		pxor   xmm5, [r8 + 22 * 16]
		round24_optimized_xmm5  B, C, D, E, A, 79

		paddd A, [rdi + 0 * 16]
		paddd B, [rdi + 1 * 16]
		paddd C, [rdi + 2 * 16]

		movdqa [r9 + 0 * 16], A
		movdqa [r9 + 1 * 16], B
		movdqa [r9 + 2 * 16], C

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
		add     rsp, 0xb8
		ret

	ENDPROC_FRAME
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00
		