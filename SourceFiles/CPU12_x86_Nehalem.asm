; Meriken's Tripcode Engine
; Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
;
; The initial veesions of this software were based on:
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
; the Free Software Foundation, either veesion 3 of the License, or
; (at your option) any later veesion.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http:;www.gnu.org/licenses/>.

; global SHA1_GenerateTripcodes_x86_SSE2
global _SHA1_GenerateTripcodesWithOptimization_x86_SSE2_Nehalem

; The only difference in this file is that movdqa is used instead of movdqa.




;;;;;;;;;;
; Macros ;
;;;;;;;;;;

%define A xmm0
%define B xmm1
%define C xmm2
%define D xmm3
%define E xmm4

%define K0 [esi + 0 * 16]
%define K1 [esi + 1 * 16]
%define K2 [esi + 2 * 16]
%define K3 [esi + 3 * 16]

%macro round1_optimized_0 5
	paddd		%5,  [ecx]
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K0
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
	paddd		%5,  [edx + %6 * 16]
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K0
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
	pxor       xmm5, [edx + %6 * 16]
	paddd		%5,   xmm5
	movdqa     xmm5, %1
	pslld		xmm5, 5
	movdqa     xmm6, %1
	psrld		xmm6, 27
	movdqa     xmm7, %3
	pxor		xmm7, %4
	pand		xmm7, %2
	paddd		%5,   K0
	por		xmm5, xmm6
	pxor		xmm7, %4
	paddd		xmm5, xmm7
	movdqa     xmm6, %2
	pslld		xmm6, 30
	psrld		%2,   2
	paddd		%5,   xmm5
	por		%2,   xmm6
%endmacro

%macro round2_optimized 6
	paddd  %5, [edx + %6 * 16]

	paddd  %5,   K1

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

%macro round2_optimized_xmm5 6
	pxor   xmm5, [edx + %6 * 16]

	paddd  %5,   xmm5

	paddd  %5,   K1

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
	paddd  %5, [edx + %6 * 16]

	paddd	%5, K2

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
	pxor   xmm5, [edx + %6 * 16]

	paddd  %5, xmm5

	paddd	%5, K2

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

%macro round4_optimized 6
	paddd  %5, [edx + %6 * 16]

	paddd  %5,   K3

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

%macro round4_optimized_xmm5 6
	pxor   xmm5, [edx + %6 * 16]

	paddd  %5,   xmm5

	paddd	%5,   K3

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

%macro set_W0_shifted 1
	movdqa xmm1, xmm0
	pslld xmm1, %1
	movdqa xmm2, xmm0
	psrld xmm2, (32 - %1)
	por   xmm1, xmm2
	movdqa [eax + %1 * 16], xmm1
%endmacro



section .data
	; Constants required for hash calculation (see p. 11 of FIPS 180-3)
	align 16
K:	dd 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
	dd 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
	dd 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
	dd 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

	; Initial hash values (see p. 14 of FIPS 180-3)
	align 16
H:	dd 0x67452301, 0x67452301, 0x67452301, 0x67452301
	dd 0xefcdab89, 0xefcdab89, 0xefcdab89, 0xefcdab89
	dd 0x98badcfe, 0x98badcfe, 0x98badcfe, 0x98badcfe
	dd 0x10325476, 0x10325476, 0x10325476, 0x10325476
	dd 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0, 0xc3d2e1f0



section .text
	_SHA1_GenerateTripcodesWithOptimization_x86_SSE2_Nehalem:
		push ebp
		mov ebp, esp
		; sub  esp, 4
		push ebx
		push esi
		push edi

		mov ecx, [ebp + 8]
		mov edx, [ebp + 12]
		mov eax, [ebp + 16]
		mov ebx, [ebp + 20]

		; ======================================

		mov     esi, dword K
		mov     edi, dword H
		
		movdqa xmm0, [ecx]
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

		movdqa A, [edi + 0 * 16]
		movdqa B, [edi + 1 * 16]
		movdqa C, [edi + 2 * 16]
		movdqa D, [edi + 3 * 16]
		movdqa E, [edi + 4 * 16]

		round1_optimized_0 A, B, C, D, E
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
		movdqa xmm5, [eax + 1 * 16]
		round1_optimized_xmm5 E, A, B, C, D, 16
		round1_optimized      D, E, A, B, C, 17
		round1_optimized      C, D, E, A, B, 18
		movdqa xmm5, [eax + 2 * 16]
		round1_optimized_xmm5 B, C, D, E, A, 19

		round2_optimized      A, B, C, D, E, 20
		round2_optimized      E, A, B, C, D, 21
		movdqa xmm5, [eax + 3 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 22
		round2_optimized      C, D, E, A, B, 23
		movdqa xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 B, C, D, E, A, 24

		movdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 25
		round2_optimized      E, A, B, C, D, 26
		round2_optimized      D, E, A, B, C, 27
		movdqa xmm5, [eax + 5 * 16]
		round2_optimized_xmm5 C, D, E, A, B, 28
		round2_optimized      B, C, D, E, A, 29

		movdqa xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 30
		movdqa xmm5, [eax + 6 * 16]
		round2_optimized_xmm5 E, A, B, C, D, 31
		movdqa xmm5, [eax + 3 * 16]
		pxor   xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 32
		round2_optimized      C, D, E, A, B, 33
		movdqa xmm5, [eax + 7 * 16]
		round2_optimized_xmm5 B, C, D, E, A, 34

		movdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 35
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 E, A, B, C, D, 36
		movdqa xmm5, [eax + 8 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 37
		movdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 C, D, E, A, B, 38
		round2_optimized      B, C, D, E, A, 39

		movdqa xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 9 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 40
		round3_optimized       E, A, B, C, D, 41
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 8 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 42
		movdqa xmm5, [eax + 10 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 43
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 3 * 16]
		pxor   xmm5, [eax + 7 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 44

		round3_optimized       A, B, C, D, E, 45
		movdqa xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 11 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 46
		movdqa xmm5, [eax + 8 * 16]
		pxor   xmm5, [eax + 4 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 47
		movdqa xmm5, [eax + 8 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 3 * 16]
		pxor   xmm5, [eax + 10 * 16]
		pxor   xmm5, [eax + 5 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 48
		movdqa xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 49

		movdqa xmm5, [eax + 8 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 50
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 4 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 51
		movdqa xmm5, [eax + 8 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 13 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 52
		round3_optimized       C, D, E, A, B, 53
		movdqa xmm5, [eax + 7  * 16]
		pxor   xmm5, [eax + 10 * 16]
		pxor   xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 54

		movdqa xmm5, [eax + 14 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 55
		movdqa xmm5, [eax + 7  * 16]
		pxor   xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 11 * 16]
		pxor   xmm5, [eax + 10 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 56
		movdqa xmm5, [eax + 8  * 16]
		round3_optimized_xmm5  D, E, A, B, C, 57
		movdqa xmm5, [eax + 8 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 15 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 58
		movdqa xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 59

		movdqa xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 4  * 16]
		pxor   xmm5, [eax + 7  * 16]
		pxor   xmm5, [eax + 14 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 60
		movdqa xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 61
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 12 * 16]
		round4_optimized_xmm5  D, E, A, B, C, 62
		movdqa xmm5, [eax + 8  * 16]
		round4_optimized_xmm5  C, D, E, A, B, 63
		movdqa xmm5, [eax + 6 * 16]
		pxor   xmm5, [eax + 4 * 16]
		pxor   xmm5, [eax + 7 * 16]
		pxor   xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 17 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 64

		round4_optimized       A, B, C, D, E, 65
		movdqa xmm5, [eax + 14 * 16]
		pxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 66
		movdqa xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 18 * 16]
		round4_optimized_xmm5  D, E, A, B, C, 67
		movdqa xmm5, [eax + 11 * 16]
		pxor   xmm5, [eax + 14 * 16]
		pxor   xmm5, [eax + 15 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 68
		round4_optimized       B, C, D, E, A, 69

		movdqa xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 19 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 70
		movdqa xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 71
		movdqa xmm5, [eax + 11 * 16]
		pxor   xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 18 * 16]
		pxor   xmm5, [eax + 13 * 16]
		pxor   xmm5, [eax + 16 * 16]
		pxor   xmm5, [eax + 5  * 16]
		round4_optimized_xmm5  D, E, A, B, C, 72
		movdqa xmm5, [eax + 20 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 73
		movdqa xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 74

		movdqa xmm5, [eax + 6  * 16]
		pxor   xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 14 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 75
		movdqa xmm5, [eax + 7  * 16]
		pxor   xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 12 * 16]
		pxor   xmm5, [eax + 16 * 16]
		pxor   xmm5, [eax + 21 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 76
		round4_optimized       D, E, A, B, C, 77
		movdqa xmm5, [eax + 7  * 16]
		pxor   xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 15 * 16]
		pxor   xmm5, [eax + 18 * 16]
		pxor   xmm5, [eax + 20 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 78
		movdqa xmm5, [eax + 8  * 16]
		pxor   xmm5, [eax + 22 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 79

		paddd A, [edi + 0 * 16]
		paddd B, [edi + 1 * 16]
		paddd C, [edi + 2 * 16]

		movdqa [ebx + 0 * 16], A
		movdqa [ebx + 1 * 16], B
		movdqa [ebx + 2 * 16], C

		; ======================================

		pop edi
		pop esi
		pop ebx
		mov esp, ebp
		pop ebp
		ret

	ENDPROC_FRAME
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00
		