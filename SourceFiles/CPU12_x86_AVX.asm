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

; global SHA1_GenerateTripcodes_x86_AVX
global _SHA1_GenerateTripcodesWithOptimization_x86_AVX



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
	vpaddd		%5,   [ecx]
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K0
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1_optimized 6
	vpaddd		%5,   [edx + %6 * 16]
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K0
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round1_optimized_xmm5 6
	vpxor       xmm5, [edx + %6 * 16]
	vpaddd		%5,   xmm5
	vpslld		xmm5, %1,  5
	vpsrld		xmm6, %1,  27
	vpxor		xmm7, %4,  %3
	vpand		xmm7, %2
	vpaddd		%5,   K0
	vpor		xmm5, xmm6
	vpxor		xmm7, %4
	vpaddd		xmm5, xmm7
	vpslld		xmm6, %2,  30
	vpsrld		%2,   %2,  2
	vpaddd		%5,   xmm5
	vpor		%2,   xmm6
%endmacro

%macro round2_optimized 6
	vpaddd  %5,   [edx + %6 * 16]

	vpaddd	%5,   K1

	vpxor   xmm6, %2,   %3
	vpxor   xmm6, %4
	vpaddd  %5,   xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5,   xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round2_optimized_xmm5 6
	vpxor   xmm5, [edx + %6 * 16]

	vpaddd  %5,   xmm5

	vpaddd	%5,   K1

	vpxor   xmm6, %2, %3
	vpxor   xmm6, %4
	vpaddd  %5,   xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5,   xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round3_optimized 6
	vpaddd  %5,   [edx + %6 * 16]

	vpaddd	%5,   K2

	vpand   xmm6, %2,   %3
	vpand   xmm7, %2,   %4
	vpand	xmm5, %3,   %4
	vpxor   xmm7, xmm5
	vpxor   xmm6, xmm7
	vpaddd  %5,   xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round3_optimized_xmm5 6
	vpxor   xmm5, [edx + %6 * 16]

	vpaddd  %5,   xmm5

	vpaddd	%5,   K2

	vpand   xmm6, %2,   %3
	vpand   xmm7, %2,   %4
	vpand	xmm5, %3,   %4
	vpxor   xmm7, xmm5
	vpxor   xmm6, xmm7
	vpaddd  %5,   xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round4_optimized 6
	vpaddd  %5,   [edx + %6 * 16]

	vpaddd	%5,   K3

	vpxor   xmm6, %2, %3
	vpxor   xmm6, %4
	vpaddd  %5,   xmm6

	vpslld  xmm7, %1,   5
	vpsrld  xmm6, %1,   27
	vpor    xmm6, xmm7
	vpaddd  %5,   %5, xmm6

	vpslld  xmm7, %2,   30
	vpsrld  xmm6, %2,   2
	vpor    %2,   xmm6, xmm7
%endmacro

%macro round4_optimized_xmm5 6
	vpxor   xmm5, [edx + %6 * 16]

	vpaddd  %5,   xmm5

	vpaddd	%5,   K3

	vpxor   xmm6, %2, %3
	vpxor   xmm6, %4
	vpaddd  %5,   xmm6

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
	vmovdqa [eax + %1 * 16], xmm1
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
	_SHA1_GenerateTripcodesWithOptimization_x86_AVX:
		push ebp
		mov  ebp, esp
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

		vmovdqa xmm0, [ecx]
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

		vmovdqa A, [edi + 0 * 16]
		vmovdqa B, [edi + 1 * 16]
		vmovdqa C, [edi + 2 * 16]
		vmovdqa D, [edi + 3 * 16]
		vmovdqa E, [edi + 4 * 16]

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
		vmovdqa xmm5, [eax + 1 * 16]
		round1_optimized_xmm5 E, A, B, C, D, 16
		round1_optimized      D, E, A, B, C, 17
		round1_optimized      C, D, E, A, B, 18
		vmovdqa xmm5, [eax + 2 * 16]
		round1_optimized_xmm5 B, C, D, E, A, 19

		round2_optimized      A, B, C, D, E, 20
		round2_optimized      E, A, B, C, D, 21
		vmovdqa xmm5, [eax + 3 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 22
		round2_optimized      C, D, E, A, B, 23
		vmovdqa xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 B, C, D, E, A, 24

		vmovdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 25
		round2_optimized      E, A, B, C, D, 26
		round2_optimized      D, E, A, B, C, 27
		vmovdqa xmm5, [eax + 5 * 16]
		round2_optimized_xmm5 C, D, E, A, B, 28
		round2_optimized      B, C, D, E, A, 29

		vmovdqa xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 30
		vmovdqa xmm5, [eax + 6 * 16]
		round2_optimized_xmm5 E, A, B, C, D, 31
		vmovdqa xmm5, [eax + 3 * 16]
		vpxor   xmm5, [eax + 2 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 32
		round2_optimized      C, D, E, A, B, 33
		vmovdqa xmm5, [eax + 7 * 16]
		round2_optimized_xmm5 B, C, D, E, A, 34

		vmovdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 A, B, C, D, E, 35
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 E, A, B, C, D, 36
		vmovdqa xmm5, [eax + 8 * 16]
		round2_optimized_xmm5 D, E, A, B, C, 37
		vmovdqa xmm5, [eax + 4 * 16]
		round2_optimized_xmm5 C, D, E, A, B, 38
		round2_optimized      B, C, D, E, A, 39

		vmovdqa xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 9 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 40
		round3_optimized       E, A, B, C, D, 41
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 8 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 42
		vmovdqa xmm5, [eax + 10 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 43
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 3 * 16]
		vpxor   xmm5, [eax + 7 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 44

		round3_optimized       A, B, C, D, E, 45
		vmovdqa xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 11 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 46
		vmovdqa xmm5, [eax + 8 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 47
		vmovdqa xmm5, [eax + 8 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 3 * 16]
		vpxor   xmm5, [eax + 10 * 16]
		vpxor   xmm5, [eax + 5 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 48
		vmovdqa xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 49

		vmovdqa xmm5, [eax + 8 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 50
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 51
		vmovdqa xmm5, [eax + 8 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 13 * 16]
		round3_optimized_xmm5  D, E, A, B, C, 52
		round3_optimized       C, D, E, A, B, 53
		vmovdqa xmm5, [eax + 7  * 16]
		vpxor   xmm5, [eax + 10 * 16]
		vpxor   xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 54

		vmovdqa xmm5, [eax + 14 * 16]
		round3_optimized_xmm5  A, B, C, D, E, 55
		vmovdqa xmm5, [eax + 7  * 16]
		vpxor   xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 11 * 16]
		vpxor   xmm5, [eax + 10 * 16]
		round3_optimized_xmm5  E, A, B, C, D, 56
		vmovdqa xmm5, [eax + 8  * 16]
		round3_optimized_xmm5  D, E, A, B, C, 57
		vmovdqa xmm5, [eax + 8 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 15 * 16]
		round3_optimized_xmm5  C, D, E, A, B, 58
		vmovdqa xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		round3_optimized_xmm5  B, C, D, E, A, 59

		vmovdqa xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 4  * 16]
		vpxor   xmm5, [eax + 7  * 16]
		vpxor   xmm5, [eax + 14 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 60
		vmovdqa xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 61
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		round4_optimized_xmm5  D, E, A, B, C, 62
		vmovdqa xmm5, [eax + 8  * 16]
		round4_optimized_xmm5  C, D, E, A, B, 63
		vmovdqa xmm5, [eax + 6 * 16]
		vpxor   xmm5, [eax + 4 * 16]
		vpxor   xmm5, [eax + 7 * 16]
		vpxor   xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 17 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 64

		round4_optimized       A, B, C, D, E, 65
		vmovdqa xmm5, [eax + 14 * 16]
		vpxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 66
		vmovdqa xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 18 * 16]
		round4_optimized_xmm5  D, E, A, B, C, 67
		vmovdqa xmm5, [eax + 11 * 16]
		vpxor   xmm5, [eax + 14 * 16]
		vpxor   xmm5, [eax + 15 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 68
		round4_optimized       B, C, D, E, A, 69

		vmovdqa xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 19 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 70
		vmovdqa xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 71
		vmovdqa xmm5, [eax + 11 * 16]
		vpxor   xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 18 * 16]
		vpxor   xmm5, [eax + 13 * 16]
		vpxor   xmm5, [eax + 16 * 16]
		vpxor   xmm5, [eax + 5  * 16]
		round4_optimized_xmm5  D, E, A, B, C, 72
		vmovdqa xmm5, [eax + 20 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 73
		vmovdqa xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 16 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 74

		vmovdqa xmm5, [eax + 6  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 14 * 16]
		round4_optimized_xmm5  A, B, C, D, E, 75
		vmovdqa xmm5, [eax + 7  * 16]
		vpxor   xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 12 * 16]
		vpxor   xmm5, [eax + 16 * 16]
		vpxor   xmm5, [eax + 21 * 16]
		round4_optimized_xmm5  E, A, B, C, D, 76
		round4_optimized       D, E, A, B, C, 77
		vmovdqa xmm5, [eax + 7  * 16]
		vpxor   xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 15 * 16]
		vpxor   xmm5, [eax + 18 * 16]
		vpxor   xmm5, [eax + 20 * 16]
		round4_optimized_xmm5  C, D, E, A, B, 78
		vmovdqa xmm5, [eax + 8  * 16]
		vpxor   xmm5, [eax + 22 * 16]
		round4_optimized_xmm5  B, C, D, E, A, 79

		vpaddd A, [edi + 0 * 16]
		vpaddd B, [edi + 1 * 16]
		vpaddd C, [edi + 2 * 16]

		vmovdqa [ebx + 0 * 16], A
		vmovdqa [ebx + 1 * 16], B
		vmovdqa [ebx + 2 * 16], C

		; ======================================

		pop edi
		pop esi
		pop ebx
		mov esp, ebp
		pop ebp
		ret

	ENDPROC_FRAME
		db "THIS_IS_THE_END_OF_THE_FUNCTION",  0x00
		