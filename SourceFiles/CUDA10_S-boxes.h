#pragma once

#if __CUDA_ARCH__ < 500

// Bitslice DES S-boxes for x86 with MMX/SSE2/AVX and for typical RISC
// architectures.  These use AND, OR, XOR, NOT, and AND-NOT gates.
//
// Gate counts: 49 44 46 33 48 46 46 41
// Average: 44.125
//
// Several same-gate-count expressions for each S-box are included (for use on
// different CPUs/GPUs).
//
// These Boolean expressions corresponding to DES S-boxes have been generated
// by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
// John the Ripper password cracker: http://www.openwall.com/john/
// Being mathematical formulas, they are not copyrighted and are free for reuse
// by anyone.
//
// This file (a specific representation of the S-box expressions, surrounding
// logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.  (This is a heavily cut-down "BSD license".)
//
// The effort has been sponsored by Rapid7: http://www.rapid7.com

//
// s1-00484, 49 gates, 17 regs, 11 andn, 4/9/39/79/120 stalls, 74 biop
// Currently used for MMX/SSE2 and x86-64 SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s1(
	DES_Vector arg1,
	DES_Vector arg2,
	DES_Vector arg3,
	DES_Vector arg4,
	DES_Vector arg5,
	DES_Vector arg6,
    DES_Vector *out1,
    DES_Vector *out2,
    DES_Vector *out3,
    DES_Vector *out4
) {
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    ".reg .u32 t10;         \n\t"
	    ".reg .u32 t11;         \n\t"
	    ".reg .u32 t12;         \n\t"
	    ".reg .u32 t13;         \n\t"
	    
	    "not.b32 t0,  %8;      \n\t"
	    "and.b32 t0,  %4, t0;  \n\t"
	    "xor.b32 t1,  %7, t0;  \n\t"
	    "or.b32  t2,  %6, %9; \n\t"
	    "xor.b32 t3,  %4, %6; \n\t"
	    "and.b32 t4,  t2,  t3;  \n\t"
	    "xor.b32 t5,  %7, t4;  \n\t"
	    "not.b32 t6,  t1;       \n\t"
	    "and.b32 t6,  t5,  t6;  \n\t"

	    "xor.b32 t7,  %8, %9; \n\t"
	    "xor.b32 t8,  %6, t7;  \n\t"
	    "not.b32 t9,  t8;       \n\t"
	    "and.b32 t9,  t1,  t9;  \n\t"
	    "or.b32  t8,  %9, t4;  \n\t"
	    "xor.b32 t4,  t9,  t8;  \n\t"
	    "not.b32 t8,  t6;       \n\t"
	    "and.b32 t8,  t4,  t8;  \n\t"

	    "or.b32  t9,  %4, %9; \n\t"
	    "or.b32  t10, t4,  t9;  \n\t"
	    "not.b32 t11, t5;       \n\t"
	    "and.b32 t11, %8, t11; \n\t"
	    "xor.b32 t5,  t10, t11; \n\t"

	    "not.b32 t12, t9;       \n\t"
		"and.b32 t12, %7, t12; \n\t"
	    "xor.b32 t9,  t11, t12; \n\t"
	    "not.b32 t12, t3;       \n\t"
	    "and.b32 t12, t7,  t12; \n\t"
	    "or.b32  t3,  t9,  t12; \n\t"

	    "not.b32 t12, t0;       \n\t"
	    "and.b32 t12, %6, t12; \n\t"
	    "xor.b32 t0,  t1,  t10; \n\t"
	    "not.b32 t9,  t12;      \n\t"
	    "and.b32 t9,  t0,  t9;  \n\t"
	    "not.b32 t12, t9;       \n\t"
	    "and.b32 t0,  t2,  t4;  \n\t"
	    "xor.b32 t4,  t12, t0;  \n\t"
	    "not.b32 t13, %5;      \n\t"
	    "and.b32 t13, t5,  t13; \n\t"
	    "xor.b32 t5,  t13, t4;  \n\t"
	    "xor.b32 %2, %2, t5;  \n\t"
	
	    "xor.b32 t12, t7,  t9;  \n\t"
	    "or.b32  t0,  t11, t12; \n\t"
	    "xor.b32 t5,  t2,  t0;  \n\t"
	    "xor.b32 t11, %4, t5;  \n\t"
	    "xor.b32 t5,  t4,  t11; \n\t"
	    "or.b32  t9,  t6,  %5; \n\t"
	    "xor.b32 t12, t9,  t5;  \n\t"
	    "xor.b32 %0, %0, t12; \n\t"
	
	    "xor.b32 t13, t2,  t10; \n\t"
	    "or.b32  t0,  t3,  t13; \n\t"
	    "xor.b32 t13, t11, t0;  \n\t"
	    "or.b32  t0,  t7,  t5;  \n\t"
	    "xor.b32 t5,  t13, t0;  \n\t"
	    "or.b32  t0,  t8,  %5; \n\t"
	    "xor.b32 t6,  t0,  t5;  \n\t"
	    "xor.b32 %1, %1, t6;  \n\t"

	    "or.b32  t6,  %8, t1;  \n\t"
	    "not.b32 t9,  t13;      \n\t"
	    "and.b32 t9,  t6,  t9;  \n\t"
	    "and.b32 t13, t8,  t11; \n\t"
	    "xor.b32 t11, t9,  t13; \n\t"
	    "or.b32  t13, t11, %5; \n\t"
	    "xor.b32 t12, t13, t3;  \n\t"
	    "xor.b32 %3, %3, t12;   \n\t"
	    "}                      \n\t"

	    : "+r"(*out1),  // %0
	      "+r"(*out2),  // %1
	      "+r"(*out3),  // %2
	      "+r"(*out4)   // %3
	      
	    : "r"(arg1)     // %4
	      "r"(arg2)     // %5
	      "r"(arg3)     // %6
	      "r"(arg4)     // %7
	      "r"(arg5)     // %8
	      "r"(arg6));   // %9
}

//
// s2-016251, 44 gates, 14 regs, 13 andn, 1/9/22/61/108 stalls, 66 biop */
//
DES_SBOX_FUNCTION_QUALIFIERS void
s2(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    ".reg .u32 t10;         \n\t"
	    ".reg .u32 t11;         \n\t"
	    ".reg .u32 t12;         \n\t"

		"xor.b32 t0, %5, %8;    \n\t"

		"not.b32 t1, %9;        \n\t"
		"and.b32 t1, %4, t1;    \n\t"
		"not.b32 t2, t1;        \n\t"
		"and.b32 t2, %8, t2;    \n\t"
		"or.b32  t1, %5, t2;    \n\t"

		"not.b32 t3, %9;        \n\t"
		"and.b32 t3, t0, t3;    \n\t"
		"and.b32 t4, %4, t0;    \n\t"
		"xor.b32 t5, %8, t4;    \n\t"
		"not.b32 t6, t3;        \n\t"
		"and.b32 t6, t5, t6;    \n\t"

		"and.b32 t7, %6, %9;    \n\t"
		"xor.b32 t8, t2, t3;    \n\t"
		"and.b32 t2, t1, t8;    \n\t"
		"not.b32 t3, t7;        \n\t"
		"and.b32 t3, t2, t3;    \n\t"

		"and.b32 t8, %6, t2;    \n\t"
		"not.b32 t2, %4;        \n\t"
		"xor.b32 t9, t8, t2;    \n\t"
		"xor.b32 t2, %9, t0;    \n\t"
		"not.b32 t0, t7;        \n\t"
		"and.b32 t0, t2, t0;    \n\t"
		"xor.b32 t10, t9, t0;   \n\t"
		"not.b32 t11, t3;       \n\t"
		"and.b32 t11, %7, t11;  \n\t"
		"xor.b32 t3, t11, t10;  \n\t"
		"xor.b32 %1, %1, t3;    \n\t"

		"not.b32 t3, t0;        \n\t"
		"and.b32 t3, %5, t3;    \n\t"
		"xor.b32 t0, t5, t3;    \n\t"
		"not.b32 t5, t0;        \n\t"
		"and.b32 t5, t9, t5;    \n\t"
		"xor.b32 t9, %6, t2;    \n\t"
		"xor.b32 t11, t5, t9;   \n\t"
		"not.b32 t5, %7;        \n\t"
		"and.b32 t5, t1, t5;    \n\t"
		"xor.b32 t12, t5, t11;  \n\t"
		"xor.b32 %0, %0, t12;   \n\t"

		"xor.b32 t5, t8, t3;    \n\t"
		"or.b32  t3, t9, t5;    \n\t"
		"xor.b32 t8, t1, t10;   \n\t"
		"or.b32  t1, t7, t8;    \n\t"
		"xor.b32 t7, t3, t1;    \n\t"

		"not.b32 t1, t11;       \n\t"
		"and.b32 t1, t10, t1;   \n\t"
		"xor.b32 t3, t4, t5;    \n\t"
		"or.b32  t4, t1, t3;    \n\t"
		"not.b32 t1, t9;        \n\t"
		"and.b32 t1, t6, t1;    \n\t"
		"xor.b32 t3, t4, t1;    \n\t"
		"or.b32  t1, t3, %7;    \n\t"
		"xor.b32 t4, t1, t7;    \n\t"
		"xor.b32 %2, %2, t4;    \n\t"

		"not.b32 t1, t0;        \n\t"
		"and.b32 t1, t3, t1;    \n\t"
		"or.b32  t0, t2, t8;    \n\t"
		"xor.b32 t2, t1, t0;    \n\t"
		"or.b32  t0, t6, %7;    \n\t"
		"xor.b32 t1, t0, t2;    \n\t"
		"xor.b32 %3, %3, t1;    \n\t"
		
		"}                      \n\t"

	    : "+r"(*out1), // %0
	      "+r"(*out2), // %1
	      "+r"(*out3), // %2
	      "+r"(*out4)  // %3
	      
	    : "r"(a1)      // %4
	      "r"(a2)      // %5
	      "r"(a3)      // %6
	      "r"(a4)      // %7
	      "r"(a5)      // %8
	      "r"(a6));    // %9
}

//
// s3-000426, 46 gates, 16 regs, 14 andn, 2/5/12/35/75 stalls, 68 biop
// Currently used for x86-64 SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s3(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    ".reg .u32 t10;         \n\t"

		"not.b32 t0, %5;        \n\t"
		"and.b32 t0, %4, t0;    \n\t"
		"xor.b32 t1, %6, %9;    \n\t"
		"or.b32  t2, t0, t1;    \n\t"
		"xor.b32 t0, %7, %9;    \n\t"
		"not.b32 t3, %4;        \n\t"
		"and.b32 t3, t0, t3;    \n\t"
		"xor.b32 t4, t2, t3;    \n\t"

		"xor.b32 t5, %5, t1;    \n\t"
		"not.b32 t6, %9;        \n\t"
		"and.b32 t6, t5, t6;    \n\t"
		"xor.b32 t7, t2, t6;    \n\t"
		"not.b32 t2, t7;        \n\t"
		"and.b32 t2, t4, t2;    \n\t"

		"and.b32 t6, %9, t4;    \n\t"
		"or.b32  t8, %7, t6;    \n\t"
		"and.b32 t6, %4, t8;    \n\t"
		"xor.b32 t8, t5, t6;    \n\t"
		"not.b32 t6, %8;        \n\t"
		"and.b32 t6, t4, t6;    \n\t"
		"xor.b32 t9, t6, t8;    \n\t"
		"xor.b32 %3, %3, t9;    \n\t"

		"and.b32 t6, t1, t0;    \n\t"
		"xor.b32 t0, %4, %7;    \n\t"
		"xor.b32 t9, t7, t0;    \n\t"
		"or.b32  t7, %6, t9;    \n\t"
		"not.b32 t9, t6;        \n\t"
		"and.b32 t9, t7, t9;    \n\t"

		"or.b32  t6, t3, t0;    \n\t"
		"not.b32 t0, t6;        \n\t"
		"and.b32 t0, t8, t0;    \n\t"
		"and.b32 t7, %7, %9;    \n\t"
		"not.b32 t8, %5;        \n\t"
		"and.b32 t8, t7, t8;    \n\t"
		"xor.b32 t10, t0, t8;   \n\t"

		"not.b32 t0, %6;        \n\t"
		"and.b32 t0, t10, t0;   \n\t"
		"or.b32  t8, t5, t7;    \n\t"
		"not.b32 t7, t0;        \n\t"
		"and.b32 t7, t8, t7;    \n\t"
		"xor.b32 t0, %4, t7;    \n\t"
		"and.b32 t7, t9, %8;    \n\t"
		"xor.b32 t8, t7, t0;    \n\t"
		"xor.b32 %1, %1, t8;    \n\t"

		"not.b32 t0, %5;        \n\t"
		"and.b32 t0, t4, t0;    \n\t"
		"not.b32 t4, %6;        \n\t"
		"and.b32 t4, t0, t4;    \n\t"
		"xor.b32 t7, t5, t6;    \n\t"
		"not.b32 t6, t7;        \n\t"
		"xor.b32 t7, t4, t6;    \n\t"
		"not.b32 t4, t2;        \n\t"
		"and.b32 t4, %8, t4;    \n\t"
		"xor.b32 t2, t4, t7;    \n\t"
		"xor.b32 %0, %0, t2;    \n\t"

		"and.b32 t2, %7, t1;    \n\t"
		"or.b32  t1, t5, t7;    \n\t"
		"not.b32 t4, t2;        \n\t"
		"and.b32 t4, t1, t4;    \n\t"
		"or.b32  t1, t3, t0;    \n\t"
		"xor.b32 t0, t4, t1;    \n\t"
		"or.b32  t1, t10, %8;   \n\t"
		"xor.b32 t2, t1, t0;    \n\t"
		"xor.b32 %2, %2, t2;    \n\t"
		
		"}                      \n\t"

	    : "+r"(*out1), // %0
	      "+r"(*out2), // %1
	      "+r"(*out3), // %2
	      "+r"(*out4)  // %3
	      
	    : "r"(a1)      // %4
	      "r"(a2)      // %5
	      "r"(a3)      // %6
	      "r"(a4)      // %7
	      "r"(a5)      // %8
	      "r"(a6));    // %9
}

//
// s4, 33 gates, 11/12 regs, 9 andn, 2/21/53/86/119 stalls, 52 biop
//
DES_SBOX_FUNCTION_QUALIFIERS void
s4(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"

	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	
		"xor.b32 t0, %4, %6;    \n\t"
		"xor.b32 t1, %6, %8;    \n\t"
		"or.b32  t2, %5, %7;    \n\t"
		"xor.b32 t3, %8, t2;    \n\t"
		"not.b32 t2, t3;        \n\t"
		"and.b32 t2, t1, t2;    \n\t"
		"not.b32 t3, %5;        \n\t"
		"and.b32 t3, t1, t3;    \n\t"
		"xor.b32 t4, %7, t3;    \n\t"
		"or.b32  t5, t0, t4;    \n\t"
		"not.b32 t6, t2;        \n\t"
		"and.b32 t6, t5, t6;    \n\t"
		"xor.b32 t5, %5, t6;    \n\t"

		"and.b32 t7, t4, t5;    \n\t"
		"not.b32 t4, t7;        \n\t"
		"and.b32 t4, t1, t4;    \n\t"
		"xor.b32 t1, t0, t5;    \n\t"
		"not.b32 t0, t4;        \n\t"
		"and.b32 t0, t1, t0;    \n\t"
		"xor.b32 t4, t2, t0;    \n\t"

		"xor.b32 t0, %5, %7;    \n\t"
		"or.b32  t2, %8, t3;    \n\t"
		"xor.b32 t3, t1, t2;    \n\t"
		"not.b32 t1, t0;        \n\t"
		"and.b32 t1, t3, t1;    \n\t"
		"xor.b32 t2, t6, t1;    \n\t"
		"not.b32 t1, t4;        \n\t"
		"and.b32 t1, %9, t1;    \n\t"
		"xor.b32 t6, t1, t2;    \n\t"
		"xor.b32 %0, %0, t6;    \n\t"

		"not.b32 t1, t2;        \n\t"
		"not.b32 t2, %9;        \n\t"
		"and.b32 t2, t4, t2;    \n\t"
		"xor.b32 t6, t2, t1;    \n\t"
		"xor.b32 %1, %1, t6;    \n\t"

		"xor.b32 t2, t4, t1;    \n\t"
		"not.b32 t1, t0;        \n\t"
		"and.b32 t1, t2, t1;    \n\t"
		"or.b32  t0, t7, t1;    \n\t"
		"xor.b32 t1, t3, t0;    \n\t"
		"or.b32  t0, t5, %9;    \n\t"
		"xor.b32 t2, t0, t1;    \n\t"
		"xor.b32 %2, %2, t2;    \n\t"

		"and.b32 t0, %9, t5;    \n\t"
		"xor.b32 t2, t0, t1;    \n\t"
		"xor.b32 %3, %3, t2;    \n\t"
		
		"}                      \n\t"

	    : "+r"(*out1), // %0
	      "+r"(*out2), // %1
	      "+r"(*out3), // %2
	      "+r"(*out4)  // %3
	      
	    : "r"(a1)      // %4
	      "r"(a2)      // %5
	      "r"(a3)      // %6
	      "r"(a4)      // %7
	      "r"(a5)      // %8
	      "r"(a6));    // %9
}

//
// s5-04832, 48 gates, 15/16 regs, 9 andn, 5/23/62/109/159 stalls, 72 biop
// Currently used for MMX/SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s5(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"

	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    ".reg .u32 t10;          \n\t"
	    ".reg .u32 t11;          \n\t"
	    ".reg .u32 t12;          \n\t"
	
		"or.b32 t1, %4, %6; \n\t"
		"not.b32 t10, %9; \n\t"
		"and.b32 t10, t1, t10; \n\t"
		"xor.b32 t6, %4, t10; \n\t"
		"xor.b32 t2, %6, t6; \n\t"
		"or.b32 t3, %7, t2; \n\t"
		"not.b32 t7, %7; \n\t"
		"and.b32 t7, t10, t7; \n\t"
		"xor.b32 t10, %6, t7; \n\t"
		"and.b32 t7, %8, t10; \n\t"
		"or.b32 t12, %4, t2; \n\t"
		"xor.b32 t2, t7, t12; \n\t"
		"xor.b32 t7, %7, t2; \n\t"
		"xor.b32 t2, %9, t7; \n\t"
		"or.b32 t4, t6, t2; \n\t"
		"and.b32 t8, %8, t4; \n\t"
		"xor.b32 t11, t6, t8; \n\t"
		"and.b32 t9, %7, t12; \n\t"
		"xor.b32 t5, t11, t9; \n\t"
		"not.b32 t11, %4; \n\t"
		"and.b32 t11, t4, t11; \n\t"
		"xor.b32 t4, t10, t11; \n\t"
		"xor.b32 t9, %8, t3; \n\t"
		"not.b32 t0, t4; \n\t"
		"and.b32 t0, t9, t0; \n\t"
		"not.b32 t4, t0; \n\t"
		"not.b32 t0, %5; \n\t"
		"and.b32 t0, t4, t0; \n\t"
		"xor.b32 t4, t0, t7; \n\t"
		"xor.b32 %2, %2, t4; \n\t"
		"not.b32 t7, t8; \n\t"
		"and.b32 t7, t10, t7; \n\t"
		"xor.b32 t0, t11, t9; \n\t"
		"or.b32 t11, t5, t0; \n\t"
		"not.b32 t4, t7; \n\t"
		"and.b32 t4, t11, t4; \n\t"
		"not.b32 t0, t4; \n\t"
		"and.b32 t0, t3, t0; \n\t"
		"and.b32 t11, t2, t4; \n\t"
		"xor.b32 t7, t9, t11; \n\t"
		"and.b32 t2, t10, t12; \n\t"
		"or.b32 t11, t7, t2; \n\t"
		"xor.b32 t9, t8, t11; \n\t"
		"and.b32 t11, t9, %5; \n\t"
		"xor.b32 t12, t11, t5; \n\t"
		"xor.b32 %3, %3, t12; \n\t"
		"xor.b32 t12, t1, t4; \n\t"
		"xor.b32 t2, %4, t12; \n\t"
		"and.b32 t11, %7, t7; \n\t"
		"xor.b32 t8, t2, t11; \n\t"
		"or.b32 t12, t0, %5; \n\t"
		"xor.b32 t11, t12, t8; \n\t"
		"xor.b32 %0, %0, t11; \n\t"
		"xor.b32 t9, t3, t10; \n\t"
		"not.b32 t5, t8; \n\t"
		"and.b32 t5, t9, t5; \n\t"
		"xor.b32 t4, t6, t7; \n\t"
		"xor.b32 t1, t5, t4; \n\t"
		"and.b32 t2, t3, %5; \n\t"
		"xor.b32 t0, t2, t1; \n\t"
		"xor.b32 %1, %1, t0; \n\t"

		"}                      \n\t"

	    : "+r"(*out1), // %0
	      "+r"(*out2), // %1
	      "+r"(*out3), // %2
	      "+r"(*out4)  // %3
	      
	    : "r"(a1)      // %4
	      "r"(a2)      // %5
	      "r"(a3)      // %6
	      "r"(a4)      // %7
	      "r"(a5)      // %8
	      "r"(a6));    // %9
}

//
// s6-000007, 46 gates, 19 regs, 8 andn, 3/19/39/66/101 stalls, 69 biop
// Currently used for x86-64 SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s6(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    ".reg .u32 t10;         \n\t"
	    ".reg .u32 t11;         \n\t"
	    ".reg .u32 t12;         \n\t"
	    ".reg .u32 t13;         \n\t"
	    
		"xor.b32 t0, %5, %8; \n\t"

		"or.b32 t8, %5, %9; \n\t"
		"and.b32 t1, %4, t8; \n\t"
		"xor.b32 t8, t0, t1; \n\t"
		"xor.b32 t0, %9, t8; \n\t"
		"not.b32 t12, t0; \n\t"
		"and.b32 t12, %8, t12; \n\t"

		"and.b32 t11, %4, t0; \n\t"
		"xor.b32 t0, %5, t11; \n\t"
		"xor.b32 t4, %4, %6; \n\t"
		"or.b32 t13, t0, t4; \n\t"
		"xor.b32 t2, t8, t13; \n\t"

		"and.b32 t7, %6, t2; \n\t"
		"not.b32 t6, %9; \n\t"
		"and.b32 t6, t7, t6; \n\t"
		"or.b32 t9, t12, t0; \n\t"
		"xor.b32 t0, t6, t9; \n\t"
		"and.b32 t10, t0, %7; \n\t"
		"xor.b32 t5, t10, t2; \n\t"
		"xor.b32 %3, %3, t5; \n\t"

		"xor.b32 t5, %5, t13; \n\t"
		"not.b32 t13, t5; \n\t"
		"and.b32 t13, %9, t13; \n\t"
		"xor.b32 t10, %6, t13; \n\t"
		"not.b32 t13, t7; \n\t"
		"and.b32 t13, %8, t13; \n\t"
		"or.b32 t3, t10, t13; \n\t"

		"or.b32 t13, %4, t2; \n\t"
		"and.b32 t2, t9, t13; \n\t"
		"xor.b32 t9, t10, t2; \n\t"
		"not.b32 t13, t6; \n\t"
		"and.b32 t13, t9, t13; \n\t"
		"or.b32 t6, t12, %7; \n\t"
		"xor.b32 t12, t6, t13; \n\t"
		"xor.b32 %2, %2, t12; \n\t"

		"or.b32 t2, %5, t4; \n\t"
		"xor.b32 t6, t0, t2; \n\t"
		"or.b32 t12, t1, t3; \n\t"
		"xor.b32 t13, t6, t12; \n\t"

		"xor.b32 t4, t8, t9; \n\t"
		"not.b32 t0, t4; \n\t"
		"and.b32 t0, %8, t0; \n\t"
		"not.b32 t1, t5; \n\t"
		"xor.b32 t6, t2, t1; \n\t"
		"xor.b32 t12, t0, t6; \n\t"
		"not.b32 t9, %7; \n\t"
		"and.b32 t9, t12, t9; \n\t"
		"xor.b32 t12, t9, t13; \n\t"
		"xor.b32 %1, %1, t12; \n\t"

		"xor.b32 t9, %9, t11; \n\t"
		"xor.b32 t8, %4, t10; \n\t"
		"and.b32 t4, t9, t8; \n\t"
		"xor.b32 t5, t7, t6; \n\t"
		"xor.b32 t2, t4, t5; \n\t"
		"not.b32 t1, %7; \n\t"
		"and.b32 t1, t3, t1; \n\t"
		"xor.b32 t0, t1, t2; \n\t"
		"xor.b32 %0, %0, t0; \n\t"

	    "}                      \n\t"

	    : "+r"(*out1),  // %0
	      "+r"(*out2),  // %1
	      "+r"(*out3),  // %2
	      "+r"(*out4)   // %3
	      
	    : "r"(a1)     // %4
	      "r"(a2)     // %5
	      "r"(a3)     // %6
	      "r"(a4)     // %7
	      "r"(a5)     // %8
	      "r"(a6));   // %9
}

//
// s7-056945, 46 gates, 16 regs, 7 andn, 10/31/62/107/156 stalls, 67 biop
// Currently used for MMX/SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s7(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    
		"xor.b32 t6, %7, %8; \n\t"
		"xor.b32 t3, %6, t6; \n\t"
		"and.b32 t1, %9, t3; \n\t"
		"and.b32 t2, %7, t6; \n\t"
		"xor.b32 t4, %5, t2; \n\t"
		"and.b32 t0, t1, t4; \n\t"

		"and.b32 t7, %9, t2; \n\t"
		"xor.b32 t5, %6, t7; \n\t"
		"or.b32 t7, t4, t5; \n\t"
		"xor.b32 t8, %9, t6; \n\t"
		"xor.b32 t6, t7, t8; \n\t"
		"not.b32 t7, t0; \n\t"
		"and.b32 t7, %4, t7; \n\t"
		"xor.b32 t9, t7, t6; \n\t"
		"xor.b32 %3, %3, t9; \n\t"

		"not.b32 t7, t3; \n\t"
		"and.b32 t7, %8, t7; \n\t"
		"or.b32 t0, t4, t7; \n\t"
		"xor.b32 t9, t1, t5; \n\t"
		"xor.b32 t5, t0, t9; \n\t"

		"xor.b32 t0, t1, t8; \n\t"
		"not.b32 t1, t0; \n\t"
		"and.b32 t1, %7, t1; \n\t"
		"not.b32 t0, t1; \n\t"
		"and.b32 t0, t4, t0; \n\t"
		"xor.b32 t4, %8, t9; \n\t"
		"xor.b32 t1, t0, t4; \n\t"

		"or.b32 t9, t2, t6; \n\t"
		"and.b32 t0, %6, t1; \n\t"
		"or.b32 t4, t9, t0; \n\t"
		"not.b32 t2, t8; \n\t"
		"and.b32 t2, t3, t2; \n\t"
		"xor.b32 t6, t4, t2; \n\t"
		"not.b32 t8, %4; \n\t"
		"and.b32 t8, t6, t8; \n\t"
		"xor.b32 t9, t8, t5; \n\t"
		"xor.b32 %0, %0, t9; \n\t"

		"or.b32 t9, t1, t6; \n\t"
		"and.b32 t8, %9, t9; \n\t"
		"and.b32 t3, %5, t8; \n\t"
		"xor.b32 t4, t5, t6; \n\t"
		"xor.b32 t2, t3, t4; \n\t"

		"or.b32 t9, t0, t2; \n\t"
		"xor.b32 t5, t8, t9; \n\t"
		"xor.b32 t3, %8, t4; \n\t"
		"or.b32 t0, t5, t3; \n\t"
		"and.b32 t9, t0, %4; \n\t"
		"xor.b32 t5, t9, t1; \n\t"
		"xor.b32 %2, %2, t5; \n\t"

		"xor.b32 t9, t8, t0; \n\t"
		"or.b32 t4, t7, t9; \n\t"
		"not.b32 t5, t6; \n\t"
		"xor.b32 t3, t4, t5; \n\t"
		"not.b32 t1, %4; \n\t"
		"and.b32 t1, t3, t1; \n\t"
		"xor.b32 t0, t1, t2; \n\t"
		"xor.b32 %1, %1, t0; \n\t"


	    "}                      \n\t"

	    : "+r"(*out1),  // %0
	      "+r"(*out2),  // %1
	      "+r"(*out3),  // %2
	      "+r"(*out4)   // %3
	      
	    : "r"(a1)     // %4
	      "r"(a2)     // %5
	      "r"(a3)     // %6
	      "r"(a4)     // %7
	      "r"(a5)     // %8
	      "r"(a6));   // %9
}

//
// s8-004798, 41 gates, 14 regs, 7 andn, 7/35/76/118/160 stalls, 59 biop
// Currently used for MMX/SSE2
//
DES_SBOX_FUNCTION_QUALIFIERS void
s8(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
    DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	asm("{                      \n\t"
	    ".reg .u32 t0;          \n\t"
	    ".reg .u32 t1;          \n\t"
	    ".reg .u32 t2;          \n\t"
	    ".reg .u32 t3;          \n\t"
	    ".reg .u32 t4;          \n\t"
	    ".reg .u32 t5;          \n\t"
	    ".reg .u32 t6;          \n\t"
	    ".reg .u32 t7;          \n\t"
	    ".reg .u32 t8;          \n\t"
	    ".reg .u32 t9;          \n\t"
	    
		"not.b32 t8, %5; \n\t"
		"and.b32 t8, %6, t8; \n\t"
		"not.b32 t1, %6; \n\t"
		"and.b32 t1, %8, t1; \n\t"
		"xor.b32 t6, %7, t1; \n\t"
		"and.b32 t1, %4, t6; \n\t"
		"not.b32 t7, t8; \n\t"
		"and.b32 t7, t1, t7; \n\t"

		"not.b32 t3, t6; \n\t"
		"and.b32 t3, %5, t3; \n\t"
		"or.b32 t9, %4, t3; \n\t"
		"not.b32 t0, %6; \n\t"
		"and.b32 t0, %5, t0; \n\t"
		"xor.b32 t4, %8, t0; \n\t"
		"and.b32 t0, t9, t4; \n\t"
		"or.b32 t2, t1, t0; \n\t"

		"xor.b32 t1, t6, t0; \n\t"
		"not.b32 t0, t1; \n\t"
		"not.b32 t6, t9; \n\t"
		"and.b32 t6, %6, t6; \n\t"
		"xor.b32 t1, t0, t6; \n\t"
		"xor.b32 t9, t8, t1; \n\t"
		"or.b32 t8, t7, %9; \n\t"
		"xor.b32 t6, t8, t9; \n\t"
		"xor.b32 %1, %1, t6; \n\t"

		"xor.b32 t0, %4, t9; \n\t"
		"and.b32 t6, %8, t0; \n\t"
		"xor.b32 t8, %5, t1; \n\t"
		"xor.b32 t9, t6, t8; \n\t"
		"xor.b32 t1, t3, t9; \n\t"

		"or.b32 t6, %7, t8; \n\t"
		"xor.b32 t3, t1, t6; \n\t"
		"xor.b32 t5, t4, t3; \n\t"
		"xor.b32 t8, %4, t5; \n\t"
		"and.b32 t6, t8, %9; \n\t"
		"xor.b32 t4, t6, t1; \n\t"
		"xor.b32 %3, %3, t4; \n\t"

		"xor.b32 t6, t2, t9; \n\t"
		"or.b32 t4, %5, t6; \n\t"
		"xor.b32 t3, t0, t4; \n\t"
		"xor.b32 t8, %8, t3; \n\t"
		"and.b32 t9, t2, %9; \n\t"
		"xor.b32 t6, t9, t8; \n\t"
		"xor.b32 %2, %2, t6; \n\t"

		"or.b32  t9, %7, t0; \n\t"
		"not.b32 t6, t9; \n\t"
		"and.b32 t6, t8, t6; \n\t"
		"or.b32  t4, t7, t6; \n\t"
		"xor.b32 t3, t5, t4; \n\t"
		"or.b32  t2, t3, %9; \n\t"
		"xor.b32 t0, t2, t1; \n\t"
		"xor.b32 %0, %0, t0; \n\t"

	    "}                      \n\t"

	    : "+r"(*out1),  // %0
	      "+r"(*out2),  // %1
	      "+r"(*out3),  // %2
	      "+r"(*out4)   // %3
	      
	    : "r"(a1)     // %4
	      "r"(a2)     // %5
	      "r"(a3)     // %6
	      "r"(a4)     // %7
	      "r"(a5)     // %8
	      "r"(a6));   // %9
}

// dummies
/*
__device__ __forceinline__ void
s1(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s2(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s3(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s4(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s5(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s6(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s7(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
__device__ __forceinline__ void
s8(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{}
*/


#else

//
// Bitslice DES S-boxes with LOP3.LUT instructions
// For NVIDIA Maxwell architecture and CUDA 7.5 RC
// by DeepLearningJohnDoe, version 0.1.6, 2015/07/19
//
// Gate counts: 25 24 25 18 25 24 24 23
// Average: 23.5
// Depth: 8 7 7 6 8 10 10 8
// Average: 8
//
// Note that same S-box function with a lower gate count isn't necessarily faster.
//
// These Boolean expressions corresponding to DES S-boxes were
// discovered by <deeplearningjohndoe at gmail.com>
//
// This file itself is Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//
// The underlying mathematical formulas are NOT copyrighted.
//

#define LUT(a,b,c,d,e) DES_Vector a; asm("lop3.b32 %0, %1, %2, %3, "#e";" : "=r"(##a): "r"(##b), "r"(##c), "r"(##d));
#define LUT_(a,b,c,d,e) asm("lop3.b32 %0, %1, %2, %3, "#e";" : "=r"(##a): "r"(##b), "r"(##c), "r"(##d));

__device__ __forceinline__ void
s1(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(xAA55AA5500550055, a1, a4, a6, 0xC1)
		LUT(xA55AA55AF0F5F0F5, a3, a6, xAA55AA5500550055, 0x9E)
		LUT(x5F5F5F5FA5A5A5A5, a1, a3, a6, 0xD6)
		LUT(xF5A0F5A0A55AA55A, a4, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x56)
		LUT(x947A947AD1E7D1E7, a2, xA55AA55AF0F5F0F5, xF5A0F5A0A55AA55A, 0x6C)
		LUT(x5FFF5FFFFFFAFFFA, a6, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x7B)
		LUT(xB96CB96C69936993, a2, xF5A0F5A0A55AA55A, x5FFF5FFFFFFAFFFA, 0xD6)
		LUT(x3, a5, x947A947AD1E7D1E7, xB96CB96C69936993, 0x6A)
		LUT(x55EE55EE55EE55EE, a1, a2, a4, 0x7A)
		LUT(x084C084CB77BB77B, a2, a6, xF5A0F5A0A55AA55A, 0xC9)
		LUT(x9C329C32E295E295, x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x72)
		LUT(xA51EA51E50E050E0, a3, a6, x55EE55EE55EE55EE, 0x29)
		LUT(x4AD34AD3BE3CBE3C, a2, x947A947AD1E7D1E7, xA51EA51E50E050E0, 0x95)
		LUT(x2, a5, x9C329C32E295E295, x4AD34AD3BE3CBE3C, 0xC6)
		LUT(xD955D95595D195D1, a1, a2, x9C329C32E295E295, 0xD2)
		LUT(x8058805811621162, x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x90)
		LUT(x7D0F7D0FC4B3C4B3, xA51EA51E50E050E0, xD955D95595D195D1, x8058805811621162, 0x76)
		LUT(x0805080500010001, a3, xAA55AA5500550055, xD955D95595D195D1, 0x80)
		LUT(x4A964A96962D962D, xB96CB96C69936993, x4AD34AD3BE3CBE3C, x0805080500010001, 0xA6)
		LUT(x4, a5, x7D0F7D0FC4B3C4B3, x4A964A96962D962D, 0xA6)
		LUT(x148014807B087B08, a1, xAA55AA5500550055, x947A947AD1E7D1E7, 0x21)
		LUT(x94D894D86B686B68, xA55AA55AF0F5F0F5, x8058805811621162, x148014807B087B08, 0x6A)
		LUT(x5555555540044004, a1, a6, x084C084CB77BB77B, 0x70)
		LUT(xAFB4AFB4BF5BBF5B, x5F5F5F5FA5A5A5A5, xA51EA51E50E050E0, x5555555540044004, 0x97)
		LUT(x1, a5, x94D894D86B686B68, xAFB4AFB4BF5BBF5B, 0x6C)

		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s2(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(xEEEEEEEE99999999, a1, a2, a6, 0x97)
		LUT(xFFFFEEEE66666666, a5, a6, xEEEEEEEE99999999, 0x67)
		LUT(x5555FFFFFFFF0000, a1, a5, a6, 0x76)
		LUT(x6666DDDD5555AAAA, a2, xFFFFEEEE66666666, x5555FFFFFFFF0000, 0x69)
		LUT(x6969D3D35353ACAC, a3, xFFFFEEEE66666666, x6666DDDD5555AAAA, 0x6A)
		LUT(xCFCF3030CFCF3030, a2, a3, a5, 0x65)
		LUT(xE4E4EEEE9999F0F0, a3, xEEEEEEEE99999999, x5555FFFFFFFF0000, 0x8D)
		LUT(xE5E5BABACDCDB0B0, a1, xCFCF3030CFCF3030, xE4E4EEEE9999F0F0, 0xCA)
		LUT(x3, a4, x6969D3D35353ACAC, xE5E5BABACDCDB0B0, 0xC6)
		LUT(x3333CCCC00000000, a2, a5, a6, 0x14)
		LUT(xCCCCDDDDFFFF0F0F, a5, xE4E4EEEE9999F0F0, x3333CCCC00000000, 0xB5)
		LUT(x00000101F0F0F0F0, a3, a6, xFFFFEEEE66666666, 0x1C)
		LUT(x9A9A64646A6A9595, a1, xCFCF3030CFCF3030, x00000101F0F0F0F0, 0x96)
		LUT(x2, a4, xCCCCDDDDFFFF0F0F, x9A9A64646A6A9595, 0x6A)
		LUT(x3333BBBB3333FFFF, a1, a2, x6666DDDD5555AAAA, 0xDE)
		LUT(x1414141441410000, a1, a3, xE4E4EEEE9999F0F0, 0x90)
		LUT(x7F7FF3F3F5F53939, x6969D3D35353ACAC, x9A9A64646A6A9595, x3333BBBB3333FFFF, 0x79)
		LUT(x9494E3E34B4B3939, a5, x1414141441410000, x7F7FF3F3F5F53939, 0x29)
		LUT(x1, a4, x3333BBBB3333FFFF, x9494E3E34B4B3939, 0xA6)
		LUT(xB1B1BBBBCCCCA5A5, a1, a1, xE4E4EEEE9999F0F0, 0x4A)
		LUT(xFFFFECECEEEEDDDD, a2, x3333CCCC00000000, x9A9A64646A6A9595, 0xEF)
		LUT(xB1B1A9A9DCDC8787, xE5E5BABACDCDB0B0, xB1B1BBBBCCCCA5A5, xFFFFECECEEEEDDDD, 0x8D)
		LUT(xFFFFCCCCEEEE4444, a2, a5, xFFFFEEEE66666666, 0x2B)
		LUT(x4, a4, xB1B1A9A9DCDC8787, xFFFFCCCCEEEE4444, 0x6C)

		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s3(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(xA50FA50FA50FA50F, a1, a3, a4, 0xC9)
		LUT(xF0F00F0FF0F0F0F0, a3, a5, a6, 0x4B)
		LUT(xAF0FA0AAAF0FAF0F, a1, xA50FA50FA50FA50F, xF0F00F0FF0F0F0F0, 0x4D)
		LUT(x5AA5A55A5AA55AA5, a1, a4, xF0F00F0FF0F0F0F0, 0x69)
		LUT(xAA005FFFAA005FFF, a3, a5, xA50FA50FA50FA50F, 0xD6)
		LUT(x5AA5A55A0F5AFAA5, a6, x5AA5A55A5AA55AA5, xAA005FFFAA005FFF, 0x9C)
		LUT(x1, a2, xAF0FA0AAAF0FAF0F, x5AA5A55A0F5AFAA5, 0xA6)
		LUT(xAA55AA5500AA00AA, a1, a4, a6, 0x49)
		LUT(xFAFAA50FFAFAA50F, a1, a5, xA50FA50FA50FA50F, 0x9B)
		LUT(x50AF0F5AFA50A5A5, a1, xAA55AA5500AA00AA, xFAFAA50FFAFAA50F, 0x66)
		LUT(xAFAFAFAFFAFAFAFA, a1, a3, a6, 0x6F)
		LUT(xAFAFFFFFFFFAFAFF, a4, x50AF0F5AFA50A5A5, xAFAFAFAFFAFAFAFA, 0xEB)
		LUT(x4, a2, x50AF0F5AFA50A5A5, xAFAFFFFFFFFAFAFF, 0x6C)
		LUT(x500F500F500F500F, a1, a3, a4, 0x98)
		LUT(xF0505A0505A5050F, x5AA5A55A0F5AFAA5, xAA55AA5500AA00AA, xAFAFAFAFFAFAFAFA, 0x1D)
		LUT(xF0505A05AA55AAFF, a6, x500F500F500F500F, xF0505A0505A5050F, 0x9A)
		LUT(xFF005F55FF005F55, a1, a4, xAA005FFFAA005FFF, 0xB2)
		LUT(xA55F5AF0A55F5AF0, a5, xA50FA50FA50FA50F, x5AA5A55A5AA55AA5, 0x3D)
		LUT(x5A5F05A5A55F5AF0, a6, xFF005F55FF005F55, xA55F5AF0A55F5AF0, 0xA6)
		LUT(x3, a2, xF0505A05AA55AAFF, x5A5F05A5A55F5AF0, 0xA6)
		LUT(x0F0F0F0FA5A5A5A5, a1, a3, a6, 0xC6)
		LUT(x5FFFFF5FFFA0FFA0, x5AA5A55A5AA55AA5, xAFAFAFAFFAFAFAFA, x0F0F0F0FA5A5A5A5, 0xDB)
		LUT(xF5555AF500A05FFF, a5, xFAFAA50FFAFAA50F, xF0505A0505A5050F, 0xB9)
		LUT(x05A5AAF55AFA55A5, xF0505A05AA55AAFF, x0F0F0F0FA5A5A5A5, xF5555AF500A05FFF, 0x9B)
		LUT(x2, a2, x5FFFFF5FFFA0FFA0, x05A5AAF55AFA55A5, 0xA6)

		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s4(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(x55F055F055F055F0, a1, a3, a4, 0x72)
		LUT(xA500F5F0A500F5F0, a3, a5, x55F055F055F055F0, 0xAD)
		LUT(xF50AF50AF50AF50A, a1, a3, a4, 0x59)
		LUT(xF5FA0FFFF5FA0FFF, a3, a5, xF50AF50AF50AF50A, 0xE7)
		LUT(x61C8F93C61C8F93C, a2, xA500F5F0A500F5F0, xF5FA0FFFF5FA0FFF, 0xC6)
		LUT(x9999666699996666, a1, a2, a5, 0x69)
		LUT(x22C022C022C022C0, a2, a4, x55F055F055F055F0, 0x18)
		LUT(xB35C94A6B35C94A6, xF5FA0FFFF5FA0FFF, x9999666699996666, x22C022C022C022C0, 0x63)
		LUT(x4, a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x6A)
		LUT(x4848484848484848, a1, a2, a3, 0x12)
		LUT(x55500AAA55500AAA, a1, a5, xF5FA0FFFF5FA0FFF, 0x28)
		LUT(x3C90B3D63C90B3D6, x61C8F93C61C8F93C, x4848484848484848, x55500AAA55500AAA, 0x1E)
		LUT(x8484333384843333, a1, x9999666699996666, x4848484848484848, 0x14)
		LUT(x4452F1AC4452F1AC, xF50AF50AF50AF50A, xF5FA0FFFF5FA0FFF, xB35C94A6B35C94A6, 0x78)
		LUT(x9586CA379586CA37, x55500AAA55500AAA, x8484333384843333, x4452F1AC4452F1AC, 0xD6)
		LUT(x2, a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0x6A)
		LUT(x1, a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0xA9)
		LUT(x3, a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x56)

		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s5(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(xA0A0A0A0FFFFFFFF, a1, a3, a6, 0xAB)
		LUT(xFFFF00005555FFFF, a1, a5, a6, 0xB9)
		LUT(xB3B320207777FFFF, a2, xA0A0A0A0FFFFFFFF, xFFFF00005555FFFF, 0xE8)
		LUT(x50505A5A5A5A5050, a1, a3, xFFFF00005555FFFF, 0x34)
		LUT(xA2A2FFFF2222FFFF, a1, a5, xB3B320207777FFFF, 0xCE)
		LUT(x2E2E6969A4A46363, a2, x50505A5A5A5A5050, xA2A2FFFF2222FFFF, 0x29)
		LUT(x3, a4, xB3B320207777FFFF, x2E2E6969A4A46363, 0xA6)
		LUT(xA5A50A0AA5A50A0A, a1, a3, a5, 0x49)
		LUT(x969639396969C6C6, a2, a6, xA5A50A0AA5A50A0A, 0x96)
		LUT(x1B1B1B1B1B1B1B1B, a1, a2, a3, 0xCA)
		LUT(xBFBFBFBFF6F6F9F9, a3, xA0A0A0A0FFFFFFFF, x969639396969C6C6, 0x7E)
		LUT(x5B5BA4A4B8B81D1D, xFFFF00005555FFFF, x1B1B1B1B1B1B1B1B, xBFBFBFBFF6F6F9F9, 0x96)
		LUT(x2, a4, x969639396969C6C6, x5B5BA4A4B8B81D1D, 0xCA)
		LUT(x5555BBBBFFFF5555, a1, a2, xFFFF00005555FFFF, 0xE5)
		LUT(x6D6D9C9C95956969, x50505A5A5A5A5050, xA2A2FFFF2222FFFF, x969639396969C6C6, 0x97)
		LUT(x1A1A67676A6AB4B4, xA5A50A0AA5A50A0A, x5555BBBBFFFF5555, x6D6D9C9C95956969, 0x47)
		LUT(xA0A0FFFFAAAA0000, a3, xFFFF00005555FFFF, xA5A50A0AA5A50A0A, 0x3B)
		LUT(x36369C9CC1C1D6D6, x969639396969C6C6, x6D6D9C9C95956969, xA0A0FFFFAAAA0000, 0xD9)
		LUT(x1, a4, x1A1A67676A6AB4B4, x36369C9CC1C1D6D6, 0xCA)
		LUT(x5555F0F0F5F55555, a1, a3, xFFFF00005555FFFF, 0xB1)
		LUT(x79790202DCDC0808, xA2A2FFFF2222FFFF, xA5A50A0AA5A50A0A, x969639396969C6C6, 0x47)
		LUT(x6C6CF2F229295D5D, xBFBFBFBFF6F6F9F9, x5555F0F0F5F55555, x79790202DCDC0808, 0x6E)
		LUT(xA3A3505010101A1A, a2, xA2A2FFFF2222FFFF, x36369C9CC1C1D6D6, 0x94)
		LUT(x7676C7C74F4FC7C7, a1, x2E2E6969A4A46363, xA3A3505010101A1A, 0xD9)
		LUT(x4, a4, x6C6CF2F229295D5D, x7676C7C74F4FC7C7, 0xC6)

		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s6(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(x5050F5F55050F5F5, a1, a3, a5, 0xB2)
		LUT(x6363C6C66363C6C6, a1, a2, x5050F5F55050F5F5, 0x66)
		LUT(xAAAA5555AAAA5555, a1, a1, a5, 0xA9)
		LUT(x3A3A65653A3A6565, a3, x6363C6C66363C6C6, xAAAA5555AAAA5555, 0xA9)
		LUT(x5963A3C65963A3C6, a4, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xC6)
		LUT(xE7E76565E7E76565, a5, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xAD)
		LUT(x455D45DF455D45DF, a1, a4, xE7E76565E7E76565, 0xE4)
		LUT(x4, a6, x5963A3C65963A3C6, x455D45DF455D45DF, 0x6C)
		LUT(x1101220211012202, a2, xAAAA5555AAAA5555, x5963A3C65963A3C6, 0x20)
		LUT(xF00F0FF0F00F0FF0, a3, a4, a5, 0x69)
		LUT(x16E94A9716E94A97, xE7E76565E7E76565, x1101220211012202, xF00F0FF0F00F0FF0, 0x9E)
		LUT(x2992922929929229, a1, a2, xF00F0FF0F00F0FF0, 0x49)
		LUT(xAFAF9823AFAF9823, a5, x5050F5F55050F5F5, x2992922929929229, 0x93)
		LUT(x3, a6, x16E94A9716E94A97, xAFAF9823AFAF9823, 0x6C)
		LUT(x4801810248018102, a4, x5963A3C65963A3C6, x1101220211012202, 0xA4)
		LUT(x5EE8FFFD5EE8FFFD, a5, x16E94A9716E94A97, x4801810248018102, 0x76)
		LUT(xF0FF00FFF0FF00FF, a3, a4, a5, 0xCD)
		LUT(x942D9A67942D9A67, x3A3A65653A3A6565, x5EE8FFFD5EE8FFFD, xF0FF00FFF0FF00FF, 0x86)
		LUT(x1, a6, x5EE8FFFD5EE8FFFD, x942D9A67942D9A67, 0xA6)
		LUT(x6A40D4ED6F4DD4EE, a2, x4, xAFAF9823AFAF9823, 0x2D)
		LUT(x6CA89C7869A49C79, x1101220211012202, x16E94A9716E94A97, x6A40D4ED6F4DD4EE, 0x26)
		LUT(xD6DE73F9D6DE73F9, a3, x6363C6C66363C6C6, x455D45DF455D45DF, 0x6B)
		LUT(x925E63E1965A63E1, x3A3A65653A3A6565, x6CA89C7869A49C79, xD6DE73F9D6DE73F9, 0xA2)
		LUT(x2, a6, x6CA89C7869A49C79, x925E63E1965A63E1, 0xCA)


		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s7(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(x88AA88AA88AA88AA, a1, a2, a4, 0x0B)
		LUT(xAAAAFF00AAAAFF00, a1, a4, a5, 0x27)
		LUT(xADAFF8A5ADAFF8A5, a3, x88AA88AA88AA88AA, xAAAAFF00AAAAFF00, 0x9E)
		LUT(x0A0AF5F50A0AF5F5, a1, a3, a5, 0xA6)
		LUT(x6B69C5DC6B69C5DC, a2, xADAFF8A5ADAFF8A5, x0A0AF5F50A0AF5F5, 0x6B)
		LUT(x1C69B2DC1C69B2DC, a4, x88AA88AA88AA88AA, x6B69C5DC6B69C5DC, 0xA9)
		LUT(x1, a6, xADAFF8A5ADAFF8A5, x1C69B2DC1C69B2DC, 0x6A)
		LUT(x9C9C9C9C9C9C9C9C, a1, a2, a3, 0x63)
		LUT(xE6E63BFDE6E63BFD, a2, xAAAAFF00AAAAFF00, x0A0AF5F50A0AF5F5, 0xE7)
		LUT(x6385639E6385639E, a4, x9C9C9C9C9C9C9C9C, xE6E63BFDE6E63BFD, 0x93)
		LUT(x5959C4CE5959C4CE, a2, x6B69C5DC6B69C5DC, xE6E63BFDE6E63BFD, 0x5D)
		LUT(x5B53F53B5B53F53B, a4, x0A0AF5F50A0AF5F5, x5959C4CE5959C4CE, 0x6E)
		LUT(x3, a6, x6385639E6385639E, x5B53F53B5B53F53B, 0xC6)
		LUT(xFAF505FAFAF505FA, a3, a4, x0A0AF5F50A0AF5F5, 0x6D)
		LUT(x6A65956A6A65956A, a3, x9C9C9C9C9C9C9C9C, xFAF505FAFAF505FA, 0xA6)
		LUT(x8888CCCC8888CCCC, a1, a2, a5, 0x23)
		LUT(x94E97A9494E97A94, x1C69B2DC1C69B2DC, x6A65956A6A65956A, x8888CCCC8888CCCC, 0x72)
		LUT(x4, a6, x6A65956A6A65956A, x94E97A9494E97A94, 0xAC)
		LUT(xA050A050A050A050, a1, a3, a4, 0x21)
		LUT(xC1B87A2BC1B87A2B, xAAAAFF00AAAAFF00, x5B53F53B5B53F53B, x94E97A9494E97A94, 0xA4)
		LUT(xE96016B7E96016B7, x8888CCCC8888CCCC, xA050A050A050A050, xC1B87A2BC1B87A2B, 0x96)
		LUT(xE3CF1FD5E3CF1FD5, x88AA88AA88AA88AA, x6A65956A6A65956A, xE96016B7E96016B7, 0x3E)
		LUT(x6776675B6776675B, xADAFF8A5ADAFF8A5, x94E97A9494E97A94, xE3CF1FD5E3CF1FD5, 0x6B)
		LUT(x2, a6, xE96016B7E96016B7, x6776675B6776675B, 0xC6)


		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}

__device__ __forceinline__ void
s8(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4)
{
	LUT(xEEEE3333EEEE3333, a1, a2, a5, 0x9D)
		LUT(xBBBBBBBBBBBBBBBB, a1, a1, a2, 0x83)
		LUT(xDDDDAAAADDDDAAAA, a1, a2, a5, 0x5B)
		LUT(x29295A5A29295A5A, a3, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0x85)
		LUT(xC729695AC729695A, a4, xEEEE3333EEEE3333, x29295A5A29295A5A, 0xA6)
		LUT(x3BF77B7B3BF77B7B, a2, a5, xC729695AC729695A, 0xF9)
		LUT(x2900FF002900FF00, a4, a5, x29295A5A29295A5A, 0x0E)
		LUT(x56B3803F56B3803F, xBBBBBBBBBBBBBBBB, x3BF77B7B3BF77B7B, x2900FF002900FF00, 0x61)
		LUT(x4, a6, xC729695AC729695A, x56B3803F56B3803F, 0x6C)
		LUT(xFBFBFBFBFBFBFBFB, a1, a2, a3, 0xDF)
		LUT(x3012B7B73012B7B7, a2, a5, xC729695AC729695A, 0xD4)
		LUT(x34E9B34C34E9B34C, a4, xFBFBFBFBFBFBFBFB, x3012B7B73012B7B7, 0x69)
		LUT(xBFEAEBBEBFEAEBBE, a1, x29295A5A29295A5A, x34E9B34C34E9B34C, 0x6F)
		LUT(xFFAEAFFEFFAEAFFE, a3, xBBBBBBBBBBBBBBBB, xBFEAEBBEBFEAEBBE, 0xB9)
		LUT(x2, a6, x34E9B34C34E9B34C, xFFAEAFFEFFAEAFFE, 0xC6)
		LUT(xCFDE88BBCFDE88BB, a2, xDDDDAAAADDDDAAAA, x34E9B34C34E9B34C, 0x5C)
		LUT(x3055574530555745, a1, xC729695AC729695A, xCFDE88BBCFDE88BB, 0x71)
		LUT(x99DDEEEE99DDEEEE, a4, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0xB9)
		LUT(x693CD926693CD926, x3BF77B7B3BF77B7B, x34E9B34C34E9B34C, x99DDEEEE99DDEEEE, 0x69)
		LUT(x3, a6, x3055574530555745, x693CD926693CD926, 0x6A)
		LUT(x9955EE559955EE55, a1, a4, x99DDEEEE99DDEEEE, 0xE2)
		LUT(x9D48FA949D48FA94, x3BF77B7B3BF77B7B, xBFEAEBBEBFEAEBBE, x9955EE559955EE55, 0x9C)
		LUT(x1, a6, xC729695AC729695A, x9D48FA949D48FA94, 0x39)


		*out1 ^= x1;
	*out2 ^= x2;
	*out3 ^= x3;
	*out4 ^= x4;
}



//Pre xor

__device__ __forceinline__ void
s1(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{
	LUT(xAA55AA5500550055, a1, a4, a6, 0xC1)
		LUT(xA55AA55AF0F5F0F5, a3, a6, xAA55AA5500550055, 0x9E)
		LUT(x5F5F5F5FA5A5A5A5, a1, a3, a6, 0xD6)
		LUT(xF5A0F5A0A55AA55A, a4, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x56)
		LUT(x947A947AD1E7D1E7, a2, xA55AA55AF0F5F0F5, xF5A0F5A0A55AA55A, 0x6C)
		LUT(x5FFF5FFFFFFAFFFA, a6, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x7B)
		LUT(xB96CB96C69936993, a2, xF5A0F5A0A55AA55A, x5FFF5FFFFFFAFFFA, 0xD6)
		LUT(x3, a5, x947A947AD1E7D1E7, xB96CB96C69936993, 0x6A)
		LUT(x55EE55EE55EE55EE, a1, a2, a4, 0x7A)
		LUT(x084C084CB77BB77B, a2, a6, xF5A0F5A0A55AA55A, 0xC9)
		LUT(x9C329C32E295E295, x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x72)
		LUT(xA51EA51E50E050E0, a3, a6, x55EE55EE55EE55EE, 0x29)
		LUT(x4AD34AD3BE3CBE3C, a2, x947A947AD1E7D1E7, xA51EA51E50E050E0, 0x95)
		LUT(x2, a5, x9C329C32E295E295, x4AD34AD3BE3CBE3C, 0xC6)
		LUT(xD955D95595D195D1, a1, a2, x9C329C32E295E295, 0xD2)
		LUT(x8058805811621162, x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x90)
		LUT(x7D0F7D0FC4B3C4B3, xA51EA51E50E050E0, xD955D95595D195D1, x8058805811621162, 0x76)
		LUT(x0805080500010001, a3, xAA55AA5500550055, xD955D95595D195D1, 0x80)
		LUT(x4A964A96962D962D, xB96CB96C69936993, x4AD34AD3BE3CBE3C, x0805080500010001, 0xA6)
		LUT(x4, a5, x7D0F7D0FC4B3C4B3, x4A964A96962D962D, 0xA6)
		LUT(x148014807B087B08, a1, xAA55AA5500550055, x947A947AD1E7D1E7, 0x21)
		LUT(x94D894D86B686B68, xA55AA55AF0F5F0F5, x8058805811621162, x148014807B087B08, 0x6A)
		LUT(x5555555540044004, a1, a6, x084C084CB77BB77B, 0x70)
		LUT(xAFB4AFB4BF5BBF5B, x5F5F5F5FA5A5A5A5, xA51EA51E50E050E0, x5555555540044004, 0x97)
		LUT(x1, a5, x94D894D86B686B68, xAFB4AFB4BF5BBF5B, 0x6C)

		*out1 ^= x1;
	*out2 ^= x2;

	LUT_(*out3, *out3, x3, key3, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s2(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{
	LUT(xEEEEEEEE99999999, a1, a2, a6, 0x97)
		LUT(xFFFFEEEE66666666, a5, a6, xEEEEEEEE99999999, 0x67)
		LUT(x5555FFFFFFFF0000, a1, a5, a6, 0x76)
		LUT(x6666DDDD5555AAAA, a2, xFFFFEEEE66666666, x5555FFFFFFFF0000, 0x69)
		LUT(x6969D3D35353ACAC, a3, xFFFFEEEE66666666, x6666DDDD5555AAAA, 0x6A)
		LUT(xCFCF3030CFCF3030, a2, a3, a5, 0x65)
		LUT(xE4E4EEEE9999F0F0, a3, xEEEEEEEE99999999, x5555FFFFFFFF0000, 0x8D)
		LUT(xE5E5BABACDCDB0B0, a1, xCFCF3030CFCF3030, xE4E4EEEE9999F0F0, 0xCA)
		LUT(x3, a4, x6969D3D35353ACAC, xE5E5BABACDCDB0B0, 0xC6)
		LUT(x3333CCCC00000000, a2, a5, a6, 0x14)
		LUT(xCCCCDDDDFFFF0F0F, a5, xE4E4EEEE9999F0F0, x3333CCCC00000000, 0xB5)
		LUT(x00000101F0F0F0F0, a3, a6, xFFFFEEEE66666666, 0x1C)
		LUT(x9A9A64646A6A9595, a1, xCFCF3030CFCF3030, x00000101F0F0F0F0, 0x96)
		LUT(x2, a4, xCCCCDDDDFFFF0F0F, x9A9A64646A6A9595, 0x6A)
		LUT(x3333BBBB3333FFFF, a1, a2, x6666DDDD5555AAAA, 0xDE)
		LUT(x1414141441410000, a1, a3, xE4E4EEEE9999F0F0, 0x90)
		LUT(x7F7FF3F3F5F53939, x6969D3D35353ACAC, x9A9A64646A6A9595, x3333BBBB3333FFFF, 0x79)
		LUT(x9494E3E34B4B3939, a5, x1414141441410000, x7F7FF3F3F5F53939, 0x29)
		LUT(x1, a4, x3333BBBB3333FFFF, x9494E3E34B4B3939, 0xA6)
		LUT(xB1B1BBBBCCCCA5A5, a1, a1, xE4E4EEEE9999F0F0, 0x4A)
		LUT(xFFFFECECEEEEDDDD, a2, x3333CCCC00000000, x9A9A64646A6A9595, 0xEF)
		LUT(xB1B1A9A9DCDC8787, xE5E5BABACDCDB0B0, xB1B1BBBBCCCCA5A5, xFFFFECECEEEEDDDD, 0x8D)
		LUT(xFFFFCCCCEEEE4444, a2, a5, xFFFFEEEE66666666, 0x2B)
		LUT(x4, a4, xB1B1A9A9DCDC8787, xFFFFCCCCEEEE4444, 0x6C)

		*out1 ^= x1;
	*out2 ^= x2;

	LUT_(*out3, *out3, x3, key3, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s3(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{
	LUT(xA50FA50FA50FA50F, a1, a3, a4, 0xC9)
		LUT(xF0F00F0FF0F0F0F0, a3, a5, a6, 0x4B)
		LUT(xAF0FA0AAAF0FAF0F, a1, xA50FA50FA50FA50F, xF0F00F0FF0F0F0F0, 0x4D)
		LUT(x5AA5A55A5AA55AA5, a1, a4, xF0F00F0FF0F0F0F0, 0x69)
		LUT(xAA005FFFAA005FFF, a3, a5, xA50FA50FA50FA50F, 0xD6)
		LUT(x5AA5A55A0F5AFAA5, a6, x5AA5A55A5AA55AA5, xAA005FFFAA005FFF, 0x9C)
		LUT(x1, a2, xAF0FA0AAAF0FAF0F, x5AA5A55A0F5AFAA5, 0xA6)
		LUT(xAA55AA5500AA00AA, a1, a4, a6, 0x49)
		LUT(xFAFAA50FFAFAA50F, a1, a5, xA50FA50FA50FA50F, 0x9B)
		LUT(x50AF0F5AFA50A5A5, a1, xAA55AA5500AA00AA, xFAFAA50FFAFAA50F, 0x66)
		LUT(xAFAFAFAFFAFAFAFA, a1, a3, a6, 0x6F)
		LUT(xAFAFFFFFFFFAFAFF, a4, x50AF0F5AFA50A5A5, xAFAFAFAFFAFAFAFA, 0xEB)
		LUT(x4, a2, x50AF0F5AFA50A5A5, xAFAFFFFFFFFAFAFF, 0x6C)
		LUT(x500F500F500F500F, a1, a3, a4, 0x98)
		LUT(xF0505A0505A5050F, x5AA5A55A0F5AFAA5, xAA55AA5500AA00AA, xAFAFAFAFFAFAFAFA, 0x1D)
		LUT(xF0505A05AA55AAFF, a6, x500F500F500F500F, xF0505A0505A5050F, 0x9A)
		LUT(xFF005F55FF005F55, a1, a4, xAA005FFFAA005FFF, 0xB2)
		LUT(xA55F5AF0A55F5AF0, a5, xA50FA50FA50FA50F, x5AA5A55A5AA55AA5, 0x3D)
		LUT(x5A5F05A5A55F5AF0, a6, xFF005F55FF005F55, xA55F5AF0A55F5AF0, 0xA6)
		LUT(x3, a2, xF0505A05AA55AAFF, x5A5F05A5A55F5AF0, 0xA6)
		LUT(x0F0F0F0FA5A5A5A5, a1, a3, a6, 0xC6)
		LUT(x5FFFFF5FFFA0FFA0, x5AA5A55A5AA55AA5, xAFAFAFAFFAFAFAFA, x0F0F0F0FA5A5A5A5, 0xDB)
		LUT(xF5555AF500A05FFF, a5, xFAFAA50FFAFAA50F, xF0505A0505A5050F, 0xB9)
		LUT(x05A5AAF55AFA55A5, xF0505A05AA55AAFF, x0F0F0F0FA5A5A5A5, xF5555AF500A05FFF, 0x9B)
		LUT(x2, a2, x5FFFFF5FFFA0FFA0, x05A5AAF55AFA55A5, 0xA6)

		*out1 ^= x1;
	*out2 ^= x2;

	LUT_(*out3, *out3, x3, key3, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s4(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key1, DES_Vector key3)
{
	LUT(x55F055F055F055F0, a1, a3, a4, 0x72)
		LUT(xA500F5F0A500F5F0, a3, a5, x55F055F055F055F0, 0xAD)
		LUT(xF50AF50AF50AF50A, a1, a3, a4, 0x59)
		LUT(xF5FA0FFFF5FA0FFF, a3, a5, xF50AF50AF50AF50A, 0xE7)
		LUT(x61C8F93C61C8F93C, a2, xA500F5F0A500F5F0, xF5FA0FFFF5FA0FFF, 0xC6)
		LUT(x9999666699996666, a1, a2, a5, 0x69)
		LUT(x22C022C022C022C0, a2, a4, x55F055F055F055F0, 0x18)
		LUT(xB35C94A6B35C94A6, xF5FA0FFFF5FA0FFF, x9999666699996666, x22C022C022C022C0, 0x63)
		LUT(x4, a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x6A)
		LUT(x4848484848484848, a1, a2, a3, 0x12)
		LUT(x55500AAA55500AAA, a1, a5, xF5FA0FFFF5FA0FFF, 0x28)
		LUT(x3C90B3D63C90B3D6, x61C8F93C61C8F93C, x4848484848484848, x55500AAA55500AAA, 0x1E)
		LUT(x8484333384843333, a1, x9999666699996666, x4848484848484848, 0x14)
		LUT(x4452F1AC4452F1AC, xF50AF50AF50AF50A, xF5FA0FFFF5FA0FFF, xB35C94A6B35C94A6, 0x78)
		LUT(x9586CA379586CA37, x55500AAA55500AAA, x8484333384843333, x4452F1AC4452F1AC, 0xD6)
		LUT(x2, a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0x6A)
		LUT(x1, a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0xA9)
		LUT(x3, a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x56)

		*out2 ^= x2;
	*out4 ^= x4;

	LUT_(*out1, *out1, x1, key1, 0x96);
	LUT_(*out3, *out3, x3, key3, 0x96);
}

__device__ __forceinline__ void
s5(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key2, DES_Vector key4)
{
	LUT(xA0A0A0A0FFFFFFFF, a1, a3, a6, 0xAB)
		LUT(xFFFF00005555FFFF, a1, a5, a6, 0xB9)
		LUT(xB3B320207777FFFF, a2, xA0A0A0A0FFFFFFFF, xFFFF00005555FFFF, 0xE8)
		LUT(x50505A5A5A5A5050, a1, a3, xFFFF00005555FFFF, 0x34)
		LUT(xA2A2FFFF2222FFFF, a1, a5, xB3B320207777FFFF, 0xCE)
		LUT(x2E2E6969A4A46363, a2, x50505A5A5A5A5050, xA2A2FFFF2222FFFF, 0x29)
		LUT(x3, a4, xB3B320207777FFFF, x2E2E6969A4A46363, 0xA6)
		LUT(xA5A50A0AA5A50A0A, a1, a3, a5, 0x49)
		LUT(x969639396969C6C6, a2, a6, xA5A50A0AA5A50A0A, 0x96)
		LUT(x1B1B1B1B1B1B1B1B, a1, a2, a3, 0xCA)
		LUT(xBFBFBFBFF6F6F9F9, a3, xA0A0A0A0FFFFFFFF, x969639396969C6C6, 0x7E)
		LUT(x5B5BA4A4B8B81D1D, xFFFF00005555FFFF, x1B1B1B1B1B1B1B1B, xBFBFBFBFF6F6F9F9, 0x96)
		LUT(x2, a4, x969639396969C6C6, x5B5BA4A4B8B81D1D, 0xCA)
		LUT(x5555BBBBFFFF5555, a1, a2, xFFFF00005555FFFF, 0xE5)
		LUT(x6D6D9C9C95956969, x50505A5A5A5A5050, xA2A2FFFF2222FFFF, x969639396969C6C6, 0x97)
		LUT(x1A1A67676A6AB4B4, xA5A50A0AA5A50A0A, x5555BBBBFFFF5555, x6D6D9C9C95956969, 0x47)
		LUT(xA0A0FFFFAAAA0000, a3, xFFFF00005555FFFF, xA5A50A0AA5A50A0A, 0x3B)
		LUT(x36369C9CC1C1D6D6, x969639396969C6C6, x6D6D9C9C95956969, xA0A0FFFFAAAA0000, 0xD9)
		LUT(x1, a4, x1A1A67676A6AB4B4, x36369C9CC1C1D6D6, 0xCA)
		LUT(x5555F0F0F5F55555, a1, a3, xFFFF00005555FFFF, 0xB1)
		LUT(x79790202DCDC0808, xA2A2FFFF2222FFFF, xA5A50A0AA5A50A0A, x969639396969C6C6, 0x47)
		LUT(x6C6CF2F229295D5D, xBFBFBFBFF6F6F9F9, x5555F0F0F5F55555, x79790202DCDC0808, 0x6E)
		LUT(xA3A3505010101A1A, a2, xA2A2FFFF2222FFFF, x36369C9CC1C1D6D6, 0x94)
		LUT(x7676C7C74F4FC7C7, a1, x2E2E6969A4A46363, xA3A3505010101A1A, 0xD9)
		LUT(x4, a4, x6C6CF2F229295D5D, x7676C7C74F4FC7C7, 0xC6)

		*out1 ^= x1;
	*out3 ^= x3;

	LUT_(*out2, *out2, x2, key2, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s6(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{
	LUT(x5050F5F55050F5F5, a1, a3, a5, 0xB2)
		LUT(x6363C6C66363C6C6, a1, a2, x5050F5F55050F5F5, 0x66)
		LUT(xAAAA5555AAAA5555, a1, a1, a5, 0xA9)
		LUT(x3A3A65653A3A6565, a3, x6363C6C66363C6C6, xAAAA5555AAAA5555, 0xA9)
		LUT(x5963A3C65963A3C6, a4, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xC6)
		LUT(xE7E76565E7E76565, a5, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xAD)
		LUT(x455D45DF455D45DF, a1, a4, xE7E76565E7E76565, 0xE4)
		LUT(x4, a6, x5963A3C65963A3C6, x455D45DF455D45DF, 0x6C)
		LUT(x1101220211012202, a2, xAAAA5555AAAA5555, x5963A3C65963A3C6, 0x20)
		LUT(xF00F0FF0F00F0FF0, a3, a4, a5, 0x69)
		LUT(x16E94A9716E94A97, xE7E76565E7E76565, x1101220211012202, xF00F0FF0F00F0FF0, 0x9E)
		LUT(x2992922929929229, a1, a2, xF00F0FF0F00F0FF0, 0x49)
		LUT(xAFAF9823AFAF9823, a5, x5050F5F55050F5F5, x2992922929929229, 0x93)
		LUT(x3, a6, x16E94A9716E94A97, xAFAF9823AFAF9823, 0x6C)
		LUT(x4801810248018102, a4, x5963A3C65963A3C6, x1101220211012202, 0xA4)
		LUT(x5EE8FFFD5EE8FFFD, a5, x16E94A9716E94A97, x4801810248018102, 0x76)
		LUT(xF0FF00FFF0FF00FF, a3, a4, a5, 0xCD)
		LUT(x942D9A67942D9A67, x3A3A65653A3A6565, x5EE8FFFD5EE8FFFD, xF0FF00FFF0FF00FF, 0x86)
		LUT(x1, a6, x5EE8FFFD5EE8FFFD, x942D9A67942D9A67, 0xA6)
		LUT(x6A40D4ED6F4DD4EE, a2, x4, xAFAF9823AFAF9823, 0x2D)
		LUT(x6CA89C7869A49C79, x1101220211012202, x16E94A9716E94A97, x6A40D4ED6F4DD4EE, 0x26)
		LUT(xD6DE73F9D6DE73F9, a3, x6363C6C66363C6C6, x455D45DF455D45DF, 0x6B)
		LUT(x925E63E1965A63E1, x3A3A65653A3A6565, x6CA89C7869A49C79, xD6DE73F9D6DE73F9, 0xA2)
		LUT(x2, a6, x6CA89C7869A49C79, x925E63E1965A63E1, 0xCA)


		*out1 ^= x1;
	*out2 ^= x2;

	LUT_(*out3, *out3, x3, key3, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s7(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key3, DES_Vector key4)
{
	LUT(x88AA88AA88AA88AA, a1, a2, a4, 0x0B)
		LUT(xAAAAFF00AAAAFF00, a1, a4, a5, 0x27)
		LUT(xADAFF8A5ADAFF8A5, a3, x88AA88AA88AA88AA, xAAAAFF00AAAAFF00, 0x9E)
		LUT(x0A0AF5F50A0AF5F5, a1, a3, a5, 0xA6)
		LUT(x6B69C5DC6B69C5DC, a2, xADAFF8A5ADAFF8A5, x0A0AF5F50A0AF5F5, 0x6B)
		LUT(x1C69B2DC1C69B2DC, a4, x88AA88AA88AA88AA, x6B69C5DC6B69C5DC, 0xA9)
		LUT(x1, a6, xADAFF8A5ADAFF8A5, x1C69B2DC1C69B2DC, 0x6A)
		LUT(x9C9C9C9C9C9C9C9C, a1, a2, a3, 0x63)
		LUT(xE6E63BFDE6E63BFD, a2, xAAAAFF00AAAAFF00, x0A0AF5F50A0AF5F5, 0xE7)
		LUT(x6385639E6385639E, a4, x9C9C9C9C9C9C9C9C, xE6E63BFDE6E63BFD, 0x93)
		LUT(x5959C4CE5959C4CE, a2, x6B69C5DC6B69C5DC, xE6E63BFDE6E63BFD, 0x5D)
		LUT(x5B53F53B5B53F53B, a4, x0A0AF5F50A0AF5F5, x5959C4CE5959C4CE, 0x6E)
		LUT(x3, a6, x6385639E6385639E, x5B53F53B5B53F53B, 0xC6)
		LUT(xFAF505FAFAF505FA, a3, a4, x0A0AF5F50A0AF5F5, 0x6D)
		LUT(x6A65956A6A65956A, a3, x9C9C9C9C9C9C9C9C, xFAF505FAFAF505FA, 0xA6)
		LUT(x8888CCCC8888CCCC, a1, a2, a5, 0x23)
		LUT(x94E97A9494E97A94, x1C69B2DC1C69B2DC, x6A65956A6A65956A, x8888CCCC8888CCCC, 0x72)
		LUT(x4, a6, x6A65956A6A65956A, x94E97A9494E97A94, 0xAC)
		LUT(xA050A050A050A050, a1, a3, a4, 0x21)
		LUT(xC1B87A2BC1B87A2B, xAAAAFF00AAAAFF00, x5B53F53B5B53F53B, x94E97A9494E97A94, 0xA4)
		LUT(xE96016B7E96016B7, x8888CCCC8888CCCC, xA050A050A050A050, xC1B87A2BC1B87A2B, 0x96)
		LUT(xE3CF1FD5E3CF1FD5, x88AA88AA88AA88AA, x6A65956A6A65956A, xE96016B7E96016B7, 0x3E)
		LUT(x6776675B6776675B, xADAFF8A5ADAFF8A5, x94E97A9494E97A94, xE3CF1FD5E3CF1FD5, 0x6B)
		LUT(x2, a6, xE96016B7E96016B7, x6776675B6776675B, 0xC6)


		*out1 ^= x1;
	*out2 ^= x2;

	LUT_(*out3, *out3, x3, key3, 0x96);
	LUT_(*out4, *out4, x4, key4, 0x96);
}

__device__ __forceinline__ void
s8(DES_Vector a1, DES_Vector a2, DES_Vector a3, DES_Vector a4, DES_Vector a5, DES_Vector a6,
DES_Vector * out1, DES_Vector * out2, DES_Vector * out3, DES_Vector * out4, DES_Vector key2, DES_Vector key3)
{
	LUT(xEEEE3333EEEE3333, a1, a2, a5, 0x9D)
		LUT(xBBBBBBBBBBBBBBBB, a1, a1, a2, 0x83)
		LUT(xDDDDAAAADDDDAAAA, a1, a2, a5, 0x5B)
		LUT(x29295A5A29295A5A, a3, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0x85)
		LUT(xC729695AC729695A, a4, xEEEE3333EEEE3333, x29295A5A29295A5A, 0xA6)
		LUT(x3BF77B7B3BF77B7B, a2, a5, xC729695AC729695A, 0xF9)
		LUT(x2900FF002900FF00, a4, a5, x29295A5A29295A5A, 0x0E)
		LUT(x56B3803F56B3803F, xBBBBBBBBBBBBBBBB, x3BF77B7B3BF77B7B, x2900FF002900FF00, 0x61)
		LUT(x4, a6, xC729695AC729695A, x56B3803F56B3803F, 0x6C)
		LUT(xFBFBFBFBFBFBFBFB, a1, a2, a3, 0xDF)
		LUT(x3012B7B73012B7B7, a2, a5, xC729695AC729695A, 0xD4)
		LUT(x34E9B34C34E9B34C, a4, xFBFBFBFBFBFBFBFB, x3012B7B73012B7B7, 0x69)
		LUT(xBFEAEBBEBFEAEBBE, a1, x29295A5A29295A5A, x34E9B34C34E9B34C, 0x6F)
		LUT(xFFAEAFFEFFAEAFFE, a3, xBBBBBBBBBBBBBBBB, xBFEAEBBEBFEAEBBE, 0xB9)
		LUT(x2, a6, x34E9B34C34E9B34C, xFFAEAFFEFFAEAFFE, 0xC6)
		LUT(xCFDE88BBCFDE88BB, a2, xDDDDAAAADDDDAAAA, x34E9B34C34E9B34C, 0x5C)
		LUT(x3055574530555745, a1, xC729695AC729695A, xCFDE88BBCFDE88BB, 0x71)
		LUT(x99DDEEEE99DDEEEE, a4, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0xB9)
		LUT(x693CD926693CD926, x3BF77B7B3BF77B7B, x34E9B34C34E9B34C, x99DDEEEE99DDEEEE, 0x69)
		LUT(x3, a6, x3055574530555745, x693CD926693CD926, 0x6A)
		LUT(x9955EE559955EE55, a1, a4, x99DDEEEE99DDEEEE, 0xE2)
		LUT(x9D48FA949D48FA94, x3BF77B7B3BF77B7B, xBFEAEBBEBFEAEBBE, x9955EE559955EE55, 0x9C)
		LUT(x1, a6, xC729695AC729695A, x9D48FA949D48FA94, 0x39)


		*out1 ^= x1;
	*out4 ^= x4;

	LUT_(*out2, *out2, x2, key2, 0x96);
	LUT_(*out3, *out3, x3, key3, 0x96);
}

#endif
