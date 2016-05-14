/*
 * Meriken's Tripcode Engine
 * Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
 *
 * The initial versions of this software were based on:
 * CUDA DES Tripper 0.2.1
 * Copyright (c) 2009 Horo/.IBXjcg
 * 
 * The code that deals with DES decryption is partially adopted from:
 * John the Ripper password cracker
 * Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
 * DeepLearningJohnDoe's fork of Meriken's Tripcode Engine
 * Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
 *
 * The code that deals with DES hash generation is partially adopted from:
 * sha_digest-2.2
 * Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
 * VecTripper 
 * Copyright (C) 2011 tmkk <tmkk@smoug.net>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http: *www.gnu.org/licenses/>.
 */



 /*
  * This code was originally generated with CodeXL and Catalyst 15.11.1 Beta for R9 285 (GCN 1.2).
  * The main loop was entirely rewritten by hand for multiple salt capability and optimization 
  * (approximately 10% performance increase).
  * Some transformations were applied to make the code compatible with GCN1.0/1.1 devices.
  */

  

.ifarch gcn1.0
	.macro v_lshlrev_b32, arg1, arg2, arg3
		v_lshl_b32 \arg1, \arg3, \arg2
	.endm
	.macro v_lshlrev_b64, arg1, arg2, arg3
		v_lshl_b64 \arg1, \arg3, \arg2
	.endm
    .macro v_add_u32, arg1, arg2, arg3, arg4
	    v_add_i32 \arg1, \arg2, \arg3, \arg4
	.endm
.elseifarch gcn1.1
	.macro v_lshlrev_b32, arg1, arg2, arg3
		v_lshl_b32 \arg1, \arg3, \arg2
	.endm
	.macro v_lshlrev_b64, arg1, arg2, arg3
		v_lshl_b64 \arg1, \arg3, \arg2
	.endm
    .macro v_add_u32, arg1, arg2, arg3, arg4
	    v_add_i32 \arg1, \arg2, \arg3, \arg4
	.endm
.endif



/*
.amd
.gpu Tonga
.32bit
.compile_options "-O5 -fbin-as -fbin-amdil -fbin-source"
.driver_info "@(#) OpenCL 1.2 AMD-APP (1800.11).  Driver version: 1800.11 (VM)"
*/
.kernel OpenCL_DES_PerformSearching
    .header
        .byte 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        .byte 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        .fill 8, 1, 0x00
    .metadata
        .ascii ";ARGSTART:__OpenCL_OpenCL_DES_PerformSearching_kernel\n"
        .ascii ";version:3:1:111\n"
        /* .ascii ";device:tonga\n" */
        .ascii ";uniqueid:1024\n"
        .ascii ";memory:uavprivate:272\n"
        .ascii ";memory:hwlocal:0\n"
        .ascii ";memory:hwregion:0\n"
        .ascii ";value:searchMode:i32:1:1:0\n"
        .ascii ";pointer:outputArray:struct:1:1:16:uav:12:32:RW:0:0\n"
        .ascii ";pointer:keyInfo:opaque:1:1:32:c:11:4:RO:0:0\n"
        .ascii ";pointer:tripcodeChunkArray:u32:1:1:48:uav:13:4:RO:0:0\n"
        .ascii ";constarg:3:tripcodeChunkArray\n"
        .ascii ";value:numTripcodeChunk:u32:1:1:64\n"
        .ascii ";pointer:smallChunkBitmap:u8:1:1:80:c:14:1:RO:0:0\n"
        .ascii ";constarg:5:smallChunkBitmap\n"
        .ascii ";pointer:compactMediumChunkBitmap:u32:1:1:96:c:11:4:RO:0:0\n"
        .ascii ";constarg:6:compactMediumChunkBitmap\n"
        .ascii ";pointer:chunkBitmap:u8:1:1:112:uav:15:1:RO:0:0\n"
        .ascii ";constarg:7:chunkBitmap\n"
        .ascii ";pointer:partialKeyFrom3To6Array:struct:1:1:128:uav:16:4:RO:0:0\n"
        .ascii ";constarg:8:partialKeyFrom3To6Array\n"
        .ascii ";value:keyFrom00To27:u32:1:1:144\n"
        .ascii ";function:1:1028\n"
        .ascii ";uavid:11\n"
        .ascii ";printfid:9\n"
        .ascii ";cbid:10\n"
        .ascii ";privateid:8\n"
        .ascii ";reflection:0:int\n"
        .ascii ";reflection:1:GPUOutput*\n"
        .ascii ";reflection:2:KeyInfo*\n"
        .ascii ";reflection:3:uint*\n"
        .ascii ";reflection:4:uint\n"
        .ascii ";reflection:5:uchar*\n"
        .ascii ";reflection:6:uint*\n"
        .ascii ";reflection:7:uchar*\n"
        .ascii ";reflection:8:PartialKeyFrom3To6*\n"
        .ascii ";reflection:9:uint\n"
        .ascii ";ARGEND:__OpenCL_OpenCL_DES_PerformSearching_kernel\n"
    .data
        .fill 4736, 1, 0x00
    .inputs
    .outputs
    .uav
        .entry 12, 4, 0, 5
        .entry 13, 4, 0, 5
        .entry 15, 4, 0, 5
        .entry 16, 4, 0, 5
        .entry 8, 3, 0, 5
    .condout 0
    .floatconsts
    .intconsts
    .boolconsts
    .earlyexit 0
    .globalbuffers
    .constantbuffers
        .cbmask 0, 0
        .cbmask 1, 0
        .cbmask 11, 0
        .cbmask 14, 0
        .cbmask 11, 0
    .inputsamplers
    .scratchbuffers
        .int 0x00000000
    .persistentbuffers
    .proginfo
        .entry 0x80001000, 0x00000003
        .entry 0x80001001, 0x00000017
        .entry 0x80001002, 0x00000000
        .entry 0x80001003, 0x00000002
        .entry 0x80001004, 0x00000002
        .entry 0x80001005, 0x00000002
        .entry 0x80001006, 0x00000000
        .entry 0x80001007, 0x00000004
        .entry 0x80001008, 0x00000004
        .entry 0x80001009, 0x00000002
        .entry 0x8000100a, 0x00000001
        .entry 0x8000100b, 0x00000008
        .entry 0x8000100c, 0x00000004
        .entry 0x80001041, 0x00000080 /* 0x0000007c */

		/* 68 SGPRs were used originally. */
.ifarch gcn1.0
        .entry 0x80001042, 0x00000068 /* 0x00000046 */ /* The last 2 SGPRs are reserved. */
.elseifarch gcn1.1
        .entry 0x80001042, 0x00000068 /* 0x00000046 */ /* The last 2 SGPRs are reserved. */
.else
        .entry 0x80001042, 0x00000066 /* 0x0000005e */ /* The last 26 SGPRs are reserved. */
.endif

        .entry 0x80001042, 0x0000005e
        .entry 0x80001863, 0x00000066
        .entry 0x80001864, 0x00000100
        .entry 0x80001043, 0x000000c0
        .entry 0x80001044, 0x00000000
        .entry 0x80001045, 0x00000000
        .entry 0x00002e13, 0x00000098
        .entry 0x8000001c, 0x00000100
        .entry 0x8000001d, 0x00000000
        .entry 0x8000001e, 0x00000000
        .entry 0x80001841, 0x00000000
        .entry 0x8000001f, 0x0001f000
        .entry 0x80001843, 0x0001f000
        .entry 0x80001844, 0x00000000
        .entry 0x80001845, 0x00000000
        .entry 0x80001846, 0x00000000
        .entry 0x80001847, 0x00000000
        .entry 0x80001848, 0x00000000
        .entry 0x80001849, 0x00000000
        .entry 0x8000184a, 0x00000000
        .entry 0x8000184b, 0x00000000
        .entry 0x8000184c, 0x00000000
        .entry 0x8000184d, 0x00000000
        .entry 0x8000184e, 0x00000000
        .entry 0x8000184f, 0x00000000
        .entry 0x80001850, 0x00000000
        .entry 0x80001851, 0x00000000
        .entry 0x80001852, 0x00000000
        .entry 0x80001853, 0x00000000
        .entry 0x80001854, 0x00000000
        .entry 0x80001855, 0x00000000
        .entry 0x80001856, 0x00000000
        .entry 0x80001857, 0x00000000
        .entry 0x80001858, 0x00000000
        .entry 0x80001859, 0x00000000
        .entry 0x8000185a, 0x00000000
        .entry 0x8000185b, 0x00000000
        .entry 0x8000185c, 0x00000000
        .entry 0x8000185d, 0x00000000
        .entry 0x8000185e, 0x00000000
        .entry 0x8000185f, 0x00000000
        .entry 0x80001860, 0x00000000
        .entry 0x80001861, 0x00000000
        .entry 0x80001862, 0x00000000
        .entry 0x8000000a, 0x00000001
        .entry 0x80000078, 0x00000040
        .entry 0x80000081, 0x00008000
        .entry 0x80000082, 0x00000000
    .subconstantbuffers
    .uavmailboxsize 0
    .uavopmask
        .byte 0x00, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
        .fill 120, 1, 0x00
    .text
.ifarch gcn1.0
        s_buffer_load_dword s0, s[4:7], 0x4
        s_buffer_load_dword s1, s[4:7], 0x18
        s_buffer_load_dword s4, s[8:11], 0x20
.elseifarch gcn1.1
        s_buffer_load_dword s0, s[4:7], 0x4
        s_buffer_load_dword s1, s[4:7], 0x18
        s_buffer_load_dword s4, s[8:11], 0x20
.else
        s_buffer_load_dword s0, s[4:7], 0x10
        s_buffer_load_dword s1, s[4:7], 0x60
        s_buffer_load_dword s4, s[8:11], 0x80
.endif
        s_waitcnt       lgkmcnt(0)
        s_min_u32       s0, s0, 0xffff
        s_mul_i32       s0, s12, s0
        s_add_u32       s0, s0, s1
.ifarch gcn1.0
        s_load_dwordx4  s[12:15], s[2:3], 0x80
.elseifarch gcn1.1
        s_load_dwordx4  s[12:15], s[2:3], 0x80
.else
        s_load_dwordx4  s[12:15], s[2:3], 0x200
.endif
        v_add_u32       v0, vcc, s0, v0
        v_lshlrev_b32   v1, 2, v0
        v_add_u32       v1, vcc, s4, v1
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v2, v1, s[12:15], 0 offen offset:1
        buffer_load_ubyte v3, v1, s[12:15], 0 offen offset:2
        buffer_load_ubyte v1, v1, s[12:15], 0 offen offset:3
.ifarch gcn1.0
        s_buffer_load_dword s0, s[8:11], 0x4
        s_buffer_load_dword s1, s[8:11], 0x24
        s_load_dwordx4  s[4:7], s[2:3], 0x60
.elseifarch gcn1.1
        s_buffer_load_dword s0, s[8:11], 0x4
        s_buffer_load_dword s1, s[8:11], 0x24
        s_load_dwordx4  s[4:7], s[2:3], 0x60
.else
        s_buffer_load_dword s0, s[8:11], 0x10
        s_buffer_load_dword s1, s[8:11], 0x90
        s_load_dwordx4  s[4:7], s[2:3], 0x180
.endif
        v_lshlrev_b32   v0, 5, v0
        s_waitcnt       lgkmcnt(0)
        v_add_u32       v0, vcc, s0, v0
        v_mov_b32       v4, 0
        s_buffer_load_dword s0, s[8:11], 0x0
.ifarch gcn1.0
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dword s13, s[8:11], 0x10
        s_buffer_load_dword s14, s[8:11], 0x14
        s_buffer_load_dword s8, s[8:11], 0x1c
.elseifarch gcn1.1
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dword s13, s[8:11], 0x10
        s_buffer_load_dword s14, s[8:11], 0x14
        s_buffer_load_dword s8, s[8:11], 0x1c
.else
        s_buffer_load_dword s12, s[8:11], 0x30
        s_buffer_load_dword s13, s[8:11], 0x40
        s_buffer_load_dword s14, s[8:11], 0x50
        s_buffer_load_dword s8, s[8:11], 0x70
.endif
        buffer_store_byte v4, v0, s[4:7], 0 offen offset:4 glc
        
		/* s_waitcnt       vmcnt(1) */
		s_waitcnt       vmcnt(1) & expcnt(0)
        


		/******************************/
		/* VARIABLES FOR BITSLICE DES */
		/******************************/

		DB00 = %v118
		DB01 = %v65
		DB02 = %v68
		DB03 = %v62
		DB04 = %v64
		DB05 = %v121
		DB06 = %v120
		DB07 = %v119
		DB08 = %v57
		DB09 = %v70
		DB10 = %v72
		DB11 = %v69
		DB12 = %v71
		DB13 = %v66
		DB14 = %v122
		DB15 = %v67
		DB16 = %v63
		DB17 = %v73
		DB18 = %v78
		DB19 = %v80
		DB20 = %v77
		DB21 = %v74
		DB22 = %v79
		DB23 = %v76
		DB24 = %v61
		DB25 = %v85
		DB26 = %v59
		DB27 = %v58
		DB28 = %v117
		DB29 = %v56
		DB30 = %v55
		DB31 = %v54
		DB32 = %v53
		DB33 = %v52
		DB34 = %v51
		DB35 = %v50
		DB36 = %v49
		DB37 = %v48
		DB38 = %v47
		DB39 = %v46
		DB40 = %v45
		DB41 = %v44
		DB42 = %v43
		DB43 = %v42
		DB44 = %v41
		DB45 = %v40
		DB46 = %v39
		DB47 = %v38
		DB48 = %v37
		DB49 = %v36
		DB50 = %v35
		DB51 = %v34
		DB52 = %v33
		DB53 = %v32
		DB54 = %v31
		DB55 = %v30
		DB56 = %v29
		DB57 = %v28
		DB58 = %v27
		DB59 = %v26
		DB60 = %v25
		DB61 = %v24
		DB62 = %v23
		DB63 = %v22

		K27 = %s10
        K26 = %s11
        K25 = %s15
        K24 = %s16
        K23 = %s17
        K22 = %s18
        K21 = %s19
        K20 = %s20
        K19 = %s21
        K18 = %s22
        K17 = %s23
        K16 = %s24
        K15 = %s25
        K14 = %s26
        K13 = %s27
        K12 = %s28
        K11 = %s29
        K10 = %s30
        K09 = %s31
        K08 = %s32
        K07 = %s33
        K06 = %s34
        K05 = %s35
        K04 = %s36
        K03 = %s37
        K02 = %s38
        K00 = %s9
        K01 = %s1
		
		K34 = %v17
        K33 = %v18
        K32 = %v19
        K31 = %v20
        K30 = %v21
        K29 = %v2
        K28 = %v8

        K41 = %v6
        K35 = %v7
        K40 = %v13
        K39 = %v14
        K38 = %v15
        K37 = %v16
        K36 = %v3

		K48 = %v4
        K42 = %v5
		K47 = %v9
        K46 = %v10
        K45 = %v11
        K44 = %v12
        K43 = %v1

		TEMP00 = %v95
		TEMP01 = %v101
		TEMP02 = %v92
		TEMP03 = %v81
		TEMP04 = %v97
		TEMP05 = %v93
		TEMP06 = %v98
		TEMP07 = %v90
		TEMP08 = %v104
		TEMP09 = %v94
		TEMP10 = %v86
		TEMP11 = %v102
		TEMP12 = %v96
		TEMP13 = %v89
		TEMP14 = %v107
		TEMP15 = %v87
		TEMP16 = %v100
		TEMP17 = %v88
		TEMP18 = %v109
		TEMP19 = %v99
		TEMP20 = %v103
		TEMP21 = %v110
		TEMP22 = %v111
		TEMP23 = %v112
		TEMP24 = %v113
		TEMP25 = %v114
		TEMP26 = %v115
		TEMP27 = %v105
		TEMP28 = %v106
		TEMP29 = %v108
		TEMP30 = %v91
		TEMP31 = %v83
		TEMP32 = %v82
		TEMP33 = %v84
		TEMP34 = %v60
		TEMP35 = %v75
		TEMP36 = %v124

        

		/**************/
		/* DUMMY DATA */
		/**************/

		/*
		DB_EF00 = %v54
		DB_EF01 = %v118
		DB_EF02 = %v65
		DB_EF03 = %v68
		DB_EF04 = %v62
		DB_EF05 = %v64
		DB_EF06 = %v62
		DB_EF07 = %v64
		DB_EF08 = %v121
		DB_EF09 = %v120
		DB_EF10 = %v119
		DB_EF11 = %v57
		DB_EF12 = %v119
		DB_EF13 = %v57
		DB_EF14 = %v70
		DB_EF15 = %v72
		DB_EF16 = %v69
		DB_EF17 = %v71
		DB_EF18 = %v69
		DB_EF19 = %v71
		DB_EF20 = %v66
		DB_EF21 = %v122
		DB_EF22 = %v67
		DB_EF23 = %v63
		DB_EF24 = %v67
		DB_EF25 = %v63
		DB_EF26 = %v73
		DB_EF27 = %v78
		DB_EF28 = %v80
		DB_EF29 = %v77
		DB_EF30 = %v80
		DB_EF31 = %v77
		DB_EF32 = %v74
		DB_EF33 = %v79
		DB_EF34 = %v76
		DB_EF35 = %v61
		DB_EF36 = %v76
		DB_EF37 = %v61
		DB_EF38 = %v85
		DB_EF39 = %v59
		DB_EF40 = %v58
		DB_EF41 = %v117
		DB_EF42 = %v58
		DB_EF43 = %v117
		DB_EF44 = %v56
		DB_EF45 = %v55
		DB_EF46 = %v54
		DB_EF47 = %v118
		DB_EF48 = %v22
		DB_EF49 = %v53
		DB_EF50 = %v52
		DB_EF51 = %v51
		DB_EF52 = %v50
		DB_EF53 = %v49
		DB_EF54 = %v50
		DB_EF55 = %v49
		DB_EF56 = %v48
		DB_EF57 = %v47
		DB_EF58 = %v46
		DB_EF59 = %v45
		DB_EF60 = %v46
		DB_EF61 = %v45
		DB_EF62 = %v44
		DB_EF63 = %v43
		DB_EF64 = %v42
		DB_EF65 = %v41
		DB_EF66 = %v42
		DB_EF67 = %v41
		DB_EF68 = %v40
		DB_EF69 = %v39
		DB_EF70 = %v38
		DB_EF71 = %v37
		DB_EF72 = %v38
		DB_EF73 = %v37
		DB_EF74 = %v36
		DB_EF75 = %v35
		DB_EF76 = %v34
		DB_EF77 = %v33
		DB_EF78 = %v34
		DB_EF79 = %v33
		DB_EF80 = %v32
		DB_EF81 = %v31
		DB_EF82 = %v30
		DB_EF83 = %v29
		DB_EF84 = %v30
		DB_EF85 = %v29
		DB_EF86 = %v28
		DB_EF87 = %v27
		DB_EF88 = %v26
		DB_EF89 = %v25
		DB_EF90 = %v26
		DB_EF91 = %v25
		DB_EF92 = %v24
		DB_EF93 = %v23
		DB_EF94 = %v22
		DB_EF95 = %v53

		K49 = 0xaaaaaaaa
        K50 = 0x33333333
        K51 = 0x3c3c3c3c
        K52 = 0xc03fc03f
        K53 = 0xffc0003f
        K54 = 0x00000000
        K55 = 0xffffffff

		KEY7_00 = 0xda
		KEY7_01 = 0xdb
		KEY7_02 = 0xdc
		KEY7_03 = 0xdd
		KEY7_04 = 0xde
		KEY7_05 = 0xdf
		KEY7_06 = 0x40
		KEY7_07 = 0x41
		KEY7_08 = 0x42
		KEY7_09 = 0x43
		KEY7_10 = 0x44
		KEY7_11 = 0x45
		KEY7_12 = 0x46
		KEY7_13 = 0x47
		KEY7_14 = 0x48
		KEY7_15 = 0x49
		KEY7_16 = 0x4a
		KEY7_17 = 0x4b
		KEY7_18 = 0x4c
		KEY7_19 = 0x4d
		KEY7_20 = 0x4e
		KEY7_21 = 0x4f
		KEY7_22 = 0x50
		KEY7_23 = 0x51
		KEY7_24 = 0x52
		KEY7_25 = 0x53
		KEY7_26 = 0x54
		KEY7_27 = 0x55
		KEY7_28 = 0x56
		KEY7_29 = 0x57
		KEY7_30 = 0x58
		KEY7_31 = 0x59
		*/



		/****************/
		/* BITSLICE DES */
		/****************/

		v_bfe_i32       K34, K29, 6, 1
        v_bfe_i32       K33, K29, 5, 1
        v_bfe_i32       K32, K29, 4, 1
        v_bfe_i32       K31, K29, 3, 1
        v_bfe_i32       K30, K29, 2, 1
        v_bfe_i32       K28, K29, 0, 1
        v_bfe_i32       K29, K29, 1, 1

        v_bfe_i32       K41, K36, 6, 1
        v_bfe_i32       K35, K36, 0, 1
        v_bfe_i32       K40, K36, 5, 1
        v_bfe_i32       K39, K36, 4, 1
        v_bfe_i32       K38, K36, 3, 1
        v_bfe_i32       K37, K36, 2, 1
        v_bfe_i32       K36, K36, 1, 1

		v_bfe_i32       K48, K43, 6, 1
        v_bfe_i32       K42, K43, 0, 1
		v_bfe_i32       K47, K43, 5, 1
        v_bfe_i32       K46, K43, 4, 1
        v_bfe_i32       K45, K43, 3, 1
        v_bfe_i32       K44, K43, 2, 1
        v_bfe_i32       K43, K43, 1, 1
        
		s_bfe_i32       K27, K01, 0x1001b
        s_bfe_i32       K26, K01, 0x1001a
        s_bfe_i32       K25, K01, 0x10019
        s_bfe_i32       K24, K01, 0x10018
        s_bfe_i32       K23, K01, 0x10017
        s_bfe_i32       K22, K01, 0x10016
        s_bfe_i32       K21, K01, 0x10015
        s_bfe_i32       K20, K01, 0x10014
        s_bfe_i32       K19, K01, 0x10013
        s_bfe_i32       K18, K01, 0x10012
        s_bfe_i32       K17, K01, 0x10011
        s_bfe_i32       K16, K01, 0x10010
        s_bfe_i32       K15, K01, 0x1000f
        s_bfe_i32       K14, K01, 0x1000e
        s_bfe_i32       K13, K01, 0x1000d
        s_bfe_i32       K12, K01, 0x1000c
        s_bfe_i32       K11, K01, 0x1000b
        s_bfe_i32       K10, K01, 0x1000a
        s_bfe_i32       K09, K01, 0x10009
        s_bfe_i32       K08, K01, 0x10008
        s_bfe_i32       K07, K01, 0x10007
        s_bfe_i32       K06, K01, 0x10006
        s_bfe_i32       K05, K01, 0x10005
        s_bfe_i32       K04, K01, 0x10004
        s_bfe_i32       K03, K01, 0x10003
        s_bfe_i32       K02, K01, 0x10002
        s_bfe_i32       K00, K01, 0x10000
        s_bfe_i32       K01, K01, 0x10001

        v_mov_b32       DB63, 0
        v_mov_b32       DB62, 0
        v_mov_b32       DB61, 0
        v_mov_b32       DB60, 0
        v_mov_b32       DB59, 0
        v_mov_b32       DB58, 0
        v_mov_b32       DB57, 0
        v_mov_b32       DB56, 0
        v_mov_b32       DB55, 0
        v_mov_b32       DB54, 0
        v_mov_b32       DB53, 0
        v_mov_b32       DB52, 0
        v_mov_b32       DB51, 0
        v_mov_b32       DB50, 0
        v_mov_b32       DB49, 0
        v_mov_b32       DB48, 0
        v_mov_b32       DB47, 0
        v_mov_b32       DB46, 0
        v_mov_b32       DB45, 0
        v_mov_b32       DB44, 0
        v_mov_b32       DB43, 0
        v_mov_b32       DB42, 0
        v_mov_b32       DB41, 0
        v_mov_b32       DB40, 0
        v_mov_b32       DB39, 0
        v_mov_b32       DB38, 0
        v_mov_b32       DB37, 0
        v_mov_b32       DB36, 0
        v_mov_b32       DB35, 0
        v_mov_b32       DB34, 0
        v_mov_b32       DB33, 0
        v_mov_b32       DB32, 0
        v_mov_b32       DB31, 0
        v_mov_b32       DB30, 0
        v_mov_b32       DB29, 0
        v_mov_b32       DB28, 0
        v_mov_b32       DB27, 0
        v_mov_b32       DB26, 0
        v_mov_b32       DB25, 0
        v_mov_b32       DB24, 0
        v_mov_b32       DB23, 0
        v_mov_b32       DB22, 0
        v_mov_b32       DB21, 0
        v_mov_b32       DB20, 0
        v_mov_b32       DB19, 0
        v_mov_b32       DB18, 0
        v_mov_b32       DB17, 0
        v_mov_b32       DB16, 0
        v_mov_b32       DB15, 0
        v_mov_b32       DB14, 0
        v_mov_b32       DB13, 0
        v_mov_b32       DB12, 0
        v_mov_b32       DB11, 0
        v_mov_b32       DB10, 0
        v_mov_b32       DB09, 0
        v_mov_b32       DB08, 0
        v_mov_b32       DB07, 0
        v_mov_b32       DB06, 0
        v_mov_b32       DB05, 0
        v_mov_b32       DB04, 0
        v_mov_b32       DB03, 0
        v_mov_b32       DB02, 0
        v_mov_b32       DB01, 0
        v_mov_b32       DB00, 0

        s_movk_i32      s39, 13

 

.S1_S2_A:
		s_getpc_b64 s[42:43]
		s_add_u32 s42,s42,12
		s_addc_u32 s43,s43,0
		s_branch .S3_S4_A
		
        v_bfi_b32 TEMP28, TEMP19, TEMP16, TEMP17
        v_xor_b32 TEMP36, TEMP16, TEMP17
        v_or_b32  TEMP35, TEMP15, TEMP18
        v_xor_b32 TEMP32, TEMP36, TEMP35
        v_bfi_b32 TEMP31, TEMP32, TEMP28, TEMP19
        v_xor_b32 TEMP30, TEMP18, TEMP31
        v_xor_b32 TEMP08, TEMP15, TEMP30
        v_bfi_b32 TEMP15, TEMP19, TEMP08, TEMP30
        v_bfi_b32 TEMP01, TEMP28, TEMP35, TEMP08
        v_bfi_b32 TEMP00, TEMP19, TEMP32, TEMP36
        v_xor_b32 TEMP01, TEMP01, TEMP00
        v_bfi_b32 TEMP35, TEMP01, TEMP08, TEMP35
        v_bfi_b32 TEMP27, TEMP15, TEMP01, TEMP35
        v_xor_b32 TEMP27, TEMP28, TEMP27
        v_bfi_b32 TEMP12, TEMP27, TEMP28, TEMP18
        v_bfi_b32 TEMP28, TEMP08, TEMP32, TEMP28
        v_bfi_b32 TEMP14, TEMP27, TEMP28, TEMP19
        v_bfi_b32 TEMP35, TEMP35, TEMP30, TEMP32
        v_xor_b32 TEMP35, TEMP14, TEMP35
        v_bfi_b32 TEMP28, TEMP17, TEMP28, TEMP08
        v_bfi_b32 TEMP30, TEMP12, TEMP28, TEMP35
        v_not_b32 TEMP30, TEMP30
        v_bfi_b32 TEMP35, TEMP20, TEMP35, TEMP30
        v_xor_b32 DB40, TEMP35, DB40
        v_bfi_b32 TEMP14, TEMP14, TEMP17, TEMP30
        v_bfi_b32 TEMP10, TEMP32, TEMP16, TEMP28
        v_bfi_b32 TEMP14, TEMP10, TEMP18, TEMP14
        v_xor_b32 TEMP18, TEMP27, TEMP14
        v_bfi_b32 TEMP28, TEMP20, TEMP08, TEMP18
        v_xor_b32 DB48, TEMP28, DB48
        v_bfi_b32 TEMP28, TEMP14, TEMP00, TEMP15
        v_bfi_b32 TEMP10, TEMP31, TEMP08, TEMP10
        v_xor_b32 TEMP28, TEMP28, TEMP10
        v_bfi_b32 TEMP28, TEMP20, TEMP27, TEMP28
        v_xor_b32 DB62, TEMP28, DB62
        v_xor_b32 TEMP08, TEMP08, TEMP18
        v_bfi_b32 TEMP14, TEMP14, TEMP08, TEMP17
        v_bfi_b32 TEMP14, TEMP10, TEMP36, TEMP14
        v_bfi_b32 TEMP14, TEMP20, TEMP01, TEMP14
        v_xor_b32 DB54, TEMP14, DB54

        v_bfi_b32 TEMP14, TEMP26, TEMP23, TEMP21
        v_bfi_b32 TEMP08, TEMP25, TEMP14, TEMP26
        v_bfi_b32 TEMP05, TEMP08, TEMP24, TEMP23
        v_xor_b32 TEMP05, TEMP21, TEMP05
        v_bfi_b32 TEMP10, TEMP26, TEMP05, TEMP24
        v_not_b32 TEMP17, TEMP10
        v_xor_b32 TEMP14, TEMP14, TEMP17
        v_xor_b32 TEMP18, TEMP26, TEMP25
        v_xor_b32 TEMP28, TEMP14, TEMP18
        v_xor_b32 TEMP36, TEMP05, TEMP18
        v_bfi_b32 TEMP28, TEMP22, TEMP36, TEMP28
        v_xor_b32 DB59, TEMP28, DB59
        v_xor_b32 TEMP28, TEMP24, TEMP08
        v_bfi_b32 TEMP35, TEMP25, TEMP28, TEMP14
        v_xor_b32 TEMP32, TEMP23, TEMP28
        v_bfi_b32 TEMP35, TEMP21, TEMP32, TEMP35
        v_bfi_b32 TEMP33, TEMP25, TEMP35, TEMP24
        v_bfi_b32 TEMP32, TEMP14, TEMP36, TEMP05
        v_xor_b32 TEMP17, TEMP17, TEMP32
        v_xor_b32 TEMP17, TEMP33, TEMP17
        v_bfi_b32 TEMP31, TEMP22, TEMP35, TEMP17
        v_xor_b32 DB44, TEMP31, DB44
        v_bfi_b32 TEMP32, TEMP35, TEMP17, TEMP32
        v_bfi_b32 TEMP13, TEMP21, TEMP14, TEMP36
        v_bfi_b32 TEMP08, TEMP08, TEMP23, TEMP13
        v_bfi_b32 TEMP21, TEMP25, TEMP08, TEMP32
        v_bfi_b32 TEMP05, TEMP18, TEMP26, TEMP05
        v_bfi_b32 TEMP14, TEMP05, TEMP28, TEMP14
        v_bfi_b32 TEMP14, TEMP22, TEMP21, TEMP14
        v_xor_b32 DB49, TEMP14, DB49
        v_bfi_b32 TEMP16, TEMP26, TEMP33, TEMP13
        v_bfi_b32 TEMP14, TEMP18, TEMP17, TEMP35
        v_bfi_b32 TEMP14, TEMP05, TEMP13, TEMP14
        v_bfi_b32 TEMP16, TEMP16, TEMP14, TEMP10
        v_xor_b32 TEMP16, TEMP08, TEMP16
        v_bfi_b32 TEMP16, TEMP22, TEMP16, TEMP14
        v_xor_b32 DB33, TEMP16, DB33

		s_setpc_b64 s[40:41]



.S3_S4_A:
		s_getpc_b64 s[44:45]
		s_add_u32 s44,s44,12
		s_addc_u32 s45,s45,0
		s_branch .S5_S6_A

        v_bfi_b32 TEMP28, TEMP16, TEMP18, TEMP14
        v_xor_b32 TEMP28, TEMP25, TEMP28
        v_bfi_b32 TEMP36, TEMP20, TEMP28, TEMP16
        v_xor_b32 TEMP35, TEMP20, TEMP28
        v_bfi_b32 TEMP32, TEMP14, TEMP36, TEMP35
        v_bfi_b32 TEMP31, TEMP28, TEMP18, TEMP16
        v_bfi_b32 TEMP30, TEMP36, TEMP14, TEMP31
        v_bfi_b32 TEMP15, TEMP35, TEMP25, TEMP18
        v_xor_b32 TEMP15, TEMP30, TEMP15
        v_bfi_b32 TEMP18, TEMP18, TEMP15, TEMP32
        v_not_b32 TEMP01, TEMP18
        v_bfi_b32 TEMP00, TEMP26, TEMP01, TEMP15
        v_xor_b32 DB47, TEMP00, DB47
        v_xor_b32 TEMP01, TEMP31, TEMP01
        v_bfi_b32 TEMP32, TEMP35, TEMP32, TEMP01
        v_bfi_b32 TEMP30, TEMP30, TEMP28, TEMP20
        v_xor_b32 TEMP00, TEMP32, TEMP30
        v_bfi_b32 TEMP27, TEMP01, TEMP25, TEMP00
        v_bfi_b32 TEMP18, TEMP16, TEMP20, TEMP18
        v_bfi_b32 TEMP28, TEMP28, TEMP25, TEMP14
        v_bfi_b32 TEMP36, TEMP36, TEMP28, TEMP01
        v_bfi_b32 TEMP36, TEMP27, TEMP18, TEMP36
        v_xor_b32 TEMP01, TEMP00, TEMP18
        v_bfi_b32 TEMP01, TEMP26, TEMP01, TEMP36
        v_xor_b32 DB55, TEMP01, DB55
        v_bfi_b32 TEMP08, TEMP16, TEMP00, TEMP32
        v_bfi_b32 TEMP34, TEMP14, TEMP31, TEMP28
        v_bfi_b32 TEMP08, TEMP34, TEMP36, TEMP08
        v_bfi_b32 TEMP08, TEMP26, TEMP08, TEMP35
        v_xor_b32 DB37, TEMP08, DB37
        v_bfi_b32 TEMP08, TEMP30, TEMP20, TEMP32
        v_bfi_b32 TEMP08, TEMP25, TEMP34, TEMP08
        v_xor_b32 TEMP08, TEMP18, TEMP08
        v_xor_b32 TEMP05, TEMP31, TEMP15
        v_bfi_b32 TEMP05, TEMP18, TEMP30, TEMP05
        v_bfi_b32 TEMP14, TEMP26, TEMP05, TEMP08
        v_xor_b32 DB61, TEMP14, DB61

        v_bfi_b32 TEMP14, TEMP19, TEMP24, TEMP13
        v_xor_b32 TEMP08, TEMP23, TEMP14
        v_bfi_b32 TEMP05, TEMP24, TEMP13, TEMP08
        v_bfi_b32 TEMP34, TEMP14, TEMP08, TEMP05
        v_bfi_b32 TEMP10, TEMP19, TEMP13, TEMP24
        v_bfi_b32 TEMP17, TEMP23, TEMP19, TEMP10
        v_xor_b32 TEMP33, TEMP13, TEMP17
        v_bfi_b32 TEMP33, TEMP22, TEMP33, TEMP19
        v_xor_b32 TEMP05, TEMP05, TEMP33
        v_not_b32 TEMP33, TEMP05
        v_bfi_b32 TEMP34, TEMP22, TEMP34, TEMP33
        v_bfi_b32 TEMP17, TEMP17, TEMP22, TEMP23
        v_xor_b32 TEMP13, TEMP19, TEMP10
        v_bfi_b32 TEMP10, TEMP13, TEMP17, TEMP33
        v_xor_b32 TEMP14, TEMP14, TEMP10
        v_not_b32 TEMP10, TEMP14
        v_bfi_b32 TEMP18, TEMP23, TEMP10, TEMP13
        v_xor_b32 TEMP34, TEMP34, TEMP18
        v_bfi_b32 TEMP05, TEMP12, TEMP05, TEMP34
        v_xor_b32 DB41, TEMP05, DB41
        v_bfi_b32 TEMP05, TEMP12, TEMP34, TEMP33
        v_xor_b32 DB32, TEMP05, DB32
        v_bfi_b32 TEMP08, TEMP08, TEMP23, TEMP22
        v_bfi_b32 TEMP08, TEMP13, TEMP08, TEMP17
        v_xor_b32 TEMP13, TEMP10, TEMP34
        v_xor_b32 TEMP08, TEMP08, TEMP13
        v_bfi_b32 TEMP13, TEMP12, TEMP08, TEMP10
        v_xor_b32 DB57, TEMP13, DB57
        v_bfi_b32 TEMP16, TEMP12, TEMP14, TEMP08
        v_xor_b32 DB51, TEMP16, DB51
		s_setpc_b64 s[40:41]



.S5_S6_A:
		s_getpc_b64 s[46:47]
		s_add_u32 s46,s46,12
		s_addc_u32 s47,s47,0
		s_branch .S7_S8_A

        v_bfi_b32 TEMP28, TEMP22, TEMP18, TEMP16
        v_not_b32 TEMP36, TEMP28
        v_bfi_b32 TEMP35, TEMP18, TEMP16, TEMP36
        v_xor_b32 TEMP32, TEMP09, TEMP35
        v_xor_b32 TEMP31, TEMP22, TEMP23
        v_xor_b32 TEMP30, TEMP32, TEMP31
        v_bfi_b32 TEMP15, TEMP32, TEMP30, TEMP09
        v_bfi_b32 TEMP01, TEMP15, TEMP28, TEMP23
        v_bfi_b32 TEMP00, TEMP16, TEMP22, TEMP01
        v_bfi_b32 TEMP18, TEMP09, TEMP36, TEMP18
        v_xor_b32 TEMP27, TEMP00, TEMP18
        v_bfi_b32 TEMP12, TEMP32, TEMP27, TEMP31
        v_bfi_b32 TEMP26, TEMP12, TEMP16, TEMP23
        v_bfi_b32 TEMP15, TEMP26, TEMP23, TEMP15
        v_xor_b32 TEMP19, TEMP27, TEMP15
        v_bfi_b32 TEMP27, TEMP21, TEMP27, TEMP19
        v_xor_b32 DB56, TEMP27, DB56
        v_bfi_b32 TEMP36, TEMP12, TEMP01, TEMP36
        v_bfi_b32 TEMP05, TEMP16, TEMP28, TEMP15
        v_xor_b32 TEMP28, TEMP36, TEMP05
        v_bfi_b32 TEMP01, TEMP21, TEMP30, TEMP28
        v_xor_b32 DB45, TEMP01, DB45
        v_bfi_b32 TEMP01, TEMP23, TEMP05, TEMP28
        v_bfi_b32 TEMP00, TEMP09, TEMP00, TEMP01
        v_bfi_b32 TEMP17, TEMP30, TEMP09, TEMP18
        v_bfi_b32 TEMP27, TEMP28, TEMP17, TEMP00
        v_bfi_b32 TEMP16, TEMP30, TEMP28, TEMP22
        v_bfi_b32 TEMP05, TEMP16, TEMP31, TEMP05
        v_bfi_b32 TEMP17, TEMP17, TEMP00, TEMP15
        v_xor_b32 TEMP05, TEMP05, TEMP17
        v_bfi_b32 TEMP05, TEMP21, TEMP05, TEMP27
        v_xor_b32 DB34, TEMP05, DB34
        v_bfi_b32 TEMP05, TEMP36, TEMP19, TEMP32
        v_bfi_b32 TEMP16, TEMP00, TEMP05, TEMP16
        v_bfi_b32 TEMP08, TEMP23, TEMP35, TEMP18
        v_bfi_b32 TEMP05, TEMP26, TEMP30, TEMP32
        v_bfi_b32 TEMP08, TEMP01, TEMP05, TEMP08
        v_bfi_b32 TEMP16, TEMP21, TEMP16, TEMP08
        v_xor_b32 DB39, TEMP16, DB39

        v_bfi_b32 TEMP16, TEMP20, TEMP24, TEMP11
        v_xor_b32 TEMP08, TEMP14, TEMP16
        v_bfi_b32 TEMP05, TEMP10, TEMP24, TEMP08
        v_xor_b32 TEMP34, TEMP11, TEMP05
        v_xor_b32 TEMP17, TEMP20, TEMP34
        v_bfi_b32 TEMP18, TEMP24, TEMP17, TEMP34
        v_bfi_b32 TEMP28, TEMP18, TEMP34, TEMP24
        v_xor_b32 TEMP28, TEMP10, TEMP28
        v_bfi_b32 TEMP18, TEMP18, TEMP24, TEMP10
        v_xor_b32 TEMP08, TEMP08, TEMP18
        v_bfi_b32 TEMP21, TEMP17, TEMP10, TEMP24
        v_bfi_b32 TEMP33, TEMP08, TEMP21, TEMP28
        v_bfi_b32 TEMP36, TEMP33, TEMP28, TEMP20
        v_not_b32 TEMP35, TEMP17
        v_bfi_b32 TEMP32, TEMP08, TEMP21, TEMP35
        v_bfi_b32 TEMP36, TEMP36, TEMP17, TEMP32
        v_bfi_b32 TEMP35, TEMP25, TEMP36, TEMP35
        v_xor_b32 DB35, TEMP35, DB35
        v_bfi_b32 TEMP29, TEMP14, TEMP36, TEMP34
        v_bfi_b32 TEMP13, TEMP29, TEMP32, TEMP11
        v_xor_b32 TEMP08, TEMP17, TEMP08
        v_xor_b32 TEMP29, TEMP13, TEMP08
        v_bfi_b32 TEMP08, TEMP25, TEMP29, TEMP08
        v_xor_b32 DB50, TEMP08, DB50
        v_bfi_b32 TEMP08, TEMP17, TEMP05, TEMP28
        v_bfi_b32 TEMP21, TEMP18, TEMP21, TEMP08
        v_xor_b32 TEMP21, TEMP29, TEMP21
        v_xor_b32 TEMP16, TEMP16, TEMP21
        v_bfi_b32 TEMP10, TEMP32, TEMP36, TEMP20
        v_bfi_b32 TEMP34, TEMP10, TEMP21, TEMP16
        v_not_b32 TEMP34, TEMP34
        v_bfi_b32 TEMP16, TEMP25, TEMP16, TEMP34
        v_xor_b32 DB60, TEMP16, DB60
        v_bfi_b32 TEMP16, TEMP21, TEMP29, TEMP10
        v_bfi_b32 TEMP08, TEMP05, TEMP08, TEMP13
        v_xor_b32 TEMP16, TEMP16, TEMP08
        v_bfi_b32 TEMP16, TEMP25, TEMP16, TEMP33
        v_xor_b32 DB42, TEMP16, DB42
		s_setpc_b64 s[40:41]



.S7_S8_A:
        s_getpc_b64 s[48:49]
		s_add_u32 s48,s48,12
		s_addc_u32 s49,s49,0
		s_branch .S1_S2_B
		
		v_bfi_b32 TEMP28, TEMP18, TEMP26, TEMP21
        v_bfi_b32 TEMP36, TEMP24, TEMP18, TEMP23
        v_bfi_b32 TEMP28, TEMP26, TEMP36, TEMP28
        v_bfi_b32 TEMP35, TEMP21, TEMP23, TEMP18
        v_xor_b32 TEMP35, TEMP24, TEMP35
        v_xor_b32 TEMP32, TEMP28, TEMP35
        v_bfi_b32 TEMP28, TEMP24, TEMP28, TEMP21
        v_xor_b32 TEMP31, TEMP21, TEMP18
        v_bfi_b32 TEMP30, TEMP35, TEMP28, TEMP31
        v_xor_b32 TEMP15, TEMP23, TEMP26
        v_xor_b32 TEMP01, TEMP30, TEMP15
        v_bfi_b32 TEMP00, TEMP16, TEMP32, TEMP01
        v_xor_b32 DB63, TEMP00, DB63
        v_xor_b32 TEMP00, TEMP18, TEMP01
        v_bfi_b32 TEMP27, TEMP31, TEMP26, TEMP00
        v_bfi_b32 TEMP27, TEMP23, TEMP27, TEMP01
        v_not_b32 TEMP08, TEMP26
        v_bfi_b32 TEMP08, TEMP28, TEMP00, TEMP08
        v_bfi_b32 TEMP14, TEMP23, TEMP00, TEMP35
        v_bfi_b32 TEMP14, TEMP15, TEMP31, TEMP14
        v_xor_b32 TEMP14, TEMP36, TEMP14
        v_bfi_b32 TEMP18, TEMP18, TEMP14, TEMP35
        v_xor_b32 TEMP28, TEMP08, TEMP18
        v_bfi_b32 TEMP36, TEMP16, TEMP27, TEMP28
        v_xor_b32 DB43, TEMP36, DB43
        v_xor_b32 TEMP28, TEMP31, TEMP28
        v_bfi_b32 TEMP18, TEMP18, TEMP28, TEMP27
        v_bfi_b32 TEMP08, TEMP08, TEMP32, TEMP18
        v_bfi_b32 TEMP14, TEMP16, TEMP14, TEMP08
        v_xor_b32 DB53, TEMP14, DB53
        v_bfi_b32 TEMP14, TEMP30, TEMP01, TEMP00
        v_xor_b32 TEMP08, TEMP00, TEMP28
        v_bfi_b32 TEMP14, TEMP24, TEMP08, TEMP14
        v_bfi_b32 TEMP08, TEMP01, TEMP32, TEMP27
        v_bfi_b32 TEMP08, TEMP08, TEMP21, TEMP14
        v_not_b32 TEMP08, TEMP08
        v_bfi_b32 TEMP14, TEMP16, TEMP08, TEMP14
        v_xor_b32 DB38, TEMP14, DB38

        v_bfi_b32 TEMP14, TEMP11, TEMP22, TEMP25
        v_bfi_b32 TEMP08, TEMP19, TEMP11, TEMP12
        v_bfi_b32 TEMP10, TEMP25, TEMP19, TEMP11
        v_xor_b32 TEMP10, TEMP22, TEMP10
        v_bfi_b32 TEMP14, TEMP08, TEMP14, TEMP10
        v_xor_b32 TEMP08, TEMP12, TEMP14
        v_bfi_b32 TEMP34, TEMP10, TEMP11, TEMP08
        v_bfi_b32 TEMP10, TEMP25, TEMP22, TEMP10
        v_bfi_b32 TEMP21, TEMP10, TEMP19, TEMP34
        v_bfi_b32 TEMP10, TEMP12, TEMP10, TEMP11
        v_bfi_b32 TEMP34, TEMP10, TEMP08, TEMP19
        v_bfi_b32 TEMP33, TEMP12, TEMP11, TEMP25
        v_xor_b32 TEMP17, TEMP34, TEMP33
        v_xor_b32 TEMP18, TEMP21, TEMP17
        v_bfi_b32 TEMP28, TEMP20, TEMP17, TEMP18
        v_xor_b32 DB46, TEMP28, DB46
        v_bfi_b32 TEMP13, TEMP11, TEMP18, TEMP33
        v_bfi_b32 TEMP18, TEMP13, TEMP12, TEMP14
        v_xor_b32 TEMP13, TEMP10, TEMP13
        v_xor_b32 TEMP10, TEMP08, TEMP13
        v_not_b32 TEMP28, TEMP10
        v_bfi_b32 TEMP36, TEMP21, TEMP18, TEMP28
        v_xor_b32 TEMP13, TEMP13, TEMP36
        v_bfi_b32 TEMP08, TEMP20, TEMP08, TEMP13
        v_xor_b32 DB58, TEMP08, DB58
        v_bfi_b32 TEMP08, TEMP18, TEMP33, TEMP34
        v_bfi_b32 TEMP08, TEMP17, TEMP08, TEMP14
        v_xor_b32 TEMP08, TEMP28, TEMP08
        v_bfi_b32 TEMP08, TEMP20, TEMP08, TEMP28
        v_xor_b32 DB52, TEMP08, DB52
        v_or_b32 TEMP08, TEMP19, TEMP21
        v_xor_b32 TEMP08, TEMP36, TEMP08
        v_bfi_b32 TEMP16, TEMP17, TEMP12, TEMP14
        v_xor_b32 TEMP16, TEMP08, TEMP16
        v_bfi_b32 TEMP16, TEMP20, TEMP10, TEMP16
        v_xor_b32 DB36, TEMP16, DB36
		s_setpc_b64 s[40:41]
		


.S1_S2_B:
        s_getpc_b64 s[50:51]
		s_add_u32 s50,s50,12
		s_addc_u32 s51,s51,0
		s_branch .S3_S4_B
		
        v_bfi_b32 TEMP28, TEMP26, TEMP18, TEMP05
        v_xor_b32 TEMP36, TEMP05, TEMP18
        v_or_b32 TEMP35, TEMP08, TEMP16
        v_xor_b32 TEMP32, TEMP36, TEMP35
        v_bfi_b32 TEMP31, TEMP32, TEMP28, TEMP26
        v_xor_b32 TEMP30, TEMP16, TEMP31
        v_xor_b32 TEMP13, TEMP08, TEMP30
        v_bfi_b32 TEMP15, TEMP26, TEMP13, TEMP30
        v_bfi_b32 TEMP01, TEMP28, TEMP35, TEMP13
        v_bfi_b32 TEMP00, TEMP26, TEMP32, TEMP36
        v_xor_b32 TEMP01, TEMP01, TEMP00
        v_bfi_b32 TEMP35, TEMP01, TEMP13, TEMP35
        v_bfi_b32 TEMP27, TEMP15, TEMP01, TEMP35
        v_xor_b32 TEMP27, TEMP28, TEMP27
        v_bfi_b32 TEMP12, TEMP27, TEMP28, TEMP16
        v_bfi_b32 TEMP28, TEMP13, TEMP32, TEMP28
        v_bfi_b32 TEMP08, TEMP27, TEMP28, TEMP26
        v_bfi_b32 TEMP35, TEMP35, TEMP30, TEMP32
        v_xor_b32 TEMP35, TEMP08, TEMP35
        v_bfi_b32 TEMP28, TEMP05, TEMP28, TEMP13
        v_bfi_b32 TEMP30, TEMP12, TEMP28, TEMP35
        v_not_b32 TEMP30, TEMP30
        v_bfi_b32 TEMP08, TEMP08, TEMP05, TEMP30
        v_bfi_b32 TEMP18, TEMP32, TEMP18, TEMP28
        v_bfi_b32 TEMP08, TEMP18, TEMP16, TEMP08
        v_xor_b32 TEMP34, TEMP27, TEMP08
        v_xor_b32 TEMP28, TEMP13, TEMP34
        v_bfi_b32 TEMP17, TEMP08, TEMP28, TEMP05
        v_bfi_b32 TEMP18, TEMP31, TEMP13, TEMP18
        v_bfi_b32 TEMP17, TEMP18, TEMP36, TEMP17
        v_bfi_b32 TEMP17, TEMP19, TEMP01, TEMP17
        v_xor_b32 DB22, DB22, TEMP17
        v_bfi_b32 TEMP17, TEMP19, TEMP35, TEMP30
        v_xor_b32 DB08, DB08, TEMP17
        v_bfi_b32 TEMP13, TEMP19, TEMP13, TEMP34
        v_xor_b32 DB16, DB16, TEMP13
        v_bfi_b32 TEMP08, TEMP08, TEMP00, TEMP15
        v_xor_b32 TEMP08, TEMP18, TEMP08
        v_bfi_b32 TEMP08, TEMP19, TEMP27, TEMP08
        v_xor_b32 DB30, DB30, TEMP08

        v_bfi_b32 TEMP08, TEMP03, TEMP02, TEMP14
        v_bfi_b32 TEMP13, TEMP04, TEMP08, TEMP03
        v_bfi_b32 TEMP29, TEMP13, TEMP07, TEMP02
        v_xor_b32 TEMP29, TEMP14, TEMP29
        v_bfi_b32 TEMP34, TEMP03, TEMP29, TEMP07
        v_not_b32 TEMP17, TEMP34
        v_xor_b32 TEMP08, TEMP08, TEMP17
        v_xor_b32 TEMP18, TEMP03, TEMP04
        v_xor_b32 TEMP28, TEMP29, TEMP18
        v_bfi_b32 TEMP36, TEMP14, TEMP08, TEMP28
        v_xor_b32 TEMP35, TEMP07, TEMP13
        v_bfi_b32 TEMP32, TEMP04, TEMP35, TEMP08
        v_xor_b32 TEMP31, TEMP02, TEMP35
        v_bfi_b32 TEMP14, TEMP14, TEMP31, TEMP32
        v_bfi_b32 TEMP21, TEMP04, TEMP14, TEMP07
        v_bfi_b32 TEMP32, TEMP03, TEMP21, TEMP36
        v_bfi_b32 TEMP31, TEMP08, TEMP28, TEMP29
        v_xor_b32 TEMP17, TEMP17, TEMP31
        v_xor_b32 TEMP21, TEMP21, TEMP17
        v_bfi_b32 TEMP17, TEMP18, TEMP21, TEMP14
        v_bfi_b32 TEMP29, TEMP18, TEMP03, TEMP29
        v_bfi_b32 TEMP05, TEMP29, TEMP36, TEMP17
        v_bfi_b32 TEMP34, TEMP32, TEMP05, TEMP34
        v_bfi_b32 TEMP13, TEMP13, TEMP02, TEMP36
        v_xor_b32 TEMP33, TEMP34, TEMP13
        v_bfi_b32 TEMP05, TEMP06, TEMP33, TEMP05
        v_xor_b32 DB01, DB01, TEMP05
        v_bfi_b32 TEMP05, TEMP06, TEMP14, TEMP21
        v_xor_b32 DB12, DB12, TEMP05
        v_bfi_b32 TEMP14, TEMP14, TEMP21, TEMP31
        v_bfi_b32 TEMP14, TEMP04, TEMP13, TEMP14
        v_bfi_b32 TEMP13, TEMP29, TEMP35, TEMP08
        v_bfi_b32 TEMP14, TEMP06, TEMP14, TEMP13
        v_xor_b32 DB17, DB17, TEMP14
        v_xor_b32 TEMP14, TEMP08, TEMP18
        v_bfi_b32 TEMP16, TEMP06, TEMP28, TEMP14
        v_xor_b32 DB27, DB27, TEMP16
		s_setpc_b64 s[40:41]



.S3_S4_B:
        s_getpc_b64 s[52:53]
		s_add_u32 s52,s52,12
		s_addc_u32 s53,s53,0
		s_branch .S5_S6_B

        v_bfi_b32 TEMP28, TEMP02, TEMP10, TEMP16
        v_xor_b32 TEMP28, TEMP04, TEMP28
        v_bfi_b32 TEMP36, TEMP18, TEMP28, TEMP02
        v_xor_b32 TEMP35, TEMP18, TEMP28
        v_bfi_b32 TEMP32, TEMP16, TEMP36, TEMP35
        v_bfi_b32 TEMP31, TEMP28, TEMP10, TEMP02
        v_bfi_b32 TEMP30, TEMP36, TEMP16, TEMP31
        v_bfi_b32 TEMP15, TEMP35, TEMP04, TEMP10
        v_xor_b32 TEMP15, TEMP30, TEMP15
        v_bfi_b32 TEMP17, TEMP10, TEMP15, TEMP32
        v_not_b32 TEMP01, TEMP17
        v_xor_b32 TEMP00, TEMP31, TEMP01
        v_bfi_b32 TEMP32, TEMP35, TEMP32, TEMP00
        v_bfi_b32 TEMP30, TEMP30, TEMP28, TEMP18
        v_xor_b32 TEMP27, TEMP32, TEMP30
        v_bfi_b32 TEMP12, TEMP00, TEMP04, TEMP27
        v_bfi_b32 TEMP17, TEMP02, TEMP18, TEMP17
        v_bfi_b32 TEMP28, TEMP28, TEMP04, TEMP16
        v_bfi_b32 TEMP36, TEMP36, TEMP28, TEMP00
        v_bfi_b32 TEMP36, TEMP12, TEMP17, TEMP36
        v_xor_b32 TEMP00, TEMP27, TEMP17
        v_bfi_b32 TEMP00, TEMP25, TEMP00, TEMP36
        v_xor_b32 DB23, DB23, TEMP00
        v_bfi_b32 TEMP05, TEMP02, TEMP27, TEMP32
        v_bfi_b32 TEMP34, TEMP16, TEMP31, TEMP28
        v_bfi_b32 TEMP05, TEMP34, TEMP36, TEMP05
        v_bfi_b32 TEMP05, TEMP25, TEMP05, TEMP35
        v_xor_b32 DB05, DB05, TEMP05
        v_bfi_b32 TEMP05, TEMP30, TEMP18, TEMP32
        v_bfi_b32 TEMP13, TEMP04, TEMP34, TEMP05
        v_xor_b32 TEMP13, TEMP17, TEMP13
        v_xor_b32 TEMP05, TEMP31, TEMP15
        v_bfi_b32 TEMP05, TEMP17, TEMP30, TEMP05
        v_bfi_b32 TEMP13, TEMP25, TEMP05, TEMP13
        v_xor_b32 DB29, DB29, TEMP13

        v_bfi_b32 TEMP13, TEMP03, TEMP19, TEMP22
        v_bfi_b32 TEMP05, TEMP26, TEMP03, TEMP13
        v_bfi_b32 TEMP34, TEMP05, TEMP06, TEMP26
        v_bfi_b32 TEMP17, TEMP03, TEMP22, TEMP19
        v_xor_b32 TEMP18, TEMP26, TEMP17
        v_bfi_b32 TEMP28, TEMP18, TEMP26, TEMP06
        v_xor_b32 TEMP13, TEMP03, TEMP13
        v_bfi_b32 TEMP28, TEMP13, TEMP28, TEMP34
        v_bfi_b32 TEMP10, TEMP22, TEMP19, TEMP18
        v_bfi_b32 TEMP18, TEMP17, TEMP18, TEMP10
        v_xor_b32 TEMP05, TEMP19, TEMP05
        v_bfi_b32 TEMP08, TEMP06, TEMP05, TEMP03
        v_xor_b32 TEMP08, TEMP10, TEMP08
        v_not_b32 TEMP05, TEMP08
        v_bfi_b32 TEMP16, TEMP06, TEMP18, TEMP05
        v_bfi_b32 TEMP10, TEMP13, TEMP34, TEMP05
        v_xor_b32 TEMP10, TEMP17, TEMP10
        v_not_b32 TEMP33, TEMP10
        v_bfi_b32 TEMP13, TEMP26, TEMP33, TEMP13
        v_xor_b32 TEMP16, TEMP16, TEMP13
        v_xor_b32 TEMP13, TEMP33, TEMP16
        v_xor_b32 TEMP13, TEMP28, TEMP13
        v_bfi_b32 TEMP10, TEMP07, TEMP10, TEMP13
        v_xor_b32 DB19, DB19, TEMP10
        v_bfi_b32 TEMP13, TEMP07, TEMP13, TEMP33
        v_xor_b32 DB25, DB25, TEMP13
        v_bfi_b32 TEMP14, TEMP25, TEMP01, TEMP15
        v_xor_b32 DB15, DB15, TEMP14
        v_bfi_b32 TEMP14, TEMP07, TEMP16, TEMP05
        v_xor_b32 DB00, DB00, TEMP14
        v_bfi_b32 TEMP16, TEMP07, TEMP08, TEMP16
        v_xor_b32 DB09, DB09, TEMP16
		s_setpc_b64 s[40:41]



.S5_S6_B:
        s_getpc_b64 s[54:55]
		s_add_u32 s54,s54,12
		s_addc_u32 s55,s55,0
		s_branch .S7_S8_B

        v_bfi_b32 TEMP28, TEMP04, TEMP21, TEMP03
        v_not_b32 TEMP36, TEMP28
        v_bfi_b32 TEMP35, TEMP21, TEMP03, TEMP36
        v_xor_b32 TEMP32, TEMP18, TEMP35
        v_xor_b32 TEMP31, TEMP04, TEMP07
        v_xor_b32 TEMP30, TEMP32, TEMP31
        v_bfi_b32 TEMP15, TEMP32, TEMP30, TEMP18
        v_bfi_b32 TEMP01, TEMP15, TEMP28, TEMP07
        v_bfi_b32 TEMP00, TEMP03, TEMP04, TEMP01
        v_bfi_b32 TEMP17, TEMP18, TEMP36, TEMP21
        v_xor_b32 TEMP27, TEMP00, TEMP17
        v_bfi_b32 TEMP12, TEMP32, TEMP27, TEMP31
        v_bfi_b32 TEMP36, TEMP12, TEMP01, TEMP36
        v_bfi_b32 TEMP01, TEMP12, TEMP03, TEMP07
        v_bfi_b32 TEMP15, TEMP01, TEMP07, TEMP15
        v_xor_b32 TEMP12, TEMP27, TEMP15
        v_bfi_b32 TEMP26, TEMP36, TEMP12, TEMP32
        v_bfi_b32 TEMP08, TEMP03, TEMP28, TEMP15
        v_xor_b32 TEMP28, TEMP36, TEMP08
        v_bfi_b32 TEMP29, TEMP30, TEMP28, TEMP04
        v_bfi_b32 TEMP36, TEMP07, TEMP08, TEMP28
        v_bfi_b32 TEMP00, TEMP18, TEMP00, TEMP36
        v_bfi_b32 TEMP26, TEMP00, TEMP26, TEMP29
        v_bfi_b32 TEMP05, TEMP07, TEMP35, TEMP17
        v_bfi_b32 TEMP35, TEMP01, TEMP30, TEMP32
        v_bfi_b32 TEMP05, TEMP36, TEMP35, TEMP05
        v_bfi_b32 TEMP05, TEMP22, TEMP26, TEMP05
        v_xor_b32 DB07, DB07, TEMP05
        v_bfi_b32 TEMP05, TEMP30, TEMP18, TEMP17
        v_bfi_b32 TEMP17, TEMP28, TEMP05, TEMP00
        v_bfi_b32 TEMP08, TEMP29, TEMP31, TEMP08
        v_bfi_b32 TEMP29, TEMP05, TEMP00, TEMP15
        v_xor_b32 TEMP08, TEMP08, TEMP29
        v_bfi_b32 TEMP08, TEMP22, TEMP08, TEMP17
        v_xor_b32 DB02, DB02, TEMP08

        v_bfi_b32 TEMP08, TEMP02, TEMP19, TEMP23
        v_xor_b32 TEMP29, TEMP06, TEMP08
        v_bfi_b32 TEMP05, TEMP10, TEMP19, TEMP29
        v_xor_b32 TEMP17, TEMP23, TEMP05
        v_xor_b32 TEMP18, TEMP02, TEMP17
        v_bfi_b32 TEMP36, TEMP19, TEMP18, TEMP17
        v_bfi_b32 TEMP35, TEMP36, TEMP19, TEMP10
        v_bfi_b32 TEMP36, TEMP36, TEMP17, TEMP19
        v_xor_b32 TEMP36, TEMP10, TEMP36
        v_bfi_b32 TEMP32, TEMP18, TEMP05, TEMP36
        v_bfi_b32 TEMP21, TEMP18, TEMP10, TEMP19
        v_bfi_b32 TEMP33, TEMP35, TEMP21, TEMP32
        v_xor_b32 TEMP29, TEMP29, TEMP35
        v_bfi_b32 TEMP35, TEMP29, TEMP21, TEMP36
        v_bfi_b32 TEMP36, TEMP35, TEMP36, TEMP02
        v_not_b32 TEMP31, TEMP18
        v_bfi_b32 TEMP21, TEMP29, TEMP21, TEMP31
        v_bfi_b32 TEMP36, TEMP36, TEMP18, TEMP21
        v_bfi_b32 TEMP16, TEMP06, TEMP36, TEMP17
        v_bfi_b32 TEMP16, TEMP16, TEMP21, TEMP23
        v_xor_b32 TEMP14, TEMP18, TEMP29
        v_xor_b32 TEMP29, TEMP16, TEMP14
        v_xor_b32 TEMP33, TEMP33, TEMP29
        v_xor_b32 TEMP08, TEMP08, TEMP33
        v_bfi_b32 TEMP10, TEMP21, TEMP36, TEMP02
        v_bfi_b32 TEMP21, TEMP10, TEMP33, TEMP08
        v_not_b32 TEMP21, TEMP21
        v_bfi_b32 TEMP08, TEMP25, TEMP08, TEMP21
        v_xor_b32 DB28, DB28, TEMP08
        v_bfi_b32 TEMP08, TEMP22, TEMP30, TEMP28
        v_xor_b32 DB13, DB13, TEMP08
        v_bfi_b32 TEMP08, TEMP33, TEMP29, TEMP10
        v_bfi_b32 TEMP16, TEMP05, TEMP32, TEMP16
        v_xor_b32 TEMP16, TEMP08, TEMP16
        v_bfi_b32 TEMP16, TEMP25, TEMP16, TEMP35
        v_xor_b32 DB10, DB10, TEMP16
        v_bfi_b32 TEMP16, TEMP25, TEMP36, TEMP31
        v_xor_b32 DB03, DB03, TEMP16
        v_bfi_b32 TEMP16, TEMP22, TEMP27, TEMP12
        v_xor_b32 DB24, DB24, TEMP16
        v_bfi_b32 TEMP16, TEMP25, TEMP29, TEMP14
        v_xor_b32 DB18, DB18, TEMP16
		s_setpc_b64 s[40:41]



.S7_S8_B:
        s_getpc_b64 s[56:57]
		s_add_u32 s56,s56,12
		s_addc_u32 s57,s57,0
		s_branch .startLoop

        v_bfi_b32 TEMP28, TEMP02, TEMP13, TEMP14
        v_bfi_b32 TEMP36, TEMP03, TEMP02, TEMP01
        v_bfi_b32 TEMP35, TEMP14, TEMP03, TEMP02
        v_xor_b32 TEMP35, TEMP13, TEMP35
        v_bfi_b32 TEMP28, TEMP36, TEMP28, TEMP35
        v_xor_b32 TEMP36, TEMP01, TEMP28
        v_bfi_b32 TEMP32, TEMP35, TEMP02, TEMP36
        v_bfi_b32 TEMP21, TEMP14, TEMP13, TEMP35
        v_bfi_b32 TEMP35, TEMP21, TEMP03, TEMP32
        v_bfi_b32 TEMP21, TEMP01, TEMP21, TEMP02
        v_bfi_b32 TEMP32, TEMP21, TEMP36, TEMP03
        v_bfi_b32 TEMP33, TEMP01, TEMP02, TEMP14
        v_xor_b32 TEMP31, TEMP32, TEMP33
        v_xor_b32 TEMP30, TEMP35, TEMP31
        v_bfi_b32 TEMP10, TEMP02, TEMP30, TEMP33
        v_bfi_b32 TEMP15, TEMP10, TEMP01, TEMP28
        v_bfi_b32 TEMP33, TEMP15, TEMP33, TEMP32
        v_bfi_b32 TEMP33, TEMP31, TEMP33, TEMP28
        v_xor_b32 TEMP10, TEMP21, TEMP10
        v_xor_b32 TEMP21, TEMP36, TEMP10
        v_not_b32 TEMP32, TEMP21
        v_xor_b32 TEMP33, TEMP33, TEMP32
        v_bfi_b32 TEMP33, TEMP04, TEMP33, TEMP32
        v_xor_b32 DB20, DB20, TEMP33
        v_bfi_b32 TEMP33, TEMP35, TEMP15, TEMP32
        v_xor_b32 TEMP10, TEMP10, TEMP33
        v_bfi_b32 TEMP10, TEMP04, TEMP36, TEMP10
        v_xor_b32 DB26, DB26, TEMP10
        v_or_b32 TEMP13, TEMP03, TEMP35
        v_xor_b32 TEMP13, TEMP33, TEMP13
        v_bfi_b32 TEMP14, TEMP31, TEMP01, TEMP28
        v_xor_b32 TEMP14, TEMP13, TEMP14
        v_bfi_b32 TEMP14, TEMP04, TEMP21, TEMP14
        v_xor_b32 DB04, DB04, TEMP14
        v_bfi_b32 TEMP14, TEMP18, TEMP12, TEMP27
        v_bfi_b32 TEMP13, TEMP00, TEMP18, TEMP07
        v_bfi_b32 TEMP14, TEMP12, TEMP13, TEMP14
        v_bfi_b32 TEMP10, TEMP00, TEMP14, TEMP27
        v_bfi_b32 TEMP21, TEMP27, TEMP07, TEMP18
        v_xor_b32 TEMP21, TEMP00, TEMP21

        v_xor_b32 TEMP33, TEMP27, TEMP18
        v_bfi_b32 TEMP28, TEMP21, TEMP10, TEMP33
        v_xor_b32 TEMP36, TEMP12, TEMP07
        v_xor_b32 TEMP35, TEMP28, TEMP36
        v_xor_b32 TEMP32, TEMP18, TEMP35
        v_bfi_b32 TEMP28, TEMP28, TEMP35, TEMP32
        v_not_b32 TEMP15, TEMP12
        v_bfi_b32 TEMP10, TEMP10, TEMP32, TEMP15
        v_bfi_b32 TEMP15, TEMP07, TEMP32, TEMP21
        v_bfi_b32 TEMP36, TEMP36, TEMP33, TEMP15
        v_xor_b32 TEMP13, TEMP13, TEMP36
        v_bfi_b32 TEMP18, TEMP18, TEMP13, TEMP21
        v_xor_b32 TEMP36, TEMP10, TEMP18
        v_xor_b32 TEMP15, TEMP33, TEMP36
        v_xor_b32 TEMP01, TEMP32, TEMP15
        v_bfi_b32 TEMP34, TEMP00, TEMP01, TEMP28
        v_bfi_b32 TEMP08, TEMP33, TEMP12, TEMP32
        v_bfi_b32 TEMP08, TEMP07, TEMP08, TEMP35
        v_xor_b32 TEMP14, TEMP14, TEMP21
        v_bfi_b32 TEMP05, TEMP35, TEMP14, TEMP08
        v_bfi_b32 TEMP05, TEMP05, TEMP27, TEMP34
        v_not_b32 TEMP05, TEMP05
        v_bfi_b32 TEMP05, TEMP06, TEMP05, TEMP34
        v_xor_b32 DB06, DB06, TEMP05
        v_bfi_b32 TEMP29, TEMP04, TEMP31, TEMP30
        v_xor_b32 DB14, DB14, TEMP29
        v_bfi_b32 TEMP29, TEMP06, TEMP08, TEMP36
        v_xor_b32 DB11, DB11, TEMP29
        v_bfi_b32 TEMP08, TEMP18, TEMP15, TEMP08
        v_bfi_b32 TEMP08, TEMP10, TEMP14, TEMP08
        v_bfi_b32 TEMP08, TEMP06, TEMP13, TEMP08
        v_xor_b32 DB21, DB21, TEMP08
        v_bfi_b32 TEMP16, TEMP06, TEMP14, TEMP35
        v_xor_b32 DB31, DB31, TEMP16
		s_setpc_b64 s[40:41]



.startLoop:

		/*******/
		/* A 0 */
		/*******/

        v_xor_b32 TEMP15, K12, DB_EF00
        v_xor_b32 TEMP16, K46, DB_EF01
        v_xor_b32 TEMP17, K33, DB_EF02
        v_xor_b32 TEMP18, K52, DB_EF03
        v_xor_b32 TEMP19, K48, DB_EF04
        v_xor_b32 TEMP20, K20, DB_EF05
        v_xor_b32 TEMP21, K34, DB_EF06
        v_xor_b32 TEMP22, K55, DB_EF07
        v_xor_b32 TEMP23, K05, DB_EF08
        v_xor_b32 TEMP24, K13, DB_EF09
        v_xor_b32 TEMP25, K18, DB_EF10
        v_xor_b32 TEMP26, K40, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K04, DB07
        v_xor_b32 TEMP20, K32, DB08
        v_xor_b32 TEMP18, K26, DB09
        v_xor_b32 TEMP14, K27, DB10
        v_xor_b32 TEMP16, K38, DB11
        v_xor_b32 TEMP25, K54, DB12
        v_xor_b32 TEMP19, K53, DB11
        v_xor_b32 TEMP22, K06, DB12
        v_xor_b32 TEMP13, K31, DB13
        v_xor_b32 TEMP23, K25, DB14
        v_xor_b32 TEMP24, K19, DB15
        v_xor_b32 TEMP12, K41, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K15, DB_EF24
        v_xor_b32 TEMP09, K24, DB_EF25
        v_xor_b32 TEMP18, K28, DB_EF26
        v_xor_b32 TEMP21, K43, DB_EF27
        v_xor_b32 TEMP22, K30, DB_EF28
        v_xor_b32 TEMP23, K03, DB_EF29
        v_xor_b32 TEMP11, K35, DB_EF30
        v_xor_b32 TEMP14, K22, DB_EF31
        v_xor_b32 TEMP10, K02, DB_EF32
        v_xor_b32 TEMP24, K44, DB_EF33
        v_xor_b32 TEMP20, K14, DB_EF34
        v_xor_b32 TEMP25, K23, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K51, DB23
        v_xor_b32 TEMP18, K16, DB24
        v_xor_b32 TEMP21, K29, DB25
        v_xor_b32 TEMP24, K49, DB26
        v_xor_b32 TEMP26, K07, DB27
        v_xor_b32 TEMP23, K17, DB28
        v_xor_b32 TEMP19, K37, DB27
        v_xor_b32 TEMP12, K08, DB28
        v_xor_b32 TEMP25, K09, DB29
        v_xor_b32 TEMP22, K50, DB30
        v_xor_b32 TEMP11, K42, DB31
        v_xor_b32 TEMP20, K21, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 1 */
		/*******/

        v_xor_b32 TEMP08, K05, DB_EF48
        v_xor_b32 TEMP18, K39, DB_EF49
        v_xor_b32 TEMP05, K26, DB_EF50
        v_xor_b32 TEMP16, K45, DB_EF51
        v_xor_b32 TEMP26, K41, DB_EF52
        v_xor_b32 TEMP19, K13, DB_EF53
        v_xor_b32 TEMP14, K27, DB_EF54
        v_xor_b32 TEMP06, K48, DB_EF55
        v_xor_b32 TEMP02, K53, DB_EF56
        v_xor_b32 TEMP07, K06, DB_EF57
        v_xor_b32 TEMP04, K11, DB_EF58
        v_xor_b32 TEMP03, K33, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K52, DB39
        v_xor_b32 TEMP18, K25, DB40
        v_xor_b32 TEMP10, K19, DB41	
        v_xor_b32 TEMP16, K20, DB42
        v_xor_b32 TEMP02, K31, DB43
        v_xor_b32 TEMP04, K47, DB44
        v_xor_b32 TEMP03, K46, DB43
        v_xor_b32 TEMP06, K54, DB44
        v_xor_b32 TEMP19, K55, DB45
        v_xor_b32 TEMP26, K18, DB46
        v_xor_b32 TEMP22, K12, DB47
        v_xor_b32 TEMP07, K34, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K08, DB_EF72
        v_xor_b32 TEMP18, K17, DB_EF73
        v_xor_b32 TEMP21, K21, DB_EF74
        v_xor_b32 TEMP22, K36, DB_EF75
        v_xor_b32 TEMP04, K23, DB_EF76
        v_xor_b32 TEMP07, K49, DB_EF77
        v_xor_b32 TEMP23, K28, DB_EF78
        v_xor_b32 TEMP06, K15, DB_EF79
        v_xor_b32 TEMP10, K24, DB_EF80
        v_xor_b32 TEMP19, K37, DB_EF81
		v_xor_b32 TEMP02, K07, DB_EF82
        v_xor_b32 TEMP25, K16, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K44, DB55
        v_xor_b32 TEMP18, K09, DB56
        v_xor_b32 TEMP27, K22, DB57
        v_xor_b32 TEMP00, K42, DB58
        v_xor_b32 TEMP12, K00, DB59
        v_xor_b32 TEMP07, K10, DB60
        v_xor_b32 TEMP03, K30, DB59
        v_xor_b32 TEMP01, K01, DB60
        v_xor_b32 TEMP14, K02, DB61
        v_xor_b32 TEMP13, K43, DB62
        v_xor_b32 TEMP02, K35, DB63
        v_xor_b32 TEMP04, K14, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 2 */
		/*******/

        v_xor_b32 TEMP15, K46, DB_EF00
        v_xor_b32 TEMP16, K25, DB_EF01
        v_xor_b32 TEMP17, K12, DB_EF02
        v_xor_b32 TEMP18, K31, DB_EF03
        v_xor_b32 TEMP19, K27, DB_EF04
        v_xor_b32 TEMP20, K54, DB_EF05
        v_xor_b32 TEMP21, K13, DB_EF06
        v_xor_b32 TEMP22, K34, DB_EF07
        v_xor_b32 TEMP23, K39, DB_EF08
        v_xor_b32 TEMP24, K47, DB_EF09
        v_xor_b32 TEMP25, K52, DB_EF10
        v_xor_b32 TEMP26, K19, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K38, DB07
        v_xor_b32 TEMP20, K11, DB08
        v_xor_b32 TEMP18, K05, DB09
        v_xor_b32 TEMP14, K06, DB10
        v_xor_b32 TEMP16, K48, DB11
        v_xor_b32 TEMP25, K33, DB12
        v_xor_b32 TEMP19, K32, DB11
        v_xor_b32 TEMP22, K40, DB12
        v_xor_b32 TEMP13, K41, DB13
        v_xor_b32 TEMP23, K04, DB14
        v_xor_b32 TEMP24, K53, DB15
        v_xor_b32 TEMP12, K20, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K51, DB_EF24
        v_xor_b32 TEMP09, K03, DB_EF25
        v_xor_b32 TEMP18, K07, DB_EF26
        v_xor_b32 TEMP21, K22, DB_EF27
        v_xor_b32 TEMP22, K09, DB_EF28
        v_xor_b32 TEMP23, K35, DB_EF29
        v_xor_b32 TEMP11, K14, DB_EF30
        v_xor_b32 TEMP14, K01, DB_EF31
        v_xor_b32 TEMP10, K10, DB_EF32
        v_xor_b32 TEMP24, K23, DB_EF33
        v_xor_b32 TEMP20, K50, DB_EF34
        v_xor_b32 TEMP25, K02, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K30, DB23
        v_xor_b32 TEMP18, K24, DB24
        v_xor_b32 TEMP21, K08, DB25
        v_xor_b32 TEMP24, K28, DB26
        v_xor_b32 TEMP26, K43, DB27
        v_xor_b32 TEMP23, K49, DB28
        v_xor_b32 TEMP19, K16, DB27
        v_xor_b32 TEMP12, K44, DB28
        v_xor_b32 TEMP25, K17, DB29
        v_xor_b32 TEMP22, K29, DB30
        v_xor_b32 TEMP11, K21, DB31
        v_xor_b32 TEMP20, K00, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 3 */
		/*******/

        v_xor_b32 TEMP08, K32, DB_EF48
        v_xor_b32 TEMP18, K11, DB_EF49
        v_xor_b32 TEMP05, K53, DB_EF50
        v_xor_b32 TEMP16, K48, DB_EF51
        v_xor_b32 TEMP26, K13, DB_EF52
        v_xor_b32 TEMP19, K40, DB_EF53
        v_xor_b32 TEMP14, K54, DB_EF54
        v_xor_b32 TEMP06, K20, DB_EF55
        v_xor_b32 TEMP02, K25, DB_EF56
        v_xor_b32 TEMP07, K33, DB_EF57
        v_xor_b32 TEMP04, K38, DB_EF58
        v_xor_b32 TEMP03, K05, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K55, DB39
        v_xor_b32 TEMP18, K52, DB40
        v_xor_b32 TEMP10, K46, DB41	
        v_xor_b32 TEMP16, K47, DB42
        v_xor_b32 TEMP02, K34, DB43
        v_xor_b32 TEMP04, K19, DB44
        v_xor_b32 TEMP03, K18, DB43
        v_xor_b32 TEMP06, K26, DB44
        v_xor_b32 TEMP19, K27, DB45
        v_xor_b32 TEMP26, K45, DB46
        v_xor_b32 TEMP22, K39, DB47
        v_xor_b32 TEMP07, K06, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K37, DB_EF72
        v_xor_b32 TEMP18, K42, DB_EF73
        v_xor_b32 TEMP21, K50, DB_EF74
        v_xor_b32 TEMP22, K08, DB_EF75
        v_xor_b32 TEMP04, K24, DB_EF76
        v_xor_b32 TEMP07, K21, DB_EF77
        v_xor_b32 TEMP23, K00, DB_EF78
        v_xor_b32 TEMP06, K44, DB_EF79
        v_xor_b32 TEMP10, K49, DB_EF80
        v_xor_b32 TEMP19, K09, DB_EF81
		v_xor_b32 TEMP02, K36, DB_EF82
        v_xor_b32 TEMP25, K17, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K16, DB55
        v_xor_b32 TEMP18, K10, DB56
        v_xor_b32 TEMP27, K51, DB57
        v_xor_b32 TEMP00, K14, DB58
        v_xor_b32 TEMP12, K29, DB59
        v_xor_b32 TEMP07, K35, DB60
        v_xor_b32 TEMP03, K02, DB59
        v_xor_b32 TEMP01, K30, DB60
        v_xor_b32 TEMP14, K03, DB61
        v_xor_b32 TEMP13, K15, DB62
        v_xor_b32 TEMP02, K07, DB63
        v_xor_b32 TEMP04, K43, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 4 */
		/*******/

        v_xor_b32 TEMP15, K18, DB_EF00
        v_xor_b32 TEMP16, K52, DB_EF01
        v_xor_b32 TEMP17, K39, DB_EF02
        v_xor_b32 TEMP18, K34, DB_EF03
        v_xor_b32 TEMP19, K54, DB_EF04
        v_xor_b32 TEMP20, K26, DB_EF05
        v_xor_b32 TEMP21, K40, DB_EF06
        v_xor_b32 TEMP22, K06, DB_EF07
        v_xor_b32 TEMP23, K11, DB_EF08
        v_xor_b32 TEMP24, K19, DB_EF09
        v_xor_b32 TEMP25, K55, DB_EF10
        v_xor_b32 TEMP26, K46, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K41, DB07
        v_xor_b32 TEMP20, K38, DB08
        v_xor_b32 TEMP18, K32, DB09
        v_xor_b32 TEMP14, K33, DB10
        v_xor_b32 TEMP16, K20, DB11
        v_xor_b32 TEMP25, K05, DB12
        v_xor_b32 TEMP19, K04, DB11
        v_xor_b32 TEMP22, K12, DB12
        v_xor_b32 TEMP13, K13, DB13
        v_xor_b32 TEMP23, K31, DB14
        v_xor_b32 TEMP24, K25, DB15
        v_xor_b32 TEMP12, K47, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K23, DB_EF24
        v_xor_b32 TEMP09, K28, DB_EF25
        v_xor_b32 TEMP18, K36, DB_EF26
        v_xor_b32 TEMP21, K51, DB_EF27
        v_xor_b32 TEMP22, K10, DB_EF28
        v_xor_b32 TEMP23, K07, DB_EF29
        v_xor_b32 TEMP11, K43, DB_EF30
        v_xor_b32 TEMP14, K30, DB_EF31
        v_xor_b32 TEMP10, K35, DB_EF32
        v_xor_b32 TEMP24, K24, DB_EF33
        v_xor_b32 TEMP20, K22, DB_EF34
        v_xor_b32 TEMP25, K03, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K02, DB23
        v_xor_b32 TEMP18, K49, DB24
        v_xor_b32 TEMP21, K37, DB25
        v_xor_b32 TEMP24, K00, DB26
        v_xor_b32 TEMP26, K15, DB27
        v_xor_b32 TEMP23, K21, DB28
        v_xor_b32 TEMP19, K17, DB27
        v_xor_b32 TEMP12, K16, DB28
        v_xor_b32 TEMP25, K42, DB29
        v_xor_b32 TEMP22, K01, DB30
        v_xor_b32 TEMP11, K50, DB31
        v_xor_b32 TEMP20, K29, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 5 */
		/*******/

        v_xor_b32 TEMP08, K04, DB_EF48
        v_xor_b32 TEMP18, K38, DB_EF49
        v_xor_b32 TEMP05, K25, DB_EF50
        v_xor_b32 TEMP16, K20, DB_EF51
        v_xor_b32 TEMP26, K40, DB_EF52
        v_xor_b32 TEMP19, K12, DB_EF53
        v_xor_b32 TEMP14, K26, DB_EF54
        v_xor_b32 TEMP06, K47, DB_EF55
        v_xor_b32 TEMP02, K52, DB_EF56
        v_xor_b32 TEMP07, K05, DB_EF57
        v_xor_b32 TEMP04, K41, DB_EF58
        v_xor_b32 TEMP03, K32, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K27, DB39
        v_xor_b32 TEMP18, K55, DB40
        v_xor_b32 TEMP10, K18, DB41	
        v_xor_b32 TEMP16, K19, DB42
        v_xor_b32 TEMP02, K06, DB43
        v_xor_b32 TEMP04, K46, DB44
        v_xor_b32 TEMP03, K45, DB43
        v_xor_b32 TEMP06, K53, DB44
        v_xor_b32 TEMP19, K54, DB45
        v_xor_b32 TEMP26, K48, DB46
        v_xor_b32 TEMP22, K11, DB47
        v_xor_b32 TEMP07, K33, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K09, DB_EF72
        v_xor_b32 TEMP18, K14, DB_EF73
        v_xor_b32 TEMP21, K22, DB_EF74
        v_xor_b32 TEMP22, K37, DB_EF75
        v_xor_b32 TEMP04, K49, DB_EF76
        v_xor_b32 TEMP07, K50, DB_EF77
        v_xor_b32 TEMP23, K29, DB_EF78
        v_xor_b32 TEMP06, K16, DB_EF79
        v_xor_b32 TEMP10, K21, DB_EF80
        v_xor_b32 TEMP19, K10, DB_EF81
		v_xor_b32 TEMP02, K08, DB_EF82
        v_xor_b32 TEMP25, K42, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K17, DB55
        v_xor_b32 TEMP18, K35, DB56
        v_xor_b32 TEMP27, K23, DB57
        v_xor_b32 TEMP00, K43, DB58
        v_xor_b32 TEMP12, K01, DB59
        v_xor_b32 TEMP07, K07, DB60
        v_xor_b32 TEMP03, K03, DB59
        v_xor_b32 TEMP01, K02, DB60
        v_xor_b32 TEMP14, K28, DB61
        v_xor_b32 TEMP13, K44, DB62
        v_xor_b32 TEMP02, K36, DB63
        v_xor_b32 TEMP04, K15, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 6 */
		/*******/

        v_xor_b32 TEMP15, K45, DB_EF00
        v_xor_b32 TEMP16, K55, DB_EF01
        v_xor_b32 TEMP17, K11, DB_EF02
        v_xor_b32 TEMP18, K06, DB_EF03
        v_xor_b32 TEMP19, K26, DB_EF04
        v_xor_b32 TEMP20, K53, DB_EF05
        v_xor_b32 TEMP21, K12, DB_EF06
        v_xor_b32 TEMP22, K33, DB_EF07
        v_xor_b32 TEMP23, K38, DB_EF08
        v_xor_b32 TEMP24, K46, DB_EF09
        v_xor_b32 TEMP25, K27, DB_EF10
        v_xor_b32 TEMP26, K18, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K13, DB07
        v_xor_b32 TEMP20, K41, DB08
        v_xor_b32 TEMP18, K04, DB09
        v_xor_b32 TEMP14, K05, DB10
        v_xor_b32 TEMP16, K47, DB11
        v_xor_b32 TEMP25, K32, DB12
        v_xor_b32 TEMP19, K31, DB11
        v_xor_b32 TEMP22, K39, DB12
        v_xor_b32 TEMP13, K40, DB13
        v_xor_b32 TEMP23, K34, DB14
        v_xor_b32 TEMP24, K52, DB15
        v_xor_b32 TEMP12, K19, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K24, DB_EF24
        v_xor_b32 TEMP09, K00, DB_EF25
        v_xor_b32 TEMP18, K08, DB_EF26
        v_xor_b32 TEMP21, K23, DB_EF27
        v_xor_b32 TEMP22, K35, DB_EF28
        v_xor_b32 TEMP23, K36, DB_EF29
        v_xor_b32 TEMP11, K15, DB_EF30
        v_xor_b32 TEMP14, K02, DB_EF31
        v_xor_b32 TEMP10, K07, DB_EF32
        v_xor_b32 TEMP24, K49, DB_EF33
        v_xor_b32 TEMP20, K51, DB_EF34
        v_xor_b32 TEMP25, K28, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K03, DB23
        v_xor_b32 TEMP18, K21, DB24
        v_xor_b32 TEMP21, K09, DB25
        v_xor_b32 TEMP24, K29, DB26
        v_xor_b32 TEMP26, K44, DB27
        v_xor_b32 TEMP23, K50, DB28
        v_xor_b32 TEMP19, K42, DB27
        v_xor_b32 TEMP12, K17, DB28
        v_xor_b32 TEMP25, K14, DB29
        v_xor_b32 TEMP22, K30, DB30
        v_xor_b32 TEMP11, K22, DB31
        v_xor_b32 TEMP20, K01, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 7 */
		/*******/

        v_xor_b32 TEMP08, K31, DB_EF48
        v_xor_b32 TEMP18, K41, DB_EF49
        v_xor_b32 TEMP05, K52, DB_EF50
        v_xor_b32 TEMP16, K47, DB_EF51
        v_xor_b32 TEMP26, K12, DB_EF52
        v_xor_b32 TEMP19, K39, DB_EF53
        v_xor_b32 TEMP14, K53, DB_EF54
        v_xor_b32 TEMP06, K19, DB_EF55
        v_xor_b32 TEMP02, K55, DB_EF56
        v_xor_b32 TEMP07, K32, DB_EF57
        v_xor_b32 TEMP04, K13, DB_EF58
        v_xor_b32 TEMP03, K04, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K54, DB39
        v_xor_b32 TEMP18, K27, DB40
        v_xor_b32 TEMP10, K45, DB41	
        v_xor_b32 TEMP16, K46, DB42
        v_xor_b32 TEMP02, K33, DB43
        v_xor_b32 TEMP04, K18, DB44
        v_xor_b32 TEMP03, K48, DB43
        v_xor_b32 TEMP06, K25, DB44
        v_xor_b32 TEMP19, K26, DB45
        v_xor_b32 TEMP26, K20, DB46
        v_xor_b32 TEMP22, K38, DB47
        v_xor_b32 TEMP07, K05, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K10, DB_EF72
        v_xor_b32 TEMP18, K43, DB_EF73
        v_xor_b32 TEMP21, K51, DB_EF74
        v_xor_b32 TEMP22, K09, DB_EF75
        v_xor_b32 TEMP04, K21, DB_EF76
        v_xor_b32 TEMP07, K22, DB_EF77
        v_xor_b32 TEMP23, K01, DB_EF78
        v_xor_b32 TEMP06, K17, DB_EF79
        v_xor_b32 TEMP10, K50, DB_EF80
        v_xor_b32 TEMP19, K35, DB_EF81
		v_xor_b32 TEMP02, K37, DB_EF82
        v_xor_b32 TEMP25, K14, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K42, DB55
        v_xor_b32 TEMP18, K07, DB56
        v_xor_b32 TEMP27, K24, DB57
        v_xor_b32 TEMP00, K15, DB58
        v_xor_b32 TEMP12, K30, DB59
        v_xor_b32 TEMP07, K36, DB60
        v_xor_b32 TEMP03, K28, DB59
        v_xor_b32 TEMP01, K03, DB60
        v_xor_b32 TEMP14, K00, DB61
        v_xor_b32 TEMP13, K16, DB62
        v_xor_b32 TEMP02, K08, DB63
        v_xor_b32 TEMP04, K44, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 8 */
		/*******/

        v_xor_b32 TEMP15, K55, DB_EF00
        v_xor_b32 TEMP16, K34, DB_EF01
        v_xor_b32 TEMP17, K45, DB_EF02
        v_xor_b32 TEMP18, K40, DB_EF03
        v_xor_b32 TEMP19, K05, DB_EF04
        v_xor_b32 TEMP20, K32, DB_EF05
        v_xor_b32 TEMP21, K46, DB_EF06
        v_xor_b32 TEMP22, K12, DB_EF07
        v_xor_b32 TEMP23, K48, DB_EF08
        v_xor_b32 TEMP24, K25, DB_EF09
        v_xor_b32 TEMP25, K06, DB_EF10
        v_xor_b32 TEMP26, K52, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K47, DB07
        v_xor_b32 TEMP20, K20, DB08
        v_xor_b32 TEMP18, K38, DB09
        v_xor_b32 TEMP14, K39, DB10
        v_xor_b32 TEMP16, K26, DB11
        v_xor_b32 TEMP25, K11, DB12
        v_xor_b32 TEMP19, K41, DB11
        v_xor_b32 TEMP22, K18, DB12
        v_xor_b32 TEMP13, K19, DB13
        v_xor_b32 TEMP23, K13, DB14
        v_xor_b32 TEMP24, K31, DB15
        v_xor_b32 TEMP12, K53, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K03, DB_EF24
        v_xor_b32 TEMP09, K36, DB_EF25
        v_xor_b32 TEMP18, K44, DB_EF26
        v_xor_b32 TEMP21, K02, DB_EF27
        v_xor_b32 TEMP22, K14, DB_EF28
        v_xor_b32 TEMP23, K15, DB_EF29
        v_xor_b32 TEMP11, K51, DB_EF30
        v_xor_b32 TEMP14, K10, DB_EF31
        v_xor_b32 TEMP10, K43, DB_EF32
        v_xor_b32 TEMP24, K28, DB_EF33
        v_xor_b32 TEMP20, K30, DB_EF34
        v_xor_b32 TEMP25, K07, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K35, DB23
        v_xor_b32 TEMP18, K00, DB24
        v_xor_b32 TEMP21, K17, DB25
        v_xor_b32 TEMP24, K08, DB26
        v_xor_b32 TEMP26, K23, DB27
        v_xor_b32 TEMP23, K29, DB28
        v_xor_b32 TEMP19, K21, DB27
        v_xor_b32 TEMP12, K49, DB28
        v_xor_b32 TEMP25, K50, DB29
        v_xor_b32 TEMP22, K09, DB30
        v_xor_b32 TEMP11, K01, DB31
        v_xor_b32 TEMP20, K37, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 9 */
		/*******/

        v_xor_b32 TEMP08, K41, DB_EF48
        v_xor_b32 TEMP18, K20, DB_EF49
        v_xor_b32 TEMP05, K31, DB_EF50
        v_xor_b32 TEMP16, K26, DB_EF51
        v_xor_b32 TEMP26, K46, DB_EF52
        v_xor_b32 TEMP19, K18, DB_EF53
        v_xor_b32 TEMP14, K32, DB_EF54
        v_xor_b32 TEMP06, K53, DB_EF55
        v_xor_b32 TEMP02, K34, DB_EF56
        v_xor_b32 TEMP07, K11, DB_EF57
        v_xor_b32 TEMP04, K47, DB_EF58
        v_xor_b32 TEMP03, K38, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K33, DB39
        v_xor_b32 TEMP18, K06, DB40
        v_xor_b32 TEMP10, K55, DB41	
        v_xor_b32 TEMP16, K25, DB42
        v_xor_b32 TEMP02, K12, DB43
        v_xor_b32 TEMP04, K52, DB44
        v_xor_b32 TEMP03, K27, DB43
        v_xor_b32 TEMP06, K04, DB44
        v_xor_b32 TEMP19, K05, DB45
        v_xor_b32 TEMP26, K54, DB46
        v_xor_b32 TEMP22, K48, DB47
        v_xor_b32 TEMP07, K39, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K42, DB_EF72
        v_xor_b32 TEMP18, K22, DB_EF73
        v_xor_b32 TEMP21, K30, DB_EF74
        v_xor_b32 TEMP22, K17, DB_EF75
        v_xor_b32 TEMP04, K00, DB_EF76
        v_xor_b32 TEMP07, K01, DB_EF77
        v_xor_b32 TEMP23, K37, DB_EF78
        v_xor_b32 TEMP06, K49, DB_EF79
        v_xor_b32 TEMP10, K29, DB_EF80
        v_xor_b32 TEMP19, K14, DB_EF81
		v_xor_b32 TEMP02, K16, DB_EF82
        v_xor_b32 TEMP25, K50, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K21, DB55
        v_xor_b32 TEMP18, K43, DB56
        v_xor_b32 TEMP27, K03, DB57
        v_xor_b32 TEMP00, K51, DB58
        v_xor_b32 TEMP12, K09, DB59
        v_xor_b32 TEMP07, K15, DB60
        v_xor_b32 TEMP03, K07, DB59
        v_xor_b32 TEMP01, K35, DB60
        v_xor_b32 TEMP14, K36, DB61
        v_xor_b32 TEMP13, K24, DB62
        v_xor_b32 TEMP02, K44, DB63
        v_xor_b32 TEMP04, K23, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/********/
		/* A 10 */
		/********/

        v_xor_b32 TEMP15, K27, DB_EF00
        v_xor_b32 TEMP16, K06, DB_EF01
        v_xor_b32 TEMP17, K48, DB_EF02
        v_xor_b32 TEMP18, K12, DB_EF03
        v_xor_b32 TEMP19, K32, DB_EF04
        v_xor_b32 TEMP20, K04, DB_EF05
        v_xor_b32 TEMP21, K18, DB_EF06
        v_xor_b32 TEMP22, K39, DB_EF07
        v_xor_b32 TEMP23, K20, DB_EF08
        v_xor_b32 TEMP24, K52, DB_EF09
        v_xor_b32 TEMP25, K33, DB_EF10
        v_xor_b32 TEMP26, K55, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K19, DB07
        v_xor_b32 TEMP20, K47, DB08
        v_xor_b32 TEMP18, K41, DB09
        v_xor_b32 TEMP14, K11, DB10
        v_xor_b32 TEMP16, K53, DB11
        v_xor_b32 TEMP25, K38, DB12
        v_xor_b32 TEMP19, K13, DB11
        v_xor_b32 TEMP22, K45, DB12
        v_xor_b32 TEMP13, K46, DB13
        v_xor_b32 TEMP23, K40, DB14
        v_xor_b32 TEMP24, K34, DB15
        v_xor_b32 TEMP12, K25, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K28, DB_EF24
        v_xor_b32 TEMP09, K08, DB_EF25
        v_xor_b32 TEMP18, K16, DB_EF26
        v_xor_b32 TEMP21, K03, DB_EF27
        v_xor_b32 TEMP22, K43, DB_EF28
        v_xor_b32 TEMP23, K44, DB_EF29
        v_xor_b32 TEMP11, K23, DB_EF30
        v_xor_b32 TEMP14, K35, DB_EF31
        v_xor_b32 TEMP10, K15, DB_EF32
        v_xor_b32 TEMP24, K00, DB_EF33
        v_xor_b32 TEMP20, K02, DB_EF34
        v_xor_b32 TEMP25, K36, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K07, DB23
        v_xor_b32 TEMP18, K29, DB24
        v_xor_b32 TEMP21, K42, DB25
        v_xor_b32 TEMP24, K37, DB26
        v_xor_b32 TEMP26, K24, DB27
        v_xor_b32 TEMP23, K01, DB28
        v_xor_b32 TEMP19, K50, DB27
        v_xor_b32 TEMP12, K21, DB28
        v_xor_b32 TEMP25, K22, DB29
        v_xor_b32 TEMP22, K10, DB30
        v_xor_b32 TEMP11, K30, DB31
        v_xor_b32 TEMP20, K09, DB00
        s_swappc_b64 s[40:41], s[48:49]

 		/********/
		/* B 11 */
		/********/

        v_xor_b32 TEMP08, K13, DB_EF48
        v_xor_b32 TEMP18, K47, DB_EF49
        v_xor_b32 TEMP05, K34, DB_EF50
        v_xor_b32 TEMP16, K53, DB_EF51
        v_xor_b32 TEMP26, K18, DB_EF52
        v_xor_b32 TEMP19, K45, DB_EF53
        v_xor_b32 TEMP14, K04, DB_EF54
        v_xor_b32 TEMP06, K25, DB_EF55
        v_xor_b32 TEMP02, K06, DB_EF56
        v_xor_b32 TEMP07, K38, DB_EF57
        v_xor_b32 TEMP04, K19, DB_EF58
        v_xor_b32 TEMP03, K41, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K05, DB39
        v_xor_b32 TEMP18, K33, DB40
        v_xor_b32 TEMP10, K27, DB41	
        v_xor_b32 TEMP16, K52, DB42
        v_xor_b32 TEMP02, K39, DB43
        v_xor_b32 TEMP04, K55, DB44
        v_xor_b32 TEMP03, K54, DB43
        v_xor_b32 TEMP06, K31, DB44
        v_xor_b32 TEMP19, K32, DB45
        v_xor_b32 TEMP26, K26, DB46
        v_xor_b32 TEMP22, K20, DB47
        v_xor_b32 TEMP07, K11, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K14, DB_EF72
        v_xor_b32 TEMP18, K51, DB_EF73
        v_xor_b32 TEMP21, K02, DB_EF74
        v_xor_b32 TEMP22, K42, DB_EF75
        v_xor_b32 TEMP04, K29, DB_EF76
        v_xor_b32 TEMP07, K30, DB_EF77
        v_xor_b32 TEMP23, K09, DB_EF78
        v_xor_b32 TEMP06, K21, DB_EF79
        v_xor_b32 TEMP10, K01, DB_EF80
        v_xor_b32 TEMP19, K43, DB_EF81
		v_xor_b32 TEMP02, K17, DB_EF82
        v_xor_b32 TEMP25, K22, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K50, DB55
        v_xor_b32 TEMP18, K15, DB56
        v_xor_b32 TEMP27, K28, DB57
        v_xor_b32 TEMP00, K23, DB58
        v_xor_b32 TEMP12, K10, DB59
        v_xor_b32 TEMP07, K44, DB60
        v_xor_b32 TEMP03, K36, DB59
        v_xor_b32 TEMP01, K07, DB60
        v_xor_b32 TEMP14, K08, DB61
        v_xor_b32 TEMP13, K49, DB62
        v_xor_b32 TEMP02, K16, DB63
        v_xor_b32 TEMP04, K24, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/********/
		/* A 12 */
		/********/

        v_xor_b32 TEMP15, K54, DB_EF00
        v_xor_b32 TEMP16, K33, DB_EF01
        v_xor_b32 TEMP17, K20, DB_EF02
        v_xor_b32 TEMP18, K39, DB_EF03
        v_xor_b32 TEMP19, K04, DB_EF04
        v_xor_b32 TEMP20, K31, DB_EF05
        v_xor_b32 TEMP21, K45, DB_EF06
        v_xor_b32 TEMP22, K11, DB_EF07
        v_xor_b32 TEMP23, K47, DB_EF08
        v_xor_b32 TEMP24, K55, DB_EF09
        v_xor_b32 TEMP25, K05, DB_EF10
        v_xor_b32 TEMP26, K27, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K46, DB07
        v_xor_b32 TEMP20, K19, DB08
        v_xor_b32 TEMP18, K13, DB09
        v_xor_b32 TEMP14, K38, DB10
        v_xor_b32 TEMP16, K25, DB11
        v_xor_b32 TEMP25, K41, DB12
        v_xor_b32 TEMP19, K40, DB11
        v_xor_b32 TEMP22, K48, DB12
        v_xor_b32 TEMP13, K18, DB13
        v_xor_b32 TEMP23, K12, DB14
        v_xor_b32 TEMP24, K06, DB15
        v_xor_b32 TEMP12, K52, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K00, DB_EF24
        v_xor_b32 TEMP09, K37, DB_EF25
        v_xor_b32 TEMP18, K17, DB_EF26
        v_xor_b32 TEMP21, K28, DB_EF27
        v_xor_b32 TEMP22, K15, DB_EF28
        v_xor_b32 TEMP23, K16, DB_EF29
        v_xor_b32 TEMP11, K24, DB_EF30
        v_xor_b32 TEMP14, K07, DB_EF31
        v_xor_b32 TEMP10, K44, DB_EF32
        v_xor_b32 TEMP24, K29, DB_EF33
        v_xor_b32 TEMP20, K03, DB_EF34
        v_xor_b32 TEMP25, K08, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K36, DB23
        v_xor_b32 TEMP18, K01, DB24
        v_xor_b32 TEMP21, K14, DB25
        v_xor_b32 TEMP24, K09, DB26
        v_xor_b32 TEMP26, K49, DB27
        v_xor_b32 TEMP23, K30, DB28
        v_xor_b32 TEMP19, K22, DB27
        v_xor_b32 TEMP12, K50, DB28
        v_xor_b32 TEMP25, K51, DB29
        v_xor_b32 TEMP22, K35, DB30
        v_xor_b32 TEMP11, K02, DB31
        v_xor_b32 TEMP20, K10, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/********/
		/* B 13 */
		/********/

        v_xor_b32 TEMP08, K40, DB_EF48
        v_xor_b32 TEMP18, K19, DB_EF49
        v_xor_b32 TEMP05, K06, DB_EF50
        v_xor_b32 TEMP16, K25, DB_EF51
        v_xor_b32 TEMP26, K45, DB_EF52
        v_xor_b32 TEMP19, K48, DB_EF53
        v_xor_b32 TEMP14, K31, DB_EF54
        v_xor_b32 TEMP06, K52, DB_EF55
        v_xor_b32 TEMP02, K33, DB_EF56
        v_xor_b32 TEMP07, K41, DB_EF57
        v_xor_b32 TEMP04, K46, DB_EF58
        v_xor_b32 TEMP03, K13, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K32, DB39
        v_xor_b32 TEMP18, K05, DB40
        v_xor_b32 TEMP10, K54, DB41	
        v_xor_b32 TEMP16, K55, DB42
        v_xor_b32 TEMP02, K11, DB43
        v_xor_b32 TEMP04, K27, DB44
        v_xor_b32 TEMP03, K26, DB43
        v_xor_b32 TEMP06, K34, DB44
        v_xor_b32 TEMP19, K04, DB45
        v_xor_b32 TEMP26, K53, DB46
        v_xor_b32 TEMP22, K47, DB47
        v_xor_b32 TEMP07, K38, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K43, DB_EF72
        v_xor_b32 TEMP18, K23, DB_EF73
        v_xor_b32 TEMP21, K03, DB_EF74
        v_xor_b32 TEMP22, K14, DB_EF75
        v_xor_b32 TEMP04, K01, DB_EF76
        v_xor_b32 TEMP07, K02, DB_EF77
        v_xor_b32 TEMP23, K10, DB_EF78
        v_xor_b32 TEMP06, K50, DB_EF79
        v_xor_b32 TEMP10, K30, DB_EF80
        v_xor_b32 TEMP19, K15, DB_EF81
		v_xor_b32 TEMP02, K42, DB_EF82
        v_xor_b32 TEMP25, K51, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K22, DB55
        v_xor_b32 TEMP18, K44, DB56
        v_xor_b32 TEMP27, K00, DB57
        v_xor_b32 TEMP00, K24, DB58
        v_xor_b32 TEMP12, K35, DB59
        v_xor_b32 TEMP07, K16, DB60
        v_xor_b32 TEMP03, K08, DB59
        v_xor_b32 TEMP01, K36, DB60
        v_xor_b32 TEMP14, K37, DB61
        v_xor_b32 TEMP13, K21, DB62
        v_xor_b32 TEMP02, K17, DB63
        v_xor_b32 TEMP04, K49, DB32
        s_swappc_b64 s[40:41], s[56:57]

 		/********/
		/* A 14 */
		/********/

        v_xor_b32 TEMP15, K26, DB_EF00
        v_xor_b32 TEMP16, K05, DB_EF01
        v_xor_b32 TEMP17, K47, DB_EF02
        v_xor_b32 TEMP18, K11, DB_EF03
        v_xor_b32 TEMP19, K31, DB_EF04
        v_xor_b32 TEMP20, K34, DB_EF05
        v_xor_b32 TEMP21, K48, DB_EF06
        v_xor_b32 TEMP22, K38, DB_EF07
        v_xor_b32 TEMP23, K19, DB_EF08
        v_xor_b32 TEMP24, K27, DB_EF09
        v_xor_b32 TEMP25, K32, DB_EF10
        v_xor_b32 TEMP26, K54, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K18, DB07
        v_xor_b32 TEMP20, K46, DB08
        v_xor_b32 TEMP18, K40, DB09
        v_xor_b32 TEMP14, K41, DB10
        v_xor_b32 TEMP16, K52, DB11
        v_xor_b32 TEMP25, K13, DB12
        v_xor_b32 TEMP19, K12, DB11
        v_xor_b32 TEMP22, K20, DB12
        v_xor_b32 TEMP13, K45, DB13
        v_xor_b32 TEMP23, K39, DB14
        v_xor_b32 TEMP24, K33, DB15
        v_xor_b32 TEMP12, K55, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K29, DB_EF24
        v_xor_b32 TEMP09, K09, DB_EF25
        v_xor_b32 TEMP18, K42, DB_EF26
        v_xor_b32 TEMP21, K00, DB_EF27
        v_xor_b32 TEMP22, K44, DB_EF28
        v_xor_b32 TEMP23, K17, DB_EF29
        v_xor_b32 TEMP11, K49, DB_EF30
        v_xor_b32 TEMP14, K36, DB_EF31
        v_xor_b32 TEMP10, K16, DB_EF32
        v_xor_b32 TEMP24, K01, DB_EF33
        v_xor_b32 TEMP20, K28, DB_EF34
        v_xor_b32 TEMP25, K37, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K08, DB23
        v_xor_b32 TEMP18, K30, DB24
        v_xor_b32 TEMP21, K43, DB25
        v_xor_b32 TEMP24, K10, DB26
        v_xor_b32 TEMP26, K21, DB27
        v_xor_b32 TEMP23, K02, DB28
        v_xor_b32 TEMP19, K51, DB27
        v_xor_b32 TEMP12, K22, DB28
        v_xor_b32 TEMP25, K23, DB29
        v_xor_b32 TEMP22, K07, DB30
        v_xor_b32 TEMP11, K03, DB31
        v_xor_b32 TEMP20, K35, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/********/
		/* B 15 */
		/********/

        v_xor_b32 TEMP08, K19, DB_EF48
        v_xor_b32 TEMP18, K53, DB_EF49
        v_xor_b32 TEMP05, K40, DB_EF50
        v_xor_b32 TEMP16, K04, DB_EF51
        v_xor_b32 TEMP26, K55, DB_EF52
        v_xor_b32 TEMP19, K27, DB_EF53
        v_xor_b32 TEMP14, K41, DB_EF54
        v_xor_b32 TEMP06, K31, DB_EF55
        v_xor_b32 TEMP02, K12, DB_EF56
        v_xor_b32 TEMP07, K20, DB_EF57
        v_xor_b32 TEMP04, K25, DB_EF58
        v_xor_b32 TEMP03, K47, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K11, DB39
        v_xor_b32 TEMP18, K39, DB40
        v_xor_b32 TEMP10, K33, DB41	
        v_xor_b32 TEMP16, K34, DB42
        v_xor_b32 TEMP02, K45, DB43
        v_xor_b32 TEMP04, K06, DB44
        v_xor_b32 TEMP03, K05, DB43
        v_xor_b32 TEMP06, K13, DB44
        v_xor_b32 TEMP19, K38, DB45
        v_xor_b32 TEMP26, K32, DB46
        v_xor_b32 TEMP22, K26, DB47
        v_xor_b32 TEMP07, K48, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K22, DB_EF72
        v_xor_b32 TEMP18, K02, DB_EF73
        v_xor_b32 TEMP21, K35, DB_EF74
        v_xor_b32 TEMP22, K50, DB_EF75
        v_xor_b32 TEMP04, K37, DB_EF76
        v_xor_b32 TEMP07, K10, DB_EF77
        v_xor_b32 TEMP23, K42, DB_EF78
        v_xor_b32 TEMP06, K29, DB_EF79
        v_xor_b32 TEMP10, K09, DB_EF80
        v_xor_b32 TEMP19, K51, DB_EF81
		v_xor_b32 TEMP02, K21, DB_EF82
        v_xor_b32 TEMP25, K30, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K01, DB55
        v_xor_b32 TEMP18, K23, DB56
        v_xor_b32 TEMP27, K36, DB57
        v_xor_b32 TEMP00, K03, DB58
        v_xor_b32 TEMP12, K14, DB59
        v_xor_b32 TEMP07, K24, DB60
        v_xor_b32 TEMP03, K44, DB59
        v_xor_b32 TEMP01, K15, DB60
        v_xor_b32 TEMP14, K16, DB61
        v_xor_b32 TEMP13, K00, DB62
        v_xor_b32 TEMP02, K49, DB63
        v_xor_b32 TEMP04, K28, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*********************************************/
	    s_cmp_eq_i32    s39, 1
        s_cbranch_scc1  .quitLoop
		/*********************************************/

		/*******/
		/* B 0 */
		/*******/

        v_xor_b32 TEMP08, K12, DB_EF48
        v_xor_b32 TEMP18, K46, DB_EF49
        v_xor_b32 TEMP05, K33, DB_EF50
        v_xor_b32 TEMP16, K52, DB_EF51
        v_xor_b32 TEMP26, K48, DB_EF52
        v_xor_b32 TEMP19, K20, DB_EF53
        v_xor_b32 TEMP14, K34, DB_EF54
		v_xor_b32 TEMP06, K55, DB_EF55
        v_xor_b32 TEMP02, K05, DB_EF56
        v_xor_b32 TEMP07, K13, DB_EF57
        v_xor_b32 TEMP04, K18, DB_EF58
        v_xor_b32 TEMP03, K40, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K04, DB39
        v_xor_b32 TEMP18, K32, DB40
        v_xor_b32 TEMP10, K26, DB41
        v_xor_b32 TEMP16, K27, DB42
        v_xor_b32 TEMP02, K38, DB43
        v_xor_b32 TEMP04, K54, DB44
        v_xor_b32 TEMP03, K53, DB43
        v_xor_b32 TEMP06, K06, DB44
        v_xor_b32 TEMP19, K31, DB45
        v_xor_b32 TEMP26, K25, DB46
        v_xor_b32 TEMP22, K19, DB47
        v_xor_b32 TEMP07, K41, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K15, DB_EF72
        v_xor_b32 TEMP18, K24, DB_EF73
        v_xor_b32 TEMP21, K28, DB_EF74
        v_xor_b32 TEMP22, K43, DB_EF75
        v_xor_b32 TEMP04, K30, DB_EF76
        v_xor_b32 TEMP07, K03, DB_EF77
        v_xor_b32 TEMP23, K35, DB_EF78
        v_xor_b32 TEMP06, K22, DB_EF79
        v_xor_b32 TEMP10, K02, DB_EF80
        v_xor_b32 TEMP19, K44, DB_EF81
        v_xor_b32 TEMP02, K14, DB_EF82
        v_xor_b32 TEMP25, K23, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K51, DB55
        v_xor_b32 TEMP18, K16, DB56
        v_xor_b32 TEMP27, K29, DB57
        v_xor_b32 TEMP00, K49, DB58
        v_xor_b32 TEMP12, K07, DB59
        v_xor_b32 TEMP07, K17, DB60
        v_xor_b32 TEMP03, K37, DB59
        v_xor_b32 TEMP01, K08, DB60
        v_xor_b32 TEMP14, K09, DB61
        v_xor_b32 TEMP13, K50, DB62
        v_xor_b32 TEMP02, K42, DB63
        v_xor_b32 TEMP04, K21, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 1 */
		/*******/

        v_xor_b32 TEMP15, K05, DB_EF00
        v_xor_b32 TEMP16, K39, DB_EF01
        v_xor_b32 TEMP17, K26, DB_EF02
        v_xor_b32 TEMP18, K45, DB_EF03
        v_xor_b32 TEMP19, K41, DB_EF04
        v_xor_b32 TEMP20, K13, DB_EF05
        v_xor_b32 TEMP21, K27, DB_EF06
        v_xor_b32 TEMP22, K48, DB_EF07
        v_xor_b32 TEMP23, K53, DB_EF08
        v_xor_b32 TEMP24, K06, DB_EF09
        v_xor_b32 TEMP25, K11, DB_EF10
        v_xor_b32 TEMP26, K33, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K52, DB07
        v_xor_b32 TEMP20, K25, DB08
        v_xor_b32 TEMP18, K19, DB09
        v_xor_b32 TEMP14, K20, DB10
        v_xor_b32 TEMP16, K31, DB11
        v_xor_b32 TEMP25, K47, DB12
        v_xor_b32 TEMP19, K46, DB11
        v_xor_b32 TEMP22, K54, DB12
        v_xor_b32 TEMP13, K55, DB13
        v_xor_b32 TEMP23, K18, DB14
        v_xor_b32 TEMP24, K12, DB15
        v_xor_b32 TEMP12, K34, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K08, DB_EF24
        v_xor_b32 TEMP09, K17, DB_EF25
        v_xor_b32 TEMP18, K21, DB_EF26
        v_xor_b32 TEMP21, K36, DB_EF27
        v_xor_b32 TEMP22, K23, DB_EF28
        v_xor_b32 TEMP23, K49, DB_EF29
        v_xor_b32 TEMP11, K28, DB_EF30
        v_xor_b32 TEMP14, K15, DB_EF31
        v_xor_b32 TEMP10, K24, DB_EF32
        v_xor_b32 TEMP24, K37, DB_EF33
        v_xor_b32 TEMP20, K07, DB_EF34
        v_xor_b32 TEMP25, K16, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K44, DB23
        v_xor_b32 TEMP18, K09, DB24
        v_xor_b32 TEMP21, K22, DB25
        v_xor_b32 TEMP24, K42, DB26
        v_xor_b32 TEMP26, K00, DB27
        v_xor_b32 TEMP23, K10, DB28
        v_xor_b32 TEMP19, K30, DB27
        v_xor_b32 TEMP12, K01, DB28
        v_xor_b32 TEMP25, K02, DB29
        v_xor_b32 TEMP22, K43, DB30
        v_xor_b32 TEMP11, K35, DB31
        v_xor_b32 TEMP20, K14, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 2 */
		/*******/

        v_xor_b32 TEMP08, K46, DB_EF48
        v_xor_b32 TEMP18, K25, DB_EF49
        v_xor_b32 TEMP05, K12, DB_EF50
        v_xor_b32 TEMP16, K31, DB_EF51
        v_xor_b32 TEMP26, K27, DB_EF52
        v_xor_b32 TEMP19, K54, DB_EF53
        v_xor_b32 TEMP14, K13, DB_EF54
		v_xor_b32 TEMP06, K34, DB_EF55
        v_xor_b32 TEMP02, K39, DB_EF56
        v_xor_b32 TEMP07, K47, DB_EF57
        v_xor_b32 TEMP04, K52, DB_EF58
        v_xor_b32 TEMP03, K19, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K38, DB39
        v_xor_b32 TEMP18, K11, DB40
        v_xor_b32 TEMP10, K05, DB41
        v_xor_b32 TEMP16, K06, DB42
        v_xor_b32 TEMP02, K48, DB43
        v_xor_b32 TEMP04, K33, DB44
        v_xor_b32 TEMP03, K32, DB43
        v_xor_b32 TEMP06, K40, DB44
        v_xor_b32 TEMP19, K41, DB45
        v_xor_b32 TEMP26, K04, DB46
        v_xor_b32 TEMP22, K53, DB47
        v_xor_b32 TEMP07, K20, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K51, DB_EF72
        v_xor_b32 TEMP18, K03, DB_EF73
        v_xor_b32 TEMP21, K07, DB_EF74
        v_xor_b32 TEMP22, K22, DB_EF75
        v_xor_b32 TEMP04, K09, DB_EF76
        v_xor_b32 TEMP07, K35, DB_EF77
        v_xor_b32 TEMP23, K14, DB_EF78
        v_xor_b32 TEMP06, K01, DB_EF79
        v_xor_b32 TEMP10, K10, DB_EF80
        v_xor_b32 TEMP19, K23, DB_EF81
        v_xor_b32 TEMP02, K50, DB_EF82
        v_xor_b32 TEMP25, K02, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K30, DB55
        v_xor_b32 TEMP18, K24, DB56
        v_xor_b32 TEMP27, K08, DB57
        v_xor_b32 TEMP00, K28, DB58
        v_xor_b32 TEMP12, K43, DB59
        v_xor_b32 TEMP07, K49, DB60
        v_xor_b32 TEMP03, K16, DB59
        v_xor_b32 TEMP01, K44, DB60
        v_xor_b32 TEMP14, K17, DB61
        v_xor_b32 TEMP13, K29, DB62
        v_xor_b32 TEMP02, K21, DB63
        v_xor_b32 TEMP04, K00, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 3 */
		/*******/

        v_xor_b32 TEMP15, K32, DB_EF00
        v_xor_b32 TEMP16, K11, DB_EF01
        v_xor_b32 TEMP17, K53, DB_EF02
        v_xor_b32 TEMP18, K48, DB_EF03
        v_xor_b32 TEMP19, K13, DB_EF04
        v_xor_b32 TEMP20, K40, DB_EF05
        v_xor_b32 TEMP21, K54, DB_EF06
        v_xor_b32 TEMP22, K20, DB_EF07
        v_xor_b32 TEMP23, K25, DB_EF08
        v_xor_b32 TEMP24, K33, DB_EF09
        v_xor_b32 TEMP25, K38, DB_EF10
        v_xor_b32 TEMP26, K05, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K55, DB07
        v_xor_b32 TEMP20, K52, DB08
        v_xor_b32 TEMP18, K46, DB09
        v_xor_b32 TEMP14, K47, DB10
        v_xor_b32 TEMP16, K34, DB11
        v_xor_b32 TEMP25, K19, DB12
        v_xor_b32 TEMP19, K18, DB11
        v_xor_b32 TEMP22, K26, DB12
        v_xor_b32 TEMP13, K27, DB13
        v_xor_b32 TEMP23, K45, DB14
        v_xor_b32 TEMP24, K39, DB15
        v_xor_b32 TEMP12, K06, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K37, DB_EF24
        v_xor_b32 TEMP09, K42, DB_EF25
        v_xor_b32 TEMP18, K50, DB_EF26
        v_xor_b32 TEMP21, K08, DB_EF27
        v_xor_b32 TEMP22, K24, DB_EF28
        v_xor_b32 TEMP23, K21, DB_EF29
        v_xor_b32 TEMP11, K00, DB_EF30
        v_xor_b32 TEMP14, K44, DB_EF31
        v_xor_b32 TEMP10, K49, DB_EF32
        v_xor_b32 TEMP24, K09, DB_EF33
        v_xor_b32 TEMP20, K36, DB_EF34
        v_xor_b32 TEMP25, K17, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K16, DB23
        v_xor_b32 TEMP18, K10, DB24
        v_xor_b32 TEMP21, K51, DB25
        v_xor_b32 TEMP24, K14, DB26
        v_xor_b32 TEMP26, K29, DB27
        v_xor_b32 TEMP23, K35, DB28
        v_xor_b32 TEMP19, K02, DB27
        v_xor_b32 TEMP12, K30, DB28
        v_xor_b32 TEMP25, K03, DB29
        v_xor_b32 TEMP22, K15, DB30
        v_xor_b32 TEMP11, K07, DB31
        v_xor_b32 TEMP20, K43, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 4 */
		/*******/

        v_xor_b32 TEMP08, K18, DB_EF48
        v_xor_b32 TEMP18, K52, DB_EF49
        v_xor_b32 TEMP05, K39, DB_EF50
        v_xor_b32 TEMP16, K34, DB_EF51
        v_xor_b32 TEMP26, K54, DB_EF52
        v_xor_b32 TEMP19, K26, DB_EF53
        v_xor_b32 TEMP14, K40, DB_EF54
		v_xor_b32 TEMP06, K06, DB_EF55
        v_xor_b32 TEMP02, K11, DB_EF56
        v_xor_b32 TEMP07, K19, DB_EF57
        v_xor_b32 TEMP04, K55, DB_EF58
        v_xor_b32 TEMP03, K46, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K41, DB39
        v_xor_b32 TEMP18, K38, DB40
        v_xor_b32 TEMP10, K32, DB41
        v_xor_b32 TEMP16, K33, DB42
        v_xor_b32 TEMP02, K20, DB43
        v_xor_b32 TEMP04, K05, DB44
        v_xor_b32 TEMP03, K04, DB43
        v_xor_b32 TEMP06, K12, DB44
        v_xor_b32 TEMP19, K13, DB45
        v_xor_b32 TEMP26, K31, DB46
        v_xor_b32 TEMP22, K25, DB47
        v_xor_b32 TEMP07, K47, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K23, DB_EF72
        v_xor_b32 TEMP18, K28, DB_EF73
        v_xor_b32 TEMP21, K36, DB_EF74
        v_xor_b32 TEMP22, K51, DB_EF75
        v_xor_b32 TEMP04, K10, DB_EF76
        v_xor_b32 TEMP07, K07, DB_EF77
        v_xor_b32 TEMP23, K43, DB_EF78
        v_xor_b32 TEMP06, K30, DB_EF79
        v_xor_b32 TEMP10, K35, DB_EF80
        v_xor_b32 TEMP19, K24, DB_EF81
        v_xor_b32 TEMP02, K22, DB_EF82
        v_xor_b32 TEMP25, K03, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K02, DB55
        v_xor_b32 TEMP18, K49, DB56
        v_xor_b32 TEMP27, K37, DB57
        v_xor_b32 TEMP00, K00, DB58
        v_xor_b32 TEMP12, K15, DB59
        v_xor_b32 TEMP07, K21, DB60
        v_xor_b32 TEMP03, K17, DB59
        v_xor_b32 TEMP01, K16, DB60
        v_xor_b32 TEMP14, K42, DB61
        v_xor_b32 TEMP13, K01, DB62
        v_xor_b32 TEMP02, K50, DB63
        v_xor_b32 TEMP04, K29, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 5 */
		/*******/

        v_xor_b32 TEMP15, K04, DB_EF00
        v_xor_b32 TEMP16, K38, DB_EF01
        v_xor_b32 TEMP17, K25, DB_EF02
        v_xor_b32 TEMP18, K20, DB_EF03
        v_xor_b32 TEMP19, K40, DB_EF04
        v_xor_b32 TEMP20, K12, DB_EF05
        v_xor_b32 TEMP21, K26, DB_EF06
        v_xor_b32 TEMP22, K47, DB_EF07
        v_xor_b32 TEMP23, K52, DB_EF08
        v_xor_b32 TEMP24, K05, DB_EF09
        v_xor_b32 TEMP25, K41, DB_EF10
        v_xor_b32 TEMP26, K32, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K27, DB07
        v_xor_b32 TEMP20, K55, DB08
        v_xor_b32 TEMP18, K18, DB09
        v_xor_b32 TEMP14, K19, DB10
        v_xor_b32 TEMP16, K06, DB11
        v_xor_b32 TEMP25, K46, DB12
        v_xor_b32 TEMP19, K45, DB11
        v_xor_b32 TEMP22, K53, DB12
        v_xor_b32 TEMP13, K54, DB13
        v_xor_b32 TEMP23, K48, DB14
        v_xor_b32 TEMP24, K11, DB15
        v_xor_b32 TEMP12, K33, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K09, DB_EF24
        v_xor_b32 TEMP09, K14, DB_EF25
        v_xor_b32 TEMP18, K22, DB_EF26
        v_xor_b32 TEMP21, K37, DB_EF27
        v_xor_b32 TEMP22, K49, DB_EF28
        v_xor_b32 TEMP23, K50, DB_EF29
        v_xor_b32 TEMP11, K29, DB_EF30
        v_xor_b32 TEMP14, K16, DB_EF31
        v_xor_b32 TEMP10, K21, DB_EF32
        v_xor_b32 TEMP24, K10, DB_EF33
        v_xor_b32 TEMP20, K08, DB_EF34
        v_xor_b32 TEMP25, K42, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K17, DB23
        v_xor_b32 TEMP18, K35, DB24
        v_xor_b32 TEMP21, K23, DB25
        v_xor_b32 TEMP24, K43, DB26
        v_xor_b32 TEMP26, K01, DB27
        v_xor_b32 TEMP23, K07, DB28
        v_xor_b32 TEMP19, K03, DB27
        v_xor_b32 TEMP12, K02, DB28
        v_xor_b32 TEMP25, K28, DB29
        v_xor_b32 TEMP22, K44, DB30
        v_xor_b32 TEMP11, K36, DB31
        v_xor_b32 TEMP20, K15, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 6 */
		/*******/

        v_xor_b32 TEMP08, K45, DB_EF48
        v_xor_b32 TEMP18, K55, DB_EF49
        v_xor_b32 TEMP05, K11, DB_EF50
        v_xor_b32 TEMP16, K06, DB_EF51
        v_xor_b32 TEMP26, K26, DB_EF52
        v_xor_b32 TEMP19, K53, DB_EF53
        v_xor_b32 TEMP14, K12, DB_EF54
		v_xor_b32 TEMP06, K33, DB_EF55
        v_xor_b32 TEMP02, K38, DB_EF56
        v_xor_b32 TEMP07, K46, DB_EF57
        v_xor_b32 TEMP04, K27, DB_EF58
        v_xor_b32 TEMP03, K18, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K13, DB39
        v_xor_b32 TEMP18, K41, DB40
        v_xor_b32 TEMP10, K04, DB41
        v_xor_b32 TEMP16, K05, DB42
        v_xor_b32 TEMP02, K47, DB43
        v_xor_b32 TEMP04, K32, DB44
        v_xor_b32 TEMP03, K31, DB43
        v_xor_b32 TEMP06, K39, DB44
        v_xor_b32 TEMP19, K40, DB45
        v_xor_b32 TEMP26, K34, DB46
        v_xor_b32 TEMP22, K52, DB47
        v_xor_b32 TEMP07, K19, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K24, DB_EF72
        v_xor_b32 TEMP18, K00, DB_EF73
        v_xor_b32 TEMP21, K08, DB_EF74
        v_xor_b32 TEMP22, K23, DB_EF75
        v_xor_b32 TEMP04, K35, DB_EF76
        v_xor_b32 TEMP07, K36, DB_EF77
        v_xor_b32 TEMP23, K15, DB_EF78
        v_xor_b32 TEMP06, K02, DB_EF79
        v_xor_b32 TEMP10, K07, DB_EF80
        v_xor_b32 TEMP19, K49, DB_EF81
        v_xor_b32 TEMP02, K51, DB_EF82
        v_xor_b32 TEMP25, K28, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K03, DB55
        v_xor_b32 TEMP18, K21, DB56
        v_xor_b32 TEMP27, K09, DB57
        v_xor_b32 TEMP00, K29, DB58
        v_xor_b32 TEMP12, K44, DB59
        v_xor_b32 TEMP07, K50, DB60
        v_xor_b32 TEMP03, K42, DB59
        v_xor_b32 TEMP01, K17, DB60
        v_xor_b32 TEMP14, K14, DB61
        v_xor_b32 TEMP13, K30, DB62
        v_xor_b32 TEMP02, K22, DB63
        v_xor_b32 TEMP04, K01, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 7 */
		/*******/

        v_xor_b32 TEMP15, K31, DB_EF00
        v_xor_b32 TEMP16, K41, DB_EF01
        v_xor_b32 TEMP17, K52, DB_EF02
        v_xor_b32 TEMP18, K47, DB_EF03
        v_xor_b32 TEMP19, K12, DB_EF04
        v_xor_b32 TEMP20, K39, DB_EF05
        v_xor_b32 TEMP21, K53, DB_EF06
        v_xor_b32 TEMP22, K19, DB_EF07
        v_xor_b32 TEMP23, K55, DB_EF08
        v_xor_b32 TEMP24, K32, DB_EF09
        v_xor_b32 TEMP25, K13, DB_EF10
        v_xor_b32 TEMP26, K04, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K54, DB07
        v_xor_b32 TEMP20, K27, DB08
        v_xor_b32 TEMP18, K45, DB09
        v_xor_b32 TEMP14, K46, DB10
        v_xor_b32 TEMP16, K33, DB11
        v_xor_b32 TEMP25, K18, DB12
        v_xor_b32 TEMP19, K48, DB11
        v_xor_b32 TEMP22, K25, DB12
        v_xor_b32 TEMP13, K26, DB13
        v_xor_b32 TEMP23, K20, DB14
        v_xor_b32 TEMP24, K38, DB15
        v_xor_b32 TEMP12, K05, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K10, DB_EF24
        v_xor_b32 TEMP09, K43, DB_EF25
        v_xor_b32 TEMP18, K51, DB_EF26
        v_xor_b32 TEMP21, K09, DB_EF27
        v_xor_b32 TEMP22, K21, DB_EF28
        v_xor_b32 TEMP23, K22, DB_EF29
        v_xor_b32 TEMP11, K01, DB_EF30
        v_xor_b32 TEMP14, K17, DB_EF31
        v_xor_b32 TEMP10, K50, DB_EF32
        v_xor_b32 TEMP24, K35, DB_EF33
        v_xor_b32 TEMP20, K37, DB_EF34
        v_xor_b32 TEMP25, K14, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K42, DB23
        v_xor_b32 TEMP18, K07, DB24
        v_xor_b32 TEMP21, K24, DB25
        v_xor_b32 TEMP24, K15, DB26
        v_xor_b32 TEMP26, K30, DB27
        v_xor_b32 TEMP23, K36, DB28
        v_xor_b32 TEMP19, K28, DB27
        v_xor_b32 TEMP12, K03, DB28
        v_xor_b32 TEMP25, K00, DB29
        v_xor_b32 TEMP22, K16, DB30
        v_xor_b32 TEMP11, K08, DB31
        v_xor_b32 TEMP20, K44, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/*******/
		/* B 8 */
		/*******/

        v_xor_b32 TEMP08, K55, DB_EF48
        v_xor_b32 TEMP18, K34, DB_EF49
        v_xor_b32 TEMP05, K45, DB_EF50
        v_xor_b32 TEMP16, K40, DB_EF51
        v_xor_b32 TEMP26, K05, DB_EF52
        v_xor_b32 TEMP19, K32, DB_EF53
        v_xor_b32 TEMP14, K46, DB_EF54
		v_xor_b32 TEMP06, K12, DB_EF55
        v_xor_b32 TEMP02, K48, DB_EF56
        v_xor_b32 TEMP07, K25, DB_EF57
        v_xor_b32 TEMP04, K06, DB_EF58
        v_xor_b32 TEMP03, K52, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K47, DB39
        v_xor_b32 TEMP18, K20, DB40
        v_xor_b32 TEMP10, K38, DB41
        v_xor_b32 TEMP16, K39, DB42
        v_xor_b32 TEMP02, K26, DB43
        v_xor_b32 TEMP04, K11, DB44
        v_xor_b32 TEMP03, K41, DB43
        v_xor_b32 TEMP06, K18, DB44
        v_xor_b32 TEMP19, K19, DB45
        v_xor_b32 TEMP26, K13, DB46
        v_xor_b32 TEMP22, K31, DB47
        v_xor_b32 TEMP07, K53, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K03, DB_EF72
        v_xor_b32 TEMP18, K36, DB_EF73
        v_xor_b32 TEMP21, K44, DB_EF74
        v_xor_b32 TEMP22, K02, DB_EF75
        v_xor_b32 TEMP04, K14, DB_EF76
        v_xor_b32 TEMP07, K15, DB_EF77
        v_xor_b32 TEMP23, K51, DB_EF78
        v_xor_b32 TEMP06, K10, DB_EF79
        v_xor_b32 TEMP10, K43, DB_EF80
        v_xor_b32 TEMP19, K28, DB_EF81
        v_xor_b32 TEMP02, K30, DB_EF82
        v_xor_b32 TEMP25, K07, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K35, DB55
        v_xor_b32 TEMP18, K00, DB56
        v_xor_b32 TEMP27, K17, DB57
        v_xor_b32 TEMP00, K08, DB58
        v_xor_b32 TEMP12, K23, DB59
        v_xor_b32 TEMP07, K29, DB60
        v_xor_b32 TEMP03, K21, DB59
        v_xor_b32 TEMP01, K49, DB60
        v_xor_b32 TEMP14, K50, DB61
        v_xor_b32 TEMP13, K09, DB62
        v_xor_b32 TEMP02, K01, DB63
        v_xor_b32 TEMP04, K37, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/*******/
		/* A 9 */
		/*******/

        v_xor_b32 TEMP15, K41, DB_EF00
        v_xor_b32 TEMP16, K20, DB_EF01
        v_xor_b32 TEMP17, K31, DB_EF02
        v_xor_b32 TEMP18, K26, DB_EF03
        v_xor_b32 TEMP19, K46, DB_EF04
        v_xor_b32 TEMP20, K18, DB_EF05
        v_xor_b32 TEMP21, K32, DB_EF06
        v_xor_b32 TEMP22, K53, DB_EF07
        v_xor_b32 TEMP23, K34, DB_EF08
        v_xor_b32 TEMP24, K11, DB_EF09
        v_xor_b32 TEMP25, K47, DB_EF10
        v_xor_b32 TEMP26, K38, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K33, DB07
        v_xor_b32 TEMP20, K06, DB08
        v_xor_b32 TEMP18, K55, DB09
        v_xor_b32 TEMP14, K25, DB10
        v_xor_b32 TEMP16, K12, DB11
        v_xor_b32 TEMP25, K52, DB12
        v_xor_b32 TEMP19, K27, DB11
        v_xor_b32 TEMP22, K04, DB12
        v_xor_b32 TEMP13, K05, DB13
        v_xor_b32 TEMP23, K54, DB14
        v_xor_b32 TEMP24, K48, DB15
        v_xor_b32 TEMP12, K39, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K42, DB_EF24
        v_xor_b32 TEMP09, K22, DB_EF25
        v_xor_b32 TEMP18, K30, DB_EF26
        v_xor_b32 TEMP21, K17, DB_EF27
        v_xor_b32 TEMP22, K00, DB_EF28
        v_xor_b32 TEMP23, K01, DB_EF29
        v_xor_b32 TEMP11, K37, DB_EF30
        v_xor_b32 TEMP14, K49, DB_EF31
        v_xor_b32 TEMP10, K29, DB_EF32
        v_xor_b32 TEMP24, K14, DB_EF33
        v_xor_b32 TEMP20, K16, DB_EF34
        v_xor_b32 TEMP25, K50, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K21, DB23
        v_xor_b32 TEMP18, K43, DB24
        v_xor_b32 TEMP21, K03, DB25
        v_xor_b32 TEMP24, K51, DB26
        v_xor_b32 TEMP26, K09, DB27
        v_xor_b32 TEMP23, K15, DB28
        v_xor_b32 TEMP19, K07, DB27
        v_xor_b32 TEMP12, K35, DB28
        v_xor_b32 TEMP25, K36, DB29
        v_xor_b32 TEMP22, K24, DB30
        v_xor_b32 TEMP11, K44, DB31
        v_xor_b32 TEMP20, K23, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/********/
		/* B 10 */
		/********/

        v_xor_b32 TEMP08, K27, DB_EF48
        v_xor_b32 TEMP18, K06, DB_EF49
        v_xor_b32 TEMP05, K48, DB_EF50
        v_xor_b32 TEMP16, K12, DB_EF51
        v_xor_b32 TEMP26, K32, DB_EF52
        v_xor_b32 TEMP19, K04, DB_EF53
        v_xor_b32 TEMP14, K18, DB_EF54
		v_xor_b32 TEMP06, K39, DB_EF55
        v_xor_b32 TEMP02, K20, DB_EF56
        v_xor_b32 TEMP07, K52, DB_EF57
        v_xor_b32 TEMP04, K33, DB_EF58
        v_xor_b32 TEMP03, K55, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K19, DB39
        v_xor_b32 TEMP18, K47, DB40
        v_xor_b32 TEMP10, K41, DB41
        v_xor_b32 TEMP16, K11, DB42
        v_xor_b32 TEMP02, K53, DB43
        v_xor_b32 TEMP04, K38, DB44
        v_xor_b32 TEMP03, K13, DB43
        v_xor_b32 TEMP06, K45, DB44
        v_xor_b32 TEMP19, K46, DB45
        v_xor_b32 TEMP26, K40, DB46
        v_xor_b32 TEMP22, K34, DB47
        v_xor_b32 TEMP07, K25, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K28, DB_EF72
        v_xor_b32 TEMP18, K08, DB_EF73
        v_xor_b32 TEMP21, K16, DB_EF74
        v_xor_b32 TEMP22, K03, DB_EF75
        v_xor_b32 TEMP04, K43, DB_EF76
        v_xor_b32 TEMP07, K44, DB_EF77
        v_xor_b32 TEMP23, K23, DB_EF78
        v_xor_b32 TEMP06, K35, DB_EF79
        v_xor_b32 TEMP10, K15, DB_EF80
        v_xor_b32 TEMP19, K00, DB_EF81
        v_xor_b32 TEMP02, K02, DB_EF82
        v_xor_b32 TEMP25, K36, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K07, DB55
        v_xor_b32 TEMP18, K29, DB56
        v_xor_b32 TEMP27, K42, DB57
        v_xor_b32 TEMP00, K37, DB58
        v_xor_b32 TEMP12, K24, DB59
        v_xor_b32 TEMP07, K01, DB60
        v_xor_b32 TEMP03, K50, DB59
        v_xor_b32 TEMP01, K21, DB60
        v_xor_b32 TEMP14, K22, DB61
        v_xor_b32 TEMP13, K10, DB62
        v_xor_b32 TEMP02, K30, DB63
        v_xor_b32 TEMP04, K09, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/********/
		/* A 11 */
		/********/

        v_xor_b32 TEMP15, K13, DB_EF00
        v_xor_b32 TEMP16, K47, DB_EF01
        v_xor_b32 TEMP17, K34, DB_EF02
        v_xor_b32 TEMP18, K53, DB_EF03
        v_xor_b32 TEMP19, K18, DB_EF04
        v_xor_b32 TEMP20, K45, DB_EF05
        v_xor_b32 TEMP21, K04, DB_EF06
        v_xor_b32 TEMP22, K25, DB_EF07
        v_xor_b32 TEMP23, K06, DB_EF08
        v_xor_b32 TEMP24, K38, DB_EF09
        v_xor_b32 TEMP25, K19, DB_EF10
        v_xor_b32 TEMP26, K41, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K05, DB07
        v_xor_b32 TEMP20, K33, DB08
        v_xor_b32 TEMP18, K27, DB09
        v_xor_b32 TEMP14, K52, DB10
        v_xor_b32 TEMP16, K39, DB11
        v_xor_b32 TEMP25, K55, DB12
        v_xor_b32 TEMP19, K54, DB11
        v_xor_b32 TEMP22, K31, DB12
        v_xor_b32 TEMP13, K32, DB13
        v_xor_b32 TEMP23, K26, DB14
        v_xor_b32 TEMP24, K20, DB15
        v_xor_b32 TEMP12, K11, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K14, DB_EF24
        v_xor_b32 TEMP09, K51, DB_EF25
        v_xor_b32 TEMP18, K02, DB_EF26
        v_xor_b32 TEMP21, K42, DB_EF27
        v_xor_b32 TEMP22, K29, DB_EF28
        v_xor_b32 TEMP23, K30, DB_EF29
        v_xor_b32 TEMP11, K09, DB_EF30
        v_xor_b32 TEMP14, K21, DB_EF31
        v_xor_b32 TEMP10, K01, DB_EF32
        v_xor_b32 TEMP24, K43, DB_EF33
        v_xor_b32 TEMP20, K17, DB_EF34
        v_xor_b32 TEMP25, K22, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K50, DB23
        v_xor_b32 TEMP18, K15, DB24
        v_xor_b32 TEMP21, K28, DB25
        v_xor_b32 TEMP24, K23, DB26
        v_xor_b32 TEMP26, K10, DB27
        v_xor_b32 TEMP23, K44, DB28
        v_xor_b32 TEMP19, K36, DB27
        v_xor_b32 TEMP12, K07, DB28
        v_xor_b32 TEMP25, K08, DB29
        v_xor_b32 TEMP22, K49, DB30
        v_xor_b32 TEMP11, K16, DB31
        v_xor_b32 TEMP20, K24, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/********/
		/* B 12 */
		/********/

        v_xor_b32 TEMP08, K54, DB_EF48
        v_xor_b32 TEMP18, K33, DB_EF49
        v_xor_b32 TEMP05, K20, DB_EF50
        v_xor_b32 TEMP16, K39, DB_EF51
        v_xor_b32 TEMP26, K04, DB_EF52
        v_xor_b32 TEMP19, K31, DB_EF53
        v_xor_b32 TEMP14, K45, DB_EF54
		v_xor_b32 TEMP06, K11, DB_EF55
        v_xor_b32 TEMP02, K47, DB_EF56
        v_xor_b32 TEMP07, K55, DB_EF57
        v_xor_b32 TEMP04, K05, DB_EF58
        v_xor_b32 TEMP03, K27, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K46, DB39
        v_xor_b32 TEMP18, K19, DB40
        v_xor_b32 TEMP10, K13, DB41
        v_xor_b32 TEMP16, K38, DB42
        v_xor_b32 TEMP02, K25, DB43
        v_xor_b32 TEMP04, K41, DB44
        v_xor_b32 TEMP03, K40, DB43
        v_xor_b32 TEMP06, K48, DB44
        v_xor_b32 TEMP19, K18, DB45
        v_xor_b32 TEMP26, K12, DB46
        v_xor_b32 TEMP22, K06, DB47
        v_xor_b32 TEMP07, K52, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K00, DB_EF72
        v_xor_b32 TEMP18, K37, DB_EF73
        v_xor_b32 TEMP21, K17, DB_EF74
        v_xor_b32 TEMP22, K28, DB_EF75
        v_xor_b32 TEMP04, K15, DB_EF76
        v_xor_b32 TEMP07, K16, DB_EF77
        v_xor_b32 TEMP23, K24, DB_EF78
        v_xor_b32 TEMP06, K07, DB_EF79
        v_xor_b32 TEMP10, K44, DB_EF80
        v_xor_b32 TEMP19, K29, DB_EF81
        v_xor_b32 TEMP02, K03, DB_EF82
        v_xor_b32 TEMP25, K08, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K36, DB55
        v_xor_b32 TEMP18, K01, DB56
        v_xor_b32 TEMP27, K14, DB57
        v_xor_b32 TEMP00, K09, DB58
        v_xor_b32 TEMP12, K49, DB59
        v_xor_b32 TEMP07, K30, DB60
        v_xor_b32 TEMP03, K22, DB59
        v_xor_b32 TEMP01, K50, DB60
        v_xor_b32 TEMP14, K51, DB61
        v_xor_b32 TEMP13, K35, DB62
        v_xor_b32 TEMP02, K02, DB63
        v_xor_b32 TEMP04, K10, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/********/
		/* A 13 */
		/********/

        v_xor_b32 TEMP15, K40, DB_EF00
        v_xor_b32 TEMP16, K19, DB_EF01
        v_xor_b32 TEMP17, K06, DB_EF02
        v_xor_b32 TEMP18, K25, DB_EF03
        v_xor_b32 TEMP19, K45, DB_EF04
        v_xor_b32 TEMP20, K48, DB_EF05
        v_xor_b32 TEMP21, K31, DB_EF06
        v_xor_b32 TEMP22, K52, DB_EF07
        v_xor_b32 TEMP23, K33, DB_EF08
        v_xor_b32 TEMP24, K41, DB_EF09
        v_xor_b32 TEMP25, K46, DB_EF10
        v_xor_b32 TEMP26, K13, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K32, DB07
        v_xor_b32 TEMP20, K05, DB08
        v_xor_b32 TEMP18, K54, DB09
        v_xor_b32 TEMP14, K55, DB10
        v_xor_b32 TEMP16, K11, DB11
        v_xor_b32 TEMP25, K27, DB12
        v_xor_b32 TEMP19, K26, DB11
        v_xor_b32 TEMP22, K34, DB12
        v_xor_b32 TEMP13, K04, DB13
        v_xor_b32 TEMP23, K53, DB14
        v_xor_b32 TEMP24, K47, DB15
        v_xor_b32 TEMP12, K38, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K43, DB_EF24
        v_xor_b32 TEMP09, K23, DB_EF25
        v_xor_b32 TEMP18, K03, DB_EF26
        v_xor_b32 TEMP21, K14, DB_EF27
        v_xor_b32 TEMP22, K01, DB_EF28
        v_xor_b32 TEMP23, K02, DB_EF29
        v_xor_b32 TEMP11, K10, DB_EF30
        v_xor_b32 TEMP14, K50, DB_EF31
        v_xor_b32 TEMP10, K30, DB_EF32
        v_xor_b32 TEMP24, K15, DB_EF33
        v_xor_b32 TEMP20, K42, DB_EF34
        v_xor_b32 TEMP25, K51, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K22, DB23
        v_xor_b32 TEMP18, K44, DB24
        v_xor_b32 TEMP21, K00, DB25
        v_xor_b32 TEMP24, K24, DB26
        v_xor_b32 TEMP26, K35, DB27
        v_xor_b32 TEMP23, K16, DB28
        v_xor_b32 TEMP19, K08, DB27
        v_xor_b32 TEMP12, K36, DB28
        v_xor_b32 TEMP25, K37, DB29
        v_xor_b32 TEMP22, K21, DB30
        v_xor_b32 TEMP11, K17, DB31
        v_xor_b32 TEMP20, K49, DB00
        s_swappc_b64 s[40:41], s[48:49]

		/********/
		/* B 14 */
		/********/

        v_xor_b32 TEMP08, K26, DB_EF48
        v_xor_b32 TEMP18, K05, DB_EF49
        v_xor_b32 TEMP05, K47, DB_EF50
        v_xor_b32 TEMP16, K11, DB_EF51
        v_xor_b32 TEMP26, K31, DB_EF52
        v_xor_b32 TEMP19, K34, DB_EF53
        v_xor_b32 TEMP14, K48, DB_EF54
		v_xor_b32 TEMP06, K38, DB_EF55
        v_xor_b32 TEMP02, K19, DB_EF56
        v_xor_b32 TEMP07, K27, DB_EF57
        v_xor_b32 TEMP04, K32, DB_EF58
        v_xor_b32 TEMP03, K54, DB_EF59
        s_swappc_b64 s[40:41], s[50:51]

        v_xor_b32 TEMP25, K18, DB39
        v_xor_b32 TEMP18, K46, DB40
        v_xor_b32 TEMP10, K40, DB41
        v_xor_b32 TEMP16, K41, DB42
        v_xor_b32 TEMP02, K52, DB43
        v_xor_b32 TEMP04, K13, DB44
        v_xor_b32 TEMP03, K12, DB43
        v_xor_b32 TEMP06, K20, DB44
        v_xor_b32 TEMP19, K45, DB45
        v_xor_b32 TEMP26, K39, DB46
        v_xor_b32 TEMP22, K33, DB47
        v_xor_b32 TEMP07, K55, DB48
        s_swappc_b64 s[40:41], s[52:53]

        v_xor_b32 TEMP03, K29, DB_EF72
        v_xor_b32 TEMP18, K09, DB_EF73
        v_xor_b32 TEMP21, K42, DB_EF74
        v_xor_b32 TEMP22, K00, DB_EF75
        v_xor_b32 TEMP04, K44, DB_EF76
        v_xor_b32 TEMP07, K17, DB_EF77
        v_xor_b32 TEMP23, K49, DB_EF78
        v_xor_b32 TEMP06, K36, DB_EF79
        v_xor_b32 TEMP10, K16, DB_EF80
        v_xor_b32 TEMP19, K01, DB_EF81
        v_xor_b32 TEMP02, K28, DB_EF82
        v_xor_b32 TEMP25, K37, DB_EF83
        s_swappc_b64 s[40:41], s[54:55]

        v_xor_b32 TEMP06, K08, DB55
        v_xor_b32 TEMP18, K30, DB56
        v_xor_b32 TEMP27, K43, DB57
        v_xor_b32 TEMP00, K10, DB58
        v_xor_b32 TEMP12, K21, DB59
        v_xor_b32 TEMP07, K02, DB60
        v_xor_b32 TEMP03, K51, DB59
        v_xor_b32 TEMP01, K22, DB60
        v_xor_b32 TEMP14, K23, DB61
        v_xor_b32 TEMP13, K07, DB62
        v_xor_b32 TEMP02, K03, DB63
        v_xor_b32 TEMP04, K35, DB32
        s_swappc_b64 s[40:41], s[56:57]

		/********/
		/* A 15 */
		/********/

        v_xor_b32 TEMP15, K19, DB_EF00
        v_xor_b32 TEMP16, K53, DB_EF01
        v_xor_b32 TEMP17, K40, DB_EF02
        v_xor_b32 TEMP18, K04, DB_EF03
        v_xor_b32 TEMP19, K55, DB_EF04
        v_xor_b32 TEMP20, K27, DB_EF05
        v_xor_b32 TEMP21, K41, DB_EF06
        v_xor_b32 TEMP22, K31, DB_EF07
        v_xor_b32 TEMP23, K12, DB_EF08
        v_xor_b32 TEMP24, K20, DB_EF09
        v_xor_b32 TEMP25, K25, DB_EF10
        v_xor_b32 TEMP26, K47, DB_EF11
        s_swappc_b64 s[40:41], s[42:43]

        v_xor_b32 TEMP26, K11, DB07
        v_xor_b32 TEMP20, K39, DB08
        v_xor_b32 TEMP18, K33, DB09
        v_xor_b32 TEMP14, K34, DB10
        v_xor_b32 TEMP16, K45, DB11
        v_xor_b32 TEMP25, K06, DB12
        v_xor_b32 TEMP19, K05, DB11
        v_xor_b32 TEMP22, K13, DB12
        v_xor_b32 TEMP13, K38, DB13
        v_xor_b32 TEMP23, K32, DB14
        v_xor_b32 TEMP24, K26, DB15
        v_xor_b32 TEMP12, K48, DB16
        s_swappc_b64 s[40:41], s[44:45]

        v_xor_b32 TEMP16, K22, DB_EF24
        v_xor_b32 TEMP09, K02, DB_EF25
        v_xor_b32 TEMP18, K35, DB_EF26
        v_xor_b32 TEMP21, K50, DB_EF27
        v_xor_b32 TEMP22, K37, DB_EF28
        v_xor_b32 TEMP23, K10, DB_EF29
        v_xor_b32 TEMP11, K42, DB_EF30
        v_xor_b32 TEMP14, K29, DB_EF31
        v_xor_b32 TEMP10, K09, DB_EF32
        v_xor_b32 TEMP24, K51, DB_EF33
        v_xor_b32 TEMP20, K21, DB_EF34
        v_xor_b32 TEMP25, K30, DB_EF35
        s_swappc_b64 s[40:41], s[46:47]

        v_xor_b32 TEMP16, K01, DB23
        v_xor_b32 TEMP18, K23, DB24
        v_xor_b32 TEMP21, K36, DB25
        v_xor_b32 TEMP24, K03, DB26
        v_xor_b32 TEMP26, K14, DB27
        v_xor_b32 TEMP23, K24, DB28
        v_xor_b32 TEMP19, K44, DB27
        v_xor_b32 TEMP12, K15, DB28
        v_xor_b32 TEMP25, K16, DB29
        v_xor_b32 TEMP22, K00, DB30
        v_xor_b32 TEMP11, K49, DB31
        v_xor_b32 TEMP20, K28, DB00
        s_swappc_b64 s[40:41], s[48:49]

        s_add_u32 s39, -1, s39
		s_branch  .startLoop

.quitLoop:



		/************/
		/* MATCHING */
		/************/

.ifarch gcn1.0
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.elseifarch gcn1.1
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.else
        s_load_dwordx4  s[16:19], s[2:3], 0x1c0
        s_load_dwordx4  s[20:23], s[2:3], 0x1e0
        s_load_dwordx4  s[24:27], s[2:3], 0x1a0
.endif
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[28:29], exec
        v_mov_b32       v1, 0
.L13452_0:
        v_cmp_lt_i32    vcc, 31, v1
        s_and_saveexec_b64 s[30:31], vcc
        v_mov_b32       v2, 0
        s_cbranch_execz .L13476_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L14540_0
.L13476_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_lshlrev_b32   v2, v1, 1
        v_and_b32       v3, v22, v2
        v_cmp_lg_i32    vcc, 0, v3
        v_mov_b32       v3, 0x20000000
        v_cndmask_b32   v3, 0, v3, vcc
        v_and_b32       v4, v54, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x10000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v47, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x8000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v120, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x4000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v39, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x2000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v122, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x1000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v31, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x800000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v79, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x400000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v23, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x200000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v55, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x100000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v48, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x80000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v121, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x40000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_lshrrev_b32   v4, 18, v3
        v_add_u32       v4, vcc, s14, v4
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v4, v4, s[16:19], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_lg_i32    vcc, 0, v4
        s_mov_b64       s[30:31], exec
        s_andn2_b64     exec, s[30:31], vcc
        v_and_b32       v4, v40, v2
        s_cbranch_execz .L14512_0
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x20000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v66, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x10000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v32, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x8000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v74, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x4000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v24, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x2000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v56, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x1000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v49, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x800
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v64, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x400
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v41, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x200
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v71, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x100
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v33, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x80
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v77, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 64, vcc
        v_or_b32        v3, v3, v4
        v_lshrrev_b32   v4, 6, v3
        v_add_u32       v4, vcc, s8, v4
        buffer_load_ubyte v4, v4, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v4
        s_and_saveexec_b64 s[32:33], vcc
        s_cbranch_execz .L14492_0
        s_buffer_load_dword s1, s[24:27], s12
        v_and_b32       v4, v25, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 32, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v117, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 16, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v50, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 8, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v62, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v42, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 2, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v2, v69, v2
        v_cmp_lg_i32    vcc, 0, v2
        v_cndmask_b32   v2, 0, 1, vcc
        v_or_b32        v2, v3, v2
        s_mov_b64       s[34:35], exec
        s_mov_b64       s[36:37], exec
        v_mov_b32       v3, 0
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v9, s1
        v_mov_b32       v4, s13
        v_mov_b32       v10, 0
.L14284_0:
        v_add_u32       v7, vcc, -1, v4
        s_mov_b64       s[38:39], exec
        s_mov_b64       s[40:41], exec
        v_mov_b32       v8, v10
.L14300_0:
        v_cmp_gt_i32    vcc, v10, v7
        v_cmp_eq_i32    s[42:43], v2, v9
        s_or_b64        vcc, vcc, s[42:43]
        s_and_saveexec_b64 s[44:45], vcc
        v_cndmask_b32   v9, 0, -1, s[42:43]
        s_cbranch_execz .L14348_0
        v_mov_b32       v3, 1
        v_mov_b32       v10, v8
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L14428_0
.L14348_0:
        s_and_b64       exec, s[44:45], s[40:41]
        v_add_u32       v4, vcc, v7, v10
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v6, 2, v4
        v_add_u32       v6, vcc, s12, v6
        v_add_u32       v8, vcc, 1, v4
        buffer_load_dword v9, v6, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_gt_u32    vcc, v2, v9
        s_mov_b64       s[42:43], exec
        s_andn2_b64     exec, s[42:43], vcc
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L14428_0
        s_mov_b64       exec, s[40:41]
        v_mov_b32       v123, v8
        v_mov_b32       v8, v10
        v_mov_b32       v10, v123
        s_branch        .L14300_0
        v_mov_b32       v10, v8
.L14428_0:
        s_mov_b64       exec, s[38:39]
        v_cmp_lg_u32    vcc, 0, v3
        s_and_saveexec_b64 s[38:39], vcc
        s_andn2_b64     s[36:37], s[36:37], exec
        s_cbranch_scc0  .L14456_0
        s_mov_b64       exec, s[36:37]
        s_branch        .L14284_0
.L14456_0:
        s_mov_b64       exec, s[34:35]
        v_cmp_lg_u32    vcc, 0, v9
        s_and_saveexec_b64 s[34:35], vcc
        v_mov_b32       v2, 1
        s_cbranch_execz .L14484_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L14540_0
.L14484_0:
        s_and_b64       exec, s[34:35], s[28:29]
        v_mov_b32       v2, 1
.L14492_0:
        s_andn2_b64     exec, s[32:33], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v2, 0
        s_cbranch_execz .L14508_0
.L14508_0:
        s_and_b64       exec, s[32:33], s[28:29]
.L14512_0:
        s_andn2_b64     exec, s[30:31], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v2, 0
        s_cbranch_execz .L14528_0
.L14528_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_add_u32       v1, vcc, 1, v1
        s_branch        .L13452_0
.L14540_0:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v2
        v_cndmask_b32   v2, 0, 1, vcc
        v_mov_b32       v4, 2
        s_branch        .L18744_0
.L14564_0:
        s_cmp_eq_i32    s0, 3
        s_cbranch_scc0  .L17576_0
        s_add_u32       s1, -1, s13
.ifarch gcn1.0
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.elseifarch gcn1.1
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.else
        s_load_dwordx4  s[16:19], s[2:3], 0x1c0
        s_load_dwordx4  s[20:23], s[2:3], 0x1e0
        s_load_dwordx4  s[24:27], s[2:3], 0x1a0
.endif
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[28:29], exec
        v_mov_b32       v1, 0
        v_mov_b32       v9, v2
        v_mov_b32       v17, 0
        v_mov_b32       v18, 0
        v_mov_b32       v5, 0
        v_mov_b32       v6, 0
        v_mov_b32       v7, 0
        v_mov_b32       v8, 0
        v_mov_b32       v10, 0
.L14644_0:
        v_add_f32       v11, v8, v10
        v_add_f32       v11, v7, v11
        v_add_f32       v11, v6, v11
        v_add_f32       v11, v5, v11
        v_add_f32       v11, v18, v11
        v_add_f32       v11, v17, v11
        v_cmp_eq_u32    vcc, 0, v11
        s_and_saveexec_b64 s[30:31], vcc
        s_andn2_b64     exec, s[30:31], exec
        s_cbranch_execz .L14692_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L17556_0
.L14692_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_cmp_ge_i32    vcc, 31, v1
        v_cndmask_b32   v17, 1.0, v17, vcc
        v_cmp_eq_u32    vcc, 0, v17
        s_and_saveexec_b64 s[30:31], vcc
        v_lshlrev_b32   v3, v1, 1
        s_cbranch_execz .L17536_0
        v_and_b32       v4, v22, v3
        v_and_b32       v11, v54, v3
        v_cmp_lg_i32    s[32:33], v4, 0
        v_mov_b32       v4, 0x20000000
        v_cmp_lg_i32    vcc, 0, v11
        v_mov_b32       v11, 0x10000000
        v_and_b32       v12, v47, v3
        v_cndmask_b32   v4, 0, v4, s[32:33]
        v_cndmask_b32   v11, 0, v11, vcc
        v_cmp_lg_i32    vcc, 0, v12
        v_mov_b32       v12, 0x8000000
        v_and_b32       v13, v120, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x4000000
        v_and_b32       v13, v39, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x2000000
        v_and_b32       v13, v122, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x1000000
        v_and_b32       v13, v31, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x800000
        v_and_b32       v13, v79, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x400000
        v_and_b32       v13, v23, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x200000
        v_and_b32       v13, v55, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x100000
        v_and_b32       v13, v48, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x80000
        v_and_b32       v13, v121, v3
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v12, 0x40000
        v_or_b32        v4, v4, v11
        v_cndmask_b32   v11, 0, v12, vcc
        v_or_b32        v4, v4, v11
        v_lshrrev_b32   v11, 18, v4
        v_add_u32       v11, vcc, s14, v11
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v11, v11, s[16:19], 0 offen
        v_and_b32       v12, v40, v3
        v_cmp_lg_i32    vcc, 0, v12
        v_mov_b32       v12, 0x20000
        v_and_b32       v13, v66, v3
        v_cndmask_b32   v12, 0, v12, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_mov_b32       v13, 0x10000
        v_and_b32       v14, v32, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x8000
        v_and_b32       v14, v74, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x4000
        v_and_b32       v14, v24, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x2000
        v_and_b32       v14, v56, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x1000
        v_and_b32       v14, v49, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x800
        v_and_b32       v14, v64, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x400
        v_and_b32       v14, v41, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x200
        v_and_b32       v14, v71, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x100
        v_and_b32       v14, v33, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_mov_b32       v13, 0x80
        v_and_b32       v14, v77, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, v13, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v13, v25, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, 64, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_and_b32       v13, v117, v3
        v_or_b32        v4, v4, v12
        v_cndmask_b32   v12, 0, 32, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_and_b32       v13, v50, v3
        v_or_b32        v12, v4, v12
        v_cndmask_b32   v14, 0, 16, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_and_b32       v13, v62, v3
        v_or_b32        v12, v12, v14
        v_cndmask_b32   v14, 0, 8, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_and_b32       v13, v42, v3
        v_or_b32        v12, v12, v14
        v_cndmask_b32   v14, 0, 4, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_and_b32       v13, v69, v3
        v_or_b32        v12, v12, v14
        v_cndmask_b32   v14, 0, 2, vcc
        v_cmp_lg_i32    vcc, 0, v13
        v_or_b32        v12, v12, v14
        v_cndmask_b32   v13, 0, 1, vcc
        v_or_b32        v12, v12, v13
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v11
        s_and_saveexec_b64 s[32:33], vcc
        v_lshrrev_b32   v4, 6, v4
        s_cbranch_execz .L15720_0
        v_add_u32       v4, vcc, s8, v4
        buffer_load_ubyte v4, v4, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v4
        s_and_saveexec_b64 s[34:35], vcc
        s_cbranch_execz .L15708_0
        s_buffer_load_dword s9, s[24:27], s12
        s_mov_b64       s[36:37], exec
        s_mov_b64       s[38:39], exec
        v_mov_b32       v4, 0
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v9, s9
        v_mov_b32       v2, 0
        v_mov_b32       v11, s13
.L15524_0:
        v_add_u32       v15, vcc, -1, v11
        s_mov_b64       s[40:41], exec
        s_mov_b64       s[42:43], exec
        v_mov_b32       v14, v2
.L15540_0:
        v_cmp_gt_i32    vcc, v2, v15
        v_cmp_eq_i32    s[44:45], v12, v9
        s_or_b64        vcc, vcc, s[44:45]
        s_and_saveexec_b64 s[46:47], vcc
        v_cndmask_b32   v9, 0, -1, s[44:45]
        s_cbranch_execz .L15588_0
        v_mov_b32       v4, 1
        v_mov_b32       v2, v14
        s_andn2_b64     s[42:43], s[42:43], exec
        s_cbranch_scc0  .L15664_0
.L15588_0:
        s_and_b64       exec, s[46:47], s[42:43]
        v_add_u32       v13, vcc, v15, v2
        v_ashrrev_i32   v11, 1, v13
        v_lshlrev_b32   v14, 2, v11
        v_add_u32       v14, vcc, s12, v14
        v_add_u32       v16, vcc, 1, v11
        buffer_load_dword v9, v14, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_gt_u32    vcc, v12, v9
        s_mov_b64       s[44:45], exec
        s_andn2_b64     exec, s[44:45], vcc
        s_andn2_b64     s[42:43], s[42:43], exec
        s_cbranch_scc0  .L15664_0
        s_mov_b64       exec, s[42:43]
        v_mov_b32       v14, v2
        v_mov_b32       v2, v16
        s_branch        .L15540_0
        v_mov_b32       v2, v14
.L15664_0:
        s_mov_b64       exec, s[40:41]
        v_cmp_lg_u32    vcc, 0, v4
        s_and_saveexec_b64 s[40:41], vcc
        s_andn2_b64     s[38:39], s[38:39], exec
        s_cbranch_scc0  .L15692_0
        s_mov_b64       exec, s[38:39]
        s_branch        .L15524_0
.L15692_0:
        s_mov_b64       exec, s[36:37]
        v_cmp_eq_u32    vcc, 0, v9
        v_cndmask_b32   v18, 1.0, v18, vcc
        v_mov_b32       v9, 1
.L15708_0:
        s_andn2_b64     exec, s[34:35], exec
        v_mov_b32       v9, 0
        s_mov_b64       exec, s[34:35]
.L15720_0:
        s_andn2_b64     exec, s[32:33], exec
        v_mov_b32       v9, 0
        s_mov_b64       exec, s[32:33]
        v_cmp_eq_u32    vcc, 0, v18
        s_and_b64       exec, s[32:33], vcc
        v_lshlrev_b32   v11, 6, v12
        s_cbranch_execz .L17532_0
        v_and_b32       v11, 0x3fffffc0, v11
        v_lshrrev_b32   v13, 18, v11
        v_add_u32       v13, vcc, s14, v13
        buffer_load_ubyte v13, v13, s[16:19], 0 offen
        v_and_b32       v14, v34, v3
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v80, v3
        v_cndmask_b32   v15, 0, 32, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v26, v3
        v_or_b32        v11, v15, v11
        v_cndmask_b32   v15, 0, 16, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v58, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 8, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v51, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 4, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v68, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 2, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v14, 0, 1, vcc
        v_or_b32        v11, v11, v14
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v13
        s_and_saveexec_b64 s[34:35], vcc
        v_bfe_u32       v12, v12, 0, 24
        s_cbranch_execz .L16092_0
        v_add_u32       v12, vcc, s8, v12
        buffer_load_ubyte v12, v12, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v12
        s_and_saveexec_b64 s[36:37], vcc
        s_cbranch_execz .L16092_0
        s_buffer_load_dword s9, s[24:27], s12
        s_mov_b64       s[38:39], exec
        s_mov_b64       s[40:41], exec
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v2, s9
        v_mov_b32       v12, s1
        v_mov_b32       v13, 0
        s_movk_i32      s42, 0x0
        s_movk_i32      s43, 0x0
.L15984_0:
        v_cmp_gt_i32    s[44:45], v13, v12
        v_cmp_eq_i32    vcc, v11, v2
        s_andn2_b64     s[42:43], s[42:43], exec
        s_or_b64        s[42:43], vcc, s[42:43]
        s_or_b64        vcc, s[44:45], vcc
        s_and_saveexec_b64 s[44:45], vcc
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L16076_0
        s_mov_b64       exec, s[40:41]
        v_add_u32       v4, vcc, v12, v13
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v14, 2, v4
        v_add_u32       v14, vcc, s12, v14
        v_add_u32       v15, vcc, -1, v4
        v_add_u32       v4, vcc, 1, v4
        buffer_load_dword v2, v14, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    vcc, v2, v11
        v_cndmask_b32   v13, v4, v13, vcc
        v_cndmask_b32   v12, v12, v15, vcc
        s_branch        .L15984_0
.L16076_0:
        s_mov_b64       exec, s[38:39]
        v_cndmask_b32   v5, v5, 1.0, s[42:43]
        v_mov_b32       v9, 1
.L16092_0:
        s_mov_b64       exec, s[34:35]
        v_cmp_eq_u32    vcc, 0, v5
        s_and_b64       exec, s[34:35], vcc
        v_lshlrev_b32   v12, 6, v11
        s_cbranch_execz .L17532_0
        v_and_b32       v12, 0x3fffffc0, v12
        v_lshrrev_b32   v13, 18, v12
        v_add_u32       v13, vcc, s14, v13
        buffer_load_ubyte v13, v13, s[16:19], 0 offen
        v_and_b32       v14, v43, v3
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v72, v3
        v_cndmask_b32   v15, 0, 32, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v35, v3
        v_or_b32        v12, v15, v12
        v_cndmask_b32   v15, 0, 16, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v78, v3
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 8, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v3, v27
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 4, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v59, v3
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 2, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v14, 0, 1, vcc
        v_or_b32        v12, v12, v14
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v13
        s_and_saveexec_b64 s[36:37], vcc
        v_bfe_u32       v11, v11, 0, 24
        s_cbranch_execz .L16456_0
        v_add_u32       v11, vcc, s8, v11
        buffer_load_ubyte v11, v11, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v11
        s_and_saveexec_b64 s[38:39], vcc
        s_cbranch_execz .L16456_0
        s_buffer_load_dword s9, s[24:27], s12
        s_mov_b64       s[40:41], exec
        s_mov_b64       s[42:43], exec
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v2, s9
        v_mov_b32       v11, s1
        v_mov_b32       v13, 0
        s_movk_i32      s44, 0x0
        s_movk_i32      s45, 0x0
.L16348_0:
        v_cmp_gt_i32    s[46:47], v13, v11
        v_cmp_eq_i32    vcc, v12, v2
        s_andn2_b64     s[44:45], s[44:45], exec
        s_or_b64        s[44:45], vcc, s[44:45]
        s_or_b64        vcc, s[46:47], vcc
        s_and_saveexec_b64 s[46:47], vcc
        s_andn2_b64     s[42:43], s[42:43], exec
        s_cbranch_scc0  .L16440_0
        s_mov_b64       exec, s[42:43]
        v_add_u32       v4, vcc, v11, v13
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v14, 2, v4
        v_add_u32       v14, vcc, s12, v14
        v_add_u32       v15, vcc, -1, v4
        v_add_u32       v4, vcc, 1, v4
        buffer_load_dword v2, v14, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    vcc, v2, v12
        v_cndmask_b32   v13, v4, v13, vcc
        v_cndmask_b32   v11, v11, v15, vcc
        s_branch        .L16348_0
.L16440_0:
        s_mov_b64       exec, s[40:41]
        v_cndmask_b32   v6, v6, 1.0, s[44:45]
        v_mov_b32       v9, 1
.L16456_0:
        s_mov_b64       exec, s[36:37]
        v_cmp_eq_u32    vcc, 0, v6
        s_and_b64       exec, s[36:37], vcc
        v_lshlrev_b32   v11, 6, v12
        s_cbranch_execz .L17532_0
        v_and_b32       v11, 0x3fffffc0, v11
        v_lshrrev_b32   v13, 18, v11
        v_add_u32       v13, vcc, s14, v13
        buffer_load_ubyte v13, v13, s[16:19], 0 offen
        v_and_b32       v14, v52, v3
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v65, v3
        v_cndmask_b32   v15, 0, 32, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v44, v3
        v_or_b32        v11, v15, v11
        v_cndmask_b32   v15, 0, 16, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v70, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 8, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v36, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 4, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v73, v3
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v15, 0, 2, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_or_b32        v11, v11, v15
        v_cndmask_b32   v14, 0, 1, vcc
        v_or_b32        v11, v11, v14
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v13
        s_and_saveexec_b64 s[38:39], vcc
        v_bfe_u32       v12, v12, 0, 24
        s_cbranch_execz .L16820_0
        v_add_u32       v12, vcc, s8, v12
        buffer_load_ubyte v12, v12, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v12
        s_and_saveexec_b64 s[40:41], vcc
        s_cbranch_execz .L16820_0
        s_buffer_load_dword s9, s[24:27], s12
        s_mov_b64       s[42:43], exec
        s_mov_b64       s[44:45], exec
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v2, s9
        v_mov_b32       v12, s1
        v_mov_b32       v13, 0
        s_movk_i32      s46, 0x0
        s_movk_i32      s47, 0x0
.L16712_0:
        v_cmp_gt_i32    s[48:49], v13, v12
        v_cmp_eq_i32    vcc, v11, v2
        s_andn2_b64     s[46:47], s[46:47], exec
        s_or_b64        s[46:47], vcc, s[46:47]
        s_or_b64        vcc, s[48:49], vcc
        s_and_saveexec_b64 s[48:49], vcc
        s_andn2_b64     s[44:45], s[44:45], exec
        s_cbranch_scc0  .L16804_0
        s_mov_b64       exec, s[44:45]
        v_add_u32       v4, vcc, v12, v13
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v14, 2, v4
        v_add_u32       v14, vcc, s12, v14
        v_add_u32       v15, vcc, -1, v4
        v_add_u32       v4, vcc, 1, v4
        buffer_load_dword v2, v14, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    vcc, v2, v11
        v_cndmask_b32   v13, v4, v13, vcc
        v_cndmask_b32   v12, v12, v15, vcc
        s_branch        .L16712_0
.L16804_0:
        s_mov_b64       exec, s[42:43]
        v_cndmask_b32   v7, v7, 1.0, s[46:47]
        v_mov_b32       v9, 1
.L16820_0:
        s_mov_b64       exec, s[38:39]
        v_cmp_eq_u32    vcc, 0, v7
        s_and_b64       exec, s[38:39], vcc
        v_lshlrev_b32   v12, 6, v11
        s_cbranch_execz .L17532_0
        v_and_b32       v12, 0x3fffffc0, v12
        v_lshrrev_b32   v13, 18, v12
        v_add_u32       v13, vcc, s14, v13
        buffer_load_ubyte v13, v13, s[16:19], 0 offen
        v_and_b32       v14, v28, v3
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v85, v3
        v_cndmask_b32   v15, 0, 32, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v53, v3
        v_or_b32        v12, v15, v12
        v_cndmask_b32   v15, 0, 16, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v118, v3
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 8, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v45, v3
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 4, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_and_b32       v14, v57, v3
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v15, 0, 2, vcc
        v_cmp_lg_i32    vcc, 0, v14
        v_or_b32        v12, v12, v15
        v_cndmask_b32   v14, 0, 1, vcc
        v_or_b32        v12, v12, v14
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v13
        s_and_saveexec_b64 s[40:41], vcc
        v_bfe_u32       v11, v11, 0, 24
        s_cbranch_execz .L17184_0
        v_add_u32       v11, vcc, s8, v11
        buffer_load_ubyte v11, v11, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v11
        s_and_saveexec_b64 s[42:43], vcc
        s_cbranch_execz .L17184_0
        s_buffer_load_dword s9, s[24:27], s12
        s_mov_b64       s[44:45], exec
        s_mov_b64       s[46:47], exec
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v2, s9
        v_mov_b32       v11, s1
        v_mov_b32       v13, 0
        s_movk_i32      s48, 0x0
        s_movk_i32      s49, 0x0
.L17076_0:
        v_cmp_gt_i32    s[50:51], v13, v11
        v_cmp_eq_i32    vcc, v12, v2
        s_andn2_b64     s[48:49], s[48:49], exec
        s_or_b64        s[48:49], vcc, s[48:49]
        s_or_b64        vcc, s[50:51], vcc
        s_and_saveexec_b64 s[50:51], vcc
        s_andn2_b64     s[46:47], s[46:47], exec
        s_cbranch_scc0  .L17168_0
        s_mov_b64       exec, s[46:47]
        v_add_u32       v4, vcc, v11, v13
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v14, 2, v4
        v_add_u32       v14, vcc, s12, v14
        v_add_u32       v15, vcc, -1, v4
        v_add_u32       v4, vcc, 1, v4
        buffer_load_dword v2, v14, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    vcc, v2, v12
        v_cndmask_b32   v13, v4, v13, vcc
        v_cndmask_b32   v11, v11, v15, vcc
        s_branch        .L17076_0
.L17168_0:
        s_mov_b64       exec, s[44:45]
        v_cndmask_b32   v8, v8, 1.0, s[48:49]
        v_mov_b32       v9, 1
.L17184_0:
        s_mov_b64       exec, s[40:41]
        v_cmp_eq_u32    vcc, 0, v8
        s_and_b64       exec, s[40:41], vcc
        v_lshlrev_b32   v11, 6, v12
        s_cbranch_execz .L17532_0
        v_and_b32       v11, 0x3fffffc0, v11
        v_lshrrev_b32   v13, 18, v11
        v_add_u32       v13, vcc, s14, v13
        buffer_load_ubyte v13, v13, s[16:19], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v13
        s_and_saveexec_b64 s[42:43], vcc
        v_bfe_u32       v12, v12, 0, 24
        s_cbranch_execz .L17516_0
        v_add_u32       v12, vcc, s8, v12
        buffer_load_ubyte v12, v12, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v12
        s_and_saveexec_b64 s[44:45], vcc
        s_cbranch_execz .L17516_0
        s_buffer_load_dword s9, s[24:27], s12
        v_and_b32       v4, v37, v3
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 32, vcc
        v_or_b32        v4, v11, v4
        v_and_b32       v11, v63, v3
        v_cmp_lg_i32    vcc, 0, v11
        v_cndmask_b32   v11, 0, 16, vcc
        v_or_b32        v4, v4, v11
        v_and_b32       v11, v29, v3
        v_cmp_lg_i32    vcc, 0, v11
        v_cndmask_b32   v11, 0, 8, vcc
        v_or_b32        v4, v4, v11
        v_and_b32       v3, v61, v3
        v_cmp_lg_i32    vcc, 0, v3
        v_cndmask_b32   v3, 0, 4, vcc
        v_or_b32        v3, v4, v3
        s_mov_b64       s[46:47], exec
        s_mov_b64       s[48:49], exec
        v_mov_b32       v4, s1
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v2, s9
        v_mov_b32       v12, 0
        s_movk_i32      s50, 0x0
        s_movk_i32      s51, 0x0
        s_nop           0x0
        s_nop           0x0
.L17408_0:
        v_cmp_gt_i32    s[52:53], v12, v4
        v_cmp_eq_i32    vcc, v3, v2
        s_andn2_b64     s[50:51], s[50:51], exec
        s_or_b64        s[50:51], vcc, s[50:51]
        s_or_b64        vcc, s[52:53], vcc
        s_and_saveexec_b64 s[52:53], vcc
        s_andn2_b64     s[48:49], s[48:49], exec
        s_cbranch_scc0  .L17500_0
        s_mov_b64       exec, s[48:49]
        v_add_u32       v11, vcc, v4, v12
        v_ashrrev_i32   v11, 1, v11
        v_lshlrev_b32   v13, 2, v11
        v_add_u32       v13, vcc, s12, v13
        v_add_u32       v14, vcc, -1, v11
        v_add_u32       v11, vcc, 1, v11
        buffer_load_dword v2, v13, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    vcc, v2, v3
        v_cndmask_b32   v12, v11, v12, vcc
        v_cndmask_b32   v4, v4, v14, vcc
        s_branch        .L17408_0
.L17500_0:
        s_mov_b64       exec, s[46:47]
        v_cndmask_b32   v10, v10, 1.0, s[50:51]
        v_mov_b32       v9, 1
.L17516_0:
        s_mov_b64       exec, s[42:43]
        v_cmp_eq_u32    vcc, 0, v10
        v_addc_u32      v1, vcc, v1, 0, vcc
.L17532_0:
        s_mov_b64       exec, s[32:33]
.L17536_0:
        s_andn2_b64     exec, s[30:31], exec
        v_mov_b32       v9, 0
        s_mov_b64       exec, s[30:31]
        v_mov_b32       v2, 2
        s_branch        .L14644_0
.L17556_0:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v9
        v_cndmask_b32   v2, 0, v2, vcc
        v_mov_b32       v4, 2
        s_branch        .L18744_0
.L17576_0:
        s_cmp_eq_i32    s0, 2
        s_cbranch_scc1  .L17596_0
        v_mov_b32       v1, 12
        v_mov_b32       v4, 1
        s_branch        .L18744_0
.L17596_0:
.ifarch gcn1.0
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.elseifarch gcn1.1
        s_load_dwordx4  s[16:19], s[2:3], 0x70
        s_load_dwordx4  s[20:23], s[2:3], 0x78
        s_load_dwordx4  s[24:27], s[2:3], 0x68
.else
        s_load_dwordx4  s[16:19], s[2:3], 0x1c0
        s_load_dwordx4  s[20:23], s[2:3], 0x1e0
        s_load_dwordx4  s[24:27], s[2:3], 0x1a0
.endif
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[28:29], exec
        v_mov_b32       v1, 0
        v_mov_b32       v3, v2
.L17636_0:
        v_cmp_lt_i32    vcc, 31, v1
        s_and_saveexec_b64 s[30:31], vcc
        v_mov_b32       v3, 0
        s_cbranch_execz .L17660_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L18724_0
.L17660_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_lshlrev_b32   v3, v1, 1
        v_and_b32       v4, v22, v3
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x20000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_and_b32       v5, v54, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x10000000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v47, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x8000000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v120, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x4000000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v39, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x2000000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v122, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x1000000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v31, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x800000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v79, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x400000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v23, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x200000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v55, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x100000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v48, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x80000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v121, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x40000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_lshrrev_b32   v5, 18, v4
        v_add_u32       v5, vcc, s14, v5
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v5, v5, s[16:19], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_lg_i32    vcc, 0, v5
        s_mov_b64       s[30:31], exec
        s_andn2_b64     exec, s[30:31], vcc
        v_and_b32       v5, v40, v3
        s_cbranch_execz .L18696_0
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x20000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v66, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x10000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v32, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x8000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v74, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x4000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v24, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x2000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v56, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x1000
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v49, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x800
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v64, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x400
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v41, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x200
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v71, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x100
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v33, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_mov_b32       v5, 0x80
        v_cndmask_b32   v5, 0, v5, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v77, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 64, vcc
        v_or_b32        v4, v4, v5
        v_lshrrev_b32   v5, 6, v4
        v_add_u32       v5, vcc, s8, v5
        buffer_load_ubyte v5, v5, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v5
        s_and_saveexec_b64 s[32:33], vcc
        s_cbranch_execz .L18676_0
        s_buffer_load_dword s1, s[24:27], s12
        v_and_b32       v5, v25, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 32, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v117, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 16, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v50, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 8, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v62, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 4, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v5, v42, v3
        v_cmp_lg_i32    vcc, 0, v5
        v_cndmask_b32   v5, 0, 2, vcc
        v_or_b32        v4, v4, v5
        v_and_b32       v3, v69, v3
        v_cmp_lg_i32    vcc, 0, v3
        v_cndmask_b32   v3, 0, 1, vcc
        v_or_b32        v3, v4, v3
        s_mov_b64       s[34:35], exec
        s_mov_b64       s[36:37], exec
        v_mov_b32       v4, 0
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v10, s1
        v_mov_b32       v5, s13
        v_mov_b32       v11, 0
.L18468_0:
        v_add_u32       v8, vcc, -1, v5
        s_mov_b64       s[38:39], exec
        s_mov_b64       s[40:41], exec
        v_mov_b32       v9, v11
.L18484_0:
        v_cmp_gt_i32    vcc, v11, v8
        v_cmp_eq_i32    s[42:43], v3, v10
        s_or_b64        vcc, vcc, s[42:43]
        s_and_saveexec_b64 s[44:45], vcc
        v_cndmask_b32   v10, 0, -1, s[42:43]
        s_cbranch_execz .L18532_0
        v_mov_b32       v4, 1
        v_mov_b32       v11, v9
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L18612_0
.L18532_0:
        s_and_b64       exec, s[44:45], s[40:41]
        v_add_u32       v5, vcc, v8, v11
        v_ashrrev_i32   v5, 1, v5
        v_lshlrev_b32   v7, 2, v5
        v_add_u32       v7, vcc, s12, v7
        v_add_u32       v9, vcc, 1, v5
        buffer_load_dword v10, v7, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_gt_u32    vcc, v3, v10
        s_mov_b64       s[42:43], exec
        s_andn2_b64     exec, s[42:43], vcc
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L18612_0
        s_mov_b64       exec, s[40:41]
        v_mov_b32       v123, v9
        v_mov_b32       v9, v11
        v_mov_b32       v11, v123
        s_branch        .L18484_0
        v_mov_b32       v11, v9
.L18612_0:
        s_mov_b64       exec, s[38:39]
        v_cmp_lg_u32    vcc, 0, v4
        s_and_saveexec_b64 s[38:39], vcc
        s_andn2_b64     s[36:37], s[36:37], exec
        s_cbranch_scc0  .L18640_0
        s_mov_b64       exec, s[36:37]
        s_branch        .L18468_0
.L18640_0:
        s_mov_b64       exec, s[34:35]
        v_cmp_lg_u32    vcc, 0, v10
        s_and_saveexec_b64 s[34:35], vcc
        v_mov_b32       v3, 1
        s_cbranch_execz .L18668_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L18724_0
.L18668_0:
        s_and_b64       exec, s[34:35], s[28:29]
        v_mov_b32       v3, 1
.L18676_0:
        s_andn2_b64     exec, s[32:33], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v3, 0
        s_cbranch_execz .L18692_0
.L18692_0:
        s_and_b64       exec, s[32:33], s[28:29]
.L18696_0:
        s_andn2_b64     exec, s[30:31], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v3, 0
        s_cbranch_execz .L18712_0
.L18712_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_add_u32       v1, vcc, 1, v1
        s_branch        .L17636_0
.L18724_0:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v3
        v_cndmask_b32   v2, 0, v2, vcc
        v_cndmask_b32   v4, 0, 1, vcc
.L18744_0:
        v_cmp_lg_i32    vcc, 2, v4
        s_and_saveexec_b64 s[10:11], vcc
        v_cmp_lg_u32    vcc, 0, v4
        s_cbranch_execz .L19904_0
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[16:17], vcc
        s_cbranch_execz .L19904_0
        s_add_u32       s0, -1, s0
        s_cmp_le_u32    s0, 1
        s_cbranch_scc0  .L19900_0
.ifarch gcn1.0
        s_load_dwordx4  s[20:23], s[2:3], 0x70
        s_load_dwordx4  s[24:27], s[2:3], 0x78
        s_load_dwordx4  s[0:3], s[2:3], 0x68
.elseifarch gcn1.1
        s_load_dwordx4  s[20:23], s[2:3], 0x70
        s_load_dwordx4  s[24:27], s[2:3], 0x78
        s_load_dwordx4  s[0:3], s[2:3], 0x68
.else
        s_load_dwordx4  s[20:23], s[2:3], 0x1c0
        s_load_dwordx4  s[24:27], s[2:3], 0x1e0
        s_load_dwordx4  s[0:3], s[2:3], 0x1a0
.endif
        s_mov_b64       s[18:19], exec
        s_mov_b64       s[28:29], exec
        v_mov_b32       v1, 0
.L18820_0:
        v_cmp_gt_i32    s[30:31], v1, 31
        s_and_saveexec_b64 s[30:31], s[30:31]
        v_mov_b32       v4, 0
        s_cbranch_execz .L18848_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L19880_0
.L18848_0:
        s_and_b64       exec, s[30:31], s[28:29]
        v_lshlrev_b32   v2, v1, 1
        v_and_b32       v3, v34, v2
        v_cmp_lg_i32    vcc, 0, v3
        v_mov_b32       v3, 0x20000000
        v_cndmask_b32   v3, 0, v3, vcc
        v_and_b32       v4, v80, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x10000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v26, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x8000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v58, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x4000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v51, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x2000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v68, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x1000000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v43, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x800000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v72, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x400000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v35, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x200000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v78, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x100000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v27, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x80000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v59, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x40000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_lshrrev_b32   v4, 18, v3
        v_add_u32       v4, vcc, s14, v4
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v4, v4, s[20:23], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_lg_i32    vcc, 0, v4
        s_mov_b64       s[30:31], exec
        s_andn2_b64     exec, s[30:31], vcc
        v_and_b32       v4, v52, v2
        s_cbranch_execz .L19852_0
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x20000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v65, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x10000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v44, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x8000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v70, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x4000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v36, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x2000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v73, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x1000
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v28, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x800
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v85, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x400
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v53, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x200
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v118, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x100
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v45, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_mov_b32       v4, 0x80
        v_cndmask_b32   v4, 0, v4, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v57, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 64, vcc
        v_or_b32        v3, v3, v4
        v_lshrrev_b32   v4, 6, v3
        v_add_u32       v4, vcc, s8, v4
        buffer_load_ubyte v4, v4, s[24:27], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v4
        s_and_saveexec_b64 s[32:33], vcc
        s_cbranch_execz .L19832_0
        s_buffer_load_dword s9, s[0:3], s12
        v_and_b32       v4, v37, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 32, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v63, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 16, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v4, v29, v2
        v_cmp_lg_i32    vcc, 0, v4
        v_cndmask_b32   v4, 0, 8, vcc
        v_or_b32        v3, v3, v4
        v_and_b32       v2, v61, v2
        v_cmp_lg_i32    vcc, 0, v2
        v_cndmask_b32   v2, 0, 4, vcc
        v_or_b32        v2, v3, v2
        s_mov_b64       s[34:35], exec
        s_mov_b64       s[36:37], exec
        v_mov_b32       v3, 0
        s_waitcnt       lgkmcnt(0)
        v_mov_b32       v9, s9
        v_mov_b32       v4, s13
        v_mov_b32       v10, 0
.L19616_0:
        v_add_u32       v7, vcc, -1, v4
        s_mov_b64       s[38:39], exec
        s_mov_b64       s[40:41], exec
        v_mov_b32       v8, v10
        s_nop           0x0
        s_nop           0x0
.L19640_0:
        v_cmp_gt_i32    vcc, v10, v7
        v_cmp_eq_i32    s[42:43], v2, v9
        s_or_b64        vcc, vcc, s[42:43]
        s_and_saveexec_b64 s[44:45], vcc
        v_cndmask_b32   v9, 0, -1, s[42:43]
        s_cbranch_execz .L19688_0
        v_mov_b32       v3, 1
        v_mov_b32       v10, v8
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L19768_0
.L19688_0:
        s_and_b64       exec, s[44:45], s[40:41]
        v_add_u32       v4, vcc, v7, v10
        v_ashrrev_i32   v4, 1, v4
        v_lshlrev_b32   v6, 2, v4
        v_add_u32       v6, vcc, s12, v6
        v_add_u32       v8, vcc, 1, v4
        buffer_load_dword v9, v6, s[0:3], 0 offen
        s_waitcnt       vmcnt(0)
        v_cmp_gt_u32    vcc, v2, v9
        s_mov_b64       s[42:43], exec
        s_andn2_b64     exec, s[42:43], vcc
        s_andn2_b64     s[40:41], s[40:41], exec
        s_cbranch_scc0  .L19768_0
        s_mov_b64       exec, s[40:41]
        v_mov_b32       v123, v8
        v_mov_b32       v8, v10
        v_mov_b32       v10, v123
        s_branch        .L19640_0
        v_mov_b32       v10, v8
.L19768_0:
        s_mov_b64       exec, s[38:39]
        v_cmp_lg_u32    vcc, 0, v3
        s_and_saveexec_b64 s[38:39], vcc
        s_andn2_b64     s[36:37], s[36:37], exec
        s_cbranch_scc0  .L19796_0
        s_mov_b64       exec, s[36:37]
        s_branch        .L19616_0
.L19796_0:
        s_mov_b64       exec, s[34:35]
        v_cmp_lg_u32    vcc, 0, v9
        s_and_saveexec_b64 s[34:35], vcc
        v_mov_b32       v4, 1
        s_cbranch_execz .L19824_0
        s_andn2_b64     s[28:29], s[28:29], exec
        s_cbranch_scc0  .L19880_0
.L19824_0:
        s_and_b64       exec, s[34:35], s[28:29]
        v_mov_b32       v4, 1
.L19832_0:
        s_andn2_b64     exec, s[32:33], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v4, 0
        s_cbranch_execz .L19848_0
.L19848_0:
        s_and_b64       exec, s[32:33], s[28:29]
.L19852_0:
        s_andn2_b64     exec, s[30:31], exec
        s_and_b64       exec, exec, s[28:29]
        v_mov_b32       v4, 0
        s_cbranch_execz .L19868_0
.L19868_0:
        s_mov_b64       exec, s[28:29]
        v_add_u32       v1, vcc, 1, v1
        s_branch        .L18820_0
.L19880_0:
        s_mov_b64       exec, s[18:19]
        v_cmp_eq_i32    vcc, 0, v4
        v_cndmask_b32   v2, 0, 2, vcc
        s_branch        .L19904_0
.L19900_0:
        v_mov_b32       v2, 2
.L19904_0:
        s_mov_b64       exec, s[10:11]
        v_cmp_lg_i32    vcc, 2, v2
        s_and_b64       exec, s[10:11], vcc
        v_cmp_eq_u32    vcc, 0, v2
        s_cbranch_execz .L20804_0
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[0:1], vcc
        v_mov_b32       v2, 1
        s_cbranch_execz .L20804_0
        buffer_store_byte v2, v0, s[4:7], 0 offen offset:4 glc
        v_cmp_lg_i32    vcc, 0, v1
        s_and_saveexec_b64 s[2:3], vcc
        v_cmp_lg_i32    vcc, 1, v1
        s_cbranch_execz .L20780_0
        s_and_saveexec_b64 s[8:9], vcc
        v_cmp_lg_i32    vcc, 2, v1
        s_cbranch_execz .L20764_0
        s_and_saveexec_b64 s[12:13], vcc
        v_cmp_lg_i32    vcc, 3, v1
        s_cbranch_execz .L20748_0
        s_and_saveexec_b64 s[14:15], vcc
        v_cmp_lg_i32    vcc, 4, v1
        s_cbranch_execz .L20732_0
        s_and_saveexec_b64 s[16:17], vcc
        v_cmp_lg_i32    vcc, 5, v1
        s_cbranch_execz .L20716_0
        s_and_saveexec_b64 s[18:19], vcc
        v_cmp_lg_i32    vcc, 6, v1
        s_cbranch_execz .L20700_0
        s_and_saveexec_b64 s[20:21], vcc
        v_cmp_lg_i32    vcc, 7, v1
        s_cbranch_execz .L20688_0
        s_and_saveexec_b64 s[22:23], vcc
        v_cmp_lg_i32    vcc, 8, v1
        s_cbranch_execz .L20672_0
        s_and_saveexec_b64 s[24:25], vcc
        v_cmp_lg_i32    vcc, 9, v1
        s_cbranch_execz .L20656_0
        s_and_saveexec_b64 s[26:27], vcc
        v_cmp_lg_i32    vcc, 10, v1
        s_cbranch_execz .L20640_0
        s_and_saveexec_b64 s[28:29], vcc
        v_cmp_lg_i32    vcc, 11, v1
        s_cbranch_execz .L20624_0
        s_and_saveexec_b64 s[30:31], vcc
        v_cmp_lg_i32    vcc, 12, v1
        s_cbranch_execz .L20608_0
        s_and_saveexec_b64 s[32:33], vcc
        v_cmp_lg_i32    vcc, 13, v1
        s_cbranch_execz .L20592_0
        s_and_saveexec_b64 s[34:35], vcc
        v_cmp_lg_i32    vcc, 14, v1
        s_cbranch_execz .L20576_0
        s_and_saveexec_b64 s[36:37], vcc
        v_cmp_lg_i32    vcc, 15, v1
        s_cbranch_execz .L20560_0
        s_and_saveexec_b64 s[38:39], vcc
        v_cmp_lg_i32    vcc, 16, v1
        s_cbranch_execz .L20544_0
        s_and_saveexec_b64 s[40:41], vcc
        v_cmp_lg_i32    vcc, 17, v1
        s_cbranch_execz .L20528_0
        s_and_saveexec_b64 s[42:43], vcc
        v_cmp_lg_i32    vcc, 18, v1
        s_cbranch_execz .L20512_0
        s_and_saveexec_b64 s[44:45], vcc
        v_cmp_lg_i32    vcc, 19, v1
        s_cbranch_execz .L20496_0
        s_and_saveexec_b64 s[46:47], vcc
        v_cmp_lg_i32    vcc, 20, v1
        s_cbranch_execz .L20480_0
        s_and_saveexec_b64 s[48:49], vcc
        v_cmp_lg_i32    vcc, 21, v1
        s_cbranch_execz .L20464_0
        s_and_saveexec_b64 s[50:51], vcc
        v_cmp_lg_i32    vcc, 22, v1
        s_cbranch_execz .L20448_0
        s_and_saveexec_b64 s[52:53], vcc
        v_cmp_lg_i32    vcc, 23, v1
        s_cbranch_execz .L20432_0
        s_and_saveexec_b64 s[54:55], vcc
        v_cmp_lg_i32    vcc, 24, v1
        s_cbranch_execz .L20416_0
        s_and_saveexec_b64 s[56:57], vcc
        v_cmp_lg_i32    vcc, 25, v1
        s_cbranch_execz .L20400_0
        s_and_saveexec_b64 s[58:59], vcc
        v_cmp_lg_i32    vcc, 26, v1
        s_cbranch_execz .L20384_0
        s_and_saveexec_b64 s[60:61], vcc
        v_cmp_eq_i32    s[62:63], v1, 27
        s_cbranch_execz .L20368_0
        v_cmp_eq_i32    s[64:65], v1, 28
        v_cmp_eq_i32    s[66:67], v1, 29
        v_cmp_eq_i32    vcc, 30, v1
        v_mov_b32       v1, KEY7_30
		
		/**/
		s_waitcnt       expcnt(0)
        /**/
		
		v_mov_b32       v2, KEY7_31
        v_cndmask_b32   v1, v2, v1, vcc
        v_mov_b32       v2, KEY7_29
        v_cndmask_b32   v1, v1, v2, s[66:67]
        v_mov_b32       v2, KEY7_28
        v_cndmask_b32   v1, v1, v2, s[64:65]
        v_mov_b32       v2, KEY7_27
        v_cndmask_b32   v1, v1, v2, s[62:63]
.L20368_0:
        s_andn2_b64     exec, s[60:61], exec
        v_mov_b32       v1, KEY7_26
        s_mov_b64       exec, s[60:61]
.L20384_0:
        s_andn2_b64     exec, s[58:59], exec
        v_mov_b32       v1, KEY7_25
        s_mov_b64       exec, s[58:59]
.L20400_0:
        s_andn2_b64     exec, s[56:57], exec
        v_mov_b32       v1, KEY7_24
        s_mov_b64       exec, s[56:57]
.L20416_0:
        s_andn2_b64     exec, s[54:55], exec
        v_mov_b32       v1, KEY7_23
        s_mov_b64       exec, s[54:55]
.L20432_0:
        s_andn2_b64     exec, s[52:53], exec
        v_mov_b32       v1, KEY7_22
        s_mov_b64       exec, s[52:53]
.L20448_0:
        s_andn2_b64     exec, s[50:51], exec
        v_mov_b32       v1, KEY7_21
        s_mov_b64       exec, s[50:51]
.L20464_0:
        s_andn2_b64     exec, s[48:49], exec
        v_mov_b32       v1, KEY7_20
        s_mov_b64       exec, s[48:49]
.L20480_0:
        s_andn2_b64     exec, s[46:47], exec
        v_mov_b32       v1, KEY7_19
        s_mov_b64       exec, s[46:47]
.L20496_0:
        s_andn2_b64     exec, s[44:45], exec
        v_mov_b32       v1, KEY7_18
        s_mov_b64       exec, s[44:45]
.L20512_0:
        s_andn2_b64     exec, s[42:43], exec
        v_mov_b32       v1, KEY7_17
        s_mov_b64       exec, s[42:43]
.L20528_0:
        s_andn2_b64     exec, s[40:41], exec
        v_mov_b32       v1, KEY7_16
        s_mov_b64       exec, s[40:41]
.L20544_0:
        s_andn2_b64     exec, s[38:39], exec
        v_mov_b32       v1, KEY7_15
        s_mov_b64       exec, s[38:39]
.L20560_0:
        s_andn2_b64     exec, s[36:37], exec
        v_mov_b32       v1, KEY7_14
        s_mov_b64       exec, s[36:37]
.L20576_0:
        s_andn2_b64     exec, s[34:35], exec
        v_mov_b32       v1, KEY7_13
        s_mov_b64       exec, s[34:35]
.L20592_0:
        s_andn2_b64     exec, s[32:33], exec
        v_mov_b32       v1, KEY7_12
        s_mov_b64       exec, s[32:33]
.L20608_0:
        s_andn2_b64     exec, s[30:31], exec
        v_mov_b32       v1, KEY7_11
        s_mov_b64       exec, s[30:31]
.L20624_0:
        s_andn2_b64     exec, s[28:29], exec
        v_mov_b32       v1, KEY7_10
        s_mov_b64       exec, s[28:29]
.L20640_0:
        s_andn2_b64     exec, s[26:27], exec
        v_mov_b32       v1, KEY7_09
        s_mov_b64       exec, s[26:27]
.L20656_0:
        s_andn2_b64     exec, s[24:25], exec
        v_mov_b32       v1, KEY7_08
        s_mov_b64       exec, s[24:25]
.L20672_0:
        s_andn2_b64     exec, s[22:23], exec
        v_mov_b32       v1, KEY7_07
        s_mov_b64       exec, s[22:23]
.L20688_0:
        s_andn2_b64     exec, s[20:21], exec
        v_mov_b32       v1, KEY7_06
        s_mov_b64       exec, s[20:21]
.L20700_0:
        s_andn2_b64     exec, s[18:19], exec
        v_mov_b32       v1, KEY7_05
        s_mov_b64       exec, s[18:19]
.L20716_0:
        s_andn2_b64     exec, s[16:17], exec
        v_mov_b32       v1, KEY7_04
        s_mov_b64       exec, s[16:17]
.L20732_0:
        s_andn2_b64     exec, s[14:15], exec
        v_mov_b32       v1, KEY7_03
        s_mov_b64       exec, s[14:15]
.L20748_0:
        s_andn2_b64     exec, s[12:13], exec
        v_mov_b32       v1, KEY7_02
        s_mov_b64       exec, s[12:13]
.L20764_0:
        s_andn2_b64     exec, s[8:9], exec
        v_mov_b32       v1, KEY7_01
        s_mov_b64       exec, s[8:9]
.L20780_0:
        s_andn2_b64     exec, s[2:3], exec
        v_mov_b32       v1, KEY7_00
        s_mov_b64       exec, s[2:3]
        buffer_store_byte v1, v0, s[4:7], 0 offen offset:24 glc
.L20804_0:
        s_mov_b64       exec, s[10:11]

		/**/
        s_waitcnt       expcnt(0)
		/**/

        v_mov_b32       v1, 32
        buffer_store_dword v1, v0, s[4:7], 0 offen
        s_endpgm
