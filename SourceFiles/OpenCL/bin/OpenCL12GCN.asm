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



.globaldata
    .byte 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    .byte 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
    .byte 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58
    .byte 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    .byte 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e
    .byte 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76
    .byte 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33
    .byte 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2e, 0x2f
.kernel OpenCL_SHA1_PerformSearching_ForwardMatching
    .header
        .fill 8, 1, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00
        .byte 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        .fill 8, 1, 0x00
    .metadata
        .ascii ";ARGSTART:__OpenCL_OpenCL_SHA1_PerformSearching_ForwardMatching_kernel\n"
        .ascii ";version:3:1:111\n"
        /* .ascii ";device:hawaii\n" */
        .ascii ";uniqueid:1024\n"
        .ascii ";memory:uavprivate:0\n"
        .ascii ";memory:hwlocal:4416\n"
        .ascii ";memory:hwregion:0\n"
        .ascii ";pointer:outputArray:struct:1:1:0:uav:12:32:RW:0:0\n"
        .ascii ";pointer:key:u8:1:1:16:c:13:1:RO:0:0\n"
        .ascii ";constarg:1:key\n"
        .ascii ";pointer:tripcodeChunkArray:u32:1:1:32:uav:14:4:RO:0:0\n"
        .ascii ";constarg:2:tripcodeChunkArray\n"
        .ascii ";value:numTripcodeChunk:u32:1:1:48\n"
        .ascii ";pointer:keyCharTable_OneByte:u8:1:1:64:c:11:1:RO:0:0\n"
        .ascii ";constarg:4:keyCharTable_OneByte\n"
        .ascii ";pointer:keyCharTable_FirstByte:u8:1:1:80:c:15:1:RO:0:0\n"
        .ascii ";constarg:5:keyCharTable_FirstByte\n"
        .ascii ";pointer:keyCharTable_SecondByte:u8:1:1:96:c:11:1:RO:0:0\n"
        .ascii ";constarg:6:keyCharTable_SecondByte\n"
        .ascii ";pointer:keyCharTable_SecondByteAndOneByte:u8:1:1:112:c:16:1:RO:0:0\n"
        .ascii ";constarg:7:keyCharTable_SecondByteAndOneByte\n"
        .ascii ";pointer:smallChunkBitmap_constant:u8:1:1:128:c:17:1:RO:0:0\n"
        .ascii ";constarg:8:smallChunkBitmap_constant\n"
        .ascii ";pointer:chunkBitmap:u8:1:1:144:uav:18:1:RO:0:0\n"
        .ascii ";constarg:9:chunkBitmap\n"
        .ascii ";memory:datareqd\n"
        .ascii ";function:1:1035\n"
        .ascii ";memory:64bitABI\n"
        .ascii ";uavid:11\n"
        .ascii ";printfid:9\n"
        .ascii ";cbid:10\n"
        .ascii ";privateid:8\n"
        .ascii ";reflection:0:GPUOutput*\n"
        .ascii ";reflection:1:uchar*\n"
        .ascii ";reflection:2:uint*\n"
        .ascii ";reflection:3:uint\n"
        .ascii ";reflection:4:uchar*\n"
        .ascii ";reflection:5:uchar*\n"
        .ascii ";reflection:6:uchar*\n"
        .ascii ";reflection:7:uchar*\n"
        .ascii ";reflection:8:uchar*\n"
        .ascii ";reflection:9:uchar*\n"
        .ascii ";ARGEND:__OpenCL_OpenCL_SHA1_PerformSearching_ForwardMatching_kernel\n"
    .data
        .fill 4736, 1, 0x00
    .inputs
    .outputs
    .uav
        .entry 12, 4, 0, 5
        .entry 14, 4, 0, 5
        .entry 18, 4, 0, 5
        .entry 8, 3, 0, 5
    .condout 0
    .floatconsts
    .intconsts
    .boolconsts
    .earlyexit 0
    .globalbuffers
    .constantbuffers
        .cbmask 0, 2021226542
        .cbmask 1, 151664689
        .cbmask 13, 1954112117
        .cbmask 11, 1633641569
        .cbmask 15, 1596535862
        .cbmask 11, 1667180851
        .cbmask 16, 863117412
        .cbmask 17, 539778911
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
        .entry 0x80001041, 0x0000003f
        .entry 0x80001042, 0x00000038
        .entry 0x80001863, 0x00000066
        .entry 0x80001864, 0x00000100
        .entry 0x80001043, 0x000000c0
        .entry 0x80001044, 0x00000000
        .entry 0x80001045, 0x00000000
        .entry 0x00002e13, 0x00048098
        .entry 0x8000001c, 0x00000100
        .entry 0x8000001d, 0x00000000
        .entry 0x8000001e, 0x00000000
        .entry 0x80001841, 0x00000000
        .entry 0x8000001f, 0x0007f400
        .entry 0x80001843, 0x0007f400
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
        .entry 0x80000082, 0x00000900
    .subconstantbuffers
    .uavmailboxsize 0
    .uavopmask
        .byte 0x00, 0xf4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00
        .fill 120, 1, 0x00
    .text
        s_mov_b32       m0, 0x10000
        s_buffer_load_dwordx2 s[0:1], s[8:11], 0x4
        s_load_dwordx4  s[16:19], s[2:3], 0x68
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 1
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 11
        s_addc_u32      s21, s1, 0
        v_mov_b32       v1, s14
        v_mov_b32       v2, s15
        v_mov_b32       v3, s20
        v_mov_b32       v4, s21
        v_mov_b32       v5, s0
        v_mov_b32       v6, s1
        buffer_load_ubyte v1, v[1:2], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[3:4], s[16:19], 0 addr64
        buffer_load_ubyte v3, v[5:6], s[16:19], 0 addr64
        s_buffer_load_dword s13, s[4:7], 0x4
        s_buffer_load_dword s14, s[4:7], 0x18
        s_buffer_load_dword s15, s[4:7], 0x1c
        s_waitcnt       lgkmcnt(0)
        s_min_u32       s13, s13, 0xffff
        s_mul_i32       s13, s12, s13
        s_buffer_load_dwordx2 s[20:21], s[8:11], 0x0
        s_buffer_load_dwordx2 s[22:23], s[8:11], 0x14
        s_buffer_load_dwordx2 s[24:25], s[8:11], 0x1c
        s_add_u32       s13, s13, s14
        v_add_i32       v4, vcc, s13, v0
        s_add_u32       s12, s12, s15
        v_ashrrev_i32   v5, 31, v4
        s_load_dwordx4  s[28:31], s[2:3], 0x60
        s_load_dwordx4  s[32:35], s[2:3], 0x78
        s_load_dwordx4  s[36:39], s[2:3], 0x80
        s_ashr_i32      s13, s12, 6
        v_and_b32       v6, 63, v0
        s_and_b32       s12, s12, 63
        v_lshl_b64      v[4:5], v[4:5], 5
        s_waitcnt       vmcnt(1)
        v_add_i32       v2, vcc, s13, v2
        v_add_i32       v1, vcc, v1, v6
        s_waitcnt       vmcnt(0)
        v_add_i32       v3, vcc, s12, v3
        s_add_u32       s12, s0, 2
        s_addc_u32      s13, s1, 0
        s_add_u32       s14, s0, 3
        s_addc_u32      s15, s1, 0
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v4, vcc, s20, v4
        v_mov_b32       v6, s21
        v_addc_u32      v5, vcc, v6, v5, vcc
        v_mov_b32       v6, 0
        v_ashrrev_i32   v7, 31, v2
        v_add_i32       v14, vcc, s24, v2
        v_mov_b32       v8, s25
        v_addc_u32      v15, vcc, v8, v7, vcc
        v_ashrrev_i32   v9, 31, v1
        v_add_i32       v7, vcc, s24, v1
        v_addc_u32      v8, vcc, v8, v9, vcc
        v_ashrrev_i32   v9, 31, v3
        v_add_i32       v16, vcc, s22, v3
        v_mov_b32       v10, s23
        v_addc_u32      v17, vcc, v10, v9, vcc
        v_mov_b32       v10, s12
        v_mov_b32       v11, s13
        v_mov_b32       v12, s14
        v_mov_b32       v13, s15
        buffer_load_ubyte v10, v[10:11], s[16:19], 0 addr64
        buffer_load_ubyte v11, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[14:15], s[36:39], 0 addr64
        buffer_load_ubyte v1, v[7:8], s[36:39], 0 addr64
        buffer_load_ubyte v3, v[16:17], s[32:35], 0 addr64
        s_buffer_load_dwordx2 s[4:5], s[4:7], 0x20
        s_buffer_load_dwordx2 s[6:7], s[8:11], 0x8
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dwordx2 s[14:15], s[8:11], 0x20
        s_buffer_load_dwordx2 s[8:9], s[8:11], 0x24
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:4 glc addr64
        v_cmp_eq_i32    vcc, 0, v0
        s_and_saveexec_b64 s[10:11], vcc
        s_cbranch_execz .L892_0
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s14, 7
        s_addc_u32      s15, s15, 0
        s_load_dwordx4  s[40:43], s[2:3], 0x88
        s_mov_b64       s[20:21], exec
        s_mov_b64       s[26:27], exec
        v_mov_b32       v6, 0
        v_mov_b32       v7, 0
.L400_0:
        v_add_i32       v8, vcc, s14, v6
        v_mov_b32       v9, s15
        v_addc_u32      v9, vcc, v9, v7, vcc
        v_add_i32       v12, vcc, v8, -7
        v_addc_u32      v13, vcc, v9, -1, vcc
        v_add_i32       v14, vcc, v8, -6
        v_addc_u32      v15, vcc, v9, -1, vcc
        v_add_i32       v16, vcc, v8, -5
        v_addc_u32      v17, vcc, v9, -1, vcc
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v12, v[12:13], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -4
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v14, v[14:15], s[40:43], 0 addr64
        v_add_i32       v23, vcc, v8, -3
        v_addc_u32      v24, vcc, v9, -1, vcc
        buffer_load_ubyte v16, v[16:17], s[40:43], 0 addr64
        v_add_i32       v19, vcc, v8, -2
        v_addc_u32      v20, vcc, v9, -1, vcc
        buffer_load_ubyte v13, v[21:22], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -1
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v15, v[23:24], s[40:43], 0 addr64
        buffer_load_ubyte v17, v[19:20], s[40:43], 0 addr64
        buffer_load_ubyte v18, v[21:22], s[40:43], 0 addr64
        buffer_load_ubyte v19, v[8:9], s[40:43], 0 addr64
        buffer_load_ubyte v20, v[8:9], s[40:43], 0 offset:1 addr64
        buffer_load_ubyte v21, v[8:9], s[40:43], 0 offset:2 addr64
        buffer_load_ubyte v22, v[8:9], s[40:43], 0 offset:3 addr64
        buffer_load_ubyte v23, v[8:9], s[40:43], 0 offset:4 addr64
        buffer_load_ubyte v24, v[8:9], s[40:43], 0 offset:5 addr64
        buffer_load_ubyte v25, v[8:9], s[40:43], 0 offset:6 addr64
        buffer_load_ubyte v26, v[8:9], s[40:43], 0 offset:7 addr64
        buffer_load_ubyte v8, v[8:9], s[40:43], 0 offset:8 addr64
        ds_write_b8     v6, v12 offset:320
        s_waitcnt       vmcnt(14)
        ds_write_b8     v6, v14 offset:321
        s_waitcnt       vmcnt(13)
        ds_write_b8     v6, v16 offset:322
        s_waitcnt       vmcnt(12)
        ds_write_b8     v6, v13 offset:323
        s_waitcnt       vmcnt(11)
        ds_write_b8     v6, v15 offset:324
        s_waitcnt       vmcnt(10)
        ds_write_b8     v6, v17 offset:325
        s_waitcnt       vmcnt(9)
        ds_write_b8     v6, v18 offset:326
        s_waitcnt       vmcnt(8)
        ds_write_b8     v6, v19 offset:327
        s_waitcnt       vmcnt(7)
        ds_write_b8     v6, v20 offset:328
        s_waitcnt       vmcnt(6)
        ds_write_b8     v6, v21 offset:329
        s_waitcnt       vmcnt(5)
        ds_write_b8     v6, v22 offset:330
        s_waitcnt       vmcnt(4)
        ds_write_b8     v6, v23 offset:331
        s_waitcnt       vmcnt(3)
        ds_write_b8     v6, v24 offset:332
        s_waitcnt       vmcnt(2)
        ds_write_b8     v6, v25 offset:333
        s_waitcnt       vmcnt(1)
        ds_write_b8     v6, v26 offset:334
        v_add_i32       v9, vcc, v6, 16
        v_addc_u32      v7, vcc, v7, 0, vcc
        s_movk_i32      s13, 0x1000
        s_waitcnt       vmcnt(0)
        ds_write_b8     v6, v8 offset:335
        v_cmp_eq_i32    vcc, s13, v9
        s_and_saveexec_b64 s[44:45], vcc
        s_andn2_b64     s[26:27], s[26:27], exec
        s_cbranch_scc0  .L892_0
        s_and_b64       exec, s[44:45], s[26:27]
        v_mov_b32       v6, v9
        s_branch        .L400_0
.L892_0:
        s_mov_b64       exec, s[10:11]
        s_add_u32       s10, s0, 5
        s_addc_u32      s11, s1, 0
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 4
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 6
        s_addc_u32      s21, s1, 0
        v_mov_b32       v6, s10
        v_mov_b32       v7, s11
        v_mov_b32       v8, s14
        v_mov_b32       v9, s15
        s_add_u32       s10, s0, 8
        s_addc_u32      s11, s1, 0
        v_mov_b32       v12, s20
        v_mov_b32       v13, s21
        v_mov_b32       v14, s10
        v_mov_b32       v15, s11
        s_add_u32       s10, s0, 9
        s_addc_u32      s11, s1, 0
        buffer_load_ubyte v6, v[6:7], s[16:19], 0 addr64
        buffer_load_ubyte v7, v[8:9], s[16:19], 0 addr64
        s_add_u32       s14, s0, 7
        s_addc_u32      s15, s1, 0
        s_add_u32       s0, s0, 10
        s_addc_u32      s1, s1, 0
        v_mov_b32       v8, s10
        v_mov_b32       v9, s11
        buffer_load_ubyte v12, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v13, v[14:15], s[16:19], 0 addr64
        v_mov_b32       v14, s14
        v_mov_b32       v15, s15
        v_mov_b32       v16, s0
        v_mov_b32       v17, s1
        buffer_load_ubyte v8, v[8:9], s[16:19], 0 addr64
        buffer_load_ubyte v9, v[14:15], s[16:19], 0 addr64
        buffer_load_ubyte v14, v[16:17], s[16:19], 0 addr64
        s_waitcnt       vmcnt(6)
        v_lshlrev_b32   v6, 16, v6
        s_waitcnt       vmcnt(5)
        v_lshlrev_b32   v7, 24, v7
        v_or_b32        v6, v6, v7
        s_waitcnt       vmcnt(4)
        v_lshlrev_b32   v7, 8, v12
        s_waitcnt       vmcnt(3)
        v_lshlrev_b32   v12, 24, v13
        s_movk_i32      s0, 0xff
        v_or_b32        v6, v6, v7
        v_bfi_b32       v7, s0, v2, v12
        s_waitcnt       vmcnt(2)
        v_lshlrev_b32   v8, 16, v8
        s_waitcnt       vmcnt(1)
        v_or_b32        v6, v9, v6
        v_mov_b32       v12, 0
        v_or_b32        v7, v7, v8
        s_waitcnt       vmcnt(0)
        v_lshlrev_b32   v8, 8, v14
        ds_write2_b32   v12, v12, v6 offset1:1
        v_or_b32        v6, v7, v8
        v_mov_b32       v7, 0x80000000
        ds_write2_b32   v12, v6, v7 offset0:2 offset1:3
        ds_write2_b32   v12, v12, v12 offset0:4 offset1:5
        ds_write2_b32   v12, v12, v12 offset0:6 offset1:7
        ds_write2_b32   v12, v12, v12 offset0:8 offset1:9
        ds_write2_b32   v12, v12, v12 offset0:10 offset1:11
        ds_write2_b32   v12, v12, v12 offset0:12 offset1:13
        v_mov_b32       v7, 0x60
        ds_write2_b32   v12, v12, v7 offset0:14 offset1:15
        v_alignbit_b32  v6, v6, v6, 31
        ds_write_b32    v12, v6 offset:64
        s_movk_i32      s0, 0x0
        s_movk_i32      s1, 0x0
.L1260_0:
        v_mov_b32       v6, s0
        ds_read2_b32    v[7:8], v6 offset0:14 offset1:15
        ds_read2_b32    v[12:13], v6 offset0:9 offset1:10
        ds_read2_b32    v[14:15], v6 offset0:3 offset1:4
        ds_read2_b32    v[16:17], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(2)
        v_xor_b32       v8, v8, v13
        v_xor_b32       v7, v7, v12
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v8, v8, v15
        v_xor_b32       v7, v14, v7
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v8, v17, v8
        v_xor_b32       v7, v16, v7
        v_alignbit_b32  v8, v8, v8, 31
        v_alignbit_b32  v7, v7, v7, 31
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:16 offset1:11
        ds_read_b32     v12, v6 offset:20
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v7, v7, v8
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v7, v7, v12
        v_xor_b32       v7, v14, v7
        v_alignbit_b32  v7, v7, v7, 31
        ds_write_b32    v6, v7 offset:76
        s_add_u32       s0, s0, 12
        s_addc_u32      s1, s1, 0
        s_cmp_eq_i32    s0, 0xfc
        s_cbranch_scc1  .L1432_0
        s_branch        .L1260_0
.L1432_0:
        v_mov_b32       v6, 0
        ds_read2_b32    v[7:8], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:1 offset1:2
        ds_read2_b32    v[7:8], v6 offset0:17 offset1:18
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:20 offset1:21
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        ds_write2_b32   v6, v7, v8 offset0:20 offset1:21
        ds_read2_b32    v[7:8], v6 offset0:23 offset1:26
        ds_read2_b32    v[12:13], v6 offset0:27 offset1:29
        s_waitcnt       lgkmcnt(1)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v12, vcc, 0x6ed9eba1, v12
        ds_write2_b32   v6, v7, v8 offset0:23 offset1:26
        v_add_i32       v7, vcc, 0x6ed9eba1, v13
        ds_write2_b32   v6, v12, v7 offset0:27 offset1:29
        ds_read2_b32    v[7:8], v6 offset0:33 offset1:39
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        ds_write2_b32   v6, v7, v8 offset0:33 offset1:39
        ds_read2_b32    v[7:8], v6 offset0:41 offset1:45
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0x8f1bbcdc, v8
        ds_write2_b32   v6, v7, v8 offset0:41 offset1:45
        ds_read2_b32    v[7:8], v6 offset0:53 offset1:65
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:53 offset1:65
        ds_read2_b32    v[7:8], v6 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0xca62c1d6, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        s_barrier
        ds_read2_b32    v[7:8], v6 offset0:38 offset1:39
        ds_read2_b32    v[12:13], v6 offset0:36 offset1:37
        ds_read2_b32    v[14:15], v6 offset0:34 offset1:35
        ds_read2_b32    v[16:17], v6 offset0:32 offset1:33
        ds_read2_b32    v[18:19], v6 offset0:30 offset1:31
        ds_read2_b32    v[20:21], v6 offset0:28 offset1:29
        ds_read2_b32    v[22:23], v6 offset0:26 offset1:27
        ds_read2_b32    v[24:25], v6 offset0:24 offset1:25
        ds_read2_b32    v[26:27], v6 offset0:22 offset1:23
        ds_read2_b32    v[28:29], v6 offset0:20 offset1:21
        ds_read2_b32    v[30:31], v6 offset0:18 offset1:19
        ds_read2_b32    v[32:33], v6 offset0:16 offset1:17
        v_lshlrev_b32   v6, 24, v3
        v_lshlrev_b32   v34, 16, v1
        v_or_b32        v6, v6, v34
        v_lshrrev_b32   v0, 2, v0
        v_and_b32       v0, 48, v0
        v_add_i32       v0, vcc, v10, v0
        s_waitcnt       lgkmcnt(0)
        s_barrier
        s_load_dwordx4  s[16:19], s[2:3], 0x90
        s_load_dwordx4  s[40:43], s[2:3], 0x70
        s_add_u32       s0, -1, s12
        s_waitcnt       lgkmcnt(0)
        s_bfe_u32       s11, s41, 0x100000
        s_mov_b32       s10, s40
        s_add_u32       s10, s10, s6
        s_addc_u32      s11, s11, s7
        s_load_dword    s1, s[10:11], 0x0
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[12:13], exec
        v_mov_b32       v10, 0
        v_mov_b32       v38, v35
        v_mov_b32       v36, v35
        v_mov_b32       v46, v35
        v_mov_b32       v37, v35
.L1964_0:
        s_movk_i32      s14, 0x3ff
        v_cmp_gt_i32    s[14:15], v10, s14
        s_and_saveexec_b64 s[20:21], s[14:15]
        v_cndmask_b32   v34, 0, -1, s[14:15]
        s_cbranch_execz .L2004_0
        v_mov_b32       v38, 0
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L6836_0
.L2004_0:
        s_and_b64       exec, s[20:21], s[12:13]
        v_ashrrev_i32   v34, 6, v10
        v_bfe_u32       v35, v0, 0, 8
        v_add_i32       v34, vcc, v35, v34
        v_ashrrev_i32   v35, 31, v34
        v_add_i32       v34, vcc, s22, v34
        v_mov_b32       v36, s23
        v_addc_u32      v35, vcc, v36, v35, vcc
        s_waitcnt       lgkmcnt(0)
        s_barrier
        v_and_b32       v36, 63, v10
        v_add_i32       v36, vcc, v11, v36
        v_ashrrev_i32   v37, 31, v36
        v_add_i32       v36, vcc, s24, v36
        v_mov_b32       v38, s25
        v_addc_u32      v37, vcc, v38, v37, vcc
        buffer_load_ubyte v34, v[34:35], s[32:35], 0 addr64
        buffer_load_ubyte v35, v[36:37], s[36:39], 0 addr64
        v_mov_b32       v36, 0
        ds_read2_b32    v[37:38], v36 offset0:1 offset1:2
        s_waitcnt       vmcnt(1)
        v_lshlrev_b32   v39, 8, v34
        v_or_b32        v39, v6, v39
        s_waitcnt       vmcnt(0)
        v_or_b32        v39, v39, v35
        v_add_i32       v40, vcc, 0x9fb498b3, v39
        v_alignbit_b32  v41, v40, v40, 27
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v37, vcc, v41, v37
        v_add_i32       v37, vcc, 0xc2e5374, v37
        v_mov_b32       v41, 0x7bf36ae2
        s_mov_b32       s14, 0x59d148c0
        v_bfi_b32       v41, v40, s14, v41
        v_alignbit_b32  v42, v37, v37, 27
        v_add_i32       v41, vcc, v41, v42
        v_add_i32       v38, vcc, v38, v41
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x98badcfe, v38
        v_bfi_b32       v41, v37, v40, s14
        v_alignbit_b32  v42, v38, v38, 27
        v_add_i32       v41, vcc, v42, v41
        v_add_i32       v41, vcc, 0x7bf36ae2, v41
        v_xor_b32       v41, 0x80000000, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v42, v41, v41, 27
        v_bfi_b32       v43, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0xb453c259, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v43, v37, v37, 27
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v38, vcc, v38, v43
        v_bfi_b32       v43, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, v44, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v43, v42, v42, 27
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v40, vcc, v40, v43
        v_bfi_b32       v43, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v44, v38
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v41, vcc, v41, v43
        v_bfi_b32       v43, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v43, v39, v39, 31
        v_add_i32       v40, vcc, 0x5a8279f9, v40
        v_xor_b32       v43, v32, v43
        v_alignbit_b32  v44, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v37, vcc, v44, v37
        v_bfi_b32       v43, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_add_i32       v38, vcc, v33, v38
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v44, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_add_i32       v41, vcc, v30, v41
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v39, v39, 30
        v_add_i32       v41, vcc, v44, v41
        v_xor_b32       v44, v31, v43
        v_alignbit_b32  v45, v41, v41, 27
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v42, vcc, v45, v42
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v44, v41, v37
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_xor_b32       v44, v38, v44
        v_add_i32       v40, vcc, v28, v40
        v_xor_b32       v45, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v44, v42, v42, 27
        v_xor_b32       v45, v45, v41
        v_add_i32       v37, vcc, v29, v37
        v_add_i32       v40, vcc, v40, v44
        v_alignbit_b32  v44, v39, v39, 29
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v46, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v26, v44
        v_add_i32       v37, vcc, v37, v45
        v_xor_b32       v45, v46, v42
        v_add_i32       v38, vcc, v38, v47
        v_alignbit_b32  v46, v37, v37, 27
        v_add_i32       v38, vcc, v45, v38
        v_add_i32       v38, vcc, v46, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v45, v37, v42
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v45, v40, v45
        v_add_i32       v41, vcc, v27, v41
        v_xor_b32       v46, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v24, v43
        v_add_i32       v41, vcc, v45, v41
        v_alignbit_b32  v45, v38, v38, 27
        v_xor_b32       v46, v46, v37
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v41, vcc, v41, v45
        v_add_i32       v42, vcc, v46, v42
        v_alignbit_b32  v45, v41, v41, 27
        v_alignbit_b32  v46, v39, v39, 28
        v_add_i32       v42, vcc, v42, v45
        v_xor_b32       v45, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v47, v25, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v45, v45, v38
        v_add_i32       v40, vcc, v40, v47
        v_alignbit_b32  v47, v42, v42, 27
        v_add_i32       v40, vcc, v45, v40
        v_add_i32       v40, vcc, v47, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v45, v42, v38
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v45, v41, v45
        v_add_i32       v37, vcc, v22, v37
        v_xor_b32       v47, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v47, v47, v42
        v_add_i32       v38, vcc, v23, v38
        v_add_i32       v37, vcc, v37, v45
        v_alignbit_b32  v45, v39, v39, 27
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v47, v37, v37, 27
        v_xor_b32       v48, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v49, v20, v45
        v_add_i32       v38, vcc, v38, v47
        v_xor_b32       v47, v48, v40
        v_add_i32       v41, vcc, v41, v49
        v_alignbit_b32  v48, v38, v38, 27
        v_add_i32       v41, vcc, v47, v41
        v_add_i32       v41, vcc, v48, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v38, v40
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_xor_b32       v48, v18, v43
        v_xor_b32       v47, v37, v47
        v_add_i32       v42, vcc, v21, v42
        v_xor_b32       v49, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v48, v46, v48
        v_add_i32       v42, vcc, v47, v42
        v_alignbit_b32  v47, v41, v41, 27
        v_xor_b32       v49, v49, v38
        v_add_i32       v40, vcc, v40, v48
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v40, vcc, v49, v40
        v_alignbit_b32  v47, v42, v42, 27
        v_alignbit_b32  v48, v39, v39, 26
        v_add_i32       v40, vcc, v40, v47
        v_xor_b32       v47, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v49, v19, v48
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v47, v47, v41
        v_add_i32       v37, vcc, v37, v49
        v_alignbit_b32  v49, v40, v40, 27
        v_add_i32       v37, vcc, v47, v37
        v_xor_b32       v43, v16, v43
        v_add_i32       v37, vcc, v49, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v40, v41
        v_xor_b32       v43, v44, v43
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v47, v42, v47
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v47, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v47, v40
        v_add_i32       v41, vcc, v17, v41
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_alignbit_b32  v47, v39, v39, 25
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v50, v14, v47
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v42, vcc, v42, v50
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v43, v42
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_xor_b32       v49, v15, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v43, v38, v43
        v_add_i32       v40, vcc, v40, v49
        v_xor_b32       v49, v46, v48
        v_add_i32       v40, vcc, v43, v40
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v50, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v51, v12, v49
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v50, v41
        v_add_i32       v37, vcc, v37, v51
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_add_i32       v37, vcc, v43, v37
        v_alignbit_b32  v43, v40, v40, 27
        v_alignbit_b32  v50, v39, v39, 24
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v51, v13, v50
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v43, v43, v42
        v_add_i32       v38, vcc, v38, v51
        v_alignbit_b32  v51, v37, v37, 27
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v51, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_xor_b32       v51, v7, v46
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v43, v40, v43
        v_add_i32       v41, vcc, v41, v51
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v51, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        ds_read2_b32    v[52:53], v36 offset0:40 offset1:41
        v_xor_b32       v43, v51, v37
        v_add_i32       v42, vcc, v8, v42
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_add_i32       v42, vcc, v43, v42
        v_alignbit_b32  v43, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v51, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        v_alignbit_b32  v55, v39, v39, 23
        v_xor_b32       v43, v43, v51
        v_add_i32       v40, vcc, v40, v54
        v_xor_b32       v51, v46, v55
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v51, v52
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v51, v41, 0, v42
        v_alignbit_b32  v52, v40, v40, 27
        ds_read2_b32    v[54:55], v36 offset0:42 offset1:43
        v_xor_b32       v43, v43, v51
        v_add_i32       v37, vcc, v37, v52
        v_add_i32       v37, vcc, v43, v37
        v_add_i32       v37, vcc, v53, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v51, v42, 0, v40
        v_alignbit_b32  v52, v37, v37, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v51, v48, v50
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v51
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v51, v40, 0, v37
        v_alignbit_b32  v52, v38, v38, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v51, v39, v39, 22
        ds_read2_b32    v[52:53], v36 offset0:44 offset1:45
        v_add_i32       v41, vcc, v43, v41
        v_xor_b32       v43, v55, v51
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v54, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v56, v44, v48
        v_xor_b32       v43, v43, v54
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v54, v47, v56
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v52
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v52, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        ds_read2_b32    v[55:56], v36 offset0:46 offset1:47
        v_xor_b32       v43, v43, v52
        v_add_i32       v40, vcc, v40, v54
        v_add_i32       v40, vcc, v43, v40
        v_add_i32       v40, vcc, v53, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v52, v41, 0, v42
        v_alignbit_b32  v53, v40, v40, 27
        v_alignbit_b32  v54, v39, v39, 21
        v_xor_b32       v43, v43, v52
        v_add_i32       v37, vcc, v37, v53
        v_xor_b32       v52, v46, v54
        v_add_i32       v37, vcc, v43, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v55, v52
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v52, v42, 0, v40
        v_alignbit_b32  v53, v37, v37, 27
        v_xor_b32       v43, v43, v52
        v_add_i32       v38, vcc, v38, v53
        v_xor_b32       v52, v46, v50
        ds_read2_b32    v[57:58], v36 offset0:48 offset1:49
        v_add_i32       v38, vcc, v43, v38
        v_xor_b32       v43, v56, v52
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v44, v45
        v_bfi_b32       v44, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        v_xor_b32       v43, v52, v43
        v_xor_b32       v44, v44, v53
        v_add_i32       v41, vcc, v41, v55
        v_xor_b32       v43, v51, v43
        v_add_i32       v41, vcc, v44, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v57
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v44, v37, 0, v38
        v_alignbit_b32  v53, v41, v41, 27
        v_xor_b32       v43, v43, v44
        v_add_i32       v42, vcc, v42, v53
        v_alignbit_b32  v44, v39, v39, 20
        ds_read2_b32    v[55:56], v36 offset0:50 offset1:51
        v_add_i32       v42, vcc, v43, v42
        v_xor_b32       v43, v58, v44
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v57, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v57
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v50, v55
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v53, v41, 0, v42
        v_alignbit_b32  v55, v40, v40, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v37, vcc, v37, v55
        ds_read2_b32    v[57:58], v36 offset0:52 offset1:53
        v_add_i32       v37, vcc, v43, v37
        v_xor_b32       v43, v49, v56
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v53, v42, 0, v40
        v_alignbit_b32  v55, v37, v37, 27
        v_alignbit_b32  v56, v39, v39, 19
        v_xor_b32       v43, v43, v53
        v_add_i32       v38, vcc, v38, v55
        v_xor_b32       v53, v52, v56
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v57
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        ds_read2_b32    v[59:60], v36 offset0:54 offset1:55
        v_xor_b32       v43, v43, v53
        v_add_i32       v41, vcc, v41, v55
        v_add_i32       v41, vcc, v43, v41
        v_add_i32       v41, vcc, v58, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v53, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v57, v47, v51
        v_xor_b32       v43, v43, v53
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v53, v44, v57
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v59
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v55, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v55
        v_alignbit_b32  v53, v39, v39, 18
        ds_read2_b32    v[57:58], v36 offset0:56 offset1:57
        v_add_i32       v40, vcc, v43, v40
        v_xor_b32       v43, v53, v60
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v47, v49
        v_bfi_b32       v55, v38, v41, v42
        v_bfi_b32       v59, v41, 0, v42
        v_alignbit_b32  v60, v40, v40, 27
        v_xor_b32       v51, v51, v43
        v_xor_b32       v55, v55, v59
        v_add_i32       v37, vcc, v37, v60
        v_xor_b32       v51, v54, v51
        v_add_i32       v37, vcc, v55, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v51, v57
        v_add_i32       v37, vcc, v37, v51
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v51, v41, v42, v40
        v_bfi_b32       v55, v42, 0, v40
        v_alignbit_b32  v57, v37, v37, 27
        v_xor_b32       v51, v51, v55
        v_add_i32       v38, vcc, v38, v57
        ds_read2_b32    v[59:60], v36 offset0:58 offset1:59
        v_add_i32       v38, vcc, v51, v38
        v_xor_b32       v51, v50, v58
        v_add_i32       v38, vcc, v38, v51
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_bfi_b32       v51, v42, v40, v37
        v_bfi_b32       v55, v40, 0, v37
        v_alignbit_b32  v57, v38, v38, 27
        v_alignbit_b32  v58, v39, v39, 17
        v_xor_b32       v51, v51, v55
        v_add_i32       v41, vcc, v41, v57
        v_xor_b32       v52, v52, v58
        v_add_i32       v41, vcc, v51, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v52, v59
        v_add_i32       v41, vcc, v41, v51
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v51, v40, v37, v38
        v_bfi_b32       v52, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        ds_read2_b32    v[61:62], v36 offset0:60 offset1:61
        v_xor_b32       v51, v51, v52
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v52, v50, v44
        v_add_i32       v42, vcc, v51, v42
        v_xor_b32       v51, v52, v60
        v_add_i32       v42, vcc, v42, v51
        v_xor_b32       v51, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v46, v46, v47
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_xor_b32       v51, v51, v38
        v_xor_b32       v46, v52, v46
        v_alignbit_b32  v55, v42, v42, 27
        v_add_i32       v40, vcc, v40, v51
        v_xor_b32       v46, v53, v46
        v_add_i32       v40, vcc, v55, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v46, v61
        v_add_i32       v40, vcc, v40, v46
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v46, v42, v38
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v46, v41, v46
        ds_read2_b32    v[59:60], v36 offset0:62 offset1:63
        v_add_i32       v37, vcc, v37, v46
        v_alignbit_b32  v46, v40, v40, 27
        v_alignbit_b32  v51, v39, v39, 16
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v51, v62
        v_xor_b32       v55, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v55, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v38, vcc, v38, v46
        v_alignbit_b32  v46, v37, v37, 27
        v_xor_b32       v49, v49, v52
        v_add_i32       v38, vcc, v38, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v49, v59
        v_add_i32       v38, vcc, v38, v46
        v_xor_b32       v46, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v46, v46, v40
        ds_read2_b32    v[61:62], v36 offset0:64 offset1:65
        v_alignbit_b32  v49, v38, v38, 27
        v_add_i32       v41, vcc, v41, v46
        v_add_i32       v41, vcc, v49, v41
        v_xor_b32       v46, v50, v60
        v_add_i32       v41, vcc, v41, v46
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v46, v38, v40
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v46, v37, v46
        v_xor_b32       v43, v43, v52
        v_alignbit_b32  v49, v39, v39, 15
        v_add_i32       v42, vcc, v42, v46
        v_alignbit_b32  v46, v41, v41, 27
        v_xor_b32       v43, v43, v49
        v_add_i32       v42, vcc, v42, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_xor_b32       v46, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, v42, v43
        ds_read2_b32    v[59:60], v36 offset0:66 offset1:67
        v_xor_b32       v43, v46, v38
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v62
        v_xor_b32       v43, v43, v41
        v_alignbit_b32  v46, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v53, v51
        v_add_i32       v37, vcc, v46, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v59
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v43, v40, v41
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v42, v43
        v_alignbit_b32  v46, v39, v39, 14
        ds_read2_b32    v[61:62], v36 offset0:68 offset1:69
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v49, v50, v46
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v49, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v40
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v49, v54, v53
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v58, v49
        v_add_i32       v41, vcc, v41, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v61
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        ds_read2_b32    v[59:60], v36 offset0:70 offset1:71
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v43, v43, v37
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_add_i32       v42, vcc, v42, v62
        v_xor_b32       v43, v38, v43
        v_alignbit_b32  v49, v39, v39, 13
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v49, v44, v49
        v_add_i32       v40, vcc, v40, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v59
        v_xor_b32       v49, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v49, v41
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        ds_read2_b32    v[61:62], v36 offset0:72 offset1:73
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v49, v44, v51
        v_xor_b32       v45, v45, v54
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v45, v44, v45
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v45, v56, v45
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v43, v42
        v_xor_b32       v45, v51, v45
        v_alignbit_b32  v49, v37, v37, 27
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v46, v45
        v_add_i32       v38, vcc, v49, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v43, v40, v43
        ds_read2_b32    v[54:55], v36 offset0:74 offset1:75
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v45, v39, v39, 12
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v45, v62
        v_xor_b32       v49, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v43, v41, v41, 27
        v_xor_b32       v49, v50, v51
        v_add_i32       v42, vcc, v42, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v54
        v_add_i32       v42, vcc, v42, v43
        v_xor_b32       v43, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_xor_b32       v43, v43, v38
        v_xor_b32       v48, v48, v44
        ds_read2_b32    v[56:57], v36 offset0:76 offset1:77
        v_alignbit_b32  v49, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v53, v48
        v_add_i32       v40, vcc, v49, v40
        v_xor_b32       v43, v43, v55
        v_xor_b32       v47, v47, v50
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v42, v38
        v_xor_b32       v44, v44, v47
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v43, v41, v43
        v_xor_b32       v44, v51, v44
        v_alignbit_b32  v48, v39, v39, 11
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v44, v44, v48
        v_add_i32       v37, vcc, v37, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v44, v56
        v_xor_b32       v44, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v43
        ds_read2_b32    v[48:49], v36 offset0:78 offset1:79
        v_xor_b32       v36, v44, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v36, vcc, v38, v36
        v_alignbit_b32  v38, v37, v37, 27
        v_add_i32       v36, vcc, v36, v38
        v_alignbit_b32  v38, v40, v40, 2
        v_xor_b32       v40, v42, v37
        v_xor_b32       v43, v58, v47
        v_add_i32       v36, vcc, v36, v57
        v_xor_b32       v40, v38, v40
        v_xor_b32       v43, v46, v43
        v_alignbit_b32  v44, v36, v36, 27
        v_add_i32       v40, vcc, v41, v40
        v_xor_b32       v41, v45, v43
        v_add_i32       v40, vcc, v44, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v41, v41, v48
        v_xor_b32       v38, v36, v38
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v40, vcc, v40, v41
        v_xor_b32       v37, v38, v37
        v_add_i32       v38, vcc, 0xca62c1d6, v40
        v_alignbit_b32  v39, v39, v39, 10
        v_add_i32       v37, vcc, v42, v37
        v_alignbit_b32  v38, v38, v38, 27
        v_xor_b32       v39, v50, v39
        v_add_i32       v37, vcc, v37, v38
        v_xor_b32       v38, v39, v49
        v_add_i32       v37, vcc, v37, v38
        v_add_i32       v37, vcc, 0x31a7e4d7, v37
        v_lshrrev_b32   v38, 20, v37
        ds_read_u8      v38, v38 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v38, v38, 0, 8
        v_cmp_lg_i32    s[14:15], v38, 0
        s_mov_b64       s[20:21], exec
        s_andn2_b64     exec, s[20:21], s[14:15]
        v_lshrrev_b32   v46, 8, v37
        s_cbranch_execz .L6796_0
        v_add_i32       v38, vcc, s8, v46
        v_mov_b32       v41, s9
        v_addc_u32      v39, vcc, v41, 0, vcc
        buffer_load_ubyte v39, v[38:39], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    s[26:27], v39, 0
        s_and_saveexec_b64 s[44:45], s[26:27]
        v_lshrrev_b32   v38, 2, v37
        s_cbranch_execz .L6768_0
        v_alignbit_b32  v36, v36, v36, 2
        v_add_i32       v36, vcc, 0x98badcfe, v36
        v_add_i32       v46, vcc, 0xba306d5f, v40
        s_mov_b64       s[46:47], exec
        s_mov_b64       s[48:49], exec
        v_mov_b32       v39, s1
        v_mov_b32       v41, 0
        v_mov_b32       v42, s0
        s_movk_i32      s50, 0x0
        s_movk_i32      s51, 0x0
        s_nop           0x0
        s_nop           0x0
        s_nop           0x0
.L6616_0:
        v_cmp_gt_i32    s[52:53], v41, v42
        v_cmp_eq_i32    vcc, v38, v39
        s_andn2_b64     s[50:51], s[50:51], exec
        s_or_b64        s[50:51], vcc, s[50:51]
        s_or_b64        vcc, s[52:53], vcc
        s_and_saveexec_b64 s[52:53], vcc
        s_andn2_b64     s[48:49], s[48:49], exec
        s_cbranch_scc0  .L6736_0
        s_and_b64       exec, s[52:53], s[48:49]
        v_add_i32       v40, vcc, v41, v42
        v_ashrrev_i32   v47, 1, v40
        v_ashrrev_i32   v48, 31, v47
        v_lshl_b64      v[43:44], v[47:48], 2
        v_add_i32       v43, vcc, s6, v43
        v_mov_b32       v45, s7
        v_addc_u32      v44, vcc, v45, v44, vcc
        buffer_load_dword v39, v[43:44], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[52:53], v39, v38
        v_add_i32       v44, vcc, -1, v47
        v_add_i32       v40, vcc, 1, v47
        v_cndmask_b32   v42, v42, v44, s[52:53]
        v_cndmask_b32   v41, v40, v41, s[52:53]
        s_branch        .L6616_0
.L6736_0:
        s_mov_b64       exec, s[46:47]
        s_and_saveexec_b64 s[46:47], s[50:51]
        v_mov_b32       v38, 1
        s_cbranch_execz .L6760_0
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L6836_0
.L6760_0:
        s_and_b64       exec, s[46:47], s[12:13]
        v_mov_b32       v38, 1
.L6768_0:
        s_andn2_b64     exec, s[44:45], exec
        s_and_b64       exec, exec, s[12:13]
        v_cndmask_b32   v36, 0, -1, s[26:27]
        s_cbranch_execz .L6792_0
        v_mov_b32       v38, 0
.L6792_0:
        s_and_b64       exec, s[44:45], s[12:13]
.L6796_0:
        s_andn2_b64     exec, s[20:21], exec
        s_and_b64       exec, exec, s[12:13]
        v_cndmask_b32   v46, 0, -1, s[14:15]
        s_cbranch_execz .L6824_0
        v_mov_b32       v38, 0
        v_mov_b32       v36, 0
.L6824_0:
        s_and_b64       exec, s[20:21], s[12:13]
        v_add_i32       v10, vcc, 1, v10
        s_branch        .L1964_0
.L6836_0:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v38
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[0:1], vcc
        v_mov_b32       v0, 0x400
        s_cbranch_execz .L6872_0
        buffer_store_dword v0, v[4:5], s[28:31], 0 addr64
.L6872_0:
        s_andn2_b64     exec, s[0:1], exec
        s_cbranch_execz .L7408_0
        s_load_dwordx4  s[8:11], s[2:3], 0x50
        v_lshrrev_b32   v6, 26, v37
        v_add_i32       v20, vcc, s4, v6
        v_mov_b32       v13, s5
        v_addc_u32      v21, vcc, v13, 0, vcc
        v_bfe_u32       v15, v37, 20, 6
        v_add_i32       v15, vcc, s4, v15
        v_addc_u32      v16, vcc, v13, 0, vcc
        v_bfe_u32       v17, v37, 14, 6
        v_add_i32       v17, vcc, s4, v17
        v_addc_u32      v18, vcc, v13, 0, vcc
        v_bfe_u32       v19, v37, 8, 6
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v6, v[20:21], s[8:11], 0 addr64
        v_add_i32       v22, vcc, s4, v19
        v_addc_u32      v23, vcc, v13, 0, vcc
        v_bfe_u32       v20, v37, 2, 6
        v_lshrrev_b32   v21, 28, v46
        v_lshlrev_b32   v12, 4, v37
        buffer_load_ubyte v15, v[15:16], s[8:11], 0 addr64
        v_add_i32       v7, vcc, s4, v20
        v_addc_u32      v8, vcc, v13, 0, vcc
        v_bfi_b32       v12, 48, v12, v21
        buffer_load_ubyte v17, v[17:18], s[8:11], 0 addr64
        v_add_i32       v24, vcc, s4, v12
        v_addc_u32      v25, vcc, v13, 0, vcc
        v_bfe_u32       v21, v46, 22, 6
        buffer_load_ubyte v14, v[22:23], s[8:11], 0 addr64
        v_add_i32       v26, vcc, s4, v21
        v_addc_u32      v27, vcc, v13, 0, vcc
        v_bfe_u32       v22, v46, 16, 6
        buffer_load_ubyte v16, v[7:8], s[8:11], 0 addr64
        v_add_i32       v7, vcc, s4, v22
        v_addc_u32      v8, vcc, v13, 0, vcc
        v_bfe_u32       v23, v46, 10, 6
        buffer_load_ubyte v12, v[24:25], s[8:11], 0 addr64
        v_add_i32       v28, vcc, s4, v23
        v_addc_u32      v29, vcc, v13, 0, vcc
        v_bfe_u32       v24, v46, 4, 6
        v_lshrrev_b32   v25, 30, v36
        v_lshlrev_b32   v11, 2, v46
        buffer_load_ubyte v19, v[26:27], s[8:11], 0 addr64
        v_add_i32       v23, vcc, s4, v24
        v_addc_u32      v24, vcc, v13, 0, vcc
        v_bfi_b32       v11, 60, v11, v25
        buffer_load_ubyte v20, v[7:8], s[8:11], 0 addr64
        v_add_i32       v25, vcc, s4, v11
        v_addc_u32      v26, vcc, v13, 0, vcc
        v_bfe_u32       v8, v36, 24, 6
        buffer_load_ubyte v18, v[28:29], s[8:11], 0 addr64
        v_add_i32       v7, vcc, s4, v8
        v_addc_u32      v8, vcc, v13, 0, vcc
        buffer_load_ubyte v21, v[23:24], s[8:11], 0 addr64
        buffer_load_ubyte v11, v[25:26], s[8:11], 0 addr64
        buffer_load_ubyte v8, v[7:8], s[8:11], 0 addr64
        buffer_store_byte v3, v[4:5], s[28:31], 0 offset:17 glc addr64
        buffer_store_byte v1, v[4:5], s[28:31], 0 offset:18 glc addr64
        buffer_store_byte v34, v[4:5], s[28:31], 0 offset:19 glc addr64
        buffer_store_byte v35, v[4:5], s[28:31], 0 offset:20 glc addr64
        buffer_store_byte v9, v[4:5], s[28:31], 0 offset:24 glc addr64
        buffer_store_byte v2, v[4:5], s[28:31], 0 offset:28 glc addr64
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:5 glc addr64
        buffer_store_byte v15, v[4:5], s[28:31], 0 offset:6 glc addr64
        buffer_store_byte v17, v[4:5], s[28:31], 0 offset:7 glc addr64
        buffer_store_byte v14, v[4:5], s[28:31], 0 offset:8 glc addr64
        buffer_store_byte v16, v[4:5], s[28:31], 0 offset:9 glc addr64
        buffer_store_byte v12, v[4:5], s[28:31], 0 offset:10 glc addr64
        buffer_store_byte v19, v[4:5], s[28:31], 0 offset:11 glc addr64
        buffer_store_byte v20, v[4:5], s[28:31], 0 offset:12 glc addr64
        buffer_store_byte v18, v[4:5], s[28:31], 0 offset:13 glc addr64
        buffer_store_byte v21, v[4:5], s[28:31], 0 offset:14 glc addr64
        v_mov_b32       v0, 1
        buffer_store_byte v11, v[4:5], s[28:31], 0 offset:15 glc addr64
        v_add_i32       v1, vcc, 1, v10
        buffer_store_byte v8, v[4:5], s[28:31], 0 offset:16 glc addr64
        buffer_store_byte v0, v[4:5], s[28:31], 0 offset:4 glc addr64
        buffer_store_dword v1, v[4:5], s[28:31], 0 addr64
.L7408_0:
        s_endpgm
.kernel OpenCL_SHA1_PerformSearching_BackwardMatching
    .header
        .fill 8, 1, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00
        .byte 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        .fill 8, 1, 0x00
    .metadata
        .ascii ";ARGSTART:__OpenCL_OpenCL_SHA1_PerformSearching_BackwardMatching_kernel\n"
        .ascii ";version:3:1:111\n"
        .ascii ";device:hawaii\n"
        .ascii ";uniqueid:1025\n"
        .ascii ";memory:uavprivate:0\n"
        .ascii ";memory:hwlocal:4416\n"
        .ascii ";memory:hwregion:0\n"
        .ascii ";pointer:outputArray:struct:1:1:0:uav:12:32:RW:0:0\n"
        .ascii ";pointer:key:u8:1:1:16:c:13:1:RO:0:0\n"
        .ascii ";constarg:1:key\n"
        .ascii ";pointer:tripcodeChunkArray:u32:1:1:32:uav:14:4:RO:0:0\n"
        .ascii ";constarg:2:tripcodeChunkArray\n"
        .ascii ";value:numTripcodeChunk:u32:1:1:48\n"
        .ascii ";pointer:keyCharTable_OneByte:u8:1:1:64:c:11:1:RO:0:0\n"
        .ascii ";constarg:4:keyCharTable_OneByte\n"
        .ascii ";pointer:keyCharTable_FirstByte:u8:1:1:80:c:15:1:RO:0:0\n"
        .ascii ";constarg:5:keyCharTable_FirstByte\n"
        .ascii ";pointer:keyCharTable_SecondByte:u8:1:1:96:c:11:1:RO:0:0\n"
        .ascii ";constarg:6:keyCharTable_SecondByte\n"
        .ascii ";pointer:keyCharTable_SecondByteAndOneByte:u8:1:1:112:c:16:1:RO:0:0\n"
        .ascii ";constarg:7:keyCharTable_SecondByteAndOneByte\n"
        .ascii ";pointer:smallChunkBitmap_constant:u8:1:1:128:c:17:1:RO:0:0\n"
        .ascii ";constarg:8:smallChunkBitmap_constant\n"
        .ascii ";pointer:chunkBitmap:u8:1:1:144:uav:18:1:RO:0:0\n"
        .ascii ";constarg:9:chunkBitmap\n"
        .ascii ";memory:datareqd\n"
        .ascii ";function:1:1036\n"
        .ascii ";memory:64bitABI\n"
        .ascii ";uavid:11\n"
        .ascii ";printfid:9\n"
        .ascii ";cbid:10\n"
        .ascii ";privateid:8\n"
        .ascii ";reflection:0:GPUOutput*\n"
        .ascii ";reflection:1:uchar*\n"
        .ascii ";reflection:2:uint*\n"
        .ascii ";reflection:3:uint\n"
        .ascii ";reflection:4:uchar*\n"
        .ascii ";reflection:5:uchar*\n"
        .ascii ";reflection:6:uchar*\n"
        .ascii ";reflection:7:uchar*\n"
        .ascii ";reflection:8:uchar*\n"
        .ascii ";reflection:9:uchar*\n"
        .ascii ";ARGEND:__OpenCL_OpenCL_SHA1_PerformSearching_BackwardMatching_kernel\n"
    .data
        .fill 4736, 1, 0x00
    .inputs
    .outputs
    .uav
        .entry 12, 4, 0, 5
        .entry 14, 4, 0, 5
        .entry 18, 4, 0, 5
        .entry 8, 3, 0, 5
    .condout 0
    .floatconsts
    .intconsts
    .boolconsts
    .earlyexit 0
    .globalbuffers
    .constantbuffers
        .cbmask 0, 875786784
        .cbmask 1, 1914711135
        .cbmask 13, 829169708
        .cbmask 11, 1684300137
        .cbmask 15, 1601796142
        .cbmask 11, 2016293683
        .cbmask 16, 875786784
        .cbmask 17, 1762200112
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
        .entry 0x80001041, 0x00000040
        .entry 0x80001042, 0x00000036
        .entry 0x80001863, 0x00000066
        .entry 0x80001864, 0x00000100
        .entry 0x80001043, 0x000000c0
        .entry 0x80001044, 0x00000000
        .entry 0x80001045, 0x00000000
        .entry 0x00002e13, 0x00048098
        .entry 0x8000001c, 0x00000100
        .entry 0x8000001d, 0x00000000
        .entry 0x8000001e, 0x00000000
        .entry 0x80001841, 0x00000000
        .entry 0x8000001f, 0x0007f400
        .entry 0x80001843, 0x0007f400
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
        .entry 0x80000082, 0x00000900
    .subconstantbuffers
    .uavmailboxsize 0
    .uavopmask
        .byte 0x00, 0xf4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00
        .fill 120, 1, 0x00
    .text
        s_mov_b32       m0, 0x10000
        s_buffer_load_dwordx2 s[0:1], s[8:11], 0x4
        s_load_dwordx4  s[16:19], s[2:3], 0x68
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 1
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 11
        s_addc_u32      s21, s1, 0
        v_mov_b32       v1, s14
        v_mov_b32       v2, s15
        v_mov_b32       v3, s20
        v_mov_b32       v4, s21
        v_mov_b32       v5, s0
        v_mov_b32       v6, s1
        buffer_load_ubyte v1, v[1:2], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[3:4], s[16:19], 0 addr64
        buffer_load_ubyte v3, v[5:6], s[16:19], 0 addr64
        s_buffer_load_dword s13, s[4:7], 0x4
        s_buffer_load_dword s14, s[4:7], 0x18
        s_buffer_load_dword s15, s[4:7], 0x1c
        s_waitcnt       lgkmcnt(0)
        s_min_u32       s13, s13, 0xffff
        s_mul_i32       s13, s12, s13
        s_buffer_load_dwordx2 s[20:21], s[8:11], 0x0
        s_buffer_load_dwordx2 s[22:23], s[8:11], 0x14
        s_buffer_load_dwordx2 s[24:25], s[8:11], 0x1c
        s_add_u32       s13, s13, s14
        v_add_i32       v4, vcc, s13, v0
        s_add_u32       s12, s12, s15
        v_ashrrev_i32   v5, 31, v4
        s_load_dwordx4  s[28:31], s[2:3], 0x60
        s_load_dwordx4  s[32:35], s[2:3], 0x78
        s_load_dwordx4  s[36:39], s[2:3], 0x80
        s_ashr_i32      s13, s12, 6
        v_and_b32       v6, 63, v0
        s_and_b32       s12, s12, 63
        v_lshl_b64      v[4:5], v[4:5], 5
        s_waitcnt       vmcnt(1)
        v_add_i32       v2, vcc, s13, v2
        v_add_i32       v1, vcc, v1, v6
        s_waitcnt       vmcnt(0)
        v_add_i32       v3, vcc, s12, v3
        s_add_u32       s12, s0, 2
        s_addc_u32      s13, s1, 0
        s_add_u32       s14, s0, 3
        s_addc_u32      s15, s1, 0
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v4, vcc, s20, v4
        v_mov_b32       v6, s21
        v_addc_u32      v5, vcc, v6, v5, vcc
        v_mov_b32       v6, 0
        v_ashrrev_i32   v7, 31, v2
        v_add_i32       v14, vcc, s24, v2
        v_mov_b32       v8, s25
        v_addc_u32      v15, vcc, v8, v7, vcc
        v_ashrrev_i32   v9, 31, v1
        v_add_i32       v7, vcc, s24, v1
        v_addc_u32      v8, vcc, v8, v9, vcc
        v_ashrrev_i32   v9, 31, v3
        v_add_i32       v16, vcc, s22, v3
        v_mov_b32       v10, s23
        v_addc_u32      v17, vcc, v10, v9, vcc
        v_mov_b32       v10, s12
        v_mov_b32       v11, s13
        v_mov_b32       v12, s14
        v_mov_b32       v13, s15
        buffer_load_ubyte v10, v[10:11], s[16:19], 0 addr64
        buffer_load_ubyte v11, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[14:15], s[36:39], 0 addr64
        buffer_load_ubyte v1, v[7:8], s[36:39], 0 addr64
        buffer_load_ubyte v3, v[16:17], s[32:35], 0 addr64
        s_buffer_load_dwordx2 s[4:5], s[4:7], 0x20
        s_buffer_load_dwordx2 s[6:7], s[8:11], 0x8
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dwordx2 s[14:15], s[8:11], 0x20
        s_buffer_load_dwordx2 s[8:9], s[8:11], 0x24
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:4 glc addr64
        v_cmp_eq_i32    vcc, 0, v0
        s_and_saveexec_b64 s[10:11], vcc
        s_cbranch_execz .L892_1
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s14, 7
        s_addc_u32      s15, s15, 0
        s_load_dwordx4  s[40:43], s[2:3], 0x88
        s_mov_b64       s[20:21], exec
        s_mov_b64       s[26:27], exec
        v_mov_b32       v6, 0
        v_mov_b32       v7, 0
.L400_1:
        v_add_i32       v8, vcc, s14, v6
        v_mov_b32       v9, s15
        v_addc_u32      v9, vcc, v9, v7, vcc
        v_add_i32       v12, vcc, v8, -7
        v_addc_u32      v13, vcc, v9, -1, vcc
        v_add_i32       v14, vcc, v8, -6
        v_addc_u32      v15, vcc, v9, -1, vcc
        v_add_i32       v16, vcc, v8, -5
        v_addc_u32      v17, vcc, v9, -1, vcc
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v12, v[12:13], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -4
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v14, v[14:15], s[40:43], 0 addr64
        v_add_i32       v23, vcc, v8, -3
        v_addc_u32      v24, vcc, v9, -1, vcc
        buffer_load_ubyte v16, v[16:17], s[40:43], 0 addr64
        v_add_i32       v19, vcc, v8, -2
        v_addc_u32      v20, vcc, v9, -1, vcc
        buffer_load_ubyte v13, v[21:22], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -1
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v15, v[23:24], s[40:43], 0 addr64
        buffer_load_ubyte v17, v[19:20], s[40:43], 0 addr64
        buffer_load_ubyte v18, v[21:22], s[40:43], 0 addr64
        buffer_load_ubyte v19, v[8:9], s[40:43], 0 addr64
        buffer_load_ubyte v20, v[8:9], s[40:43], 0 offset:1 addr64
        buffer_load_ubyte v21, v[8:9], s[40:43], 0 offset:2 addr64
        buffer_load_ubyte v22, v[8:9], s[40:43], 0 offset:3 addr64
        buffer_load_ubyte v23, v[8:9], s[40:43], 0 offset:4 addr64
        buffer_load_ubyte v24, v[8:9], s[40:43], 0 offset:5 addr64
        buffer_load_ubyte v25, v[8:9], s[40:43], 0 offset:6 addr64
        buffer_load_ubyte v26, v[8:9], s[40:43], 0 offset:7 addr64
        buffer_load_ubyte v8, v[8:9], s[40:43], 0 offset:8 addr64
        ds_write_b8     v6, v12 offset:320
        s_waitcnt       vmcnt(14)
        ds_write_b8     v6, v14 offset:321
        s_waitcnt       vmcnt(13)
        ds_write_b8     v6, v16 offset:322
        s_waitcnt       vmcnt(12)
        ds_write_b8     v6, v13 offset:323
        s_waitcnt       vmcnt(11)
        ds_write_b8     v6, v15 offset:324
        s_waitcnt       vmcnt(10)
        ds_write_b8     v6, v17 offset:325
        s_waitcnt       vmcnt(9)
        ds_write_b8     v6, v18 offset:326
        s_waitcnt       vmcnt(8)
        ds_write_b8     v6, v19 offset:327
        s_waitcnt       vmcnt(7)
        ds_write_b8     v6, v20 offset:328
        s_waitcnt       vmcnt(6)
        ds_write_b8     v6, v21 offset:329
        s_waitcnt       vmcnt(5)
        ds_write_b8     v6, v22 offset:330
        s_waitcnt       vmcnt(4)
        ds_write_b8     v6, v23 offset:331
        s_waitcnt       vmcnt(3)
        ds_write_b8     v6, v24 offset:332
        s_waitcnt       vmcnt(2)
        ds_write_b8     v6, v25 offset:333
        s_waitcnt       vmcnt(1)
        ds_write_b8     v6, v26 offset:334
        v_add_i32       v9, vcc, v6, 16
        v_addc_u32      v7, vcc, v7, 0, vcc
        s_movk_i32      s13, 0x1000
        s_waitcnt       vmcnt(0)
        ds_write_b8     v6, v8 offset:335
        v_cmp_eq_i32    vcc, s13, v9
        s_and_saveexec_b64 s[44:45], vcc
        s_andn2_b64     s[26:27], s[26:27], exec
        s_cbranch_scc0  .L892_1
        s_and_b64       exec, s[44:45], s[26:27]
        v_mov_b32       v6, v9
        s_branch        .L400_1
.L892_1:
        s_mov_b64       exec, s[10:11]
        s_add_u32       s10, s0, 5
        s_addc_u32      s11, s1, 0
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 4
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 6
        s_addc_u32      s21, s1, 0
        v_mov_b32       v6, s10
        v_mov_b32       v7, s11
        v_mov_b32       v8, s14
        v_mov_b32       v9, s15
        s_add_u32       s10, s0, 8
        s_addc_u32      s11, s1, 0
        v_mov_b32       v12, s20
        v_mov_b32       v13, s21
        v_mov_b32       v14, s10
        v_mov_b32       v15, s11
        s_add_u32       s10, s0, 9
        s_addc_u32      s11, s1, 0
        buffer_load_ubyte v6, v[6:7], s[16:19], 0 addr64
        buffer_load_ubyte v7, v[8:9], s[16:19], 0 addr64
        s_add_u32       s14, s0, 7
        s_addc_u32      s15, s1, 0
        s_add_u32       s0, s0, 10
        s_addc_u32      s1, s1, 0
        v_mov_b32       v8, s10
        v_mov_b32       v9, s11
        buffer_load_ubyte v12, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v13, v[14:15], s[16:19], 0 addr64
        v_mov_b32       v14, s14
        v_mov_b32       v15, s15
        v_mov_b32       v16, s0
        v_mov_b32       v17, s1
        buffer_load_ubyte v8, v[8:9], s[16:19], 0 addr64
        buffer_load_ubyte v9, v[14:15], s[16:19], 0 addr64
        buffer_load_ubyte v14, v[16:17], s[16:19], 0 addr64
        s_waitcnt       vmcnt(6)
        v_lshlrev_b32   v6, 16, v6
        s_waitcnt       vmcnt(5)
        v_lshlrev_b32   v7, 24, v7
        v_or_b32        v6, v6, v7
        s_waitcnt       vmcnt(4)
        v_lshlrev_b32   v7, 8, v12
        s_waitcnt       vmcnt(3)
        v_lshlrev_b32   v12, 24, v13
        s_movk_i32      s0, 0xff
        v_or_b32        v6, v6, v7
        v_bfi_b32       v7, s0, v2, v12
        s_waitcnt       vmcnt(2)
        v_lshlrev_b32   v8, 16, v8
        s_waitcnt       vmcnt(1)
        v_or_b32        v6, v9, v6
        v_mov_b32       v12, 0
        v_or_b32        v7, v7, v8
        s_waitcnt       vmcnt(0)
        v_lshlrev_b32   v8, 8, v14
        ds_write2_b32   v12, v12, v6 offset1:1
        v_or_b32        v6, v7, v8
        v_mov_b32       v7, 0x80000000
        ds_write2_b32   v12, v6, v7 offset0:2 offset1:3
        ds_write2_b32   v12, v12, v12 offset0:4 offset1:5
        ds_write2_b32   v12, v12, v12 offset0:6 offset1:7
        ds_write2_b32   v12, v12, v12 offset0:8 offset1:9
        ds_write2_b32   v12, v12, v12 offset0:10 offset1:11
        ds_write2_b32   v12, v12, v12 offset0:12 offset1:13
        v_mov_b32       v7, 0x60
        ds_write2_b32   v12, v12, v7 offset0:14 offset1:15
        v_alignbit_b32  v6, v6, v6, 31
        ds_write_b32    v12, v6 offset:64
        s_movk_i32      s0, 0x0
        s_movk_i32      s1, 0x0
.L1260_1:
        v_mov_b32       v6, s0
        ds_read2_b32    v[7:8], v6 offset0:14 offset1:15
        ds_read2_b32    v[12:13], v6 offset0:9 offset1:10
        ds_read2_b32    v[14:15], v6 offset0:3 offset1:4
        ds_read2_b32    v[16:17], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(2)
        v_xor_b32       v8, v8, v13
        v_xor_b32       v7, v7, v12
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v8, v8, v15
        v_xor_b32       v7, v14, v7
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v8, v17, v8
        v_xor_b32       v7, v16, v7
        v_alignbit_b32  v8, v8, v8, 31
        v_alignbit_b32  v7, v7, v7, 31
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:16 offset1:11
        ds_read_b32     v12, v6 offset:20
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v7, v7, v8
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v7, v7, v12
        v_xor_b32       v7, v14, v7
        v_alignbit_b32  v7, v7, v7, 31
        ds_write_b32    v6, v7 offset:76
        s_add_u32       s0, s0, 12
        s_addc_u32      s1, s1, 0
        s_cmp_eq_i32    s0, 0xfc
        s_cbranch_scc1  .L1432_1
        s_branch        .L1260_1
.L1432_1:
        v_mov_b32       v6, 0
        ds_read2_b32    v[7:8], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:1 offset1:2
        ds_read2_b32    v[7:8], v6 offset0:17 offset1:18
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:20 offset1:21
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        ds_write2_b32   v6, v7, v8 offset0:20 offset1:21
        ds_read2_b32    v[7:8], v6 offset0:23 offset1:26
        ds_read2_b32    v[12:13], v6 offset0:27 offset1:29
        s_waitcnt       lgkmcnt(1)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v12, vcc, 0x6ed9eba1, v12
        ds_write2_b32   v6, v7, v8 offset0:23 offset1:26
        v_add_i32       v7, vcc, 0x6ed9eba1, v13
        ds_write2_b32   v6, v12, v7 offset0:27 offset1:29
        ds_read2_b32    v[7:8], v6 offset0:33 offset1:39
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        ds_write2_b32   v6, v7, v8 offset0:33 offset1:39
        ds_read2_b32    v[7:8], v6 offset0:41 offset1:45
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0x8f1bbcdc, v8
        ds_write2_b32   v6, v7, v8 offset0:41 offset1:45
        ds_read2_b32    v[7:8], v6 offset0:53 offset1:65
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:53 offset1:65
        ds_read2_b32    v[7:8], v6 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0xca62c1d6, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        s_barrier
        ds_read2_b32    v[7:8], v6 offset0:38 offset1:39
        ds_read2_b32    v[12:13], v6 offset0:36 offset1:37
        ds_read2_b32    v[14:15], v6 offset0:34 offset1:35
        ds_read2_b32    v[16:17], v6 offset0:32 offset1:33
        ds_read2_b32    v[18:19], v6 offset0:30 offset1:31
        ds_read2_b32    v[20:21], v6 offset0:28 offset1:29
        ds_read2_b32    v[22:23], v6 offset0:26 offset1:27
        ds_read2_b32    v[24:25], v6 offset0:24 offset1:25
        ds_read2_b32    v[26:27], v6 offset0:22 offset1:23
        ds_read2_b32    v[28:29], v6 offset0:20 offset1:21
        ds_read2_b32    v[30:31], v6 offset0:18 offset1:19
        ds_read2_b32    v[32:33], v6 offset0:16 offset1:17
        v_lshlrev_b32   v6, 24, v3
        v_lshlrev_b32   v34, 16, v1
        v_or_b32        v6, v6, v34
        v_lshrrev_b32   v0, 2, v0
        v_and_b32       v0, 48, v0
        v_add_i32       v0, vcc, v10, v0
        s_waitcnt       lgkmcnt(0)
        s_barrier
        s_load_dwordx4  s[16:19], s[2:3], 0x90
        s_load_dwordx4  s[40:43], s[2:3], 0x70
        s_add_u32       s0, -1, s12
        s_waitcnt       lgkmcnt(0)
        s_bfe_u32       s11, s41, 0x100000
        s_mov_b32       s10, s40
        s_add_u32       s10, s10, s6
        s_addc_u32      s11, s11, s7
        s_load_dword    s1, s[10:11], 0x0
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[12:13], exec
        v_mov_b32       v10, 0
        v_mov_b32       v36, v35
        v_mov_b32       v63, v35
        v_mov_b32       v41, v35
        v_mov_b32       v43, v35
.L1964_1:
        s_movk_i32      s14, 0x3ff
        v_cmp_gt_i32    s[14:15], v10, s14
        s_and_saveexec_b64 s[20:21], s[14:15]
        v_cndmask_b32   v34, 0, -1, s[14:15]
        s_cbranch_execz .L2004_1
        v_mov_b32       v36, 0
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L6856_1
.L2004_1:
        s_and_b64       exec, s[20:21], s[12:13]
        v_ashrrev_i32   v34, 6, v10
        v_bfe_u32       v35, v0, 0, 8
        v_add_i32       v34, vcc, v35, v34
        v_ashrrev_i32   v35, 31, v34
        v_add_i32       v34, vcc, s22, v34
        v_mov_b32       v36, s23
        v_addc_u32      v35, vcc, v36, v35, vcc
        s_waitcnt       lgkmcnt(0)
        s_barrier
        v_and_b32       v36, 63, v10
        v_add_i32       v36, vcc, v11, v36
        v_ashrrev_i32   v37, 31, v36
        v_add_i32       v36, vcc, s24, v36
        v_mov_b32       v38, s25
        v_addc_u32      v37, vcc, v38, v37, vcc
        buffer_load_ubyte v34, v[34:35], s[32:35], 0 addr64
        buffer_load_ubyte v35, v[36:37], s[36:39], 0 addr64
        v_mov_b32       v36, 0
        ds_read2_b32    v[37:38], v36 offset0:1 offset1:2
        s_waitcnt       vmcnt(1)
        v_lshlrev_b32   v39, 8, v34
        v_or_b32        v39, v6, v39
        s_waitcnt       vmcnt(0)
        v_or_b32        v63, v39, v35
        v_add_i32       v40, vcc, 0x9fb498b3, v63
        v_alignbit_b32  v41, v40, v40, 27
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v37, vcc, v41, v37
        v_add_i32       v37, vcc, 0xc2e5374, v37
        v_mov_b32       v41, 0x7bf36ae2
        s_mov_b32       s14, 0x59d148c0
        v_bfi_b32       v41, v40, s14, v41
        v_alignbit_b32  v42, v37, v37, 27
        v_add_i32       v41, vcc, v41, v42
        v_add_i32       v38, vcc, v38, v41
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x98badcfe, v38
        v_bfi_b32       v41, v37, v40, s14
        v_alignbit_b32  v42, v38, v38, 27
        v_add_i32       v41, vcc, v42, v41
        v_add_i32       v41, vcc, 0x7bf36ae2, v41
        v_xor_b32       v41, 0x80000000, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v42, v41, v41, 27
        v_bfi_b32       v43, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0xb453c259, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v43, v37, v37, 27
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v38, vcc, v38, v43
        v_bfi_b32       v43, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, v44, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v43, v42, v42, 27
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v40, vcc, v40, v43
        v_bfi_b32       v43, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v44, v38
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v41, vcc, v41, v43
        v_bfi_b32       v43, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v43, v63, v63, 31
        v_add_i32       v40, vcc, 0x5a8279f9, v40
        v_xor_b32       v43, v32, v43
        v_alignbit_b32  v44, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v37, vcc, v44, v37
        v_bfi_b32       v43, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_add_i32       v38, vcc, v33, v38
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v44, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_add_i32       v41, vcc, v30, v41
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v63, v63, 30
        v_add_i32       v41, vcc, v44, v41
        v_xor_b32       v44, v31, v43
        v_alignbit_b32  v45, v41, v41, 27
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v42, vcc, v45, v42
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v44, v41, v37
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_xor_b32       v44, v38, v44
        v_add_i32       v40, vcc, v28, v40
        v_xor_b32       v45, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v44, v42, v42, 27
        v_xor_b32       v45, v45, v41
        v_add_i32       v37, vcc, v29, v37
        v_add_i32       v40, vcc, v40, v44
        v_alignbit_b32  v44, v63, v63, 29
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v46, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v26, v44
        v_add_i32       v37, vcc, v37, v45
        v_xor_b32       v45, v46, v42
        v_add_i32       v38, vcc, v38, v47
        v_alignbit_b32  v46, v37, v37, 27
        v_add_i32       v38, vcc, v45, v38
        v_add_i32       v38, vcc, v46, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v45, v37, v42
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v45, v40, v45
        v_add_i32       v41, vcc, v27, v41
        v_xor_b32       v46, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v24, v43
        v_add_i32       v41, vcc, v45, v41
        v_alignbit_b32  v45, v38, v38, 27
        v_xor_b32       v46, v46, v37
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v41, vcc, v41, v45
        v_add_i32       v42, vcc, v46, v42
        v_alignbit_b32  v45, v41, v41, 27
        v_alignbit_b32  v46, v63, v63, 28
        v_add_i32       v42, vcc, v42, v45
        v_xor_b32       v45, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v47, v25, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v45, v45, v38
        v_add_i32       v40, vcc, v40, v47
        v_alignbit_b32  v47, v42, v42, 27
        v_add_i32       v40, vcc, v45, v40
        v_add_i32       v40, vcc, v47, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v45, v42, v38
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v45, v41, v45
        v_add_i32       v37, vcc, v22, v37
        v_xor_b32       v47, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v47, v47, v42
        v_add_i32       v38, vcc, v23, v38
        v_add_i32       v37, vcc, v37, v45
        v_alignbit_b32  v45, v63, v63, 27
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v47, v37, v37, 27
        v_xor_b32       v48, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v49, v20, v45
        v_add_i32       v38, vcc, v38, v47
        v_xor_b32       v47, v48, v40
        v_add_i32       v41, vcc, v41, v49
        v_alignbit_b32  v48, v38, v38, 27
        v_add_i32       v41, vcc, v47, v41
        v_add_i32       v41, vcc, v48, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v38, v40
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_xor_b32       v48, v18, v43
        v_xor_b32       v47, v37, v47
        v_add_i32       v42, vcc, v21, v42
        v_xor_b32       v49, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v48, v46, v48
        v_add_i32       v42, vcc, v47, v42
        v_alignbit_b32  v47, v41, v41, 27
        v_xor_b32       v49, v49, v38
        v_add_i32       v40, vcc, v40, v48
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v40, vcc, v49, v40
        v_alignbit_b32  v47, v42, v42, 27
        v_alignbit_b32  v48, v63, v63, 26
        v_add_i32       v40, vcc, v40, v47
        v_xor_b32       v47, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v49, v19, v48
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v47, v47, v41
        v_add_i32       v37, vcc, v37, v49
        v_alignbit_b32  v49, v40, v40, 27
        v_add_i32       v37, vcc, v47, v37
        v_xor_b32       v43, v16, v43
        v_add_i32       v37, vcc, v49, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v40, v41
        v_xor_b32       v43, v44, v43
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v47, v42, v47
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v47, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v47, v40
        v_add_i32       v41, vcc, v17, v41
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_alignbit_b32  v47, v63, v63, 25
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v50, v14, v47
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v42, vcc, v42, v50
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v43, v42
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_xor_b32       v49, v15, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v43, v38, v43
        v_add_i32       v40, vcc, v40, v49
        v_xor_b32       v49, v46, v48
        v_add_i32       v40, vcc, v43, v40
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v50, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v51, v12, v49
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v50, v41
        v_add_i32       v37, vcc, v37, v51
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_add_i32       v37, vcc, v43, v37
        v_alignbit_b32  v43, v40, v40, 27
        v_alignbit_b32  v50, v63, v63, 24
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v51, v13, v50
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v43, v43, v42
        v_add_i32       v38, vcc, v38, v51
        v_alignbit_b32  v51, v37, v37, 27
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v51, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_xor_b32       v51, v7, v46
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v43, v40, v43
        v_add_i32       v41, vcc, v41, v51
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v51, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        ds_read2_b32    v[52:53], v36 offset0:40 offset1:41
        v_xor_b32       v43, v51, v37
        v_add_i32       v42, vcc, v8, v42
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_add_i32       v42, vcc, v43, v42
        v_alignbit_b32  v43, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v51, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        v_alignbit_b32  v55, v63, v63, 23
        v_xor_b32       v43, v43, v51
        v_add_i32       v40, vcc, v40, v54
        v_xor_b32       v51, v46, v55
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v51, v52
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v51, v41, 0, v42
        v_alignbit_b32  v52, v40, v40, 27
        ds_read2_b32    v[54:55], v36 offset0:42 offset1:43
        v_xor_b32       v43, v43, v51
        v_add_i32       v37, vcc, v37, v52
        v_add_i32       v37, vcc, v43, v37
        v_add_i32       v37, vcc, v53, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v51, v42, 0, v40
        v_alignbit_b32  v52, v37, v37, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v51, v48, v50
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v51
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v51, v40, 0, v37
        v_alignbit_b32  v52, v38, v38, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v51, v63, v63, 22
        ds_read2_b32    v[52:53], v36 offset0:44 offset1:45
        v_add_i32       v41, vcc, v43, v41
        v_xor_b32       v43, v55, v51
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v54, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v56, v44, v48
        v_xor_b32       v43, v43, v54
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v54, v47, v56
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v52
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v52, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        ds_read2_b32    v[55:56], v36 offset0:46 offset1:47
        v_xor_b32       v43, v43, v52
        v_add_i32       v40, vcc, v40, v54
        v_add_i32       v40, vcc, v43, v40
        v_add_i32       v40, vcc, v53, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v52, v41, 0, v42
        v_alignbit_b32  v53, v40, v40, 27
        v_alignbit_b32  v54, v63, v63, 21
        v_xor_b32       v43, v43, v52
        v_add_i32       v37, vcc, v37, v53
        v_xor_b32       v52, v46, v54
        v_add_i32       v37, vcc, v43, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v55, v52
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v52, v42, 0, v40
        v_alignbit_b32  v53, v37, v37, 27
        v_xor_b32       v43, v43, v52
        v_add_i32       v38, vcc, v38, v53
        v_xor_b32       v52, v46, v50
        ds_read2_b32    v[57:58], v36 offset0:48 offset1:49
        v_add_i32       v38, vcc, v43, v38
        v_xor_b32       v43, v56, v52
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v44, v45
        v_bfi_b32       v44, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        v_xor_b32       v43, v52, v43
        v_xor_b32       v44, v44, v53
        v_add_i32       v41, vcc, v41, v55
        v_xor_b32       v43, v51, v43
        v_add_i32       v41, vcc, v44, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v57
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v44, v37, 0, v38
        v_alignbit_b32  v53, v41, v41, 27
        v_xor_b32       v43, v43, v44
        v_add_i32       v42, vcc, v42, v53
        v_alignbit_b32  v44, v63, v63, 20
        ds_read2_b32    v[55:56], v36 offset0:50 offset1:51
        v_add_i32       v42, vcc, v43, v42
        v_xor_b32       v43, v58, v44
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v57, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v57
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v50, v55
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v53, v41, 0, v42
        v_alignbit_b32  v55, v40, v40, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v37, vcc, v37, v55
        ds_read2_b32    v[57:58], v36 offset0:52 offset1:53
        v_add_i32       v37, vcc, v43, v37
        v_xor_b32       v43, v49, v56
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v53, v42, 0, v40
        v_alignbit_b32  v55, v37, v37, 27
        v_alignbit_b32  v56, v63, v63, 19
        v_xor_b32       v43, v43, v53
        v_add_i32       v38, vcc, v38, v55
        v_xor_b32       v53, v52, v56
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v57
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        ds_read2_b32    v[59:60], v36 offset0:54 offset1:55
        v_xor_b32       v43, v43, v53
        v_add_i32       v41, vcc, v41, v55
        v_add_i32       v41, vcc, v43, v41
        v_add_i32       v41, vcc, v58, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v53, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v57, v47, v51
        v_xor_b32       v43, v43, v53
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v53, v44, v57
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v59
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v55, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v55
        v_alignbit_b32  v53, v63, v63, 18
        ds_read2_b32    v[57:58], v36 offset0:56 offset1:57
        v_add_i32       v40, vcc, v43, v40
        v_xor_b32       v43, v53, v60
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v47, v49
        v_bfi_b32       v55, v38, v41, v42
        v_bfi_b32       v59, v41, 0, v42
        v_alignbit_b32  v60, v40, v40, 27
        v_xor_b32       v51, v51, v43
        v_xor_b32       v55, v55, v59
        v_add_i32       v37, vcc, v37, v60
        v_xor_b32       v51, v54, v51
        v_add_i32       v37, vcc, v55, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v51, v57
        v_add_i32       v37, vcc, v37, v51
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v51, v41, v42, v40
        v_bfi_b32       v55, v42, 0, v40
        v_alignbit_b32  v57, v37, v37, 27
        v_xor_b32       v51, v51, v55
        v_add_i32       v38, vcc, v38, v57
        ds_read2_b32    v[59:60], v36 offset0:58 offset1:59
        v_add_i32       v38, vcc, v51, v38
        v_xor_b32       v51, v50, v58
        v_add_i32       v38, vcc, v38, v51
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_bfi_b32       v51, v42, v40, v37
        v_bfi_b32       v55, v40, 0, v37
        v_alignbit_b32  v57, v38, v38, 27
        v_alignbit_b32  v58, v63, v63, 17
        v_xor_b32       v51, v51, v55
        v_add_i32       v41, vcc, v41, v57
        v_xor_b32       v52, v52, v58
        v_add_i32       v41, vcc, v51, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v52, v59
        v_add_i32       v41, vcc, v41, v51
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v51, v40, v37, v38
        v_bfi_b32       v52, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        ds_read2_b32    v[61:62], v36 offset0:60 offset1:61
        v_xor_b32       v51, v51, v52
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v52, v50, v44
        v_add_i32       v42, vcc, v51, v42
        v_xor_b32       v51, v52, v60
        v_add_i32       v42, vcc, v42, v51
        v_xor_b32       v51, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v46, v46, v47
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_xor_b32       v51, v51, v38
        v_xor_b32       v46, v52, v46
        v_alignbit_b32  v55, v42, v42, 27
        v_add_i32       v40, vcc, v40, v51
        v_xor_b32       v46, v53, v46
        v_add_i32       v40, vcc, v55, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v46, v61
        v_add_i32       v40, vcc, v40, v46
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v46, v42, v38
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v46, v41, v46
        ds_read2_b32    v[59:60], v36 offset0:62 offset1:63
        v_add_i32       v37, vcc, v37, v46
        v_alignbit_b32  v46, v40, v40, 27
        v_alignbit_b32  v51, v63, v63, 16
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v51, v62
        v_xor_b32       v55, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v55, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v38, vcc, v38, v46
        v_alignbit_b32  v46, v37, v37, 27
        v_xor_b32       v49, v49, v52
        v_add_i32       v38, vcc, v38, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v49, v59
        v_add_i32       v38, vcc, v38, v46
        v_xor_b32       v46, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v46, v46, v40
        ds_read2_b32    v[61:62], v36 offset0:64 offset1:65
        v_alignbit_b32  v49, v38, v38, 27
        v_add_i32       v41, vcc, v41, v46
        v_add_i32       v41, vcc, v49, v41
        v_xor_b32       v46, v50, v60
        v_add_i32       v41, vcc, v41, v46
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v46, v38, v40
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v46, v37, v46
        v_xor_b32       v43, v43, v52
        v_alignbit_b32  v49, v63, v63, 15
        v_add_i32       v42, vcc, v42, v46
        v_alignbit_b32  v46, v41, v41, 27
        v_xor_b32       v43, v43, v49
        v_add_i32       v42, vcc, v42, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_xor_b32       v46, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, v42, v43
        ds_read2_b32    v[59:60], v36 offset0:66 offset1:67
        v_xor_b32       v43, v46, v38
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v62
        v_xor_b32       v43, v43, v41
        v_alignbit_b32  v46, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v53, v51
        v_add_i32       v37, vcc, v46, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v59
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v43, v40, v41
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v42, v43
        v_alignbit_b32  v46, v63, v63, 14
        ds_read2_b32    v[61:62], v36 offset0:68 offset1:69
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v49, v50, v46
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v49, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v40
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v49, v54, v53
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v58, v49
        v_add_i32       v41, vcc, v41, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v61
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        ds_read2_b32    v[59:60], v36 offset0:70 offset1:71
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v43, v43, v37
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_add_i32       v42, vcc, v42, v62
        v_xor_b32       v43, v38, v43
        v_alignbit_b32  v49, v63, v63, 13
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v49, v44, v49
        v_add_i32       v40, vcc, v40, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v59
        v_xor_b32       v49, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v49, v41
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        ds_read2_b32    v[61:62], v36 offset0:72 offset1:73
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v49, v44, v51
        v_xor_b32       v45, v45, v54
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v45, v44, v45
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v45, v56, v45
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v43, v42
        v_xor_b32       v45, v51, v45
        v_alignbit_b32  v49, v37, v37, 27
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v46, v45
        v_add_i32       v38, vcc, v49, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v43, v40, v43
        ds_read2_b32    v[54:55], v36 offset0:74 offset1:75
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v45, v63, v63, 12
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v45, v62
        v_xor_b32       v49, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v43, v41, v41, 27
        v_xor_b32       v49, v50, v51
        v_add_i32       v42, vcc, v42, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v54
        v_add_i32       v42, vcc, v42, v43
        v_xor_b32       v43, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_xor_b32       v43, v43, v38
        v_xor_b32       v48, v48, v44
        ds_read2_b32    v[56:57], v36 offset0:76 offset1:77
        v_alignbit_b32  v49, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v53, v48
        v_add_i32       v40, vcc, v49, v40
        v_xor_b32       v43, v43, v55
        v_xor_b32       v47, v47, v50
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v42, v38
        v_xor_b32       v44, v44, v47
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v43, v41, v43
        v_xor_b32       v44, v51, v44
        v_alignbit_b32  v48, v63, v63, 11
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v44, v44, v48
        v_add_i32       v37, vcc, v37, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v44, v56
        v_xor_b32       v44, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v43
        ds_read_b32     v36, v36 offset:312
        v_xor_b32       v43, v44, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v43, v37, v37, 27
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v44, v58, v47
        v_add_i32       v38, vcc, v38, v57
        v_xor_b32       v43, v43, v40
        v_xor_b32       v44, v46, v44
        v_alignbit_b32  v46, v38, v38, 27
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v45, v44
        v_add_i32       v41, vcc, v46, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v36, v43, v36
        v_add_i32       v36, vcc, v41, v36
        v_add_i32       v41, vcc, 0xba306d5f, v36
        v_bfe_u32       v43, v41, 10, 12
        ds_read_u8      v43, v43 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v43, v43, 0, 8
        v_cmp_lg_i32    s[14:15], v43, 0
        s_mov_b64       s[20:21], exec
        s_andn2_b64     exec, s[20:21], s[14:15]
        v_alignbit_b32  v43, v38, v38, 2
        s_cbranch_execz .L6820_1
        v_add_i32       v43, vcc, 0x98badcfe, v43
        v_lshlrev_b32   v44, 8, v36
        v_add_i32       v44, vcc, 0x306d5f00, v44
        v_lshrrev_b32   v45, 24, v43
        s_mov_b32       s26, 0x3fffff00
        v_bfi_b32       v44, s26, v44, v45
        v_lshrrev_b32   v45, 6, v44
        v_add_i32       v45, vcc, s8, v45
        v_mov_b32       v46, s9
        v_addc_u32      v46, vcc, v46, 0, vcc
        buffer_load_ubyte v45, v[45:46], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v45
        s_and_saveexec_b64 s[26:27], vcc
        v_mov_b32       v45, 0
        s_cbranch_execz .L6800_1
        ds_read_b32     v45, v45 offset:316
        v_xor_b32       v38, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v37, v38, v37
        v_add_i32       v36, vcc, 0xca62c1d6, v36
        v_alignbit_b32  v38, v63, v63, 10
        v_add_i32       v37, vcc, v42, v37
        v_alignbit_b32  v36, v36, v36, 27
        v_xor_b32       v38, v50, v38
        v_add_i32       v36, vcc, v37, v36
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v37, v38, v45
        v_add_i32       v36, vcc, v36, v37
        v_add_i32       v63, vcc, 0x31a7e4d7, v36
        s_mov_b64       s[44:45], exec
        s_mov_b64       s[46:47], exec
        v_mov_b32       v37, 0
        v_mov_b32       v40, s1
        v_mov_b32       v39, s0
        s_movk_i32      s48, 0x0
        s_movk_i32      s49, 0x0
.L6648_1:
        v_cmp_gt_i32    s[50:51], v37, v39
        v_cmp_eq_i32    vcc, v44, v40
        s_andn2_b64     s[48:49], s[48:49], exec
        s_or_b64        s[48:49], vcc, s[48:49]
        s_or_b64        vcc, s[50:51], vcc
        s_and_saveexec_b64 s[50:51], vcc
        s_andn2_b64     s[46:47], s[46:47], exec
        s_cbranch_scc0  .L6768_1
        s_and_b64       exec, s[50:51], s[46:47]
        v_add_i32       v38, vcc, v37, v39
        v_ashrrev_i32   v47, 1, v38
        v_ashrrev_i32   v48, 31, v47
        v_lshl_b64      v[45:46], v[47:48], 2
        v_add_i32       v45, vcc, s6, v45
        v_mov_b32       v42, s7
        v_addc_u32      v46, vcc, v42, v46, vcc
        buffer_load_dword v40, v[45:46], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[50:51], v40, v44
        v_add_i32       v42, vcc, -1, v47
        v_add_i32       v38, vcc, 1, v47
        v_cndmask_b32   v39, v39, v42, s[50:51]
        v_cndmask_b32   v37, v38, v37, s[50:51]
        s_branch        .L6648_1
.L6768_1:
        s_mov_b64       exec, s[44:45]
        s_and_saveexec_b64 s[44:45], s[48:49]
        v_mov_b32       v36, 1
        s_cbranch_execz .L6792_1
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L6856_1
.L6792_1:
        s_and_b64       exec, s[44:45], s[12:13]
        v_mov_b32       v36, 1
.L6800_1:
        s_andn2_b64     exec, s[26:27], exec
        s_and_b64       exec, exec, s[12:13]
        v_mov_b32       v36, 0
        s_cbranch_execz .L6816_1
.L6816_1:
        s_and_b64       exec, s[26:27], s[12:13]
.L6820_1:
        s_andn2_b64     exec, s[20:21], exec
        s_and_b64       exec, exec, s[12:13]
        v_cndmask_b32   v43, 0, -1, s[14:15]
        s_cbranch_execz .L6844_1
        v_mov_b32       v36, 0
.L6844_1:
        s_and_b64       exec, s[20:21], s[12:13]
        v_add_i32       v10, vcc, 1, v10
        s_branch        .L1964_1
.L6856_1:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v36
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[0:1], vcc
        v_mov_b32       v0, 0x400
        s_cbranch_execz .L6892_1
        buffer_store_dword v0, v[4:5], s[28:31], 0 addr64
.L6892_1:
        s_andn2_b64     exec, s[0:1], exec
        s_cbranch_execz .L7432_1
        s_load_dwordx4  s[8:11], s[2:3], 0x50
        v_lshrrev_b32   v6, 26, v63
        v_add_i32       v20, vcc, s4, v6
        v_mov_b32       v13, s5
        v_addc_u32      v21, vcc, v13, 0, vcc
        v_bfe_u32       v15, v63, 20, 6
        v_add_i32       v15, vcc, s4, v15
        v_addc_u32      v16, vcc, v13, 0, vcc
        v_bfe_u32       v17, v63, 14, 6
        v_add_i32       v17, vcc, s4, v17
        v_addc_u32      v18, vcc, v13, 0, vcc
        v_bfe_u32       v19, v63, 8, 6
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v6, v[20:21], s[8:11], 0 addr64
        v_add_i32       v22, vcc, s4, v19
        v_addc_u32      v23, vcc, v13, 0, vcc
        v_bfe_u32       v20, v63, 2, 6
        v_lshrrev_b32   v21, 28, v41
        v_lshlrev_b32   v8, 4, v63
        buffer_load_ubyte v15, v[15:16], s[8:11], 0 addr64
        v_add_i32       v11, vcc, s4, v20
        v_addc_u32      v12, vcc, v13, 0, vcc
        v_bfi_b32       v8, 48, v8, v21
        buffer_load_ubyte v17, v[17:18], s[8:11], 0 addr64
        v_add_i32       v24, vcc, s4, v8
        v_addc_u32      v25, vcc, v13, 0, vcc
        v_bfe_u32       v21, v41, 22, 6
        buffer_load_ubyte v14, v[22:23], s[8:11], 0 addr64
        v_add_i32       v26, vcc, s4, v21
        v_addc_u32      v27, vcc, v13, 0, vcc
        v_bfe_u32       v22, v41, 16, 6
        buffer_load_ubyte v16, v[11:12], s[8:11], 0 addr64
        v_add_i32       v28, vcc, s4, v22
        v_addc_u32      v29, vcc, v13, 0, vcc
        v_bfe_u32       v23, v41, 10, 6
        buffer_load_ubyte v8, v[24:25], s[8:11], 0 addr64
        v_add_i32       v30, vcc, s4, v23
        v_addc_u32      v31, vcc, v13, 0, vcc
        v_bfe_u32       v24, v41, 4, 6
        v_lshrrev_b32   v25, 30, v43
        v_lshlrev_b32   v11, 2, v41
        buffer_load_ubyte v19, v[26:27], s[8:11], 0 addr64
        v_add_i32       v23, vcc, s4, v24
        v_addc_u32      v24, vcc, v13, 0, vcc
        v_bfi_b32       v11, 60, v11, v25
        buffer_load_ubyte v20, v[28:29], s[8:11], 0 addr64
        v_add_i32       v25, vcc, s4, v11
        v_addc_u32      v26, vcc, v13, 0, vcc
        v_bfe_u32       v12, v43, 24, 6
        buffer_load_ubyte v18, v[30:31], s[8:11], 0 addr64
        v_add_i32       v12, vcc, s4, v12
        v_addc_u32      v13, vcc, v13, 0, vcc
        buffer_load_ubyte v21, v[23:24], s[8:11], 0 addr64
        buffer_load_ubyte v11, v[25:26], s[8:11], 0 addr64
        s_nop           0x0
        buffer_load_ubyte v12, v[12:13], s[8:11], 0 addr64
        buffer_store_byte v3, v[4:5], s[28:31], 0 offset:17 glc addr64
        buffer_store_byte v1, v[4:5], s[28:31], 0 offset:18 glc addr64
        buffer_store_byte v34, v[4:5], s[28:31], 0 offset:19 glc addr64
        buffer_store_byte v35, v[4:5], s[28:31], 0 offset:20 glc addr64
        buffer_store_byte v9, v[4:5], s[28:31], 0 offset:24 glc addr64
        buffer_store_byte v2, v[4:5], s[28:31], 0 offset:28 glc addr64
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:5 glc addr64
        buffer_store_byte v15, v[4:5], s[28:31], 0 offset:6 glc addr64
        buffer_store_byte v17, v[4:5], s[28:31], 0 offset:7 glc addr64
        buffer_store_byte v14, v[4:5], s[28:31], 0 offset:8 glc addr64
        buffer_store_byte v16, v[4:5], s[28:31], 0 offset:9 glc addr64
        buffer_store_byte v8, v[4:5], s[28:31], 0 offset:10 glc addr64
        buffer_store_byte v19, v[4:5], s[28:31], 0 offset:11 glc addr64
        buffer_store_byte v20, v[4:5], s[28:31], 0 offset:12 glc addr64
        buffer_store_byte v18, v[4:5], s[28:31], 0 offset:13 glc addr64
        buffer_store_byte v21, v[4:5], s[28:31], 0 offset:14 glc addr64
        v_mov_b32       v0, 1
        buffer_store_byte v11, v[4:5], s[28:31], 0 offset:15 glc addr64
        v_add_i32       v1, vcc, 1, v10
        buffer_store_byte v12, v[4:5], s[28:31], 0 offset:16 glc addr64
        buffer_store_byte v0, v[4:5], s[28:31], 0 offset:4 glc addr64
        buffer_store_dword v1, v[4:5], s[28:31], 0 addr64
.L7432_1:
        s_endpgm
.kernel OpenCL_SHA1_PerformSearching_Flexible
    .header
        .fill 8, 1, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00
        .byte 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        .fill 8, 1, 0x00
    .metadata
        .ascii ";ARGSTART:__OpenCL_OpenCL_SHA1_PerformSearching_Flexible_kernel\n"
        .ascii ";version:3:1:111\n"
        .ascii ";device:hawaii\n"
        .ascii ";uniqueid:1026\n"
        .ascii ";memory:uavprivate:0\n"
        .ascii ";memory:hwlocal:4416\n"
        .ascii ";memory:hwregion:0\n"
        .ascii ";pointer:outputArray:struct:1:1:0:uav:12:32:RW:0:0\n"
        .ascii ";pointer:key:u8:1:1:16:c:13:1:RO:0:0\n"
        .ascii ";constarg:1:key\n"
        .ascii ";pointer:tripcodeChunkArray:u32:1:1:32:uav:14:4:RO:0:0\n"
        .ascii ";constarg:2:tripcodeChunkArray\n"
        .ascii ";value:numTripcodeChunk:u32:1:1:48\n"
        .ascii ";pointer:keyCharTable_OneByte:u8:1:1:64:c:11:1:RO:0:0\n"
        .ascii ";constarg:4:keyCharTable_OneByte\n"
        .ascii ";pointer:keyCharTable_FirstByte:u8:1:1:80:c:15:1:RO:0:0\n"
        .ascii ";constarg:5:keyCharTable_FirstByte\n"
        .ascii ";pointer:keyCharTable_SecondByte:u8:1:1:96:c:11:1:RO:0:0\n"
        .ascii ";constarg:6:keyCharTable_SecondByte\n"
        .ascii ";pointer:keyCharTable_SecondByteAndOneByte:u8:1:1:112:c:16:1:RO:0:0\n"
        .ascii ";constarg:7:keyCharTable_SecondByteAndOneByte\n"
        .ascii ";pointer:smallChunkBitmap_constant:u8:1:1:128:c:17:1:RO:0:0\n"
        .ascii ";constarg:8:smallChunkBitmap_constant\n"
        .ascii ";pointer:chunkBitmap:u8:1:1:144:uav:18:1:RO:0:0\n"
        .ascii ";constarg:9:chunkBitmap\n"
        .ascii ";memory:datareqd\n"
        .ascii ";function:1:1037\n"
        .ascii ";memory:64bitABI\n"
        .ascii ";uavid:11\n"
        .ascii ";printfid:9\n"
        .ascii ";cbid:10\n"
        .ascii ";privateid:8\n"
        .ascii ";reflection:0:GPUOutput*\n"
        .ascii ";reflection:1:uchar*\n"
        .ascii ";reflection:2:uint*\n"
        .ascii ";reflection:3:uint\n"
        .ascii ";reflection:4:uchar*\n"
        .ascii ";reflection:5:uchar*\n"
        .ascii ";reflection:6:uchar*\n"
        .ascii ";reflection:7:uchar*\n"
        .ascii ";reflection:8:uchar*\n"
        .ascii ";reflection:9:uchar*\n"
        .ascii ";ARGEND:__OpenCL_OpenCL_SHA1_PerformSearching_Flexible_kernel\n"
    .data
        .fill 4736, 1, 0x00
    .inputs
    .outputs
    .uav
        .entry 12, 4, 0, 5
        .entry 14, 4, 0, 5
        .entry 18, 4, 0, 5
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
        .cbmask 13, 0
        .cbmask 11, 0
        .cbmask 15, 0
        .cbmask 11, 0
        .cbmask 16, 0
        .cbmask 17, 0
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
        .entry 0x80001041, 0x0000004c
        .entry 0x80001042, 0x00000046
        .entry 0x80001863, 0x00000066
        .entry 0x80001864, 0x00000100
        .entry 0x80001043, 0x000000c0
        .entry 0x80001044, 0x00000000
        .entry 0x80001045, 0x00000000
        .entry 0x00002e13, 0x00048098
        .entry 0x8000001c, 0x00000100
        .entry 0x8000001d, 0x00000000
        .entry 0x8000001e, 0x00000000
        .entry 0x80001841, 0x00000000
        .entry 0x8000001f, 0x0007f400
        .entry 0x80001843, 0x0007f400
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
        .entry 0x80000082, 0x00000900
    .subconstantbuffers
    .uavmailboxsize 0
    .uavopmask
        .byte 0x00, 0xf4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00
        .fill 120, 1, 0x00
    .text
        s_mov_b32       m0, 0x10000
        s_buffer_load_dwordx2 s[0:1], s[8:11], 0x4
        s_load_dwordx4  s[16:19], s[2:3], 0x68
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 1
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 11
        s_addc_u32      s21, s1, 0
        v_mov_b32       v1, s14
        v_mov_b32       v2, s15
        v_mov_b32       v3, s20
        v_mov_b32       v4, s21
        v_mov_b32       v5, s0
        v_mov_b32       v6, s1
        buffer_load_ubyte v1, v[1:2], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[3:4], s[16:19], 0 addr64
        buffer_load_ubyte v3, v[5:6], s[16:19], 0 addr64
        s_buffer_load_dword s13, s[4:7], 0x4
        s_buffer_load_dword s14, s[4:7], 0x18
        s_buffer_load_dword s15, s[4:7], 0x1c
        s_waitcnt       lgkmcnt(0)
        s_min_u32       s13, s13, 0xffff
        s_mul_i32       s13, s12, s13
        s_buffer_load_dwordx2 s[20:21], s[8:11], 0x0
        s_buffer_load_dwordx2 s[22:23], s[8:11], 0x14
        s_buffer_load_dwordx2 s[24:25], s[8:11], 0x1c
        s_add_u32       s13, s13, s14
        v_add_i32       v4, vcc, s13, v0
        s_add_u32       s12, s12, s15
        v_ashrrev_i32   v5, 31, v4
        s_load_dwordx4  s[28:31], s[2:3], 0x60
        s_load_dwordx4  s[32:35], s[2:3], 0x78
        s_load_dwordx4  s[36:39], s[2:3], 0x80
        s_ashr_i32      s13, s12, 6
        v_and_b32       v6, 63, v0
        s_and_b32       s12, s12, 63
        v_lshl_b64      v[4:5], v[4:5], 5
        s_waitcnt       vmcnt(1)
        v_add_i32       v2, vcc, s13, v2
        v_add_i32       v1, vcc, v1, v6
        s_waitcnt       vmcnt(0)
        v_add_i32       v3, vcc, s12, v3
        s_add_u32       s12, s0, 2
        s_addc_u32      s13, s1, 0
        s_add_u32       s14, s0, 3
        s_addc_u32      s15, s1, 0
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v4, vcc, s20, v4
        v_mov_b32       v6, s21
        v_addc_u32      v5, vcc, v6, v5, vcc
        v_mov_b32       v6, 0
        v_ashrrev_i32   v7, 31, v2
        v_add_i32       v14, vcc, s24, v2
        v_mov_b32       v8, s25
        v_addc_u32      v15, vcc, v8, v7, vcc
        v_ashrrev_i32   v9, 31, v1
        v_add_i32       v7, vcc, s24, v1
        v_addc_u32      v8, vcc, v8, v9, vcc
        v_ashrrev_i32   v9, 31, v3
        v_add_i32       v16, vcc, s22, v3
        v_mov_b32       v10, s23
        v_addc_u32      v17, vcc, v10, v9, vcc
        v_mov_b32       v10, s12
        v_mov_b32       v11, s13
        v_mov_b32       v12, s14
        v_mov_b32       v13, s15
        buffer_load_ubyte v10, v[10:11], s[16:19], 0 addr64
        buffer_load_ubyte v11, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[14:15], s[36:39], 0 addr64
        buffer_load_ubyte v1, v[7:8], s[36:39], 0 addr64
        buffer_load_ubyte v3, v[16:17], s[32:35], 0 addr64
        s_buffer_load_dwordx2 s[4:5], s[4:7], 0x20
        s_buffer_load_dwordx2 s[6:7], s[8:11], 0x8
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dwordx2 s[14:15], s[8:11], 0x20
        s_buffer_load_dwordx2 s[8:9], s[8:11], 0x24
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:4 glc addr64
        v_cmp_eq_i32    vcc, 0, v0
        s_and_saveexec_b64 s[10:11], vcc
        s_cbranch_execz .L892_2
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s14, 7
        s_addc_u32      s15, s15, 0
        s_load_dwordx4  s[40:43], s[2:3], 0x88
        s_mov_b64       s[20:21], exec
        s_mov_b64       s[26:27], exec
        v_mov_b32       v6, 0
        v_mov_b32       v7, 0
.L400_2:
        v_add_i32       v8, vcc, s14, v6
        v_mov_b32       v9, s15
        v_addc_u32      v9, vcc, v9, v7, vcc
        v_add_i32       v12, vcc, v8, -7
        v_addc_u32      v13, vcc, v9, -1, vcc
        v_add_i32       v14, vcc, v8, -6
        v_addc_u32      v15, vcc, v9, -1, vcc
        v_add_i32       v16, vcc, v8, -5
        v_addc_u32      v17, vcc, v9, -1, vcc
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v12, v[12:13], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -4
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v14, v[14:15], s[40:43], 0 addr64
        v_add_i32       v23, vcc, v8, -3
        v_addc_u32      v24, vcc, v9, -1, vcc
        buffer_load_ubyte v16, v[16:17], s[40:43], 0 addr64
        v_add_i32       v19, vcc, v8, -2
        v_addc_u32      v20, vcc, v9, -1, vcc
        buffer_load_ubyte v13, v[21:22], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -1
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v15, v[23:24], s[40:43], 0 addr64
        buffer_load_ubyte v17, v[19:20], s[40:43], 0 addr64
        buffer_load_ubyte v18, v[21:22], s[40:43], 0 addr64
        buffer_load_ubyte v19, v[8:9], s[40:43], 0 addr64
        buffer_load_ubyte v20, v[8:9], s[40:43], 0 offset:1 addr64
        buffer_load_ubyte v21, v[8:9], s[40:43], 0 offset:2 addr64
        buffer_load_ubyte v22, v[8:9], s[40:43], 0 offset:3 addr64
        buffer_load_ubyte v23, v[8:9], s[40:43], 0 offset:4 addr64
        buffer_load_ubyte v24, v[8:9], s[40:43], 0 offset:5 addr64
        buffer_load_ubyte v25, v[8:9], s[40:43], 0 offset:6 addr64
        buffer_load_ubyte v26, v[8:9], s[40:43], 0 offset:7 addr64
        buffer_load_ubyte v8, v[8:9], s[40:43], 0 offset:8 addr64
        ds_write_b8     v6, v12 offset:320
        s_waitcnt       vmcnt(14)
        ds_write_b8     v6, v14 offset:321
        s_waitcnt       vmcnt(13)
        ds_write_b8     v6, v16 offset:322
        s_waitcnt       vmcnt(12)
        ds_write_b8     v6, v13 offset:323
        s_waitcnt       vmcnt(11)
        ds_write_b8     v6, v15 offset:324
        s_waitcnt       vmcnt(10)
        ds_write_b8     v6, v17 offset:325
        s_waitcnt       vmcnt(9)
        ds_write_b8     v6, v18 offset:326
        s_waitcnt       vmcnt(8)
        ds_write_b8     v6, v19 offset:327
        s_waitcnt       vmcnt(7)
        ds_write_b8     v6, v20 offset:328
        s_waitcnt       vmcnt(6)
        ds_write_b8     v6, v21 offset:329
        s_waitcnt       vmcnt(5)
        ds_write_b8     v6, v22 offset:330
        s_waitcnt       vmcnt(4)
        ds_write_b8     v6, v23 offset:331
        s_waitcnt       vmcnt(3)
        ds_write_b8     v6, v24 offset:332
        s_waitcnt       vmcnt(2)
        ds_write_b8     v6, v25 offset:333
        s_waitcnt       vmcnt(1)
        ds_write_b8     v6, v26 offset:334
        v_add_i32       v9, vcc, v6, 16
        v_addc_u32      v7, vcc, v7, 0, vcc
        s_movk_i32      s13, 0x1000
        s_waitcnt       vmcnt(0)
        ds_write_b8     v6, v8 offset:335
        v_cmp_eq_i32    vcc, s13, v9
        s_and_saveexec_b64 s[44:45], vcc
        s_andn2_b64     s[26:27], s[26:27], exec
        s_cbranch_scc0  .L892_2
        s_and_b64       exec, s[44:45], s[26:27]
        v_mov_b32       v6, v9
        s_branch        .L400_2
.L892_2:
        s_mov_b64       exec, s[10:11]
        s_add_u32       s10, s0, 5
        s_addc_u32      s11, s1, 0
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 4
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 6
        s_addc_u32      s21, s1, 0
        v_mov_b32       v6, s10
        v_mov_b32       v7, s11
        v_mov_b32       v8, s14
        v_mov_b32       v9, s15
        s_add_u32       s10, s0, 8
        s_addc_u32      s11, s1, 0
        v_mov_b32       v12, s20
        v_mov_b32       v13, s21
        v_mov_b32       v14, s10
        v_mov_b32       v15, s11
        s_add_u32       s10, s0, 9
        s_addc_u32      s11, s1, 0
        buffer_load_ubyte v6, v[6:7], s[16:19], 0 addr64
        buffer_load_ubyte v7, v[8:9], s[16:19], 0 addr64
        s_add_u32       s14, s0, 7
        s_addc_u32      s15, s1, 0
        s_add_u32       s0, s0, 10
        s_addc_u32      s1, s1, 0
        v_mov_b32       v8, s10
        v_mov_b32       v9, s11
        buffer_load_ubyte v12, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v13, v[14:15], s[16:19], 0 addr64
        v_mov_b32       v14, s14
        v_mov_b32       v15, s15
        v_mov_b32       v16, s0
        v_mov_b32       v17, s1
        buffer_load_ubyte v8, v[8:9], s[16:19], 0 addr64
        buffer_load_ubyte v9, v[14:15], s[16:19], 0 addr64
        buffer_load_ubyte v14, v[16:17], s[16:19], 0 addr64
        s_waitcnt       vmcnt(6)
        v_lshlrev_b32   v6, 16, v6
        s_waitcnt       vmcnt(5)
        v_lshlrev_b32   v7, 24, v7
        v_or_b32        v6, v6, v7
        s_waitcnt       vmcnt(4)
        v_lshlrev_b32   v7, 8, v12
        s_waitcnt       vmcnt(3)
        v_lshlrev_b32   v12, 24, v13
        s_movk_i32      s0, 0xff
        v_or_b32        v6, v6, v7
        v_bfi_b32       v7, s0, v2, v12
        s_waitcnt       vmcnt(2)
        v_lshlrev_b32   v8, 16, v8
        s_waitcnt       vmcnt(1)
        v_or_b32        v6, v9, v6
        v_mov_b32       v12, 0
        v_or_b32        v7, v7, v8
        s_waitcnt       vmcnt(0)
        v_lshlrev_b32   v8, 8, v14
        ds_write2_b32   v12, v12, v6 offset1:1
        v_or_b32        v6, v7, v8
        v_mov_b32       v7, 0x80000000
        ds_write2_b32   v12, v6, v7 offset0:2 offset1:3
        ds_write2_b32   v12, v12, v12 offset0:4 offset1:5
        ds_write2_b32   v12, v12, v12 offset0:6 offset1:7
        ds_write2_b32   v12, v12, v12 offset0:8 offset1:9
        ds_write2_b32   v12, v12, v12 offset0:10 offset1:11
        ds_write2_b32   v12, v12, v12 offset0:12 offset1:13
        v_mov_b32       v7, 0x60
        ds_write2_b32   v12, v12, v7 offset0:14 offset1:15
        v_alignbit_b32  v6, v6, v6, 31
        ds_write_b32    v12, v6 offset:64
        s_movk_i32      s0, 0x0
        s_movk_i32      s1, 0x0
.L1260_2:
        v_mov_b32       v6, s0
        ds_read2_b32    v[7:8], v6 offset0:14 offset1:15
        ds_read2_b32    v[12:13], v6 offset0:9 offset1:10
        ds_read2_b32    v[14:15], v6 offset0:3 offset1:4
        ds_read2_b32    v[16:17], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(2)
        v_xor_b32       v8, v8, v13
        v_xor_b32       v7, v7, v12
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v8, v8, v15
        v_xor_b32       v7, v14, v7
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v8, v17, v8
        v_xor_b32       v7, v16, v7
        v_alignbit_b32  v8, v8, v8, 31
        v_alignbit_b32  v7, v7, v7, 31
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:16 offset1:11
        ds_read_b32     v12, v6 offset:20
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v7, v7, v8
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v7, v7, v12
        v_xor_b32       v7, v14, v7
        v_alignbit_b32  v7, v7, v7, 31
        ds_write_b32    v6, v7 offset:76
        s_add_u32       s0, s0, 12
        s_addc_u32      s1, s1, 0
        s_cmp_eq_i32    s0, 0xfc
        s_cbranch_scc1  .L1432_2
        s_branch        .L1260_2
.L1432_2:
        v_mov_b32       v6, 0
        ds_read2_b32    v[7:8], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:1 offset1:2
        ds_read2_b32    v[7:8], v6 offset0:17 offset1:18
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:20 offset1:21
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        ds_write2_b32   v6, v7, v8 offset0:20 offset1:21
        ds_read2_b32    v[7:8], v6 offset0:23 offset1:26
        ds_read2_b32    v[12:13], v6 offset0:27 offset1:29
        s_waitcnt       lgkmcnt(1)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v12, vcc, 0x6ed9eba1, v12
        ds_write2_b32   v6, v7, v8 offset0:23 offset1:26
        v_add_i32       v7, vcc, 0x6ed9eba1, v13
        ds_write2_b32   v6, v12, v7 offset0:27 offset1:29
        ds_read2_b32    v[7:8], v6 offset0:33 offset1:39
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        ds_write2_b32   v6, v7, v8 offset0:33 offset1:39
        ds_read2_b32    v[7:8], v6 offset0:41 offset1:45
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0x8f1bbcdc, v8
        ds_write2_b32   v6, v7, v8 offset0:41 offset1:45
        ds_read2_b32    v[7:8], v6 offset0:53 offset1:65
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:53 offset1:65
        ds_read2_b32    v[7:8], v6 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0xca62c1d6, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        s_barrier
        ds_read2_b32    v[7:8], v6 offset0:38 offset1:39
        ds_read2_b32    v[12:13], v6 offset0:36 offset1:37
        ds_read2_b32    v[14:15], v6 offset0:34 offset1:35
        ds_read2_b32    v[16:17], v6 offset0:32 offset1:33
        ds_read2_b32    v[18:19], v6 offset0:30 offset1:31
        ds_read2_b32    v[20:21], v6 offset0:28 offset1:29
        ds_read2_b32    v[22:23], v6 offset0:26 offset1:27
        ds_read2_b32    v[24:25], v6 offset0:24 offset1:25
        ds_read2_b32    v[26:27], v6 offset0:22 offset1:23
        ds_read2_b32    v[28:29], v6 offset0:20 offset1:21
        ds_read2_b32    v[30:31], v6 offset0:18 offset1:19
        ds_read2_b32    v[32:33], v6 offset0:16 offset1:17
        v_lshlrev_b32   v6, 24, v3
        v_lshlrev_b32   v34, 16, v1
        v_or_b32        v6, v6, v34
        v_lshrrev_b32   v0, 2, v0
        v_and_b32       v0, 48, v0
        v_add_i32       v0, vcc, v10, v0
        s_waitcnt       lgkmcnt(0)
        s_barrier
        s_load_dwordx4  s[16:19], s[2:3], 0x90
        s_load_dwordx4  s[40:43], s[2:3], 0x70
        s_add_u32       s0, -1, s12
        s_waitcnt       lgkmcnt(0)
        s_bfe_u32       s11, s41, 0x100000
        s_mov_b32       s10, s40
        s_add_u32       s10, s10, s6
        s_addc_u32      s11, s11, s7
        s_load_dword    s1, s[10:11], 0x0
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[12:13], exec
        v_mov_b32       v10, v0
        v_mov_b32       v36, v11
        v_mov_b32       v35, 0
        v_mov_b32       v56, v34
        v_mov_b32       v53, v34
        v_mov_b32       v59, v34
        v_mov_b32       v42, v34
        v_mov_b32       v39, v34
        v_mov_b32       v43, v34
        v_mov_b32       v34, 0
        v_mov_b32       v72, 0
        v_mov_b32       v75, 0
        v_mov_b32       v44, 0
        v_mov_b32       v73, 0
        v_mov_b32       v45, 0
        v_mov_b32       v46, 0
        v_mov_b32       v47, 0
        v_mov_b32       v50, 0
.L2016_2:
        v_add_f32       v51, v47, v50
        v_add_f32       v51, v46, v51
        v_add_f32       v51, v45, v51
        v_add_f32       v51, v73, v51
        v_add_f32       v51, v44, v51
        v_add_f32       v51, v75, v51
        v_add_f32       v51, v72, v51
        v_add_f32       v51, v34, v51
        v_cmp_eq_u32    vcc, 0, v51
        s_and_saveexec_b64 s[14:15], vcc
        s_andn2_b64     exec, s[14:15], exec
        s_cbranch_execz .L2072_2
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L9040_2
.L2072_2:
        s_and_b64       exec, s[14:15], s[12:13]
        s_movk_i32      s14, 0x3ff
        v_cmp_gt_i32    s[14:15], v35, s14
        v_cndmask_b32   v34, v34, 1.0, s[14:15]
        v_cmp_eq_u32    vcc, 0, v34
        s_and_saveexec_b64 s[20:21], vcc
        v_ashrrev_i32   v10, 6, v35
        s_cbranch_execz .L9016_2
        v_bfe_u32       v36, v0, 0, 8
        v_add_i32       v10, vcc, v36, v10
        v_ashrrev_i32   v36, 31, v10
        v_add_i32       v40, vcc, s22, v10
        v_mov_b32       v37, s23
        v_addc_u32      v41, vcc, v37, v36, vcc
        s_waitcnt       lgkmcnt(0)
        s_barrier
        v_and_b32       v10, 63, v35
        v_bfe_u32       v38, v11, 0, 8
        v_add_i32       v10, vcc, v38, v10
        v_ashrrev_i32   v38, 31, v10
        v_add_i32       v37, vcc, s24, v10
        v_mov_b32       v39, s25
        v_addc_u32      v38, vcc, v39, v38, vcc
        buffer_load_ubyte v36, v[40:41], s[32:35], 0 addr64
        buffer_load_ubyte v10, v[37:38], s[36:39], 0 addr64
        v_mov_b32       v37, 0
        ds_read2_b32    v[38:39], v37 offset0:1 offset1:2
        s_waitcnt       vmcnt(1)
        v_lshlrev_b32   v40, 8, v36
        v_or_b32        v40, v6, v40
        s_waitcnt       vmcnt(0)
        v_or_b32        v40, v40, v10
        v_add_i32       v41, vcc, 0x9fb498b3, v40
        v_alignbit_b32  v42, v41, v41, 27
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v38, vcc, v42, v38
        v_add_i32       v38, vcc, 0xc2e5374, v38
        v_mov_b32       v42, 0x7bf36ae2
        s_mov_b32       s26, 0x59d148c0
        v_bfi_b32       v42, v41, s26, v42
        v_alignbit_b32  v51, v38, v38, 27
        v_add_i32       v42, vcc, v42, v51
        v_add_i32       v39, vcc, v39, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, 0x98badcfe, v39
        v_bfi_b32       v42, v38, v41, s26
        v_alignbit_b32  v51, v39, v39, 27
        v_add_i32       v42, vcc, v51, v42
        v_add_i32       v42, vcc, 0x7bf36ae2, v42
        v_xor_b32       v42, 0x80000000, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v51, v42, v42, 27
        v_bfi_b32       v52, v39, v38, v41
        v_add_i32       v51, vcc, v51, v52
        v_add_i32       v51, vcc, 0xb453c259, v51
        v_alignbit_b32  v39, v39, v39, 2
        v_alignbit_b32  v52, v51, v51, 27
        v_bfi_b32       v53, v42, v39, v38
        v_add_i32       v41, vcc, v41, v52
        v_add_i32       v41, vcc, v53, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v52, v41, v41, 27
        v_bfi_b32       v53, v51, v42, v39
        v_add_i32       v38, vcc, v38, v52
        v_add_i32       v38, vcc, v53, v38
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v52, v38, v38, 27
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v39, vcc, v39, v52
        v_bfi_b32       v52, v41, v51, v42
        v_add_i32       v39, vcc, v39, v52
        v_add_i32       v39, vcc, 0x5a827999, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v52, v39, v39, 27
        v_bfi_b32       v53, v38, v41, v51
        v_add_i32       v42, vcc, v42, v52
        v_add_i32       v42, vcc, v53, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v52, v42, v42, 27
        v_bfi_b32       v53, v39, v38, v41
        v_add_i32       v51, vcc, v51, v52
        v_add_i32       v51, vcc, v53, v51
        v_add_i32       v51, vcc, 0x5a827999, v51
        v_alignbit_b32  v52, v51, v51, 27
        v_alignbit_b32  v39, v39, v39, 2
        v_add_i32       v41, vcc, v41, v52
        v_bfi_b32       v52, v42, v39, v38
        v_add_i32       v41, vcc, v41, v52
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v52, v41, v41, 27
        v_bfi_b32       v53, v51, v42, v39
        v_add_i32       v38, vcc, v38, v52
        v_add_i32       v38, vcc, v53, v38
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v51, v51, v51, 2
        v_alignbit_b32  v52, v38, v38, 27
        v_bfi_b32       v53, v41, v51, v42
        v_add_i32       v39, vcc, v39, v52
        v_add_i32       v39, vcc, v53, v39
        v_add_i32       v39, vcc, 0x5a827999, v39
        v_alignbit_b32  v52, v39, v39, 27
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v42, vcc, v42, v52
        v_bfi_b32       v52, v38, v41, v51
        v_add_i32       v42, vcc, v42, v52
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v52, v42, v42, 27
        v_bfi_b32       v53, v39, v38, v41
        v_add_i32       v51, vcc, v51, v52
        v_add_i32       v51, vcc, v53, v51
        v_add_i32       v51, vcc, 0x5a827999, v51
        v_alignbit_b32  v39, v39, v39, 2
        v_alignbit_b32  v52, v51, v51, 27
        v_bfi_b32       v53, v42, v39, v38
        v_add_i32       v41, vcc, v41, v52
        v_add_i32       v41, vcc, v53, v41
        v_alignbit_b32  v52, v40, v40, 31
        v_add_i32       v41, vcc, 0x5a8279f9, v41
        v_xor_b32       v52, v32, v52
        v_alignbit_b32  v53, v41, v41, 27
        v_add_i32       v38, vcc, v38, v52
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v38, vcc, v53, v38
        v_bfi_b32       v52, v51, v42, v39
        v_add_i32       v38, vcc, v38, v52
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v51, v51, v51, 2
        v_alignbit_b32  v52, v38, v38, 27
        v_add_i32       v39, vcc, v33, v39
        v_bfi_b32       v53, v41, v51, v42
        v_add_i32       v39, vcc, v52, v39
        v_add_i32       v39, vcc, v53, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v52, v39, v39, 27
        v_add_i32       v42, vcc, v30, v42
        v_bfi_b32       v53, v38, v41, v51
        v_add_i32       v42, vcc, v52, v42
        v_alignbit_b32  v52, v40, v40, 30
        v_add_i32       v42, vcc, v53, v42
        v_xor_b32       v53, v31, v52
        v_alignbit_b32  v54, v42, v42, 27
        v_add_i32       v51, vcc, v51, v53
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v51, vcc, v54, v51
        v_bfi_b32       v53, v39, v38, v41
        v_add_i32       v51, vcc, v51, v53
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v53, v42, v38
        v_add_i32       v51, vcc, 0x5a827999, v51
        v_xor_b32       v53, v39, v53
        v_add_i32       v41, vcc, v28, v41
        v_xor_b32       v54, v51, v39
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v41, vcc, v53, v41
        v_alignbit_b32  v53, v51, v51, 27
        v_xor_b32       v54, v54, v42
        v_add_i32       v38, vcc, v29, v38
        v_add_i32       v41, vcc, v41, v53
        v_alignbit_b32  v53, v40, v40, 29
        v_add_i32       v38, vcc, v54, v38
        v_alignbit_b32  v54, v41, v41, 27
        v_xor_b32       v55, v42, v41
        v_alignbit_b32  v51, v51, v51, 2
        v_xor_b32       v56, v26, v53
        v_add_i32       v38, vcc, v38, v54
        v_xor_b32       v54, v55, v51
        v_add_i32       v39, vcc, v39, v56
        v_alignbit_b32  v55, v38, v38, 27
        v_add_i32       v39, vcc, v54, v39
        v_add_i32       v39, vcc, v55, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v54, v38, v51
        v_add_i32       v39, vcc, 0x6ed9eba1, v39
        v_xor_b32       v54, v41, v54
        v_add_i32       v42, vcc, v27, v42
        v_xor_b32       v55, v39, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v56, v24, v52
        v_add_i32       v42, vcc, v54, v42
        v_alignbit_b32  v54, v39, v39, 27
        v_xor_b32       v55, v55, v38
        v_add_i32       v51, vcc, v51, v56
        v_add_i32       v42, vcc, v42, v54
        v_add_i32       v51, vcc, v55, v51
        v_alignbit_b32  v54, v42, v42, 27
        v_alignbit_b32  v55, v40, v40, 28
        v_add_i32       v51, vcc, v51, v54
        v_xor_b32       v54, v38, v42
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v56, v25, v55
        v_add_i32       v51, vcc, 0x6ed9eba1, v51
        v_xor_b32       v54, v54, v39
        v_add_i32       v41, vcc, v41, v56
        v_alignbit_b32  v56, v51, v51, 27
        v_add_i32       v41, vcc, v54, v41
        v_add_i32       v41, vcc, v56, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v54, v51, v39
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_xor_b32       v54, v42, v54
        v_add_i32       v38, vcc, v22, v38
        v_xor_b32       v56, v41, v42
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v38, vcc, v54, v38
        v_alignbit_b32  v54, v41, v41, 27
        v_xor_b32       v56, v56, v51
        v_add_i32       v39, vcc, v23, v39
        v_add_i32       v38, vcc, v38, v54
        v_alignbit_b32  v54, v40, v40, 27
        v_add_i32       v39, vcc, v56, v39
        v_alignbit_b32  v56, v38, v38, 27
        v_xor_b32       v57, v51, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v58, v20, v54
        v_add_i32       v39, vcc, v39, v56
        v_xor_b32       v56, v57, v41
        v_add_i32       v42, vcc, v42, v58
        v_alignbit_b32  v57, v39, v39, 27
        v_add_i32       v42, vcc, v56, v42
        v_add_i32       v42, vcc, v57, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v56, v39, v41
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v57, v18, v52
        v_xor_b32       v56, v38, v56
        v_add_i32       v51, vcc, v21, v51
        v_xor_b32       v58, v42, v38
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v57, v55, v57
        v_add_i32       v51, vcc, v56, v51
        v_alignbit_b32  v56, v42, v42, 27
        v_xor_b32       v58, v58, v39
        v_add_i32       v41, vcc, v41, v57
        v_add_i32       v51, vcc, v51, v56
        v_add_i32       v41, vcc, v58, v41
        v_alignbit_b32  v56, v51, v51, 27
        v_alignbit_b32  v57, v40, v40, 26
        v_add_i32       v41, vcc, v41, v56
        v_xor_b32       v56, v39, v51
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v58, v19, v57
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_xor_b32       v56, v56, v42
        v_add_i32       v38, vcc, v38, v58
        v_alignbit_b32  v58, v41, v41, 27
        v_add_i32       v38, vcc, v56, v38
        v_xor_b32       v52, v16, v52
        v_add_i32       v38, vcc, v58, v38
        v_alignbit_b32  v51, v51, v51, 2
        v_xor_b32       v56, v41, v42
        v_xor_b32       v52, v53, v52
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v56, v51, v56
        v_add_i32       v39, vcc, v39, v52
        v_add_i32       v39, vcc, v56, v39
        v_alignbit_b32  v52, v38, v38, 27
        v_xor_b32       v56, v38, v51
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, v39, v52
        v_xor_b32       v52, v56, v41
        v_add_i32       v42, vcc, v17, v42
        v_add_i32       v39, vcc, 0x6ed9eba1, v39
        v_alignbit_b32  v56, v40, v40, 25
        v_add_i32       v42, vcc, v52, v42
        v_alignbit_b32  v52, v39, v39, 27
        v_xor_b32       v58, v41, v39
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v59, v14, v56
        v_add_i32       v42, vcc, v42, v52
        v_xor_b32       v52, v58, v38
        v_add_i32       v51, vcc, v51, v59
        v_alignbit_b32  v58, v42, v42, 27
        v_add_i32       v51, vcc, v52, v51
        v_add_i32       v51, vcc, v58, v51
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v52, v42, v38
        v_xor_b32       v58, v15, v55
        v_add_i32       v51, vcc, 0x6ed9eba1, v51
        v_xor_b32       v52, v39, v52
        v_add_i32       v41, vcc, v41, v58
        v_xor_b32       v58, v55, v57
        v_add_i32       v41, vcc, v52, v41
        v_alignbit_b32  v52, v51, v51, 27
        v_xor_b32       v59, v51, v39
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v60, v12, v58
        v_add_i32       v41, vcc, v41, v52
        v_xor_b32       v52, v59, v42
        v_add_i32       v38, vcc, v38, v60
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_add_i32       v38, vcc, v52, v38
        v_alignbit_b32  v52, v41, v41, 27
        v_alignbit_b32  v59, v40, v40, 24
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v52, v42, v41
        v_alignbit_b32  v51, v51, v51, 2
        v_xor_b32       v60, v13, v59
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v52, v52, v51
        v_add_i32       v39, vcc, v39, v60
        v_alignbit_b32  v60, v38, v38, 27
        v_add_i32       v39, vcc, v52, v39
        v_add_i32       v39, vcc, v60, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v52, v38, v51
        v_xor_b32       v60, v7, v55
        v_add_i32       v39, vcc, 0x6ed9eba1, v39
        v_xor_b32       v52, v41, v52
        v_add_i32       v42, vcc, v42, v60
        v_add_i32       v42, vcc, v52, v42
        v_alignbit_b32  v52, v39, v39, 27
        v_xor_b32       v60, v39, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, v42, v52
        ds_read2_b32    v[61:62], v37 offset0:40 offset1:41
        v_xor_b32       v52, v60, v38
        v_add_i32       v51, vcc, v8, v51
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_add_i32       v51, vcc, v52, v51
        v_alignbit_b32  v52, v42, v42, 27
        v_add_i32       v51, vcc, v51, v52
        v_alignbit_b32  v39, v39, v39, 2
        v_bfi_b32       v52, v38, v39, v42
        v_bfi_b32       v60, v39, 0, v42
        v_alignbit_b32  v63, v51, v51, 27
        v_alignbit_b32  v64, v40, v40, 23
        v_xor_b32       v52, v52, v60
        v_add_i32       v41, vcc, v41, v63
        v_xor_b32       v60, v55, v64
        v_add_i32       v41, vcc, v52, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v60, v61
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v52, v39, v42, v51
        v_bfi_b32       v60, v42, 0, v51
        v_alignbit_b32  v61, v41, v41, 27
        ds_read2_b32    v[63:64], v37 offset0:42 offset1:43
        v_xor_b32       v52, v52, v60
        v_add_i32       v38, vcc, v38, v61
        v_add_i32       v38, vcc, v52, v38
        v_add_i32       v38, vcc, v62, v38
        v_alignbit_b32  v51, v51, v51, 2
        v_bfi_b32       v52, v42, v51, v41
        v_bfi_b32       v60, v51, 0, v41
        v_alignbit_b32  v61, v38, v38, 27
        v_xor_b32       v52, v52, v60
        v_add_i32       v39, vcc, v39, v61
        v_xor_b32       v60, v57, v59
        v_add_i32       v39, vcc, v52, v39
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v63, v60
        v_add_i32       v39, vcc, v39, v52
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, 0x8f1bbcdc, v39
        v_bfi_b32       v52, v51, v41, v38
        v_bfi_b32       v60, v41, 0, v38
        v_alignbit_b32  v61, v39, v39, 27
        v_xor_b32       v52, v52, v60
        v_add_i32       v42, vcc, v42, v61
        v_alignbit_b32  v60, v40, v40, 22
        ds_read2_b32    v[61:62], v37 offset0:44 offset1:45
        v_add_i32       v42, vcc, v52, v42
        v_xor_b32       v52, v64, v60
        v_add_i32       v42, vcc, v42, v52
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v52, v41, v38, v39
        v_bfi_b32       v63, v38, 0, v39
        v_alignbit_b32  v64, v42, v42, 27
        v_xor_b32       v65, v53, v57
        v_xor_b32       v52, v52, v63
        v_add_i32       v51, vcc, v51, v64
        v_xor_b32       v63, v56, v65
        v_add_i32       v51, vcc, v52, v51
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v63, v61
        v_add_i32       v51, vcc, v51, v52
        v_alignbit_b32  v39, v39, v39, 2
        v_add_i32       v51, vcc, 0x8f1bbcdc, v51
        v_bfi_b32       v52, v38, v39, v42
        v_bfi_b32       v61, v39, 0, v42
        v_alignbit_b32  v63, v51, v51, 27
        ds_read2_b32    v[64:65], v37 offset0:46 offset1:47
        v_xor_b32       v52, v52, v61
        v_add_i32       v41, vcc, v41, v63
        v_add_i32       v41, vcc, v52, v41
        v_add_i32       v41, vcc, v62, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v52, v39, v42, v51
        v_bfi_b32       v61, v42, 0, v51
        v_alignbit_b32  v62, v41, v41, 27
        v_alignbit_b32  v63, v40, v40, 21
        v_xor_b32       v52, v52, v61
        v_add_i32       v38, vcc, v38, v62
        v_xor_b32       v61, v55, v63
        v_add_i32       v38, vcc, v52, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v64, v61
        v_add_i32       v38, vcc, v38, v52
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v52, v42, v51, v41
        v_bfi_b32       v61, v51, 0, v41
        v_alignbit_b32  v62, v38, v38, 27
        v_xor_b32       v52, v52, v61
        v_add_i32       v39, vcc, v39, v62
        v_xor_b32       v61, v55, v59
        ds_read2_b32    v[66:67], v37 offset0:48 offset1:49
        v_add_i32       v39, vcc, v52, v39
        v_xor_b32       v52, v65, v61
        v_add_i32       v39, vcc, v39, v52
        v_add_i32       v39, vcc, 0x8f1bbcdc, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v52, v53, v54
        v_bfi_b32       v53, v51, v41, v38
        v_bfi_b32       v62, v41, 0, v38
        v_alignbit_b32  v64, v39, v39, 27
        v_xor_b32       v52, v61, v52
        v_xor_b32       v53, v53, v62
        v_add_i32       v42, vcc, v42, v64
        v_xor_b32       v52, v60, v52
        v_add_i32       v42, vcc, v53, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v52, v66
        v_add_i32       v42, vcc, v42, v52
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v52, v41, v38, v39
        v_bfi_b32       v53, v38, 0, v39
        v_alignbit_b32  v62, v42, v42, 27
        v_xor_b32       v52, v52, v53
        v_add_i32       v51, vcc, v51, v62
        v_alignbit_b32  v53, v40, v40, 20
        ds_read2_b32    v[64:65], v37 offset0:50 offset1:51
        v_add_i32       v51, vcc, v52, v51
        v_xor_b32       v52, v67, v53
        v_add_i32       v51, vcc, v51, v52
        v_add_i32       v51, vcc, 0x8f1bbcdc, v51
        v_alignbit_b32  v39, v39, v39, 2
        v_bfi_b32       v52, v38, v39, v42
        v_bfi_b32       v62, v39, 0, v42
        v_alignbit_b32  v66, v51, v51, 27
        v_xor_b32       v52, v52, v62
        v_add_i32       v41, vcc, v41, v66
        v_add_i32       v41, vcc, v52, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v59, v64
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v52, v39, v42, v51
        v_bfi_b32       v62, v42, 0, v51
        v_alignbit_b32  v64, v41, v41, 27
        v_xor_b32       v52, v52, v62
        v_add_i32       v38, vcc, v38, v64
        ds_read2_b32    v[66:67], v37 offset0:52 offset1:53
        v_add_i32       v38, vcc, v52, v38
        v_xor_b32       v52, v58, v65
        v_add_i32       v38, vcc, v38, v52
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v51, v51, v51, 2
        v_bfi_b32       v52, v42, v51, v41
        v_bfi_b32       v62, v51, 0, v41
        v_alignbit_b32  v64, v38, v38, 27
        v_alignbit_b32  v65, v40, v40, 19
        v_xor_b32       v52, v52, v62
        v_add_i32       v39, vcc, v39, v64
        v_xor_b32       v62, v61, v65
        v_add_i32       v39, vcc, v52, v39
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v62, v66
        v_add_i32       v39, vcc, v39, v52
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, 0x8f1bbcdc, v39
        v_bfi_b32       v52, v51, v41, v38
        v_bfi_b32       v62, v41, 0, v38
        v_alignbit_b32  v64, v39, v39, 27
        ds_read2_b32    v[68:69], v37 offset0:54 offset1:55
        v_xor_b32       v52, v52, v62
        v_add_i32       v42, vcc, v42, v64
        v_add_i32       v42, vcc, v52, v42
        v_add_i32       v42, vcc, v67, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v52, v41, v38, v39
        v_bfi_b32       v62, v38, 0, v39
        v_alignbit_b32  v64, v42, v42, 27
        v_xor_b32       v66, v56, v60
        v_xor_b32       v52, v52, v62
        v_add_i32       v51, vcc, v51, v64
        v_xor_b32       v62, v53, v66
        v_add_i32       v51, vcc, v52, v51
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v62, v68
        v_add_i32       v51, vcc, v51, v52
        v_alignbit_b32  v39, v39, v39, 2
        v_add_i32       v51, vcc, 0x8f1bbcdc, v51
        v_bfi_b32       v52, v38, v39, v42
        v_bfi_b32       v62, v39, 0, v42
        v_alignbit_b32  v64, v51, v51, 27
        v_xor_b32       v52, v52, v62
        v_add_i32       v41, vcc, v41, v64
        v_alignbit_b32  v62, v40, v40, 18
        ds_read2_b32    v[66:67], v37 offset0:56 offset1:57
        v_add_i32       v41, vcc, v52, v41
        v_xor_b32       v52, v62, v69
        v_add_i32       v41, vcc, v41, v52
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v52, v56, v58
        v_bfi_b32       v64, v39, v42, v51
        v_bfi_b32       v68, v42, 0, v51
        v_alignbit_b32  v69, v41, v41, 27
        v_xor_b32       v60, v60, v52
        v_xor_b32       v64, v64, v68
        v_add_i32       v38, vcc, v38, v69
        v_xor_b32       v60, v63, v60
        v_add_i32       v38, vcc, v64, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v60, v60, v66
        v_add_i32       v38, vcc, v38, v60
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v60, v42, v51, v41
        v_bfi_b32       v64, v51, 0, v41
        v_alignbit_b32  v66, v38, v38, 27
        v_xor_b32       v60, v60, v64
        v_add_i32       v39, vcc, v39, v66
        ds_read2_b32    v[68:69], v37 offset0:58 offset1:59
        v_add_i32       v39, vcc, v60, v39
        v_xor_b32       v60, v59, v67
        v_add_i32       v39, vcc, v39, v60
        v_add_i32       v39, vcc, 0x8f1bbcdc, v39
        v_alignbit_b32  v41, v41, v41, 2
        v_bfi_b32       v60, v51, v41, v38
        v_bfi_b32       v64, v41, 0, v38
        v_alignbit_b32  v66, v39, v39, 27
        v_alignbit_b32  v67, v40, v40, 17
        v_xor_b32       v60, v60, v64
        v_add_i32       v42, vcc, v42, v66
        v_xor_b32       v61, v61, v67
        v_add_i32       v42, vcc, v60, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v60, v61, v68
        v_add_i32       v42, vcc, v42, v60
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v60, v41, v38, v39
        v_bfi_b32       v61, v38, 0, v39
        v_alignbit_b32  v64, v42, v42, 27
        ds_read2_b32    v[70:71], v37 offset0:60 offset1:61
        v_xor_b32       v60, v60, v61
        v_add_i32       v51, vcc, v51, v64
        v_xor_b32       v61, v59, v53
        v_add_i32       v51, vcc, v60, v51
        v_xor_b32       v60, v61, v69
        v_add_i32       v51, vcc, v51, v60
        v_xor_b32       v60, v38, v42
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v55, v55, v56
        v_add_i32       v51, vcc, 0x8f1bbcdc, v51
        v_xor_b32       v60, v60, v39
        v_xor_b32       v55, v61, v55
        v_alignbit_b32  v64, v51, v51, 27
        v_add_i32       v41, vcc, v41, v60
        v_xor_b32       v55, v62, v55
        v_add_i32       v41, vcc, v64, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v55, v55, v70
        v_add_i32       v41, vcc, v41, v55
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v55, v51, v39
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v55, v42, v55
        ds_read2_b32    v[68:69], v37 offset0:62 offset1:63
        v_add_i32       v38, vcc, v38, v55
        v_alignbit_b32  v55, v41, v41, 27
        v_alignbit_b32  v60, v40, v40, 16
        v_add_i32       v38, vcc, v38, v55
        v_xor_b32       v55, v60, v71
        v_xor_b32       v64, v41, v42
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v38, vcc, v38, v55
        v_xor_b32       v55, v64, v51
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_add_i32       v39, vcc, v39, v55
        v_alignbit_b32  v55, v38, v38, 27
        v_xor_b32       v58, v58, v61
        v_add_i32       v39, vcc, v39, v55
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v55, v58, v68
        v_add_i32       v39, vcc, v39, v55
        v_xor_b32       v55, v51, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, 0xca62c1d6, v39
        v_xor_b32       v55, v55, v41
        ds_read2_b32    v[70:71], v37 offset0:64 offset1:65
        v_alignbit_b32  v58, v39, v39, 27
        v_add_i32       v42, vcc, v42, v55
        v_add_i32       v42, vcc, v58, v42
        v_xor_b32       v55, v59, v69
        v_add_i32       v42, vcc, v42, v55
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v55, v39, v41
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_xor_b32       v55, v38, v55
        v_xor_b32       v52, v52, v61
        v_alignbit_b32  v58, v40, v40, 15
        v_add_i32       v51, vcc, v51, v55
        v_alignbit_b32  v55, v42, v42, 27
        v_xor_b32       v52, v52, v58
        v_add_i32       v51, vcc, v51, v55
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v52, v70
        v_xor_b32       v55, v42, v38
        v_alignbit_b32  v39, v39, v39, 2
        v_add_i32       v51, vcc, v51, v52
        ds_read2_b32    v[68:69], v37 offset0:66 offset1:67
        v_xor_b32       v52, v55, v39
        v_add_i32       v51, vcc, 0xca62c1d6, v51
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v52, v51, v51, 27
        v_add_i32       v41, vcc, v41, v52
        v_xor_b32       v52, v39, v51
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v41, vcc, v41, v71
        v_xor_b32       v52, v52, v42
        v_alignbit_b32  v55, v41, v41, 27
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v52, v62, v60
        v_add_i32       v38, vcc, v55, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v52, v68
        v_add_i32       v38, vcc, v38, v52
        v_alignbit_b32  v51, v51, v51, 2
        v_xor_b32       v52, v41, v42
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v52, v51, v52
        v_alignbit_b32  v55, v40, v40, 14
        ds_read2_b32    v[70:71], v37 offset0:68 offset1:69
        v_add_i32       v39, vcc, v39, v52
        v_alignbit_b32  v52, v38, v38, 27
        v_xor_b32       v58, v59, v55
        v_add_i32       v39, vcc, v39, v52
        v_xor_b32       v52, v58, v69
        v_xor_b32       v58, v38, v51
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v39, vcc, v39, v52
        v_xor_b32       v52, v58, v41
        v_add_i32       v39, vcc, 0xca62c1d6, v39
        v_xor_b32       v58, v63, v62
        v_add_i32       v42, vcc, v42, v52
        v_alignbit_b32  v52, v39, v39, 27
        v_xor_b32       v58, v67, v58
        v_add_i32       v42, vcc, v42, v52
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v58, v70
        v_add_i32       v42, vcc, v42, v52
        v_xor_b32       v52, v41, v39
        v_alignbit_b32  v38, v38, v38, 2
        ds_read2_b32    v[68:69], v37 offset0:70 offset1:71
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_xor_b32       v52, v52, v38
        v_alignbit_b32  v58, v42, v42, 27
        v_add_i32       v51, vcc, v51, v52
        v_add_i32       v51, vcc, v58, v51
        v_alignbit_b32  v39, v39, v39, 2
        v_xor_b32       v52, v42, v38
        v_add_i32       v51, vcc, v51, v71
        v_xor_b32       v52, v39, v52
        v_alignbit_b32  v58, v40, v40, 13
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v52, v51, v51, 27
        v_xor_b32       v58, v53, v58
        v_add_i32       v41, vcc, v41, v52
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v58, v68
        v_xor_b32       v58, v51, v39
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v41, vcc, v41, v52
        v_xor_b32       v52, v58, v42
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        ds_read2_b32    v[70:71], v37 offset0:72 offset1:73
        v_add_i32       v38, vcc, v38, v52
        v_alignbit_b32  v52, v41, v41, 27
        v_xor_b32       v58, v53, v60
        v_xor_b32       v54, v54, v63
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v52, v58, v69
        v_xor_b32       v54, v53, v54
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v52, v42, v41
        v_alignbit_b32  v51, v51, v51, 2
        v_xor_b32       v54, v65, v54
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v52, v52, v51
        v_xor_b32       v54, v60, v54
        v_alignbit_b32  v58, v38, v38, 27
        v_add_i32       v39, vcc, v39, v52
        v_xor_b32       v52, v55, v54
        v_add_i32       v39, vcc, v58, v39
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v52, v70
        v_add_i32       v39, vcc, v39, v52
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v52, v38, v51
        v_add_i32       v39, vcc, 0xca62c1d6, v39
        v_xor_b32       v52, v41, v52
        ds_read2_b32    v[63:64], v37 offset0:74 offset1:75
        v_add_i32       v42, vcc, v42, v52
        v_alignbit_b32  v52, v39, v39, 27
        v_alignbit_b32  v54, v40, v40, 12
        v_add_i32       v42, vcc, v42, v52
        v_xor_b32       v52, v54, v71
        v_xor_b32       v58, v39, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, v42, v52
        v_xor_b32       v52, v58, v38
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_add_i32       v51, vcc, v51, v52
        v_alignbit_b32  v52, v42, v42, 27
        v_xor_b32       v58, v59, v60
        v_add_i32       v51, vcc, v51, v52
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v58, v63
        v_add_i32       v51, vcc, v51, v52
        v_xor_b32       v52, v38, v42
        v_alignbit_b32  v39, v39, v39, 2
        v_add_i32       v51, vcc, 0xca62c1d6, v51
        v_xor_b32       v52, v52, v39
        v_xor_b32       v57, v57, v53
        ds_read2_b32    v[65:66], v37 offset0:76 offset1:77
        v_alignbit_b32  v58, v51, v51, 27
        v_add_i32       v41, vcc, v41, v52
        v_xor_b32       v52, v62, v57
        v_add_i32       v41, vcc, v58, v41
        v_xor_b32       v52, v52, v64
        v_xor_b32       v56, v56, v59
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v52, v51, v39
        v_xor_b32       v53, v53, v56
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v52, v42, v52
        v_xor_b32       v53, v60, v53
        v_alignbit_b32  v57, v40, v40, 11
        v_add_i32       v38, vcc, v38, v52
        v_alignbit_b32  v52, v41, v41, 27
        v_xor_b32       v53, v53, v57
        v_add_i32       v38, vcc, v38, v52
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v52, v53, v65
        v_xor_b32       v53, v41, v42
        v_alignbit_b32  v51, v51, v51, 2
        v_add_i32       v38, vcc, v38, v52
        ds_read2_b32    v[57:58], v37 offset0:78 offset1:79
        v_xor_b32       v37, v53, v51
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_add_i32       v37, vcc, v39, v37
        v_alignbit_b32  v39, v38, v38, 27
        v_add_i32       v37, vcc, v37, v39
        v_alignbit_b32  v39, v41, v41, 2
        v_xor_b32       v41, v51, v38
        v_xor_b32       v52, v67, v56
        v_add_i32       v43, vcc, v37, v66
        v_xor_b32       v41, v39, v41
        v_xor_b32       v52, v55, v52
        v_alignbit_b32  v53, v43, v43, 27
        v_add_i32       v41, vcc, v42, v41
        v_xor_b32       v42, v54, v52
        v_add_i32       v41, vcc, v53, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v42, v42, v57
        v_xor_b32       v39, v43, v39
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v41, vcc, v41, v42
        v_xor_b32       v38, v39, v38
        v_add_i32       v39, vcc, 0xca62c1d6, v41
        v_alignbit_b32  v40, v40, v40, 10
        v_add_i32       v38, vcc, v51, v38
        v_alignbit_b32  v39, v39, v39, 27
        v_xor_b32       v40, v59, v40
        v_add_i32       v38, vcc, v38, v39
        v_xor_b32       v39, v40, v58
        v_add_i32       v38, vcc, v38, v39
        v_add_i32       v39, vcc, 0x31a7e4d7, v38
        v_lshrrev_b32   v40, 20, v39
        ds_read_u8      v40, v40 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v40, v40, 0, 8
        v_alignbit_b32  v42, v43, v43, 2
        v_lshrrev_b32   v51, 2, v39
        v_cmp_eq_i32    s[26:27], v40, 0
        v_add_i32       v59, vcc, 0x98badcfe, v42
        v_add_i32       v42, vcc, 0xba306d5f, v41
        s_and_saveexec_b64 s[26:27], s[26:27]
        v_lshrrev_b32   v37, 8, v39
        s_cbranch_execz .L6856_2
        v_add_i32       v48, vcc, s8, v37
        v_mov_b32       v52, s9
        v_addc_u32      v49, vcc, v52, 0, vcc
        buffer_load_ubyte v37, v[48:49], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    s[44:45], v37, 0
        s_and_saveexec_b64 s[46:47], s[44:45]
        s_cbranch_execz .L6836_2
        s_mov_b64       s[48:49], exec
        s_mov_b64       s[50:51], exec
        v_mov_b32       v37, 0
        v_mov_b32       v54, s1
        v_mov_b32       v53, s0
.L6700_2:
        v_cmp_gt_i32    s[52:53], v37, v53
        v_cmp_eq_i32    vcc, v51, v54
        s_or_b64        vcc, s[52:53], vcc
        s_and_saveexec_b64 s[52:53], vcc
        s_andn2_b64     s[50:51], s[50:51], exec
        s_cbranch_scc0  .L6812_2
        s_and_b64       exec, s[52:53], s[50:51]
        v_add_i32       v52, vcc, v37, v53
        v_ashrrev_i32   v48, 1, v52
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[54:55], v[48:49], 2
        v_add_i32       v54, vcc, s6, v54
        v_mov_b32       v56, s7
        v_addc_u32      v55, vcc, v56, v55, vcc
        buffer_load_dword v54, v[54:55], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[52:53], v54, v51
        v_add_i32       v55, vcc, -1, v48
        v_add_i32       v52, vcc, 1, v48
        v_cndmask_b32   v53, v53, v55, s[52:53]
        v_cndmask_b32   v37, v52, v37, s[52:53]
        s_branch        .L6700_2
.L6812_2:
        s_mov_b64       exec, s[48:49]
        v_cmp_lg_i32    vcc, v51, v54
        v_cndmask_b32   v72, 1.0, v72, vcc
        v_cndmask_b32   v43, 0, -1, vcc
        v_mov_b32       v56, 1
.L6836_2:
        s_andn2_b64     exec, s[46:47], exec
        v_cndmask_b32   v43, 0, -1, s[44:45]
        v_mov_b32       v56, 0
        s_mov_b64       exec, s[46:47]
.L6856_2:
        s_andn2_b64     exec, s[26:27], exec
        v_mov_b32       v56, 0
        s_mov_b64       exec, s[26:27]
        v_cmp_eq_u32    vcc, 0, v72
        s_and_b64       exec, s[26:27], vcc
        v_lshlrev_b32   v43, 4, v38
        s_cbranch_execz .L9004_2
        v_add_i32       v43, vcc, 0x1a7e4d70, v43
        v_and_b32       v52, 0x3ffffff0, v43
        v_lshrrev_b32   v53, 18, v52
        ds_read_u8      v53, v53 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v53, v53, 0, 8
        v_cmp_eq_i32    vcc, 0, v53
        v_lshrrev_b32   v53, 28, v42
        s_and_saveexec_b64 s[44:45], vcc
        v_lshrrev_b32   v52, 6, v52
        s_cbranch_execz .L7164_2
        v_add_i32       v48, vcc, s8, v52
        v_mov_b32       v54, s9
        v_addc_u32      v49, vcc, v54, 0, vcc
        buffer_load_ubyte v52, v[48:49], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[46:47], vcc
        s_cbranch_execz .L7164_2
        s_mov_b32       s48, 0x3ffffff0
        v_bfi_b32       v37, s48, v43, v53
        s_mov_b64       s[48:49], exec
        s_mov_b64       s[50:51], exec
        v_mov_b32       v52, 0
        v_mov_b32       v51, s1
        v_mov_b32       v55, s0
        s_movk_i32      s52, 0x0
        s_movk_i32      s53, 0x0
.L7028_2:
        v_cmp_gt_i32    s[54:55], v52, v55
        v_cmp_eq_i32    vcc, v37, v51
        s_andn2_b64     s[52:53], s[52:53], exec
        s_or_b64        s[52:53], vcc, s[52:53]
        s_or_b64        vcc, s[54:55], vcc
        s_and_saveexec_b64 s[54:55], vcc
        s_andn2_b64     s[50:51], s[50:51], exec
        s_cbranch_scc0  .L7148_2
        s_and_b64       exec, s[54:55], s[50:51]
        v_add_i32       v54, vcc, v52, v55
        v_ashrrev_i32   v48, 1, v54
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[56:57], v[48:49], 2
        v_add_i32       v56, vcc, s6, v56
        v_mov_b32       v58, s7
        v_addc_u32      v57, vcc, v58, v57, vcc
        buffer_load_dword v51, v[56:57], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[54:55], v51, v37
        v_add_i32       v57, vcc, -1, v48
        v_add_i32       v54, vcc, 1, v48
        v_cndmask_b32   v55, v55, v57, s[54:55]
        v_cndmask_b32   v52, v54, v52, s[54:55]
        s_branch        .L7028_2
.L7148_2:
        s_mov_b64       exec, s[48:49]
        v_cndmask_b32   v75, v75, 1.0, s[52:53]
        v_mov_b32       v56, 2
.L7164_2:
        s_mov_b64       exec, s[44:45]
        v_cmp_eq_u32    vcc, 0, v75
        s_and_b64       exec, s[44:45], vcc
        v_bfe_u32       v52, v39, 8, 12
        s_cbranch_execz .L9000_2
        ds_read_u8      v52, v52 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v52, v52, 0, 8
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[46:47], vcc
        v_lshrrev_b32   v52, 22, v42
        s_cbranch_execz .L7464_2
        v_lshlrev_b32   v54, 10, v38
        v_add_i32       v54, vcc, 0x9f935c00, v54
        s_mov_b32       s48, 0x3ffffc00
        v_bfi_b32       v52, s48, v54, v52
        v_lshrrev_b32   v54, 6, v52
        v_add_i32       v54, vcc, s8, v54
        v_mov_b32       v55, s9
        v_addc_u32      v55, vcc, v55, 0, vcc
        buffer_load_ubyte v54, v[54:55], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v54
        s_and_saveexec_b64 s[48:49], vcc
        s_cbranch_execz .L7464_2
        s_mov_b64       s[50:51], exec
        s_mov_b64       s[52:53], exec
        v_mov_b32       v37, 0
        v_mov_b32       v51, s1
        v_mov_b32       v55, s0
        s_movk_i32      s54, 0x0
        s_movk_i32      s55, 0x0
        s_nop           0x0
.L7328_2:
        v_cmp_gt_i32    s[56:57], v37, v55
        v_cmp_eq_i32    vcc, v52, v51
        s_andn2_b64     s[54:55], s[54:55], exec
        s_or_b64        s[54:55], vcc, s[54:55]
        s_or_b64        vcc, s[56:57], vcc
        s_and_saveexec_b64 s[56:57], vcc
        s_andn2_b64     s[52:53], s[52:53], exec
        s_cbranch_scc0  .L7448_2
        s_and_b64       exec, s[56:57], s[52:53]
        v_add_i32       v54, vcc, v37, v55
        v_ashrrev_i32   v48, 1, v54
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[56:57], v[48:49], 2
        v_add_i32       v56, vcc, s6, v56
        v_mov_b32       v58, s7
        v_addc_u32      v57, vcc, v58, v57, vcc
        buffer_load_dword v51, v[56:57], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[56:57], v51, v52
        v_add_i32       v57, vcc, -1, v48
        v_add_i32       v54, vcc, 1, v48
        v_cndmask_b32   v55, v55, v57, s[56:57]
        v_cndmask_b32   v37, v54, v37, s[56:57]
        s_branch        .L7328_2
.L7448_2:
        s_mov_b64       exec, s[50:51]
        v_cndmask_b32   v44, v44, 1.0, s[54:55]
        v_mov_b32       v56, 2
.L7464_2:
        s_mov_b64       exec, s[46:47]
        v_cmp_eq_u32    vcc, 0, v44
        s_and_b64       exec, s[46:47], vcc
        v_bfe_u32       v52, v39, 2, 12
        s_cbranch_execz .L9000_2
        ds_read_u8      v52, v52 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v52, v52, 0, 8
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[48:49], vcc
        v_lshlrev_b32   v52, 16, v38
        s_cbranch_execz .L7768_2
        v_add_i32       v52, vcc, 0xe4d70000, v52
        v_lshrrev_b32   v54, 16, v42
        s_mov_b32       s50, 0x3fff0000
        v_bfi_b32       v52, s50, v52, v54
        v_lshrrev_b32   v54, 6, v52
        v_add_i32       v54, vcc, s8, v54
        v_mov_b32       v55, s9
        v_addc_u32      v55, vcc, v55, 0, vcc
        buffer_load_ubyte v54, v[54:55], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v54
        s_and_saveexec_b64 s[50:51], vcc
        s_cbranch_execz .L7768_2
        s_mov_b64       s[52:53], exec
        s_mov_b64       s[54:55], exec
        v_mov_b32       v37, 0
        v_mov_b32       v51, s1
        v_mov_b32       v55, s0
        s_movk_i32      s56, 0x0
        s_movk_i32      s57, 0x0
        s_nop           0x0
        s_nop           0x0
.L7632_2:
        v_cmp_gt_i32    s[58:59], v37, v55
        v_cmp_eq_i32    vcc, v52, v51
        s_andn2_b64     s[56:57], s[56:57], exec
        s_or_b64        s[56:57], vcc, s[56:57]
        s_or_b64        vcc, s[58:59], vcc
        s_and_saveexec_b64 s[58:59], vcc
        s_andn2_b64     s[54:55], s[54:55], exec
        s_cbranch_scc0  .L7752_2
        s_and_b64       exec, s[58:59], s[54:55]
        v_add_i32       v54, vcc, v37, v55
        v_ashrrev_i32   v48, 1, v54
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[56:57], v[48:49], 2
        v_add_i32       v56, vcc, s6, v56
        v_mov_b32       v58, s7
        v_addc_u32      v57, vcc, v58, v57, vcc
        buffer_load_dword v51, v[56:57], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[58:59], v51, v52
        v_add_i32       v57, vcc, -1, v48
        v_add_i32       v54, vcc, 1, v48
        v_cndmask_b32   v55, v55, v57, s[58:59]
        v_cndmask_b32   v37, v54, v37, s[58:59]
        s_branch        .L7632_2
.L7752_2:
        s_mov_b64       exec, s[52:53]
        v_cndmask_b32   v73, v73, 1.0, s[56:57]
        v_mov_b32       v56, 2
.L7768_2:
        s_mov_b64       exec, s[48:49]
        v_cmp_eq_u32    vcc, 0, v73
        s_and_b64       exec, s[48:49], vcc
        v_lshrrev_b32   v52, 10, v42
        s_cbranch_execz .L9000_2
        v_lshlrev_b32   v54, 22, v38
        v_add_i32       v54, vcc, 0x35c00000, v54
        s_mov_b32       s50, 0x3fc00000
        v_bfi_b32       v52, s50, v54, v52
        v_lshrrev_b32   v54, 18, v52
        ds_read_u8      v54, v54 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v54, v54, 0, 8
        v_cmp_eq_i32    vcc, 0, v54
        s_and_saveexec_b64 s[50:51], vcc
        v_lshrrev_b32   v54, 6, v52
        s_cbranch_execz .L8072_2
        v_add_i32       v54, vcc, s8, v54
        v_mov_b32       v55, s9
        v_addc_u32      v55, vcc, v55, 0, vcc
        buffer_load_ubyte v54, v[54:55], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v54
        s_and_saveexec_b64 s[52:53], vcc
        s_cbranch_execz .L8072_2
        s_mov_b64       s[54:55], exec
        s_mov_b64       s[56:57], exec
        v_mov_b32       v37, 0
        v_mov_b32       v51, s1
        v_mov_b32       v55, s0
        s_movk_i32      s58, 0x0
        s_movk_i32      s59, 0x0
        s_nop           0x0
        s_nop           0x0
        s_nop           0x0
.L7936_2:
        v_cmp_gt_i32    s[60:61], v37, v55
        v_cmp_eq_i32    vcc, v52, v51
        s_andn2_b64     s[58:59], s[58:59], exec
        s_or_b64        s[58:59], vcc, s[58:59]
        s_or_b64        vcc, s[60:61], vcc
        s_and_saveexec_b64 s[60:61], vcc
        s_andn2_b64     s[56:57], s[56:57], exec
        s_cbranch_scc0  .L8056_2
        s_and_b64       exec, s[60:61], s[56:57]
        v_add_i32       v54, vcc, v37, v55
        v_ashrrev_i32   v48, 1, v54
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[56:57], v[48:49], 2
        v_add_i32       v56, vcc, s6, v56
        v_mov_b32       v58, s7
        v_addc_u32      v57, vcc, v58, v57, vcc
        buffer_load_dword v51, v[56:57], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[60:61], v51, v52
        v_add_i32       v57, vcc, -1, v48
        v_add_i32       v54, vcc, 1, v48
        v_cndmask_b32   v55, v55, v57, s[60:61]
        v_cndmask_b32   v37, v54, v37, s[60:61]
        s_branch        .L7936_2
.L8056_2:
        s_mov_b64       exec, s[54:55]
        v_cndmask_b32   v45, v45, 1.0, s[58:59]
        v_mov_b32       v56, 2
.L8072_2:
        s_mov_b64       exec, s[50:51]
        v_cmp_eq_u32    vcc, 0, v45
        s_and_b64       exec, s[50:51], vcc
        v_lshrrev_b32   v52, 4, v42
        s_cbranch_execz .L9000_2
        v_lshlrev_b32   v38, 28, v38
        v_add_i32       v38, vcc, 0x70000000, v38
        s_mov_b32       s52, 0x30000000
        v_bfi_b32       v38, s52, v38, v52
        v_lshrrev_b32   v52, 18, v38
        ds_read_u8      v52, v52 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v52, v52, 0, 8
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[52:53], vcc
        v_lshrrev_b32   v52, 6, v38
        s_cbranch_execz .L8376_2
        v_add_i32       v48, vcc, s8, v52
        v_mov_b32       v54, s9
        v_addc_u32      v49, vcc, v54, 0, vcc
        buffer_load_ubyte v52, v[48:49], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[54:55], vcc
        s_cbranch_execz .L8376_2
        s_mov_b64       s[56:57], exec
        s_mov_b64       s[58:59], exec
        v_mov_b32       v37, 0
        v_mov_b32       v51, s1
        v_mov_b32       v54, s0
        s_movk_i32      s60, 0x0
        s_movk_i32      s61, 0x0
        s_nop           0x0
        s_nop           0x0
        s_nop           0x0
.L8240_2:
        v_cmp_gt_i32    s[62:63], v37, v54
        v_cmp_eq_i32    vcc, v38, v51
        s_andn2_b64     s[60:61], s[60:61], exec
        s_or_b64        s[60:61], vcc, s[60:61]
        s_or_b64        vcc, s[62:63], vcc
        s_and_saveexec_b64 s[62:63], vcc
        s_andn2_b64     s[58:59], s[58:59], exec
        s_cbranch_scc0  .L8360_2
        s_and_b64       exec, s[62:63], s[58:59]
        v_add_i32       v52, vcc, v37, v54
        v_ashrrev_i32   v48, 1, v52
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[55:56], v[48:49], 2
        v_add_i32       v55, vcc, s6, v55
        v_mov_b32       v57, s7
        v_addc_u32      v56, vcc, v57, v56, vcc
        buffer_load_dword v51, v[55:56], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[62:63], v51, v38
        v_add_i32       v56, vcc, -1, v48
        v_add_i32       v52, vcc, 1, v48
        v_cndmask_b32   v54, v54, v56, s[62:63]
        v_cndmask_b32   v37, v52, v37, s[62:63]
        s_branch        .L8240_2
.L8360_2:
        s_mov_b64       exec, s[56:57]
        v_cndmask_b32   v46, v46, 1.0, s[60:61]
        v_mov_b32       v56, 2
.L8376_2:
        s_mov_b64       exec, s[52:53]
        v_cmp_eq_u32    vcc, 0, v46
        s_and_b64       exec, s[52:53], vcc
        v_lshlrev_b32   v48, 2, v41
        s_cbranch_execz .L9000_2
        v_add_i32       v48, vcc, 0xe8c1b57c, v48
        v_and_b32       v52, 0x3ffffffc, v48
        v_lshrrev_b32   v54, 18, v52
        ds_read_u8      v54, v54 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v54, v54, 0, 8
        v_cmp_eq_i32    vcc, 0, v54
        s_and_saveexec_b64 s[54:55], vcc
        v_lshrrev_b32   v52, 6, v52
        s_cbranch_execz .L8680_2
        v_add_i32       v37, vcc, s8, v52
        v_mov_b32       v54, s9
        v_addc_u32      v38, vcc, v54, 0, vcc
        buffer_load_ubyte v52, v[37:38], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v52
        s_and_saveexec_b64 s[56:57], vcc
        v_lshrrev_b32   v37, 30, v59
        s_cbranch_execz .L8680_2
        s_mov_b32       s58, 0x3ffffffc
        v_bfi_b32       v37, s58, v48, v37
        s_mov_b64       s[58:59], exec
        s_mov_b64       s[60:61], exec
        v_mov_b32       v48, 0
        v_mov_b32       v38, s1
        v_mov_b32       v54, s0
        s_movk_i32      s62, 0x0
        s_movk_i32      s63, 0x0
        s_nop           0x0
.L8544_2:
        v_cmp_gt_i32    s[64:65], v48, v54
        v_cmp_eq_i32    vcc, v37, v38
        s_andn2_b64     s[62:63], s[62:63], exec
        s_or_b64        s[62:63], vcc, s[62:63]
        s_or_b64        vcc, s[64:65], vcc
        s_and_saveexec_b64 s[64:65], vcc
        s_andn2_b64     s[60:61], s[60:61], exec
        s_cbranch_scc0  .L8664_2
        s_and_b64       exec, s[64:65], s[60:61]
        v_add_i32       v52, vcc, v48, v54
        v_ashrrev_i32   v51, 1, v52
        v_ashrrev_i32   v52, 31, v51
        v_lshl_b64      v[55:56], v[51:52], 2
        v_add_i32       v55, vcc, s6, v55
        v_mov_b32       v57, s7
        v_addc_u32      v56, vcc, v57, v56, vcc
        buffer_load_dword v38, v[55:56], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[64:65], v38, v37
        v_add_i32       v56, vcc, -1, v51
        v_add_i32       v52, vcc, 1, v51
        v_cndmask_b32   v54, v54, v56, s[64:65]
        v_cndmask_b32   v48, v52, v48, s[64:65]
        s_branch        .L8544_2
.L8664_2:
        s_mov_b64       exec, s[58:59]
        v_cndmask_b32   v47, v47, 1.0, s[62:63]
        v_mov_b32       v56, 2
.L8680_2:
        s_mov_b64       exec, s[54:55]
        v_cmp_eq_u32    vcc, 0, v47
        s_and_b64       exec, s[54:55], vcc
        v_bfe_u32       v49, v42, 10, 12
        s_cbranch_execz .L9000_2
        ds_read_u8      v49, v49 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v49, v49, 0, 8
        v_cmp_eq_i32    vcc, 0, v49
        s_and_saveexec_b64 s[56:57], vcc
        v_lshlrev_b32   v41, 8, v41
        s_cbranch_execz .L8984_2
        v_add_i32       v41, vcc, 0x306d5f00, v41
        v_lshrrev_b32   v49, 24, v59
        s_mov_b32       s58, 0x3fffff00
        v_bfi_b32       v41, s58, v41, v49
        v_lshrrev_b32   v49, 6, v41
        v_add_i32       v54, vcc, s8, v49
        v_mov_b32       v52, s9
        v_addc_u32      v55, vcc, v52, 0, vcc
        buffer_load_ubyte v49, v[54:55], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v49
        s_and_saveexec_b64 s[58:59], vcc
        s_cbranch_execz .L8984_2
        s_mov_b64       s[60:61], exec
        s_mov_b64       s[62:63], exec
        v_mov_b32       v37, 0
        v_mov_b32       v38, s1
        v_mov_b32       v52, s0
        s_movk_i32      s64, 0x0
        s_movk_i32      s65, 0x0
        s_nop           0x0
        s_nop           0x0
.L8848_2:
        v_cmp_gt_i32    s[66:67], v37, v52
        v_cmp_eq_i32    vcc, v41, v38
        s_andn2_b64     s[64:65], s[64:65], exec
        s_or_b64        s[64:65], vcc, s[64:65]
        s_or_b64        vcc, s[66:67], vcc
        s_and_saveexec_b64 s[66:67], vcc
        s_andn2_b64     s[62:63], s[62:63], exec
        s_cbranch_scc0  .L8968_2
        s_and_b64       exec, s[66:67], s[62:63]
        v_add_i32       v49, vcc, v37, v52
        v_ashrrev_i32   v48, 1, v49
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[54:55], v[48:49], 2
        v_add_i32       v54, vcc, s6, v54
        v_mov_b32       v56, s7
        v_addc_u32      v55, vcc, v56, v55, vcc
        buffer_load_dword v38, v[54:55], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[66:67], v38, v41
        v_add_i32       v55, vcc, -1, v48
        v_add_i32       v49, vcc, 1, v48
        v_cndmask_b32   v52, v52, v55, s[66:67]
        v_cndmask_b32   v37, v49, v37, s[66:67]
        s_branch        .L8848_2
.L8968_2:
        s_mov_b64       exec, s[60:61]
        v_cndmask_b32   v50, v50, 1.0, s[64:65]
        v_mov_b32       v56, 2
.L8984_2:
        s_mov_b64       exec, s[56:57]
        v_cmp_eq_u32    vcc, 0, v50
        v_addc_u32      v35, vcc, v35, 0, vcc
.L9000_2:
        s_mov_b64       exec, s[44:45]
.L9004_2:
        s_andn2_b64     exec, s[26:27], exec
        v_mov_b32       v53, 0
        s_mov_b64       exec, s[26:27]
.L9016_2:
        s_andn2_b64     exec, s[20:21], exec
        v_cndmask_b32   v36, 0, -1, s[14:15]
        v_mov_b32       v56, 0
        s_mov_b64       exec, s[20:21]
        s_branch        .L2016_2
.L9040_2:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v56
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[0:1], vcc
        v_mov_b32       v0, 0x400
        s_cbranch_execz .L9076_2
        buffer_store_dword v0, v[4:5], s[28:31], 0 addr64
.L9076_2:
        s_andn2_b64     exec, s[0:1], exec
        s_cbranch_execz .L9640_2
        s_load_dwordx4  s[8:11], s[2:3], 0x50
        v_lshrrev_b32   v0, 26, v39
        v_add_i32       v17, vcc, s4, v0
        v_mov_b32       v6, s5
        v_addc_u32      v18, vcc, v6, 0, vcc
        v_bfe_u32       v8, v39, 20, 6
        v_cmp_eq_i32    s[2:3], v56, 1
        v_lshlrev_b32   v11, 4, v39
        v_add_i32       v19, s[6:7], s4, v8
        v_addc_u32      v20, vcc, v6, 0, s[6:7]
        v_bfe_u32       v13, v39, 14, 6
        v_lshrrev_b32   v14, 28, v42
        v_cndmask_b32   v11, v43, v11, s[2:3]
        v_add_i32       v21, vcc, s4, v13
        v_addc_u32      v22, vcc, v6, 0, vcc
        v_bfe_u32       v16, v39, 8, 6
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v0, v[17:18], s[8:11], 0 addr64
        v_cndmask_b32   v7, v53, v14, s[2:3]
        v_add_i32       v23, vcc, s4, v16
        v_addc_u32      v24, vcc, v6, 0, vcc
        v_bfe_u32       v17, v39, 2, 6
        v_and_b32       v11, 48, v11
        buffer_load_ubyte v8, v[19:20], s[8:11], 0 addr64
        v_add_i32       v19, vcc, s4, v17
        v_addc_u32      v20, vcc, v6, 0, vcc
        v_or_b32        v7, v7, v11
        buffer_load_ubyte v11, v[21:22], s[8:11], 0 addr64
        v_add_i32       v21, vcc, s4, v7
        v_addc_u32      v22, vcc, v6, 0, vcc
        v_bfe_u32       v15, v42, 22, 6
        buffer_load_ubyte v14, v[23:24], s[8:11], 0 addr64
        v_add_i32       v15, vcc, s4, v15
        v_addc_u32      v16, vcc, v6, 0, vcc
        v_bfe_u32       v18, v42, 16, 6
        buffer_load_ubyte v12, v[19:20], s[8:11], 0 addr64
        v_add_i32       v17, vcc, s4, v18
        v_addc_u32      v18, vcc, v6, 0, vcc
        v_bfe_u32       v19, v42, 10, 6
        buffer_load_ubyte v7, v[21:22], s[8:11], 0 addr64
        v_add_i32       v23, vcc, s4, v19
        v_addc_u32      v24, vcc, v6, 0, vcc
        v_bfe_u32       v20, v42, 4, 6
        v_lshrrev_b32   v21, 30, v59
        v_lshlrev_b32   v22, 2, v42
        buffer_load_ubyte v15, v[15:16], s[8:11], 0 addr64
        v_add_i32       v25, vcc, s4, v20
        v_addc_u32      v26, vcc, v6, 0, vcc
        v_bfi_b32       v21, 60, v22, v21
        buffer_load_ubyte v17, v[17:18], s[8:11], 0 addr64
        v_add_i32       v20, vcc, s4, v21
        v_addc_u32      v21, vcc, v6, 0, vcc
        v_bfe_u32       v22, v59, 24, 6
        buffer_load_ubyte v13, v[23:24], s[8:11], 0 addr64
        v_add_i32       v22, vcc, s4, v22
        v_addc_u32      v23, vcc, v6, 0, vcc
        buffer_load_ubyte v16, v[25:26], s[8:11], 0 addr64
        buffer_load_ubyte v18, v[20:21], s[8:11], 0 addr64
        buffer_load_ubyte v6, v[22:23], s[8:11], 0 addr64
        buffer_store_byte v3, v[4:5], s[28:31], 0 offset:17 glc addr64
        buffer_store_byte v1, v[4:5], s[28:31], 0 offset:18 glc addr64
        buffer_store_byte v36, v[4:5], s[28:31], 0 offset:19 glc addr64
        buffer_store_byte v10, v[4:5], s[28:31], 0 offset:20 glc addr64
        buffer_store_byte v9, v[4:5], s[28:31], 0 offset:24 glc addr64
        buffer_store_byte v2, v[4:5], s[28:31], 0 offset:28 glc addr64
        buffer_store_byte v0, v[4:5], s[28:31], 0 offset:5 glc addr64
        buffer_store_byte v8, v[4:5], s[28:31], 0 offset:6 glc addr64
        buffer_store_byte v11, v[4:5], s[28:31], 0 offset:7 glc addr64
        buffer_store_byte v14, v[4:5], s[28:31], 0 offset:8 glc addr64
        buffer_store_byte v12, v[4:5], s[28:31], 0 offset:9 glc addr64
        buffer_store_byte v7, v[4:5], s[28:31], 0 offset:10 glc addr64
        buffer_store_byte v15, v[4:5], s[28:31], 0 offset:11 glc addr64
        buffer_store_byte v17, v[4:5], s[28:31], 0 offset:12 glc addr64
        buffer_store_byte v13, v[4:5], s[28:31], 0 offset:13 glc addr64
        buffer_store_byte v16, v[4:5], s[28:31], 0 offset:14 glc addr64
        v_mov_b32       v0, 1
        buffer_store_byte v18, v[4:5], s[28:31], 0 offset:15 glc addr64
        v_add_i32       v1, vcc, 1, v35
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:16 glc addr64
        buffer_store_byte v0, v[4:5], s[28:31], 0 offset:4 glc addr64
        buffer_store_dword v1, v[4:5], s[28:31], 0 addr64
.L9640_2:
        s_endpgm
.kernel OpenCL_SHA1_PerformSearching_ForwardAndBackwardMatching
    .header
        .fill 8, 1, 0x00
        .byte 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00
        .byte 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        .fill 8, 1, 0x00
    .metadata
        .ascii ";ARGSTART:__OpenCL_OpenCL_SHA1_PerformSearching_ForwardAndBackwardMatchi"
        .ascii "ng_kernel\n"
        .ascii ";version:3:1:111\n"
        .ascii ";device:hawaii\n"
        .ascii ";uniqueid:1027\n"
        .ascii ";memory:uavprivate:0\n"
        .ascii ";memory:hwlocal:4416\n"
        .ascii ";memory:hwregion:0\n"
        .ascii ";pointer:outputArray:struct:1:1:0:uav:12:32:RW:0:0\n"
        .ascii ";pointer:key:u8:1:1:16:c:13:1:RO:0:0\n"
        .ascii ";constarg:1:key\n"
        .ascii ";pointer:tripcodeChunkArray:u32:1:1:32:uav:14:4:RO:0:0\n"
        .ascii ";constarg:2:tripcodeChunkArray\n"
        .ascii ";value:numTripcodeChunk:u32:1:1:48\n"
        .ascii ";pointer:keyCharTable_OneByte:u8:1:1:64:c:11:1:RO:0:0\n"
        .ascii ";constarg:4:keyCharTable_OneByte\n"
        .ascii ";pointer:keyCharTable_FirstByte:u8:1:1:80:c:15:1:RO:0:0\n"
        .ascii ";constarg:5:keyCharTable_FirstByte\n"
        .ascii ";pointer:keyCharTable_SecondByte:u8:1:1:96:c:11:1:RO:0:0\n"
        .ascii ";constarg:6:keyCharTable_SecondByte\n"
        .ascii ";pointer:keyCharTable_SecondByteAndOneByte:u8:1:1:112:c:16:1:RO:0:0\n"
        .ascii ";constarg:7:keyCharTable_SecondByteAndOneByte\n"
        .ascii ";pointer:smallChunkBitmap_constant:u8:1:1:128:c:17:1:RO:0:0\n"
        .ascii ";constarg:8:smallChunkBitmap_constant\n"
        .ascii ";pointer:chunkBitmap:u8:1:1:144:uav:18:1:RO:0:0\n"
        .ascii ";constarg:9:chunkBitmap\n"
        .ascii ";memory:datareqd\n"
        .ascii ";function:1:1038\n"
        .ascii ";memory:64bitABI\n"
        .ascii ";uavid:11\n"
        .ascii ";printfid:9\n"
        .ascii ";cbid:10\n"
        .ascii ";privateid:8\n"
        .ascii ";reflection:0:GPUOutput*\n"
        .ascii ";reflection:1:uchar*\n"
        .ascii ";reflection:2:uint*\n"
        .ascii ";reflection:3:uint\n"
        .ascii ";reflection:4:uchar*\n"
        .ascii ";reflection:5:uchar*\n"
        .ascii ";reflection:6:uchar*\n"
        .ascii ";reflection:7:uchar*\n"
        .ascii ";reflection:8:uchar*\n"
        .ascii ";reflection:9:uchar*\n"
        .ascii ";ARGEND:__OpenCL_OpenCL_SHA1_PerformSearching_ForwardAndBackwardMatching"
        .ascii "_kernel\n"
    .data
        .fill 4736, 1, 0x00
    .inputs
    .outputs
    .uav
        .entry 12, 4, 0, 5
        .entry 14, 4, 0, 5
        .entry 18, 4, 0, 5
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
        .cbmask 13, 0
        .cbmask 11, 0
        .cbmask 15, 0
        .cbmask 11, 0
        .cbmask 16, 0
        .cbmask 17, 0
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
        .entry 0x80001041, 0x00000041
        .entry 0x80001042, 0x00000034
        .entry 0x80001863, 0x00000066
        .entry 0x80001864, 0x00000100
        .entry 0x80001043, 0x000000c0
        .entry 0x80001044, 0x00000000
        .entry 0x80001045, 0x00000000
        .entry 0x00002e13, 0x00048098
        .entry 0x8000001c, 0x00000100
        .entry 0x8000001d, 0x00000000
        .entry 0x8000001e, 0x00000000
        .entry 0x80001841, 0x00000000
        .entry 0x8000001f, 0x0007f400
        .entry 0x80001843, 0x0007f400
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
        .entry 0x80000082, 0x00000900
    .subconstantbuffers
    .uavmailboxsize 0
    .uavopmask
        .byte 0x00, 0xf4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00
        .fill 120, 1, 0x00
    .text
        s_mov_b32       m0, 0x10000
        s_buffer_load_dwordx2 s[0:1], s[8:11], 0x4
        s_load_dwordx4  s[16:19], s[2:3], 0x68
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 1
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 11
        s_addc_u32      s21, s1, 0
        v_mov_b32       v1, s14
        v_mov_b32       v2, s15
        v_mov_b32       v3, s20
        v_mov_b32       v4, s21
        v_mov_b32       v5, s0
        v_mov_b32       v6, s1
        buffer_load_ubyte v1, v[1:2], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[3:4], s[16:19], 0 addr64
        buffer_load_ubyte v3, v[5:6], s[16:19], 0 addr64
        s_buffer_load_dword s13, s[4:7], 0x4
        s_buffer_load_dword s14, s[4:7], 0x18
        s_buffer_load_dword s15, s[4:7], 0x1c
        s_waitcnt       lgkmcnt(0)
        s_min_u32       s13, s13, 0xffff
        s_mul_i32       s13, s12, s13
        s_buffer_load_dwordx2 s[20:21], s[8:11], 0x0
        s_buffer_load_dwordx2 s[22:23], s[8:11], 0x14
        s_buffer_load_dwordx2 s[24:25], s[8:11], 0x1c
        s_add_u32       s13, s13, s14
        v_add_i32       v4, vcc, s13, v0
        s_add_u32       s12, s12, s15
        v_ashrrev_i32   v5, 31, v4
        s_load_dwordx4  s[28:31], s[2:3], 0x60
        s_load_dwordx4  s[32:35], s[2:3], 0x78
        s_load_dwordx4  s[36:39], s[2:3], 0x80
        s_ashr_i32      s13, s12, 6
        v_and_b32       v6, 63, v0
        s_and_b32       s12, s12, 63
        v_lshl_b64      v[4:5], v[4:5], 5
        s_waitcnt       vmcnt(1)
        v_add_i32       v2, vcc, s13, v2
        v_add_i32       v1, vcc, v1, v6
        s_waitcnt       vmcnt(0)
        v_add_i32       v3, vcc, s12, v3
        s_add_u32       s12, s0, 2
        s_addc_u32      s13, s1, 0
        s_add_u32       s14, s0, 3
        s_addc_u32      s15, s1, 0
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v4, vcc, s20, v4
        v_mov_b32       v6, s21
        v_addc_u32      v5, vcc, v6, v5, vcc
        v_mov_b32       v6, 0
        v_ashrrev_i32   v7, 31, v2
        v_add_i32       v14, vcc, s24, v2
        v_mov_b32       v8, s25
        v_addc_u32      v15, vcc, v8, v7, vcc
        v_ashrrev_i32   v9, 31, v1
        v_add_i32       v7, vcc, s24, v1
        v_addc_u32      v8, vcc, v8, v9, vcc
        v_ashrrev_i32   v9, 31, v3
        v_add_i32       v16, vcc, s22, v3
        v_mov_b32       v10, s23
        v_addc_u32      v17, vcc, v10, v9, vcc
        v_mov_b32       v10, s12
        v_mov_b32       v11, s13
        v_mov_b32       v12, s14
        v_mov_b32       v13, s15
        buffer_load_ubyte v10, v[10:11], s[16:19], 0 addr64
        buffer_load_ubyte v11, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v2, v[14:15], s[36:39], 0 addr64
        buffer_load_ubyte v1, v[7:8], s[36:39], 0 addr64
        buffer_load_ubyte v3, v[16:17], s[32:35], 0 addr64
        s_buffer_load_dwordx2 s[4:5], s[4:7], 0x20
        s_buffer_load_dwordx2 s[6:7], s[8:11], 0x8
        s_buffer_load_dword s12, s[8:11], 0xc
        s_buffer_load_dwordx2 s[14:15], s[8:11], 0x20
        s_buffer_load_dwordx2 s[8:9], s[8:11], 0x24
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:4 glc addr64
        v_cmp_eq_i32    vcc, 0, v0
        s_and_saveexec_b64 s[10:11], vcc
        s_cbranch_execz .L892_3
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s14, 7
        s_addc_u32      s15, s15, 0
        s_load_dwordx4  s[40:43], s[2:3], 0x88
        s_mov_b64       s[20:21], exec
        s_mov_b64       s[26:27], exec
        v_mov_b32       v6, 0
        v_mov_b32       v7, 0
.L400_3:
        v_add_i32       v8, vcc, s14, v6
        v_mov_b32       v9, s15
        v_addc_u32      v9, vcc, v9, v7, vcc
        v_add_i32       v12, vcc, v8, -7
        v_addc_u32      v13, vcc, v9, -1, vcc
        v_add_i32       v14, vcc, v8, -6
        v_addc_u32      v15, vcc, v9, -1, vcc
        v_add_i32       v16, vcc, v8, -5
        v_addc_u32      v17, vcc, v9, -1, vcc
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v12, v[12:13], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -4
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v14, v[14:15], s[40:43], 0 addr64
        v_add_i32       v23, vcc, v8, -3
        v_addc_u32      v24, vcc, v9, -1, vcc
        buffer_load_ubyte v16, v[16:17], s[40:43], 0 addr64
        v_add_i32       v19, vcc, v8, -2
        v_addc_u32      v20, vcc, v9, -1, vcc
        buffer_load_ubyte v13, v[21:22], s[40:43], 0 addr64
        v_add_i32       v21, vcc, v8, -1
        v_addc_u32      v22, vcc, v9, -1, vcc
        buffer_load_ubyte v15, v[23:24], s[40:43], 0 addr64
        buffer_load_ubyte v17, v[19:20], s[40:43], 0 addr64
        buffer_load_ubyte v18, v[21:22], s[40:43], 0 addr64
        buffer_load_ubyte v19, v[8:9], s[40:43], 0 addr64
        buffer_load_ubyte v20, v[8:9], s[40:43], 0 offset:1 addr64
        buffer_load_ubyte v21, v[8:9], s[40:43], 0 offset:2 addr64
        buffer_load_ubyte v22, v[8:9], s[40:43], 0 offset:3 addr64
        buffer_load_ubyte v23, v[8:9], s[40:43], 0 offset:4 addr64
        buffer_load_ubyte v24, v[8:9], s[40:43], 0 offset:5 addr64
        buffer_load_ubyte v25, v[8:9], s[40:43], 0 offset:6 addr64
        buffer_load_ubyte v26, v[8:9], s[40:43], 0 offset:7 addr64
        buffer_load_ubyte v8, v[8:9], s[40:43], 0 offset:8 addr64
        ds_write_b8     v6, v12 offset:320
        s_waitcnt       vmcnt(14)
        ds_write_b8     v6, v14 offset:321
        s_waitcnt       vmcnt(13)
        ds_write_b8     v6, v16 offset:322
        s_waitcnt       vmcnt(12)
        ds_write_b8     v6, v13 offset:323
        s_waitcnt       vmcnt(11)
        ds_write_b8     v6, v15 offset:324
        s_waitcnt       vmcnt(10)
        ds_write_b8     v6, v17 offset:325
        s_waitcnt       vmcnt(9)
        ds_write_b8     v6, v18 offset:326
        s_waitcnt       vmcnt(8)
        ds_write_b8     v6, v19 offset:327
        s_waitcnt       vmcnt(7)
        ds_write_b8     v6, v20 offset:328
        s_waitcnt       vmcnt(6)
        ds_write_b8     v6, v21 offset:329
        s_waitcnt       vmcnt(5)
        ds_write_b8     v6, v22 offset:330
        s_waitcnt       vmcnt(4)
        ds_write_b8     v6, v23 offset:331
        s_waitcnt       vmcnt(3)
        ds_write_b8     v6, v24 offset:332
        s_waitcnt       vmcnt(2)
        ds_write_b8     v6, v25 offset:333
        s_waitcnt       vmcnt(1)
        ds_write_b8     v6, v26 offset:334
        v_add_i32       v9, vcc, v6, 16
        v_addc_u32      v7, vcc, v7, 0, vcc
        s_movk_i32      s13, 0x1000
        s_waitcnt       vmcnt(0)
        ds_write_b8     v6, v8 offset:335
        v_cmp_eq_i32    vcc, s13, v9
        s_and_saveexec_b64 s[44:45], vcc
        s_andn2_b64     s[26:27], s[26:27], exec
        s_cbranch_scc0  .L892_3
        s_and_b64       exec, s[44:45], s[26:27]
        v_mov_b32       v6, v9
        s_branch        .L400_3
.L892_3:
        s_mov_b64       exec, s[10:11]
        s_add_u32       s10, s0, 5
        s_addc_u32      s11, s1, 0
        s_waitcnt       lgkmcnt(0)
        s_add_u32       s14, s0, 4
        s_addc_u32      s15, s1, 0
        s_add_u32       s20, s0, 6
        s_addc_u32      s21, s1, 0
        v_mov_b32       v6, s10
        v_mov_b32       v7, s11
        v_mov_b32       v8, s14
        v_mov_b32       v9, s15
        s_add_u32       s10, s0, 8
        s_addc_u32      s11, s1, 0
        v_mov_b32       v12, s20
        v_mov_b32       v13, s21
        v_mov_b32       v14, s10
        v_mov_b32       v15, s11
        s_add_u32       s10, s0, 9
        s_addc_u32      s11, s1, 0
        buffer_load_ubyte v6, v[6:7], s[16:19], 0 addr64
        buffer_load_ubyte v7, v[8:9], s[16:19], 0 addr64
        s_add_u32       s14, s0, 7
        s_addc_u32      s15, s1, 0
        s_add_u32       s0, s0, 10
        s_addc_u32      s1, s1, 0
        v_mov_b32       v8, s10
        v_mov_b32       v9, s11
        buffer_load_ubyte v12, v[12:13], s[16:19], 0 addr64
        buffer_load_ubyte v13, v[14:15], s[16:19], 0 addr64
        v_mov_b32       v14, s14
        v_mov_b32       v15, s15
        v_mov_b32       v16, s0
        v_mov_b32       v17, s1
        buffer_load_ubyte v8, v[8:9], s[16:19], 0 addr64
        buffer_load_ubyte v9, v[14:15], s[16:19], 0 addr64
        buffer_load_ubyte v14, v[16:17], s[16:19], 0 addr64
        s_waitcnt       vmcnt(6)
        v_lshlrev_b32   v6, 16, v6
        s_waitcnt       vmcnt(5)
        v_lshlrev_b32   v7, 24, v7
        v_or_b32        v6, v6, v7
        s_waitcnt       vmcnt(4)
        v_lshlrev_b32   v7, 8, v12
        s_waitcnt       vmcnt(3)
        v_lshlrev_b32   v12, 24, v13
        s_movk_i32      s0, 0xff
        v_or_b32        v6, v6, v7
        v_bfi_b32       v7, s0, v2, v12
        s_waitcnt       vmcnt(2)
        v_lshlrev_b32   v8, 16, v8
        s_waitcnt       vmcnt(1)
        v_or_b32        v6, v9, v6
        v_mov_b32       v12, 0
        v_or_b32        v7, v7, v8
        s_waitcnt       vmcnt(0)
        v_lshlrev_b32   v8, 8, v14
        ds_write2_b32   v12, v12, v6 offset1:1
        v_or_b32        v6, v7, v8
        v_mov_b32       v7, 0x80000000
        ds_write2_b32   v12, v6, v7 offset0:2 offset1:3
        ds_write2_b32   v12, v12, v12 offset0:4 offset1:5
        ds_write2_b32   v12, v12, v12 offset0:6 offset1:7
        ds_write2_b32   v12, v12, v12 offset0:8 offset1:9
        ds_write2_b32   v12, v12, v12 offset0:10 offset1:11
        ds_write2_b32   v12, v12, v12 offset0:12 offset1:13
        v_mov_b32       v7, 0x60
        ds_write2_b32   v12, v12, v7 offset0:14 offset1:15
        v_alignbit_b32  v6, v6, v6, 31
        ds_write_b32    v12, v6 offset:64
        s_movk_i32      s0, 0x0
        s_movk_i32      s1, 0x0
.L1260_3:
        v_mov_b32       v6, s0
        ds_read2_b32    v[7:8], v6 offset0:14 offset1:15
        ds_read2_b32    v[12:13], v6 offset0:9 offset1:10
        ds_read2_b32    v[14:15], v6 offset0:3 offset1:4
        ds_read2_b32    v[16:17], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(2)
        v_xor_b32       v8, v8, v13
        v_xor_b32       v7, v7, v12
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v8, v8, v15
        v_xor_b32       v7, v14, v7
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v8, v17, v8
        v_xor_b32       v7, v16, v7
        v_alignbit_b32  v8, v8, v8, 31
        v_alignbit_b32  v7, v7, v7, 31
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:16 offset1:11
        ds_read_b32     v12, v6 offset:20
        s_waitcnt       lgkmcnt(1)
        v_xor_b32       v7, v7, v8
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v7, v7, v12
        v_xor_b32       v7, v14, v7
        v_alignbit_b32  v7, v7, v7, 31
        ds_write_b32    v6, v7 offset:76
        s_add_u32       s0, s0, 12
        s_addc_u32      s1, s1, 0
        s_cmp_eq_i32    s0, 0xfc
        s_cbranch_scc1  .L1432_3
        s_branch        .L1260_3
.L1432_3:
        v_mov_b32       v6, 0
        ds_read2_b32    v[7:8], v6 offset0:1 offset1:2
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:1 offset1:2
        ds_read2_b32    v[7:8], v6 offset0:17 offset1:18
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x5a827999, v8
        v_add_i32       v7, vcc, 0x5a827999, v7
        ds_write2_b32   v6, v7, v8 offset0:17 offset1:18
        ds_read2_b32    v[7:8], v6 offset0:20 offset1:21
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        ds_write2_b32   v6, v7, v8 offset0:20 offset1:21
        ds_read2_b32    v[7:8], v6 offset0:23 offset1:26
        ds_read2_b32    v[12:13], v6 offset0:27 offset1:29
        s_waitcnt       lgkmcnt(1)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v12, vcc, 0x6ed9eba1, v12
        ds_write2_b32   v6, v7, v8 offset0:23 offset1:26
        v_add_i32       v7, vcc, 0x6ed9eba1, v13
        ds_write2_b32   v6, v12, v7 offset0:27 offset1:29
        ds_read2_b32    v[7:8], v6 offset0:33 offset1:39
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x6ed9eba1, v7
        v_add_i32       v8, vcc, 0x6ed9eba1, v8
        ds_write2_b32   v6, v7, v8 offset0:33 offset1:39
        ds_read2_b32    v[7:8], v6 offset0:41 offset1:45
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0x8f1bbcdc, v8
        ds_write2_b32   v6, v7, v8 offset0:41 offset1:45
        ds_read2_b32    v[7:8], v6 offset0:53 offset1:65
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0x8f1bbcdc, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:53 offset1:65
        ds_read2_b32    v[7:8], v6 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v7, vcc, 0xca62c1d6, v7
        v_add_i32       v8, vcc, 0xca62c1d6, v8
        ds_write2_b32   v6, v7, v8 offset0:69 offset1:77
        s_waitcnt       lgkmcnt(0)
        s_barrier
        ds_read2_b32    v[7:8], v6 offset0:38 offset1:39
        ds_read2_b32    v[12:13], v6 offset0:36 offset1:37
        ds_read2_b32    v[14:15], v6 offset0:34 offset1:35
        ds_read2_b32    v[16:17], v6 offset0:32 offset1:33
        ds_read2_b32    v[18:19], v6 offset0:30 offset1:31
        ds_read2_b32    v[20:21], v6 offset0:28 offset1:29
        ds_read2_b32    v[22:23], v6 offset0:26 offset1:27
        ds_read2_b32    v[24:25], v6 offset0:24 offset1:25
        ds_read2_b32    v[26:27], v6 offset0:22 offset1:23
        ds_read2_b32    v[28:29], v6 offset0:20 offset1:21
        ds_read2_b32    v[30:31], v6 offset0:18 offset1:19
        ds_read2_b32    v[32:33], v6 offset0:16 offset1:17
        v_lshlrev_b32   v6, 24, v3
        v_lshlrev_b32   v34, 16, v1
        v_or_b32        v6, v6, v34
        v_lshrrev_b32   v0, 2, v0
        v_and_b32       v0, 48, v0
        v_add_i32       v0, vcc, v10, v0
        s_waitcnt       lgkmcnt(0)
        s_barrier
        s_load_dwordx4  s[16:19], s[2:3], 0x90
        s_load_dwordx4  s[40:43], s[2:3], 0x70
        s_add_u32       s0, -1, s12
        s_waitcnt       lgkmcnt(0)
        s_bfe_u32       s11, s41, 0x100000
        s_mov_b32       s10, s40
        s_add_u32       s10, s10, s6
        s_addc_u32      s11, s11, s7
        s_load_dword    s1, s[10:11], 0x0
        s_mov_b64       s[10:11], exec
        s_mov_b64       s[12:13], exec
        v_mov_b32       v63, v11
        v_mov_b32       v35, v34
        v_mov_b32       v64, v34
        v_mov_b32       v47, v34
        v_mov_b32       v10, v34
        v_mov_b32       v36, v34
        v_mov_b32       v37, v34
        v_mov_b32       v38, v34
        v_mov_b32       v34, 0
.L1980_3:
        s_movk_i32      s14, 0x3ff
        v_cmp_gt_i32    s[14:15], v34, s14
        s_and_saveexec_b64 s[20:21], s[14:15]
        v_cndmask_b32   v63, 0, -1, s[14:15]
        s_cbranch_execz .L2020_3
        v_mov_b32       v35, 0
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L7160_3
.L2020_3:
        s_and_b64       exec, s[20:21], s[12:13]
        v_ashrrev_i32   v10, 6, v34
        v_bfe_u32       v35, v0, 0, 8
        v_add_i32       v10, vcc, v35, v10
        v_ashrrev_i32   v35, 31, v10
        v_add_i32       v39, vcc, s22, v10
        v_mov_b32       v36, s23
        v_addc_u32      v40, vcc, v36, v35, vcc
        s_waitcnt       lgkmcnt(0)
        s_barrier
        v_and_b32       v10, 63, v34
        v_bfe_u32       v37, v11, 0, 8
        v_add_i32       v10, vcc, v37, v10
        v_ashrrev_i32   v37, 31, v10
        v_add_i32       v36, vcc, s24, v10
        v_mov_b32       v38, s25
        v_addc_u32      v37, vcc, v38, v37, vcc
        buffer_load_ubyte v63, v[39:40], s[32:35], 0 addr64
        buffer_load_ubyte v64, v[36:37], s[36:39], 0 addr64
        v_mov_b32       v36, 0
        ds_read2_b32    v[37:38], v36 offset0:1 offset1:2
        s_waitcnt       vmcnt(1)
        v_lshlrev_b32   v39, 8, v63
        v_or_b32        v39, v6, v39
        s_waitcnt       vmcnt(0)
        v_or_b32        v39, v39, v64
        v_add_i32       v40, vcc, 0x9fb498b3, v39
        v_alignbit_b32  v41, v40, v40, 27
        s_waitcnt       lgkmcnt(0)
        v_add_i32       v37, vcc, v41, v37
        v_add_i32       v37, vcc, 0xc2e5374, v37
        v_mov_b32       v41, 0x7bf36ae2
        s_mov_b32       s14, 0x59d148c0
        v_bfi_b32       v41, v40, s14, v41
        v_alignbit_b32  v42, v37, v37, 27
        v_add_i32       v41, vcc, v41, v42
        v_add_i32       v38, vcc, v38, v41
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x98badcfe, v38
        v_bfi_b32       v41, v37, v40, s14
        v_alignbit_b32  v42, v38, v38, 27
        v_add_i32       v41, vcc, v42, v41
        v_add_i32       v41, vcc, 0x7bf36ae2, v41
        v_xor_b32       v41, 0x80000000, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v42, v41, v41, 27
        v_bfi_b32       v43, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0xb453c259, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v43, v37, v37, 27
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v38, vcc, v38, v43
        v_bfi_b32       v43, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, v44, v41
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v43, v42, v42, 27
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v40, vcc, v40, v43
        v_bfi_b32       v43, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x5a827999, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_alignbit_b32  v43, v40, v40, 27
        v_bfi_b32       v44, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, v44, v37
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v44, v38
        v_add_i32       v38, vcc, 0x5a827999, v38
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v41, vcc, v41, v43
        v_bfi_b32       v43, v37, v40, v42
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x5a827999, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_alignbit_b32  v43, v41, v41, 27
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v44, v42
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_alignbit_b32  v43, v42, v42, 27
        v_bfi_b32       v44, v41, v38, v37
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v43, v39, v39, 31
        v_add_i32       v40, vcc, 0x5a8279f9, v40
        v_xor_b32       v43, v32, v43
        v_alignbit_b32  v44, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v37, vcc, v44, v37
        v_bfi_b32       v43, v42, v41, v38
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x5a827999, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_alignbit_b32  v43, v37, v37, 27
        v_add_i32       v38, vcc, v33, v38
        v_bfi_b32       v44, v40, v42, v41
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v44, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_alignbit_b32  v43, v38, v38, 27
        v_add_i32       v41, vcc, v30, v41
        v_bfi_b32       v44, v37, v40, v42
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v39, v39, 30
        v_add_i32       v41, vcc, v44, v41
        v_xor_b32       v44, v31, v43
        v_alignbit_b32  v45, v41, v41, 27
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v42, vcc, v45, v42
        v_bfi_b32       v44, v38, v37, v40
        v_add_i32       v42, vcc, v42, v44
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v44, v41, v37
        v_add_i32       v42, vcc, 0x5a827999, v42
        v_xor_b32       v44, v38, v44
        v_add_i32       v40, vcc, v28, v40
        v_xor_b32       v45, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v44, v40
        v_alignbit_b32  v44, v42, v42, 27
        v_xor_b32       v45, v45, v41
        v_add_i32       v37, vcc, v29, v37
        v_add_i32       v40, vcc, v40, v44
        v_alignbit_b32  v44, v39, v39, 29
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v46, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v26, v44
        v_add_i32       v37, vcc, v37, v45
        v_xor_b32       v45, v46, v42
        v_add_i32       v38, vcc, v38, v47
        v_alignbit_b32  v46, v37, v37, 27
        v_add_i32       v38, vcc, v45, v38
        v_add_i32       v38, vcc, v46, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v45, v37, v42
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v45, v40, v45
        v_add_i32       v41, vcc, v27, v41
        v_xor_b32       v46, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v24, v43
        v_add_i32       v41, vcc, v45, v41
        v_alignbit_b32  v45, v38, v38, 27
        v_xor_b32       v46, v46, v37
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v41, vcc, v41, v45
        v_add_i32       v42, vcc, v46, v42
        v_alignbit_b32  v45, v41, v41, 27
        v_alignbit_b32  v46, v39, v39, 28
        v_add_i32       v42, vcc, v42, v45
        v_xor_b32       v45, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v47, v25, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v45, v45, v38
        v_add_i32       v40, vcc, v40, v47
        v_alignbit_b32  v47, v42, v42, 27
        v_add_i32       v40, vcc, v45, v40
        v_add_i32       v40, vcc, v47, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v45, v42, v38
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v45, v41, v45
        v_add_i32       v37, vcc, v22, v37
        v_xor_b32       v47, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v45, v37
        v_alignbit_b32  v45, v40, v40, 27
        v_xor_b32       v47, v47, v42
        v_add_i32       v38, vcc, v23, v38
        v_add_i32       v37, vcc, v37, v45
        v_alignbit_b32  v45, v39, v39, 27
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v47, v37, v37, 27
        v_xor_b32       v48, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v49, v20, v45
        v_add_i32       v38, vcc, v38, v47
        v_xor_b32       v47, v48, v40
        v_add_i32       v41, vcc, v41, v49
        v_alignbit_b32  v48, v38, v38, 27
        v_add_i32       v41, vcc, v47, v41
        v_add_i32       v41, vcc, v48, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v47, v38, v40
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_xor_b32       v48, v18, v43
        v_xor_b32       v47, v37, v47
        v_add_i32       v42, vcc, v21, v42
        v_xor_b32       v49, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v48, v46, v48
        v_add_i32       v42, vcc, v47, v42
        v_alignbit_b32  v47, v41, v41, 27
        v_xor_b32       v49, v49, v38
        v_add_i32       v40, vcc, v40, v48
        v_add_i32       v42, vcc, v42, v47
        v_add_i32       v40, vcc, v49, v40
        v_alignbit_b32  v47, v42, v42, 27
        v_alignbit_b32  v48, v39, v39, 26
        v_add_i32       v40, vcc, v40, v47
        v_xor_b32       v47, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v49, v19, v48
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_xor_b32       v47, v47, v41
        v_add_i32       v37, vcc, v37, v49
        v_alignbit_b32  v49, v40, v40, 27
        v_add_i32       v37, vcc, v47, v37
        v_xor_b32       v43, v16, v43
        v_add_i32       v37, vcc, v49, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v47, v40, v41
        v_xor_b32       v43, v44, v43
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v47, v42, v47
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, v47, v38
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v47, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v47, v40
        v_add_i32       v41, vcc, v17, v41
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_alignbit_b32  v47, v39, v39, 25
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v50, v14, v47
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v42, vcc, v42, v50
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v43, v42
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_xor_b32       v49, v15, v46
        v_add_i32       v42, vcc, 0x6ed9eba1, v42
        v_xor_b32       v43, v38, v43
        v_add_i32       v40, vcc, v40, v49
        v_xor_b32       v49, v46, v48
        v_add_i32       v40, vcc, v43, v40
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v50, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v51, v12, v49
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v50, v41
        v_add_i32       v37, vcc, v37, v51
        v_add_i32       v40, vcc, 0x6ed9eba1, v40
        v_add_i32       v37, vcc, v43, v37
        v_alignbit_b32  v43, v40, v40, 27
        v_alignbit_b32  v50, v39, v39, 24
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v51, v13, v50
        v_add_i32       v37, vcc, 0x6ed9eba1, v37
        v_xor_b32       v43, v43, v42
        v_add_i32       v38, vcc, v38, v51
        v_alignbit_b32  v51, v37, v37, 27
        v_add_i32       v38, vcc, v43, v38
        v_add_i32       v38, vcc, v51, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_xor_b32       v51, v7, v46
        v_add_i32       v38, vcc, 0x6ed9eba1, v38
        v_xor_b32       v43, v40, v43
        v_add_i32       v41, vcc, v41, v51
        v_add_i32       v41, vcc, v43, v41
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v51, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        ds_read2_b32    v[52:53], v36 offset0:40 offset1:41
        v_xor_b32       v43, v51, v37
        v_add_i32       v42, vcc, v8, v42
        v_add_i32       v41, vcc, 0x6ed9eba1, v41
        v_add_i32       v42, vcc, v43, v42
        v_alignbit_b32  v43, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v51, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        v_alignbit_b32  v55, v39, v39, 23
        v_xor_b32       v43, v43, v51
        v_add_i32       v40, vcc, v40, v54
        v_xor_b32       v51, v46, v55
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v51, v52
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v51, v41, 0, v42
        v_alignbit_b32  v52, v40, v40, 27
        ds_read2_b32    v[54:55], v36 offset0:42 offset1:43
        v_xor_b32       v43, v43, v51
        v_add_i32       v37, vcc, v37, v52
        v_add_i32       v37, vcc, v43, v37
        v_add_i32       v37, vcc, v53, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v51, v42, 0, v40
        v_alignbit_b32  v52, v37, v37, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v38, vcc, v38, v52
        v_xor_b32       v51, v48, v50
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v51
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v51, v40, 0, v37
        v_alignbit_b32  v52, v38, v38, 27
        v_xor_b32       v43, v43, v51
        v_add_i32       v41, vcc, v41, v52
        v_alignbit_b32  v51, v39, v39, 22
        ds_read2_b32    v[52:53], v36 offset0:44 offset1:45
        v_add_i32       v41, vcc, v43, v41
        v_xor_b32       v43, v55, v51
        v_add_i32       v41, vcc, v41, v43
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v54, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v56, v44, v48
        v_xor_b32       v43, v43, v54
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v54, v47, v56
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v54, v52
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v52, v38, 0, v41
        v_alignbit_b32  v54, v42, v42, 27
        ds_read2_b32    v[55:56], v36 offset0:46 offset1:47
        v_xor_b32       v43, v43, v52
        v_add_i32       v40, vcc, v40, v54
        v_add_i32       v40, vcc, v43, v40
        v_add_i32       v40, vcc, v53, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v52, v41, 0, v42
        v_alignbit_b32  v53, v40, v40, 27
        v_alignbit_b32  v54, v39, v39, 21
        v_xor_b32       v43, v43, v52
        v_add_i32       v37, vcc, v37, v53
        v_xor_b32       v52, v46, v54
        v_add_i32       v37, vcc, v43, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v55, v52
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v52, v42, 0, v40
        v_alignbit_b32  v53, v37, v37, 27
        v_xor_b32       v43, v43, v52
        v_add_i32       v38, vcc, v38, v53
        v_xor_b32       v52, v46, v50
        ds_read2_b32    v[57:58], v36 offset0:48 offset1:49
        v_add_i32       v38, vcc, v43, v38
        v_xor_b32       v43, v56, v52
        v_add_i32       v38, vcc, v38, v43
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v44, v45
        v_bfi_b32       v44, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        v_xor_b32       v43, v52, v43
        v_xor_b32       v44, v44, v53
        v_add_i32       v41, vcc, v41, v55
        v_xor_b32       v43, v51, v43
        v_add_i32       v41, vcc, v44, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v57
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v44, v37, 0, v38
        v_alignbit_b32  v53, v41, v41, 27
        v_xor_b32       v43, v43, v44
        v_add_i32       v42, vcc, v42, v53
        v_alignbit_b32  v44, v39, v39, 20
        ds_read2_b32    v[55:56], v36 offset0:50 offset1:51
        v_add_i32       v42, vcc, v43, v42
        v_xor_b32       v43, v58, v44
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v57, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v57
        v_add_i32       v40, vcc, v43, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v50, v55
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_bfi_b32       v43, v38, v41, v42
        v_bfi_b32       v53, v41, 0, v42
        v_alignbit_b32  v55, v40, v40, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v37, vcc, v37, v55
        ds_read2_b32    v[57:58], v36 offset0:52 offset1:53
        v_add_i32       v37, vcc, v43, v37
        v_xor_b32       v43, v49, v56
        v_add_i32       v37, vcc, v37, v43
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_alignbit_b32  v42, v42, v42, 2
        v_bfi_b32       v43, v41, v42, v40
        v_bfi_b32       v53, v42, 0, v40
        v_alignbit_b32  v55, v37, v37, 27
        v_alignbit_b32  v56, v39, v39, 19
        v_xor_b32       v43, v43, v53
        v_add_i32       v38, vcc, v38, v55
        v_xor_b32       v53, v52, v56
        v_add_i32       v38, vcc, v43, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v57
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_bfi_b32       v43, v42, v40, v37
        v_bfi_b32       v53, v40, 0, v37
        v_alignbit_b32  v55, v38, v38, 27
        ds_read2_b32    v[59:60], v36 offset0:54 offset1:55
        v_xor_b32       v43, v43, v53
        v_add_i32       v41, vcc, v41, v55
        v_add_i32       v41, vcc, v43, v41
        v_add_i32       v41, vcc, v58, v41
        v_alignbit_b32  v37, v37, v37, 2
        v_bfi_b32       v43, v40, v37, v38
        v_bfi_b32       v53, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        v_xor_b32       v57, v47, v51
        v_xor_b32       v43, v43, v53
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v53, v44, v57
        v_add_i32       v42, vcc, v43, v42
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v53, v59
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_bfi_b32       v43, v37, v38, v41
        v_bfi_b32       v53, v38, 0, v41
        v_alignbit_b32  v55, v42, v42, 27
        v_xor_b32       v43, v43, v53
        v_add_i32       v40, vcc, v40, v55
        v_alignbit_b32  v53, v39, v39, 18
        ds_read2_b32    v[57:58], v36 offset0:56 offset1:57
        v_add_i32       v40, vcc, v43, v40
        v_xor_b32       v43, v53, v60
        v_add_i32       v40, vcc, v40, v43
        v_add_i32       v40, vcc, 0x8f1bbcdc, v40
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v47, v49
        v_bfi_b32       v55, v38, v41, v42
        v_bfi_b32       v59, v41, 0, v42
        v_alignbit_b32  v60, v40, v40, 27
        v_xor_b32       v51, v51, v43
        v_xor_b32       v55, v55, v59
        v_add_i32       v37, vcc, v37, v60
        v_xor_b32       v51, v54, v51
        v_add_i32       v37, vcc, v55, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v51, v57
        v_add_i32       v37, vcc, v37, v51
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, 0x8f1bbcdc, v37
        v_bfi_b32       v51, v41, v42, v40
        v_bfi_b32       v55, v42, 0, v40
        v_alignbit_b32  v57, v37, v37, 27
        v_xor_b32       v51, v51, v55
        v_add_i32       v38, vcc, v38, v57
        ds_read2_b32    v[59:60], v36 offset0:58 offset1:59
        v_add_i32       v38, vcc, v51, v38
        v_xor_b32       v51, v50, v58
        v_add_i32       v38, vcc, v38, v51
        v_add_i32       v38, vcc, 0x8f1bbcdc, v38
        v_alignbit_b32  v40, v40, v40, 2
        v_bfi_b32       v51, v42, v40, v37
        v_bfi_b32       v55, v40, 0, v37
        v_alignbit_b32  v57, v38, v38, 27
        v_alignbit_b32  v58, v39, v39, 17
        v_xor_b32       v51, v51, v55
        v_add_i32       v41, vcc, v41, v57
        v_xor_b32       v52, v52, v58
        v_add_i32       v41, vcc, v51, v41
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v51, v52, v59
        v_add_i32       v41, vcc, v41, v51
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, 0x8f1bbcdc, v41
        v_bfi_b32       v51, v40, v37, v38
        v_bfi_b32       v52, v37, 0, v38
        v_alignbit_b32  v55, v41, v41, 27
        ds_read2_b32    v[61:62], v36 offset0:60 offset1:61
        v_xor_b32       v51, v51, v52
        v_add_i32       v42, vcc, v42, v55
        v_xor_b32       v52, v50, v44
        v_add_i32       v42, vcc, v51, v42
        v_xor_b32       v51, v52, v60
        v_add_i32       v42, vcc, v42, v51
        v_xor_b32       v51, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v46, v46, v47
        v_add_i32       v42, vcc, 0x8f1bbcdc, v42
        v_xor_b32       v51, v51, v38
        v_xor_b32       v46, v52, v46
        v_alignbit_b32  v55, v42, v42, 27
        v_add_i32       v40, vcc, v40, v51
        v_xor_b32       v46, v53, v46
        v_add_i32       v40, vcc, v55, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v46, v61
        v_add_i32       v40, vcc, v40, v46
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v46, v42, v38
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v46, v41, v46
        ds_read2_b32    v[59:60], v36 offset0:62 offset1:63
        v_add_i32       v37, vcc, v37, v46
        v_alignbit_b32  v46, v40, v40, 27
        v_alignbit_b32  v51, v39, v39, 16
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v51, v62
        v_xor_b32       v55, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v46
        v_xor_b32       v46, v55, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v38, vcc, v38, v46
        v_alignbit_b32  v46, v37, v37, 27
        v_xor_b32       v49, v49, v52
        v_add_i32       v38, vcc, v38, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v46, v49, v59
        v_add_i32       v38, vcc, v38, v46
        v_xor_b32       v46, v42, v37
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v46, v46, v40
        ds_read2_b32    v[61:62], v36 offset0:64 offset1:65
        v_alignbit_b32  v49, v38, v38, 27
        v_add_i32       v41, vcc, v41, v46
        v_add_i32       v41, vcc, v49, v41
        v_xor_b32       v46, v50, v60
        v_add_i32       v41, vcc, v41, v46
        v_alignbit_b32  v37, v37, v37, 2
        v_xor_b32       v46, v38, v40
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v46, v37, v46
        v_xor_b32       v43, v43, v52
        v_alignbit_b32  v49, v39, v39, 15
        v_add_i32       v42, vcc, v42, v46
        v_alignbit_b32  v46, v41, v41, 27
        v_xor_b32       v43, v43, v49
        v_add_i32       v42, vcc, v42, v46
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_xor_b32       v46, v41, v37
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, v42, v43
        ds_read2_b32    v[59:60], v36 offset0:66 offset1:67
        v_xor_b32       v43, v46, v38
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v38, v42
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v62
        v_xor_b32       v43, v43, v41
        v_alignbit_b32  v46, v40, v40, 27
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v53, v51
        v_add_i32       v37, vcc, v46, v37
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v59
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v43, v40, v41
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v42, v43
        v_alignbit_b32  v46, v39, v39, 14
        ds_read2_b32    v[61:62], v36 offset0:68 offset1:69
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v43, v37, v37, 27
        v_xor_b32       v49, v50, v46
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v49, v37, v42
        v_alignbit_b32  v40, v40, v40, 2
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v49, v40
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v49, v54, v53
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_xor_b32       v49, v58, v49
        v_add_i32       v41, vcc, v41, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v61
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v40, v38
        v_alignbit_b32  v37, v37, v37, 2
        ds_read2_b32    v[59:60], v36 offset0:70 offset1:71
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_xor_b32       v43, v43, v37
        v_alignbit_b32  v49, v41, v41, 27
        v_add_i32       v42, vcc, v42, v43
        v_add_i32       v42, vcc, v49, v42
        v_alignbit_b32  v38, v38, v38, 2
        v_xor_b32       v43, v41, v37
        v_add_i32       v42, vcc, v42, v62
        v_xor_b32       v43, v38, v43
        v_alignbit_b32  v49, v39, v39, 13
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v43, v42, v42, 27
        v_xor_b32       v49, v44, v49
        v_add_i32       v40, vcc, v40, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v59
        v_xor_b32       v49, v42, v38
        v_alignbit_b32  v41, v41, v41, 2
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v49, v41
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        ds_read2_b32    v[61:62], v36 offset0:72 offset1:73
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v49, v44, v51
        v_xor_b32       v45, v45, v54
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v49, v60
        v_xor_b32       v45, v44, v45
        v_add_i32       v37, vcc, v37, v43
        v_xor_b32       v43, v41, v40
        v_alignbit_b32  v42, v42, v42, 2
        v_xor_b32       v45, v56, v45
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_xor_b32       v43, v43, v42
        v_xor_b32       v45, v51, v45
        v_alignbit_b32  v49, v37, v37, 27
        v_add_i32       v38, vcc, v38, v43
        v_xor_b32       v43, v46, v45
        v_add_i32       v38, vcc, v49, v38
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v43, v61
        v_add_i32       v38, vcc, v38, v43
        v_alignbit_b32  v40, v40, v40, 2
        v_xor_b32       v43, v37, v42
        v_add_i32       v38, vcc, 0xca62c1d6, v38
        v_xor_b32       v43, v40, v43
        ds_read2_b32    v[54:55], v36 offset0:74 offset1:75
        v_add_i32       v41, vcc, v41, v43
        v_alignbit_b32  v43, v38, v38, 27
        v_alignbit_b32  v45, v39, v39, 12
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v45, v62
        v_xor_b32       v49, v38, v40
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v41, vcc, v41, v43
        v_xor_b32       v43, v49, v37
        v_add_i32       v41, vcc, 0xca62c1d6, v41
        v_add_i32       v42, vcc, v42, v43
        v_alignbit_b32  v43, v41, v41, 27
        v_xor_b32       v49, v50, v51
        v_add_i32       v42, vcc, v42, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v49, v54
        v_add_i32       v42, vcc, v42, v43
        v_xor_b32       v43, v37, v41
        v_alignbit_b32  v38, v38, v38, 2
        v_add_i32       v42, vcc, 0xca62c1d6, v42
        v_xor_b32       v43, v43, v38
        v_xor_b32       v48, v48, v44
        ds_read2_b32    v[56:57], v36 offset0:76 offset1:77
        v_alignbit_b32  v49, v42, v42, 27
        v_add_i32       v40, vcc, v40, v43
        v_xor_b32       v43, v53, v48
        v_add_i32       v40, vcc, v49, v40
        v_xor_b32       v43, v43, v55
        v_xor_b32       v47, v47, v50
        v_add_i32       v40, vcc, v40, v43
        v_alignbit_b32  v41, v41, v41, 2
        v_xor_b32       v43, v42, v38
        v_xor_b32       v44, v44, v47
        v_add_i32       v40, vcc, 0xca62c1d6, v40
        v_xor_b32       v43, v41, v43
        v_xor_b32       v44, v51, v44
        v_alignbit_b32  v48, v39, v39, 11
        v_add_i32       v37, vcc, v37, v43
        v_alignbit_b32  v43, v40, v40, 27
        v_xor_b32       v44, v44, v48
        v_add_i32       v37, vcc, v37, v43
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v43, v44, v56
        v_xor_b32       v44, v40, v41
        v_alignbit_b32  v42, v42, v42, 2
        v_add_i32       v37, vcc, v37, v43
        ds_read2_b32    v[48:49], v36 offset0:78 offset1:79
        v_xor_b32       v36, v44, v42
        v_add_i32       v37, vcc, 0xca62c1d6, v37
        v_add_i32       v36, vcc, v38, v36
        v_alignbit_b32  v38, v37, v37, 27
        v_add_i32       v36, vcc, v36, v38
        v_alignbit_b32  v38, v40, v40, 2
        v_xor_b32       v40, v42, v37
        v_xor_b32       v43, v58, v47
        v_add_i32       v36, vcc, v36, v57
        v_xor_b32       v40, v38, v40
        v_xor_b32       v43, v46, v43
        v_alignbit_b32  v44, v36, v36, 27
        v_add_i32       v40, vcc, v41, v40
        v_xor_b32       v41, v45, v43
        v_add_i32       v40, vcc, v44, v40
        s_waitcnt       lgkmcnt(0)
        v_xor_b32       v41, v41, v48
        v_xor_b32       v38, v36, v38
        v_alignbit_b32  v37, v37, v37, 2
        v_add_i32       v40, vcc, v40, v41
        v_xor_b32       v37, v38, v37
        v_add_i32       v38, vcc, 0xca62c1d6, v40
        v_alignbit_b32  v39, v39, v39, 10
        v_add_i32       v37, vcc, v42, v37
        v_alignbit_b32  v38, v38, v38, 27
        v_xor_b32       v39, v50, v39
        v_add_i32       v37, vcc, v37, v38
        v_xor_b32       v38, v39, v49
        v_add_i32       v37, vcc, v37, v38
        v_add_i32       v37, vcc, 0x31a7e4d7, v37
        v_lshrrev_b32   v38, 20, v37
        ds_read_u8      v38, v38 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v38, v38, 0, 8
        v_alignbit_b32  v36, v36, v36, 2
        v_cmp_lg_i32    s[14:15], v38, 0
        v_add_i32       v36, vcc, 0x98badcfe, v36
        v_add_i32       v10, vcc, 0xba306d5f, v40
        s_mov_b64       s[20:21], exec
        s_andn2_b64     exec, s[20:21], s[14:15]
        v_lshrrev_b32   v38, 8, v37
        s_cbranch_execz .L6792_3
        v_add_i32       v41, vcc, s8, v38
        v_mov_b32       v42, s9
        v_addc_u32      v42, vcc, v42, 0, vcc
        buffer_load_ubyte v41, v[41:42], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v41
        s_and_saveexec_b64 s[14:15], vcc
        v_lshrrev_b32   v41, 2, v37
        s_cbranch_execz .L6772_3
        s_mov_b64       s[26:27], exec
        s_mov_b64       s[44:45], exec
        v_mov_b32       v42, 0
        v_mov_b32       v35, s1
        v_mov_b32       v44, s0
.L6616_3:
        v_cmp_gt_i32    s[46:47], v42, v44
        v_cmp_eq_i32    vcc, v41, v35
        s_or_b64        vcc, s[46:47], vcc
        s_and_saveexec_b64 s[46:47], vcc
        s_andn2_b64     s[44:45], s[44:45], exec
        s_cbranch_scc0  .L6728_3
        s_and_b64       exec, s[46:47], s[44:45]
        v_add_i32       v43, vcc, v42, v44
        v_ashrrev_i32   v48, 1, v43
        v_ashrrev_i32   v49, 31, v48
        v_lshl_b64      v[45:46], v[48:49], 2
        v_add_i32       v45, vcc, s6, v45
        v_mov_b32       v47, s7
        v_addc_u32      v46, vcc, v47, v46, vcc
        buffer_load_dword v35, v[45:46], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[46:47], v35, v41
        v_add_i32       v46, vcc, -1, v48
        v_add_i32       v43, vcc, 1, v48
        v_cndmask_b32   v44, v44, v46, s[46:47]
        v_cndmask_b32   v42, v43, v42, s[46:47]
        s_branch        .L6616_3
.L6728_3:
        s_mov_b64       exec, s[26:27]
        v_cmp_lg_i32    vcc, v41, v35
        s_mov_b64       s[26:27], exec
        s_andn2_b64     exec, s[26:27], vcc
        v_mov_b32       v35, 1
        s_cbranch_execz .L6764_3
        v_mov_b32       v47, 0
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L7160_3
.L6764_3:
        s_and_b64       exec, s[26:27], s[12:13]
        v_mov_b32       v35, 1
.L6772_3:
        s_andn2_b64     exec, s[14:15], exec
        s_and_b64       exec, exec, s[12:13]
        v_mov_b32       v35, 0
        s_cbranch_execz .L6788_3
.L6788_3:
        s_and_b64       exec, s[14:15], s[12:13]
.L6792_3:
        s_andn2_b64     exec, s[20:21], exec
        s_and_b64       exec, exec, s[12:13]
        v_mov_b32       v35, 0
        s_cbranch_execz .L6808_3
.L6808_3:
        s_and_b64       exec, s[20:21], s[12:13]
        v_bfe_u32       v38, v10, 10, 12
        ds_read_u8      v42, v38 offset:320
        s_waitcnt       lgkmcnt(0)
        v_bfe_u32       v42, v42, 0, 8
        v_cmp_eq_i32    s[14:15], v42, 0
        s_and_saveexec_b64 s[20:21], s[14:15]
        v_lshlrev_b32   v40, 8, v40
        s_cbranch_execz .L7128_3
        v_lshrrev_b32   v47, 24, v36
        v_add_i32       v40, vcc, 0x306d5f00, v40
        s_mov_b32       s26, 0x3fffff00
        v_bfi_b32       v38, s26, v40, v47
        v_lshrrev_b32   v42, 6, v38
        v_add_i32       v42, vcc, s8, v42
        v_mov_b32       v43, s9
        v_addc_u32      v43, vcc, v43, 0, vcc
        buffer_load_ubyte v42, v[42:43], s[16:19], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_eq_i32    vcc, 0, v42
        s_and_saveexec_b64 s[26:27], vcc
        s_cbranch_execz .L7124_3
        s_mov_b64       s[44:45], exec
        s_mov_b64       s[46:47], exec
        v_mov_b32       v39, 0
        v_mov_b32       v35, s1
        v_mov_b32       v43, s0
.L6952_3:
        v_cmp_gt_i32    s[48:49], v39, v43
        v_cmp_eq_i32    vcc, v38, v35
        s_or_b64        vcc, s[48:49], vcc
        s_and_saveexec_b64 s[48:49], vcc
        s_andn2_b64     s[46:47], s[46:47], exec
        s_cbranch_scc0  .L7064_3
        s_and_b64       exec, s[48:49], s[46:47]
        v_add_i32       v42, vcc, v39, v43
        v_ashrrev_i32   v40, 1, v42
        v_ashrrev_i32   v41, 31, v40
        v_lshl_b64      v[44:45], v[40:41], 2
        v_add_i32       v44, vcc, s6, v44
        v_mov_b32       v46, s7
        v_addc_u32      v45, vcc, v46, v45, vcc
        buffer_load_dword v35, v[44:45], s[40:43], 0 addr64
        s_waitcnt       vmcnt(0)
        v_cmp_ge_u32    s[48:49], v35, v38
        v_add_i32       v45, vcc, -1, v40
        v_add_i32       v42, vcc, 1, v40
        v_cndmask_b32   v43, v43, v45, s[48:49]
        v_cndmask_b32   v39, v42, v39, s[48:49]
        s_branch        .L6952_3
.L7064_3:
        s_mov_b64       exec, s[44:45]
        v_cmp_lg_i32    s[44:45], v38, v35
        s_mov_b64       s[46:47], exec
        s_andn2_b64     exec, s[46:47], s[44:45]
        v_cndmask_b32   v38, 0, -1, s[44:45]
        s_cbranch_execz .L7108_3
        v_mov_b32       v35, 2
        s_andn2_b64     s[12:13], s[12:13], exec
        s_cbranch_scc0  .L7160_3
.L7108_3:
        s_and_b64       exec, s[46:47], s[12:13]
        v_cndmask_b32   v38, 0, -1, s[44:45]
        v_mov_b32       v35, 2
.L7124_3:
        s_and_b64       exec, s[26:27], s[12:13]
.L7128_3:
        s_andn2_b64     exec, s[20:21], exec
        s_and_b64       exec, exec, s[12:13]
        v_cndmask_b32   v47, 0, -1, s[14:15]
        s_cbranch_execz .L7148_3
.L7148_3:
        s_and_b64       exec, s[20:21], s[12:13]
        v_add_i32       v34, vcc, 1, v34
        s_branch        .L1980_3
.L7160_3:
        s_mov_b64       exec, s[10:11]
        v_cmp_eq_i32    vcc, 0, v35
        s_waitcnt       lgkmcnt(0)
        s_and_saveexec_b64 s[0:1], vcc
        v_mov_b32       v0, 0x400
        s_cbranch_execz .L7196_3
        buffer_store_dword v0, v[4:5], s[28:31], 0 addr64
.L7196_3:
        s_andn2_b64     exec, s[0:1], exec
        s_cbranch_execz .L7760_3
        s_load_dwordx4  s[8:11], s[2:3], 0x50
        v_lshrrev_b32   v14, 26, v37
        v_cmp_eq_i32    s[2:3], v35, 1
        v_lshrrev_b32   v6, 8, v37
        v_add_i32       v20, s[6:7], s4, v14
        v_mov_b32       v15, s5
        v_addc_u32      v21, vcc, v15, 0, s[6:7]
        v_bfe_u32       v17, v37, 20, 6
        v_cndmask_b32   v6, v6, v38, s[2:3]
        v_add_i32       v22, vcc, s4, v17
        v_addc_u32      v23, vcc, v15, 0, vcc
        v_bfe_u32       v18, v37, 14, 6
        v_add_i32       v18, vcc, s4, v18
        v_addc_u32      v19, vcc, v15, 0, vcc
        v_and_b32       v6, 63, v6
        s_waitcnt       lgkmcnt(0)
        buffer_load_ubyte v14, v[20:21], s[8:11], 0 addr64
        v_add_i32       v6, vcc, s4, v6
        v_addc_u32      v7, vcc, v15, 0, vcc
        v_bfe_u32       v20, v37, 2, 6
        v_lshrrev_b32   v21, 28, v10
        v_lshlrev_b32   v12, 4, v37
        buffer_load_ubyte v13, v[22:23], s[8:11], 0 addr64
        v_add_i32       v23, vcc, s4, v20
        v_addc_u32      v24, vcc, v15, 0, vcc
        v_bfi_b32       v12, 48, v12, v21
        buffer_load_ubyte v18, v[18:19], s[8:11], 0 addr64
        v_add_i32       v11, vcc, s4, v12
        v_addc_u32      v12, vcc, v15, 0, vcc
        v_bfe_u32       v21, v10, 22, 6
        buffer_load_ubyte v6, v[6:7], s[8:11], 0 addr64
        v_add_i32       v26, vcc, s4, v21
        v_addc_u32      v27, vcc, v15, 0, vcc
        v_bfe_u32       v22, v10, 16, 6
        buffer_load_ubyte v17, v[23:24], s[8:11], 0 addr64
        v_add_i32       v28, vcc, s4, v22
        v_addc_u32      v29, vcc, v15, 0, vcc
        v_bfe_u32       v23, v10, 10, 6
        buffer_load_ubyte v12, v[11:12], s[8:11], 0 addr64
        v_lshrrev_b32   v19, 24, v36
        v_add_i32       v22, vcc, s4, v23
        v_addc_u32      v23, vcc, v15, 0, vcc
        v_bfe_u32       v25, v10, 4, 6
        v_lshrrev_b32   v11, 30, v36
        v_lshlrev_b32   v10, 2, v10
        buffer_load_ubyte v16, v[26:27], s[8:11], 0 addr64
        v_cndmask_b32   v8, v47, v19, s[2:3]
        v_add_i32       v24, vcc, s4, v25
        v_addc_u32      v25, vcc, v15, 0, vcc
        v_bfi_b32       v10, 60, v10, v11
        buffer_load_ubyte v11, v[28:29], s[8:11], 0 addr64
        v_add_i32       v20, vcc, s4, v10
        v_addc_u32      v21, vcc, v15, 0, vcc
        v_and_b32       v8, 63, v8
        buffer_load_ubyte v22, v[22:23], s[8:11], 0 addr64
        v_add_i32       v7, vcc, s4, v8
        v_addc_u32      v8, vcc, v15, 0, vcc
        buffer_load_ubyte v19, v[24:25], s[8:11], 0 addr64
        buffer_load_ubyte v10, v[20:21], s[8:11], 0 addr64
        buffer_load_ubyte v8, v[7:8], s[8:11], 0 addr64
        buffer_store_byte v3, v[4:5], s[28:31], 0 offset:17 glc addr64
        buffer_store_byte v1, v[4:5], s[28:31], 0 offset:18 glc addr64
        buffer_store_byte v63, v[4:5], s[28:31], 0 offset:19 glc addr64
        buffer_store_byte v64, v[4:5], s[28:31], 0 offset:20 glc addr64
        buffer_store_byte v9, v[4:5], s[28:31], 0 offset:24 glc addr64
        buffer_store_byte v2, v[4:5], s[28:31], 0 offset:28 glc addr64
        buffer_store_byte v14, v[4:5], s[28:31], 0 offset:5 glc addr64
        buffer_store_byte v13, v[4:5], s[28:31], 0 offset:6 glc addr64
        buffer_store_byte v18, v[4:5], s[28:31], 0 offset:7 glc addr64
        buffer_store_byte v6, v[4:5], s[28:31], 0 offset:8 glc addr64
        buffer_store_byte v17, v[4:5], s[28:31], 0 offset:9 glc addr64
        buffer_store_byte v12, v[4:5], s[28:31], 0 offset:10 glc addr64
        buffer_store_byte v16, v[4:5], s[28:31], 0 offset:11 glc addr64
        buffer_store_byte v11, v[4:5], s[28:31], 0 offset:12 glc addr64
        buffer_store_byte v22, v[4:5], s[28:31], 0 offset:13 glc addr64
        buffer_store_byte v19, v[4:5], s[28:31], 0 offset:14 glc addr64
        v_mov_b32       v0, 1
        buffer_store_byte v10, v[4:5], s[28:31], 0 offset:15 glc addr64
        v_add_i32       v1, vcc, 1, v34
        buffer_store_byte v8, v[4:5], s[28:31], 0 offset:16 glc addr64
        buffer_store_byte v0, v[4:5], s[28:31], 0 offset:4 glc addr64
        buffer_store_dword v1, v[4:5], s[28:31], 0 addr64
.L7760_3:
        s_endpgm
