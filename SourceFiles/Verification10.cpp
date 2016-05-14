// Meriken's Tripcode Engine
// Copyright (c) 2011-2016 /Meriken/. <meriken.ygch.net@gmail.com>
//
// The initial versions of this software were based on:
// CUDA SHA-1 Tripper 0.2.1
// Copyright (c) 2009 Horo/.IBXjcg
// 
// The code that deals with DES decryption is partially adopted from:
// John the Ripper password cracker
// Copyright (c) 1996-2002, 2005, 2010 by Solar Designer
// DeepLearningJohnDoe's fork of Meriken's Tripcode Engine
// Copyright (c) 2015 by <deeplearningjohndoe at gmail.com>
//
// The code that deals with SHA-1 hash generation is partially adopted from:
// sha_digest-2.2
// Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
// VecTripper 
// Copyright (C) 2011 tmkk <tmkk@smoug.net>
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.



///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILE(S)                                                           //
///////////////////////////////////////////////////////////////////////////////

#include "MerikensTripcodeEngine.h"



///////////////////////////////////////////////////////////////////////////////
// DES CRYPT(3) WITH CPU                                                     //
///////////////////////////////////////////////////////////////////////////////

char *crypt(char *key, char *salt);

static spinlock descrypt_spinlock;

BOOL VerifyDESTripcode(unsigned char *tripcode, unsigned char *key)
{
        descrypt_spinlock.lock();

        if (strlen((char *)tripcode) != lenTripcode || strlen((char *)key) != lenTripcodeKey)
                return FALSE;
        
        char actualKey[MAX_LEN_TRIPCODE_KEY + 1];
        BOOL fillRestWithZero = FALSE;
        
        strcpy(actualKey, (char *)key);
        for (int32_t i = 0; i < lenTripcodeKey; ++i) {
                if (fillRestWithZero) {
                        actualKey[i] = 0x00;
                } else if (actualKey[i] == 0x80) {
                        fillRestWithZero = TRUE;
                }
        }
        BOOL result = strcmp((char *)tripcode, crypt((char *)actualKey, (char *)(actualKey + 1)) + 3) == 0;

#if FALSE
        if (!result) {
                printf("key:       `%s'\n", key);
                printf("actualKey: `%s'\n", actualKey);
                printf("tripcode:  `%s'\n", tripcode);
                printf("crypt((char *)actualKey, (char *)(actualKey + 1)): `%s'\n", crypt((char *)actualKey, (char *)(actualKey + 1)));
        }
        fflush(stdout);
#endif

        descrypt_spinlock.unlock();

        return result;
}

void GenerateDESTripcode(unsigned char *tripcode, unsigned char *key)
{
    descrypt_spinlock.lock();

    char actualKey[MAX_LEN_TRIPCODE_KEY + 1];
    BOOL fillRestWithZero = FALSE;
        
    memcpy(actualKey, (char *)key, 8);
	actualKey[8] = '\0';
	for (int32_t i = 0; i < lenTripcodeKey; ++i) {
            if (fillRestWithZero) {
                    actualKey[i] = 0x00;
            } else if (actualKey[i] == 0x80) {
                    fillRestWithZero = TRUE;
            }
    }
    strncpy((char *)tripcode, crypt((char *)actualKey, (char *)(actualKey + 1)) + 3, 10);
	tripcode[10] = '\0';

    descrypt_spinlock.unlock();
}



/////////////////////////////////////////////////////////////////////////
// The following are modified versions of ufc.c and ufc_util.c in:     //
// http://packetstorm.foofus.com/crypt/LIBS/ufc-crypt/ufc-crypt.tar.gz //
/////////////////////////////////////////////////////////////////////////

#define _UFC_32_ TRUE

typedef uint32_t ufc_long;
typedef uint32_t long32;

/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 1992, Free Software Foundation, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @(#)crypt_util.c        2.31 02/08/92
 *
 * Support routines
 *
 */

#ifdef DEBUG
#include <stdio.h>
#endif

#ifndef STATIC
#define STATIC static
#endif

// #include "patchlevel.h"
// #include "ufc-crypt.h"

// static char patchlevel_str[] = PATCHLEVEL;

/* 
 * Permutation done once on the 56 bit 
 *  key derived from the original 8 byte ASCII key.
 */
static int32_t pc1[56] = { 
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

/*
 * How much to rotate each 28 bit half of the pc1 permutated
 *  56 bit key before using pc2 to give the i' key
 */
static int32_t rots[16] = { 
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 
};

/* 
 * Permutation giving the key 
 * of the i' DES round 
 */
static int32_t pc2[48] = { 
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/*
 * The E expansion table which selects
 * bits from the 32 bit intermediate result.
 */
static int32_t esel[48] = { 
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
   8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};
static int32_t e_inverse[64];

/* 
 * Permutation done on the 
 * result of sbox lookups 
 */
static int32_t perm32[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
  2,   8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

/* 
 * The sboxes
 */
static int32_t sbox[8][4][16]= {
        { { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
          {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
          {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
          { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
        },

        { { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
          {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
          {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
          { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
        },

        { { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
          { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
          { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
          {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
        },

        { {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
          { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
          { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
          {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
        },

        { {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
          { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
          {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
          { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
        },

        { { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
          { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
          {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
          {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
        },

        { {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
          { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
          {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
          {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
        },

        { { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
          {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
          {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
          {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
        }
};

/* 
 * This is the initial 
 * permutation matrix
 */
static int32_t initial_perm[64] = { 
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15, 7
};

/* 
 * This is the final 
 * permutation matrix
 */
static int32_t final_perm[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

/* 
 * The 16 DES keys in BITMASK format 
 */
#ifdef _UFC_32_
long32 _ufc_keytab[16][2];
#endif
#ifdef _UFC_64_
long64 _ufc_keytab[16];
#endif

#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

/* Macro to set a bit (0..23) */
#define BITMASK(i) ( (1<<(11-(i)%12+3)) << ((i)<12?16:0) )

/*
 * sb arrays:
 *
 * Workhorses of the inner loop of the DES implementation.
 * They do sbox lookup, shifting of this  value, 32 bit
 * permutation and E permutation for the next round.
 *
 * Kept in 'BITMASK' format.
 */

#ifdef _UFC_32_
long32 _ufc_sb0[8192], _ufc_sb1[8192], _ufc_sb2[8192], _ufc_sb3[8192];
static long32 *sb[4] = {_ufc_sb0, _ufc_sb1, _ufc_sb2, _ufc_sb3}; 
#endif

#ifdef _UFC_64_
long64 _ufc_sb0[4096], _ufc_sb1[4096], _ufc_sb2[4096], _ufc_sb3[4096];
static long64 *sb[4] = {_ufc_sb0, _ufc_sb1, _ufc_sb2, _ufc_sb3}; 
#endif

/* 
 * eperm32tab: do 32 bit permutation and E selection
 *
 * The first index is the byte number in the 32 bit value to be permuted
 *  -  second  -   is the value of this byte
 *  -  third   -   selects the two 32 bit values
 *
 * The table is used and generated internally in init_des to speed it up
 */
static ufc_long eperm32tab[4][256][2];

/* 
 * do_pc1: permform pc1 permutation in the key schedule generation.
 *
 * The first   index is the byte number in the 8 byte ASCII key
 *  -  second    -      -    the two 28 bits halfs of the result
 *  -  third     -   selects the 7 bits actually used of each byte
 *
 * The result is kept with 28 bit per 32 bit with the 4 most significant
 * bits zero.
 */
static ufc_long do_pc1[8][2][128];

/*
 * do_pc2: permform pc2 permutation in the key schedule generation.
 *
 * The first   index is the septet number in the two 28 bit intermediate values
 *  -  second    -    -  -  septet values
 *
 * Knowledge of the structure of the pc2 permutation is used.
 *
 * The result is kept with 28 bit per 32 bit with the 4 most significant
 * bits zero.
 */
static ufc_long do_pc2[8][128];

/*
 * efp: undo an extra e selection and do final
 *      permutation giving the DES result.
 * 
 *      Invoked 6 bit a time on two 48 bit values
 *      giving two 32 bit longs.
 */
static ufc_long efp[16][64][2];

static unsigned char bytemask[8]  = {
  0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};

static ufc_long longmask[32] = {
  0x80000000, 0x40000000, 0x20000000, 0x10000000,
  0x08000000, 0x04000000, 0x02000000, 0x01000000,
  0x00800000, 0x00400000, 0x00200000, 0x00100000,
  0x00080000, 0x00040000, 0x00020000, 0x00010000,
  0x00008000, 0x00004000, 0x00002000, 0x00001000,
  0x00000800, 0x00000400, 0x00000200, 0x00000100,
  0x00000080, 0x00000040, 0x00000020, 0x00000010,
  0x00000008, 0x00000004, 0x00000002, 0x00000001
};

#ifdef DEBUG

pr_bits(a, n)
  ufc_long *a;
  int32_t n;
  { ufc_long i, j, t, tmp;
    n /= 8;
    for(i = 0; i < n; i++) {
      tmp=0;
      for(j = 0; j < 8; j++) {
        t=8*i+j;
        tmp|=(a[t/24] & BITMASK(t % 24))?bytemask[j]:0;
      }
      (void)printf("%02x ",tmp);
    }
    printf(" ");
  }

static set_bits(v, b)
  ufc_long v;
  ufc_long *b;
  { ufc_long i;
    *b = 0;
    for(i = 0; i < 24; i++) {
      if(v & longmask[8 + i])
        *b |= BITMASK(i);
    }
  }

#endif

/*
 * Silly rewrite of 'bzero'. I do so
 * because some machines don't have
 * bzero and some don't have memset.
 */

STATIC void clearmem(char *start, int32_t cnt)
  { while(cnt--)
      *start++ = '\0';
  }

static int32_t initialized = 0;

/* lookup a 6 bit value in sbox */

#define s_lookup(i,s) sbox[(i)][(((s)>>4) & 0x2)|((s) & 0x1)][((s)>>1) & 0xf];

/*
 * Initialize unit - may be invoked directly
 * by fcrypt users.
 */

void init_des()
  { int32_t comes_from_bit;
    int32_t bit, sg;
    ufc_long j;
    ufc_long mask1, mask2;

    /*
     * Create the do_pc1 table used
     * to affect pc1 permutation
     * when generating keys
     */
    for(bit = 0; bit < 56; bit++) {
      comes_from_bit  = pc1[bit] - 1;
      mask1 = bytemask[comes_from_bit % 8 + 1];
      mask2 = longmask[bit % 28 + 4];
      for(j = 0; j < 128; j++) {
        if(j & mask1) 
          do_pc1[comes_from_bit / 8][bit / 28][j] |= mask2;
      }
    }

    /*
     * Create the do_pc2 table used
     * to affect pc2 permutation when
     * generating keys
     */
    for(bit = 0; bit < 48; bit++) {
      comes_from_bit  = pc2[bit] - 1;
      mask1 = bytemask[comes_from_bit % 7 + 1];
      mask2 = BITMASK(bit % 24);
      for(j = 0; j < 128; j++) {
        if(j & mask1)
          do_pc2[comes_from_bit / 7][j] |= mask2;
      }
    }

    /* 
     * Now generate the table used to do combined
     * 32 bit permutation and e expansion
     *
     * We use it because we have to permute 16384 32 bit
     * longs into 48 bit in order to initialize sb.
     *
     * Looping 48 rounds per permutation becomes 
     * just too slow...
     *
     */

    clearmem((char*)eperm32tab, sizeof(eperm32tab));

    for(bit = 0; bit < 48; bit++) {
      ufc_long mask1,comes_from;
        
      comes_from = perm32[esel[bit]-1]-1;
      mask1      = bytemask[comes_from % 8];
        
      for(j = 256; j--;) {
        if(j & mask1)
          eperm32tab[comes_from / 8][j][bit / 24] |= BITMASK(bit % 24);
      }
    }
    
    /* 
     * Create the sb tables:
     *
     * For each 12 bit segment of an 48 bit intermediate
     * result, the sb table precomputes the two 4 bit
     * values of the sbox lookups done with the two 6
     * bit halves, shifts them to their proper place,
     * sends them through perm32 and finally E expands
     * them so that they are ready for the next
     * DES round.
     *
     */
    for(sg = 0; sg < 4; sg++) {
      int32_t j1, j2;
      int32_t s1, s2;
    
      for(j1 = 0; j1 < 64; j1++) {
        s1 = s_lookup(2 * sg, j1);
        for(j2 = 0; j2 < 64; j2++) {
          ufc_long to_permute, inx;
    
          s2         = s_lookup(2 * sg + 1, j2);
          to_permute = ((s1 << 4)  | s2) << (24 - 8 * sg);

#ifdef _UFC_32_
          inx = ((j1 << 6)  | j2) << 1;
          sb[sg][inx  ]  = eperm32tab[0][(to_permute >> 24) & 0xff][0];
          sb[sg][inx+1]  = eperm32tab[0][(to_permute >> 24) & 0xff][1];
          sb[sg][inx  ] |= eperm32tab[1][(to_permute >> 16) & 0xff][0];
          sb[sg][inx+1] |= eperm32tab[1][(to_permute >> 16) & 0xff][1];
            sb[sg][inx  ] |= eperm32tab[2][(to_permute >>  8) & 0xff][0];
          sb[sg][inx+1] |= eperm32tab[2][(to_permute >>  8) & 0xff][1];
          sb[sg][inx  ] |= eperm32tab[3][(to_permute)       & 0xff][0];
          sb[sg][inx+1] |= eperm32tab[3][(to_permute)       & 0xff][1];
#endif
#ifdef _UFC_64_
          inx = ((j1 << 6)  | j2);
          sb[sg][inx]  = 
            ((long64)eperm32tab[0][(to_permute >> 24) & 0xff][0] << 32) |
             (long64)eperm32tab[0][(to_permute >> 24) & 0xff][1];
          sb[sg][inx] |=
            ((long64)eperm32tab[1][(to_permute >> 16) & 0xff][0] << 32) |
             (long64)eperm32tab[1][(to_permute >> 16) & 0xff][1];
            sb[sg][inx] |= 
            ((long64)eperm32tab[2][(to_permute >>  8) & 0xff][0] << 32) |
             (long64)eperm32tab[2][(to_permute >>  8) & 0xff][1];
          sb[sg][inx] |=
            ((long64)eperm32tab[3][(to_permute)       & 0xff][0] << 32) |
             (long64)eperm32tab[3][(to_permute)       & 0xff][1];
#endif
        }
      }
    }  

    /* 
     * Create an inverse matrix for esel telling
     * where to plug out bits if undoing it
     */
    for(bit=48; bit--;) {
      e_inverse[esel[bit] - 1     ] = bit;
      e_inverse[esel[bit] - 1 + 32] = bit + 48;
    }

    /* 
     * create efp: the matrix used to
     * undo the E expansion and effect final permutation
     */
    clearmem((char*)efp, sizeof efp);
    for(bit = 0; bit < 64; bit++) {
      int32_t o_bit, o_long;
      ufc_long word_value, mask1, mask2;
      int32_t comes_from_f_bit, comes_from_e_bit;
      int32_t comes_from_word, bit_within_word;

      /* See where bit i belongs in the two 32 bit long's */
      o_long = bit / 32; /* 0..1  */
      o_bit  = bit % 32; /* 0..31 */

      /* 
       * And find a bit in the e permutated value setting this bit.
       *
       * Note: the e selection may have selected the same bit several
       * times. By the initialization of e_inverse, we only look
       * for one specific instance.
       */
      comes_from_f_bit = final_perm[bit] - 1;         /* 0..63 */
      comes_from_e_bit = e_inverse[comes_from_f_bit]; /* 0..95 */
      comes_from_word  = comes_from_e_bit / 6;        /* 0..15 */
      bit_within_word  = comes_from_e_bit % 6;        /* 0..5  */

      mask1 = longmask[bit_within_word + 26];
      mask2 = longmask[o_bit];

      for(word_value = 64; word_value--;) {
        if(word_value & mask1)
          efp[comes_from_word][word_value][o_long] |= mask2;
      }
    }
    initialized++;
  }

/* 
 * Process the elements of the sb table permuting the
 * bits swapped in the expansion by the current salt.
 */

#ifdef _UFC_32_
STATIC void shuffle_sb(long32 *k, ufc_long saltbits)
  { ufc_long j;
    long32 x;
    for(j=4096; j--;) {
      x = (k[0] ^ k[1]) & (long32)saltbits;
      *k++ ^= x;
      *k++ ^= x;
    }
  }
#endif

#ifdef _UFC_64_
STATIC void shuffle_sb(k, saltbits)
  long64 *k;
  ufc_long saltbits;
  { ufc_long j;
    long64 x;
    for(j=4096; j--;) {
      x = ((*k >> 32) ^ *k) & (long64)saltbits;
      *k++ ^= (x << 32) | x;
    }
  }
#endif

/* 
 * Setup the unit for a new salt
 * Hopefully we'll not see a new salt in each crypt call.
 */

static unsigned char current_salt[3] = "&&"; /* invalid value */
static ufc_long current_saltbits = 0;
static int32_t direction = 0;

STATIC void setup_salt(const char *s)
  { ufc_long i, j, saltbits;

    if(!initialized)
      init_des();

    if(s[0] == current_salt[0] && s[1] == current_salt[1])
      return;
    current_salt[0] = s[0]; current_salt[1] = s[1];

    /* 
     * This is the only crypt change to DES:
     * entries are swapped in the expansion table
     * according to the bits set in the salt.
     */
    saltbits = 0;
    for(i = 0; i < 2; i++) {
      int32_t c=ascii_to_bin(s[i]);
      if(c < 0 || c > 63)
        c = 0;
      for(j = 0; j < 6; j++) {
        if((c >> j) & 0x1)
          saltbits |= BITMASK(6 * i + j);
      }
    }

    /*
     * Permute the sb table values
     * to reflect the changed e
     * selection table
     */
    shuffle_sb(_ufc_sb0, current_saltbits ^ saltbits); 
    shuffle_sb(_ufc_sb1, current_saltbits ^ saltbits);
    shuffle_sb(_ufc_sb2, current_saltbits ^ saltbits);
    shuffle_sb(_ufc_sb3, current_saltbits ^ saltbits);

    current_saltbits = saltbits;
  }

STATIC void ufc_mk_keytab(char *key)
  { ufc_long v1, v2, *k1;
    int32_t i;
#ifdef _UFC_32_
    long32 v, *k2 = &_ufc_keytab[0][0];
#endif
#ifdef _UFC_64_
    long64 v, *k2 = &_ufc_keytab[0];
#endif

    v1 = v2 = 0; k1 = &do_pc1[0][0][0];
    for(i = 8; i--;) {
      v1 |= k1[*key   & 0x7f]; k1 += 128;
      v2 |= k1[*key++ & 0x7f]; k1 += 128;
    }

    for(i = 0; i < 16; i++) {
      k1 = &do_pc2[0][0];

      v1 = (v1 << rots[i]) | (v1 >> (28 - rots[i]));
      v  = k1[(v1 >> 21) & 0x7f]; k1 += 128;
      v |= k1[(v1 >> 14) & 0x7f]; k1 += 128;
      v |= k1[(v1 >>  7) & 0x7f]; k1 += 128;
      v |= k1[(v1      ) & 0x7f]; k1 += 128;

#ifdef _UFC_32_
      *k2++ = v;
      v = 0;
#endif
#ifdef _UFC_64_
      v <<= 32;
#endif

      v2 = (v2 << rots[i]) | (v2 >> (28 - rots[i]));
      v |= k1[(v2 >> 21) & 0x7f]; k1 += 128;
      v |= k1[(v2 >> 14) & 0x7f]; k1 += 128;
      v |= k1[(v2 >>  7) & 0x7f]; k1 += 128;
      v |= k1[(v2      ) & 0x7f];

      *k2++ = v;
    }

    direction = 0;
  }

/* 
 * Undo an extra E selection and do final permutations
 */

ufc_long *_ufc_dofinalperm(ufc_long l1, ufc_long l2, ufc_long r1, ufc_long r2)
  { ufc_long v1, v2, x;
    static ufc_long ary[2];

    x = (l1 ^ l2) & current_saltbits; l1 ^= x; l2 ^= x;
    x = (r1 ^ r2) & current_saltbits; r1 ^= x; r2 ^= x;

    v1=v2=0; l1 >>= 3; l2 >>= 3; r1 >>= 3; r2 >>= 3;

    v1 |= efp[15][ r2         & 0x3f][0]; v2 |= efp[15][ r2 & 0x3f][1];
    v1 |= efp[14][(r2 >>= 6)  & 0x3f][0]; v2 |= efp[14][ r2 & 0x3f][1];
    v1 |= efp[13][(r2 >>= 10) & 0x3f][0]; v2 |= efp[13][ r2 & 0x3f][1];
    v1 |= efp[12][(r2 >>= 6)  & 0x3f][0]; v2 |= efp[12][ r2 & 0x3f][1];

    v1 |= efp[11][ r1         & 0x3f][0]; v2 |= efp[11][ r1 & 0x3f][1];
    v1 |= efp[10][(r1 >>= 6)  & 0x3f][0]; v2 |= efp[10][ r1 & 0x3f][1];
    v1 |= efp[ 9][(r1 >>= 10) & 0x3f][0]; v2 |= efp[ 9][ r1 & 0x3f][1];
    v1 |= efp[ 8][(r1 >>= 6)  & 0x3f][0]; v2 |= efp[ 8][ r1 & 0x3f][1];

    v1 |= efp[ 7][ l2         & 0x3f][0]; v2 |= efp[ 7][ l2 & 0x3f][1];
    v1 |= efp[ 6][(l2 >>= 6)  & 0x3f][0]; v2 |= efp[ 6][ l2 & 0x3f][1];
    v1 |= efp[ 5][(l2 >>= 10) & 0x3f][0]; v2 |= efp[ 5][ l2 & 0x3f][1];
    v1 |= efp[ 4][(l2 >>= 6)  & 0x3f][0]; v2 |= efp[ 4][ l2 & 0x3f][1];

    v1 |= efp[ 3][ l1         & 0x3f][0]; v2 |= efp[ 3][ l1 & 0x3f][1];
    v1 |= efp[ 2][(l1 >>= 6)  & 0x3f][0]; v2 |= efp[ 2][ l1 & 0x3f][1];
    v1 |= efp[ 1][(l1 >>= 10) & 0x3f][0]; v2 |= efp[ 1][ l1 & 0x3f][1];
    v1 |= efp[ 0][(l1 >>= 6)  & 0x3f][0]; v2 |= efp[ 0][ l1 & 0x3f][1];

    ary[0] = v1; ary[1] = v2;
    return ary;
  }

/* 
 * crypt only: convert from 64 bit to 11 bit ASCII 
 * prefixing with the salt
 */

STATIC char *output_conversion(ufc_long v1, ufc_long v2, char *salt)
  { static char outbuf[14];
    int32_t i, s;

    outbuf[0] = salt[0];
    outbuf[1] = salt[1] ? salt[1] : salt[0];

    for(i = 0; i < 5; i++)
      outbuf[i + 2] = bin_to_ascii((v1 >> (26 - 6 * i)) & 0x3f);

    s  = (v2 & 0xf) << 2;
    v2 = (v2 >> 2) | ((v1 & 0x3) << 30);

    for(i = 5; i < 10; i++)
      outbuf[i + 2] = bin_to_ascii((v2 >> (56 - 6 * i)) & 0x3f);

    outbuf[12] = bin_to_ascii(s);
    outbuf[13] = 0;

    return outbuf;
  }

ufc_long *_ufc_doit(ufc_long l1, ufc_long l2, ufc_long r1, ufc_long r2, ufc_long itr);

/* 
 * UNIX crypt function
 */
   
char *crypt(char *key, char *salt)
  { ufc_long *s;
    char ktab[9];

    /*
     * Hack DES tables according to salt
     */
    setup_salt(salt);

    /*
     * Setup key schedule
     */
    clearmem(ktab, sizeof ktab);
    (void)strncpy(ktab, key, 8);
    ufc_mk_keytab(ktab);

    /*
     * Go for the 25 DES encryptions
     */
    s = _ufc_doit((ufc_long)0, (ufc_long)0, 
                  (ufc_long)0, (ufc_long)0, (ufc_long)25);

    /*
     * And convert back to 6 bit ASCII
     */
    return output_conversion(s[0], s[1], salt);
  }

/* 
 * To make fcrypt users happy.
 * They don't need to call init_des.
 */

char *fcrypt(char *key, char *salt)
  { return crypt(key, salt);
  }

/* 
 * UNIX encrypt function. Takes a bitvector
 * represented by one byte per bit and
 * encrypt/decrypt according to edflag
 */

void encrypt(char *block, int32_t edflag)
  { ufc_long l1, l2, r1, r2, *s;
    int32_t i;

    /*
     * Undo any salt changes to E expansion
     */
    setup_salt("..");

    /*
     * Reverse key table if
     * changing operation (encrypt/decrypt)
     */
    if((edflag == 0) != (direction == 0)) {
      for(i = 0; i < 8; i++) {
#ifdef _UFC_32_
        long32 x;
        x = _ufc_keytab[15-i][0]; 
        _ufc_keytab[15-i][0] = _ufc_keytab[i][0]; 
        _ufc_keytab[i][0] = x;

        x = _ufc_keytab[15-i][1]; 
        _ufc_keytab[15-i][1] = _ufc_keytab[i][1]; 
        _ufc_keytab[i][1] = x;
#endif
#ifdef _UFC_64_
        long64 x;
        x = _ufc_keytab[15-i];
        _ufc_keytab[15-i] = _ufc_keytab[i];
        _ufc_keytab[i] = x;
#endif
      }
      direction = edflag;
    }

    /*
     * Do initial permutation + E expansion
     */
    i = 0;
    for(l1 = 0; i < 24; i++) {
      if(block[initial_perm[esel[i]-1]-1])
        l1 |= BITMASK(i);
    }
    for(l2 = 0; i < 48; i++) {
      if(block[initial_perm[esel[i]-1]-1])
        l2 |= BITMASK(i-24);
    }

    i = 0;
    for(r1 = 0; i < 24; i++) {
      if(block[initial_perm[esel[i]-1+32]-1])
        r1 |= BITMASK(i);
    }
    for(r2 = 0; i < 48; i++) {
      if(block[initial_perm[esel[i]-1+32]-1])
        r2 |= BITMASK(i-24);
    }

    /*
     * Do DES inner loops + final conversion
     */
    s = _ufc_doit(l1, l2, r1, r2, (ufc_long)1);

    /*
     * And convert to bit array
     */
    l1 = s[0]; r1 = s[1];
    for(i = 0; i < 32; i++) {
      *block++ = (l1 & longmask[i]) != 0;
    }
    for(i = 0; i < 32; i++) {
      *block++ = (r1 & longmask[i]) != 0;
    }
    
  }

/* 
 * UNIX setkey function. Take a 64 bit DES
 * key and setup the machinery.
 */

void setkey(char *key)
  { int32_t i,j;
    unsigned char c;
    unsigned char ktab[8];

    setup_salt(".."); /* be sure we're initialized */

    for(i = 0; i < 8; i++) {
      for(j = 0, c = 0; j < 8; j++)
        c = c << 1 | *key++;
      ktab[i] = c >> 1;
    }
    
    ufc_mk_keytab((char *)ktab);
  }

/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 1992, Free Software Foundation, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @(#)crypt.c        2.17 2/22/92
 *
 * Semiportable C version
 *
 */

// #include "ufc-crypt.h"

extern ufc_long *_ufc_dofinalperm();

#ifdef _UFC_32_

/*
 * 32 bit version
 */

extern long32 _ufc_keytab[16][2];
extern long32 _ufc_sb0[], _ufc_sb1[], _ufc_sb2[], _ufc_sb3[];

#define SBA(sb, v) (*(long32*)((char*)(sb)+(v)))

ufc_long *_ufc_doit(ufc_long l1, ufc_long l2, ufc_long r1, ufc_long r2, ufc_long itr)
  { int32_t i;
    long32 s, *k;

    while(itr--) {
      k = &_ufc_keytab[0][0];
      for(i=8; i--; ) {
        s = *k++ ^ r1;
        l1 ^= SBA(_ufc_sb1, s & 0xffff); l2 ^= SBA(_ufc_sb1, (s & 0xffff)+4);  
        l1 ^= SBA(_ufc_sb0, s >>= 16);   l2 ^= SBA(_ufc_sb0, (s)         +4); 
        s = *k++ ^ r2; 
        l1 ^= SBA(_ufc_sb3, s & 0xffff); l2 ^= SBA(_ufc_sb3, (s & 0xffff)+4);
        l1 ^= SBA(_ufc_sb2, s >>= 16);   l2 ^= SBA(_ufc_sb2, (s)         +4);

        s = *k++ ^ l1; 
        r1 ^= SBA(_ufc_sb1, s & 0xffff); r2 ^= SBA(_ufc_sb1, (s & 0xffff)+4);  
        r1 ^= SBA(_ufc_sb0, s >>= 16);   r2 ^= SBA(_ufc_sb0, (s)         +4); 
        s = *k++ ^ l2; 
        r1 ^= SBA(_ufc_sb3, s & 0xffff); r2 ^= SBA(_ufc_sb3, (s & 0xffff)+4);  
        r1 ^= SBA(_ufc_sb2, s >>= 16);   r2 ^= SBA(_ufc_sb2, (s)         +4);
      } 
      s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
    }
    return _ufc_dofinalperm(l1, l2, r1, r2);
  }

#endif

#ifdef _UFC_64_

/*
 * 64 bit version
 */

extern long64 _ufc_keytab[16];
extern long64 _ufc_sb0[], _ufc_sb1[], _ufc_sb2[], _ufc_sb3[];

#define SBA(sb, v) (*(long64*)((char*)(sb)+(v)))

ufc_long *_ufc_doit(l1, l2, r1, r2, itr)
  ufc_long l1, l2, r1, r2, itr;
  { int32_t i;
    long64 l, r, s, *k;

    l = (((long64)l1) << 32) | ((long64)l2);
    r = (((long64)r1) << 32) | ((long64)r2);

    while(itr--) {
      k = &_ufc_keytab[0];
      for(i=8; i--; ) {
        s = *k++ ^ r;
        l ^= SBA(_ufc_sb3, (s >>  0) & 0xffff);
        l ^= SBA(_ufc_sb2, (s >> 16) & 0xffff);
        l ^= SBA(_ufc_sb1, (s >> 32) & 0xffff);
        l ^= SBA(_ufc_sb0, (s >> 48) & 0xffff);

        s = *k++ ^ l;
        r ^= SBA(_ufc_sb3, (s >>  0) & 0xffff);
        r ^= SBA(_ufc_sb2, (s >> 16) & 0xffff);
        r ^= SBA(_ufc_sb1, (s >> 32) & 0xffff);
        r ^= SBA(_ufc_sb0, (s >> 48) & 0xffff);
      } 
      s=l; l=r; r=s;
    }

    l1 = l >> 32; l2 = l & 0xffffffff;
    r1 = r >> 32; r2 = r & 0xffffffff;
    return _ufc_dofinalperm(l1, l2, r1, r2);
  }

#endif



///////////////////////////////////////////////////////////////////////////////
// BITSLICE DES                                                              //
///////////////////////////////////////////////////////////////////////////////

typedef uint32_t vtype;

#define BITSLICE_DES_DEPTH     32

// All bitslice DES parameters combined into one struct for more efficient
// cache usage and multi-threading.
#define DES_NUM_KEYS 56
#define NUM_DATA_BLOCKS 64
typedef struct {
	unsigned char expansionFunction[96];
	vtype    expandedKeySchedule[0x300];
	vtype    dataBlocks[NUM_DATA_BLOCKS];
	vtype    temp[1 + 12];
	vtype    keys[DES_NUM_KEYS];
	//
	void          (*crypt25)(void *);
} DES_Context;

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

#define vnot(dst, a)     (dst) =  (~(a))
#define vand(dst, a, b)  (dst) =  ((a) & (b))
#define vor(dst, a, b)   (dst) =  ((a) | (b))
#define vxor(dst, a, b)  (dst) =  ((a) ^ (b))
#define vandn(dst, a, b) (dst) =  ((a) & (~(b)))

#define s1(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var0, var4); \
	vxor(var7, var3, var6); \
	vor(var8, var2, var5); \
	vxor(var9, var0, var2); \
	vand(var10, var8, var9); \
	vxor(var11, var3, var10); \
	vandn(var12, var11, var7); \
	vxor(var13, var4, var5); \
	vxor(var14, var2, var13); \
	vandn(var15, var7, var14); \
	vor(var14, var5, var10); \
	vxor(var10, var15, var14); \
	vandn(var14, var10, var12); \
	vor(var15, var0, var5); \
	vor(var5, var10, var15); \
	vandn(var16, var4, var11); \
	vxor(var11, var5, var16); \
	vandn(var17, var3, var15); \
	vxor(var3, var16, var17); \
	vandn(var15, var13, var9); \
	vor(var9, var3, var15); \
	vandn(var3, var2, var6); \
	vxor(var2, var7, var5); \
	vandn(var6, var2, var3); \
	vnot(var2, var6); \
	vand(var3, var8, var10); \
	vxor(var10, var2, var3); \
	vandn(var2, var11, var1); \
	vxor(var3, var2, var10); \
	vxor(out3, out3, var3); \
	vxor(var2, var13, var6); \
	vor(var3, var16, var2); \
	vxor(var2, var8, var3); \
	vxor(var3, var0, var2); \
	vxor(var0, var10, var3); \
	vor(var2, var12, var1); \
	vxor(var6, var2, var0); \
	vxor(out1, out1, var6); \
	vxor(var2, var8, var5); \
	vor(var5, var9, var2); \
	vxor(var2, var3, var5); \
	vor(var5, var13, var0); \
	vxor(var0, var2, var5); \
	vor(var5, var14, var1); \
	vxor(var6, var5, var0); \
	vxor(out2, out2, var6); \
	vor(var0, var4, var7); \
	vandn(var4, var0, var2); \
	vand(var0, var14, var3); \
	vxor(var2, var4, var0); \
	vor(var0, var2, var1); \
	vxor(var1, var0, var9); \
	vxor(out4, out4, var1); \
}                  \

#define s2(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor(var6, var1, var4); \
	vandn(var7, var0, var5); \
	vandn(var8, var4, var7); \
	vor(var7, var1, var8); \
	vandn(var9, var6, var5); \
	vand(var10, var0, var6); \
	vxor(var11, var4, var10); \
	vandn(var10, var11, var9); \
	vand(var12, var2, var5); \
	vxor(var13, var8, var9); \
	vand(var8, var7, var13); \
	vandn(var13, var8, var12); \
	vand(var14, var2, var8); \
	vnot(var8, var0); \
	vxor(var0, var14, var8); \
	vxor(var8, var5, var6); \
	vandn(var5, var8, var12); \
	vxor(var6, var0, var5); \
	vandn(var15, var3, var13); \
	vxor(var13, var15, var6); \
	vxor(out2, out2, var13); \
	vandn(var13, var1, var5); \
	vxor(var1, var11, var13); \
	vandn(var5, var0, var1); \
	vxor(var0, var2, var8); \
	vxor(var2, var5, var0); \
	vandn(var5, var7, var3); \
	vxor(var11, var5, var2); \
	vxor(out1, out1, var11); \
	vxor(var5, var14, var13); \
	vor(var11, var0, var5); \
	vxor(var0, var7, var6); \
	vor(var7, var12, var0); \
	vxor(var12, var11, var7); \
	vxor(var11, var2, var5); \
	vand(var2, var7, var11); \
	vxor(var5, var4, var2); \
	vandn(var2, var5, var9); \
	vxor(var4, var6, var2); \
	vor(var2, var4, var3); \
	vxor(var5, var2, var12); \
	vxor(out3, out3, var5); \
	vandn(var2, var4, var1); \
	vor(var1, var8, var0); \
	vxor(var0, var2, var1); \
	vor(var1, var10, var3); \
	vxor(var2, var1, var0); \
	vxor(out4, out4, var2); \
}                      \

#define s3(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var0, var1); \
	vxor(var7, var2, var5); \
	vor(var8, var6, var7); \
	vxor(var6, var3, var5); \
	vandn(var9, var6, var0); \
	vxor(var10, var8, var9); \
	vxor(var11, var1, var7); \
	vandn(var12, var11, var5); \
	vxor(var13, var8, var12); \
	vandn(var8, var10, var13); \
	vand(var12, var5, var10); \
	vor(var14, var3, var12); \
	vand(var12, var0, var14); \
	vxor(var14, var11, var12); \
	vandn(var12, var10, var4); \
	vxor(var15, var12, var14); \
	vxor(out4, out4, var15); \
	vand(var12, var7, var6); \
	vxor(var6, var0, var3); \
	vxor(var7, var13, var6); \
	vor(var13, var2, var7); \
	vandn(var7, var13, var12); \
	vor(var12, var9, var6); \
	vandn(var6, var14, var12); \
	vand(var9, var3, var5); \
	vandn(var3, var9, var1); \
	vxor(var5, var6, var3); \
	vandn(var3, var5, var2); \
	vor(var6, var11, var9); \
	vandn(var9, var6, var3); \
	vxor(var3, var0, var9); \
	vand(var6, var7, var4); \
	vxor(var9, var6, var3); \
	vxor(out2, out2, var9); \
	vor(var3, var1, var2); \
	vandn(var1, var10, var3); \
	vxor(var2, var11, var12); \
	vnot(var6, var2); \
	vxor(var2, var1, var6); \
	vandn(var1, var4, var8); \
	vxor(var8, var1, var2); \
	vxor(out1, out1, var8); \
	vxor(var1, var0, var7); \
	vor(var0, var6, var1); \
	vxor(var1, var10, var0); \
	vxor(var0, var14, var1); \
	vxor(var1, var3, var0); \
	vor(var0, var5, var4); \
	vxor(var2, var0, var1); \
	vxor(out3, out3, var2); \
}

#define s4(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{  \
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor (var6, var0, var2); \
	vxor (var0, var2, var4); \
	vor  (var2, var1, var3); \
	vxor (var7, var4, var2); \
	vandn(var2, var0, var7); \
	vandn(var7, var0, var1); \
	vxor (var8, var3, var7); \
	vor  (var9, var6, var8); \
	vandn(var10, var9, var2); \
	vxor (var9, var1, var10); \
	vand (var11, var8, var9); \
	vandn(var8, var0, var11); \
	vxor (var0, var6, var9); \
	vandn(var6, var0, var8); \
	vxor (var8, var2, var6); \
	vxor (var2, var1, var3); \
	vor  (var1, var4, var7); \
	vxor (var3, var0, var1); \
	vandn(var0, var3, var2); \
	vxor (var1, var10, var0); \
	vandn(var0, var5, var8); \
	vxor (var4, var0, var1); \
	vxor (var4, var4, out1); \
	out1 = var4; \
	vnot (var0, var1); \
	vandn(var1, var8, var5); \
	vxor (var4, var1, var0); \
	vxor (var4, var4, out2); \
	out2 = var4; \
	vxor (var1, var8, var0); \
	vandn(var0, var1, var2); \
	vor  (var1, var11, var0); \
	vxor (var0, var3, var1); \
	vor  (var1, var9, var5); \
	vxor (var2, var1, var0); \
 	vxor (var2, var2, out3); \
	out3 = var2; \
	vand (var1, var5, var9); \
	vxor (var2, var1, var0); \
	vxor (var2, var2, out4); \
	out4 = var2;  \
} \

#define s5(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vor(var6, var0, var2); \
	vandn(var7, var6, var5); \
	vxor(var8, var0, var7); \
	vxor(var9, var2, var8); \
	vor(var10, var3, var9); \
	vandn(var11, var7, var3); \
	vxor(var7, var2, var11); \
	vand(var2, var4, var7); \
	vor(var11, var0, var9); \
	vxor(var9, var2, var11); \
	vxor(var2, var3, var9); \
	vxor(var9, var5, var2); \
	vor(var5, var8, var9); \
	vand(var12, var4, var5); \
	vxor(var13, var8, var12); \
	vand(var14, var3, var11); \
	vxor(var15, var13, var14); \
	vandn(var13, var5, var0); \
	vxor(var5, var7, var13); \
	vxor(var14, var4, var10); \
	vandn(var4, var14, var5); \
	vnot(var5, var4); \
	vandn(var4, var5, var1); \
	vxor(var5, var4, var2); \
	vxor(out3, out3, var5); \
	vandn(var2, var7, var12); \
	vxor(var4, var13, var14); \
	vor(var5, var15, var4); \
	vandn(var4, var5, var2); \
	vandn(var2, var10, var4); \
	vand(var5, var9, var4); \
	vxor(var9, var14, var5); \
	vand(var5, var7, var11); \
	vor(var11, var9, var5); \
	vxor(var5, var12, var11); \
	vand(var11, var5, var1); \
	vxor(var5, var11, var15); \
	vxor(out4, out4, var5); \
	vxor(var5, var0, var6); \
	vxor(var0, var4, var5); \
	vand(var4, var3, var9); \
	vxor(var3, var0, var4); \
	vor(var0, var2, var1); \
	vxor(var2, var0, var3); \
	vxor(out1, out1, var2); \
	vxor(var0, var10, var7); \
	vandn(var2, var0, var3); \
	vxor(var0, var8, var9); \
	vxor(var3, var2, var0); \
	vand(var0, var10, var1); \
	vxor(var1, var0, var3); \
	vxor(out2, out2, var1); \
}

#define s6(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vxor(var6, var1, var4); \
	vor(var7, var1, var5); \
	vand(var8, var0, var7); \
	vxor(var7, var6, var8); \
	vxor(var6, var5, var7); \
	vandn(var9, var4, var6); \
	vand(var10, var0, var6); \
	vxor(var6, var1, var10); \
	vxor(var11, var0, var2); \
	vor(var12, var6, var11); \
	vxor(var13, var7, var12); \
	vand(var14, var2, var13); \
	vandn(var15, var14, var5); \
	vor(var16, var9, var6); \
	vxor(var6, var15, var16); \
	vand(var17, var6, var3); \
	vxor(var18, var17, var13); \
	vxor(out4, out4, var18); \
	vxor(var17, var1, var12); \
	vandn(var12, var5, var17); \
	vxor(var18, var2, var12); \
	vandn(var2, var4, var14); \
	vor(var12, var18, var2); \
	vor(var2, var0, var13); \
	vand(var13, var16, var2); \
	vxor(var2, var18, var13); \
	vandn(var13, var2, var15); \
	vor(var15, var9, var3); \
	vxor(var9, var15, var13); \
	vxor(out3, out3, var9); \
	vor(var9, var1, var11); \
	vxor(var1, var6, var9); \
	vor(var6, var8, var12); \
	vxor(var8, var1, var6); \
	vxor(var1, var7, var2); \
	vandn(var2, var4, var1); \
	vnot(var1, var17); \
	vxor(var4, var9, var1); \
	vxor(var1, var2, var4); \
	vandn(var2, var1, var3); \
	vxor(var1, var2, var8); \
	vxor(out2, out2, var1); \
	vxor(var1, var5, var10); \
	vxor(var2, var0, var18); \
	vand(var0, var1, var2); \
	vxor(var1, var14, var4); \
	vxor(var2, var0, var1); \
	vandn(var0, var12, var3); \
	vxor(var1, var0, var2); \
	vxor(out1, out1, var1); \
}                      \

#define s7(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var3, var4); \
	vxor(var7, var1, var6); \
	vor(var8, var2, var7); \
	vxor(var9, var0, var3); \
	vxor(var10, var4, var9); \
	vxor(var11, var8, var10); \
	vxor(var8, var2, var10); \
	vandn(var12, var0, var8); \
	vxor(var13, var6, var12); \
	vand(var12, var7, var13); \
	vxor(var7, var6, var12); \
	vandn(var6, var5, var7); \
	vxor(var14, var6, var11); \
	vxor(var14, var14, out4); \
	out4 = var14; \
	vor(var6, var1, var3); \
	vand(var3, var2, var6); \
	vor(var2, var0, var3); \
	vandn(var11, var2, var13); \
	vxor(var14, var8, var7); \
	vandn(var7, var13, var14); \
	vandn(var15, var6, var7); \
	vandn(var7, var9, var3); \
	vxor(var3, var15, var7); \
	vand(var9, var10, var2); \
	vxor(var2, var1, var14); \
	vor(var10, var9, var2); \
	vxor(var2, var15, var10); \
	vor(var14, var11, var5); \
	vxor(var15, var14, var2); \
	vxor(var15, var15, out1); \
	out1 = var15; \
	vand(var2, var8, var9); \
	vxor(var9, var1, var2); \
	vandn(var1, var9, var7); \
	vxor(var9, var13, var1); \
	vxor(var1, var10, var9); \
	vor(var10, var12, var2); \
	vandn(var2, var10, var4); \
	vxor(var10, var8, var2); \
	vxor(var2, var6, var10); \
	vand(var6, var1, var5); \
	vxor(var1, var6, var2); \
	vxor(var1, var1, out3); \
	out3 = var1; \
 	vandn(var1, var4, var7); \
	vxor(var2, var11, var1); \
	vor(var0, var0, var2); \
 	vnot(var1, var9); \
	vxor(var2, var0, var1); \
	vand(var0, var3, var5); \
	vxor(var1, var0, var2); \
	vxor(var1, var1, out2); \
	out2 = var1; \
}                     \

#define s8(a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)\
{\
	var0 = (a1); \
	var1 = (a2); \
	var2 = (a3); \
	var3 = (a4); \
	var4 = (a5); \
	var5 = (a6); \
	\
	vandn(var6, var2, var1); \
	vandn(var7, var4, var2); \
	vxor(var8, var3, var7); \
	vand(var7, var0, var8); \
	vandn(var9, var7, var6); \
	vandn(var10, var1, var8); \
	vor(var11, var0, var10); \
	vandn(var12, var1, var2); \
	vxor(var13, var4, var12); \
	vand(var12, var11, var13); \
	vor(var14, var7, var12); \
	vnot(var7, var8); \
	vxor(var8, var12, var7); \
	vandn(var7, var2, var11); \
	vxor(var2, var8, var7); \
	vxor(var7, var6, var2); \
	vor(var6, var9, var5); \
	vxor(var8, var6, var7); \
	vxor(out2, out2, var8); \
	vxor(var6, var0, var7); \
	vand(var7, var4, var6); \
	vxor(var8, var1, var2); \
	vxor(var2, var7, var8); \
	vxor(var7, var10, var2); \
	vxor(var10, var14, var2); \
	vor(var2, var1, var10); \
	vxor(var1, var4, var6); \
	vxor(var4, var2, var1); \
	vand(var1, var14, var5); \
	vxor(var2, var1, var4); \
	vxor(out3, out3, var2); \
	vxor(var1, var13, var7); \
	vor(var2, var3, var8); \
	vxor(var6, var1, var2); \
	vxor(var2, var0, var6); \
	vand(var0, var2, var5); \
	vxor(var2, var0, var7); \
	vxor(out4, out4, var2); \
	vandn(var0, var1, var3); \
	vand(var1, var4, var0); \
	vxor(var0, var9, var6); \
	vxor(var2, var1, var0); \
	vor(var0, var2, var5); \
	vxor(var1, var0, var7); \
	vxor(out1, out1, var1); \
}                      \



#define x(p)    (dataBlocks[expansionFunction[p]] ^ expandedKeySchedule[keyScheduleIndexBase + (p)])
#define y(p, q) (dataBlocks[p]                    ^ expandedKeySchedule[keyScheduleIndexBase + (q)])
#define z(r)    (dataBlocks[r])

static void CPU_DES_SBoxes1(unsigned char *expansionFunction, vtype *expandedKeySchedule, vtype *dataBlocks, int32_t keyScheduleIndexBase)
{
	vtype var0;
	vtype var1;
	vtype var2;
	vtype var3; 
	vtype var4; 
	vtype var5; 
	vtype var6; 
	vtype var7; 
	vtype var8; 
	vtype var9; 
	vtype var10; 
	vtype var11; 
	vtype var12; 
	vtype var13; 
	vtype var14; 
	vtype var15; 
	vtype var16; 
	vtype var17; 
	vtype var18;  

	s1(x( 0),     x( 1),     x( 2),     x( 3),     x( 4),     x( 5),     z(40), z(48), z(54), z(62));
	s2(x( 6),     x( 7),     x( 8),     x( 9),     x(10),     x(11),     z(44), z(59), z(33), z(49));
	s3(y( 7, 12), y( 8, 13), y( 9, 14), y(10, 15), y(11, 16), y(12, 17), z(55), z(47), z(61), z(37));
	s4(y(11, 18), y(12, 19), y(13, 20), y(14, 21), y(15, 22), y(16, 23), z(57), z(51), z(41), z(32));
	s5(x(24),     x(25),     x(26),     x(27),     x(28),     x(29),     z(39), z(45), z(56), z(34));
	s6(x(30),     x(31),     x(32),     x(33),     x(34),     x(35),     z(35), z(60), z(42), z(50));
	s7(y(23, 36), y(24, 37), y(25, 38),	y(26, 39), y(27, 40), y(28, 41), z(63), z(43), z(53), z(38));
	s8(y(27, 42), y(28, 43), y(29, 44), y(30, 45), y(31, 46), y( 0, 47), z(36), z(58), z(46), z(52));
}

static void CPU_DES_SBoxes2(unsigned char *expansionFunction, vtype *expandedKeySchedule, vtype *dataBlocks, int32_t keyScheduleIndexBase)
{
	vtype var0;
	vtype var1;
	vtype var2;
	vtype var3; 
	vtype var4; 
	vtype var5; 
	vtype var6; 
	vtype var7; 
	vtype var8; 
	vtype var9; 
	vtype var10; 
	vtype var11; 
	vtype var12; 
	vtype var13; 
	vtype var14; 
	vtype var15; 
	vtype var16; 
	vtype var17; 
	vtype var18; 

	s1(x(48),     x(49),     x(50),     x(51),     x(52),     x(53),     z( 8), z(16), z(22), z(30));
	s2(x(54),     x(55),     x(56),     x(57),     x(58),     x(59),     z(12), z(27), z( 1), z(17));
	s3(y(39, 60), y(40, 61), y(41, 62), y(42, 63), y(43, 64), y(44, 65), z(23), z(15), z(29), z( 5));
	s4(y(43, 66), y(44, 67), y(45, 68), y(46, 69), y(47, 70), y(48, 71), z(25), z(19), z( 9), z( 0));
	s5(x(72),     x(73),     x(74),     x(75),     x(76),     x(77),     z( 7), z(13), z(24), z( 2));
	s6(x(78),     x(79),     x(80),     x(81),     x(82),     x(83),     z( 3), z(28), z(10), z(18));
	s7(y(55, 84), y(56, 85), y(57, 86), y(58, 87), y(59, 88), y(60, 89), z(31), z(11), z(21), z( 6));
	s8(y(59, 90), y(60, 91), y(61, 92), y(62, 93), y(63, 94), y(32, 95), z( 4), z(26), z(14), z(20));
}

#define GET_TRIPCODE_CHAR_INDEX(r, t, i0, i1, i2, i3, i4, i5, pos)  \
		(  ((( (r)[i0] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (5 + ((pos) * 6)))  \
	 	 | ((( (r)[i1] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (4 + ((pos) * 6)))  \
		 | ((( (r)[i2] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (3 + ((pos) * 6)))  \
		 | ((( (r)[i3] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (2 + ((pos) * 6)))  \
		 | ((( (r)[i4] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (1 + ((pos) * 6)))  \
		 | ((( (r)[i5] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << (0 + ((pos) * 6)))) \

#define GET_TRIPCODE_CHAR_INDEX_LAST(r, t, i0, i1, i2, i3)     \
		(  ((((r)[i0] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 5)  \
	 	 | ((((r)[i1] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 4)  \
		 | ((((r)[i2] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 3)  \
		 | ((((r)[i3] & (0x01 << ((t) & 0x1f))) ? (0x1) : (0x0)) << 2)) \

#define GET_TRIPCODE_CHAR(r, t, i)   DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX((r), (t), (i))]

#define GET_TRIPCODE_CHAR_LAST(r, t) DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX_LAST((r), (t))]


static char DES_indexToCharTable[64] =
//	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
{
	/* 00 */ '.', '/',
	/* 02 */ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
	/* 12 */ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
	/* 28 */ 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	/* 38 */ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	/* 54 */ 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
};

static unsigned char *DES_GetTripcode(DES_Context *context, int32_t tripcodeIndex, unsigned char *tripcode)
{
	// Perform the final permutation as necessary.
  	tripcode[0] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 63, 31, 38,  6, 46, 14, 0)];
  	tripcode[1] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 54, 22, 62, 30, 37,  5, 0)];
  	tripcode[2] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 45, 13, 53, 21, 61, 29, 0)];
  	tripcode[3] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 36,  4, 44, 12, 52, 20, 0)];
  	tripcode[4] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 60, 28, 35,  3, 43, 11, 0)];
  	tripcode[5] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 51, 19, 59, 27, 34,  2, 0)];
  	tripcode[6] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 42, 10, 50, 18, 58, 26, 0)];
  	tripcode[7] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 33,  1, 41,  9, 49, 17, 0)];
  	tripcode[8] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX(context->dataBlocks, tripcodeIndex, 57, 25, 32,  0, 40,  8, 0)];
	tripcode[9] = DES_indexToCharTable[GET_TRIPCODE_CHAR_INDEX_LAST(context->dataBlocks, tripcodeIndex, 48, 16, 56, 24)];
 	tripcode[10] = '\0';

	return tripcode;
}

#define CLEAR_KEYS(charIndex)                       \
	for (int32_t i = 0; i < 7; ++i) {                   \
		context.keys[(charIndex) * 7 + i] = 0;     \
	}                                               \

#define SET_BIT_FOR_KEY(i, j, k)      \
	if (p[tripcodeIndex].key.c[j] & (0x1 << (k))) {           \
			context.keys[i] |= 1 << tripcodeIndex; \
	}                                      \

static void DES_SetSalt(DES_Context *context, int32_t salt)
{
	int32_t mask;
	int32_t src, dst;

	mask = 1;
	for (dst = 0; dst < 48; dst++) {
		if (dst == 24) mask = 1;

		if (salt & mask) {
			if (dst < 24) src = dst + 24; else src = dst - 24;
		} else src = dst;

		context->expansionFunction[dst     ] = expansionTable[src];
		context->expansionFunction[dst + 48] = expansionTable[src] + 32;

		mask <<= 1;
	}
}

static char DES_charToIndexTable[0x100] = {
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
	0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
	0x23, 0x24, 0x25, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
	0x3d, 0x3e, 0x3f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
};

#define CONVERT_CHAR_FOR_SALT(ch) (charTableForSeed[(unsigned char)(ch)])



static void DES_Crypt25(DES_Context *context)
{
	int32_t iterations, roundsAndSwapped; 
	int32_t keyScheduleIndexBase = 0;

	roundsAndSwapped = 8;
	iterations = 25;

start:
	CPU_DES_SBoxes1(context->expansionFunction, context->expandedKeySchedule, context->dataBlocks, keyScheduleIndexBase);

	if (roundsAndSwapped == 0x100)
		goto next;

swap:
	CPU_DES_SBoxes2(context->expansionFunction, context->expandedKeySchedule, context->dataBlocks, keyScheduleIndexBase);

	keyScheduleIndexBase += 96;

	if (--roundsAndSwapped)
		goto start;
	keyScheduleIndexBase -= (0x300 + 48);
	roundsAndSwapped = 0x108;
	if (--iterations)
		goto swap;
	return;

next:
	keyScheduleIndexBase -= (0x300 - 48);
	roundsAndSwapped = 8;
	iterations--;
	goto start;
}


static unsigned char keySchedule[0x300] = {
	12, 46, 33, 52, 48, 20, 34, 55,  5, 13, 18, 40,  4, 32, 26, 27,
	38, 54, 53,  6, 31, 25, 19, 41, 15, 24, 28, 43, 30,  3, 35, 22,
	 2, 44, 14, 23, 51, 16, 29, 49,  7, 17, 37,  8,  9, 50, 42, 21,
	 5, 39, 26, 45, 41, 13, 27, 48, 53,  6, 11, 33, 52, 25, 19, 20,
	31, 47, 46, 54, 55, 18, 12, 34,  8, 17, 21, 36, 23, 49, 28, 15,
	24, 37,  7, 16, 44,  9, 22, 42,  0, 10, 30,  1,  2, 43, 35, 14,
	46, 25, 12, 31, 27, 54, 13, 34, 39, 47, 52, 19, 38, 11,  5,  6,
	48, 33, 32, 40, 41,  4, 53, 20, 51,  3,  7, 22,  9, 35, 14,  1,
	10, 23, 50,  2, 30, 24,  8, 28, 43, 49, 16, 44, 17, 29, 21,  0,
	32, 11, 53, 48, 13, 40, 54, 20, 25, 33, 38,  5, 55, 52, 46, 47,
	34, 19, 18, 26, 27, 45, 39,  6, 37, 42, 50,  8, 24, 21,  0, 44,
	49,  9, 36, 17, 16, 10, 51, 14, 29, 35,  2, 30,  3, 15,  7, 43,
	18, 52, 39, 34, 54, 26, 40,  6, 11, 19, 55, 46, 41, 38, 32, 33,
	20,  5,  4, 12, 13, 31, 25, 47, 23, 28, 36, 51, 10,  7, 43, 30,
	35, 24, 22,  3,  2, 49, 37,  0, 15, 21, 17, 16, 42,  1, 50, 29,
	 4, 38, 25, 20, 40, 12, 26, 47, 52,  5, 41, 32, 27, 55, 18, 19,
	 6, 46, 45, 53, 54, 48, 11, 33,  9, 14, 22, 37, 49, 50, 29, 16,
	21, 10,  8, 42, 17, 35, 23, 43,  1,  7,  3,  2, 28, 44, 36, 15,
	45, 55, 11,  6, 26, 53, 12, 33, 38, 46, 27, 18, 13, 41,  4,  5,
	47, 32, 31, 39, 40, 34, 52, 19, 24,  0,  8, 23, 35, 36, 15,  2,
	 7, 49, 51, 28,  3, 21,  9, 29, 44, 50, 42, 17, 14, 30, 22,  1,
	31, 41, 52, 47, 12, 39, 53, 19, 55, 32, 13,  4, 54, 27, 45, 46,
	33, 18, 48, 25, 26, 20, 38,  5, 10, 43, 51,  9, 21, 22,  1, 17,
	50, 35, 37, 14, 42,  7, 24, 15, 30, 36, 28,  3,  0, 16,  8, 44,
	55, 34, 45, 40,  5, 32, 46, 12, 48, 25,  6, 52, 47, 20, 38, 39,
	26, 11, 41, 18, 19, 13, 31, 53,  3, 36, 44,  2, 14, 15, 51, 10,
	43, 28, 30,  7, 35,  0, 17,  8, 23, 29, 21, 49, 50,  9,  1, 37,
	41, 20, 31, 26, 46, 18, 32, 53, 34, 11, 47, 38, 33,  6, 55, 25,
	12, 52, 27,  4,  5, 54, 48, 39, 42, 22, 30, 17,  0,  1, 37, 49,
	29, 14, 16, 50, 21, 43,  3, 51,  9, 15,  7, 35, 36, 24, 44, 23,
	27,  6, 48, 12, 32,  4, 18, 39, 20, 52, 33, 55, 19, 47, 41, 11,
	53, 38, 13, 45, 46, 40, 34, 25, 28,  8, 16,  3, 43, 44, 23, 35,
	15,  0,  2, 36,  7, 29, 42, 37, 24,  1, 50, 21, 22, 10, 30,  9,
	13, 47, 34, 53, 18, 45,  4, 25,  6, 38, 19, 41,  5, 33, 27, 52,
	39, 55, 54, 31, 32, 26, 20, 11, 14, 51,  2, 42, 29, 30,  9, 21,
	 1, 43, 17, 22, 50, 15, 28, 23, 10, 44, 36,  7,  8, 49, 16, 24,
	54, 33, 20, 39,  4, 31, 45, 11, 47, 55,  5, 27, 46, 19, 13, 38,
	25, 41, 40, 48, 18, 12,  6, 52,  0, 37, 17, 28, 15, 16, 24,  7,
	44, 29,  3,  8, 36,  1, 14,  9, 49, 30, 22, 50, 51, 35,  2, 10,
	40, 19,  6, 25, 45, 48, 31, 52, 33, 41, 46, 13, 32,  5, 54, 55,
	11, 27, 26, 34,  4, 53, 47, 38, 43, 23,  3, 14,  1,  2, 10, 50,
	30, 15, 42, 51, 22, 44,  0, 24, 35, 16,  8, 36, 37, 21, 17, 49,
	26,  5, 47, 11, 31, 34, 48, 38, 19, 27, 32, 54, 18, 46, 40, 41,
	52, 13, 12, 20, 45, 39, 33, 55, 29,  9, 42,  0, 44, 17, 49, 36,
	16,  1, 28, 37,  8, 30, 43, 10, 21,  2, 51, 22, 23,  7,  3, 35,
	19, 53, 40,  4, 55, 27, 41, 31, 12, 20, 25, 47, 11, 39, 33, 34,
	45,  6,  5, 13, 38, 32, 26, 48, 22,  2, 35, 50, 37, 10, 42, 29,
	 9, 51, 21, 30,  1, 23, 36,  3, 14, 24, 44, 15, 16,  0, 49, 28,
};

void Generate10CharTripcodes(TripcodeKeyPair *p, int32_t numTripcodes)
{
	DES_Context context;

	CLEAR_KEYS(0);
	CLEAR_KEYS(1);
	CLEAR_KEYS(2);
	CLEAR_KEYS(3);
	CLEAR_KEYS(4);
	CLEAR_KEYS(5);
	CLEAR_KEYS(6);
	CLEAR_KEYS(7);

	for (int32_t tripcodeIndex = 0; tripcodeIndex < numTripcodes; ++tripcodeIndex) {
		SET_BIT_FOR_KEY( 0, 0, 0);
		SET_BIT_FOR_KEY( 1, 0, 1);
		SET_BIT_FOR_KEY( 2, 0, 2);
		SET_BIT_FOR_KEY( 3, 0, 3);
		SET_BIT_FOR_KEY( 4, 0, 4);
		SET_BIT_FOR_KEY( 5, 0, 5);
		SET_BIT_FOR_KEY( 6, 0, 6);

		SET_BIT_FOR_KEY( 7, 1, 0);
		SET_BIT_FOR_KEY( 8, 1, 1);
		SET_BIT_FOR_KEY( 9, 1, 2);
		SET_BIT_FOR_KEY(10, 1, 3);
		SET_BIT_FOR_KEY(11, 1, 4);
		SET_BIT_FOR_KEY(12, 1, 5);
		SET_BIT_FOR_KEY(13, 1, 6);
	
		SET_BIT_FOR_KEY(14, 2, 0);
		SET_BIT_FOR_KEY(15, 2, 1);
		SET_BIT_FOR_KEY(16, 2, 2);
		SET_BIT_FOR_KEY(17, 2, 3);
		SET_BIT_FOR_KEY(18, 2, 4);
		SET_BIT_FOR_KEY(19, 2, 5);
		SET_BIT_FOR_KEY(20, 2, 6);

		SET_BIT_FOR_KEY(21, 3, 0);
		SET_BIT_FOR_KEY(22, 3, 1);
		SET_BIT_FOR_KEY(23, 3, 2);
		SET_BIT_FOR_KEY(24, 3, 3);
		SET_BIT_FOR_KEY(25, 3, 4);
		SET_BIT_FOR_KEY(26, 3, 5);
		SET_BIT_FOR_KEY(27, 3, 6);

		SET_BIT_FOR_KEY(28, 4, 0);
		SET_BIT_FOR_KEY(29, 4, 1);
		SET_BIT_FOR_KEY(30, 4, 2);
		SET_BIT_FOR_KEY(31, 4, 3);
		SET_BIT_FOR_KEY(32, 4, 4);
		SET_BIT_FOR_KEY(33, 4, 5);
		SET_BIT_FOR_KEY(34, 4, 6);

		SET_BIT_FOR_KEY(35, 5, 0);
		SET_BIT_FOR_KEY(36, 5, 1);
		SET_BIT_FOR_KEY(37, 5, 2);
		SET_BIT_FOR_KEY(38, 5, 3);
		SET_BIT_FOR_KEY(39, 5, 4);
		SET_BIT_FOR_KEY(40, 5, 5);
		SET_BIT_FOR_KEY(41, 5, 6);

		SET_BIT_FOR_KEY(42, 6, 0);
		SET_BIT_FOR_KEY(43, 6, 1);
		SET_BIT_FOR_KEY(44, 6, 2);
		SET_BIT_FOR_KEY(45, 6, 3);
		SET_BIT_FOR_KEY(46, 6, 4);
		SET_BIT_FOR_KEY(47, 6, 5);
		SET_BIT_FOR_KEY(48, 6, 6);

		SET_BIT_FOR_KEY(49, 7, 0);
		SET_BIT_FOR_KEY(50, 7, 1);
		SET_BIT_FOR_KEY(51, 7, 2);
		SET_BIT_FOR_KEY(52, 7, 3);
		SET_BIT_FOR_KEY(53, 7, 4);
		SET_BIT_FOR_KEY(54, 7, 5);
		SET_BIT_FOR_KEY(55, 7, 6);
	}

	for (int32_t i = 0; i < 0x300; ++i)
		context.expandedKeySchedule[i] = context.keys[keySchedule[i]];

	for (int32_t i = 0; i < NUM_DATA_BLOCKS; ++i) {
		context.dataBlocks[i] = 0;
	}

	DES_SetSalt(&context,
				DES_charToIndexTable[CONVERT_CHAR_FOR_SALT(p[0].key.c[1])]
			| (DES_charToIndexTable[CONVERT_CHAR_FOR_SALT(p[0].key.c[2])] << 6));	

	DES_Crypt25(&context);
	
	for (int32_t tripcodeIndex = 0; tripcodeIndex < numTripcodes; ++tripcodeIndex) {
		DES_GetTripcode(&context, tripcodeIndex, p[tripcodeIndex].tripcode.c);
		p[tripcodeIndex].tripcode.c[10] = '\0';
	}
}
