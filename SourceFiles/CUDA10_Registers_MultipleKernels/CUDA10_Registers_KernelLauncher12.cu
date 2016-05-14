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



#include "../MerikensTripcodeEngine.h"

#ifdef CUDA_DES_ENABLE_MULTIPLE_KERNELS_MODE

#include "../CUDA10_Registers_Kernel_Common.h"

#define SALT 3072
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3073
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3074
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3075
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3076
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3077
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3078
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3079
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3080
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3081
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3082
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3083
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3084
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3085
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3086
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3087
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3088
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3089
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3090
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3091
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3092
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3093
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3094
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3095
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3096
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3097
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3098
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3099
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3100
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3101
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3102
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3103
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3104
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3105
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3106
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3107
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3108
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3109
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3110
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3111
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3112
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3113
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3114
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3115
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3116
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3117
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3118
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3119
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3120
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3121
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3122
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3123
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3124
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3125
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3126
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3127
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3128
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3129
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3130
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3131
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3132
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3133
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3134
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3135
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3136
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3137
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3138
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3139
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3140
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3141
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3142
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3143
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3144
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3145
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3146
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3147
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3148
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3149
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3150
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3151
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3152
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3153
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3154
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3155
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3156
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3157
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3158
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3159
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3160
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3161
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3162
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3163
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3164
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3165
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3166
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3167
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3168
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3169
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3170
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3171
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3172
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3173
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3174
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3175
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3176
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3177
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3178
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3179
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3180
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3181
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3182
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3183
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3184
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3185
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3186
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3187
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3188
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3189
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3190
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3191
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3192
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3193
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3194
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3195
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3196
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3197
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3198
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3199
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3200
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3201
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3202
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3203
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3204
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3205
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3206
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3207
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3208
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3209
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3210
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3211
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3212
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3213
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3214
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3215
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3216
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3217
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3218
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3219
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3220
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3221
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3222
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3223
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3224
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3225
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3226
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3227
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3228
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3229
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3230
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3231
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3232
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3233
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3234
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3235
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3236
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3237
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3238
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3239
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3240
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3241
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3242
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3243
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3244
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3245
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3246
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3247
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3248
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3249
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3250
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3251
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3252
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3253
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3254
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3255
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3256
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3257
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3258
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3259
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3260
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3261
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3262
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3263
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3264
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3265
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3266
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3267
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3268
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3269
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3270
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3271
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3272
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3273
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3274
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3275
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3276
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3277
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3278
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3279
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3280
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3281
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3282
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3283
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3284
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3285
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3286
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3287
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3288
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3289
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3290
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3291
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3292
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3293
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3294
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3295
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3296
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3297
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3298
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3299
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3300
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3301
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3302
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3303
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3304
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3305
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3306
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3307
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3308
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3309
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3310
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3311
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3312
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3313
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3314
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3315
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3316
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3317
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3318
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3319
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3320
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3321
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3322
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3323
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3324
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3325
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3326
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3327
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher12()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel12(
	uint32_t numBlocksPerGrid,
	cudaDeviceProp CUDADeviceProperties,
	cudaStream_t currentStream,
	unsigned char *cudaPassCountArray,
	unsigned char *cudaTripcodeIndexArray,
	uint32_t *cudaTripcodeChunkArray,
	uint32_t numTripcodeChunk,
	int32_t intSalt,
	unsigned char *cudaKey0Array,
	unsigned char *cudaKey7Array,
	DES_Vector *cudaKeyVectorsFrom49To55,
	unsigned char *cudaKeyAndRandomBytes,
	int32_t searchMode)
{
	dim3 dimGrid(numBlocksPerGrid);
	dim3 dimBlock(CUDA_DES_NUM_THREADS_PER_BLOCK);
	switch (intSalt) {
	case 3072: LAUNCH_KERNEL(3072); break;
	case 3073: LAUNCH_KERNEL(3073); break;
	case 3074: LAUNCH_KERNEL(3074); break;
	case 3075: LAUNCH_KERNEL(3075); break;
	case 3076: LAUNCH_KERNEL(3076); break;
	case 3077: LAUNCH_KERNEL(3077); break;
	case 3078: LAUNCH_KERNEL(3078); break;
	case 3079: LAUNCH_KERNEL(3079); break;
	case 3080: LAUNCH_KERNEL(3080); break;
	case 3081: LAUNCH_KERNEL(3081); break;
	case 3082: LAUNCH_KERNEL(3082); break;
	case 3083: LAUNCH_KERNEL(3083); break;
	case 3084: LAUNCH_KERNEL(3084); break;
	case 3085: LAUNCH_KERNEL(3085); break;
	case 3086: LAUNCH_KERNEL(3086); break;
	case 3087: LAUNCH_KERNEL(3087); break;
	case 3088: LAUNCH_KERNEL(3088); break;
	case 3089: LAUNCH_KERNEL(3089); break;
	case 3090: LAUNCH_KERNEL(3090); break;
	case 3091: LAUNCH_KERNEL(3091); break;
	case 3092: LAUNCH_KERNEL(3092); break;
	case 3093: LAUNCH_KERNEL(3093); break;
	case 3094: LAUNCH_KERNEL(3094); break;
	case 3095: LAUNCH_KERNEL(3095); break;
	case 3096: LAUNCH_KERNEL(3096); break;
	case 3097: LAUNCH_KERNEL(3097); break;
	case 3098: LAUNCH_KERNEL(3098); break;
	case 3099: LAUNCH_KERNEL(3099); break;
	case 3100: LAUNCH_KERNEL(3100); break;
	case 3101: LAUNCH_KERNEL(3101); break;
	case 3102: LAUNCH_KERNEL(3102); break;
	case 3103: LAUNCH_KERNEL(3103); break;
	case 3104: LAUNCH_KERNEL(3104); break;
	case 3105: LAUNCH_KERNEL(3105); break;
	case 3106: LAUNCH_KERNEL(3106); break;
	case 3107: LAUNCH_KERNEL(3107); break;
	case 3108: LAUNCH_KERNEL(3108); break;
	case 3109: LAUNCH_KERNEL(3109); break;
	case 3110: LAUNCH_KERNEL(3110); break;
	case 3111: LAUNCH_KERNEL(3111); break;
	case 3112: LAUNCH_KERNEL(3112); break;
	case 3113: LAUNCH_KERNEL(3113); break;
	case 3114: LAUNCH_KERNEL(3114); break;
	case 3115: LAUNCH_KERNEL(3115); break;
	case 3116: LAUNCH_KERNEL(3116); break;
	case 3117: LAUNCH_KERNEL(3117); break;
	case 3118: LAUNCH_KERNEL(3118); break;
	case 3119: LAUNCH_KERNEL(3119); break;
	case 3120: LAUNCH_KERNEL(3120); break;
	case 3121: LAUNCH_KERNEL(3121); break;
	case 3122: LAUNCH_KERNEL(3122); break;
	case 3123: LAUNCH_KERNEL(3123); break;
	case 3124: LAUNCH_KERNEL(3124); break;
	case 3125: LAUNCH_KERNEL(3125); break;
	case 3126: LAUNCH_KERNEL(3126); break;
	case 3127: LAUNCH_KERNEL(3127); break;
	case 3128: LAUNCH_KERNEL(3128); break;
	case 3129: LAUNCH_KERNEL(3129); break;
	case 3130: LAUNCH_KERNEL(3130); break;
	case 3131: LAUNCH_KERNEL(3131); break;
	case 3132: LAUNCH_KERNEL(3132); break;
	case 3133: LAUNCH_KERNEL(3133); break;
	case 3134: LAUNCH_KERNEL(3134); break;
	case 3135: LAUNCH_KERNEL(3135); break;
	case 3136: LAUNCH_KERNEL(3136); break;
	case 3137: LAUNCH_KERNEL(3137); break;
	case 3138: LAUNCH_KERNEL(3138); break;
	case 3139: LAUNCH_KERNEL(3139); break;
	case 3140: LAUNCH_KERNEL(3140); break;
	case 3141: LAUNCH_KERNEL(3141); break;
	case 3142: LAUNCH_KERNEL(3142); break;
	case 3143: LAUNCH_KERNEL(3143); break;
	case 3144: LAUNCH_KERNEL(3144); break;
	case 3145: LAUNCH_KERNEL(3145); break;
	case 3146: LAUNCH_KERNEL(3146); break;
	case 3147: LAUNCH_KERNEL(3147); break;
	case 3148: LAUNCH_KERNEL(3148); break;
	case 3149: LAUNCH_KERNEL(3149); break;
	case 3150: LAUNCH_KERNEL(3150); break;
	case 3151: LAUNCH_KERNEL(3151); break;
	case 3152: LAUNCH_KERNEL(3152); break;
	case 3153: LAUNCH_KERNEL(3153); break;
	case 3154: LAUNCH_KERNEL(3154); break;
	case 3155: LAUNCH_KERNEL(3155); break;
	case 3156: LAUNCH_KERNEL(3156); break;
	case 3157: LAUNCH_KERNEL(3157); break;
	case 3158: LAUNCH_KERNEL(3158); break;
	case 3159: LAUNCH_KERNEL(3159); break;
	case 3160: LAUNCH_KERNEL(3160); break;
	case 3161: LAUNCH_KERNEL(3161); break;
	case 3162: LAUNCH_KERNEL(3162); break;
	case 3163: LAUNCH_KERNEL(3163); break;
	case 3164: LAUNCH_KERNEL(3164); break;
	case 3165: LAUNCH_KERNEL(3165); break;
	case 3166: LAUNCH_KERNEL(3166); break;
	case 3167: LAUNCH_KERNEL(3167); break;
	case 3168: LAUNCH_KERNEL(3168); break;
	case 3169: LAUNCH_KERNEL(3169); break;
	case 3170: LAUNCH_KERNEL(3170); break;
	case 3171: LAUNCH_KERNEL(3171); break;
	case 3172: LAUNCH_KERNEL(3172); break;
	case 3173: LAUNCH_KERNEL(3173); break;
	case 3174: LAUNCH_KERNEL(3174); break;
	case 3175: LAUNCH_KERNEL(3175); break;
	case 3176: LAUNCH_KERNEL(3176); break;
	case 3177: LAUNCH_KERNEL(3177); break;
	case 3178: LAUNCH_KERNEL(3178); break;
	case 3179: LAUNCH_KERNEL(3179); break;
	case 3180: LAUNCH_KERNEL(3180); break;
	case 3181: LAUNCH_KERNEL(3181); break;
	case 3182: LAUNCH_KERNEL(3182); break;
	case 3183: LAUNCH_KERNEL(3183); break;
	case 3184: LAUNCH_KERNEL(3184); break;
	case 3185: LAUNCH_KERNEL(3185); break;
	case 3186: LAUNCH_KERNEL(3186); break;
	case 3187: LAUNCH_KERNEL(3187); break;
	case 3188: LAUNCH_KERNEL(3188); break;
	case 3189: LAUNCH_KERNEL(3189); break;
	case 3190: LAUNCH_KERNEL(3190); break;
	case 3191: LAUNCH_KERNEL(3191); break;
	case 3192: LAUNCH_KERNEL(3192); break;
	case 3193: LAUNCH_KERNEL(3193); break;
	case 3194: LAUNCH_KERNEL(3194); break;
	case 3195: LAUNCH_KERNEL(3195); break;
	case 3196: LAUNCH_KERNEL(3196); break;
	case 3197: LAUNCH_KERNEL(3197); break;
	case 3198: LAUNCH_KERNEL(3198); break;
	case 3199: LAUNCH_KERNEL(3199); break;
	case 3200: LAUNCH_KERNEL(3200); break;
	case 3201: LAUNCH_KERNEL(3201); break;
	case 3202: LAUNCH_KERNEL(3202); break;
	case 3203: LAUNCH_KERNEL(3203); break;
	case 3204: LAUNCH_KERNEL(3204); break;
	case 3205: LAUNCH_KERNEL(3205); break;
	case 3206: LAUNCH_KERNEL(3206); break;
	case 3207: LAUNCH_KERNEL(3207); break;
	case 3208: LAUNCH_KERNEL(3208); break;
	case 3209: LAUNCH_KERNEL(3209); break;
	case 3210: LAUNCH_KERNEL(3210); break;
	case 3211: LAUNCH_KERNEL(3211); break;
	case 3212: LAUNCH_KERNEL(3212); break;
	case 3213: LAUNCH_KERNEL(3213); break;
	case 3214: LAUNCH_KERNEL(3214); break;
	case 3215: LAUNCH_KERNEL(3215); break;
	case 3216: LAUNCH_KERNEL(3216); break;
	case 3217: LAUNCH_KERNEL(3217); break;
	case 3218: LAUNCH_KERNEL(3218); break;
	case 3219: LAUNCH_KERNEL(3219); break;
	case 3220: LAUNCH_KERNEL(3220); break;
	case 3221: LAUNCH_KERNEL(3221); break;
	case 3222: LAUNCH_KERNEL(3222); break;
	case 3223: LAUNCH_KERNEL(3223); break;
	case 3224: LAUNCH_KERNEL(3224); break;
	case 3225: LAUNCH_KERNEL(3225); break;
	case 3226: LAUNCH_KERNEL(3226); break;
	case 3227: LAUNCH_KERNEL(3227); break;
	case 3228: LAUNCH_KERNEL(3228); break;
	case 3229: LAUNCH_KERNEL(3229); break;
	case 3230: LAUNCH_KERNEL(3230); break;
	case 3231: LAUNCH_KERNEL(3231); break;
	case 3232: LAUNCH_KERNEL(3232); break;
	case 3233: LAUNCH_KERNEL(3233); break;
	case 3234: LAUNCH_KERNEL(3234); break;
	case 3235: LAUNCH_KERNEL(3235); break;
	case 3236: LAUNCH_KERNEL(3236); break;
	case 3237: LAUNCH_KERNEL(3237); break;
	case 3238: LAUNCH_KERNEL(3238); break;
	case 3239: LAUNCH_KERNEL(3239); break;
	case 3240: LAUNCH_KERNEL(3240); break;
	case 3241: LAUNCH_KERNEL(3241); break;
	case 3242: LAUNCH_KERNEL(3242); break;
	case 3243: LAUNCH_KERNEL(3243); break;
	case 3244: LAUNCH_KERNEL(3244); break;
	case 3245: LAUNCH_KERNEL(3245); break;
	case 3246: LAUNCH_KERNEL(3246); break;
	case 3247: LAUNCH_KERNEL(3247); break;
	case 3248: LAUNCH_KERNEL(3248); break;
	case 3249: LAUNCH_KERNEL(3249); break;
	case 3250: LAUNCH_KERNEL(3250); break;
	case 3251: LAUNCH_KERNEL(3251); break;
	case 3252: LAUNCH_KERNEL(3252); break;
	case 3253: LAUNCH_KERNEL(3253); break;
	case 3254: LAUNCH_KERNEL(3254); break;
	case 3255: LAUNCH_KERNEL(3255); break;
	case 3256: LAUNCH_KERNEL(3256); break;
	case 3257: LAUNCH_KERNEL(3257); break;
	case 3258: LAUNCH_KERNEL(3258); break;
	case 3259: LAUNCH_KERNEL(3259); break;
	case 3260: LAUNCH_KERNEL(3260); break;
	case 3261: LAUNCH_KERNEL(3261); break;
	case 3262: LAUNCH_KERNEL(3262); break;
	case 3263: LAUNCH_KERNEL(3263); break;
	case 3264: LAUNCH_KERNEL(3264); break;
	case 3265: LAUNCH_KERNEL(3265); break;
	case 3266: LAUNCH_KERNEL(3266); break;
	case 3267: LAUNCH_KERNEL(3267); break;
	case 3268: LAUNCH_KERNEL(3268); break;
	case 3269: LAUNCH_KERNEL(3269); break;
	case 3270: LAUNCH_KERNEL(3270); break;
	case 3271: LAUNCH_KERNEL(3271); break;
	case 3272: LAUNCH_KERNEL(3272); break;
	case 3273: LAUNCH_KERNEL(3273); break;
	case 3274: LAUNCH_KERNEL(3274); break;
	case 3275: LAUNCH_KERNEL(3275); break;
	case 3276: LAUNCH_KERNEL(3276); break;
	case 3277: LAUNCH_KERNEL(3277); break;
	case 3278: LAUNCH_KERNEL(3278); break;
	case 3279: LAUNCH_KERNEL(3279); break;
	case 3280: LAUNCH_KERNEL(3280); break;
	case 3281: LAUNCH_KERNEL(3281); break;
	case 3282: LAUNCH_KERNEL(3282); break;
	case 3283: LAUNCH_KERNEL(3283); break;
	case 3284: LAUNCH_KERNEL(3284); break;
	case 3285: LAUNCH_KERNEL(3285); break;
	case 3286: LAUNCH_KERNEL(3286); break;
	case 3287: LAUNCH_KERNEL(3287); break;
	case 3288: LAUNCH_KERNEL(3288); break;
	case 3289: LAUNCH_KERNEL(3289); break;
	case 3290: LAUNCH_KERNEL(3290); break;
	case 3291: LAUNCH_KERNEL(3291); break;
	case 3292: LAUNCH_KERNEL(3292); break;
	case 3293: LAUNCH_KERNEL(3293); break;
	case 3294: LAUNCH_KERNEL(3294); break;
	case 3295: LAUNCH_KERNEL(3295); break;
	case 3296: LAUNCH_KERNEL(3296); break;
	case 3297: LAUNCH_KERNEL(3297); break;
	case 3298: LAUNCH_KERNEL(3298); break;
	case 3299: LAUNCH_KERNEL(3299); break;
	case 3300: LAUNCH_KERNEL(3300); break;
	case 3301: LAUNCH_KERNEL(3301); break;
	case 3302: LAUNCH_KERNEL(3302); break;
	case 3303: LAUNCH_KERNEL(3303); break;
	case 3304: LAUNCH_KERNEL(3304); break;
	case 3305: LAUNCH_KERNEL(3305); break;
	case 3306: LAUNCH_KERNEL(3306); break;
	case 3307: LAUNCH_KERNEL(3307); break;
	case 3308: LAUNCH_KERNEL(3308); break;
	case 3309: LAUNCH_KERNEL(3309); break;
	case 3310: LAUNCH_KERNEL(3310); break;
	case 3311: LAUNCH_KERNEL(3311); break;
	case 3312: LAUNCH_KERNEL(3312); break;
	case 3313: LAUNCH_KERNEL(3313); break;
	case 3314: LAUNCH_KERNEL(3314); break;
	case 3315: LAUNCH_KERNEL(3315); break;
	case 3316: LAUNCH_KERNEL(3316); break;
	case 3317: LAUNCH_KERNEL(3317); break;
	case 3318: LAUNCH_KERNEL(3318); break;
	case 3319: LAUNCH_KERNEL(3319); break;
	case 3320: LAUNCH_KERNEL(3320); break;
	case 3321: LAUNCH_KERNEL(3321); break;
	case 3322: LAUNCH_KERNEL(3322); break;
	case 3323: LAUNCH_KERNEL(3323); break;
	case 3324: LAUNCH_KERNEL(3324); break;
	case 3325: LAUNCH_KERNEL(3325); break;
	case 3326: LAUNCH_KERNEL(3326); break;
	case 3327: LAUNCH_KERNEL(3327); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
