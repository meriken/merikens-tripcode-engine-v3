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

#define SALT 3328
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3329
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3330
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3331
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3332
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3333
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3334
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3335
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3336
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3337
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3338
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3339
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3340
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3341
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3342
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3343
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3344
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3345
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3346
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3347
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3348
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3349
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3350
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3351
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3352
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3353
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3354
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3355
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3356
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3357
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3358
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3359
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3360
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3361
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3362
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3363
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3364
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3365
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3366
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3367
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3368
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3369
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3370
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3371
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3372
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3373
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3374
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3375
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3376
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3377
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3378
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3379
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3380
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3381
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3382
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3383
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3384
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3385
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3386
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3387
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3388
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3389
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3390
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3391
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3392
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3393
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3394
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3395
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3396
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3397
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3398
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3399
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3400
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3401
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3402
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3403
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3404
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3405
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3406
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3407
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3408
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3409
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3410
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3411
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3412
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3413
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3414
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3415
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3416
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3417
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3418
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3419
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3420
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3421
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3422
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3423
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3424
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3425
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3426
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3427
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3428
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3429
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3430
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3431
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3432
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3433
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3434
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3435
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3436
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3437
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3438
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3439
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3440
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3441
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3442
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3443
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3444
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3445
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3446
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3447
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3448
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3449
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3450
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3451
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3452
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3453
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3454
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3455
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3456
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3457
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3458
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3459
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3460
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3461
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3462
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3463
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3464
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3465
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3466
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3467
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3468
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3469
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3470
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3471
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3472
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3473
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3474
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3475
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3476
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3477
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3478
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3479
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3480
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3481
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3482
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3483
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3484
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3485
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3486
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3487
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3488
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3489
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3490
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3491
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3492
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3493
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3494
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3495
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3496
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3497
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3498
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3499
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3500
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3501
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3502
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3503
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3504
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3505
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3506
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3507
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3508
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3509
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3510
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3511
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3512
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3513
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3514
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3515
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3516
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3517
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3518
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3519
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3520
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3521
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3522
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3523
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3524
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3525
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3526
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3527
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3528
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3529
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3530
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3531
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3532
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3533
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3534
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3535
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3536
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3537
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3538
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3539
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3540
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3541
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3542
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3543
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3544
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3545
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3546
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3547
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3548
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3549
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3550
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3551
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3552
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3553
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3554
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3555
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3556
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3557
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3558
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3559
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3560
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3561
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3562
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3563
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3564
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3565
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3566
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3567
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3568
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3569
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3570
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3571
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3572
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3573
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3574
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3575
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3576
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3577
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3578
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3579
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3580
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3581
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3582
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3583
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher13()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel13(
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
	case 3328: LAUNCH_KERNEL(3328); break;
	case 3329: LAUNCH_KERNEL(3329); break;
	case 3330: LAUNCH_KERNEL(3330); break;
	case 3331: LAUNCH_KERNEL(3331); break;
	case 3332: LAUNCH_KERNEL(3332); break;
	case 3333: LAUNCH_KERNEL(3333); break;
	case 3334: LAUNCH_KERNEL(3334); break;
	case 3335: LAUNCH_KERNEL(3335); break;
	case 3336: LAUNCH_KERNEL(3336); break;
	case 3337: LAUNCH_KERNEL(3337); break;
	case 3338: LAUNCH_KERNEL(3338); break;
	case 3339: LAUNCH_KERNEL(3339); break;
	case 3340: LAUNCH_KERNEL(3340); break;
	case 3341: LAUNCH_KERNEL(3341); break;
	case 3342: LAUNCH_KERNEL(3342); break;
	case 3343: LAUNCH_KERNEL(3343); break;
	case 3344: LAUNCH_KERNEL(3344); break;
	case 3345: LAUNCH_KERNEL(3345); break;
	case 3346: LAUNCH_KERNEL(3346); break;
	case 3347: LAUNCH_KERNEL(3347); break;
	case 3348: LAUNCH_KERNEL(3348); break;
	case 3349: LAUNCH_KERNEL(3349); break;
	case 3350: LAUNCH_KERNEL(3350); break;
	case 3351: LAUNCH_KERNEL(3351); break;
	case 3352: LAUNCH_KERNEL(3352); break;
	case 3353: LAUNCH_KERNEL(3353); break;
	case 3354: LAUNCH_KERNEL(3354); break;
	case 3355: LAUNCH_KERNEL(3355); break;
	case 3356: LAUNCH_KERNEL(3356); break;
	case 3357: LAUNCH_KERNEL(3357); break;
	case 3358: LAUNCH_KERNEL(3358); break;
	case 3359: LAUNCH_KERNEL(3359); break;
	case 3360: LAUNCH_KERNEL(3360); break;
	case 3361: LAUNCH_KERNEL(3361); break;
	case 3362: LAUNCH_KERNEL(3362); break;
	case 3363: LAUNCH_KERNEL(3363); break;
	case 3364: LAUNCH_KERNEL(3364); break;
	case 3365: LAUNCH_KERNEL(3365); break;
	case 3366: LAUNCH_KERNEL(3366); break;
	case 3367: LAUNCH_KERNEL(3367); break;
	case 3368: LAUNCH_KERNEL(3368); break;
	case 3369: LAUNCH_KERNEL(3369); break;
	case 3370: LAUNCH_KERNEL(3370); break;
	case 3371: LAUNCH_KERNEL(3371); break;
	case 3372: LAUNCH_KERNEL(3372); break;
	case 3373: LAUNCH_KERNEL(3373); break;
	case 3374: LAUNCH_KERNEL(3374); break;
	case 3375: LAUNCH_KERNEL(3375); break;
	case 3376: LAUNCH_KERNEL(3376); break;
	case 3377: LAUNCH_KERNEL(3377); break;
	case 3378: LAUNCH_KERNEL(3378); break;
	case 3379: LAUNCH_KERNEL(3379); break;
	case 3380: LAUNCH_KERNEL(3380); break;
	case 3381: LAUNCH_KERNEL(3381); break;
	case 3382: LAUNCH_KERNEL(3382); break;
	case 3383: LAUNCH_KERNEL(3383); break;
	case 3384: LAUNCH_KERNEL(3384); break;
	case 3385: LAUNCH_KERNEL(3385); break;
	case 3386: LAUNCH_KERNEL(3386); break;
	case 3387: LAUNCH_KERNEL(3387); break;
	case 3388: LAUNCH_KERNEL(3388); break;
	case 3389: LAUNCH_KERNEL(3389); break;
	case 3390: LAUNCH_KERNEL(3390); break;
	case 3391: LAUNCH_KERNEL(3391); break;
	case 3392: LAUNCH_KERNEL(3392); break;
	case 3393: LAUNCH_KERNEL(3393); break;
	case 3394: LAUNCH_KERNEL(3394); break;
	case 3395: LAUNCH_KERNEL(3395); break;
	case 3396: LAUNCH_KERNEL(3396); break;
	case 3397: LAUNCH_KERNEL(3397); break;
	case 3398: LAUNCH_KERNEL(3398); break;
	case 3399: LAUNCH_KERNEL(3399); break;
	case 3400: LAUNCH_KERNEL(3400); break;
	case 3401: LAUNCH_KERNEL(3401); break;
	case 3402: LAUNCH_KERNEL(3402); break;
	case 3403: LAUNCH_KERNEL(3403); break;
	case 3404: LAUNCH_KERNEL(3404); break;
	case 3405: LAUNCH_KERNEL(3405); break;
	case 3406: LAUNCH_KERNEL(3406); break;
	case 3407: LAUNCH_KERNEL(3407); break;
	case 3408: LAUNCH_KERNEL(3408); break;
	case 3409: LAUNCH_KERNEL(3409); break;
	case 3410: LAUNCH_KERNEL(3410); break;
	case 3411: LAUNCH_KERNEL(3411); break;
	case 3412: LAUNCH_KERNEL(3412); break;
	case 3413: LAUNCH_KERNEL(3413); break;
	case 3414: LAUNCH_KERNEL(3414); break;
	case 3415: LAUNCH_KERNEL(3415); break;
	case 3416: LAUNCH_KERNEL(3416); break;
	case 3417: LAUNCH_KERNEL(3417); break;
	case 3418: LAUNCH_KERNEL(3418); break;
	case 3419: LAUNCH_KERNEL(3419); break;
	case 3420: LAUNCH_KERNEL(3420); break;
	case 3421: LAUNCH_KERNEL(3421); break;
	case 3422: LAUNCH_KERNEL(3422); break;
	case 3423: LAUNCH_KERNEL(3423); break;
	case 3424: LAUNCH_KERNEL(3424); break;
	case 3425: LAUNCH_KERNEL(3425); break;
	case 3426: LAUNCH_KERNEL(3426); break;
	case 3427: LAUNCH_KERNEL(3427); break;
	case 3428: LAUNCH_KERNEL(3428); break;
	case 3429: LAUNCH_KERNEL(3429); break;
	case 3430: LAUNCH_KERNEL(3430); break;
	case 3431: LAUNCH_KERNEL(3431); break;
	case 3432: LAUNCH_KERNEL(3432); break;
	case 3433: LAUNCH_KERNEL(3433); break;
	case 3434: LAUNCH_KERNEL(3434); break;
	case 3435: LAUNCH_KERNEL(3435); break;
	case 3436: LAUNCH_KERNEL(3436); break;
	case 3437: LAUNCH_KERNEL(3437); break;
	case 3438: LAUNCH_KERNEL(3438); break;
	case 3439: LAUNCH_KERNEL(3439); break;
	case 3440: LAUNCH_KERNEL(3440); break;
	case 3441: LAUNCH_KERNEL(3441); break;
	case 3442: LAUNCH_KERNEL(3442); break;
	case 3443: LAUNCH_KERNEL(3443); break;
	case 3444: LAUNCH_KERNEL(3444); break;
	case 3445: LAUNCH_KERNEL(3445); break;
	case 3446: LAUNCH_KERNEL(3446); break;
	case 3447: LAUNCH_KERNEL(3447); break;
	case 3448: LAUNCH_KERNEL(3448); break;
	case 3449: LAUNCH_KERNEL(3449); break;
	case 3450: LAUNCH_KERNEL(3450); break;
	case 3451: LAUNCH_KERNEL(3451); break;
	case 3452: LAUNCH_KERNEL(3452); break;
	case 3453: LAUNCH_KERNEL(3453); break;
	case 3454: LAUNCH_KERNEL(3454); break;
	case 3455: LAUNCH_KERNEL(3455); break;
	case 3456: LAUNCH_KERNEL(3456); break;
	case 3457: LAUNCH_KERNEL(3457); break;
	case 3458: LAUNCH_KERNEL(3458); break;
	case 3459: LAUNCH_KERNEL(3459); break;
	case 3460: LAUNCH_KERNEL(3460); break;
	case 3461: LAUNCH_KERNEL(3461); break;
	case 3462: LAUNCH_KERNEL(3462); break;
	case 3463: LAUNCH_KERNEL(3463); break;
	case 3464: LAUNCH_KERNEL(3464); break;
	case 3465: LAUNCH_KERNEL(3465); break;
	case 3466: LAUNCH_KERNEL(3466); break;
	case 3467: LAUNCH_KERNEL(3467); break;
	case 3468: LAUNCH_KERNEL(3468); break;
	case 3469: LAUNCH_KERNEL(3469); break;
	case 3470: LAUNCH_KERNEL(3470); break;
	case 3471: LAUNCH_KERNEL(3471); break;
	case 3472: LAUNCH_KERNEL(3472); break;
	case 3473: LAUNCH_KERNEL(3473); break;
	case 3474: LAUNCH_KERNEL(3474); break;
	case 3475: LAUNCH_KERNEL(3475); break;
	case 3476: LAUNCH_KERNEL(3476); break;
	case 3477: LAUNCH_KERNEL(3477); break;
	case 3478: LAUNCH_KERNEL(3478); break;
	case 3479: LAUNCH_KERNEL(3479); break;
	case 3480: LAUNCH_KERNEL(3480); break;
	case 3481: LAUNCH_KERNEL(3481); break;
	case 3482: LAUNCH_KERNEL(3482); break;
	case 3483: LAUNCH_KERNEL(3483); break;
	case 3484: LAUNCH_KERNEL(3484); break;
	case 3485: LAUNCH_KERNEL(3485); break;
	case 3486: LAUNCH_KERNEL(3486); break;
	case 3487: LAUNCH_KERNEL(3487); break;
	case 3488: LAUNCH_KERNEL(3488); break;
	case 3489: LAUNCH_KERNEL(3489); break;
	case 3490: LAUNCH_KERNEL(3490); break;
	case 3491: LAUNCH_KERNEL(3491); break;
	case 3492: LAUNCH_KERNEL(3492); break;
	case 3493: LAUNCH_KERNEL(3493); break;
	case 3494: LAUNCH_KERNEL(3494); break;
	case 3495: LAUNCH_KERNEL(3495); break;
	case 3496: LAUNCH_KERNEL(3496); break;
	case 3497: LAUNCH_KERNEL(3497); break;
	case 3498: LAUNCH_KERNEL(3498); break;
	case 3499: LAUNCH_KERNEL(3499); break;
	case 3500: LAUNCH_KERNEL(3500); break;
	case 3501: LAUNCH_KERNEL(3501); break;
	case 3502: LAUNCH_KERNEL(3502); break;
	case 3503: LAUNCH_KERNEL(3503); break;
	case 3504: LAUNCH_KERNEL(3504); break;
	case 3505: LAUNCH_KERNEL(3505); break;
	case 3506: LAUNCH_KERNEL(3506); break;
	case 3507: LAUNCH_KERNEL(3507); break;
	case 3508: LAUNCH_KERNEL(3508); break;
	case 3509: LAUNCH_KERNEL(3509); break;
	case 3510: LAUNCH_KERNEL(3510); break;
	case 3511: LAUNCH_KERNEL(3511); break;
	case 3512: LAUNCH_KERNEL(3512); break;
	case 3513: LAUNCH_KERNEL(3513); break;
	case 3514: LAUNCH_KERNEL(3514); break;
	case 3515: LAUNCH_KERNEL(3515); break;
	case 3516: LAUNCH_KERNEL(3516); break;
	case 3517: LAUNCH_KERNEL(3517); break;
	case 3518: LAUNCH_KERNEL(3518); break;
	case 3519: LAUNCH_KERNEL(3519); break;
	case 3520: LAUNCH_KERNEL(3520); break;
	case 3521: LAUNCH_KERNEL(3521); break;
	case 3522: LAUNCH_KERNEL(3522); break;
	case 3523: LAUNCH_KERNEL(3523); break;
	case 3524: LAUNCH_KERNEL(3524); break;
	case 3525: LAUNCH_KERNEL(3525); break;
	case 3526: LAUNCH_KERNEL(3526); break;
	case 3527: LAUNCH_KERNEL(3527); break;
	case 3528: LAUNCH_KERNEL(3528); break;
	case 3529: LAUNCH_KERNEL(3529); break;
	case 3530: LAUNCH_KERNEL(3530); break;
	case 3531: LAUNCH_KERNEL(3531); break;
	case 3532: LAUNCH_KERNEL(3532); break;
	case 3533: LAUNCH_KERNEL(3533); break;
	case 3534: LAUNCH_KERNEL(3534); break;
	case 3535: LAUNCH_KERNEL(3535); break;
	case 3536: LAUNCH_KERNEL(3536); break;
	case 3537: LAUNCH_KERNEL(3537); break;
	case 3538: LAUNCH_KERNEL(3538); break;
	case 3539: LAUNCH_KERNEL(3539); break;
	case 3540: LAUNCH_KERNEL(3540); break;
	case 3541: LAUNCH_KERNEL(3541); break;
	case 3542: LAUNCH_KERNEL(3542); break;
	case 3543: LAUNCH_KERNEL(3543); break;
	case 3544: LAUNCH_KERNEL(3544); break;
	case 3545: LAUNCH_KERNEL(3545); break;
	case 3546: LAUNCH_KERNEL(3546); break;
	case 3547: LAUNCH_KERNEL(3547); break;
	case 3548: LAUNCH_KERNEL(3548); break;
	case 3549: LAUNCH_KERNEL(3549); break;
	case 3550: LAUNCH_KERNEL(3550); break;
	case 3551: LAUNCH_KERNEL(3551); break;
	case 3552: LAUNCH_KERNEL(3552); break;
	case 3553: LAUNCH_KERNEL(3553); break;
	case 3554: LAUNCH_KERNEL(3554); break;
	case 3555: LAUNCH_KERNEL(3555); break;
	case 3556: LAUNCH_KERNEL(3556); break;
	case 3557: LAUNCH_KERNEL(3557); break;
	case 3558: LAUNCH_KERNEL(3558); break;
	case 3559: LAUNCH_KERNEL(3559); break;
	case 3560: LAUNCH_KERNEL(3560); break;
	case 3561: LAUNCH_KERNEL(3561); break;
	case 3562: LAUNCH_KERNEL(3562); break;
	case 3563: LAUNCH_KERNEL(3563); break;
	case 3564: LAUNCH_KERNEL(3564); break;
	case 3565: LAUNCH_KERNEL(3565); break;
	case 3566: LAUNCH_KERNEL(3566); break;
	case 3567: LAUNCH_KERNEL(3567); break;
	case 3568: LAUNCH_KERNEL(3568); break;
	case 3569: LAUNCH_KERNEL(3569); break;
	case 3570: LAUNCH_KERNEL(3570); break;
	case 3571: LAUNCH_KERNEL(3571); break;
	case 3572: LAUNCH_KERNEL(3572); break;
	case 3573: LAUNCH_KERNEL(3573); break;
	case 3574: LAUNCH_KERNEL(3574); break;
	case 3575: LAUNCH_KERNEL(3575); break;
	case 3576: LAUNCH_KERNEL(3576); break;
	case 3577: LAUNCH_KERNEL(3577); break;
	case 3578: LAUNCH_KERNEL(3578); break;
	case 3579: LAUNCH_KERNEL(3579); break;
	case 3580: LAUNCH_KERNEL(3580); break;
	case 3581: LAUNCH_KERNEL(3581); break;
	case 3582: LAUNCH_KERNEL(3582); break;
	case 3583: LAUNCH_KERNEL(3583); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
