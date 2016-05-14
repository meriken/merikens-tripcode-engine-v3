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

#define SALT 2304
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2305
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2306
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2307
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2308
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2309
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2310
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2311
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2312
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2313
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2314
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2315
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2316
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2317
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2318
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2319
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2320
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2321
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2322
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2323
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2324
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2325
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2326
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2327
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2328
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2329
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2330
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2331
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2332
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2333
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2334
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2335
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2336
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2337
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2338
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2339
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2340
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2341
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2342
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2343
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2344
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2345
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2346
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2347
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2348
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2349
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2350
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2351
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2352
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2353
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2354
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2355
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2356
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2357
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2358
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2359
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2360
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2361
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2362
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2363
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2364
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2365
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2366
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2367
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2368
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2369
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2370
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2371
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2372
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2373
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2374
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2375
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2376
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2377
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2378
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2379
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2380
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2381
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2382
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2383
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2384
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2385
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2386
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2387
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2388
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2389
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2390
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2391
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2392
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2393
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2394
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2395
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2396
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2397
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2398
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2399
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2400
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2401
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2402
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2403
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2404
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2405
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2406
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2407
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2408
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2409
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2410
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2411
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2412
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2413
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2414
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2415
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2416
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2417
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2418
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2419
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2420
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2421
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2422
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2423
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2424
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2425
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2426
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2427
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2428
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2429
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2430
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2431
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2432
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2433
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2434
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2435
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2436
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2437
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2438
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2439
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2440
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2441
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2442
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2443
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2444
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2445
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2446
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2447
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2448
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2449
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2450
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2451
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2452
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2453
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2454
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2455
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2456
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2457
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2458
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2459
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2460
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2461
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2462
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2463
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2464
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2465
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2466
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2467
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2468
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2469
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2470
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2471
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2472
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2473
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2474
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2475
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2476
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2477
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2478
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2479
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2480
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2481
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2482
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2483
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2484
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2485
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2486
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2487
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2488
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2489
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2490
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2491
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2492
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2493
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2494
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2495
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2496
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2497
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2498
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2499
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2500
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2501
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2502
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2503
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2504
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2505
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2506
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2507
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2508
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2509
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2510
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2511
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2512
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2513
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2514
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2515
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2516
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2517
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2518
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2519
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2520
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2521
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2522
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2523
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2524
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2525
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2526
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2527
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2528
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2529
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2530
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2531
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2532
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2533
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2534
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2535
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2536
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2537
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2538
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2539
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2540
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2541
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2542
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2543
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2544
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2545
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2546
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2547
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2548
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2549
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2550
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2551
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2552
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2553
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2554
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2555
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2556
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2557
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2558
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2559
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher9()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel9(
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
	case 2304: LAUNCH_KERNEL(2304); break;
	case 2305: LAUNCH_KERNEL(2305); break;
	case 2306: LAUNCH_KERNEL(2306); break;
	case 2307: LAUNCH_KERNEL(2307); break;
	case 2308: LAUNCH_KERNEL(2308); break;
	case 2309: LAUNCH_KERNEL(2309); break;
	case 2310: LAUNCH_KERNEL(2310); break;
	case 2311: LAUNCH_KERNEL(2311); break;
	case 2312: LAUNCH_KERNEL(2312); break;
	case 2313: LAUNCH_KERNEL(2313); break;
	case 2314: LAUNCH_KERNEL(2314); break;
	case 2315: LAUNCH_KERNEL(2315); break;
	case 2316: LAUNCH_KERNEL(2316); break;
	case 2317: LAUNCH_KERNEL(2317); break;
	case 2318: LAUNCH_KERNEL(2318); break;
	case 2319: LAUNCH_KERNEL(2319); break;
	case 2320: LAUNCH_KERNEL(2320); break;
	case 2321: LAUNCH_KERNEL(2321); break;
	case 2322: LAUNCH_KERNEL(2322); break;
	case 2323: LAUNCH_KERNEL(2323); break;
	case 2324: LAUNCH_KERNEL(2324); break;
	case 2325: LAUNCH_KERNEL(2325); break;
	case 2326: LAUNCH_KERNEL(2326); break;
	case 2327: LAUNCH_KERNEL(2327); break;
	case 2328: LAUNCH_KERNEL(2328); break;
	case 2329: LAUNCH_KERNEL(2329); break;
	case 2330: LAUNCH_KERNEL(2330); break;
	case 2331: LAUNCH_KERNEL(2331); break;
	case 2332: LAUNCH_KERNEL(2332); break;
	case 2333: LAUNCH_KERNEL(2333); break;
	case 2334: LAUNCH_KERNEL(2334); break;
	case 2335: LAUNCH_KERNEL(2335); break;
	case 2336: LAUNCH_KERNEL(2336); break;
	case 2337: LAUNCH_KERNEL(2337); break;
	case 2338: LAUNCH_KERNEL(2338); break;
	case 2339: LAUNCH_KERNEL(2339); break;
	case 2340: LAUNCH_KERNEL(2340); break;
	case 2341: LAUNCH_KERNEL(2341); break;
	case 2342: LAUNCH_KERNEL(2342); break;
	case 2343: LAUNCH_KERNEL(2343); break;
	case 2344: LAUNCH_KERNEL(2344); break;
	case 2345: LAUNCH_KERNEL(2345); break;
	case 2346: LAUNCH_KERNEL(2346); break;
	case 2347: LAUNCH_KERNEL(2347); break;
	case 2348: LAUNCH_KERNEL(2348); break;
	case 2349: LAUNCH_KERNEL(2349); break;
	case 2350: LAUNCH_KERNEL(2350); break;
	case 2351: LAUNCH_KERNEL(2351); break;
	case 2352: LAUNCH_KERNEL(2352); break;
	case 2353: LAUNCH_KERNEL(2353); break;
	case 2354: LAUNCH_KERNEL(2354); break;
	case 2355: LAUNCH_KERNEL(2355); break;
	case 2356: LAUNCH_KERNEL(2356); break;
	case 2357: LAUNCH_KERNEL(2357); break;
	case 2358: LAUNCH_KERNEL(2358); break;
	case 2359: LAUNCH_KERNEL(2359); break;
	case 2360: LAUNCH_KERNEL(2360); break;
	case 2361: LAUNCH_KERNEL(2361); break;
	case 2362: LAUNCH_KERNEL(2362); break;
	case 2363: LAUNCH_KERNEL(2363); break;
	case 2364: LAUNCH_KERNEL(2364); break;
	case 2365: LAUNCH_KERNEL(2365); break;
	case 2366: LAUNCH_KERNEL(2366); break;
	case 2367: LAUNCH_KERNEL(2367); break;
	case 2368: LAUNCH_KERNEL(2368); break;
	case 2369: LAUNCH_KERNEL(2369); break;
	case 2370: LAUNCH_KERNEL(2370); break;
	case 2371: LAUNCH_KERNEL(2371); break;
	case 2372: LAUNCH_KERNEL(2372); break;
	case 2373: LAUNCH_KERNEL(2373); break;
	case 2374: LAUNCH_KERNEL(2374); break;
	case 2375: LAUNCH_KERNEL(2375); break;
	case 2376: LAUNCH_KERNEL(2376); break;
	case 2377: LAUNCH_KERNEL(2377); break;
	case 2378: LAUNCH_KERNEL(2378); break;
	case 2379: LAUNCH_KERNEL(2379); break;
	case 2380: LAUNCH_KERNEL(2380); break;
	case 2381: LAUNCH_KERNEL(2381); break;
	case 2382: LAUNCH_KERNEL(2382); break;
	case 2383: LAUNCH_KERNEL(2383); break;
	case 2384: LAUNCH_KERNEL(2384); break;
	case 2385: LAUNCH_KERNEL(2385); break;
	case 2386: LAUNCH_KERNEL(2386); break;
	case 2387: LAUNCH_KERNEL(2387); break;
	case 2388: LAUNCH_KERNEL(2388); break;
	case 2389: LAUNCH_KERNEL(2389); break;
	case 2390: LAUNCH_KERNEL(2390); break;
	case 2391: LAUNCH_KERNEL(2391); break;
	case 2392: LAUNCH_KERNEL(2392); break;
	case 2393: LAUNCH_KERNEL(2393); break;
	case 2394: LAUNCH_KERNEL(2394); break;
	case 2395: LAUNCH_KERNEL(2395); break;
	case 2396: LAUNCH_KERNEL(2396); break;
	case 2397: LAUNCH_KERNEL(2397); break;
	case 2398: LAUNCH_KERNEL(2398); break;
	case 2399: LAUNCH_KERNEL(2399); break;
	case 2400: LAUNCH_KERNEL(2400); break;
	case 2401: LAUNCH_KERNEL(2401); break;
	case 2402: LAUNCH_KERNEL(2402); break;
	case 2403: LAUNCH_KERNEL(2403); break;
	case 2404: LAUNCH_KERNEL(2404); break;
	case 2405: LAUNCH_KERNEL(2405); break;
	case 2406: LAUNCH_KERNEL(2406); break;
	case 2407: LAUNCH_KERNEL(2407); break;
	case 2408: LAUNCH_KERNEL(2408); break;
	case 2409: LAUNCH_KERNEL(2409); break;
	case 2410: LAUNCH_KERNEL(2410); break;
	case 2411: LAUNCH_KERNEL(2411); break;
	case 2412: LAUNCH_KERNEL(2412); break;
	case 2413: LAUNCH_KERNEL(2413); break;
	case 2414: LAUNCH_KERNEL(2414); break;
	case 2415: LAUNCH_KERNEL(2415); break;
	case 2416: LAUNCH_KERNEL(2416); break;
	case 2417: LAUNCH_KERNEL(2417); break;
	case 2418: LAUNCH_KERNEL(2418); break;
	case 2419: LAUNCH_KERNEL(2419); break;
	case 2420: LAUNCH_KERNEL(2420); break;
	case 2421: LAUNCH_KERNEL(2421); break;
	case 2422: LAUNCH_KERNEL(2422); break;
	case 2423: LAUNCH_KERNEL(2423); break;
	case 2424: LAUNCH_KERNEL(2424); break;
	case 2425: LAUNCH_KERNEL(2425); break;
	case 2426: LAUNCH_KERNEL(2426); break;
	case 2427: LAUNCH_KERNEL(2427); break;
	case 2428: LAUNCH_KERNEL(2428); break;
	case 2429: LAUNCH_KERNEL(2429); break;
	case 2430: LAUNCH_KERNEL(2430); break;
	case 2431: LAUNCH_KERNEL(2431); break;
	case 2432: LAUNCH_KERNEL(2432); break;
	case 2433: LAUNCH_KERNEL(2433); break;
	case 2434: LAUNCH_KERNEL(2434); break;
	case 2435: LAUNCH_KERNEL(2435); break;
	case 2436: LAUNCH_KERNEL(2436); break;
	case 2437: LAUNCH_KERNEL(2437); break;
	case 2438: LAUNCH_KERNEL(2438); break;
	case 2439: LAUNCH_KERNEL(2439); break;
	case 2440: LAUNCH_KERNEL(2440); break;
	case 2441: LAUNCH_KERNEL(2441); break;
	case 2442: LAUNCH_KERNEL(2442); break;
	case 2443: LAUNCH_KERNEL(2443); break;
	case 2444: LAUNCH_KERNEL(2444); break;
	case 2445: LAUNCH_KERNEL(2445); break;
	case 2446: LAUNCH_KERNEL(2446); break;
	case 2447: LAUNCH_KERNEL(2447); break;
	case 2448: LAUNCH_KERNEL(2448); break;
	case 2449: LAUNCH_KERNEL(2449); break;
	case 2450: LAUNCH_KERNEL(2450); break;
	case 2451: LAUNCH_KERNEL(2451); break;
	case 2452: LAUNCH_KERNEL(2452); break;
	case 2453: LAUNCH_KERNEL(2453); break;
	case 2454: LAUNCH_KERNEL(2454); break;
	case 2455: LAUNCH_KERNEL(2455); break;
	case 2456: LAUNCH_KERNEL(2456); break;
	case 2457: LAUNCH_KERNEL(2457); break;
	case 2458: LAUNCH_KERNEL(2458); break;
	case 2459: LAUNCH_KERNEL(2459); break;
	case 2460: LAUNCH_KERNEL(2460); break;
	case 2461: LAUNCH_KERNEL(2461); break;
	case 2462: LAUNCH_KERNEL(2462); break;
	case 2463: LAUNCH_KERNEL(2463); break;
	case 2464: LAUNCH_KERNEL(2464); break;
	case 2465: LAUNCH_KERNEL(2465); break;
	case 2466: LAUNCH_KERNEL(2466); break;
	case 2467: LAUNCH_KERNEL(2467); break;
	case 2468: LAUNCH_KERNEL(2468); break;
	case 2469: LAUNCH_KERNEL(2469); break;
	case 2470: LAUNCH_KERNEL(2470); break;
	case 2471: LAUNCH_KERNEL(2471); break;
	case 2472: LAUNCH_KERNEL(2472); break;
	case 2473: LAUNCH_KERNEL(2473); break;
	case 2474: LAUNCH_KERNEL(2474); break;
	case 2475: LAUNCH_KERNEL(2475); break;
	case 2476: LAUNCH_KERNEL(2476); break;
	case 2477: LAUNCH_KERNEL(2477); break;
	case 2478: LAUNCH_KERNEL(2478); break;
	case 2479: LAUNCH_KERNEL(2479); break;
	case 2480: LAUNCH_KERNEL(2480); break;
	case 2481: LAUNCH_KERNEL(2481); break;
	case 2482: LAUNCH_KERNEL(2482); break;
	case 2483: LAUNCH_KERNEL(2483); break;
	case 2484: LAUNCH_KERNEL(2484); break;
	case 2485: LAUNCH_KERNEL(2485); break;
	case 2486: LAUNCH_KERNEL(2486); break;
	case 2487: LAUNCH_KERNEL(2487); break;
	case 2488: LAUNCH_KERNEL(2488); break;
	case 2489: LAUNCH_KERNEL(2489); break;
	case 2490: LAUNCH_KERNEL(2490); break;
	case 2491: LAUNCH_KERNEL(2491); break;
	case 2492: LAUNCH_KERNEL(2492); break;
	case 2493: LAUNCH_KERNEL(2493); break;
	case 2494: LAUNCH_KERNEL(2494); break;
	case 2495: LAUNCH_KERNEL(2495); break;
	case 2496: LAUNCH_KERNEL(2496); break;
	case 2497: LAUNCH_KERNEL(2497); break;
	case 2498: LAUNCH_KERNEL(2498); break;
	case 2499: LAUNCH_KERNEL(2499); break;
	case 2500: LAUNCH_KERNEL(2500); break;
	case 2501: LAUNCH_KERNEL(2501); break;
	case 2502: LAUNCH_KERNEL(2502); break;
	case 2503: LAUNCH_KERNEL(2503); break;
	case 2504: LAUNCH_KERNEL(2504); break;
	case 2505: LAUNCH_KERNEL(2505); break;
	case 2506: LAUNCH_KERNEL(2506); break;
	case 2507: LAUNCH_KERNEL(2507); break;
	case 2508: LAUNCH_KERNEL(2508); break;
	case 2509: LAUNCH_KERNEL(2509); break;
	case 2510: LAUNCH_KERNEL(2510); break;
	case 2511: LAUNCH_KERNEL(2511); break;
	case 2512: LAUNCH_KERNEL(2512); break;
	case 2513: LAUNCH_KERNEL(2513); break;
	case 2514: LAUNCH_KERNEL(2514); break;
	case 2515: LAUNCH_KERNEL(2515); break;
	case 2516: LAUNCH_KERNEL(2516); break;
	case 2517: LAUNCH_KERNEL(2517); break;
	case 2518: LAUNCH_KERNEL(2518); break;
	case 2519: LAUNCH_KERNEL(2519); break;
	case 2520: LAUNCH_KERNEL(2520); break;
	case 2521: LAUNCH_KERNEL(2521); break;
	case 2522: LAUNCH_KERNEL(2522); break;
	case 2523: LAUNCH_KERNEL(2523); break;
	case 2524: LAUNCH_KERNEL(2524); break;
	case 2525: LAUNCH_KERNEL(2525); break;
	case 2526: LAUNCH_KERNEL(2526); break;
	case 2527: LAUNCH_KERNEL(2527); break;
	case 2528: LAUNCH_KERNEL(2528); break;
	case 2529: LAUNCH_KERNEL(2529); break;
	case 2530: LAUNCH_KERNEL(2530); break;
	case 2531: LAUNCH_KERNEL(2531); break;
	case 2532: LAUNCH_KERNEL(2532); break;
	case 2533: LAUNCH_KERNEL(2533); break;
	case 2534: LAUNCH_KERNEL(2534); break;
	case 2535: LAUNCH_KERNEL(2535); break;
	case 2536: LAUNCH_KERNEL(2536); break;
	case 2537: LAUNCH_KERNEL(2537); break;
	case 2538: LAUNCH_KERNEL(2538); break;
	case 2539: LAUNCH_KERNEL(2539); break;
	case 2540: LAUNCH_KERNEL(2540); break;
	case 2541: LAUNCH_KERNEL(2541); break;
	case 2542: LAUNCH_KERNEL(2542); break;
	case 2543: LAUNCH_KERNEL(2543); break;
	case 2544: LAUNCH_KERNEL(2544); break;
	case 2545: LAUNCH_KERNEL(2545); break;
	case 2546: LAUNCH_KERNEL(2546); break;
	case 2547: LAUNCH_KERNEL(2547); break;
	case 2548: LAUNCH_KERNEL(2548); break;
	case 2549: LAUNCH_KERNEL(2549); break;
	case 2550: LAUNCH_KERNEL(2550); break;
	case 2551: LAUNCH_KERNEL(2551); break;
	case 2552: LAUNCH_KERNEL(2552); break;
	case 2553: LAUNCH_KERNEL(2553); break;
	case 2554: LAUNCH_KERNEL(2554); break;
	case 2555: LAUNCH_KERNEL(2555); break;
	case 2556: LAUNCH_KERNEL(2556); break;
	case 2557: LAUNCH_KERNEL(2557); break;
	case 2558: LAUNCH_KERNEL(2558); break;
	case 2559: LAUNCH_KERNEL(2559); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
