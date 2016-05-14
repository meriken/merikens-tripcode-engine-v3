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

#define SALT 2560
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2561
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2562
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2563
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2564
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2565
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2566
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2567
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2568
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2569
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2570
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2571
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2572
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2573
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2574
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2575
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2576
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2577
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2578
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2579
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2580
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2581
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2582
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2583
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2584
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2585
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2586
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2587
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2588
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2589
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2590
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2591
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2592
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2593
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2594
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2595
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2596
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2597
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2598
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2599
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2600
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2601
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2602
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2603
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2604
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2605
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2606
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2607
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2608
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2609
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2610
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2611
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2612
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2613
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2614
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2615
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2616
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2617
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2618
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2619
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2620
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2621
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2622
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2623
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2624
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2625
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2626
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2627
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2628
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2629
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2630
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2631
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2632
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2633
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2634
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2635
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2636
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2637
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2638
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2639
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2640
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2641
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2642
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2643
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2644
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2645
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2646
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2647
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2648
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2649
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2650
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2651
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2652
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2653
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2654
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2655
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2656
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2657
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2658
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2659
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2660
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2661
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2662
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2663
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2664
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2665
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2666
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2667
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2668
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2669
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2670
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2671
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2672
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2673
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2674
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2675
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2676
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2677
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2678
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2679
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2680
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2681
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2682
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2683
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2684
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2685
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2686
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2687
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2688
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2689
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2690
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2691
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2692
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2693
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2694
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2695
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2696
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2697
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2698
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2699
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2700
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2701
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2702
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2703
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2704
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2705
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2706
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2707
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2708
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2709
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2710
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2711
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2712
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2713
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2714
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2715
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2716
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2717
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2718
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2719
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2720
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2721
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2722
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2723
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2724
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2725
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2726
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2727
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2728
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2729
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2730
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2731
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2732
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2733
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2734
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2735
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2736
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2737
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2738
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2739
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2740
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2741
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2742
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2743
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2744
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2745
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2746
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2747
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2748
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2749
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2750
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2751
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2752
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2753
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2754
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2755
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2756
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2757
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2758
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2759
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2760
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2761
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2762
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2763
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2764
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2765
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2766
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2767
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2768
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2769
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2770
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2771
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2772
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2773
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2774
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2775
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2776
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2777
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2778
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2779
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2780
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2781
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2782
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2783
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2784
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2785
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2786
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2787
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2788
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2789
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2790
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2791
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2792
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2793
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2794
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2795
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2796
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2797
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2798
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2799
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2800
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2801
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2802
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2803
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2804
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2805
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2806
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2807
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2808
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2809
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2810
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2811
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2812
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2813
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2814
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2815
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher10()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel10(
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
	case 2560: LAUNCH_KERNEL(2560); break;
	case 2561: LAUNCH_KERNEL(2561); break;
	case 2562: LAUNCH_KERNEL(2562); break;
	case 2563: LAUNCH_KERNEL(2563); break;
	case 2564: LAUNCH_KERNEL(2564); break;
	case 2565: LAUNCH_KERNEL(2565); break;
	case 2566: LAUNCH_KERNEL(2566); break;
	case 2567: LAUNCH_KERNEL(2567); break;
	case 2568: LAUNCH_KERNEL(2568); break;
	case 2569: LAUNCH_KERNEL(2569); break;
	case 2570: LAUNCH_KERNEL(2570); break;
	case 2571: LAUNCH_KERNEL(2571); break;
	case 2572: LAUNCH_KERNEL(2572); break;
	case 2573: LAUNCH_KERNEL(2573); break;
	case 2574: LAUNCH_KERNEL(2574); break;
	case 2575: LAUNCH_KERNEL(2575); break;
	case 2576: LAUNCH_KERNEL(2576); break;
	case 2577: LAUNCH_KERNEL(2577); break;
	case 2578: LAUNCH_KERNEL(2578); break;
	case 2579: LAUNCH_KERNEL(2579); break;
	case 2580: LAUNCH_KERNEL(2580); break;
	case 2581: LAUNCH_KERNEL(2581); break;
	case 2582: LAUNCH_KERNEL(2582); break;
	case 2583: LAUNCH_KERNEL(2583); break;
	case 2584: LAUNCH_KERNEL(2584); break;
	case 2585: LAUNCH_KERNEL(2585); break;
	case 2586: LAUNCH_KERNEL(2586); break;
	case 2587: LAUNCH_KERNEL(2587); break;
	case 2588: LAUNCH_KERNEL(2588); break;
	case 2589: LAUNCH_KERNEL(2589); break;
	case 2590: LAUNCH_KERNEL(2590); break;
	case 2591: LAUNCH_KERNEL(2591); break;
	case 2592: LAUNCH_KERNEL(2592); break;
	case 2593: LAUNCH_KERNEL(2593); break;
	case 2594: LAUNCH_KERNEL(2594); break;
	case 2595: LAUNCH_KERNEL(2595); break;
	case 2596: LAUNCH_KERNEL(2596); break;
	case 2597: LAUNCH_KERNEL(2597); break;
	case 2598: LAUNCH_KERNEL(2598); break;
	case 2599: LAUNCH_KERNEL(2599); break;
	case 2600: LAUNCH_KERNEL(2600); break;
	case 2601: LAUNCH_KERNEL(2601); break;
	case 2602: LAUNCH_KERNEL(2602); break;
	case 2603: LAUNCH_KERNEL(2603); break;
	case 2604: LAUNCH_KERNEL(2604); break;
	case 2605: LAUNCH_KERNEL(2605); break;
	case 2606: LAUNCH_KERNEL(2606); break;
	case 2607: LAUNCH_KERNEL(2607); break;
	case 2608: LAUNCH_KERNEL(2608); break;
	case 2609: LAUNCH_KERNEL(2609); break;
	case 2610: LAUNCH_KERNEL(2610); break;
	case 2611: LAUNCH_KERNEL(2611); break;
	case 2612: LAUNCH_KERNEL(2612); break;
	case 2613: LAUNCH_KERNEL(2613); break;
	case 2614: LAUNCH_KERNEL(2614); break;
	case 2615: LAUNCH_KERNEL(2615); break;
	case 2616: LAUNCH_KERNEL(2616); break;
	case 2617: LAUNCH_KERNEL(2617); break;
	case 2618: LAUNCH_KERNEL(2618); break;
	case 2619: LAUNCH_KERNEL(2619); break;
	case 2620: LAUNCH_KERNEL(2620); break;
	case 2621: LAUNCH_KERNEL(2621); break;
	case 2622: LAUNCH_KERNEL(2622); break;
	case 2623: LAUNCH_KERNEL(2623); break;
	case 2624: LAUNCH_KERNEL(2624); break;
	case 2625: LAUNCH_KERNEL(2625); break;
	case 2626: LAUNCH_KERNEL(2626); break;
	case 2627: LAUNCH_KERNEL(2627); break;
	case 2628: LAUNCH_KERNEL(2628); break;
	case 2629: LAUNCH_KERNEL(2629); break;
	case 2630: LAUNCH_KERNEL(2630); break;
	case 2631: LAUNCH_KERNEL(2631); break;
	case 2632: LAUNCH_KERNEL(2632); break;
	case 2633: LAUNCH_KERNEL(2633); break;
	case 2634: LAUNCH_KERNEL(2634); break;
	case 2635: LAUNCH_KERNEL(2635); break;
	case 2636: LAUNCH_KERNEL(2636); break;
	case 2637: LAUNCH_KERNEL(2637); break;
	case 2638: LAUNCH_KERNEL(2638); break;
	case 2639: LAUNCH_KERNEL(2639); break;
	case 2640: LAUNCH_KERNEL(2640); break;
	case 2641: LAUNCH_KERNEL(2641); break;
	case 2642: LAUNCH_KERNEL(2642); break;
	case 2643: LAUNCH_KERNEL(2643); break;
	case 2644: LAUNCH_KERNEL(2644); break;
	case 2645: LAUNCH_KERNEL(2645); break;
	case 2646: LAUNCH_KERNEL(2646); break;
	case 2647: LAUNCH_KERNEL(2647); break;
	case 2648: LAUNCH_KERNEL(2648); break;
	case 2649: LAUNCH_KERNEL(2649); break;
	case 2650: LAUNCH_KERNEL(2650); break;
	case 2651: LAUNCH_KERNEL(2651); break;
	case 2652: LAUNCH_KERNEL(2652); break;
	case 2653: LAUNCH_KERNEL(2653); break;
	case 2654: LAUNCH_KERNEL(2654); break;
	case 2655: LAUNCH_KERNEL(2655); break;
	case 2656: LAUNCH_KERNEL(2656); break;
	case 2657: LAUNCH_KERNEL(2657); break;
	case 2658: LAUNCH_KERNEL(2658); break;
	case 2659: LAUNCH_KERNEL(2659); break;
	case 2660: LAUNCH_KERNEL(2660); break;
	case 2661: LAUNCH_KERNEL(2661); break;
	case 2662: LAUNCH_KERNEL(2662); break;
	case 2663: LAUNCH_KERNEL(2663); break;
	case 2664: LAUNCH_KERNEL(2664); break;
	case 2665: LAUNCH_KERNEL(2665); break;
	case 2666: LAUNCH_KERNEL(2666); break;
	case 2667: LAUNCH_KERNEL(2667); break;
	case 2668: LAUNCH_KERNEL(2668); break;
	case 2669: LAUNCH_KERNEL(2669); break;
	case 2670: LAUNCH_KERNEL(2670); break;
	case 2671: LAUNCH_KERNEL(2671); break;
	case 2672: LAUNCH_KERNEL(2672); break;
	case 2673: LAUNCH_KERNEL(2673); break;
	case 2674: LAUNCH_KERNEL(2674); break;
	case 2675: LAUNCH_KERNEL(2675); break;
	case 2676: LAUNCH_KERNEL(2676); break;
	case 2677: LAUNCH_KERNEL(2677); break;
	case 2678: LAUNCH_KERNEL(2678); break;
	case 2679: LAUNCH_KERNEL(2679); break;
	case 2680: LAUNCH_KERNEL(2680); break;
	case 2681: LAUNCH_KERNEL(2681); break;
	case 2682: LAUNCH_KERNEL(2682); break;
	case 2683: LAUNCH_KERNEL(2683); break;
	case 2684: LAUNCH_KERNEL(2684); break;
	case 2685: LAUNCH_KERNEL(2685); break;
	case 2686: LAUNCH_KERNEL(2686); break;
	case 2687: LAUNCH_KERNEL(2687); break;
	case 2688: LAUNCH_KERNEL(2688); break;
	case 2689: LAUNCH_KERNEL(2689); break;
	case 2690: LAUNCH_KERNEL(2690); break;
	case 2691: LAUNCH_KERNEL(2691); break;
	case 2692: LAUNCH_KERNEL(2692); break;
	case 2693: LAUNCH_KERNEL(2693); break;
	case 2694: LAUNCH_KERNEL(2694); break;
	case 2695: LAUNCH_KERNEL(2695); break;
	case 2696: LAUNCH_KERNEL(2696); break;
	case 2697: LAUNCH_KERNEL(2697); break;
	case 2698: LAUNCH_KERNEL(2698); break;
	case 2699: LAUNCH_KERNEL(2699); break;
	case 2700: LAUNCH_KERNEL(2700); break;
	case 2701: LAUNCH_KERNEL(2701); break;
	case 2702: LAUNCH_KERNEL(2702); break;
	case 2703: LAUNCH_KERNEL(2703); break;
	case 2704: LAUNCH_KERNEL(2704); break;
	case 2705: LAUNCH_KERNEL(2705); break;
	case 2706: LAUNCH_KERNEL(2706); break;
	case 2707: LAUNCH_KERNEL(2707); break;
	case 2708: LAUNCH_KERNEL(2708); break;
	case 2709: LAUNCH_KERNEL(2709); break;
	case 2710: LAUNCH_KERNEL(2710); break;
	case 2711: LAUNCH_KERNEL(2711); break;
	case 2712: LAUNCH_KERNEL(2712); break;
	case 2713: LAUNCH_KERNEL(2713); break;
	case 2714: LAUNCH_KERNEL(2714); break;
	case 2715: LAUNCH_KERNEL(2715); break;
	case 2716: LAUNCH_KERNEL(2716); break;
	case 2717: LAUNCH_KERNEL(2717); break;
	case 2718: LAUNCH_KERNEL(2718); break;
	case 2719: LAUNCH_KERNEL(2719); break;
	case 2720: LAUNCH_KERNEL(2720); break;
	case 2721: LAUNCH_KERNEL(2721); break;
	case 2722: LAUNCH_KERNEL(2722); break;
	case 2723: LAUNCH_KERNEL(2723); break;
	case 2724: LAUNCH_KERNEL(2724); break;
	case 2725: LAUNCH_KERNEL(2725); break;
	case 2726: LAUNCH_KERNEL(2726); break;
	case 2727: LAUNCH_KERNEL(2727); break;
	case 2728: LAUNCH_KERNEL(2728); break;
	case 2729: LAUNCH_KERNEL(2729); break;
	case 2730: LAUNCH_KERNEL(2730); break;
	case 2731: LAUNCH_KERNEL(2731); break;
	case 2732: LAUNCH_KERNEL(2732); break;
	case 2733: LAUNCH_KERNEL(2733); break;
	case 2734: LAUNCH_KERNEL(2734); break;
	case 2735: LAUNCH_KERNEL(2735); break;
	case 2736: LAUNCH_KERNEL(2736); break;
	case 2737: LAUNCH_KERNEL(2737); break;
	case 2738: LAUNCH_KERNEL(2738); break;
	case 2739: LAUNCH_KERNEL(2739); break;
	case 2740: LAUNCH_KERNEL(2740); break;
	case 2741: LAUNCH_KERNEL(2741); break;
	case 2742: LAUNCH_KERNEL(2742); break;
	case 2743: LAUNCH_KERNEL(2743); break;
	case 2744: LAUNCH_KERNEL(2744); break;
	case 2745: LAUNCH_KERNEL(2745); break;
	case 2746: LAUNCH_KERNEL(2746); break;
	case 2747: LAUNCH_KERNEL(2747); break;
	case 2748: LAUNCH_KERNEL(2748); break;
	case 2749: LAUNCH_KERNEL(2749); break;
	case 2750: LAUNCH_KERNEL(2750); break;
	case 2751: LAUNCH_KERNEL(2751); break;
	case 2752: LAUNCH_KERNEL(2752); break;
	case 2753: LAUNCH_KERNEL(2753); break;
	case 2754: LAUNCH_KERNEL(2754); break;
	case 2755: LAUNCH_KERNEL(2755); break;
	case 2756: LAUNCH_KERNEL(2756); break;
	case 2757: LAUNCH_KERNEL(2757); break;
	case 2758: LAUNCH_KERNEL(2758); break;
	case 2759: LAUNCH_KERNEL(2759); break;
	case 2760: LAUNCH_KERNEL(2760); break;
	case 2761: LAUNCH_KERNEL(2761); break;
	case 2762: LAUNCH_KERNEL(2762); break;
	case 2763: LAUNCH_KERNEL(2763); break;
	case 2764: LAUNCH_KERNEL(2764); break;
	case 2765: LAUNCH_KERNEL(2765); break;
	case 2766: LAUNCH_KERNEL(2766); break;
	case 2767: LAUNCH_KERNEL(2767); break;
	case 2768: LAUNCH_KERNEL(2768); break;
	case 2769: LAUNCH_KERNEL(2769); break;
	case 2770: LAUNCH_KERNEL(2770); break;
	case 2771: LAUNCH_KERNEL(2771); break;
	case 2772: LAUNCH_KERNEL(2772); break;
	case 2773: LAUNCH_KERNEL(2773); break;
	case 2774: LAUNCH_KERNEL(2774); break;
	case 2775: LAUNCH_KERNEL(2775); break;
	case 2776: LAUNCH_KERNEL(2776); break;
	case 2777: LAUNCH_KERNEL(2777); break;
	case 2778: LAUNCH_KERNEL(2778); break;
	case 2779: LAUNCH_KERNEL(2779); break;
	case 2780: LAUNCH_KERNEL(2780); break;
	case 2781: LAUNCH_KERNEL(2781); break;
	case 2782: LAUNCH_KERNEL(2782); break;
	case 2783: LAUNCH_KERNEL(2783); break;
	case 2784: LAUNCH_KERNEL(2784); break;
	case 2785: LAUNCH_KERNEL(2785); break;
	case 2786: LAUNCH_KERNEL(2786); break;
	case 2787: LAUNCH_KERNEL(2787); break;
	case 2788: LAUNCH_KERNEL(2788); break;
	case 2789: LAUNCH_KERNEL(2789); break;
	case 2790: LAUNCH_KERNEL(2790); break;
	case 2791: LAUNCH_KERNEL(2791); break;
	case 2792: LAUNCH_KERNEL(2792); break;
	case 2793: LAUNCH_KERNEL(2793); break;
	case 2794: LAUNCH_KERNEL(2794); break;
	case 2795: LAUNCH_KERNEL(2795); break;
	case 2796: LAUNCH_KERNEL(2796); break;
	case 2797: LAUNCH_KERNEL(2797); break;
	case 2798: LAUNCH_KERNEL(2798); break;
	case 2799: LAUNCH_KERNEL(2799); break;
	case 2800: LAUNCH_KERNEL(2800); break;
	case 2801: LAUNCH_KERNEL(2801); break;
	case 2802: LAUNCH_KERNEL(2802); break;
	case 2803: LAUNCH_KERNEL(2803); break;
	case 2804: LAUNCH_KERNEL(2804); break;
	case 2805: LAUNCH_KERNEL(2805); break;
	case 2806: LAUNCH_KERNEL(2806); break;
	case 2807: LAUNCH_KERNEL(2807); break;
	case 2808: LAUNCH_KERNEL(2808); break;
	case 2809: LAUNCH_KERNEL(2809); break;
	case 2810: LAUNCH_KERNEL(2810); break;
	case 2811: LAUNCH_KERNEL(2811); break;
	case 2812: LAUNCH_KERNEL(2812); break;
	case 2813: LAUNCH_KERNEL(2813); break;
	case 2814: LAUNCH_KERNEL(2814); break;
	case 2815: LAUNCH_KERNEL(2815); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
