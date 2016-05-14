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

#define SALT 2816
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2817
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2818
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2819
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2820
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2821
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2822
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2823
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2824
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2825
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2826
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2827
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2828
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2829
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2830
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2831
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2832
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2833
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2834
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2835
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2836
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2837
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2838
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2839
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2840
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2841
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2842
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2843
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2844
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2845
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2846
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2847
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2848
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2849
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2850
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2851
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2852
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2853
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2854
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2855
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2856
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2857
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2858
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2859
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2860
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2861
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2862
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2863
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2864
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2865
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2866
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2867
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2868
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2869
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2870
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2871
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2872
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2873
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2874
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2875
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2876
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2877
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2878
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2879
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2880
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2881
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2882
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2883
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2884
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2885
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2886
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2887
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2888
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2889
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2890
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2891
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2892
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2893
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2894
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2895
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2896
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2897
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2898
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2899
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2900
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2901
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2902
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2903
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2904
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2905
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2906
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2907
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2908
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2909
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2910
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2911
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2912
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2913
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2914
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2915
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2916
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2917
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2918
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2919
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2920
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2921
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2922
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2923
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2924
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2925
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2926
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2927
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2928
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2929
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2930
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2931
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2932
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2933
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2934
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2935
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2936
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2937
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2938
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2939
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2940
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2941
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2942
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2943
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2944
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2945
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2946
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2947
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2948
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2949
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2950
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2951
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2952
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2953
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2954
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2955
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2956
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2957
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2958
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2959
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2960
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2961
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2962
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2963
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2964
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2965
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2966
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2967
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2968
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2969
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2970
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2971
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2972
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2973
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2974
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2975
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2976
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2977
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2978
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2979
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2980
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2981
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2982
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2983
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2984
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2985
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2986
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2987
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2988
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2989
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2990
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2991
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2992
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2993
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2994
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2995
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2996
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2997
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2998
#include "../CUDA10_Registers_Kernel.h"
#define SALT 2999
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3000
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3001
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3002
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3003
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3004
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3005
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3006
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3007
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3008
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3009
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3010
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3011
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3012
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3013
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3014
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3015
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3016
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3017
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3018
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3019
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3020
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3021
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3022
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3023
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3024
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3025
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3026
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3027
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3028
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3029
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3030
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3031
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3032
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3033
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3034
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3035
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3036
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3037
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3038
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3039
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3040
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3041
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3042
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3043
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3044
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3045
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3046
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3047
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3048
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3049
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3050
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3051
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3052
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3053
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3054
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3055
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3056
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3057
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3058
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3059
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3060
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3061
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3062
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3063
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3064
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3065
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3066
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3067
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3068
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3069
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3070
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3071
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher11()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel11(
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
	case 2816: LAUNCH_KERNEL(2816); break;
	case 2817: LAUNCH_KERNEL(2817); break;
	case 2818: LAUNCH_KERNEL(2818); break;
	case 2819: LAUNCH_KERNEL(2819); break;
	case 2820: LAUNCH_KERNEL(2820); break;
	case 2821: LAUNCH_KERNEL(2821); break;
	case 2822: LAUNCH_KERNEL(2822); break;
	case 2823: LAUNCH_KERNEL(2823); break;
	case 2824: LAUNCH_KERNEL(2824); break;
	case 2825: LAUNCH_KERNEL(2825); break;
	case 2826: LAUNCH_KERNEL(2826); break;
	case 2827: LAUNCH_KERNEL(2827); break;
	case 2828: LAUNCH_KERNEL(2828); break;
	case 2829: LAUNCH_KERNEL(2829); break;
	case 2830: LAUNCH_KERNEL(2830); break;
	case 2831: LAUNCH_KERNEL(2831); break;
	case 2832: LAUNCH_KERNEL(2832); break;
	case 2833: LAUNCH_KERNEL(2833); break;
	case 2834: LAUNCH_KERNEL(2834); break;
	case 2835: LAUNCH_KERNEL(2835); break;
	case 2836: LAUNCH_KERNEL(2836); break;
	case 2837: LAUNCH_KERNEL(2837); break;
	case 2838: LAUNCH_KERNEL(2838); break;
	case 2839: LAUNCH_KERNEL(2839); break;
	case 2840: LAUNCH_KERNEL(2840); break;
	case 2841: LAUNCH_KERNEL(2841); break;
	case 2842: LAUNCH_KERNEL(2842); break;
	case 2843: LAUNCH_KERNEL(2843); break;
	case 2844: LAUNCH_KERNEL(2844); break;
	case 2845: LAUNCH_KERNEL(2845); break;
	case 2846: LAUNCH_KERNEL(2846); break;
	case 2847: LAUNCH_KERNEL(2847); break;
	case 2848: LAUNCH_KERNEL(2848); break;
	case 2849: LAUNCH_KERNEL(2849); break;
	case 2850: LAUNCH_KERNEL(2850); break;
	case 2851: LAUNCH_KERNEL(2851); break;
	case 2852: LAUNCH_KERNEL(2852); break;
	case 2853: LAUNCH_KERNEL(2853); break;
	case 2854: LAUNCH_KERNEL(2854); break;
	case 2855: LAUNCH_KERNEL(2855); break;
	case 2856: LAUNCH_KERNEL(2856); break;
	case 2857: LAUNCH_KERNEL(2857); break;
	case 2858: LAUNCH_KERNEL(2858); break;
	case 2859: LAUNCH_KERNEL(2859); break;
	case 2860: LAUNCH_KERNEL(2860); break;
	case 2861: LAUNCH_KERNEL(2861); break;
	case 2862: LAUNCH_KERNEL(2862); break;
	case 2863: LAUNCH_KERNEL(2863); break;
	case 2864: LAUNCH_KERNEL(2864); break;
	case 2865: LAUNCH_KERNEL(2865); break;
	case 2866: LAUNCH_KERNEL(2866); break;
	case 2867: LAUNCH_KERNEL(2867); break;
	case 2868: LAUNCH_KERNEL(2868); break;
	case 2869: LAUNCH_KERNEL(2869); break;
	case 2870: LAUNCH_KERNEL(2870); break;
	case 2871: LAUNCH_KERNEL(2871); break;
	case 2872: LAUNCH_KERNEL(2872); break;
	case 2873: LAUNCH_KERNEL(2873); break;
	case 2874: LAUNCH_KERNEL(2874); break;
	case 2875: LAUNCH_KERNEL(2875); break;
	case 2876: LAUNCH_KERNEL(2876); break;
	case 2877: LAUNCH_KERNEL(2877); break;
	case 2878: LAUNCH_KERNEL(2878); break;
	case 2879: LAUNCH_KERNEL(2879); break;
	case 2880: LAUNCH_KERNEL(2880); break;
	case 2881: LAUNCH_KERNEL(2881); break;
	case 2882: LAUNCH_KERNEL(2882); break;
	case 2883: LAUNCH_KERNEL(2883); break;
	case 2884: LAUNCH_KERNEL(2884); break;
	case 2885: LAUNCH_KERNEL(2885); break;
	case 2886: LAUNCH_KERNEL(2886); break;
	case 2887: LAUNCH_KERNEL(2887); break;
	case 2888: LAUNCH_KERNEL(2888); break;
	case 2889: LAUNCH_KERNEL(2889); break;
	case 2890: LAUNCH_KERNEL(2890); break;
	case 2891: LAUNCH_KERNEL(2891); break;
	case 2892: LAUNCH_KERNEL(2892); break;
	case 2893: LAUNCH_KERNEL(2893); break;
	case 2894: LAUNCH_KERNEL(2894); break;
	case 2895: LAUNCH_KERNEL(2895); break;
	case 2896: LAUNCH_KERNEL(2896); break;
	case 2897: LAUNCH_KERNEL(2897); break;
	case 2898: LAUNCH_KERNEL(2898); break;
	case 2899: LAUNCH_KERNEL(2899); break;
	case 2900: LAUNCH_KERNEL(2900); break;
	case 2901: LAUNCH_KERNEL(2901); break;
	case 2902: LAUNCH_KERNEL(2902); break;
	case 2903: LAUNCH_KERNEL(2903); break;
	case 2904: LAUNCH_KERNEL(2904); break;
	case 2905: LAUNCH_KERNEL(2905); break;
	case 2906: LAUNCH_KERNEL(2906); break;
	case 2907: LAUNCH_KERNEL(2907); break;
	case 2908: LAUNCH_KERNEL(2908); break;
	case 2909: LAUNCH_KERNEL(2909); break;
	case 2910: LAUNCH_KERNEL(2910); break;
	case 2911: LAUNCH_KERNEL(2911); break;
	case 2912: LAUNCH_KERNEL(2912); break;
	case 2913: LAUNCH_KERNEL(2913); break;
	case 2914: LAUNCH_KERNEL(2914); break;
	case 2915: LAUNCH_KERNEL(2915); break;
	case 2916: LAUNCH_KERNEL(2916); break;
	case 2917: LAUNCH_KERNEL(2917); break;
	case 2918: LAUNCH_KERNEL(2918); break;
	case 2919: LAUNCH_KERNEL(2919); break;
	case 2920: LAUNCH_KERNEL(2920); break;
	case 2921: LAUNCH_KERNEL(2921); break;
	case 2922: LAUNCH_KERNEL(2922); break;
	case 2923: LAUNCH_KERNEL(2923); break;
	case 2924: LAUNCH_KERNEL(2924); break;
	case 2925: LAUNCH_KERNEL(2925); break;
	case 2926: LAUNCH_KERNEL(2926); break;
	case 2927: LAUNCH_KERNEL(2927); break;
	case 2928: LAUNCH_KERNEL(2928); break;
	case 2929: LAUNCH_KERNEL(2929); break;
	case 2930: LAUNCH_KERNEL(2930); break;
	case 2931: LAUNCH_KERNEL(2931); break;
	case 2932: LAUNCH_KERNEL(2932); break;
	case 2933: LAUNCH_KERNEL(2933); break;
	case 2934: LAUNCH_KERNEL(2934); break;
	case 2935: LAUNCH_KERNEL(2935); break;
	case 2936: LAUNCH_KERNEL(2936); break;
	case 2937: LAUNCH_KERNEL(2937); break;
	case 2938: LAUNCH_KERNEL(2938); break;
	case 2939: LAUNCH_KERNEL(2939); break;
	case 2940: LAUNCH_KERNEL(2940); break;
	case 2941: LAUNCH_KERNEL(2941); break;
	case 2942: LAUNCH_KERNEL(2942); break;
	case 2943: LAUNCH_KERNEL(2943); break;
	case 2944: LAUNCH_KERNEL(2944); break;
	case 2945: LAUNCH_KERNEL(2945); break;
	case 2946: LAUNCH_KERNEL(2946); break;
	case 2947: LAUNCH_KERNEL(2947); break;
	case 2948: LAUNCH_KERNEL(2948); break;
	case 2949: LAUNCH_KERNEL(2949); break;
	case 2950: LAUNCH_KERNEL(2950); break;
	case 2951: LAUNCH_KERNEL(2951); break;
	case 2952: LAUNCH_KERNEL(2952); break;
	case 2953: LAUNCH_KERNEL(2953); break;
	case 2954: LAUNCH_KERNEL(2954); break;
	case 2955: LAUNCH_KERNEL(2955); break;
	case 2956: LAUNCH_KERNEL(2956); break;
	case 2957: LAUNCH_KERNEL(2957); break;
	case 2958: LAUNCH_KERNEL(2958); break;
	case 2959: LAUNCH_KERNEL(2959); break;
	case 2960: LAUNCH_KERNEL(2960); break;
	case 2961: LAUNCH_KERNEL(2961); break;
	case 2962: LAUNCH_KERNEL(2962); break;
	case 2963: LAUNCH_KERNEL(2963); break;
	case 2964: LAUNCH_KERNEL(2964); break;
	case 2965: LAUNCH_KERNEL(2965); break;
	case 2966: LAUNCH_KERNEL(2966); break;
	case 2967: LAUNCH_KERNEL(2967); break;
	case 2968: LAUNCH_KERNEL(2968); break;
	case 2969: LAUNCH_KERNEL(2969); break;
	case 2970: LAUNCH_KERNEL(2970); break;
	case 2971: LAUNCH_KERNEL(2971); break;
	case 2972: LAUNCH_KERNEL(2972); break;
	case 2973: LAUNCH_KERNEL(2973); break;
	case 2974: LAUNCH_KERNEL(2974); break;
	case 2975: LAUNCH_KERNEL(2975); break;
	case 2976: LAUNCH_KERNEL(2976); break;
	case 2977: LAUNCH_KERNEL(2977); break;
	case 2978: LAUNCH_KERNEL(2978); break;
	case 2979: LAUNCH_KERNEL(2979); break;
	case 2980: LAUNCH_KERNEL(2980); break;
	case 2981: LAUNCH_KERNEL(2981); break;
	case 2982: LAUNCH_KERNEL(2982); break;
	case 2983: LAUNCH_KERNEL(2983); break;
	case 2984: LAUNCH_KERNEL(2984); break;
	case 2985: LAUNCH_KERNEL(2985); break;
	case 2986: LAUNCH_KERNEL(2986); break;
	case 2987: LAUNCH_KERNEL(2987); break;
	case 2988: LAUNCH_KERNEL(2988); break;
	case 2989: LAUNCH_KERNEL(2989); break;
	case 2990: LAUNCH_KERNEL(2990); break;
	case 2991: LAUNCH_KERNEL(2991); break;
	case 2992: LAUNCH_KERNEL(2992); break;
	case 2993: LAUNCH_KERNEL(2993); break;
	case 2994: LAUNCH_KERNEL(2994); break;
	case 2995: LAUNCH_KERNEL(2995); break;
	case 2996: LAUNCH_KERNEL(2996); break;
	case 2997: LAUNCH_KERNEL(2997); break;
	case 2998: LAUNCH_KERNEL(2998); break;
	case 2999: LAUNCH_KERNEL(2999); break;
	case 3000: LAUNCH_KERNEL(3000); break;
	case 3001: LAUNCH_KERNEL(3001); break;
	case 3002: LAUNCH_KERNEL(3002); break;
	case 3003: LAUNCH_KERNEL(3003); break;
	case 3004: LAUNCH_KERNEL(3004); break;
	case 3005: LAUNCH_KERNEL(3005); break;
	case 3006: LAUNCH_KERNEL(3006); break;
	case 3007: LAUNCH_KERNEL(3007); break;
	case 3008: LAUNCH_KERNEL(3008); break;
	case 3009: LAUNCH_KERNEL(3009); break;
	case 3010: LAUNCH_KERNEL(3010); break;
	case 3011: LAUNCH_KERNEL(3011); break;
	case 3012: LAUNCH_KERNEL(3012); break;
	case 3013: LAUNCH_KERNEL(3013); break;
	case 3014: LAUNCH_KERNEL(3014); break;
	case 3015: LAUNCH_KERNEL(3015); break;
	case 3016: LAUNCH_KERNEL(3016); break;
	case 3017: LAUNCH_KERNEL(3017); break;
	case 3018: LAUNCH_KERNEL(3018); break;
	case 3019: LAUNCH_KERNEL(3019); break;
	case 3020: LAUNCH_KERNEL(3020); break;
	case 3021: LAUNCH_KERNEL(3021); break;
	case 3022: LAUNCH_KERNEL(3022); break;
	case 3023: LAUNCH_KERNEL(3023); break;
	case 3024: LAUNCH_KERNEL(3024); break;
	case 3025: LAUNCH_KERNEL(3025); break;
	case 3026: LAUNCH_KERNEL(3026); break;
	case 3027: LAUNCH_KERNEL(3027); break;
	case 3028: LAUNCH_KERNEL(3028); break;
	case 3029: LAUNCH_KERNEL(3029); break;
	case 3030: LAUNCH_KERNEL(3030); break;
	case 3031: LAUNCH_KERNEL(3031); break;
	case 3032: LAUNCH_KERNEL(3032); break;
	case 3033: LAUNCH_KERNEL(3033); break;
	case 3034: LAUNCH_KERNEL(3034); break;
	case 3035: LAUNCH_KERNEL(3035); break;
	case 3036: LAUNCH_KERNEL(3036); break;
	case 3037: LAUNCH_KERNEL(3037); break;
	case 3038: LAUNCH_KERNEL(3038); break;
	case 3039: LAUNCH_KERNEL(3039); break;
	case 3040: LAUNCH_KERNEL(3040); break;
	case 3041: LAUNCH_KERNEL(3041); break;
	case 3042: LAUNCH_KERNEL(3042); break;
	case 3043: LAUNCH_KERNEL(3043); break;
	case 3044: LAUNCH_KERNEL(3044); break;
	case 3045: LAUNCH_KERNEL(3045); break;
	case 3046: LAUNCH_KERNEL(3046); break;
	case 3047: LAUNCH_KERNEL(3047); break;
	case 3048: LAUNCH_KERNEL(3048); break;
	case 3049: LAUNCH_KERNEL(3049); break;
	case 3050: LAUNCH_KERNEL(3050); break;
	case 3051: LAUNCH_KERNEL(3051); break;
	case 3052: LAUNCH_KERNEL(3052); break;
	case 3053: LAUNCH_KERNEL(3053); break;
	case 3054: LAUNCH_KERNEL(3054); break;
	case 3055: LAUNCH_KERNEL(3055); break;
	case 3056: LAUNCH_KERNEL(3056); break;
	case 3057: LAUNCH_KERNEL(3057); break;
	case 3058: LAUNCH_KERNEL(3058); break;
	case 3059: LAUNCH_KERNEL(3059); break;
	case 3060: LAUNCH_KERNEL(3060); break;
	case 3061: LAUNCH_KERNEL(3061); break;
	case 3062: LAUNCH_KERNEL(3062); break;
	case 3063: LAUNCH_KERNEL(3063); break;
	case 3064: LAUNCH_KERNEL(3064); break;
	case 3065: LAUNCH_KERNEL(3065); break;
	case 3066: LAUNCH_KERNEL(3066); break;
	case 3067: LAUNCH_KERNEL(3067); break;
	case 3068: LAUNCH_KERNEL(3068); break;
	case 3069: LAUNCH_KERNEL(3069); break;
	case 3070: LAUNCH_KERNEL(3070); break;
	case 3071: LAUNCH_KERNEL(3071); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
