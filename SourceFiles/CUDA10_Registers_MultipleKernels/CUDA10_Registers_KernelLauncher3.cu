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

#define SALT 768
#include "../CUDA10_Registers_Kernel.h"
#define SALT 769
#include "../CUDA10_Registers_Kernel.h"
#define SALT 770
#include "../CUDA10_Registers_Kernel.h"
#define SALT 771
#include "../CUDA10_Registers_Kernel.h"
#define SALT 772
#include "../CUDA10_Registers_Kernel.h"
#define SALT 773
#include "../CUDA10_Registers_Kernel.h"
#define SALT 774
#include "../CUDA10_Registers_Kernel.h"
#define SALT 775
#include "../CUDA10_Registers_Kernel.h"
#define SALT 776
#include "../CUDA10_Registers_Kernel.h"
#define SALT 777
#include "../CUDA10_Registers_Kernel.h"
#define SALT 778
#include "../CUDA10_Registers_Kernel.h"
#define SALT 779
#include "../CUDA10_Registers_Kernel.h"
#define SALT 780
#include "../CUDA10_Registers_Kernel.h"
#define SALT 781
#include "../CUDA10_Registers_Kernel.h"
#define SALT 782
#include "../CUDA10_Registers_Kernel.h"
#define SALT 783
#include "../CUDA10_Registers_Kernel.h"
#define SALT 784
#include "../CUDA10_Registers_Kernel.h"
#define SALT 785
#include "../CUDA10_Registers_Kernel.h"
#define SALT 786
#include "../CUDA10_Registers_Kernel.h"
#define SALT 787
#include "../CUDA10_Registers_Kernel.h"
#define SALT 788
#include "../CUDA10_Registers_Kernel.h"
#define SALT 789
#include "../CUDA10_Registers_Kernel.h"
#define SALT 790
#include "../CUDA10_Registers_Kernel.h"
#define SALT 791
#include "../CUDA10_Registers_Kernel.h"
#define SALT 792
#include "../CUDA10_Registers_Kernel.h"
#define SALT 793
#include "../CUDA10_Registers_Kernel.h"
#define SALT 794
#include "../CUDA10_Registers_Kernel.h"
#define SALT 795
#include "../CUDA10_Registers_Kernel.h"
#define SALT 796
#include "../CUDA10_Registers_Kernel.h"
#define SALT 797
#include "../CUDA10_Registers_Kernel.h"
#define SALT 798
#include "../CUDA10_Registers_Kernel.h"
#define SALT 799
#include "../CUDA10_Registers_Kernel.h"
#define SALT 800
#include "../CUDA10_Registers_Kernel.h"
#define SALT 801
#include "../CUDA10_Registers_Kernel.h"
#define SALT 802
#include "../CUDA10_Registers_Kernel.h"
#define SALT 803
#include "../CUDA10_Registers_Kernel.h"
#define SALT 804
#include "../CUDA10_Registers_Kernel.h"
#define SALT 805
#include "../CUDA10_Registers_Kernel.h"
#define SALT 806
#include "../CUDA10_Registers_Kernel.h"
#define SALT 807
#include "../CUDA10_Registers_Kernel.h"
#define SALT 808
#include "../CUDA10_Registers_Kernel.h"
#define SALT 809
#include "../CUDA10_Registers_Kernel.h"
#define SALT 810
#include "../CUDA10_Registers_Kernel.h"
#define SALT 811
#include "../CUDA10_Registers_Kernel.h"
#define SALT 812
#include "../CUDA10_Registers_Kernel.h"
#define SALT 813
#include "../CUDA10_Registers_Kernel.h"
#define SALT 814
#include "../CUDA10_Registers_Kernel.h"
#define SALT 815
#include "../CUDA10_Registers_Kernel.h"
#define SALT 816
#include "../CUDA10_Registers_Kernel.h"
#define SALT 817
#include "../CUDA10_Registers_Kernel.h"
#define SALT 818
#include "../CUDA10_Registers_Kernel.h"
#define SALT 819
#include "../CUDA10_Registers_Kernel.h"
#define SALT 820
#include "../CUDA10_Registers_Kernel.h"
#define SALT 821
#include "../CUDA10_Registers_Kernel.h"
#define SALT 822
#include "../CUDA10_Registers_Kernel.h"
#define SALT 823
#include "../CUDA10_Registers_Kernel.h"
#define SALT 824
#include "../CUDA10_Registers_Kernel.h"
#define SALT 825
#include "../CUDA10_Registers_Kernel.h"
#define SALT 826
#include "../CUDA10_Registers_Kernel.h"
#define SALT 827
#include "../CUDA10_Registers_Kernel.h"
#define SALT 828
#include "../CUDA10_Registers_Kernel.h"
#define SALT 829
#include "../CUDA10_Registers_Kernel.h"
#define SALT 830
#include "../CUDA10_Registers_Kernel.h"
#define SALT 831
#include "../CUDA10_Registers_Kernel.h"
#define SALT 832
#include "../CUDA10_Registers_Kernel.h"
#define SALT 833
#include "../CUDA10_Registers_Kernel.h"
#define SALT 834
#include "../CUDA10_Registers_Kernel.h"
#define SALT 835
#include "../CUDA10_Registers_Kernel.h"
#define SALT 836
#include "../CUDA10_Registers_Kernel.h"
#define SALT 837
#include "../CUDA10_Registers_Kernel.h"
#define SALT 838
#include "../CUDA10_Registers_Kernel.h"
#define SALT 839
#include "../CUDA10_Registers_Kernel.h"
#define SALT 840
#include "../CUDA10_Registers_Kernel.h"
#define SALT 841
#include "../CUDA10_Registers_Kernel.h"
#define SALT 842
#include "../CUDA10_Registers_Kernel.h"
#define SALT 843
#include "../CUDA10_Registers_Kernel.h"
#define SALT 844
#include "../CUDA10_Registers_Kernel.h"
#define SALT 845
#include "../CUDA10_Registers_Kernel.h"
#define SALT 846
#include "../CUDA10_Registers_Kernel.h"
#define SALT 847
#include "../CUDA10_Registers_Kernel.h"
#define SALT 848
#include "../CUDA10_Registers_Kernel.h"
#define SALT 849
#include "../CUDA10_Registers_Kernel.h"
#define SALT 850
#include "../CUDA10_Registers_Kernel.h"
#define SALT 851
#include "../CUDA10_Registers_Kernel.h"
#define SALT 852
#include "../CUDA10_Registers_Kernel.h"
#define SALT 853
#include "../CUDA10_Registers_Kernel.h"
#define SALT 854
#include "../CUDA10_Registers_Kernel.h"
#define SALT 855
#include "../CUDA10_Registers_Kernel.h"
#define SALT 856
#include "../CUDA10_Registers_Kernel.h"
#define SALT 857
#include "../CUDA10_Registers_Kernel.h"
#define SALT 858
#include "../CUDA10_Registers_Kernel.h"
#define SALT 859
#include "../CUDA10_Registers_Kernel.h"
#define SALT 860
#include "../CUDA10_Registers_Kernel.h"
#define SALT 861
#include "../CUDA10_Registers_Kernel.h"
#define SALT 862
#include "../CUDA10_Registers_Kernel.h"
#define SALT 863
#include "../CUDA10_Registers_Kernel.h"
#define SALT 864
#include "../CUDA10_Registers_Kernel.h"
#define SALT 865
#include "../CUDA10_Registers_Kernel.h"
#define SALT 866
#include "../CUDA10_Registers_Kernel.h"
#define SALT 867
#include "../CUDA10_Registers_Kernel.h"
#define SALT 868
#include "../CUDA10_Registers_Kernel.h"
#define SALT 869
#include "../CUDA10_Registers_Kernel.h"
#define SALT 870
#include "../CUDA10_Registers_Kernel.h"
#define SALT 871
#include "../CUDA10_Registers_Kernel.h"
#define SALT 872
#include "../CUDA10_Registers_Kernel.h"
#define SALT 873
#include "../CUDA10_Registers_Kernel.h"
#define SALT 874
#include "../CUDA10_Registers_Kernel.h"
#define SALT 875
#include "../CUDA10_Registers_Kernel.h"
#define SALT 876
#include "../CUDA10_Registers_Kernel.h"
#define SALT 877
#include "../CUDA10_Registers_Kernel.h"
#define SALT 878
#include "../CUDA10_Registers_Kernel.h"
#define SALT 879
#include "../CUDA10_Registers_Kernel.h"
#define SALT 880
#include "../CUDA10_Registers_Kernel.h"
#define SALT 881
#include "../CUDA10_Registers_Kernel.h"
#define SALT 882
#include "../CUDA10_Registers_Kernel.h"
#define SALT 883
#include "../CUDA10_Registers_Kernel.h"
#define SALT 884
#include "../CUDA10_Registers_Kernel.h"
#define SALT 885
#include "../CUDA10_Registers_Kernel.h"
#define SALT 886
#include "../CUDA10_Registers_Kernel.h"
#define SALT 887
#include "../CUDA10_Registers_Kernel.h"
#define SALT 888
#include "../CUDA10_Registers_Kernel.h"
#define SALT 889
#include "../CUDA10_Registers_Kernel.h"
#define SALT 890
#include "../CUDA10_Registers_Kernel.h"
#define SALT 891
#include "../CUDA10_Registers_Kernel.h"
#define SALT 892
#include "../CUDA10_Registers_Kernel.h"
#define SALT 893
#include "../CUDA10_Registers_Kernel.h"
#define SALT 894
#include "../CUDA10_Registers_Kernel.h"
#define SALT 895
#include "../CUDA10_Registers_Kernel.h"
#define SALT 896
#include "../CUDA10_Registers_Kernel.h"
#define SALT 897
#include "../CUDA10_Registers_Kernel.h"
#define SALT 898
#include "../CUDA10_Registers_Kernel.h"
#define SALT 899
#include "../CUDA10_Registers_Kernel.h"
#define SALT 900
#include "../CUDA10_Registers_Kernel.h"
#define SALT 901
#include "../CUDA10_Registers_Kernel.h"
#define SALT 902
#include "../CUDA10_Registers_Kernel.h"
#define SALT 903
#include "../CUDA10_Registers_Kernel.h"
#define SALT 904
#include "../CUDA10_Registers_Kernel.h"
#define SALT 905
#include "../CUDA10_Registers_Kernel.h"
#define SALT 906
#include "../CUDA10_Registers_Kernel.h"
#define SALT 907
#include "../CUDA10_Registers_Kernel.h"
#define SALT 908
#include "../CUDA10_Registers_Kernel.h"
#define SALT 909
#include "../CUDA10_Registers_Kernel.h"
#define SALT 910
#include "../CUDA10_Registers_Kernel.h"
#define SALT 911
#include "../CUDA10_Registers_Kernel.h"
#define SALT 912
#include "../CUDA10_Registers_Kernel.h"
#define SALT 913
#include "../CUDA10_Registers_Kernel.h"
#define SALT 914
#include "../CUDA10_Registers_Kernel.h"
#define SALT 915
#include "../CUDA10_Registers_Kernel.h"
#define SALT 916
#include "../CUDA10_Registers_Kernel.h"
#define SALT 917
#include "../CUDA10_Registers_Kernel.h"
#define SALT 918
#include "../CUDA10_Registers_Kernel.h"
#define SALT 919
#include "../CUDA10_Registers_Kernel.h"
#define SALT 920
#include "../CUDA10_Registers_Kernel.h"
#define SALT 921
#include "../CUDA10_Registers_Kernel.h"
#define SALT 922
#include "../CUDA10_Registers_Kernel.h"
#define SALT 923
#include "../CUDA10_Registers_Kernel.h"
#define SALT 924
#include "../CUDA10_Registers_Kernel.h"
#define SALT 925
#include "../CUDA10_Registers_Kernel.h"
#define SALT 926
#include "../CUDA10_Registers_Kernel.h"
#define SALT 927
#include "../CUDA10_Registers_Kernel.h"
#define SALT 928
#include "../CUDA10_Registers_Kernel.h"
#define SALT 929
#include "../CUDA10_Registers_Kernel.h"
#define SALT 930
#include "../CUDA10_Registers_Kernel.h"
#define SALT 931
#include "../CUDA10_Registers_Kernel.h"
#define SALT 932
#include "../CUDA10_Registers_Kernel.h"
#define SALT 933
#include "../CUDA10_Registers_Kernel.h"
#define SALT 934
#include "../CUDA10_Registers_Kernel.h"
#define SALT 935
#include "../CUDA10_Registers_Kernel.h"
#define SALT 936
#include "../CUDA10_Registers_Kernel.h"
#define SALT 937
#include "../CUDA10_Registers_Kernel.h"
#define SALT 938
#include "../CUDA10_Registers_Kernel.h"
#define SALT 939
#include "../CUDA10_Registers_Kernel.h"
#define SALT 940
#include "../CUDA10_Registers_Kernel.h"
#define SALT 941
#include "../CUDA10_Registers_Kernel.h"
#define SALT 942
#include "../CUDA10_Registers_Kernel.h"
#define SALT 943
#include "../CUDA10_Registers_Kernel.h"
#define SALT 944
#include "../CUDA10_Registers_Kernel.h"
#define SALT 945
#include "../CUDA10_Registers_Kernel.h"
#define SALT 946
#include "../CUDA10_Registers_Kernel.h"
#define SALT 947
#include "../CUDA10_Registers_Kernel.h"
#define SALT 948
#include "../CUDA10_Registers_Kernel.h"
#define SALT 949
#include "../CUDA10_Registers_Kernel.h"
#define SALT 950
#include "../CUDA10_Registers_Kernel.h"
#define SALT 951
#include "../CUDA10_Registers_Kernel.h"
#define SALT 952
#include "../CUDA10_Registers_Kernel.h"
#define SALT 953
#include "../CUDA10_Registers_Kernel.h"
#define SALT 954
#include "../CUDA10_Registers_Kernel.h"
#define SALT 955
#include "../CUDA10_Registers_Kernel.h"
#define SALT 956
#include "../CUDA10_Registers_Kernel.h"
#define SALT 957
#include "../CUDA10_Registers_Kernel.h"
#define SALT 958
#include "../CUDA10_Registers_Kernel.h"
#define SALT 959
#include "../CUDA10_Registers_Kernel.h"
#define SALT 960
#include "../CUDA10_Registers_Kernel.h"
#define SALT 961
#include "../CUDA10_Registers_Kernel.h"
#define SALT 962
#include "../CUDA10_Registers_Kernel.h"
#define SALT 963
#include "../CUDA10_Registers_Kernel.h"
#define SALT 964
#include "../CUDA10_Registers_Kernel.h"
#define SALT 965
#include "../CUDA10_Registers_Kernel.h"
#define SALT 966
#include "../CUDA10_Registers_Kernel.h"
#define SALT 967
#include "../CUDA10_Registers_Kernel.h"
#define SALT 968
#include "../CUDA10_Registers_Kernel.h"
#define SALT 969
#include "../CUDA10_Registers_Kernel.h"
#define SALT 970
#include "../CUDA10_Registers_Kernel.h"
#define SALT 971
#include "../CUDA10_Registers_Kernel.h"
#define SALT 972
#include "../CUDA10_Registers_Kernel.h"
#define SALT 973
#include "../CUDA10_Registers_Kernel.h"
#define SALT 974
#include "../CUDA10_Registers_Kernel.h"
#define SALT 975
#include "../CUDA10_Registers_Kernel.h"
#define SALT 976
#include "../CUDA10_Registers_Kernel.h"
#define SALT 977
#include "../CUDA10_Registers_Kernel.h"
#define SALT 978
#include "../CUDA10_Registers_Kernel.h"
#define SALT 979
#include "../CUDA10_Registers_Kernel.h"
#define SALT 980
#include "../CUDA10_Registers_Kernel.h"
#define SALT 981
#include "../CUDA10_Registers_Kernel.h"
#define SALT 982
#include "../CUDA10_Registers_Kernel.h"
#define SALT 983
#include "../CUDA10_Registers_Kernel.h"
#define SALT 984
#include "../CUDA10_Registers_Kernel.h"
#define SALT 985
#include "../CUDA10_Registers_Kernel.h"
#define SALT 986
#include "../CUDA10_Registers_Kernel.h"
#define SALT 987
#include "../CUDA10_Registers_Kernel.h"
#define SALT 988
#include "../CUDA10_Registers_Kernel.h"
#define SALT 989
#include "../CUDA10_Registers_Kernel.h"
#define SALT 990
#include "../CUDA10_Registers_Kernel.h"
#define SALT 991
#include "../CUDA10_Registers_Kernel.h"
#define SALT 992
#include "../CUDA10_Registers_Kernel.h"
#define SALT 993
#include "../CUDA10_Registers_Kernel.h"
#define SALT 994
#include "../CUDA10_Registers_Kernel.h"
#define SALT 995
#include "../CUDA10_Registers_Kernel.h"
#define SALT 996
#include "../CUDA10_Registers_Kernel.h"
#define SALT 997
#include "../CUDA10_Registers_Kernel.h"
#define SALT 998
#include "../CUDA10_Registers_Kernel.h"
#define SALT 999
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1000
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1001
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1002
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1003
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1004
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1005
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1006
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1007
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1008
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1009
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1010
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1011
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1012
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1013
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1014
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1015
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1016
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1017
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1018
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1019
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1020
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1021
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1022
#include "../CUDA10_Registers_Kernel.h"
#define SALT 1023
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher3()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel3(
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
		case 768: LAUNCH_KERNEL(768); break;
		case 769: LAUNCH_KERNEL(769); break;
		case 770: LAUNCH_KERNEL(770); break;
		case 771: LAUNCH_KERNEL(771); break;
		case 772: LAUNCH_KERNEL(772); break;
		case 773: LAUNCH_KERNEL(773); break;
		case 774: LAUNCH_KERNEL(774); break;
		case 775: LAUNCH_KERNEL(775); break;
		case 776: LAUNCH_KERNEL(776); break;
		case 777: LAUNCH_KERNEL(777); break;
		case 778: LAUNCH_KERNEL(778); break;
		case 779: LAUNCH_KERNEL(779); break;
		case 780: LAUNCH_KERNEL(780); break;
		case 781: LAUNCH_KERNEL(781); break;
		case 782: LAUNCH_KERNEL(782); break;
		case 783: LAUNCH_KERNEL(783); break;
		case 784: LAUNCH_KERNEL(784); break;
		case 785: LAUNCH_KERNEL(785); break;
		case 786: LAUNCH_KERNEL(786); break;
		case 787: LAUNCH_KERNEL(787); break;
		case 788: LAUNCH_KERNEL(788); break;
		case 789: LAUNCH_KERNEL(789); break;
		case 790: LAUNCH_KERNEL(790); break;
		case 791: LAUNCH_KERNEL(791); break;
		case 792: LAUNCH_KERNEL(792); break;
		case 793: LAUNCH_KERNEL(793); break;
		case 794: LAUNCH_KERNEL(794); break;
		case 795: LAUNCH_KERNEL(795); break;
		case 796: LAUNCH_KERNEL(796); break;
		case 797: LAUNCH_KERNEL(797); break;
		case 798: LAUNCH_KERNEL(798); break;
		case 799: LAUNCH_KERNEL(799); break;
		case 800: LAUNCH_KERNEL(800); break;
		case 801: LAUNCH_KERNEL(801); break;
		case 802: LAUNCH_KERNEL(802); break;
		case 803: LAUNCH_KERNEL(803); break;
		case 804: LAUNCH_KERNEL(804); break;
		case 805: LAUNCH_KERNEL(805); break;
		case 806: LAUNCH_KERNEL(806); break;
		case 807: LAUNCH_KERNEL(807); break;
		case 808: LAUNCH_KERNEL(808); break;
		case 809: LAUNCH_KERNEL(809); break;
		case 810: LAUNCH_KERNEL(810); break;
		case 811: LAUNCH_KERNEL(811); break;
		case 812: LAUNCH_KERNEL(812); break;
		case 813: LAUNCH_KERNEL(813); break;
		case 814: LAUNCH_KERNEL(814); break;
		case 815: LAUNCH_KERNEL(815); break;
		case 816: LAUNCH_KERNEL(816); break;
		case 817: LAUNCH_KERNEL(817); break;
		case 818: LAUNCH_KERNEL(818); break;
		case 819: LAUNCH_KERNEL(819); break;
		case 820: LAUNCH_KERNEL(820); break;
		case 821: LAUNCH_KERNEL(821); break;
		case 822: LAUNCH_KERNEL(822); break;
		case 823: LAUNCH_KERNEL(823); break;
		case 824: LAUNCH_KERNEL(824); break;
		case 825: LAUNCH_KERNEL(825); break;
		case 826: LAUNCH_KERNEL(826); break;
		case 827: LAUNCH_KERNEL(827); break;
		case 828: LAUNCH_KERNEL(828); break;
		case 829: LAUNCH_KERNEL(829); break;
		case 830: LAUNCH_KERNEL(830); break;
		case 831: LAUNCH_KERNEL(831); break;
		case 832: LAUNCH_KERNEL(832); break;
		case 833: LAUNCH_KERNEL(833); break;
		case 834: LAUNCH_KERNEL(834); break;
		case 835: LAUNCH_KERNEL(835); break;
		case 836: LAUNCH_KERNEL(836); break;
		case 837: LAUNCH_KERNEL(837); break;
		case 838: LAUNCH_KERNEL(838); break;
		case 839: LAUNCH_KERNEL(839); break;
		case 840: LAUNCH_KERNEL(840); break;
		case 841: LAUNCH_KERNEL(841); break;
		case 842: LAUNCH_KERNEL(842); break;
		case 843: LAUNCH_KERNEL(843); break;
		case 844: LAUNCH_KERNEL(844); break;
		case 845: LAUNCH_KERNEL(845); break;
		case 846: LAUNCH_KERNEL(846); break;
		case 847: LAUNCH_KERNEL(847); break;
		case 848: LAUNCH_KERNEL(848); break;
		case 849: LAUNCH_KERNEL(849); break;
		case 850: LAUNCH_KERNEL(850); break;
		case 851: LAUNCH_KERNEL(851); break;
		case 852: LAUNCH_KERNEL(852); break;
		case 853: LAUNCH_KERNEL(853); break;
		case 854: LAUNCH_KERNEL(854); break;
		case 855: LAUNCH_KERNEL(855); break;
		case 856: LAUNCH_KERNEL(856); break;
		case 857: LAUNCH_KERNEL(857); break;
		case 858: LAUNCH_KERNEL(858); break;
		case 859: LAUNCH_KERNEL(859); break;
		case 860: LAUNCH_KERNEL(860); break;
		case 861: LAUNCH_KERNEL(861); break;
		case 862: LAUNCH_KERNEL(862); break;
		case 863: LAUNCH_KERNEL(863); break;
		case 864: LAUNCH_KERNEL(864); break;
		case 865: LAUNCH_KERNEL(865); break;
		case 866: LAUNCH_KERNEL(866); break;
		case 867: LAUNCH_KERNEL(867); break;
		case 868: LAUNCH_KERNEL(868); break;
		case 869: LAUNCH_KERNEL(869); break;
		case 870: LAUNCH_KERNEL(870); break;
		case 871: LAUNCH_KERNEL(871); break;
		case 872: LAUNCH_KERNEL(872); break;
		case 873: LAUNCH_KERNEL(873); break;
		case 874: LAUNCH_KERNEL(874); break;
		case 875: LAUNCH_KERNEL(875); break;
		case 876: LAUNCH_KERNEL(876); break;
		case 877: LAUNCH_KERNEL(877); break;
		case 878: LAUNCH_KERNEL(878); break;
		case 879: LAUNCH_KERNEL(879); break;
		case 880: LAUNCH_KERNEL(880); break;
		case 881: LAUNCH_KERNEL(881); break;
		case 882: LAUNCH_KERNEL(882); break;
		case 883: LAUNCH_KERNEL(883); break;
		case 884: LAUNCH_KERNEL(884); break;
		case 885: LAUNCH_KERNEL(885); break;
		case 886: LAUNCH_KERNEL(886); break;
		case 887: LAUNCH_KERNEL(887); break;
		case 888: LAUNCH_KERNEL(888); break;
		case 889: LAUNCH_KERNEL(889); break;
		case 890: LAUNCH_KERNEL(890); break;
		case 891: LAUNCH_KERNEL(891); break;
		case 892: LAUNCH_KERNEL(892); break;
		case 893: LAUNCH_KERNEL(893); break;
		case 894: LAUNCH_KERNEL(894); break;
		case 895: LAUNCH_KERNEL(895); break;
		case 896: LAUNCH_KERNEL(896); break;
		case 897: LAUNCH_KERNEL(897); break;
		case 898: LAUNCH_KERNEL(898); break;
		case 899: LAUNCH_KERNEL(899); break;
		case 900: LAUNCH_KERNEL(900); break;
		case 901: LAUNCH_KERNEL(901); break;
		case 902: LAUNCH_KERNEL(902); break;
		case 903: LAUNCH_KERNEL(903); break;
		case 904: LAUNCH_KERNEL(904); break;
		case 905: LAUNCH_KERNEL(905); break;
		case 906: LAUNCH_KERNEL(906); break;
		case 907: LAUNCH_KERNEL(907); break;
		case 908: LAUNCH_KERNEL(908); break;
		case 909: LAUNCH_KERNEL(909); break;
		case 910: LAUNCH_KERNEL(910); break;
		case 911: LAUNCH_KERNEL(911); break;
		case 912: LAUNCH_KERNEL(912); break;
		case 913: LAUNCH_KERNEL(913); break;
		case 914: LAUNCH_KERNEL(914); break;
		case 915: LAUNCH_KERNEL(915); break;
		case 916: LAUNCH_KERNEL(916); break;
		case 917: LAUNCH_KERNEL(917); break;
		case 918: LAUNCH_KERNEL(918); break;
		case 919: LAUNCH_KERNEL(919); break;
		case 920: LAUNCH_KERNEL(920); break;
		case 921: LAUNCH_KERNEL(921); break;
		case 922: LAUNCH_KERNEL(922); break;
		case 923: LAUNCH_KERNEL(923); break;
		case 924: LAUNCH_KERNEL(924); break;
		case 925: LAUNCH_KERNEL(925); break;
		case 926: LAUNCH_KERNEL(926); break;
		case 927: LAUNCH_KERNEL(927); break;
		case 928: LAUNCH_KERNEL(928); break;
		case 929: LAUNCH_KERNEL(929); break;
		case 930: LAUNCH_KERNEL(930); break;
		case 931: LAUNCH_KERNEL(931); break;
		case 932: LAUNCH_KERNEL(932); break;
		case 933: LAUNCH_KERNEL(933); break;
		case 934: LAUNCH_KERNEL(934); break;
		case 935: LAUNCH_KERNEL(935); break;
		case 936: LAUNCH_KERNEL(936); break;
		case 937: LAUNCH_KERNEL(937); break;
		case 938: LAUNCH_KERNEL(938); break;
		case 939: LAUNCH_KERNEL(939); break;
		case 940: LAUNCH_KERNEL(940); break;
		case 941: LAUNCH_KERNEL(941); break;
		case 942: LAUNCH_KERNEL(942); break;
		case 943: LAUNCH_KERNEL(943); break;
		case 944: LAUNCH_KERNEL(944); break;
		case 945: LAUNCH_KERNEL(945); break;
		case 946: LAUNCH_KERNEL(946); break;
		case 947: LAUNCH_KERNEL(947); break;
		case 948: LAUNCH_KERNEL(948); break;
		case 949: LAUNCH_KERNEL(949); break;
		case 950: LAUNCH_KERNEL(950); break;
		case 951: LAUNCH_KERNEL(951); break;
		case 952: LAUNCH_KERNEL(952); break;
		case 953: LAUNCH_KERNEL(953); break;
		case 954: LAUNCH_KERNEL(954); break;
		case 955: LAUNCH_KERNEL(955); break;
		case 956: LAUNCH_KERNEL(956); break;
		case 957: LAUNCH_KERNEL(957); break;
		case 958: LAUNCH_KERNEL(958); break;
		case 959: LAUNCH_KERNEL(959); break;
		case 960: LAUNCH_KERNEL(960); break;
		case 961: LAUNCH_KERNEL(961); break;
		case 962: LAUNCH_KERNEL(962); break;
		case 963: LAUNCH_KERNEL(963); break;
		case 964: LAUNCH_KERNEL(964); break;
		case 965: LAUNCH_KERNEL(965); break;
		case 966: LAUNCH_KERNEL(966); break;
		case 967: LAUNCH_KERNEL(967); break;
		case 968: LAUNCH_KERNEL(968); break;
		case 969: LAUNCH_KERNEL(969); break;
		case 970: LAUNCH_KERNEL(970); break;
		case 971: LAUNCH_KERNEL(971); break;
		case 972: LAUNCH_KERNEL(972); break;
		case 973: LAUNCH_KERNEL(973); break;
		case 974: LAUNCH_KERNEL(974); break;
		case 975: LAUNCH_KERNEL(975); break;
		case 976: LAUNCH_KERNEL(976); break;
		case 977: LAUNCH_KERNEL(977); break;
		case 978: LAUNCH_KERNEL(978); break;
		case 979: LAUNCH_KERNEL(979); break;
		case 980: LAUNCH_KERNEL(980); break;
		case 981: LAUNCH_KERNEL(981); break;
		case 982: LAUNCH_KERNEL(982); break;
		case 983: LAUNCH_KERNEL(983); break;
		case 984: LAUNCH_KERNEL(984); break;
		case 985: LAUNCH_KERNEL(985); break;
		case 986: LAUNCH_KERNEL(986); break;
		case 987: LAUNCH_KERNEL(987); break;
		case 988: LAUNCH_KERNEL(988); break;
		case 989: LAUNCH_KERNEL(989); break;
		case 990: LAUNCH_KERNEL(990); break;
		case 991: LAUNCH_KERNEL(991); break;
		case 992: LAUNCH_KERNEL(992); break;
		case 993: LAUNCH_KERNEL(993); break;
		case 994: LAUNCH_KERNEL(994); break;
		case 995: LAUNCH_KERNEL(995); break;
		case 996: LAUNCH_KERNEL(996); break;
		case 997: LAUNCH_KERNEL(997); break;
		case 998: LAUNCH_KERNEL(998); break;
		case 999: LAUNCH_KERNEL(999); break;
		case 1000: LAUNCH_KERNEL(1000); break;
		case 1001: LAUNCH_KERNEL(1001); break;
		case 1002: LAUNCH_KERNEL(1002); break;
		case 1003: LAUNCH_KERNEL(1003); break;
		case 1004: LAUNCH_KERNEL(1004); break;
		case 1005: LAUNCH_KERNEL(1005); break;
		case 1006: LAUNCH_KERNEL(1006); break;
		case 1007: LAUNCH_KERNEL(1007); break;
		case 1008: LAUNCH_KERNEL(1008); break;
		case 1009: LAUNCH_KERNEL(1009); break;
		case 1010: LAUNCH_KERNEL(1010); break;
		case 1011: LAUNCH_KERNEL(1011); break;
		case 1012: LAUNCH_KERNEL(1012); break;
		case 1013: LAUNCH_KERNEL(1013); break;
		case 1014: LAUNCH_KERNEL(1014); break;
		case 1015: LAUNCH_KERNEL(1015); break;
		case 1016: LAUNCH_KERNEL(1016); break;
		case 1017: LAUNCH_KERNEL(1017); break;
		case 1018: LAUNCH_KERNEL(1018); break;
		case 1019: LAUNCH_KERNEL(1019); break;
		case 1020: LAUNCH_KERNEL(1020); break;
		case 1021: LAUNCH_KERNEL(1021); break;
		case 1022: LAUNCH_KERNEL(1022); break;
		case 1023: LAUNCH_KERNEL(1023); break;
		default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
