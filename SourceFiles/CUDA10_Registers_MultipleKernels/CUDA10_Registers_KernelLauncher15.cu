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

#define SALT 3840
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3841
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3842
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3843
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3844
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3845
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3846
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3847
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3848
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3849
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3850
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3851
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3852
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3853
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3854
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3855
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3856
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3857
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3858
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3859
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3860
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3861
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3862
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3863
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3864
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3865
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3866
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3867
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3868
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3869
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3870
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3871
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3872
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3873
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3874
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3875
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3876
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3877
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3878
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3879
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3880
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3881
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3882
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3883
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3884
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3885
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3886
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3887
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3888
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3889
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3890
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3891
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3892
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3893
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3894
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3895
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3896
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3897
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3898
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3899
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3900
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3901
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3902
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3903
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3904
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3905
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3906
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3907
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3908
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3909
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3910
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3911
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3912
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3913
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3914
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3915
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3916
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3917
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3918
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3919
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3920
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3921
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3922
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3923
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3924
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3925
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3926
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3927
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3928
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3929
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3930
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3931
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3932
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3933
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3934
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3935
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3936
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3937
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3938
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3939
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3940
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3941
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3942
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3943
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3944
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3945
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3946
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3947
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3948
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3949
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3950
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3951
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3952
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3953
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3954
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3955
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3956
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3957
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3958
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3959
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3960
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3961
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3962
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3963
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3964
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3965
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3966
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3967
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3968
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3969
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3970
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3971
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3972
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3973
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3974
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3975
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3976
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3977
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3978
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3979
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3980
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3981
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3982
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3983
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3984
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3985
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3986
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3987
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3988
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3989
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3990
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3991
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3992
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3993
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3994
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3995
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3996
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3997
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3998
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3999
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4000
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4001
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4002
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4003
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4004
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4005
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4006
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4007
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4008
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4009
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4010
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4011
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4012
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4013
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4014
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4015
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4016
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4017
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4018
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4019
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4020
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4021
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4022
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4023
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4024
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4025
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4026
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4027
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4028
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4029
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4030
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4031
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4032
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4033
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4034
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4035
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4036
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4037
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4038
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4039
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4040
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4041
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4042
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4043
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4044
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4045
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4046
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4047
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4048
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4049
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4050
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4051
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4052
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4053
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4054
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4055
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4056
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4057
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4058
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4059
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4060
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4061
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4062
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4063
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4064
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4065
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4066
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4067
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4068
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4069
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4070
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4071
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4072
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4073
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4074
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4075
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4076
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4077
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4078
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4079
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4080
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4081
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4082
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4083
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4084
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4085
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4086
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4087
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4088
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4089
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4090
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4091
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4092
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4093
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4094
#include "../CUDA10_Registers_Kernel.h"
#define SALT 4095
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher15()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel15(
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
	case 3840: LAUNCH_KERNEL(3840); break;
	case 3841: LAUNCH_KERNEL(3841); break;
	case 3842: LAUNCH_KERNEL(3842); break;
	case 3843: LAUNCH_KERNEL(3843); break;
	case 3844: LAUNCH_KERNEL(3844); break;
	case 3845: LAUNCH_KERNEL(3845); break;
	case 3846: LAUNCH_KERNEL(3846); break;
	case 3847: LAUNCH_KERNEL(3847); break;
	case 3848: LAUNCH_KERNEL(3848); break;
	case 3849: LAUNCH_KERNEL(3849); break;
	case 3850: LAUNCH_KERNEL(3850); break;
	case 3851: LAUNCH_KERNEL(3851); break;
	case 3852: LAUNCH_KERNEL(3852); break;
	case 3853: LAUNCH_KERNEL(3853); break;
	case 3854: LAUNCH_KERNEL(3854); break;
	case 3855: LAUNCH_KERNEL(3855); break;
	case 3856: LAUNCH_KERNEL(3856); break;
	case 3857: LAUNCH_KERNEL(3857); break;
	case 3858: LAUNCH_KERNEL(3858); break;
	case 3859: LAUNCH_KERNEL(3859); break;
	case 3860: LAUNCH_KERNEL(3860); break;
	case 3861: LAUNCH_KERNEL(3861); break;
	case 3862: LAUNCH_KERNEL(3862); break;
	case 3863: LAUNCH_KERNEL(3863); break;
	case 3864: LAUNCH_KERNEL(3864); break;
	case 3865: LAUNCH_KERNEL(3865); break;
	case 3866: LAUNCH_KERNEL(3866); break;
	case 3867: LAUNCH_KERNEL(3867); break;
	case 3868: LAUNCH_KERNEL(3868); break;
	case 3869: LAUNCH_KERNEL(3869); break;
	case 3870: LAUNCH_KERNEL(3870); break;
	case 3871: LAUNCH_KERNEL(3871); break;
	case 3872: LAUNCH_KERNEL(3872); break;
	case 3873: LAUNCH_KERNEL(3873); break;
	case 3874: LAUNCH_KERNEL(3874); break;
	case 3875: LAUNCH_KERNEL(3875); break;
	case 3876: LAUNCH_KERNEL(3876); break;
	case 3877: LAUNCH_KERNEL(3877); break;
	case 3878: LAUNCH_KERNEL(3878); break;
	case 3879: LAUNCH_KERNEL(3879); break;
	case 3880: LAUNCH_KERNEL(3880); break;
	case 3881: LAUNCH_KERNEL(3881); break;
	case 3882: LAUNCH_KERNEL(3882); break;
	case 3883: LAUNCH_KERNEL(3883); break;
	case 3884: LAUNCH_KERNEL(3884); break;
	case 3885: LAUNCH_KERNEL(3885); break;
	case 3886: LAUNCH_KERNEL(3886); break;
	case 3887: LAUNCH_KERNEL(3887); break;
	case 3888: LAUNCH_KERNEL(3888); break;
	case 3889: LAUNCH_KERNEL(3889); break;
	case 3890: LAUNCH_KERNEL(3890); break;
	case 3891: LAUNCH_KERNEL(3891); break;
	case 3892: LAUNCH_KERNEL(3892); break;
	case 3893: LAUNCH_KERNEL(3893); break;
	case 3894: LAUNCH_KERNEL(3894); break;
	case 3895: LAUNCH_KERNEL(3895); break;
	case 3896: LAUNCH_KERNEL(3896); break;
	case 3897: LAUNCH_KERNEL(3897); break;
	case 3898: LAUNCH_KERNEL(3898); break;
	case 3899: LAUNCH_KERNEL(3899); break;
	case 3900: LAUNCH_KERNEL(3900); break;
	case 3901: LAUNCH_KERNEL(3901); break;
	case 3902: LAUNCH_KERNEL(3902); break;
	case 3903: LAUNCH_KERNEL(3903); break;
	case 3904: LAUNCH_KERNEL(3904); break;
	case 3905: LAUNCH_KERNEL(3905); break;
	case 3906: LAUNCH_KERNEL(3906); break;
	case 3907: LAUNCH_KERNEL(3907); break;
	case 3908: LAUNCH_KERNEL(3908); break;
	case 3909: LAUNCH_KERNEL(3909); break;
	case 3910: LAUNCH_KERNEL(3910); break;
	case 3911: LAUNCH_KERNEL(3911); break;
	case 3912: LAUNCH_KERNEL(3912); break;
	case 3913: LAUNCH_KERNEL(3913); break;
	case 3914: LAUNCH_KERNEL(3914); break;
	case 3915: LAUNCH_KERNEL(3915); break;
	case 3916: LAUNCH_KERNEL(3916); break;
	case 3917: LAUNCH_KERNEL(3917); break;
	case 3918: LAUNCH_KERNEL(3918); break;
	case 3919: LAUNCH_KERNEL(3919); break;
	case 3920: LAUNCH_KERNEL(3920); break;
	case 3921: LAUNCH_KERNEL(3921); break;
	case 3922: LAUNCH_KERNEL(3922); break;
	case 3923: LAUNCH_KERNEL(3923); break;
	case 3924: LAUNCH_KERNEL(3924); break;
	case 3925: LAUNCH_KERNEL(3925); break;
	case 3926: LAUNCH_KERNEL(3926); break;
	case 3927: LAUNCH_KERNEL(3927); break;
	case 3928: LAUNCH_KERNEL(3928); break;
	case 3929: LAUNCH_KERNEL(3929); break;
	case 3930: LAUNCH_KERNEL(3930); break;
	case 3931: LAUNCH_KERNEL(3931); break;
	case 3932: LAUNCH_KERNEL(3932); break;
	case 3933: LAUNCH_KERNEL(3933); break;
	case 3934: LAUNCH_KERNEL(3934); break;
	case 3935: LAUNCH_KERNEL(3935); break;
	case 3936: LAUNCH_KERNEL(3936); break;
	case 3937: LAUNCH_KERNEL(3937); break;
	case 3938: LAUNCH_KERNEL(3938); break;
	case 3939: LAUNCH_KERNEL(3939); break;
	case 3940: LAUNCH_KERNEL(3940); break;
	case 3941: LAUNCH_KERNEL(3941); break;
	case 3942: LAUNCH_KERNEL(3942); break;
	case 3943: LAUNCH_KERNEL(3943); break;
	case 3944: LAUNCH_KERNEL(3944); break;
	case 3945: LAUNCH_KERNEL(3945); break;
	case 3946: LAUNCH_KERNEL(3946); break;
	case 3947: LAUNCH_KERNEL(3947); break;
	case 3948: LAUNCH_KERNEL(3948); break;
	case 3949: LAUNCH_KERNEL(3949); break;
	case 3950: LAUNCH_KERNEL(3950); break;
	case 3951: LAUNCH_KERNEL(3951); break;
	case 3952: LAUNCH_KERNEL(3952); break;
	case 3953: LAUNCH_KERNEL(3953); break;
	case 3954: LAUNCH_KERNEL(3954); break;
	case 3955: LAUNCH_KERNEL(3955); break;
	case 3956: LAUNCH_KERNEL(3956); break;
	case 3957: LAUNCH_KERNEL(3957); break;
	case 3958: LAUNCH_KERNEL(3958); break;
	case 3959: LAUNCH_KERNEL(3959); break;
	case 3960: LAUNCH_KERNEL(3960); break;
	case 3961: LAUNCH_KERNEL(3961); break;
	case 3962: LAUNCH_KERNEL(3962); break;
	case 3963: LAUNCH_KERNEL(3963); break;
	case 3964: LAUNCH_KERNEL(3964); break;
	case 3965: LAUNCH_KERNEL(3965); break;
	case 3966: LAUNCH_KERNEL(3966); break;
	case 3967: LAUNCH_KERNEL(3967); break;
	case 3968: LAUNCH_KERNEL(3968); break;
	case 3969: LAUNCH_KERNEL(3969); break;
	case 3970: LAUNCH_KERNEL(3970); break;
	case 3971: LAUNCH_KERNEL(3971); break;
	case 3972: LAUNCH_KERNEL(3972); break;
	case 3973: LAUNCH_KERNEL(3973); break;
	case 3974: LAUNCH_KERNEL(3974); break;
	case 3975: LAUNCH_KERNEL(3975); break;
	case 3976: LAUNCH_KERNEL(3976); break;
	case 3977: LAUNCH_KERNEL(3977); break;
	case 3978: LAUNCH_KERNEL(3978); break;
	case 3979: LAUNCH_KERNEL(3979); break;
	case 3980: LAUNCH_KERNEL(3980); break;
	case 3981: LAUNCH_KERNEL(3981); break;
	case 3982: LAUNCH_KERNEL(3982); break;
	case 3983: LAUNCH_KERNEL(3983); break;
	case 3984: LAUNCH_KERNEL(3984); break;
	case 3985: LAUNCH_KERNEL(3985); break;
	case 3986: LAUNCH_KERNEL(3986); break;
	case 3987: LAUNCH_KERNEL(3987); break;
	case 3988: LAUNCH_KERNEL(3988); break;
	case 3989: LAUNCH_KERNEL(3989); break;
	case 3990: LAUNCH_KERNEL(3990); break;
	case 3991: LAUNCH_KERNEL(3991); break;
	case 3992: LAUNCH_KERNEL(3992); break;
	case 3993: LAUNCH_KERNEL(3993); break;
	case 3994: LAUNCH_KERNEL(3994); break;
	case 3995: LAUNCH_KERNEL(3995); break;
	case 3996: LAUNCH_KERNEL(3996); break;
	case 3997: LAUNCH_KERNEL(3997); break;
	case 3998: LAUNCH_KERNEL(3998); break;
	case 3999: LAUNCH_KERNEL(3999); break;
	case 4000: LAUNCH_KERNEL(4000); break;
	case 4001: LAUNCH_KERNEL(4001); break;
	case 4002: LAUNCH_KERNEL(4002); break;
	case 4003: LAUNCH_KERNEL(4003); break;
	case 4004: LAUNCH_KERNEL(4004); break;
	case 4005: LAUNCH_KERNEL(4005); break;
	case 4006: LAUNCH_KERNEL(4006); break;
	case 4007: LAUNCH_KERNEL(4007); break;
	case 4008: LAUNCH_KERNEL(4008); break;
	case 4009: LAUNCH_KERNEL(4009); break;
	case 4010: LAUNCH_KERNEL(4010); break;
	case 4011: LAUNCH_KERNEL(4011); break;
	case 4012: LAUNCH_KERNEL(4012); break;
	case 4013: LAUNCH_KERNEL(4013); break;
	case 4014: LAUNCH_KERNEL(4014); break;
	case 4015: LAUNCH_KERNEL(4015); break;
	case 4016: LAUNCH_KERNEL(4016); break;
	case 4017: LAUNCH_KERNEL(4017); break;
	case 4018: LAUNCH_KERNEL(4018); break;
	case 4019: LAUNCH_KERNEL(4019); break;
	case 4020: LAUNCH_KERNEL(4020); break;
	case 4021: LAUNCH_KERNEL(4021); break;
	case 4022: LAUNCH_KERNEL(4022); break;
	case 4023: LAUNCH_KERNEL(4023); break;
	case 4024: LAUNCH_KERNEL(4024); break;
	case 4025: LAUNCH_KERNEL(4025); break;
	case 4026: LAUNCH_KERNEL(4026); break;
	case 4027: LAUNCH_KERNEL(4027); break;
	case 4028: LAUNCH_KERNEL(4028); break;
	case 4029: LAUNCH_KERNEL(4029); break;
	case 4030: LAUNCH_KERNEL(4030); break;
	case 4031: LAUNCH_KERNEL(4031); break;
	case 4032: LAUNCH_KERNEL(4032); break;
	case 4033: LAUNCH_KERNEL(4033); break;
	case 4034: LAUNCH_KERNEL(4034); break;
	case 4035: LAUNCH_KERNEL(4035); break;
	case 4036: LAUNCH_KERNEL(4036); break;
	case 4037: LAUNCH_KERNEL(4037); break;
	case 4038: LAUNCH_KERNEL(4038); break;
	case 4039: LAUNCH_KERNEL(4039); break;
	case 4040: LAUNCH_KERNEL(4040); break;
	case 4041: LAUNCH_KERNEL(4041); break;
	case 4042: LAUNCH_KERNEL(4042); break;
	case 4043: LAUNCH_KERNEL(4043); break;
	case 4044: LAUNCH_KERNEL(4044); break;
	case 4045: LAUNCH_KERNEL(4045); break;
	case 4046: LAUNCH_KERNEL(4046); break;
	case 4047: LAUNCH_KERNEL(4047); break;
	case 4048: LAUNCH_KERNEL(4048); break;
	case 4049: LAUNCH_KERNEL(4049); break;
	case 4050: LAUNCH_KERNEL(4050); break;
	case 4051: LAUNCH_KERNEL(4051); break;
	case 4052: LAUNCH_KERNEL(4052); break;
	case 4053: LAUNCH_KERNEL(4053); break;
	case 4054: LAUNCH_KERNEL(4054); break;
	case 4055: LAUNCH_KERNEL(4055); break;
	case 4056: LAUNCH_KERNEL(4056); break;
	case 4057: LAUNCH_KERNEL(4057); break;
	case 4058: LAUNCH_KERNEL(4058); break;
	case 4059: LAUNCH_KERNEL(4059); break;
	case 4060: LAUNCH_KERNEL(4060); break;
	case 4061: LAUNCH_KERNEL(4061); break;
	case 4062: LAUNCH_KERNEL(4062); break;
	case 4063: LAUNCH_KERNEL(4063); break;
	case 4064: LAUNCH_KERNEL(4064); break;
	case 4065: LAUNCH_KERNEL(4065); break;
	case 4066: LAUNCH_KERNEL(4066); break;
	case 4067: LAUNCH_KERNEL(4067); break;
	case 4068: LAUNCH_KERNEL(4068); break;
	case 4069: LAUNCH_KERNEL(4069); break;
	case 4070: LAUNCH_KERNEL(4070); break;
	case 4071: LAUNCH_KERNEL(4071); break;
	case 4072: LAUNCH_KERNEL(4072); break;
	case 4073: LAUNCH_KERNEL(4073); break;
	case 4074: LAUNCH_KERNEL(4074); break;
	case 4075: LAUNCH_KERNEL(4075); break;
	case 4076: LAUNCH_KERNEL(4076); break;
	case 4077: LAUNCH_KERNEL(4077); break;
	case 4078: LAUNCH_KERNEL(4078); break;
	case 4079: LAUNCH_KERNEL(4079); break;
	case 4080: LAUNCH_KERNEL(4080); break;
	case 4081: LAUNCH_KERNEL(4081); break;
	case 4082: LAUNCH_KERNEL(4082); break;
	case 4083: LAUNCH_KERNEL(4083); break;
	case 4084: LAUNCH_KERNEL(4084); break;
	case 4085: LAUNCH_KERNEL(4085); break;
	case 4086: LAUNCH_KERNEL(4086); break;
	case 4087: LAUNCH_KERNEL(4087); break;
	case 4088: LAUNCH_KERNEL(4088); break;
	case 4089: LAUNCH_KERNEL(4089); break;
	case 4090: LAUNCH_KERNEL(4090); break;
	case 4091: LAUNCH_KERNEL(4091); break;
	case 4092: LAUNCH_KERNEL(4092); break;
	case 4093: LAUNCH_KERNEL(4093); break;
	case 4094: LAUNCH_KERNEL(4094); break;
	case 4095: LAUNCH_KERNEL(4095); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
