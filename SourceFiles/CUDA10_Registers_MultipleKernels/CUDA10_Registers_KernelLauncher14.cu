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

#define SALT 3584
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3585
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3586
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3587
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3588
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3589
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3590
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3591
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3592
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3593
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3594
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3595
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3596
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3597
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3598
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3599
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3600
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3601
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3602
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3603
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3604
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3605
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3606
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3607
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3608
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3609
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3610
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3611
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3612
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3613
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3614
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3615
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3616
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3617
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3618
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3619
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3620
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3621
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3622
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3623
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3624
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3625
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3626
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3627
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3628
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3629
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3630
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3631
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3632
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3633
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3634
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3635
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3636
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3637
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3638
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3639
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3640
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3641
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3642
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3643
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3644
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3645
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3646
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3647
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3648
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3649
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3650
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3651
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3652
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3653
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3654
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3655
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3656
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3657
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3658
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3659
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3660
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3661
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3662
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3663
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3664
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3665
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3666
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3667
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3668
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3669
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3670
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3671
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3672
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3673
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3674
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3675
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3676
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3677
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3678
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3679
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3680
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3681
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3682
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3683
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3684
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3685
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3686
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3687
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3688
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3689
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3690
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3691
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3692
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3693
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3694
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3695
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3696
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3697
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3698
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3699
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3700
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3701
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3702
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3703
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3704
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3705
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3706
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3707
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3708
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3709
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3710
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3711
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3712
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3713
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3714
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3715
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3716
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3717
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3718
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3719
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3720
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3721
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3722
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3723
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3724
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3725
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3726
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3727
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3728
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3729
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3730
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3731
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3732
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3733
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3734
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3735
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3736
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3737
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3738
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3739
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3740
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3741
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3742
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3743
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3744
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3745
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3746
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3747
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3748
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3749
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3750
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3751
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3752
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3753
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3754
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3755
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3756
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3757
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3758
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3759
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3760
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3761
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3762
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3763
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3764
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3765
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3766
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3767
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3768
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3769
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3770
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3771
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3772
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3773
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3774
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3775
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3776
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3777
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3778
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3779
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3780
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3781
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3782
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3783
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3784
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3785
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3786
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3787
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3788
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3789
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3790
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3791
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3792
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3793
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3794
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3795
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3796
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3797
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3798
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3799
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3800
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3801
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3802
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3803
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3804
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3805
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3806
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3807
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3808
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3809
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3810
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3811
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3812
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3813
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3814
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3815
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3816
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3817
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3818
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3819
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3820
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3821
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3822
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3823
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3824
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3825
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3826
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3827
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3828
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3829
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3830
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3831
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3832
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3833
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3834
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3835
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3836
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3837
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3838
#include "../CUDA10_Registers_Kernel.h"
#define SALT 3839
#include "../CUDA10_Registers_Kernel.h"



void CUDA_DES_InitializeKernelLauncher14()
{
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_FirstByte,   keyCharTable_FirstByte,   SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaKeyCharTable_SecondByte,  keyCharTable_SecondByte,  SIZE_KEY_CHAR_TABLE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaChunkBitmap,               chunkBitmap,               CHUNK_BITMAP_SIZE));
	CUDA_ERROR(cudaMemcpyToSymbol(cudaCompactMediumChunkBitmap,    compactMediumChunkBitmap,  COMPACT_MEDIUM_CHUNK_BITMAP_SIZE));
}

void CUDA_DES_LaunchKernel14(
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
	case 3584: LAUNCH_KERNEL(3584); break;
	case 3585: LAUNCH_KERNEL(3585); break;
	case 3586: LAUNCH_KERNEL(3586); break;
	case 3587: LAUNCH_KERNEL(3587); break;
	case 3588: LAUNCH_KERNEL(3588); break;
	case 3589: LAUNCH_KERNEL(3589); break;
	case 3590: LAUNCH_KERNEL(3590); break;
	case 3591: LAUNCH_KERNEL(3591); break;
	case 3592: LAUNCH_KERNEL(3592); break;
	case 3593: LAUNCH_KERNEL(3593); break;
	case 3594: LAUNCH_KERNEL(3594); break;
	case 3595: LAUNCH_KERNEL(3595); break;
	case 3596: LAUNCH_KERNEL(3596); break;
	case 3597: LAUNCH_KERNEL(3597); break;
	case 3598: LAUNCH_KERNEL(3598); break;
	case 3599: LAUNCH_KERNEL(3599); break;
	case 3600: LAUNCH_KERNEL(3600); break;
	case 3601: LAUNCH_KERNEL(3601); break;
	case 3602: LAUNCH_KERNEL(3602); break;
	case 3603: LAUNCH_KERNEL(3603); break;
	case 3604: LAUNCH_KERNEL(3604); break;
	case 3605: LAUNCH_KERNEL(3605); break;
	case 3606: LAUNCH_KERNEL(3606); break;
	case 3607: LAUNCH_KERNEL(3607); break;
	case 3608: LAUNCH_KERNEL(3608); break;
	case 3609: LAUNCH_KERNEL(3609); break;
	case 3610: LAUNCH_KERNEL(3610); break;
	case 3611: LAUNCH_KERNEL(3611); break;
	case 3612: LAUNCH_KERNEL(3612); break;
	case 3613: LAUNCH_KERNEL(3613); break;
	case 3614: LAUNCH_KERNEL(3614); break;
	case 3615: LAUNCH_KERNEL(3615); break;
	case 3616: LAUNCH_KERNEL(3616); break;
	case 3617: LAUNCH_KERNEL(3617); break;
	case 3618: LAUNCH_KERNEL(3618); break;
	case 3619: LAUNCH_KERNEL(3619); break;
	case 3620: LAUNCH_KERNEL(3620); break;
	case 3621: LAUNCH_KERNEL(3621); break;
	case 3622: LAUNCH_KERNEL(3622); break;
	case 3623: LAUNCH_KERNEL(3623); break;
	case 3624: LAUNCH_KERNEL(3624); break;
	case 3625: LAUNCH_KERNEL(3625); break;
	case 3626: LAUNCH_KERNEL(3626); break;
	case 3627: LAUNCH_KERNEL(3627); break;
	case 3628: LAUNCH_KERNEL(3628); break;
	case 3629: LAUNCH_KERNEL(3629); break;
	case 3630: LAUNCH_KERNEL(3630); break;
	case 3631: LAUNCH_KERNEL(3631); break;
	case 3632: LAUNCH_KERNEL(3632); break;
	case 3633: LAUNCH_KERNEL(3633); break;
	case 3634: LAUNCH_KERNEL(3634); break;
	case 3635: LAUNCH_KERNEL(3635); break;
	case 3636: LAUNCH_KERNEL(3636); break;
	case 3637: LAUNCH_KERNEL(3637); break;
	case 3638: LAUNCH_KERNEL(3638); break;
	case 3639: LAUNCH_KERNEL(3639); break;
	case 3640: LAUNCH_KERNEL(3640); break;
	case 3641: LAUNCH_KERNEL(3641); break;
	case 3642: LAUNCH_KERNEL(3642); break;
	case 3643: LAUNCH_KERNEL(3643); break;
	case 3644: LAUNCH_KERNEL(3644); break;
	case 3645: LAUNCH_KERNEL(3645); break;
	case 3646: LAUNCH_KERNEL(3646); break;
	case 3647: LAUNCH_KERNEL(3647); break;
	case 3648: LAUNCH_KERNEL(3648); break;
	case 3649: LAUNCH_KERNEL(3649); break;
	case 3650: LAUNCH_KERNEL(3650); break;
	case 3651: LAUNCH_KERNEL(3651); break;
	case 3652: LAUNCH_KERNEL(3652); break;
	case 3653: LAUNCH_KERNEL(3653); break;
	case 3654: LAUNCH_KERNEL(3654); break;
	case 3655: LAUNCH_KERNEL(3655); break;
	case 3656: LAUNCH_KERNEL(3656); break;
	case 3657: LAUNCH_KERNEL(3657); break;
	case 3658: LAUNCH_KERNEL(3658); break;
	case 3659: LAUNCH_KERNEL(3659); break;
	case 3660: LAUNCH_KERNEL(3660); break;
	case 3661: LAUNCH_KERNEL(3661); break;
	case 3662: LAUNCH_KERNEL(3662); break;
	case 3663: LAUNCH_KERNEL(3663); break;
	case 3664: LAUNCH_KERNEL(3664); break;
	case 3665: LAUNCH_KERNEL(3665); break;
	case 3666: LAUNCH_KERNEL(3666); break;
	case 3667: LAUNCH_KERNEL(3667); break;
	case 3668: LAUNCH_KERNEL(3668); break;
	case 3669: LAUNCH_KERNEL(3669); break;
	case 3670: LAUNCH_KERNEL(3670); break;
	case 3671: LAUNCH_KERNEL(3671); break;
	case 3672: LAUNCH_KERNEL(3672); break;
	case 3673: LAUNCH_KERNEL(3673); break;
	case 3674: LAUNCH_KERNEL(3674); break;
	case 3675: LAUNCH_KERNEL(3675); break;
	case 3676: LAUNCH_KERNEL(3676); break;
	case 3677: LAUNCH_KERNEL(3677); break;
	case 3678: LAUNCH_KERNEL(3678); break;
	case 3679: LAUNCH_KERNEL(3679); break;
	case 3680: LAUNCH_KERNEL(3680); break;
	case 3681: LAUNCH_KERNEL(3681); break;
	case 3682: LAUNCH_KERNEL(3682); break;
	case 3683: LAUNCH_KERNEL(3683); break;
	case 3684: LAUNCH_KERNEL(3684); break;
	case 3685: LAUNCH_KERNEL(3685); break;
	case 3686: LAUNCH_KERNEL(3686); break;
	case 3687: LAUNCH_KERNEL(3687); break;
	case 3688: LAUNCH_KERNEL(3688); break;
	case 3689: LAUNCH_KERNEL(3689); break;
	case 3690: LAUNCH_KERNEL(3690); break;
	case 3691: LAUNCH_KERNEL(3691); break;
	case 3692: LAUNCH_KERNEL(3692); break;
	case 3693: LAUNCH_KERNEL(3693); break;
	case 3694: LAUNCH_KERNEL(3694); break;
	case 3695: LAUNCH_KERNEL(3695); break;
	case 3696: LAUNCH_KERNEL(3696); break;
	case 3697: LAUNCH_KERNEL(3697); break;
	case 3698: LAUNCH_KERNEL(3698); break;
	case 3699: LAUNCH_KERNEL(3699); break;
	case 3700: LAUNCH_KERNEL(3700); break;
	case 3701: LAUNCH_KERNEL(3701); break;
	case 3702: LAUNCH_KERNEL(3702); break;
	case 3703: LAUNCH_KERNEL(3703); break;
	case 3704: LAUNCH_KERNEL(3704); break;
	case 3705: LAUNCH_KERNEL(3705); break;
	case 3706: LAUNCH_KERNEL(3706); break;
	case 3707: LAUNCH_KERNEL(3707); break;
	case 3708: LAUNCH_KERNEL(3708); break;
	case 3709: LAUNCH_KERNEL(3709); break;
	case 3710: LAUNCH_KERNEL(3710); break;
	case 3711: LAUNCH_KERNEL(3711); break;
	case 3712: LAUNCH_KERNEL(3712); break;
	case 3713: LAUNCH_KERNEL(3713); break;
	case 3714: LAUNCH_KERNEL(3714); break;
	case 3715: LAUNCH_KERNEL(3715); break;
	case 3716: LAUNCH_KERNEL(3716); break;
	case 3717: LAUNCH_KERNEL(3717); break;
	case 3718: LAUNCH_KERNEL(3718); break;
	case 3719: LAUNCH_KERNEL(3719); break;
	case 3720: LAUNCH_KERNEL(3720); break;
	case 3721: LAUNCH_KERNEL(3721); break;
	case 3722: LAUNCH_KERNEL(3722); break;
	case 3723: LAUNCH_KERNEL(3723); break;
	case 3724: LAUNCH_KERNEL(3724); break;
	case 3725: LAUNCH_KERNEL(3725); break;
	case 3726: LAUNCH_KERNEL(3726); break;
	case 3727: LAUNCH_KERNEL(3727); break;
	case 3728: LAUNCH_KERNEL(3728); break;
	case 3729: LAUNCH_KERNEL(3729); break;
	case 3730: LAUNCH_KERNEL(3730); break;
	case 3731: LAUNCH_KERNEL(3731); break;
	case 3732: LAUNCH_KERNEL(3732); break;
	case 3733: LAUNCH_KERNEL(3733); break;
	case 3734: LAUNCH_KERNEL(3734); break;
	case 3735: LAUNCH_KERNEL(3735); break;
	case 3736: LAUNCH_KERNEL(3736); break;
	case 3737: LAUNCH_KERNEL(3737); break;
	case 3738: LAUNCH_KERNEL(3738); break;
	case 3739: LAUNCH_KERNEL(3739); break;
	case 3740: LAUNCH_KERNEL(3740); break;
	case 3741: LAUNCH_KERNEL(3741); break;
	case 3742: LAUNCH_KERNEL(3742); break;
	case 3743: LAUNCH_KERNEL(3743); break;
	case 3744: LAUNCH_KERNEL(3744); break;
	case 3745: LAUNCH_KERNEL(3745); break;
	case 3746: LAUNCH_KERNEL(3746); break;
	case 3747: LAUNCH_KERNEL(3747); break;
	case 3748: LAUNCH_KERNEL(3748); break;
	case 3749: LAUNCH_KERNEL(3749); break;
	case 3750: LAUNCH_KERNEL(3750); break;
	case 3751: LAUNCH_KERNEL(3751); break;
	case 3752: LAUNCH_KERNEL(3752); break;
	case 3753: LAUNCH_KERNEL(3753); break;
	case 3754: LAUNCH_KERNEL(3754); break;
	case 3755: LAUNCH_KERNEL(3755); break;
	case 3756: LAUNCH_KERNEL(3756); break;
	case 3757: LAUNCH_KERNEL(3757); break;
	case 3758: LAUNCH_KERNEL(3758); break;
	case 3759: LAUNCH_KERNEL(3759); break;
	case 3760: LAUNCH_KERNEL(3760); break;
	case 3761: LAUNCH_KERNEL(3761); break;
	case 3762: LAUNCH_KERNEL(3762); break;
	case 3763: LAUNCH_KERNEL(3763); break;
	case 3764: LAUNCH_KERNEL(3764); break;
	case 3765: LAUNCH_KERNEL(3765); break;
	case 3766: LAUNCH_KERNEL(3766); break;
	case 3767: LAUNCH_KERNEL(3767); break;
	case 3768: LAUNCH_KERNEL(3768); break;
	case 3769: LAUNCH_KERNEL(3769); break;
	case 3770: LAUNCH_KERNEL(3770); break;
	case 3771: LAUNCH_KERNEL(3771); break;
	case 3772: LAUNCH_KERNEL(3772); break;
	case 3773: LAUNCH_KERNEL(3773); break;
	case 3774: LAUNCH_KERNEL(3774); break;
	case 3775: LAUNCH_KERNEL(3775); break;
	case 3776: LAUNCH_KERNEL(3776); break;
	case 3777: LAUNCH_KERNEL(3777); break;
	case 3778: LAUNCH_KERNEL(3778); break;
	case 3779: LAUNCH_KERNEL(3779); break;
	case 3780: LAUNCH_KERNEL(3780); break;
	case 3781: LAUNCH_KERNEL(3781); break;
	case 3782: LAUNCH_KERNEL(3782); break;
	case 3783: LAUNCH_KERNEL(3783); break;
	case 3784: LAUNCH_KERNEL(3784); break;
	case 3785: LAUNCH_KERNEL(3785); break;
	case 3786: LAUNCH_KERNEL(3786); break;
	case 3787: LAUNCH_KERNEL(3787); break;
	case 3788: LAUNCH_KERNEL(3788); break;
	case 3789: LAUNCH_KERNEL(3789); break;
	case 3790: LAUNCH_KERNEL(3790); break;
	case 3791: LAUNCH_KERNEL(3791); break;
	case 3792: LAUNCH_KERNEL(3792); break;
	case 3793: LAUNCH_KERNEL(3793); break;
	case 3794: LAUNCH_KERNEL(3794); break;
	case 3795: LAUNCH_KERNEL(3795); break;
	case 3796: LAUNCH_KERNEL(3796); break;
	case 3797: LAUNCH_KERNEL(3797); break;
	case 3798: LAUNCH_KERNEL(3798); break;
	case 3799: LAUNCH_KERNEL(3799); break;
	case 3800: LAUNCH_KERNEL(3800); break;
	case 3801: LAUNCH_KERNEL(3801); break;
	case 3802: LAUNCH_KERNEL(3802); break;
	case 3803: LAUNCH_KERNEL(3803); break;
	case 3804: LAUNCH_KERNEL(3804); break;
	case 3805: LAUNCH_KERNEL(3805); break;
	case 3806: LAUNCH_KERNEL(3806); break;
	case 3807: LAUNCH_KERNEL(3807); break;
	case 3808: LAUNCH_KERNEL(3808); break;
	case 3809: LAUNCH_KERNEL(3809); break;
	case 3810: LAUNCH_KERNEL(3810); break;
	case 3811: LAUNCH_KERNEL(3811); break;
	case 3812: LAUNCH_KERNEL(3812); break;
	case 3813: LAUNCH_KERNEL(3813); break;
	case 3814: LAUNCH_KERNEL(3814); break;
	case 3815: LAUNCH_KERNEL(3815); break;
	case 3816: LAUNCH_KERNEL(3816); break;
	case 3817: LAUNCH_KERNEL(3817); break;
	case 3818: LAUNCH_KERNEL(3818); break;
	case 3819: LAUNCH_KERNEL(3819); break;
	case 3820: LAUNCH_KERNEL(3820); break;
	case 3821: LAUNCH_KERNEL(3821); break;
	case 3822: LAUNCH_KERNEL(3822); break;
	case 3823: LAUNCH_KERNEL(3823); break;
	case 3824: LAUNCH_KERNEL(3824); break;
	case 3825: LAUNCH_KERNEL(3825); break;
	case 3826: LAUNCH_KERNEL(3826); break;
	case 3827: LAUNCH_KERNEL(3827); break;
	case 3828: LAUNCH_KERNEL(3828); break;
	case 3829: LAUNCH_KERNEL(3829); break;
	case 3830: LAUNCH_KERNEL(3830); break;
	case 3831: LAUNCH_KERNEL(3831); break;
	case 3832: LAUNCH_KERNEL(3832); break;
	case 3833: LAUNCH_KERNEL(3833); break;
	case 3834: LAUNCH_KERNEL(3834); break;
	case 3835: LAUNCH_KERNEL(3835); break;
	case 3836: LAUNCH_KERNEL(3836); break;
	case 3837: LAUNCH_KERNEL(3837); break;
	case 3838: LAUNCH_KERNEL(3838); break;
	case 3839: LAUNCH_KERNEL(3839); break;
	default: printf("intSalt: %d\n", intSalt); ASSERT(FALSE);
	}
}

#endif
