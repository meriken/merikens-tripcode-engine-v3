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
// CONSTANTS                                                                 //
///////////////////////////////////////////////////////////////////////////////

#define SEARCH_MODE_NIL                    -1
#define SEARCH_MODE_FORWARD_MATCHING       0
#define SEARCH_MODE_BACKWARD_MATCHING      1
#define SEARCH_MODE_FORWARD_AND_BACKWARD_MATCHING 2
#define SEARCH_MODE_FLEXIBLE               3

#define SEARCH_DEVICE_NIL                  0
#define SEARCH_DEVICE_GPU_AND_CPU          1
#define SEARCH_DEVICE_GPU                  2
#define SEARCH_DEVICE_CPU                  3

#define GPU_INDEX_ALL                      (-1)

#define NUM_CPU_SEARCH_THREADS_NIL         (-1)

#define CUDA_OPTIMIZATION_PHASE_NUM_BLOCKS 0
#define CUDA_OPTIMIZATION_PHASE_COMPLETED  1

#define OPENCL_NUM_NUM_WORK_ITEMS_PER_CU_NIL  0
#define OPENCL_NUM_WORK_ITEMS_PER_WG_NIL   0

#define ERROR_INVALID_TARGET_PATTERN 0
#define ERROR_INVALID_REGEX          1
#define ERROR_PATTERN_TOO_LONG       2
#define ERROR_PATTERN_TOO_SHORT      3
#define ERROR_CUDA                   4
#define ERROR_NO_MEMORY              5
#define ERROR_PATTERN_FILE           6
#define ERROR_IGNORE_DIRECTIVE       7
#define ERROR_NO_TARGET_PATTERNS     8
#define ERROR_CRYPTOGRAPHIC_SERVICE  9
#define ERROR_INVALID_OPTION         10
#define ERROR_TRIPCODE_FILE          11
#define ERROR_SEARCH_THREAD          12
#define ERROR_MUTEX                  13
#define ERROR_ASSERTION              14
#define ERROR_OPENCL                 15
#define ERROR_DES                    16
#define ERROR_SHA1                   17
#define ERROR_INTEL_HD_GRAPHICS      18
#define ERROR_CHILD_PROCESS          19
#define ERROR_TRIPCODE_VERIFICATION_FAILED 20
#define ERROR_EVENT                  21
#define ERROR_SEARCH_THREAD_UNRESPONSIVE 22
#define ERROR_UNKNOWN                23
#define ERROR_GCN_ASSEMBLER          24
#define ERROR_DLL                    25



///////////////////////////////////////////////////////////////////////////////
// PARAMETERS                                                                //
///////////////////////////////////////////////////////////////////////////////

// Default options
#define DEFAULT_OPTION_GPU_INDEX                        GPU_INDEX_ALL
#define DEFAULT_OPTION_CUDA_NUM_BLOCKS_PER_SM           128
#define DEFAULT_OPTION_BEEP_WHEN_NEW_TRIPCODE_IS_FOUND  FALSE
#define DEFAULT_OPTION_OUTPUT_INVALID_TRIPCODE          FALSE
#define DEFAULT_OPTION_WARN_SPEED_DROP                  FALSE
#define DEFAULT_OPTION_SEARCH_DEVICE                    SEARCH_DEVICE_NIL
#define DEFAULT_OPTION_TEST_NEW_CODE                    FALSE
#define DEFAULT_OPTION_NUM_CPU_SEARCH_THREADS           NUM_CPU_SEARCH_THREADS_NIL
#define DEFAULT_OPTION_REDIRECTION                      FALSE
#define DEFAULT_OPTION_OPENCL_NUM_NUM_WORK_ITEMS_PER_CU    OPENCL_NUM_NUM_WORK_ITEMS_PER_CU_NIL
#define DEFAULT_OPTION_OPENCL_NUM_WORK_ITEMS_PER_WG     OPENCL_NUM_WORK_ITEMS_PER_WG_NIL
#define DEFAULT_OPTION_OPENCL_RUN_CHILD_PROCESSES_FOR_MULTIPLE_DEVICES TRUE
#define DEFAULT_OPTION_OPENCL_NUM_THREADS_PER_AMD_GPU   2
#define DEFAULT_OPTION_OPENCL_NUM_PROCESSES_PER_AMD_GPU 2
#define DEFAULT_OPTION_SEARCH_FOR_HISEKI_ON_CPU         FALSE
#define DEFAULT_OPTION_SEARCH_FOR_KAKUHI_ON_CPU         FALSE
#define DEFAULT_OPTION_SEARCH_FOR_KAIBUN_ON_CPU         FALSE
#define DEFAULT_OPTION_SEARCH_FOR_YAMABIKO_ON_CPU       FALSE
#define DEFAULT_OPTION_SEARCH_FOR_SOUREN_ON_CPU         FALSE
#define DEFAULT_OPTION_SEARCH_FOR_KAGAMI_ON_CPU         FALSE
#define DEFAULT_OPTION_USE_OPENCL_FOR_CUDA_DEVICES      FALSE
#define DEFAULT_OPTION_IS_AVX_ENABLED                   TRUE
#define DEFAULT_OPTION_MAXIMIZE_KEY_SPACE               FALSE
#define DEFAULT_OPTION_IS_AVX2_ENABLED                  TRUE
#define DEFAULT_OPTION_CHECK_TRIPCODES                  TRUE
#define DEFAULT_OPTION_ENABLE_GCN_ASSEMBLER             TRUE

#ifdef ENGLISH_VERSION
#define DEFAULT_OPTION_USE_ONE_BYTE_CHARACTERS_FOR_KEYS   TRUE
#define DEFAULT_OPTION_USE_ONLY_ASCII_CHARACTERS_FOR_KEYS TRUE
#else
#define DEFAULT_OPTION_USE_ONE_BYTE_CHARACTERS_FOR_KEYS   FALSE
#define DEFAULT_OPTION_USE_ONLY_ASCII_CHARACTERS_FOR_KEYS FALSE
#endif


// For dynamic arrays
#define MIN_SIZE_ARRAY  256

// Files
#define DEFAULT_NAME_PATTERN_FILE  "patterns.txt"
#define DEFAULT_NAME_TRIPCODE_FILE "tripcodes.txt"
#define MAX_LEN_FILE_PATH          1024
#define MAX_LEN_INPUT_LINE         256
#define MAX_LEN_COMMAND_LINE       1024
#define MAX_NUM_PATTERN_FILES      256

// Tripcodes and keys
#define MAX_LEN_TRIPCODE           12
#define MAX_LEN_TRIPCODE_KEY       12
#define LEN_TRIPCODE_CHUNK         5   // Do not touch this.
#define SIZE_KEY_CHAR_TABLE        512

// Patterns
#define MIN_LEN_EXPANDED_PATTERN     LEN_TRIPCODE_CHUNK // Must be at least LEN_TRIPCODE_CHUNK
#define MAX_LEN_EXPANDED_PATTERN     MAX_LEN_TRIPCODE
#define MAX_LEN_TARGET_PATTERN       MAX_LEN_INPUT_LINE
#define CHUNK_BITMAP_LEN_STRING        4
#define CHUNK_BITMAP_SIZE              (64 * 64 * 64 * 64)
#define MEDIUM_CHUNK_BITMAP_LEN_STRING 3
#define MEDIUM_CHUNK_BITMAP_SIZE       (64 * 64 * 64)
#define SMALL_CHUNK_BITMAP_LEN_STRING  2
#define SMALL_CHUNK_BITMAP_SIZE        (64 * 64)
#define COMPACT_MEDIUM_CHUNK_BITMAP_SIZE (MEDIUM_CHUNK_BITMAP_SIZE / 8)
#define COMPACT_SMALL_CHUNK_BITMAP_SIZE (SMALL_CHUNK_BITMAP_SIZE / 8)
#define MAX_NUM_SUBEXPRESSIONS_IN_REGEX_PATTERN 9
#define MAX_NUM_DEPTHS_IN_REGEX_PATTERN         (10 + 1)

// For screen output
#define PRODUCT_NAME                 "Meriken's Tripcode Engine 3.0.0"
#define COMMAND                      "MerikensTripcodeEngine"
#define STATUS_UPDATE_INTERVAL       10.000       // in seconds
#define NUM_CHECKS_PER_INTERVAL      10
#define PAUSE_INTERVAL               100          // in milliseconds
#define SPEED_DROP_WARNING_THRESHOLD 0.50         // Issue a warning if the speed drops below 50% of the maximum speed.
#define SCREEN_WIDTH                 80
#define LEN_LINE_BUFFER_FOR_SCREEN   1024
#define MAX_NUM_LINES_STATUS_MSG     40

// CPU
#define CPU_SHA1_MAX_INDEX_FOR_KEYS         63
#define CPU_DES_MAX_INDEX_FOR_KEYS          31

// CUDA
#define CUDA_MIN_NUM_BLOCKS_PER_SM          1
#define CUDA_MAX_NUM_BLOCKS_PER_SM          256
#define CUDA_SIMPLE_SEARCH_THRESHOLD        4
#define CUDA_OPTIMIZATION_SUBPHASE_DURATION 60.0
#define CUDA_OPTIMIZATION_THRESHOLD         0.001
#define CUDA_NUM_THREADS_PER_DEVICE         2

// OpenCL
#define OPENCL_VENDOR_AMD                       "Advanced Micro Devices, Inc."
#define OPENCL_VENDOR_NVIDIA                    "NVIDIA Corporation"
#define OPENCL_VENDOR_INTEL                     "Intel(R) Corporation"
#define OPENCL_MAX_SIZE_SOURCE_CODE             (1024 * 1024)
#define OPENCL_SHA1_DEFAULT_SOURCE_FILE         "OpenCL/OpenCL12.cl"
#define OPENCL_SHA1_DEFAULT_NUM_WORK_ITEMS_PER_COMPUTE_UNIT 256
#define OPENCL_SHA1_DEFAULT_NUM_WORK_ITEMS_PER_WORK_GROUP      32
#define OPENCL_DES_DEFAULT_SOURCE_FILE          "OpenCL/OpenCL10.cl"
#define OPENCL_DES_MAX_LEN_BUILD_OPTIONS        4096
#define OPENCL_DES_BS_DEPTH                     32
#define OPENCL_SIMPLE_SEARCH_THRESHOLD          4
#define OPENCL_MIN_NUM_WORK_ITEMS_PER_CU        1
#define OPENCL_MAX_NUM_WORK_ITEMS_PER_CU        16384
#define OPENCL_MIN_NUM_WORK_ITEMS_PER_WG        1
#define OPENCL_MAX_NUM_WORK_ITEMS_PER_WG        256
#define OPENCL_MIN_NUM_THREADS_PER_AMD_GPU      1
#define OPENCL_MAX_NUM_THREADS_PER_AMD_GPU      32
#define OPENCL_MIN_NUM_PROCESSES_PER_AMD_GPU	1
#define OPENCL_MAX_NUM_PROCESSES_PER_AMD_GPU	32

// DES
#define DES_SIZE_KEY_SCHEDULE                   0x300
#define DES_SIZE_EXPANSION_FUNCTION             96

// Child processes
#define CHILD_PROCESS_MAX_LEN_COMMAND_LINE      1024

// Options
#define USE_TABLE_FOR_SEED
// #define DISPLAY_MAXIMUM_SPEED

// For debugging
#define DEBUG_TEST_NEW_CODE
// #define DEBUG_REGEX
// #define DEBUG_DISPLAY_EXPANDED_PATTERNS
// #define DEBUG_DISPLAY_TRIPCODE_CHUNKS
// #define DEBUG_DISPLAY_MATCHING_PROBABILITY
// #define DEBUG_DISPLAY_NUM_COLLISIONS
// #define DEBUG_ADD_DUMMY_PATTERNS
// #define DEBUG_USE_CPU_ONLY
// #define DEBUG_ONE_CPU_SEARCH_THREAD
// #define DEBUG_PRINT_INVALID_KEY_INFO
